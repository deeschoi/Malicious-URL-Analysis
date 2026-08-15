"""Scan telemetry storage.

Runtime scan history lives here so the API can report what it has seen and how
its score distribution moves over time. Research outputs stay as files in
``reports/`` — they are static artifacts of a pipeline run, not telemetry.

SQLite by default so the app runs with no extra services; point
``PHISHING_DATABASE_URL`` at Postgres in a deployment.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse, urlunparse

from sqlalchemy import (
    JSON,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    create_engine,
    func,
    select,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from phishing.config import PROJECT_ROOT

DEFAULT_DATABASE_URL = f"sqlite:///{PROJECT_ROOT / 'data' / 'scans.db'}"


def database_url() -> str:
    return os.environ.get("PHISHING_DATABASE_URL", DEFAULT_DATABASE_URL)


class Base(DeclarativeBase):
    pass


class Scan(Base):
    """One scored URL.

    Query strings are dropped before storage: they routinely carry session
    tokens, password-reset links, and other credentials, and the model never
    reads them anyway. ``url_hash`` covers the full URL so repeat scans of the
    same link can still be counted without retaining the sensitive part.
    """

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
    url: Mapped[str] = mapped_column(Text)
    url_hash: Mapped[str] = mapped_column(String(64), index=True)
    host: Mapped[str] = mapped_column(String(255), index=True)
    verdict: Mapped[str] = mapped_column(String(32), index=True)
    probability: Mapped[float] = mapped_column(Float)
    model_name: Mapped[str] = mapped_column(String(64))
    warn_threshold: Mapped[float] = mapped_column(Float)
    block_threshold: Mapped[float] = mapped_column(Float)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    page_fetched: Mapped[bool] = mapped_column(default=False)
    tls_checked: Mapped[bool] = mapped_column(default=False)
    features: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    signals: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "url": self.url,
            "host": self.host,
            "verdict": self.verdict,
            "probability": self.probability,
            "model": self.model_name,
            "duration_ms": self.duration_ms,
            "page_fetched": self.page_fetched,
            "tls_checked": self.tls_checked,
        }


_engine = None
_Session: sessionmaker[Session] | None = None


def get_engine():
    global _engine, _Session
    if _engine is None:
        url = database_url()
        if url.startswith("sqlite:///"):
            path = url.removeprefix("sqlite:///")
            if path and path != ":memory:":
                os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        # check_same_thread=False: FastAPI serves requests on a threadpool.
        connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
        _engine = create_engine(url, future=True, connect_args=connect_args)
        _Session = sessionmaker(bind=_engine, expire_on_commit=False, future=True)
    return _engine


def init_db() -> None:
    Base.metadata.create_all(get_engine())


@contextmanager
def session_scope() -> Iterator[Session]:
    get_engine()
    assert _Session is not None
    session = _Session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def strip_query(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse(parsed._replace(query="", fragment=""))


def record_scan(result: dict[str, Any], duration_ms: int = 0) -> int | None:
    """Persist a scan result. Returns the row id, or None if storage failed.

    Telemetry must never turn a successful scan into a failed request, so all
    database errors are swallowed here and surfaced only in the logs.
    """
    try:
        url = str(result.get("url", ""))
        coverage = result.get("coverage") or {}
        quality = result.get("model_quality") or {}
        with session_scope() as session:
            row = Scan(
                url=strip_query(url),
                url_hash=hashlib.sha256(url.encode("utf-8")).hexdigest(),
                host=(urlparse(url).hostname or "")[:255],
                verdict=str(result.get("verdict", "unknown")),
                probability=float(result.get("probability", 0.0)),
                model_name=str(result.get("model", "unknown")),
                warn_threshold=float(quality.get("warn_threshold", 0.0)),
                block_threshold=float(quality.get("block_threshold", 0.0)),
                duration_ms=int(duration_ms),
                page_fetched=bool(coverage.get("page_fetched", False)),
                tls_checked=bool(coverage.get("tls_checked", False)),
                features=result.get("features") or {},
                signals=result.get("signals") or [],
            )
            session.add(row)
            session.flush()
            return row.id
    except Exception:  # noqa: BLE001 - logging telemetry must not break scanning
        import logging

        logging.getLogger(__name__).exception("Failed to record scan")
        return None


def recent_scans(limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
    with session_scope() as session:
        rows = session.scalars(
            select(Scan).order_by(Scan.created_at.desc()).limit(limit).offset(offset)
        ).all()
        return [row.to_dict() for row in rows]


def scan_stats(days: int = 30) -> dict[str, Any]:
    """Verdict mix and mean score per day — the drift signal for the deployed model."""
    with session_scope() as session:
        total = session.scalar(select(func.count(Scan.id))) or 0

        verdicts = session.execute(
            select(Scan.verdict, func.count(Scan.id)).group_by(Scan.verdict)
        ).all()

        day = func.date(Scan.created_at)
        daily = session.execute(
            select(day, func.count(Scan.id), func.avg(Scan.probability))
            .group_by(day)
            .order_by(day.desc())
            .limit(days)
        ).all()

        return {
            "total_scans": int(total),
            "verdicts": {str(v): int(c) for v, c in verdicts},
            "daily": [
                {"date": str(d), "scans": int(c), "mean_probability": float(p or 0.0)}
                for d, c, p in daily
            ],
        }
