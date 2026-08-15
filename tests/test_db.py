"""Scan telemetry storage and the endpoints built on it."""

from __future__ import annotations

import importlib

import pytest


@pytest.fixture
def db(tmp_path, monkeypatch):
    """A fresh SQLite database per test, with module globals reset."""
    monkeypatch.setenv("PHISHING_DATABASE_URL", f"sqlite:///{tmp_path / 'scans.db'}")
    from phishing import db as db_module

    importlib.reload(db_module)
    db_module.init_db()
    return db_module


def sample_result(url: str = "https://example.com/login?token=secret") -> dict:
    return {
        "url": url,
        "verdict": "suspicious",
        "probability": 0.62,
        "model": "XGBoost",
        "coverage": {"page_fetched": True, "tls_checked": True},
        "model_quality": {"warn_threshold": 0.5, "block_threshold": 0.85},
        "features": {"having_IP_Address": 1},
        "signals": [{"feature": "SSLfinal_State", "contribution": 0.3}],
    }


def test_record_and_read_back(db):
    scan_id = db.record_scan(sample_result(), duration_ms=123)
    assert scan_id is not None

    rows = db.recent_scans()
    assert len(rows) == 1
    assert rows[0]["verdict"] == "suspicious"
    assert rows[0]["duration_ms"] == 123
    assert rows[0]["host"] == "example.com"


def test_query_string_is_not_stored(db):
    db.record_scan(sample_result("https://example.com/reset?token=hunter2"))
    stored = db.recent_scans()[0]["url"]
    assert "hunter2" not in stored
    assert stored == "https://example.com/reset"


def test_same_url_hashes_consistently(db):
    url = "https://example.com/a?x=1"
    db.record_scan(sample_result(url))
    db.record_scan(sample_result(url))
    with db.session_scope() as session:
        hashes = {row.url_hash for row in session.query(db.Scan).all()}
    assert len(hashes) == 1


def test_stats_counts_verdicts(db):
    db.record_scan(sample_result())
    phishing = sample_result("https://bad.example.org/")
    phishing["verdict"] = "phishing"
    db.record_scan(phishing)

    stats = db.scan_stats()
    assert stats["total_scans"] == 2
    assert stats["verdicts"] == {"suspicious": 1, "phishing": 1}
    assert stats["daily"][0]["scans"] == 2


def test_record_scan_never_raises(db, monkeypatch):
    """A telemetry failure must not turn a successful scan into an error."""

    def boom():
        raise RuntimeError("database is down")

    monkeypatch.setattr(db, "session_scope", boom)
    assert db.record_scan(sample_result()) is None


def test_scans_and_stats_endpoints(db, monkeypatch):
    from fastapi.testclient import TestClient

    import api.main as api_main

    importlib.reload(api_main)
    monkeypatch.setattr(api_main, "record_scan", db.record_scan)
    monkeypatch.setattr(api_main, "recent_scans", db.recent_scans)
    monkeypatch.setattr(api_main, "scan_stats", db.scan_stats)

    db.record_scan(sample_result())

    with TestClient(api_main.app) as client:
        listed = client.get("/api/scans")
        assert listed.status_code == 200
        assert len(listed.json()["scans"]) == 1

        stats = client.get("/api/stats")
        assert stats.status_code == 200
        assert stats.json()["total_scans"] == 1

        assert client.get("/api/health").json() == {"status": "ok"}
