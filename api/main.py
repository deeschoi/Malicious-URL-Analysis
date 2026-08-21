"""FastAPI service for the phishing scanner."""

from __future__ import annotations

import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from api.security import client_key, require_api_key, scan_limiter
from phishing.agent import AgentUnavailableError
from phishing.agent import answer as agent_answer
from phishing.agent import is_enabled as agent_enabled
from phishing.db import init_db, recent_scans, record_scan, scan_stats
from phishing.netguard import UnsafeTargetError
from phishing.scanner import available_models, research_findings, scan
from phishing.settings import GROQ_MODEL

ROOT = Path(__file__).resolve().parent.parent
DIST_DIR = ROOT / "web" / "dist"
_RESERVED_FRONTEND = {"api", "docs", "redoc", "openapi.json"}

MISSING_FRONTEND = """<!doctype html>
<title>Frontend not built</title>
<p>The React UI has not been built. From the repo root:</p>
<pre>cd web &amp;&amp; npm install &amp;&amp; npm run build</pre>
<p>Or run the Vite dev server on port 5173 while this API is on 8000.</p>
"""


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    init_db()
    yield


app = FastAPI(
    title="Sphinx",
    description="URL phishing guardian: explained phishing verdicts from a "
                "model trained on the PhiUSIIL 2023 URL dataset.",
    version="1.1.0",
    lifespan=lifespan,
)


class ScanRequest(BaseModel):
    url: str = Field(..., description="URL to scan", max_length=2048)
    timeout: int = Field(8, ge=2, le=20, description="Per-request timeout in seconds")


class ChatMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(..., max_length=4000)


class ChatRequest(BaseModel):
    """A question about a scan the caller already ran.

    ``scan`` is that scan's response payload, echoed back. It is grounding data
    for the analyst, never instructions: the system prompt is server-side and
    the model can only reach real evidence through tools.
    """

    scan: dict = Field(..., description="The /api/scan response being discussed")
    messages: list[ChatMessage] = Field(..., min_length=1, max_length=24)


@app.post("/api/scan", dependencies=[Depends(require_api_key)])
def scan_url(request: ScanRequest, http_request: Request) -> dict:
    # A scan is a DNS lookup, an outbound fetch of up to 20s, an HTML parse and
    # two model passes, all on the request threadpool. Both limits are load
    # bearing: the per-caller budget stops one client monopolising the service,
    # and the in-flight cap stops many clients exhausting sockets together.
    scan_limiter.check(client_key(http_request))
    try:
        with scan_limiter.slot():
            started = time.perf_counter()
            result = scan(request.url, timeout=request.timeout)
            duration_ms = int((time.perf_counter() - started) * 1000)
        result["scan_id"] = record_scan(result, duration_ms=duration_ms)
        result["duration_ms"] = duration_ms
        return result
    except HTTPException:
        raise
    except UnsafeTargetError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500, detail=f"Scan failed: {type(exc).__name__}"
        ) from exc


@app.get("/api/agent")
def agent_status() -> dict:
    """Whether the analyst chat is configured, so the UI can hide it if not."""
    return {
        "enabled": agent_enabled(),
        "model": GROQ_MODEL if agent_enabled() else None,
        "detail": (
            "Set GROQ_API_KEY in .env at the repo root to enable the analyst."
            if not agent_enabled()
            else None
        ),
    }


@app.post("/api/chat", dependencies=[Depends(require_api_key)])
def chat(request: ChatRequest, http_request: Request) -> dict:
    """Answer a question about a scan, grounded in that scan's evidence."""
    scan_limiter.check(f"chat:{client_key(http_request)}")
    try:
        return agent_answer(
            request.scan,
            [message.model_dump() for message in request.messages],
        )
    except AgentUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500, detail=f"Chat failed: {type(exc).__name__}"
        ) from exc


@app.get("/api/model")
def model_info() -> dict:
    models = available_models()
    return {
        name: {
            "features": bundle["features"],
            "accuracy": bundle["metrics"]["accuracy"],
            "auroc": bundle["metrics"]["auroc"],
            "dataset": bundle.get("dataset", ""),
            # The held-out numbers above are the frozen 2023 dataset columns.
            # This is the same model measured over the live network, which is
            # what a scan of a real URL gets.
            "live_sample": bundle.get("live_sample") or {},
            "thresholds": bundle["thresholds"],
            "url_only": bundle.get("url_only") or {},
        }
        for name, bundle in models.items()
    }


@app.get("/api/findings")
def findings() -> dict:
    """Headline results from the analysis, surfaced alongside the scanner."""
    return research_findings()


@app.get("/api/scans", dependencies=[Depends(require_api_key)])
def scans(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> dict:
    """Recent scan history. URLs are stored without credentials, query, or path tokens."""
    return {"scans": recent_scans(limit=limit, offset=offset)}


@app.get("/api/stats", dependencies=[Depends(require_api_key)])
def stats(days: int = Query(30, ge=1, le=365)) -> dict:
    """Verdict mix and mean score per day, for spotting score drift."""
    return scan_stats(days=days)


@app.get("/api/health")
def health() -> dict:
    """Liveness only: the process is up and serving. Never touches the model or DB."""
    return {"status": "ok"}


@app.get("/api/ready")
def ready() -> dict:
    """Readiness: can this instance actually serve a scan?

    ``/api/health`` returning ok while ``artifacts/model.joblib`` is missing
    meant an orchestrator kept routing traffic to an instance that answered
    every scan with a 503.
    """
    checks: dict[str, object] = {}
    ok = True

    try:
        models = available_models()
        checks["model"] = next(iter(models)) if models else None
        if not models:
            ok = False
            checks["model_error"] = "No trained model artifact. Run: python run.py train"
    except Exception as exc:  # noqa: BLE001 — readiness reports, never raises
        ok = False
        checks["model_error"] = f"{type(exc).__name__}: {exc}"

    try:
        from sqlalchemy import text

        from phishing.db import session_scope

        with session_scope() as session:
            session.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as exc:  # noqa: BLE001 — readiness reports, never raises
        ok = False
        checks["database"] = f"{type(exc).__name__}: {exc}"

    checks["frontend"] = "built" if (DIST_DIR / "index.html").is_file() else "not built"
    checks["analyst"] = "enabled" if agent_enabled() else "disabled"
    if not ok:
        raise HTTPException(status_code=503, detail={"status": "not ready", **checks})
    return {"status": "ready", **checks}


def _frontend_file(relative: str) -> Path | None:
    if not relative:
        return None
    candidate = (DIST_DIR / relative).resolve()
    try:
        candidate.relative_to(DIST_DIR.resolve())
    except ValueError:
        return None
    return candidate if candidate.is_file() else None


def _frontend_index():
    index_path = DIST_DIR / "index.html"
    if index_path.is_file():
        return FileResponse(index_path)
    return HTMLResponse(MISSING_FRONTEND, status_code=503)


@app.get("/")
def index():
    """Serve the built React app, or a short how-to if it has not been built."""
    return _frontend_index()


@app.get("/{full_path:path}")
def spa(full_path: str):
    """Client-side routes (/history, /stats, /findings) all share index.html."""
    first = full_path.split("/", 1)[0]
    if first in _RESERVED_FRONTEND:
        raise HTTPException(status_code=404, detail="Not found")
    direct = _frontend_file(full_path)
    if direct is not None:
        return FileResponse(direct)
    return _frontend_index()


_assets = DIST_DIR / "assets"
if _assets.is_dir():
    app.mount("/assets", StaticFiles(directory=_assets), name="assets")
