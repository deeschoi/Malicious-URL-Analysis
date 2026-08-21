"""FastAPI service for the phishing scanner."""

from __future__ import annotations

import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from phishing.db import init_db, recent_scans, record_scan, scan_stats
from phishing.scanner import UnsafeTargetError, available_models, research_findings, scan

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
    version="1.0.0",
    lifespan=lifespan,
)


class ScanRequest(BaseModel):
    url: str = Field(..., description="URL to scan", max_length=2048)
    timeout: int = Field(8, ge=2, le=20, description="Per-request timeout in seconds")


@app.post("/api/scan")
def scan_url(request: ScanRequest) -> dict:
    try:
        started = time.perf_counter()
        result = scan(request.url, timeout=request.timeout)
        duration_ms = int((time.perf_counter() - started) * 1000)
        result["scan_id"] = record_scan(result, duration_ms=duration_ms)
        result["duration_ms"] = duration_ms
        return result
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


@app.get("/api/model")
def model_info() -> dict:
    models = available_models()
    return {
        name: {
            "features": bundle["features"],
            "accuracy": bundle["metrics"]["accuracy"],
            "auroc": bundle["metrics"]["auroc"],
            "thresholds": {
                k: {"threshold": v["threshold"], "recall": v["recall"],
                    "false_positive_rate": v["false_positive_rate"]}
                for k, v in bundle["thresholds"].items()
            },
        }
        for name, bundle in models.items()
    }


@app.get("/api/findings")
def findings() -> dict:
    """Headline results from the analysis, surfaced alongside the scanner."""
    return research_findings()


@app.get("/api/scans")
def scans(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> dict:
    """Recent scan history. URLs are stored without their query strings."""
    return {"scans": recent_scans(limit=limit, offset=offset)}


@app.get("/api/stats")
def stats(days: int = Query(30, ge=1, le=365)) -> dict:
    """Verdict mix and mean score per day, for spotting score drift."""
    return scan_stats(days=days)


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


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
