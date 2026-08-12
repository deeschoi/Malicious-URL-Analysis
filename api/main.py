"""FastAPI service for the phishing scanner."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from phishing.config import RESULTS_DIR, ROOT, UNAVAILABLE_FEATURES, DEAD_FEATURE_REASON
from phishing.extract import UnsafeTargetError
from phishing.scanner import available_models, scan

WEB_DIR = ROOT / "web"

app = FastAPI(
    title="Phishing URL Scanner",
    description="Explained phishing verdicts from a model trained on the UCI "
                "Phishing Websites dataset.",
    version="1.0.0",
)


class ScanRequest(BaseModel):
    url: str = Field(..., description="URL to scan", max_length=2048)
    timeout: int = Field(8, ge=2, le=20, description="Per-request timeout in seconds")


@app.post("/api/scan")
def scan_url(request: ScanRequest) -> dict:
    try:
        return scan(request.url, timeout=request.timeout)
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
    def read(name: str) -> dict:
        path = RESULTS_DIR / name
        return json.loads(path.read_text()) if path.exists() else {}

    leakage = read("01_grouped_evaluation.json")
    shap_res = read("03_shap.json")
    obsolescence = read("04_obsolescence.json")
    minimal = read("05_minimal_features.json")

    return {
        "leakage": leakage.get("leakage", {}),
        "models": leakage.get("results", []),
        "reversed_features": shap_res.get("reversed_features", []),
        "no_signal_features": shap_res.get("no_signal_features", []),
        "encoding_audit": shap_res.get("encoding_audit", []),
        "top_interactions": shap_res.get("interactions", [])[:6],
        "scenarios": obsolescence.get("scenarios", []),
        "minimal_feature_set": minimal.get("minimal_feature_set", []),
        "unavailable_features": [
            {"feature": f, "reason": DEAD_FEATURE_REASON[f]} for f in UNAVAILABLE_FEATURES
        ],
    }


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


if WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(WEB_DIR / "index.html")
