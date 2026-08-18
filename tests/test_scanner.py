"""Scanner helpers used by the FastAPI app."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from phishing.config import DEPLOYABLE_FEATURES, FEATURE_COLUMNS
from phishing.features.reachability import LiveProbe
from phishing.scanner import UnsafeTargetError, research_findings, scan
from phishing.schema import ModelArtifact


def test_scan_rejects_loopback():
    with pytest.raises(UnsafeTargetError):
        scan("http://127.0.0.1/")
    with pytest.raises(UnsafeTargetError):
        scan("http://localhost:8000/")


def test_scan_rejects_empty_and_non_http():
    with pytest.raises(ValueError, match="empty"):
        scan("   ")
    with pytest.raises(ValueError, match="javascript"):
        scan("javascript:alert(1)")


def test_missing_model_message(tmp_path, monkeypatch):
    from phishing import scanner

    monkeypatch.setattr(scanner, "ARTIFACTS_DIR", tmp_path)
    scanner._loaded_model.cache_clear()
    with pytest.raises(FileNotFoundError, match="train"):
        scanner._loaded_model()
    scanner._loaded_model.cache_clear()


def test_research_findings_has_ui_keys():
    data = research_findings()
    assert "leakage" in data
    assert "models" in data
    assert "unavailable_features" in data
    reasons = {row["feature"] for row in data["unavailable_features"]}
    assert reasons == {
        "web_traffic",
        "Page_Rank",
        "Google_Index",
        "Links_pointing_to_page",
        "Statistical_report",
    }
    if data["models"]:
        row = data["models"][0]
        assert "random_accuracy" in row
        assert "grouped_accuracy" in row


def test_api_module_imports():
    from api.main import app

    routes = {getattr(route, "path", None) for route in app.routes}
    assert "/" in routes
    assert "/api/scan" in routes
    assert "/api/findings" in routes
    assert "/api/health" in routes


def _fake_model(probability: float = 0.003):
    class Est:
        def predict_proba(self, X):
            return np.array([[1.0 - probability, probability]] * len(X))

    artifact = ModelArtifact(
        model_name="Fake",
        feature_names=list(DEPLOYABLE_FEATURES),
        threshold=0.38,
        metrics={"accuracy": 0.9, "auroc": 0.99, "recall": 0.9, "fpr": 0.01},
        trained_at="test",
        extra={"fpr_threshold": 0.85},
    )
    return Est(), artifact


def _patch_scan(monkeypatch, probe: LiveProbe, probability: float = 0.003):
    from phishing import scanner

    features = pd.Series({c: 1 for c in FEATURE_COLUMNS}, dtype="int64")
    monkeypatch.setattr(
        scanner, "url_to_features", lambda *a, **k: (features, [], probe)
    )
    monkeypatch.setattr(scanner, "_loaded_model", lambda: _fake_model(probability))

    def _skip_shap(*_a, **_k):
        raise RuntimeError("shap skipped in test")

    monkeypatch.setattr("phishing.explain.shap_values", _skip_shap)


def test_unresolved_host_is_not_legitimate(monkeypatch):
    _patch_scan(
        monkeypatch,
        LiveProbe(
            status="unreachable",
            dns_ok=False,
            page_fetched=False,
            tls_inspected=False,
        ),
        probability=0.003,
    )
    result = scan("https://iqospots.com")
    assert result["verdict"] == "unreachable"
    assert result["risk"] is None
    assert result["url_only"] is True
    assert result["prediction"] is None
    assert result["probability"] == pytest.approx(0.003)
    assert "does not resolve" in result["rationale"]
    assert result["reachability"]["status"] == "unreachable"
    assert result["coverage"]["page_fetched"] is False
    assert result["coverage"]["tls_checked"] is False


def test_fetch_failed_withholds_risk(monkeypatch):
    _patch_scan(
        monkeypatch,
        LiveProbe(
            status="fetch_failed",
            dns_ok=True,
            page_fetched=False,
            tls_inspected=False,
        ),
    )
    result = scan("https://example.com")
    assert result["verdict"] == "fetch_failed"
    assert result["risk"] is None
    assert result["url_only"] is True
    assert "Risk is withheld" in result["rationale"]


def test_resolved_host_uses_probability_bands(monkeypatch):
    _patch_scan(
        monkeypatch,
        LiveProbe(
            status="resolved",
            dns_ok=True,
            page_fetched=True,
            tls_inspected=True,
        ),
        probability=0.003,
    )
    result = scan("https://example.com")
    assert result["verdict"] == "legitimate"
    assert result["risk"] == "legitimate"
    assert result["url_only"] is False
    assert result["prediction"] == "legitimate"
