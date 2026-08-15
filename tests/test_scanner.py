"""Scanner helpers used by the FastAPI app."""

from __future__ import annotations

import pytest

from phishing.scanner import UnsafeTargetError, research_findings, scan


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
