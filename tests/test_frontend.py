"""Serving the built React UI from FastAPI."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_index_without_build(monkeypatch, tmp_path):
    import api.main as api_main

    monkeypatch.setattr(api_main, "DIST_DIR", tmp_path / "dist")
    with TestClient(api_main.app) as client:
        response = client.get("/")
        assert response.status_code == 503
        assert "Frontend not built" in response.text
        assert client.get("/api/health").json() == {"status": "ok"}


def test_index_and_spa_from_dist(monkeypatch, tmp_path):
    import api.main as api_main

    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<!doctype html><title>Sphinx</title>")
    (dist / "favicon.ico").write_bytes(b"ico")
    monkeypatch.setattr(api_main, "DIST_DIR", dist)

    with TestClient(api_main.app) as client:
        home = client.get("/")
        assert home.status_code == 200
        assert "Sphinx" in home.text

        history = client.get("/history")
        assert history.status_code == 200
        assert "Sphinx" in history.text

        asset = client.get("/favicon.ico")
        assert asset.status_code == 200

        listed = client.get("/api/health")
        assert listed.status_code == 200
        assert listed.json() == {"status": "ok"}


def test_spa_does_not_swallow_missing_api_routes(monkeypatch, tmp_path):
    import api.main as api_main

    monkeypatch.setattr(api_main, "DIST_DIR", tmp_path / "dist")
    with TestClient(api_main.app) as client:
        response = client.get("/api/does-not-exist")
        assert response.status_code == 404
        assert response.headers["content-type"].startswith("application/json")
