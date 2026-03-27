"""TDD: Tests for Dashboard API — scan, agent, OSINT, stats endpoints."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest


@pytest.fixture
def app(tmp_path):
    from argus_lite.dashboard.app import create_app

    app, socketio = create_app(str(tmp_path))
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(app):
    return app.test_client()


class TestDashboardPages:
    def test_index_returns_200(self, client):
        resp = client.get("/")
        assert resp.status_code == 200

    def test_scan_page_returns_200(self, client):
        resp = client.get("/scan")
        assert resp.status_code == 200
        assert b"Scan" in resp.data

    def test_osint_page_returns_200(self, client):
        resp = client.get("/osint")
        assert resp.status_code == 200

    def test_settings_page_returns_200(self, client):
        resp = client.get("/settings")
        assert resp.status_code == 200

    def test_missing_report_returns_404(self, client):
        resp = client.get("/report/nonexistent-id")
        assert resp.status_code == 404


class TestScanAPI:
    def test_start_scan_requires_target(self, client):
        resp = client.post("/api/scan/start", json={"target": ""})
        assert resp.status_code == 400

    def test_start_scan_returns_started(self, client):
        resp = client.post("/api/scan/start", json={"target": "test.com", "preset": "quick"})
        data = resp.get_json()
        assert data["status"] == "started"
        assert data["target"] == "test.com"

    def test_stop_scan_nonexistent(self, client):
        resp = client.post("/api/scan/stop", json={"target": "nope.com"})
        assert resp.status_code == 404


class TestAgentAPI:
    def test_start_agent_requires_target(self, client):
        resp = client.post("/api/agent/start", json={"target": ""})
        assert resp.status_code == 400

    def test_start_agent_returns_started(self, client):
        resp = client.post("/api/agent/start", json={
            "target": "test.com", "mission": "full_assessment", "max_steps": 3,
        })
        data = resp.get_json()
        assert data["status"] == "started"

    def test_agent_status_returns_json(self, client):
        resp = client.get("/api/agent/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "running" in data

    def test_stop_agent_nonexistent(self, client):
        resp = client.post("/api/agent/stop", json={"target": "nope.com"})
        assert resp.status_code == 404


class TestRestAPI:
    def test_scans_list_empty(self, client):
        resp = client.get("/api/scans")
        assert resp.status_code == 200
        assert resp.get_json() == []

    def test_stats_empty(self, client):
        resp = client.get("/api/stats")
        data = resp.get_json()
        assert data["total"] == 0

    def test_running_endpoint(self, client):
        resp = client.get("/api/running")
        assert resp.status_code == 200

    def test_compare_requires_params(self, client):
        resp = client.get("/api/compare")
        assert resp.status_code == 400

    def test_scan_detail_404(self, client):
        resp = client.get("/api/scans/nonexistent")
        assert resp.status_code == 404


class TestCreateApp:
    def test_returns_app_and_socketio(self, tmp_path):
        from argus_lite.dashboard.app import create_app

        result = create_app(str(tmp_path))
        assert isinstance(result, tuple)
        assert len(result) == 2
        app, socketio = result
        assert app is not None
        assert socketio is not None
