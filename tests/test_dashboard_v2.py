"""TDD: Tests for Dashboard v2 API endpoints."""

from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture
def dashboard_client(tmp_path):
    """Create Flask test client with sample scan data."""
    scans_dir = tmp_path / "scans"
    scans_dir.mkdir()

    # Create two sample scans
    for i, (sid, target, risk) in enumerate([
        ("scan-aaa", "example.com", "LOW"),
        ("scan-bbb", "test.com", "MEDIUM"),
    ]):
        scan_dir = scans_dir / sid
        scan_dir.mkdir()
        (scan_dir / "partial.json").write_text(json.dumps({
            "scan_id": sid,
            "target": target,
            "target_type": "domain",
            "status": "completed",
            "started_at": "2025-01-01T00:00:00",
            "findings": [
                {"id": f"f{i}", "type": "test", "severity": "INFO",
                 "title": f"Finding {target}", "description": "", "asset": target,
                 "evidence": "", "source": "test", "remediation": "fix"},
            ],
            "risk_summary": {"overall_score": 10 + i * 10, "risk_level": risk},
            "tools_used": ["dig", "whois"],
        }))
        report_dir = scan_dir / "report"
        report_dir.mkdir()
        (report_dir / "report.html").write_text("<html>Report</html>")

    from argus_lite.dashboard.app import create_app
    app = create_app(str(tmp_path))
    app.config["TESTING"] = True
    return app.test_client()


class TestDashboardIndex:
    def test_returns_html(self, dashboard_client):
        resp = dashboard_client.get("/")
        assert resp.status_code == 200
        assert b"Argus" in resp.data

    def test_shows_scan_targets(self, dashboard_client):
        resp = dashboard_client.get("/")
        assert b"example.com" in resp.data
        assert b"test.com" in resp.data

    def test_shows_risk_cards(self, dashboard_client):
        resp = dashboard_client.get("/")
        assert b"Total Scans" in resp.data


class TestDashboardAPI:
    def test_api_scans_list(self, dashboard_client):
        resp = dashboard_client.get("/api/scans")
        data = resp.get_json()
        assert len(data) == 2

    def test_api_scan_detail(self, dashboard_client):
        resp = dashboard_client.get("/api/scans/scan-aaa")
        data = resp.get_json()
        assert data["target"] == "example.com"

    def test_api_scan_404(self, dashboard_client):
        resp = dashboard_client.get("/api/scans/nonexistent")
        assert resp.status_code == 404

    def test_api_findings(self, dashboard_client):
        resp = dashboard_client.get("/api/scans/scan-aaa/findings")
        data = resp.get_json()
        assert len(data) == 1
        assert data[0]["title"] == "Finding example.com"

    def test_api_compare(self, dashboard_client):
        resp = dashboard_client.get("/api/compare?a=scan-aaa&b=scan-bbb")
        data = resp.get_json()
        assert "new_in_b" in data
        assert "resolved_in_b" in data
        assert "unchanged" in data

    def test_api_compare_missing_params(self, dashboard_client):
        resp = dashboard_client.get("/api/compare")
        assert resp.status_code == 400

    def test_api_stats(self, dashboard_client):
        resp = dashboard_client.get("/api/stats")
        data = resp.get_json()
        assert data["total"] == 2
        assert data["findings"] == 2


class TestDashboardReport:
    def test_report_renders(self, dashboard_client):
        resp = dashboard_client.get("/report/scan-aaa")
        assert resp.status_code == 200
        assert b"Report" in resp.data

    def test_report_404(self, dashboard_client):
        resp = dashboard_client.get("/report/nonexistent")
        assert resp.status_code == 404
