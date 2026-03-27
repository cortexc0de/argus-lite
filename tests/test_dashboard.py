"""TDD: Tests for web dashboard."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from argus_lite.models.scan import ScanResult


@pytest.fixture
def dashboard_dir(tmp_path):
    """Create a mock scans directory with 2 scans."""
    scans = tmp_path / "scans"
    scans.mkdir()

    for scan_id in ("scan-001", "scan-002"):
        scan_dir = scans / scan_id
        scan_dir.mkdir()
        report_dir = scan_dir / "report"
        report_dir.mkdir()

        scan = ScanResult(
            scan_id=scan_id,
            target="example.com" if scan_id == "scan-001" else "test.local",
            target_type="domain",
            status="completed",
            started_at=datetime(2026, 3, 21, 10, 0, 0, tzinfo=timezone.utc),
        )
        (scan_dir / "partial.json").write_text(scan.model_dump_json(indent=2))
        (report_dir / "report.html").write_text("<html><body>Test Report</body></html>")

    return tmp_path


class TestDashboard:
    def test_app_creates(self):
        from argus_lite.dashboard.app import create_app

        app, _sio = create_app("/tmp/nonexistent")
        assert app is not None

    def test_index_page(self, dashboard_dir):
        from argus_lite.dashboard.app import create_app

        app, _sio = create_app(str(dashboard_dir))
        client = app.test_client()
        resp = client.get("/")
        assert resp.status_code == 200
        assert b"Argus" in resp.data

    def test_scans_list(self, dashboard_dir):
        from argus_lite.dashboard.app import create_app

        app, _sio = create_app(str(dashboard_dir))
        client = app.test_client()
        resp = client.get("/api/scans")
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data) == 2

    def test_scan_detail(self, dashboard_dir):
        from argus_lite.dashboard.app import create_app

        app, _sio = create_app(str(dashboard_dir))
        client = app.test_client()
        resp = client.get("/api/scans/scan-001")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["target"] == "example.com"

    def test_scan_report(self, dashboard_dir):
        from argus_lite.dashboard.app import create_app

        app, _sio = create_app(str(dashboard_dir))
        client = app.test_client()
        resp = client.get("/report/scan-001")
        assert resp.status_code == 200
        assert b"Test Report" in resp.data

    def test_missing_scan_404(self, dashboard_dir):
        from argus_lite.dashboard.app import create_app

        app, _sio = create_app(str(dashboard_dir))
        client = app.test_client()
        resp = client.get("/api/scans/nonexistent")
        assert resp.status_code == 404
