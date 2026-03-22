"""TDD: Tests for audit logging — written BEFORE implementation."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest


class TestAuditLogger:
    def test_log_action(self, tmp_path):
        from argus_lite.core.audit import AuditLogger

        log_file = tmp_path / "audit.log"
        logger = AuditLogger(log_file)
        logger.log("scan_started", target="example.com", scan_id="test-uuid")

        lines = log_file.read_text().strip().splitlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["action"] == "scan_started"
        assert entry["target"] == "example.com"
        assert entry["scan_id"] == "test-uuid"
        assert "timestamp" in entry

    def test_log_multiple_actions(self, tmp_path):
        from argus_lite.core.audit import AuditLogger

        log_file = tmp_path / "audit.log"
        logger = AuditLogger(log_file)
        logger.log("scan_started", target="a.com")
        logger.log("stage_completed", stage="recon")
        logger.log("scan_completed", target="a.com")

        lines = log_file.read_text().strip().splitlines()
        assert len(lines) == 3

    def test_masks_api_keys(self, tmp_path):
        from argus_lite.core.audit import AuditLogger

        log_file = tmp_path / "audit.log"
        logger = AuditLogger(log_file)
        logger.log(
            "config_loaded",
            api_key="super-secret-key-12345",
            shodan_key="another-secret",
        )

        content = log_file.read_text()
        assert "super-secret-key-12345" not in content
        assert "another-secret" not in content
        assert "***" in content

    def test_creates_log_directory(self, tmp_path):
        from argus_lite.core.audit import AuditLogger

        log_file = tmp_path / "subdir" / "audit.log"
        logger = AuditLogger(log_file)
        logger.log("test_action")

        assert log_file.exists()

    def test_timestamp_is_utc_iso(self, tmp_path):
        from argus_lite.core.audit import AuditLogger

        log_file = tmp_path / "audit.log"
        logger = AuditLogger(log_file)
        logger.log("test")

        entry = json.loads(log_file.read_text().strip())
        ts = entry["timestamp"]
        # Should be parseable as ISO datetime
        dt = datetime.fromisoformat(ts)
        assert dt.tzinfo is not None or "Z" in ts or "+" in ts
