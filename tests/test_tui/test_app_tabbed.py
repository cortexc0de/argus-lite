"""Tests for the full tabbed TUI application."""

from __future__ import annotations

import pytest


class TestArgusAppInstantiation:
    def test_creates_without_args(self):
        from argus_lite.tui.app import ArgusApp
        app = ArgusApp()
        assert app is not None

    def test_creates_with_target(self):
        from argus_lite.tui.app import ArgusApp
        app = ArgusApp(target="example.com")
        assert app._target == "example.com"

    def test_creates_with_config(self):
        from argus_lite.core.config import AppConfig
        from argus_lite.tui.app import ArgusApp
        config = AppConfig()
        app = ArgusApp(config=config)
        assert app._config is config


class TestTuiMessages:
    def test_stage_update(self):
        from argus_lite.tui.messages import StageUpdate
        msg = StageUpdate(stage="recon", status="done")
        assert msg.stage == "recon"
        assert msg.status == "done"

    def test_finding_update(self):
        from argus_lite.models.finding import Finding
        from argus_lite.tui.messages import FindingUpdate
        f = Finding(id="f1", type="t", severity="INFO", title="T",
                    description="d", asset="a", evidence="e", source="s", remediation="r")
        msg = FindingUpdate(finding=f)
        assert msg.finding.id == "f1"

    def test_scan_complete(self):
        from datetime import datetime, timezone
        from argus_lite.models.scan import ScanResult
        from argus_lite.tui.messages import ScanComplete
        sr = ScanResult(scan_id="s1", target="t", target_type="domain",
                        status="completed", started_at=datetime.now(tz=timezone.utc))
        msg = ScanComplete(result=sr)
        assert msg.result.scan_id == "s1"

    def test_config_saved(self):
        from argus_lite.tui.messages import ConfigSaved
        msg = ConfigSaved()
        assert isinstance(msg, ConfigSaved)

    def test_osint_query_complete(self):
        from argus_lite.tui.messages import OsintQueryComplete
        msg = OsintQueryComplete(hosts=[{"ip": "1.1.1.1"}])
        assert len(msg.hosts) == 1


class TestTabImports:
    def test_scan_tab_importable(self):
        from argus_lite.tui.tabs.scan_tab import ScanTab
        assert ScanTab is not None

    def test_settings_tab_importable(self):
        from argus_lite.tui.tabs.settings_tab import SettingsTab
        assert SettingsTab is not None

    def test_results_tab_importable(self):
        from argus_lite.tui.tabs.results_tab import ResultsTab
        assert ResultsTab is not None

    def test_osint_tab_importable(self):
        from argus_lite.tui.tabs.osint_tab import OsintTab
        assert OsintTab is not None

    def test_monitor_tab_importable(self):
        from argus_lite.tui.tabs.monitor_tab import MonitorTab
        assert MonitorTab is not None


class TestScanTabInstantiation:
    def test_creates_with_config(self):
        from argus_lite.core.config import AppConfig
        from argus_lite.tui.tabs.scan_tab import ScanTab
        tab = ScanTab(config=AppConfig())
        assert tab is not None

    def test_creates_without_config(self):
        from argus_lite.tui.tabs.scan_tab import ScanTab
        tab = ScanTab()
        assert tab._config is not None


class TestSettingsTabInstantiation:
    def test_creates_with_config(self):
        from argus_lite.core.config import AppConfig
        from argus_lite.tui.tabs.settings_tab import SettingsTab
        config = AppConfig()
        config.api_keys.shodan = "test-key"
        tab = SettingsTab(config=config)
        assert tab._config.api_keys.shodan == "test-key"


class TestOsintTabQueryParsing:
    def test_parses_cve(self):
        from argus_lite.tui.tabs.osint_tab import OsintTab
        tab = OsintTab()
        q = tab._parse_query("CVE-2024-1234")
        assert q.cve == "CVE-2024-1234"

    def test_parses_port_number(self):
        from argus_lite.tui.tabs.osint_tab import OsintTab
        tab = OsintTab()
        q = tab._parse_query("3389")
        assert q.port == 3389

    def test_parses_tech_name(self):
        from argus_lite.tui.tabs.osint_tab import OsintTab
        tab = OsintTab()
        q = tab._parse_query("WordPress 6.3")
        assert q.tech == "WordPress 6.3"


class TestSaveConfig:
    def test_save_and_load_roundtrip(self, tmp_path):
        from argus_lite.core.config import AppConfig, load_config, save_config
        config = AppConfig()
        config.api_keys.shodan = "roundtrip-key"
        config.ai.model = "test-model"
        path = tmp_path / "config.yaml"
        save_config(config, path)
        loaded = load_config(path)
        assert loaded.api_keys.shodan == "roundtrip-key"
        assert loaded.ai.model == "test-model"

    def test_save_creates_directory(self, tmp_path):
        from argus_lite.core.config import AppConfig, save_config
        config = AppConfig()
        path = tmp_path / "deep" / "nested" / "config.yaml"
        save_config(config, path)
        assert path.exists()

    def test_save_sets_permissions(self, tmp_path):
        import stat
        from argus_lite.core.config import AppConfig, save_config
        config = AppConfig()
        path = tmp_path / "config.yaml"
        save_config(config, path)
        mode = path.stat().st_mode & 0o777
        assert mode == 0o600
