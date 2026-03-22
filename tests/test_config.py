"""TDD: Tests for config loading and validation — written BEFORE implementation."""

import os
from pathlib import Path

import pytest


class TestConfigModels:
    def test_default_config(self):
        from argus_lite.core.config import AppConfig

        config = AppConfig()
        assert config.general.log_level == "INFO"
        assert config.security.require_confirmation is True
        assert config.rate_limits.global_rps == 50
        assert config.rate_limits.concurrent_requests == 5

    def test_nuclei_severity_enforcement(self):
        from pydantic import ValidationError

        from argus_lite.core.config import NucleiToolConfig

        # Valid severities
        c = NucleiToolConfig(severity=["info", "low"])
        assert c.severity == ["info", "low"]

        # Invalid severity rejected
        with pytest.raises(ValidationError):
            NucleiToolConfig(severity=["info", "low", "medium"])

        with pytest.raises(ValidationError):
            NucleiToolConfig(severity=["high"])

        with pytest.raises(ValidationError):
            NucleiToolConfig(severity=["critical"])

    def test_tool_config(self):
        from argus_lite.core.config import ToolEntry

        t = ToolEntry(enabled=True, path="/usr/bin/naabu")
        assert t.enabled is True
        assert t.path == Path("/usr/bin/naabu")


class TestConfigLoading:
    def test_load_from_yaml(self, sample_config_yaml):
        from argus_lite.core.config import load_config

        config = load_config(sample_config_yaml)
        assert config.general.log_level == "INFO"
        assert config.rate_limits.per_target_rps == 10

    def test_load_missing_file_returns_defaults(self, tmp_path):
        from argus_lite.core.config import load_config

        config = load_config(tmp_path / "nonexistent.yaml")
        assert config.general.log_level == "INFO"

    def test_env_var_overrides_api_key(self, sample_config_yaml, monkeypatch):
        from argus_lite.core.config import load_config

        monkeypatch.setenv("ARGUS_SHODAN_KEY", "test-key-123")
        config = load_config(sample_config_yaml)
        assert config.api_keys.shodan == "test-key-123"

    def test_env_var_override_virustotal(self, sample_config_yaml, monkeypatch):
        from argus_lite.core.config import load_config

        monkeypatch.setenv("ARGUS_VIRUSTOTAL_KEY", "vt-key-456")
        config = load_config(sample_config_yaml)
        assert config.api_keys.virustotal == "vt-key-456"

    def test_insecure_permissions_warning(self, sample_config_yaml, capsys):
        from argus_lite.core.config import load_config

        os.chmod(sample_config_yaml, 0o644)
        load_config(sample_config_yaml)
        captured = capsys.readouterr()
        assert "permission" in captured.err.lower() or "permission" in captured.out.lower()

    def test_invalid_yaml_raises(self, tmp_config_dir):
        from argus_lite.core.config import ConfigLoadError, load_config

        bad_file = tmp_config_dir / "config.yaml"
        bad_file.write_text("invalid: yaml: [broken")
        with pytest.raises(ConfigLoadError):
            load_config(bad_file)
