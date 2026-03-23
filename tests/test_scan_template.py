"""TDD: Tests for YAML scan template loader — written BEFORE implementation."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml


@pytest.fixture
def template_dir(tmp_path: Path) -> Path:
    return tmp_path


def _write_template(path: Path, content: dict) -> Path:
    f = path / "scan.yaml"
    f.write_text(yaml.dump(content))
    return f


class TestScanTemplateLoading:
    def test_load_basic_template(self, template_dir):
        from argus_lite.core.scan_template import load_scan_template

        f = _write_template(template_dir, {"version": "1", "target": "example.com"})
        tmpl = load_scan_template(f)
        assert tmpl.target == "example.com"
        assert tmpl.version == "1"

    def test_default_values(self, template_dir):
        from argus_lite.core.scan_template import load_scan_template

        f = _write_template(template_dir, {"target": "test.com"})
        tmpl = load_scan_template(f)
        assert tmpl.preset == "quick"
        assert tmpl.rate_limit == 10
        assert tmpl.timeout == 30
        assert tmpl.no_confirm is False
        assert tmpl.report.format == "md"

    def test_all_fields_populated(self, template_dir):
        from argus_lite.core.scan_template import load_scan_template

        f = _write_template(template_dir, {
            "version": "1",
            "target": "full.example.com",
            "preset": "full",
            "report": {"format": "html", "output": "./out/"},
            "notify": {"telegram": True, "discord": False},
            "ai": {"enabled": True, "model": "gpt-4o"},
            "rate_limit": 20,
            "timeout": 60,
            "no_confirm": True,
        })
        tmpl = load_scan_template(f)
        assert tmpl.preset == "full"
        assert tmpl.report.format == "html"
        assert tmpl.report.output == "./out/"
        assert tmpl.notify.telegram is True
        assert tmpl.ai.enabled is True
        assert tmpl.ai.model == "gpt-4o"
        assert tmpl.rate_limit == 20
        assert tmpl.timeout == 60
        assert tmpl.no_confirm is True


class TestScanTemplateEnvVars:
    def test_env_var_substitution(self, template_dir, monkeypatch):
        from argus_lite.core.scan_template import load_scan_template

        monkeypatch.setenv("MY_TARGET", "env-target.com")
        f = template_dir / "scan.yaml"
        f.write_text("target: ${MY_TARGET}\n")
        tmpl = load_scan_template(f)
        assert tmpl.target == "env-target.com"

    def test_missing_env_var_keeps_placeholder(self, template_dir, monkeypatch):
        from argus_lite.core.scan_template import load_scan_template

        monkeypatch.delenv("UNKNOWN_VAR", raising=False)
        f = template_dir / "scan.yaml"
        f.write_text("target: ${UNKNOWN_VAR}\n")
        tmpl = load_scan_template(f)
        assert tmpl.target == "${UNKNOWN_VAR}"


class TestScanTemplateValidation:
    def test_invalid_preset_raises(self, template_dir):
        from pydantic import ValidationError

        from argus_lite.core.scan_template import load_scan_template

        f = _write_template(template_dir, {"target": "x.com", "preset": "extreme"})
        with pytest.raises((ValidationError, ValueError)):
            load_scan_template(f)

    def test_invalid_format_raises(self, template_dir):
        from pydantic import ValidationError

        from argus_lite.core.scan_template import load_scan_template

        f = _write_template(template_dir, {
            "target": "x.com",
            "report": {"format": "pdf"},
        })
        with pytest.raises((ValidationError, ValueError)):
            load_scan_template(f)

    def test_no_target_raises(self, template_dir):
        from pydantic import ValidationError

        from argus_lite.core.scan_template import load_scan_template

        f = _write_template(template_dir, {"version": "1", "preset": "quick"})
        with pytest.raises((ValidationError, ValueError)):
            load_scan_template(f)

    def test_nonexistent_file_raises(self, template_dir):
        from argus_lite.core.scan_template import load_scan_template

        with pytest.raises(FileNotFoundError):
            load_scan_template(template_dir / "nonexistent.yaml")

    def test_invalid_yaml_raises(self, template_dir):
        from argus_lite.core.scan_template import load_scan_template

        f = template_dir / "bad.yaml"
        f.write_text("target: [broken yaml")
        with pytest.raises(Exception):
            load_scan_template(f)
