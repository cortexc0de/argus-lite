"""TDD: Tests for nuclei custom template support."""

import pytest


class TestNucleiCustomTemplates:
    def test_build_args_with_custom_templates(self):
        from argus_lite.modules.analysis.nuclei import build_nuclei_args

        args = build_nuclei_args(
            target="example.com",
            templates=["/custom/templates/", "~/.argus-lite/templates/"],
        )
        assert "-u" in args
        assert "example.com" in args
        assert "-t" in args
        assert "/custom/templates/" in args
        assert "~/.argus-lite/templates/" in args

    def test_build_args_without_templates(self):
        from argus_lite.modules.analysis.nuclei import build_nuclei_args

        args = build_nuclei_args(target="example.com")
        assert "-u" in args
        assert "-t" not in args

    def test_build_args_severity_always_info_low(self):
        from argus_lite.modules.analysis.nuclei import build_nuclei_args

        args = build_nuclei_args(target="example.com")
        sev_idx = args.index("-severity")
        assert args[sev_idx + 1] == "info,low"
