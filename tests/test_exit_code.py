"""TDD: Tests for risk_to_exit_code() — written BEFORE implementation."""

import pytest


class TestRiskToExitCode:
    def test_none_never_fails(self):
        from argus_lite.core.exit_code import risk_to_exit_code

        assert risk_to_exit_code("NONE", "NONE") == 0
        assert risk_to_exit_code("NONE", "LOW") == 0
        assert risk_to_exit_code("NONE", "HIGH") == 0

    def test_fail_on_low_with_low_risk(self):
        from argus_lite.core.exit_code import risk_to_exit_code

        assert risk_to_exit_code("LOW", "LOW") == 1

    def test_fail_on_low_with_none_risk_no_fail(self):
        from argus_lite.core.exit_code import risk_to_exit_code

        assert risk_to_exit_code("NONE", "LOW") == 0

    def test_fail_on_high_with_medium_risk_no_fail(self):
        from argus_lite.core.exit_code import risk_to_exit_code

        assert risk_to_exit_code("MEDIUM", "HIGH") == 0

    def test_fail_on_high_with_high_risk_fails(self):
        from argus_lite.core.exit_code import risk_to_exit_code

        assert risk_to_exit_code("HIGH", "HIGH") == 1

    def test_fail_on_medium_with_high_risk_fails(self):
        from argus_lite.core.exit_code import risk_to_exit_code

        assert risk_to_exit_code("HIGH", "MEDIUM") == 1

    def test_case_insensitive(self):
        from argus_lite.core.exit_code import risk_to_exit_code

        assert risk_to_exit_code("high", "medium") == 1
        assert risk_to_exit_code("LOW", "low") == 1

    def test_unknown_level_defaults_to_none(self):
        from argus_lite.core.exit_code import risk_to_exit_code

        assert risk_to_exit_code("CRITICAL", "HIGH") == 0
        assert risk_to_exit_code("HIGH", "CRITICAL") == 0
