"""TDD: Tests for Stealth Mode."""

from __future__ import annotations

import pytest


class TestStealthConfig:
    def test_default_disabled(self):
        from argus_lite.core.environment import StealthConfig
        sc = StealthConfig()
        assert sc.enabled is False

    def test_custom_config(self):
        from argus_lite.core.environment import StealthConfig
        sc = StealthConfig(enabled=True, delay_ms=3000, max_rps=0.3)
        assert sc.enabled is True
        assert sc.delay_ms == 3000

    def test_randomize_headers(self):
        from argus_lite.core.environment import randomize_headers
        h1 = randomize_headers()
        h2 = randomize_headers()
        # Both should have User-Agent
        assert "User-Agent" in h1
        assert "User-Agent" in h2

    def test_user_agent_pool(self):
        from argus_lite.core.environment import USER_AGENTS
        assert len(USER_AGENTS) >= 5
