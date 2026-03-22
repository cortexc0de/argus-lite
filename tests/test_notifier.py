"""TDD: Tests for notification system — written BEFORE implementation."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from argus_lite.models.risk import RiskSummary
from argus_lite.models.scan import ScanResult


def _scan_result() -> ScanResult:
    return ScanResult(
        scan_id="test-uuid", target="example.com", target_type="domain",
        status="completed", started_at=datetime.now(tz=timezone.utc),
        risk_summary=RiskSummary(overall_score=25, risk_level="MEDIUM"),
    )


class TestTelegramNotifier:
    def test_format_message(self):
        from argus_lite.core.notifier import TelegramNotifier

        n = TelegramNotifier(token="fake", chat_id="123")
        msg = n.format_message(_scan_result())
        assert "example.com" in msg
        assert "MEDIUM" in msg

    def test_send_calls_api(self):
        from argus_lite.core.notifier import TelegramNotifier

        n = TelegramNotifier(token="fake", chat_id="123")
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = AsyncMock(status_code=200)
            import asyncio
            asyncio.get_event_loop().run_until_complete(n.send(_scan_result()))
            mock_post.assert_called_once()


class TestDiscordNotifier:
    def test_format_embed(self):
        from argus_lite.core.notifier import DiscordNotifier

        n = DiscordNotifier(webhook_url="https://discord.com/api/webhooks/fake")
        payload = n.format_payload(_scan_result())
        assert "embeds" in payload
        assert "example.com" in str(payload)


class TestSlackNotifier:
    def test_format_blocks(self):
        from argus_lite.core.notifier import SlackNotifier

        n = SlackNotifier(webhook_url="https://hooks.slack.com/fake")
        payload = n.format_payload(_scan_result())
        assert "blocks" in payload
        assert "example.com" in str(payload)


class TestNotificationDispatcher:
    def test_skips_unconfigured(self):
        from argus_lite.core.config import NotificationConfig
        from argus_lite.core.notifier import NotificationDispatcher

        config = NotificationConfig(enabled=True)  # No tokens set
        d = NotificationDispatcher(config)
        assert len(d.get_active_notifiers()) == 0

    def test_dispatches_to_configured(self):
        from argus_lite.core.config import NotificationConfig
        from argus_lite.core.notifier import NotificationDispatcher

        config = NotificationConfig(
            enabled=True, telegram_token="tok", telegram_chat_id="123",
        )
        d = NotificationDispatcher(config)
        assert len(d.get_active_notifiers()) == 1

    def test_disabled_sends_nothing(self):
        from argus_lite.core.config import NotificationConfig
        from argus_lite.core.notifier import NotificationDispatcher

        config = NotificationConfig(
            enabled=False, telegram_token="tok", telegram_chat_id="123",
        )
        d = NotificationDispatcher(config)
        assert len(d.get_active_notifiers()) == 0
