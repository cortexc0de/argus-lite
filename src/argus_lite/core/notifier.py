"""Notification system — Telegram, Discord, Slack."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from argus_lite.core.config import NotificationConfig
from argus_lite.models.scan import ScanResult

logger = logging.getLogger(__name__)


class TelegramNotifier:
    def __init__(self, token: str, chat_id: str) -> None:
        self.token = token
        self.chat_id = chat_id

    def format_message(self, scan: ScanResult) -> str:
        risk = scan.risk_summary
        risk_text = f"{risk.risk_level} ({risk.overall_score})" if risk else "N/A"
        findings = len(scan.findings)
        return (
            f"Argus Scan Complete\n"
            f"Target: {scan.target}\n"
            f"Status: {scan.status}\n"
            f"Risk: {risk_text}\n"
            f"Findings: {findings}\n"
            f"Tools: {', '.join(scan.tools_used)}"
        )

    async def send(self, scan: ScanResult) -> None:
        msg = self.format_message(scan)
        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        async with httpx.AsyncClient() as client:
            await client.post(url, json={"chat_id": self.chat_id, "text": msg})


class DiscordNotifier:
    def __init__(self, webhook_url: str) -> None:
        self.webhook_url = webhook_url

    def format_payload(self, scan: ScanResult) -> dict[str, Any]:
        risk = scan.risk_summary
        risk_text = f"{risk.risk_level} ({risk.overall_score})" if risk else "N/A"
        return {
            "embeds": [{
                "title": f"Argus Scan — {scan.target}",
                "color": 0x58a6ff,
                "fields": [
                    {"name": "Status", "value": scan.status, "inline": True},
                    {"name": "Risk", "value": risk_text, "inline": True},
                    {"name": "Findings", "value": str(len(scan.findings)), "inline": True},
                ],
            }]
        }

    async def send(self, scan: ScanResult) -> None:
        payload = self.format_payload(scan)
        async with httpx.AsyncClient() as client:
            await client.post(self.webhook_url, json=payload)


class SlackNotifier:
    def __init__(self, webhook_url: str) -> None:
        self.webhook_url = webhook_url

    def format_payload(self, scan: ScanResult) -> dict[str, Any]:
        risk = scan.risk_summary
        risk_text = f"{risk.risk_level} ({risk.overall_score})" if risk else "N/A"
        return {
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": f"Argus Scan — {scan.target}"}},
                {"type": "section", "fields": [
                    {"type": "mrkdwn", "text": f"*Status:* {scan.status}"},
                    {"type": "mrkdwn", "text": f"*Risk:* {risk_text}"},
                    {"type": "mrkdwn", "text": f"*Findings:* {len(scan.findings)}"},
                ]},
            ]
        }

    async def send(self, scan: ScanResult) -> None:
        payload = self.format_payload(scan)
        async with httpx.AsyncClient() as client:
            await client.post(self.webhook_url, json=payload)


class NotificationDispatcher:
    """Dispatches notifications to all configured channels."""

    def __init__(self, config: NotificationConfig) -> None:
        self._config = config

    def get_active_notifiers(self) -> list:
        if not self._config.enabled:
            return []

        notifiers = []
        if self._config.telegram_token and self._config.telegram_chat_id:
            notifiers.append(TelegramNotifier(self._config.telegram_token, self._config.telegram_chat_id))
        if self._config.discord_webhook:
            notifiers.append(DiscordNotifier(self._config.discord_webhook))
        if self._config.slack_webhook:
            notifiers.append(SlackNotifier(self._config.slack_webhook))
        return notifiers

    async def notify_all(self, scan: ScanResult) -> None:
        for notifier in self.get_active_notifiers():
            try:
                await notifier.send(scan)
            except Exception as e:
                logger.warning("Notification failed (%s): %s", type(notifier).__name__, e)
