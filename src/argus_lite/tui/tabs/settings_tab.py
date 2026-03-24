"""Settings Tab — edit API keys, AI config, notifications, rate limits."""

from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Vertical, VerticalScroll
from textual.widgets import Button, Collapsible, Input, Label, Static, Switch

from argus_lite.core.config import (
    AIConfig,
    ApiKeysConfig,
    AppConfig,
    NotificationConfig,
    RateLimitsConfig,
)
from argus_lite.tui.messages import ConfigSaved


class SettingsTab(Static):
    """Tab for editing all Argus configuration."""

    DEFAULT_CSS = """
    SettingsTab { height: 100%; padding: 1 2; }
    .setting-row { height: 3; margin-bottom: 0; }
    .setting-label { width: 22; padding: 1 0 0 0; }
    #save-settings { margin-top: 1; }
    """

    def __init__(self, config: AppConfig | None = None) -> None:
        super().__init__()
        self._config = config or AppConfig()

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            with Collapsible(title="API Keys", collapsed=False):
                for key_id, label in [
                    ("key-shodan", "Shodan"),
                    ("key-virustotal", "VirusTotal"),
                    ("key-censys-id", "Censys API ID"),
                    ("key-censys-secret", "Censys Secret"),
                    ("key-zoomeye", "ZoomEye"),
                    ("key-fofa-email", "FOFA Email"),
                    ("key-fofa-key", "FOFA Key"),
                    ("key-greynoise", "GreyNoise"),
                    ("key-nvd", "NVD"),
                ]:
                    yield Label(label)
                    is_email = "email" in key_id
                    yield Input(id=key_id, password=not is_email)

            with Collapsible(title="AI Configuration"):
                yield Label("Enabled")
                yield Switch(id="ai-enabled", value=False)
                yield Label("Base URL")
                yield Input(id="ai-base-url", value="https://api.openai.com/v1")
                yield Label("API Key")
                yield Input(id="ai-api-key", password=True)
                yield Label("Model")
                yield Input(id="ai-model", value="gpt-4o")

            with Collapsible(title="Notifications"):
                yield Label("Enabled")
                yield Switch(id="notify-enabled", value=False)
                yield Label("Telegram Token")
                yield Input(id="notify-tg-token", password=True)
                yield Label("Telegram Chat ID")
                yield Input(id="notify-tg-chatid")
                yield Label("Discord Webhook")
                yield Input(id="notify-discord", password=True)
                yield Label("Slack Webhook")
                yield Input(id="notify-slack", password=True)

            with Collapsible(title="Rate Limits"):
                yield Label("Global RPS")
                yield Input(id="rate-global", value="50")
                yield Label("Per-target RPS")
                yield Input(id="rate-per-target", value="10")
                yield Label("Concurrent")
                yield Input(id="rate-concurrent", value="5")

            yield Button("Save Configuration", id="save-settings", variant="primary")

    def on_mount(self) -> None:
        """Populate fields from current config."""
        k = self._config.api_keys
        self._set("key-shodan", k.shodan)
        self._set("key-virustotal", k.virustotal)
        self._set("key-censys-id", k.censys_api_id)
        self._set("key-censys-secret", k.censys_api_secret)
        self._set("key-zoomeye", k.zoomeye_api_key)
        self._set("key-fofa-email", k.fofa_email)
        self._set("key-fofa-key", k.fofa_api_key)
        self._set("key-greynoise", k.greynoise_api_key)
        self._set("key-nvd", k.nvd_api_key)

        ai = self._config.ai
        self.query_one("#ai-enabled", Switch).value = ai.enabled
        self._set("ai-base-url", ai.base_url)
        self._set("ai-api-key", ai.api_key)
        self._set("ai-model", ai.model)

        n = self._config.notifications
        self.query_one("#notify-enabled", Switch).value = n.enabled
        self._set("notify-tg-token", n.telegram_token)
        self._set("notify-tg-chatid", n.telegram_chat_id)
        self._set("notify-discord", n.discord_webhook)
        self._set("notify-slack", n.slack_webhook)

        rl = self._config.rate_limits
        self._set("rate-global", str(rl.global_rps))
        self._set("rate-per-target", str(rl.per_target_rps))
        self._set("rate-concurrent", str(rl.concurrent_requests))

    def _set(self, wid: str, val: str) -> None:
        self.query_one(f"#{wid}", Input).value = val or ""

    def _get(self, wid: str) -> str:
        return self.query_one(f"#{wid}", Input).value.strip()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save-settings":
            self._save()

    def _save(self) -> None:
        from argus_lite.core.config import save_config

        self._config.api_keys = ApiKeysConfig(
            shodan=self._get("key-shodan"),
            virustotal=self._get("key-virustotal"),
            censys_api_id=self._get("key-censys-id"),
            censys_api_secret=self._get("key-censys-secret"),
            zoomeye_api_key=self._get("key-zoomeye"),
            fofa_email=self._get("key-fofa-email"),
            fofa_api_key=self._get("key-fofa-key"),
            greynoise_api_key=self._get("key-greynoise"),
            nvd_api_key=self._get("key-nvd"),
        )
        self._config.ai = AIConfig(
            enabled=self.query_one("#ai-enabled", Switch).value,
            base_url=self._get("ai-base-url"),
            api_key=self._get("ai-api-key"),
            model=self._get("ai-model"),
        )
        self._config.notifications = NotificationConfig(
            enabled=self.query_one("#notify-enabled", Switch).value,
            telegram_token=self._get("notify-tg-token"),
            telegram_chat_id=self._get("notify-tg-chatid"),
            discord_webhook=self._get("notify-discord"),
            slack_webhook=self._get("notify-slack"),
        )
        self._config.rate_limits = RateLimitsConfig(
            global_rps=int(self._get("rate-global") or 50),
            per_target_rps=int(self._get("rate-per-target") or 10),
            concurrent_requests=int(self._get("rate-concurrent") or 5),
        )

        config_path = Path.home() / ".argus-lite" / "config.yaml"
        save_config(self._config, config_path)
        self.notify("Configuration saved", severity="information")
        self.post_message(ConfigSaved())
