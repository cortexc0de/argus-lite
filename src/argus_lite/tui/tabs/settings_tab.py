"""Settings Tab — clean, organized configuration editor."""

from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.widgets import Button, Collapsible, Input, Label, Static, Switch

from argus_lite.core.config import (
    AIConfig,
    ApiKeysConfig,
    AppConfig,
    NotificationConfig,
    RateLimitsConfig,
)
from argus_lite.tui.messages import ConfigSaved

_CSS = """
SettingsTab { height: 1fr; }

#settings-title {
    color: #00ff41;
    text-style: bold;
    margin-bottom: 1;
}

.key-label {
    color: #58a6ff;
    margin: 0 0 0 0;
}

.section-desc {
    color: #8b949e;
    margin: 0 0 1 0;
}

#save-settings {
    margin-top: 2;
    width: 100%;
}
"""


class SettingsTab(Static):
    """Configuration editor with organized sections."""

    DEFAULT_CSS = _CSS

    def __init__(self, config: AppConfig | None = None) -> None:
        super().__init__()
        self._config = config or AppConfig()

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            yield Label("CONFIGURATION", id="settings-title")

            with Collapsible(title="OSINT API Keys", collapsed=False):
                yield Label("Connect to Shodan, Censys, ZoomEye, FOFA, GreyNoise, VirusTotal", classes="section-desc")
                for key_id, label in [
                    ("key-shodan", "Shodan API Key"),
                    ("key-virustotal", "VirusTotal API Key"),
                    ("key-censys-id", "Censys API ID"),
                    ("key-censys-secret", "Censys API Secret"),
                    ("key-zoomeye", "ZoomEye API Key"),
                    ("key-fofa-email", "FOFA Email"),
                    ("key-fofa-key", "FOFA API Key"),
                    ("key-greynoise", "GreyNoise API Key"),
                    ("key-nvd", "NVD API Key (CVE lookup)"),
                ]:
                    yield Label(label, classes="key-label")
                    yield Input(id=key_id, password="email" not in key_id)

            with Collapsible(title="AI Provider"):
                yield Label("OpenAI-compatible API for scan analysis", classes="section-desc")
                yield Label("Enabled", classes="key-label")
                yield Switch(id="ai-enabled", value=False)
                yield Label("Base URL", classes="key-label")
                yield Input(id="ai-base-url", placeholder="https://api.openai.com/v1")
                yield Label("API Key", classes="key-label")
                yield Input(id="ai-api-key", password=True)
                yield Label("Model", classes="key-label")
                yield Input(id="ai-model", placeholder="gpt-4o")
                yield Label("Language (en/ru)", classes="key-label")
                yield Input(id="ai-lang", placeholder="en")

            with Collapsible(title="Notifications"):
                yield Label("Telegram, Discord, Slack alerts", classes="section-desc")
                yield Label("Enabled", classes="key-label")
                yield Switch(id="notify-enabled", value=False)
                yield Label("Telegram Token", classes="key-label")
                yield Input(id="notify-tg-token", password=True)
                yield Label("Telegram Chat ID", classes="key-label")
                yield Input(id="notify-tg-chatid")
                yield Label("Discord Webhook", classes="key-label")
                yield Input(id="notify-discord", password=True)
                yield Label("Slack Webhook", classes="key-label")
                yield Input(id="notify-slack", password=True)

            with Collapsible(title="Rate Limits"):
                yield Label("Control scan speed", classes="section-desc")
                yield Label("Global RPS", classes="key-label")
                yield Input(id="rate-global", value="50")
                yield Label("Per-target RPS", classes="key-label")
                yield Input(id="rate-per-target", value="10")
                yield Label("Concurrent requests", classes="key-label")
                yield Input(id="rate-concurrent", value="5")

            yield Button("SAVE CONFIGURATION", id="save-settings", variant="primary")

    def on_mount(self) -> None:
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
        self._set("ai-lang", ai.language)

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
            language=self._get("ai-lang") or "en",
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
