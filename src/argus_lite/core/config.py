"""Configuration loading, validation, and env-var overrides."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, field_validator


class ConfigLoadError(Exception):
    """Raised when config file cannot be loaded or parsed."""


# --- Nested config models ---


class GeneralConfig(BaseModel):
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_dir: str = "~/.argus-lite/logs"
    scan_dir: str = "~/.argus-lite/scans"


class SecurityConfig(BaseModel):
    require_confirmation: bool = True
    allowlist_only: bool = False
    max_scan_duration_minutes: int = 120


class RateLimitsConfig(BaseModel):
    global_rps: int = 50
    per_target_rps: int = 10
    concurrent_requests: int = 5


class ToolEntry(BaseModel):
    enabled: bool = True
    path: Path = Path("/usr/bin/unknown")
    templates_dir: str | None = None


NUCLEI_ALLOWED_SEVERITIES = frozenset({"info", "low"})


class NucleiToolConfig(BaseModel):
    severity: list[str] = ["info", "low"]

    @field_validator("severity")
    @classmethod
    def enforce_severity_ceiling(cls, v: list[str]) -> list[str]:
        for sev in v:
            if sev not in NUCLEI_ALLOWED_SEVERITIES:
                raise ValueError(
                    f"Severity '{sev}' is forbidden. "
                    f"Allowed: {sorted(NUCLEI_ALLOWED_SEVERITIES)}"
                )
        return v


class ToolsConfig(BaseModel):
    subfinder: ToolEntry = ToolEntry(path=Path("/usr/bin/subfinder"))
    naabu: ToolEntry = ToolEntry(path=Path("/usr/bin/naabu"))
    nuclei: ToolEntry = ToolEntry(path=Path("/usr/bin/nuclei"))
    whatweb: ToolEntry = ToolEntry(path=Path("/usr/bin/whatweb"))


class ApiKeysConfig(BaseModel):
    shodan: str = ""
    virustotal: str = ""


class AppConfig(BaseModel):
    general: GeneralConfig = GeneralConfig()
    security: SecurityConfig = SecurityConfig()
    rate_limits: RateLimitsConfig = RateLimitsConfig()
    tools: ToolsConfig = ToolsConfig()
    nuclei: NucleiToolConfig = NucleiToolConfig()
    api_keys: ApiKeysConfig = ApiKeysConfig()


def load_config(config_path: Path) -> AppConfig:
    """Load config from YAML, apply env-var overrides, check permissions."""
    if not config_path.exists():
        config = AppConfig()
        _apply_env_overrides(config)
        return config

    # Check file permissions
    _check_permissions(config_path)

    # Parse YAML
    try:
        raw = yaml.safe_load(config_path.read_text())
    except yaml.YAMLError as e:
        raise ConfigLoadError(f"Invalid YAML in {config_path}: {e}")

    if not isinstance(raw, dict):
        raise ConfigLoadError(f"Config file must contain a YAML mapping, got {type(raw)}")

    # Build config from parsed YAML
    config = AppConfig.model_validate(raw)

    # Env var overrides
    _apply_env_overrides(config)

    return config


def _apply_env_overrides(config: AppConfig) -> None:
    """Override API keys from environment variables."""
    shodan_key = os.environ.get("ARGUS_SHODAN_KEY")
    if shodan_key:
        config.api_keys.shodan = shodan_key

    vt_key = os.environ.get("ARGUS_VIRUSTOTAL_KEY")
    if vt_key:
        config.api_keys.virustotal = vt_key


def _check_permissions(config_path: Path) -> None:
    """Warn if config file permissions are too open."""
    try:
        file_stat = config_path.stat()
        mode = file_stat.st_mode
        # Check if group or others have any permissions
        if mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH):
            print(
                f"WARNING: Config file {config_path} has insecure permission "
                f"(mode {oct(mode & 0o777)}). Recommended: chmod 600.",
                file=sys.stderr,
            )
    except OSError:
        pass
