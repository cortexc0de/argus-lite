"""Shared test fixtures for Argus Lite."""

import os
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def tmp_config_dir(tmp_path: Path) -> Path:
    """Temporary directory simulating ~/.argus-lite/."""
    config_dir = tmp_path / ".argus-lite"
    config_dir.mkdir()
    return config_dir


@pytest.fixture
def sample_config_yaml(tmp_config_dir: Path) -> Path:
    """Create a sample config.yaml in temp dir."""
    config_file = tmp_config_dir / "config.yaml"
    config_file.write_text(
        """\
general:
  log_level: INFO
  log_dir: /tmp/argus-logs
  scan_dir: /tmp/argus-scans

security:
  require_confirmation: true
  allowlist_only: false
  max_scan_duration_minutes: 120

rate_limits:
  global_rps: 50
  per_target_rps: 10
  concurrent_requests: 5

tools:
  subfinder:
    enabled: true
    path: /usr/bin/subfinder
  naabu:
    enabled: true
    path: /usr/bin/naabu
  nuclei:
    enabled: true
    path: /usr/bin/nuclei
    templates_dir: ~/nuclei-templates
  whatweb:
    enabled: true
    path: /usr/bin/whatweb

api_keys:
  shodan: ""
  virustotal: ""
"""
    )
    os.chmod(config_file, 0o600)
    return config_file


@pytest.fixture
def sample_allowlist(tmp_config_dir: Path) -> Path:
    """Create sample allowlist."""
    allowlist = tmp_config_dir / "allowlist.txt"
    allowlist.write_text("example.com\ntest.local\n192.168.1.100\n")
    return allowlist


@pytest.fixture
def sample_denylist(tmp_config_dir: Path) -> Path:
    """Create sample denylist."""
    denylist = tmp_config_dir / "denylist.txt"
    denylist.write_text("google.com\nfacebook.com\n")
    return denylist


@pytest.fixture
def fixtures_dir() -> Path:
    """Path to test fixtures directory."""
    return Path(__file__).parent / "fixtures"
