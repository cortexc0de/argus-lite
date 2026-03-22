"""TDD: Tests for port scanning — written BEFORE implementation."""

from pathlib import Path

import pytest


@pytest.fixture
def naabu_output(fixtures_dir: Path) -> str:
    return (fixtures_dir / "naabu_output.json").read_text()


class TestNaabuParser:
    def test_parse_port_count(self, naabu_output):
        from argus_lite.modules.analysis.ports import parse_naabu_output

        ports = parse_naabu_output(naabu_output)
        assert len(ports) == 5

    def test_parse_port_80(self, naabu_output):
        from argus_lite.modules.analysis.ports import parse_naabu_output

        ports = parse_naabu_output(naabu_output)
        p80 = [p for p in ports if p.port == 80]
        assert len(p80) == 1
        assert p80[0].protocol == "tcp"

    def test_parse_port_443_tls(self, naabu_output):
        from argus_lite.modules.analysis.ports import parse_naabu_output

        ports = parse_naabu_output(naabu_output)
        p443 = [p for p in ports if p.port == 443]
        assert len(p443) == 1
        assert p443[0].service == "https"

    def test_parse_port_22(self, naabu_output):
        from argus_lite.modules.analysis.ports import parse_naabu_output

        ports = parse_naabu_output(naabu_output)
        p22 = [p for p in ports if p.port == 22]
        assert len(p22) == 1
        assert p22[0].service == "ssh"

    def test_parse_assigns_known_services(self, naabu_output):
        from argus_lite.modules.analysis.ports import parse_naabu_output

        ports = parse_naabu_output(naabu_output)
        services = {p.port: p.service for p in ports}
        assert services[80] == "http"
        assert services[443] == "https"
        assert services[22] == "ssh"
        assert services[8080] == "http-alt"
        assert services[8443] == "https-alt"

    def test_parse_empty_output(self):
        from argus_lite.modules.analysis.ports import parse_naabu_output

        ports = parse_naabu_output("")
        assert ports == []

    def test_parse_invalid_json_line_skipped(self):
        from argus_lite.modules.analysis.ports import parse_naabu_output

        bad = 'not json\n{"host":"x","ip":"1.2.3.4","port":80,"protocol":"tcp","tls":false}\n'
        ports = parse_naabu_output(bad)
        assert len(ports) == 1

    def test_ports_sorted_by_number(self, naabu_output):
        from argus_lite.modules.analysis.ports import parse_naabu_output

        ports = parse_naabu_output(naabu_output)
        port_numbers = [p.port for p in ports]
        assert port_numbers == sorted(port_numbers)


class TestPortScan:
    def test_port_scan_with_mock(self, naabu_output):
        from unittest.mock import AsyncMock, MagicMock

        from argus_lite.core.tool_runner import ToolOutput
        from argus_lite.modules.analysis.ports import port_scan

        mock_runner = MagicMock()
        mock_runner.run = AsyncMock(
            return_value=ToolOutput(
                returncode=0, stdout=naabu_output, stderr="",
                duration_seconds=10.0, command=["naabu"],
            )
        )

        import asyncio
        ports = asyncio.get_event_loop().run_until_complete(
            port_scan("example.com", runner=mock_runner)
        )
        assert len(ports) == 5
