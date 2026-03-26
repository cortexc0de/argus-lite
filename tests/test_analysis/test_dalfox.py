"""TDD: Tests for Dalfox XSS scanner integration."""

from __future__ import annotations

import pytest


class TestParseDalfoxOutput:
    def test_parses_json_findings(self):
        from argus_lite.modules.analysis.dalfox import parse_dalfox_output

        raw = '{"type":"R","data":"https://example.com/search?q=test","param":"q","payload":"<script>alert(1)</script>","evidence":"reflected"}\n'
        findings = parse_dalfox_output(raw)
        assert len(findings) == 1
        assert findings[0].param == "q"
        assert "script" in findings[0].payload

    def test_empty_output(self):
        from argus_lite.modules.analysis.dalfox import parse_dalfox_output

        assert parse_dalfox_output("") == []
        assert parse_dalfox_output("\n\n") == []

    def test_invalid_json_skipped(self):
        from argus_lite.modules.analysis.dalfox import parse_dalfox_output

        raw = "not json\n{\"type\":\"R\",\"data\":\"https://x.com\",\"param\":\"q\",\"payload\":\"x\"}\n"
        findings = parse_dalfox_output(raw)
        assert len(findings) == 1


class TestParseSqlmapOutput:
    def test_parses_findings(self):
        from argus_lite.modules.analysis.sqlmap_scan import parse_sqlmap_output

        raw = """Parameter: id (GET)
    Type: boolean-based blind
    Payload: id=1 AND 1=1

    Type: time-based blind
    Payload: id=1 AND SLEEP(5)

back-end DBMS: MySQL"""
        findings = parse_sqlmap_output(raw, url="https://example.com/page?id=1")
        assert len(findings) >= 1
        assert any(f.type == "boolean-based blind" for f in findings)
        assert any(f.dbms == "MySQL" for f in findings)

    def test_empty_output(self):
        from argus_lite.modules.analysis.sqlmap_scan import parse_sqlmap_output

        assert parse_sqlmap_output("", url="") == []


class TestParseInteractshOutput:
    def test_parses_events(self):
        from argus_lite.modules.analysis.interactsh_oast import parse_interactsh_output

        raw = '[dns] Received DNS interaction from 1.2.3.4 at 2025-01-15\n[http] Received HTTP interaction from 5.6.7.8 at 2025-01-15\n'
        events = parse_interactsh_output(raw)
        assert len(events) == 2
        assert events[0].protocol == "dns"
        assert events[1].protocol == "http"

    def test_empty_output(self):
        from argus_lite.modules.analysis.interactsh_oast import parse_interactsh_output

        assert parse_interactsh_output("") == []


class TestGfPatterns:
    def test_filters_xss_params(self):
        from argus_lite.modules.analysis.gf_patterns import filter_urls_by_pattern

        urls = [
            "https://example.com/search?q=test",
            "https://example.com/page?id=1",
            "https://example.com/api/data",
            "https://example.com/redirect?url=http://evil.com",
        ]
        xss_urls = filter_urls_by_pattern(urls, "xss")
        assert any("q=" in u for u in xss_urls)

    def test_filters_sqli_params(self):
        from argus_lite.modules.analysis.gf_patterns import filter_urls_by_pattern

        urls = [
            "https://example.com/page?id=1",
            "https://example.com/user?name=test",
        ]
        sqli_urls = filter_urls_by_pattern(urls, "sqli")
        assert any("id=" in u for u in sqli_urls)

    def test_unknown_pattern_returns_urls_with_params(self):
        from argus_lite.modules.analysis.gf_patterns import filter_urls_by_pattern

        urls = ["https://example.com/a?x=1", "https://example.com/b?y=2", "https://example.com/c"]
        result = filter_urls_by_pattern(urls, "unknown")
        assert len(result) == 2  # only URLs with query params
