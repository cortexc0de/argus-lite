"""Skill System — formal abstraction layer between AI Agent and tools.

Each Skill wraps an existing tool module with a uniform interface:
  execute(params, context) → SkillResult

The SkillRegistry manages available skills and generates LLM tool descriptions.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from argus_lite.core.config import AppConfig
from argus_lite.core.tool_runner import BaseToolRunner
from argus_lite.models.finding import SENSITIVE_PATHS, Finding, nuclei_finding_to_finding

if TYPE_CHECKING:
    from argus_lite.core.agent_context import AgentContext

logger = logging.getLogger(__name__)


@dataclass
class SkillResult:
    """Result of executing a skill."""

    success: bool
    data: dict = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    summary: str = ""
    error: str = ""


class Skill(ABC):
    """Abstract base for all agent skills."""

    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def description(self) -> str: ...

    @abstractmethod
    async def execute(self, params: dict, context: AgentContext) -> SkillResult: ...

    def is_available(self) -> bool:
        return True


class SkillRegistry:
    """Manages available skills for the agent."""

    def __init__(self) -> None:
        self._skills: dict[str, Skill] = {}

    def register(self, skill: Skill) -> None:
        self._skills[skill.name] = skill

    def get(self, name: str) -> Skill | None:
        return self._skills.get(name)

    def list_available(self) -> list[Skill]:
        return [s for s in self._skills.values() if s.is_available()]

    def to_llm_description(self) -> str:
        """Generate skill list for LLM system prompt."""
        lines = []
        for s in self.list_available():
            lines.append(f"- {s.name}: {s.description}")
        return "\n".join(lines)

    async def execute(self, name: str, params: dict, context: AgentContext) -> SkillResult:
        """Execute a skill by name."""
        skill = self.get(name)
        if skill is None:
            return SkillResult(success=False, error=f"Unknown skill: {name}")
        if not skill.is_available():
            return SkillResult(success=False, error=f"Skill not available: {name}")
        try:
            return await skill.execute(params, context)
        except Exception as exc:
            logger.warning("Skill '%s' failed: %s", name, exc)
            return SkillResult(success=False, error=str(exc))


# ── Skill Implementations ──


class EnumerateSubdomainsSkill(Skill):
    name = "enumerate_subdomains"
    description = "Find subdomains using subfinder"

    def __init__(self, config: AppConfig) -> None:
        self._config = config

    def is_available(self) -> bool:
        runner = BaseToolRunner("subfinder", str(self._config.tools.subfinder.path))
        return runner.check_available()

    async def execute(self, params: dict, context: AgentContext) -> SkillResult:
        from argus_lite.modules.recon.subdomains import subdomain_enumerate

        target = params.get("target", context.target)
        runner = BaseToolRunner("subfinder", str(self._config.tools.subfinder.path))
        subs = await subdomain_enumerate(target, runner=runner)
        context.scan_result.recon.subdomains = subs
        return SkillResult(
            success=True,
            data={"count": len(subs), "subdomains": [s.name for s in subs[:20]]},
            summary=f"Found {len(subs)} subdomains for {target}",
        )


class ProbeHttpSkill(Skill):
    name = "probe_http"
    description = "Check which hosts are alive via HTTP probing"

    def __init__(self, config: AppConfig) -> None:
        self._config = config

    def is_available(self) -> bool:
        runner = BaseToolRunner("httpx", str(self._config.tools.httpx_tool.path))
        return runner.check_available()

    async def execute(self, params: dict, context: AgentContext) -> SkillResult:
        from argus_lite.modules.recon.httpx_probe import httpx_probe

        target = params.get("target", context.target)
        runner = BaseToolRunner("httpx", str(self._config.tools.httpx_tool.path))
        probes = await httpx_probe(target, runner=runner)
        context.scan_result.recon.http_probes = probes
        return SkillResult(
            success=True,
            data={"count": len(probes), "urls": [p.url for p in probes[:10]]},
            summary=f"Probed {len(probes)} live hosts",
        )


class CrawlSiteSkill(Skill):
    name = "crawl_site"
    description = "Discover URLs and endpoints by crawling the target"

    def __init__(self, config: AppConfig) -> None:
        self._config = config

    def is_available(self) -> bool:
        runner = BaseToolRunner("katana", str(self._config.tools.katana.path))
        return runner.check_available()

    async def execute(self, params: dict, context: AgentContext) -> SkillResult:
        from argus_lite.modules.recon.katana_crawl import katana_crawl

        target = params.get("target", context.target)
        runner = BaseToolRunner("katana", str(self._config.tools.katana.path))
        results = await katana_crawl(target, runner=runner)
        context.scan_result.recon.crawl_results = results
        return SkillResult(
            success=True,
            data={"count": len(results), "urls": [c.url for c in results[:20]]},
            summary=f"Crawled {len(results)} URLs from {target}",
        )


class ScanNucleiSkill(Skill):
    name = "scan_nuclei"
    description = "Scan for known vulnerabilities using Nuclei templates"

    def __init__(self, config: AppConfig) -> None:
        self._config = config

    def is_available(self) -> bool:
        runner = BaseToolRunner("nuclei", str(self._config.tools.nuclei.path))
        return runner.check_available()

    async def execute(self, params: dict, context: AgentContext) -> SkillResult:
        from argus_lite.modules.analysis.nuclei import nuclei_scan

        target = params.get("target", f"https://{context.target}")
        runner = BaseToolRunner("nuclei", str(self._config.tools.nuclei.path))
        nuclei_findings = await nuclei_scan(target, runner=runner)
        context.scan_result.analysis.nuclei_findings.extend(nuclei_findings)
        converted = [nuclei_finding_to_finding(nf, target) for nf in nuclei_findings]
        return SkillResult(
            success=True,
            data={"count": len(nuclei_findings)},
            findings=converted,
            summary=f"Nuclei found {len(nuclei_findings)} results on {target}",
        )


class FuzzPathsSkill(Skill):
    name = "fuzz_paths"
    description = "Brute-force directories and files using ffuf"

    def __init__(self, config: AppConfig) -> None:
        self._config = config

    def is_available(self) -> bool:
        runner = BaseToolRunner("ffuf", str(self._config.tools.ffuf.path))
        return runner.check_available()

    async def execute(self, params: dict, context: AgentContext) -> SkillResult:
        from argus_lite.modules.analysis.ffuf_fuzz import ffuf_scan

        target = params.get("target", f"https://{context.target}")
        runner = BaseToolRunner("ffuf", str(self._config.tools.ffuf.path))
        results = await ffuf_scan(target, runner=runner)
        context.scan_result.analysis.fuzz_results.extend(results)
        _SENSITIVE = SENSITIVE_PATHS
        converted = [
            Finding(
                id=f"fuzz-{r.url}", type="sensitive_path", severity="LOW",
                title=f"Sensitive path: {r.url}", description=f"HTTP {r.status_code} at {r.url}",
                asset=target, evidence=f"Status: {r.status_code}, Length: {r.content_length}",
                source="ffuf", remediation="Restrict access or remove sensitive endpoint",
            )
            for r in results
            if r.status_code in (200, 301, 302, 403)
            and any(kw in r.url.lower() for kw in _SENSITIVE)
        ]
        return SkillResult(
            success=True,
            data={"count": len(results), "paths": [r.url for r in results[:10]]},
            findings=converted,
            summary=f"Fuzzed {len(results)} paths on {target}",
        )


class ScanXssSkill(Skill):
    name = "scan_xss"
    description = "Test for XSS vulnerabilities using Dalfox"

    def __init__(self, config: AppConfig) -> None:
        self._config = config

    def is_available(self) -> bool:
        runner = BaseToolRunner("dalfox", str(self._config.tools.dalfox.path))
        return runner.check_available()

    async def execute(self, params: dict, context: AgentContext) -> SkillResult:
        from argus_lite.modules.analysis.dalfox import dalfox_scan

        target = params.get("target", f"https://{context.target}")
        urls = params.get("urls", [target])
        runner = BaseToolRunner("dalfox", str(self._config.tools.dalfox.path))
        findings = await dalfox_scan(target, runner=runner, urls=urls if len(urls) > 1 else None)
        context.scan_result.analysis.xss_findings.extend(findings)
        xss_findings = [
            Finding(id=f"xss-{f.param}", type="xss", severity="MEDIUM",
                    title=f"XSS ({f.type}) in '{f.param}'", description=f.evidence,
                    asset=f.url, evidence=f.payload[:100], source="dalfox",
                    remediation="Sanitize input, implement CSP")
            for f in findings
        ]
        return SkillResult(
            success=True, data={"count": len(findings)},
            findings=xss_findings,
            summary=f"Dalfox found {len(findings)} XSS on {target}",
        )


class ScanSqliSkill(Skill):
    name = "scan_sqli"
    description = "Test for SQL injection using SQLMap"

    def __init__(self, config: AppConfig) -> None:
        self._config = config

    def is_available(self) -> bool:
        runner = BaseToolRunner("sqlmap", str(self._config.tools.sqlmap.path))
        return runner.check_available()

    async def execute(self, params: dict, context: AgentContext) -> SkillResult:
        from argus_lite.modules.analysis.sqlmap_scan import sqlmap_scan

        url = params.get("url", f"https://{context.target}")
        runner = BaseToolRunner("sqlmap", str(self._config.tools.sqlmap.path))
        findings = await sqlmap_scan(url, runner=runner)
        context.scan_result.analysis.sqli_findings.extend(findings)
        sqli_findings = [
            Finding(id=f"sqli-{f.param}", type="sqli", severity="HIGH",
                    title=f"SQLi ({f.type}) in '{f.param}'", description=f"DBMS: {f.dbms}",
                    asset=f.url, evidence=f.payload[:100], source="sqlmap",
                    remediation="Use parameterized queries")
            for f in findings
        ]
        return SkillResult(
            success=True, data={"count": len(findings)},
            findings=sqli_findings,
            summary=f"SQLMap found {len(findings)} injections",
        )


class CheckHeadersSkill(Skill):
    name = "check_headers"
    description = "Analyze HTTP security headers"

    async def execute(self, params: dict, context: AgentContext) -> SkillResult:
        import httpx as _httpx

        from argus_lite.modules.analysis.security_headers import (
            analyze_security_headers,
            security_headers_findings,
        )

        target = params.get("target", context.target)
        try:
            async with _httpx.AsyncClient(follow_redirects=True, timeout=20) as client:
                resp = await client.head(f"https://{target}")
                raw = f"HTTP/{resp.http_version} {resp.status_code}\n"
                raw += "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
                result = analyze_security_headers(raw)
                findings = security_headers_findings(raw, asset=target)
                return SkillResult(
                    success=True,
                    data={"missing": result.missing_headers},
                    findings=findings,
                    summary=f"{len(result.missing_headers)} missing security headers",
                )
        except Exception as exc:
            return SkillResult(success=False, error=str(exc))


class DetectTechSkill(Skill):
    name = "detect_tech"
    description = "Identify technologies (CMS, framework, server) using whatweb"

    def __init__(self, config: AppConfig) -> None:
        self._config = config

    def is_available(self) -> bool:
        runner = BaseToolRunner("whatweb", str(self._config.tools.whatweb.path))
        return runner.check_available()

    async def execute(self, params: dict, context: AgentContext) -> SkillResult:
        from argus_lite.modules.analysis.techstack import tech_scan

        target = params.get("target", context.target)
        runner = BaseToolRunner("whatweb", str(self._config.tools.whatweb.path))
        techs = await tech_scan(target, runner=runner)
        context.scan_result.analysis.technologies = techs
        return SkillResult(
            success=True,
            data={"technologies": [{"name": t.name, "version": t.version} for t in techs]},
            summary=f"Detected {len(techs)} technologies: {', '.join(t.name for t in techs[:5])}",
        )


class ScanPortsSkill(Skill):
    name = "scan_ports"
    description = "Scan for open TCP ports using naabu"

    def __init__(self, config: AppConfig) -> None:
        self._config = config

    def is_available(self) -> bool:
        runner = BaseToolRunner("naabu", str(self._config.tools.naabu.path))
        return runner.check_available()

    async def execute(self, params: dict, context: AgentContext) -> SkillResult:
        from argus_lite.modules.analysis.ports import port_scan

        target = params.get("target", context.target)
        runner = BaseToolRunner("naabu", str(self._config.tools.naabu.path))
        ports = await port_scan(target, runner=runner)
        context.scan_result.analysis.open_ports = ports
        return SkillResult(
            success=True,
            data={"ports": [{"port": p.port, "service": p.service} for p in ports]},
            summary=f"Found {len(ports)} open ports: {', '.join(str(p.port) for p in ports[:10])}",
        )


class TestPayloadSkill(Skill):
    name = "test_payload"
    description = "Send a custom HTTP request with a specific payload and analyze the response"

    async def execute(self, params: dict, context: AgentContext) -> SkillResult:
        import httpx as _httpx

        url = params.get("url", f"https://{context.target}")
        method = params.get("method", "GET").upper()
        payload = params.get("payload", "")
        param_name = params.get("param", "")

        if param_name and payload:
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}{param_name}={payload}"

        try:
            async with _httpx.AsyncClient(follow_redirects=False, timeout=15, verify=False) as client:
                if method == "POST":
                    resp = await client.post(url, data={param_name: payload} if param_name else None)
                else:
                    resp = await client.get(url)

                body_preview = resp.text[:500]
                reflected = payload in body_preview if payload else False

                return SkillResult(
                    success=True,
                    data={
                        "status_code": resp.status_code,
                        "content_length": len(resp.content),
                        "reflected": reflected,
                        "body_preview": body_preview[:200],
                        "headers": dict(resp.headers),
                    },
                    summary=f"HTTP {resp.status_code}, {len(resp.content)} bytes, reflected={reflected}",
                )
        except Exception as exc:
            return SkillResult(success=False, error=str(exc))


class BrowseTargetSkill(Skill):
    name = "browse_target"
    description = "Open target in headless browser, capture API calls, extract JS endpoints, get cookies"

    def is_available(self) -> bool:
        from argus_lite.core.browser import BrowserAgent
        return BrowserAgent.is_available()

    async def execute(self, params: dict, context: AgentContext) -> SkillResult:
        from argus_lite.core.browser import BrowserAgent

        target = params.get("target", f"https://{context.target}")
        browser = BrowserAgent()
        try:
            await browser.start(headless=True)
            status = await browser.navigate(target)
            api_calls = browser.get_api_calls()
            cookies = await browser.get_cookies()
            inputs = await browser.get_dom_inputs()
            js_endpoints = await browser.get_js_endpoints()

            return SkillResult(
                success=True,
                data={
                    "status": status,
                    "api_calls": [{"method": c.method, "url": c.url} for c in api_calls[:20]],
                    "cookies": [{"name": c["name"], "domain": c.get("domain", "")} for c in cookies],
                    "inputs": inputs[:20],
                    "js_endpoints": js_endpoints[:20],
                },
                summary=f"Browser: {len(api_calls)} API calls, {len(cookies)} cookies, {len(inputs)} inputs, {len(js_endpoints)} JS endpoints",
            )
        except Exception as exc:
            return SkillResult(success=False, error=str(exc))
        finally:
            await browser.close()


class GraphQLIntrospectSkill(Skill):
    name = "graphql_introspect"
    description = "Send GraphQL introspection query to discover schema, types, and queries"

    async def execute(self, params: dict, context: AgentContext) -> SkillResult:
        import httpx as _httpx

        target = params.get("target", f"https://{context.target}")
        endpoint = params.get("endpoint", f"{target}/graphql")
        query = {"query": '{ __schema { types { name fields { name type { name } } } queryType { name } mutationType { name } } }'}

        try:
            async with _httpx.AsyncClient(timeout=20, verify=False) as client:
                resp = await client.post(endpoint, json=query)
                data = resp.json()

                if "errors" in data and not data.get("data"):
                    return SkillResult(success=False, error=f"Introspection disabled: {data['errors'][0].get('message', '')}")

                schema = data.get("data", {}).get("__schema", {})
                types = schema.get("types", [])
                user_types = [t for t in types if not t["name"].startswith("__")]
                query_type = schema.get("queryType", {}).get("name", "")
                mutation_type = schema.get("mutationType", {})

                # Find types with ID fields (IDOR candidates)
                idor_candidates = []
                for t in user_types:
                    for f in (t.get("fields") or []):
                        if f["name"].lower() in ("id", "userid", "user_id", "accountid"):
                            idor_candidates.append(f"{t['name']}.{f['name']}")

                return SkillResult(
                    success=True,
                    data={
                        "types_count": len(user_types),
                        "type_names": [t["name"] for t in user_types[:20]],
                        "query_type": query_type,
                        "has_mutations": mutation_type is not None,
                        "idor_candidates": idor_candidates,
                    },
                    summary=f"GraphQL: {len(user_types)} types, {len(idor_candidates)} IDOR candidates",
                )
        except Exception as exc:
            return SkillResult(success=False, error=str(exc))


class TestWebSocketSkill(Skill):
    name = "test_websocket"
    description = "Connect to WebSocket endpoint, send test payloads, analyze responses"

    async def execute(self, params: dict, context: AgentContext) -> SkillResult:
        import asyncio

        target = params.get("target", context.target)
        ws_url = params.get("ws_url", f"wss://{target}/ws")
        payloads = params.get("payloads", ["ping", '{"type":"subscribe","channel":"test"}'])

        try:
            import websockets  # noqa: F401
        except ImportError:
            return SkillResult(success=False, error="websockets package not installed")

        import websockets

        results: list[dict] = []
        try:
            async with websockets.connect(ws_url, open_timeout=10) as ws:
                for payload in payloads[:5]:
                    await ws.send(payload)
                    try:
                        response = await asyncio.wait_for(ws.recv(), timeout=5)
                        results.append({"sent": payload, "received": str(response)[:200]})
                    except asyncio.TimeoutError:
                        results.append({"sent": payload, "received": "(timeout)"})

            return SkillResult(
                success=True,
                data={"exchanges": results, "ws_url": ws_url},
                summary=f"WebSocket: {len(results)} exchanges on {ws_url}",
            )
        except Exception as exc:
            return SkillResult(success=False, error=f"WebSocket failed: {exc}")


def build_skill_registry(
    config: AppConfig,
    skill_dirs: list["Path"] | None = None,
) -> SkillRegistry:
    """Build a SkillRegistry with all available skills.

    Args:
        config: Application config.
        skill_dirs: Optional list of directories containing .md custom skills.
                    If None, loads from config.skills.dirs.
    """
    from pathlib import Path

    from argus_lite.core.skill_loader import register_markdown_skills

    registry = SkillRegistry()
    registry.register(EnumerateSubdomainsSkill(config))
    registry.register(ProbeHttpSkill(config))
    registry.register(CrawlSiteSkill(config))
    registry.register(ScanNucleiSkill(config))
    registry.register(FuzzPathsSkill(config))
    registry.register(ScanXssSkill(config))
    registry.register(ScanSqliSkill(config))
    registry.register(CheckHeadersSkill())
    registry.register(DetectTechSkill(config))
    registry.register(ScanPortsSkill(config))
    registry.register(TestPayloadSkill())
    registry.register(BrowseTargetSkill())
    registry.register(GraphQLIntrospectSkill())
    registry.register(TestWebSocketSkill())

    # Load custom .md skills
    dirs = skill_dirs or [Path(d).expanduser() for d in config.skills.dirs]
    if dirs:
        count = register_markdown_skills(registry, dirs)
        if count:
            logger.info("Loaded %d custom markdown skills", count)

    return registry
