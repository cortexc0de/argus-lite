"""Environment Detection — fingerprint WAF, CDN, rate limits, server type."""

from __future__ import annotations

import logging
import re

import httpx

from pydantic import BaseModel

logger = logging.getLogger(__name__)

# WAF fingerprint signatures: (header_pattern, cookie_pattern, body_pattern) → WAF name
_WAF_SIGNATURES: list[tuple[str, dict[str, str]]] = [
    ("cloudflare", {"header": "cf-ray", "cookie": "__cfduid|cf_clearance", "body": "cloudflare"}),
    ("modsecurity", {"header": "mod_security|modsec", "body": "mod_security|not acceptable", "status": "406"}),
    ("imperva", {"header": "x-cdn|x-iinfo", "cookie": "incap_ses|visid_incap", "body": "imperva|incapsula"}),
    ("akamai", {"header": "x-akamai|akamai-grn", "cookie": "ak_bmsc", "body": "akamai"}),
    ("sucuri", {"header": "x-sucuri", "body": "sucuri|cloudproxy", "cookie": "sucuri"}),
    ("aws_waf", {"header": "x-amz-cf|x-amzn", "body": "aws|amazonaws"}),
    ("f5_bigip", {"header": "x-wa-info|bigipserver", "cookie": "bigipserver"}),
]

# Common user agents for stealth mode
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0",
]


class StealthConfig(BaseModel):
    """Configuration for stealth/evasion mode."""

    enabled: bool = False
    delay_ms: int = 2000
    randomize_headers: bool = True
    rotate_user_agents: bool = True
    max_rps: float = 0.5


def randomize_headers() -> dict[str, str]:
    """Generate randomized HTTP headers to avoid fingerprinting."""
    import random
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": random.choice(["en-US,en;q=0.9", "en-GB,en;q=0.8", "en;q=0.5"]),
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Cache-Control": random.choice(["no-cache", "max-age=0"]),
    }


class EnvironmentProfile(BaseModel):
    """Detected characteristics of the target environment."""

    waf_type: str = ""
    waf_detected: bool = False
    rate_limit_rps: int = 0
    anti_bot: bool = False
    server: str = ""
    cdn: str = ""
    technologies: list[str] = []


class EnvironmentDetector:
    """Detect WAF type, CDN, rate limits from HTTP responses."""

    async def detect(self, target: str) -> EnvironmentProfile:
        """Send probe requests and fingerprint the environment."""
        profile = EnvironmentProfile()

        try:
            async with httpx.AsyncClient(
                timeout=15, follow_redirects=True, verify=False
            ) as client:
                # Normal request
                resp = await client.get(f"https://{target}")
                headers = dict(resp.headers)
                cookies = str(resp.cookies)
                body = resp.text[:2000].lower()
                status = resp.status_code

                # Server detection
                profile.server = headers.get("server", "").lower()

                # WAF detection
                profile.waf_type = self._detect_waf(headers, cookies, body, status)
                profile.waf_detected = bool(profile.waf_type)

                # CDN detection
                profile.cdn = self._detect_cdn(headers)

                # Anti-bot detection
                profile.anti_bot = self._detect_anti_bot(headers, body, cookies)

                # Rate limit probe (send XSS-like request to trigger WAF)
                try:
                    probe_resp = await client.get(
                        f"https://{target}/?test=<script>alert(1)</script>"
                    )
                    if probe_resp.status_code in (403, 406, 429):
                        profile.waf_detected = True
                        if not profile.waf_type:
                            profile.waf_type = self._detect_waf(
                                dict(probe_resp.headers),
                                str(probe_resp.cookies),
                                probe_resp.text[:2000].lower(),
                                probe_resp.status_code,
                            ) or "unknown"
                except Exception:
                    pass

        except Exception as exc:
            logger.debug("Environment detection failed for %s: %s", target, exc)

        return profile

    def _detect_waf(self, headers: dict, cookies: str, body: str, status: int) -> str:
        """Fingerprint WAF from response signatures."""
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        all_headers = " ".join(f"{k}:{v}" for k, v in headers_lower.items())
        cookies_lower = cookies.lower()

        for waf_name, sigs in _WAF_SIGNATURES:
            score = 0
            if "header" in sigs and re.search(sigs["header"], all_headers):
                score += 2
            if "cookie" in sigs and re.search(sigs["cookie"], cookies_lower):
                score += 2
            if "body" in sigs and re.search(sigs["body"], body):
                score += 1
            if "status" in sigs and str(status) == sigs["status"]:
                score += 1
            if score >= 2:
                return waf_name

        return ""

    def _detect_cdn(self, headers: dict) -> str:
        """Detect CDN from headers."""
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        if "cf-ray" in headers_lower:
            return "cloudflare"
        if "x-amz-cf-id" in headers_lower:
            return "cloudfront"
        if "x-fastly-request-id" in headers_lower:
            return "fastly"
        if "x-akamai" in headers_lower or "akamai" in headers_lower.get("server", ""):
            return "akamai"
        return ""

    def _detect_anti_bot(self, headers: dict, body: str, cookies: str) -> bool:
        """Detect anti-bot systems."""
        indicators = [
            "captcha", "recaptcha", "hcaptcha", "challenge",
            "bot-detection", "antibot", "datadome",
        ]
        combined = body + cookies.lower() + " ".join(headers.values()).lower()
        return any(ind in combined for ind in indicators)
