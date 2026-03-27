# Built-in Skills

Argus includes 11 built-in skills that wrap external security tools.

## Reconnaissance Skills

### `enumerate_subdomains`
**Tool:** subfinder | **Availability:** Requires `subfinder` binary

Discovers subdomains using passive sources (crt.sh, web archives, DNS datasets).

```json
{"action": "enumerate_subdomains", "input": {"target": "example.com"}}
```

**Returns:** List of discovered subdomains, stored in `context.scan_result.recon.subdomains`.

---

### `probe_http`
**Tool:** httpx | **Availability:** Requires `httpx` binary

Probes discovered hosts to check which are alive and responding to HTTP.

```json
{"action": "probe_http", "input": {"target": "example.com"}}
```

**Returns:** Live hosts with status codes, titles, content types, server headers.

---

### `crawl_site`
**Tool:** katana | **Availability:** Requires `katana` binary

Crawls the target to discover URLs, endpoints, and parameters.

```json
{"action": "crawl_site", "input": {"target": "example.com"}}
```

**Returns:** Discovered URLs with methods, sources, and attributes.

---

## Analysis Skills

### `scan_nuclei`
**Tool:** nuclei | **Availability:** Requires `nuclei` binary

Scans for known vulnerabilities using Nuclei's template library.

```json
{"action": "scan_nuclei", "input": {"target": "https://example.com"}}
```

**Returns:** Findings converted to `Finding` objects with proper severity levels.

---

### `fuzz_paths`
**Tool:** ffuf | **Availability:** Requires `ffuf` binary

Brute-forces directories and files to discover hidden content.

```json
{"action": "fuzz_paths", "input": {"target": "https://example.com"}}
```

**Returns:** Discovered paths. Sensitive paths (`/admin`, `/.git`, `/.env`) automatically flagged as findings.

---

### `scan_xss`
**Tool:** dalfox | **Availability:** Requires `dalfox` binary | **Severity:** MEDIUM

Tests for Cross-Site Scripting (reflected, stored, DOM-based).

```json
{"action": "scan_xss", "input": {"target": "https://example.com", "urls": ["https://example.com/search?q=test"]}}
```

---

### `scan_sqli`
**Tool:** sqlmap | **Availability:** Requires `sqlmap` binary | **Severity:** HIGH

Tests for SQL injection vulnerabilities.

```json
{"action": "scan_sqli", "input": {"url": "https://example.com/api/user?id=1"}}
```

---

### `check_headers`
**Tool:** httpx (built-in) | **Availability:** Always available

Analyzes HTTP security headers (HSTS, CSP, X-Frame-Options, etc.).

```json
{"action": "check_headers", "input": {"target": "example.com"}}
```

**Returns:** List of missing security headers as findings.

---

### `detect_tech`
**Tool:** whatweb | **Availability:** Requires `whatweb` binary

Identifies technologies (CMS, framework, server, programming language).

```json
{"action": "detect_tech", "input": {"target": "example.com"}}
```

---

### `scan_ports`
**Tool:** naabu | **Availability:** Requires `naabu` binary

Scans for open TCP ports.

```json
{"action": "scan_ports", "input": {"target": "example.com"}}
```

---

### `test_payload`
**Tool:** httpx (built-in) | **Availability:** Always available

Sends custom HTTP requests with specific payloads. Detects reflection and error signatures.

```json
{
  "action": "test_payload",
  "input": {
    "url": "https://example.com/search",
    "param": "q",
    "payload": "<script>alert(1)</script>",
    "method": "GET"
  }
}
```

**Returns:** Status code, content length, whether payload was reflected, body preview.
