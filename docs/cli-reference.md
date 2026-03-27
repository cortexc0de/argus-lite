# CLI Reference

## Global Entry Points

```bash
argus [COMMAND]       # Main entry point
argus-lite [COMMAND]  # Alias
```

Running `argus` without arguments launches the TUI (Textual-based terminal UI).

---

## `argus scan`

Pipeline-based security scanning.

```bash
argus scan TARGET [OPTIONS]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `TARGET` | string | required | Domain, IP, or URL to scan |
| `--preset` | choice | `quick` | Scan preset: `quick`, `full`, `recon`, `web`, `bulk` |
| `--output` | string | auto | Output file path |
| `--format` | choice | `json` | Report format: `json`, `html`, `md`, `sarif` |
| `--no-cve` | flag | false | Skip CVE correlation |
| `--no-confirm` | flag | false | Skip confirmation prompt |
| `--ai` | flag | false | Enable AI analysis |
| `--tui` | flag | false | Show TUI progress |

---

## `argus agent`

AI-driven autonomous pentesting.

```bash
argus agent TARGET [OPTIONS]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `TARGET` | string | required | Target domain |
| `--max-steps` | int | 8 | Max agent decision loops |
| `--preset` | string | `full` | Base scan preset |
| `--multi-agent` | flag | false | Use 3-agent team |
| `--stealth` | flag | false | Stealth mode |
| `--mission` | choice | `full_assessment` | `full_assessment`, `data_exfiltration`, `admin_access`, `rce` |
| `--skills-dir` | path | none | Custom skills directory |

---

## `argus discover`

Find vulnerable hosts via OSINT APIs.

```bash
argus discover [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--cve` | string | Search by CVE ID |
| `--tech` | string | Search by technology |
| `--service` | string | Search by service name |
| `--port` | int | Search by port number |
| `--country` | string | Filter by country code |
| `--limit` | int | Max results (default: 100) |

---

## `argus bulk`

Multi-target scanning.

```bash
argus bulk [SOURCES...] [OPTIONS]
```

Sources: file paths, CIDR ranges, or API queries.

| Option | Type | Description |
|--------|------|-------------|
| `--shodan` | string | Shodan search query |
| `--censys` | string | Censys search query |
| `--zoomeye` | string | ZoomEye search query |
| `--fofa` | string | FOFA search query |
| `--preset` | string | Scan preset (default: `bulk`) |
| `--max-concurrent` | int | Parallel scans (default: 5) |

---

## `argus monitor`

Continuous monitoring with change detection.

```bash
argus monitor TARGET [OPTIONS]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--interval` | string | `24h` | Check interval |
| `--notify` | flag | false | Send notifications on new findings |

---

## `argus dashboard`

Launch the web dashboard.

```bash
argus dashboard [OPTIONS]
```

Opens at `http://127.0.0.1:8443`.

---

## `argus config ai`

Interactive AI provider configuration.

```bash
argus config ai
```

---

## `argus tools check`

Verify all tool binaries are available.

```bash
argus tools check
```

---

## `argus run`

Execute a YAML scan template.

```bash
argus run TEMPLATE_PATH
```
