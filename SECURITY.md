# Security Policy

## Responsible Use

Argus is designed exclusively for **authorized security testing**. Always obtain written permission before scanning any target. Unauthorized scanning is illegal in most jurisdictions.

## Reporting a Vulnerability

If you discover a security vulnerability in Argus itself (not in targets you're scanning), please report it responsibly:

1. **Do NOT** open a public GitHub issue
2. Email: **c0rtexc0de@proton.me**
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## Response Timeline

| Action | Timeline |
|--------|----------|
| Acknowledgment | 48 hours |
| Initial assessment | 5 business days |
| Fix development | 14 business days |
| Public disclosure | After fix is released |

## Scope

In scope:
- Command injection via crafted input
- Path traversal in report generation
- Credential exposure in logs/reports
- Dependency vulnerabilities

Out of scope:
- Issues in external tools (nuclei, sqlmap, etc.) — report upstream
- Social engineering
- Denial of service against Argus itself

## Supported Versions

| Version | Supported |
|---------|-----------|
| 6.x     | Yes       |
| 5.x     | Security fixes only |
| < 5.0   | No        |
