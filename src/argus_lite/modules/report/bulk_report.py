"""Bulk scan HTML summary report generator."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Template

from argus_lite.models.bulk import BulkScanResult

_BULK_TEMPLATE = Template("""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Argus — Bulk Scan {{ bulk.bulk_id[:8] }}</title>
<style>
  :root { --bg:#0d1117;--card:#161b22;--border:#30363d;--text:#e6edf3;--dim:#8b949e;--accent:#58a6ff;--green:#3fb950;--yellow:#d29922;--red:#f85149; }
  * { box-sizing:border-box;margin:0;padding:0; }
  body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--text);line-height:1.6; }
  .container { max-width:1200px;margin:0 auto;padding:30px 20px; }
  h1 { font-size:26px;font-weight:600;margin-bottom:8px; }
  h1 span { color:var(--accent); }
  h2 { font-size:18px;font-weight:600;margin:28px 0 12px; }
  .meta { color:var(--dim);font-size:13px;margin-bottom:24px; }
  .cards { display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:28px; }
  .card { background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px;text-align:center; }
  .card .num { font-size:32px;font-weight:700;color:var(--accent); }
  .card .num.warn { color:var(--yellow); }
  .card .num.danger { color:var(--red); }
  .card .num.ok { color:var(--green); }
  .card .label { font-size:12px;color:var(--dim);margin-top:4px; }
  table { width:100%;border-collapse:collapse;margin-bottom:20px; }
  th { text-align:left;padding:10px 14px;background:var(--card);color:var(--dim);font-size:12px;text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--border); }
  td { padding:10px 14px;border-bottom:1px solid var(--border);font-size:14px;vertical-align:middle; }
  tr:hover td { background:rgba(110,118,129,.05); }
  .badge { display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600;text-transform:uppercase; }
  .badge-none,.badge-ok { background:rgba(63,185,80,.15);color:var(--green); }
  .badge-low { background:rgba(88,166,255,.15);color:var(--accent); }
  .badge-medium { background:rgba(210,153,34,.15);color:var(--yellow); }
  .badge-high { background:rgba(248,81,73,.15);color:var(--red); }
  .badge-failed { background:rgba(248,81,73,.1);color:var(--red); }
  code { background:#1c2128;padding:1px 6px;border-radius:4px;font-size:12px; }
  a { color:var(--accent);text-decoration:none; }
  a:hover { text-decoration:underline; }
  .section { background:var(--card);border:1px solid var(--border);border-radius:10px;padding:20px 24px;margin-bottom:20px; }
  .legal { margin-top:32px;padding:14px 18px;background:rgba(210,153,34,.08);border:1px solid rgba(210,153,34,.2);border-radius:8px;color:var(--dim);font-size:12px; }
  .footer { text-align:center;color:var(--dim);font-size:12px;margin-top:16px;padding:16px; }
</style>
</head>
<body>
<div class="container">

<h1>Bulk Scan — <span>{{ bulk.sources | join(', ') | truncate(60) }}</span></h1>
<div class="meta">
  ID: <code>{{ bulk.bulk_id }}</code> &nbsp;·&nbsp;
  Preset: {{ bulk.preset }} &nbsp;·&nbsp;
  {% if bulk.started_at %}{{ bulk.started_at.strftime('%Y-%m-%d %H:%M UTC') }}{% endif %}
  {% if bulk.completed_at %}&nbsp;·&nbsp;{{ ((bulk.completed_at - bulk.started_at).seconds // 60) }}m {{ ((bulk.completed_at - bulk.started_at).seconds % 60) }}s{% endif %}
</div>

<!-- Summary Cards -->
<div class="cards">
  <div class="card"><div class="num">{{ s.total_targets }}</div><div class="label">Targets</div></div>
  <div class="card"><div class="num ok">{{ s.completed }}</div><div class="label">Completed</div></div>
  {% if s.failed > 0 %}<div class="card"><div class="num danger">{{ s.failed }}</div><div class="label">Failed</div></div>{% endif %}
  <div class="card"><div class="num">{{ s.live_hosts }}</div><div class="label">Live Hosts</div></div>
  <div class="card"><div class="num {{ 'warn' if s.total_findings > 0 else 'ok' }}">{{ s.total_findings }}</div><div class="label">Findings</div></div>
  <div class="card"><div class="num {{ 'warn' if s.total_vulnerabilities > 0 else 'ok' }}">{{ s.total_vulnerabilities }}</div><div class="label">CVEs</div></div>
  <div class="card">
    <div class="num {{ 'danger' if s.highest_risk == 'HIGH' else 'warn' if s.highest_risk in ('MEDIUM','LOW') else 'ok' }}">{{ s.highest_risk }}</div>
    <div class="label">Highest Risk</div>
  </div>
</div>

<!-- Per-Host Table -->
<div class="section">
  <h2>Scanned Hosts</h2>
  <table>
    <thead>
      <tr><th>Host</th><th>Status</th><th>Risk</th><th>Findings</th><th>CVEs</th><th>Technologies</th><th>Report</th></tr>
    </thead>
    <tbody>
    {% for r in bulk.scan_results %}
    {% set risk = r.risk_summary.risk_level if r.risk_summary else 'NONE' %}
    <tr>
      <td><code>{{ r.target }}</code></td>
      <td><span class="badge badge-ok">{{ r.status }}</span></td>
      <td><span class="badge badge-{{ risk | lower }}">{{ risk }}</span></td>
      <td>{{ r.findings | length }}</td>
      <td>{{ r.vulnerabilities | length }}</td>
      <td>{{ r.analysis.technologies | map(attribute='name') | join(', ') or '—' }}</td>
      <td><a href="{{ r.target }}/report.html">view</a></td>
    </tr>
    {% endfor %}
    {% for t in bulk.failed_targets %}
    <tr>
      <td><code>{{ t }}</code></td>
      <td><span class="badge badge-failed">FAILED</span></td>
      <td>—</td><td>—</td><td>—</td><td>—</td><td>—</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
</div>

<!-- Technology Distribution -->
{% if s.technologies_seen %}
<div class="section">
  <h2>Technologies Detected</h2>
  <div style="display:flex;flex-wrap:wrap;gap:8px;">
  {% for tech in s.technologies_seen %}
    <span style="background:rgba(88,166,255,.12);border:1px solid rgba(88,166,255,.25);padding:4px 12px;border-radius:16px;font-size:13px;">{{ tech }}</span>
  {% endfor %}
  </div>
</div>
{% endif %}

<!-- Top CVEs (found on multiple hosts) -->
{% if s.top_cves %}
<div class="section">
  <h2>CVEs Found on Multiple Hosts</h2>
  <div style="display:flex;flex-wrap:wrap;gap:8px;">
  {% for cve in s.top_cves %}
    <a href="https://nvd.nist.gov/vuln/detail/{{ cve }}" target="_blank"
       style="background:rgba(248,81,73,.1);border:1px solid rgba(248,81,73,.25);padding:4px 12px;border-radius:16px;font-size:13px;color:var(--red);">{{ cve }}</a>
  {% endfor %}
  </div>
</div>
{% endif %}

<div class="legal">LEGAL NOTICE: This report was generated by Argus Lite for authorized security testing only. Always obtain written permission before scanning any system you do not own.</div>
<div class="footer">Generated by Argus Lite — Bulk Scan</div>
</div>
</body>
</html>
""")


def generate_bulk_summary_html(bulk: BulkScanResult) -> str:
    """Generate a combined HTML summary report for a bulk scan."""
    return _BULK_TEMPLATE.render(bulk=bulk, s=bulk.summary)


def write_bulk_report(bulk: BulkScanResult, output_dir: Path) -> None:
    """Write summary.html to output_dir."""
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "summary.html").write_text(generate_bulk_summary_html(bulk))
