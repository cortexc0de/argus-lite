"""Argus web dashboard v2 — scan history, risk trends, API, compare."""

from __future__ import annotations

import json
from pathlib import Path

from flask import Flask, abort, jsonify, request


def create_app(argus_home: str) -> Flask:
    """Create Flask app for the dashboard."""
    app = Flask(__name__)
    home = Path(argus_home)
    scans_dir = home / "scans"

    # ── HTML Routes ──

    @app.route("/")
    def index():
        scans = _list_scans(scans_dir)
        total = len(scans)
        risks = {"NONE": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0}
        total_findings = 0
        for s in scans:
            rs = s.get("risk_summary") or {}
            rl = rs.get("risk_level", "NONE")
            risks[rl] = risks.get(rl, 0) + 1
            total_findings += len(s.get("findings", []))

        rows = ""
        for s in scans:
            sid = s.get("scan_id", "")
            target = s.get("target", "?")
            status = s.get("status", "?")
            date = (s.get("started_at", "") or "")[:16].replace("T", " ")
            fc = len(s.get("findings", []))
            rs = s.get("risk_summary") or {}
            rl = rs.get("risk_level", "NONE")
            score = rs.get("overall_score", 0)
            rc = {"NONE": "#3fb950", "LOW": "#58a6ff", "MEDIUM": "#d29922", "HIGH": "#f85149"}.get(rl, "#8b949e")
            tools = ", ".join(s.get("tools_used", [])[:5])
            rows += f"""<tr onclick="window.location='/report/{sid}'" style="cursor:pointer">
              <td><code>{sid[:8]}</code></td><td><strong>{target}</strong></td>
              <td>{status}</td><td>{date}</td><td>{fc}</td>
              <td><span style="color:{rc};font-weight:600">{rl}</span> <span style="color:#8b949e;font-size:12px">({score})</span></td>
              <td style="color:#8b949e;font-size:12px">{tools}</td>
            </tr>"""

        return _DASHBOARD_HTML.format(
            total=total,
            findings=total_findings,
            risk_none=risks["NONE"],
            risk_low=risks["LOW"],
            risk_med=risks["MEDIUM"],
            risk_high=risks["HIGH"],
            rows=rows or '<tr><td colspan="7" style="text-align:center;color:#8b949e;padding:40px">No scans found. Run: argus scan &lt;target&gt;</td></tr>',
        )

    @app.route("/report/<scan_id>")
    def view_report(scan_id: str):
        report = scans_dir / scan_id / "report" / "report.html"
        if not report.exists():
            abort(404)
        return report.read_text()

    # ── REST API ──

    @app.route("/api/scans")
    def api_scans():
        return jsonify(_list_scans(scans_dir))

    @app.route("/api/scans/<scan_id>")
    def api_scan_detail(scan_id: str):
        data = _load_scan(scans_dir / scan_id)
        if data is None:
            abort(404)
        return jsonify(data)

    @app.route("/api/scans/<scan_id>/findings")
    def api_scan_findings(scan_id: str):
        data = _load_scan(scans_dir / scan_id)
        if data is None:
            abort(404)
        return jsonify(data.get("findings", []))

    @app.route("/api/compare")
    def api_compare():
        """Compare two scans: /api/compare?a=SCAN_ID_1&b=SCAN_ID_2."""
        id_a = request.args.get("a", "")
        id_b = request.args.get("b", "")
        if not id_a or not id_b:
            return jsonify({"error": "Provide ?a=SCAN_ID&b=SCAN_ID"}), 400

        scan_a = _load_scan(scans_dir / id_a)
        scan_b = _load_scan(scans_dir / id_b)
        if not scan_a or not scan_b:
            abort(404)

        findings_a = {f.get("title", "") for f in scan_a.get("findings", [])}
        findings_b = {f.get("title", "") for f in scan_b.get("findings", [])}

        return jsonify({
            "scan_a": id_a,
            "scan_b": id_b,
            "new_in_b": sorted(findings_b - findings_a),
            "resolved_in_b": sorted(findings_a - findings_b),
            "unchanged": sorted(findings_a & findings_b),
        })

    @app.route("/api/stats")
    def api_stats():
        scans = _list_scans(scans_dir)
        risks = {}
        for s in scans:
            rl = (s.get("risk_summary") or {}).get("risk_level", "NONE")
            risks[rl] = risks.get(rl, 0) + 1
        return jsonify({
            "total_scans": len(scans),
            "total_findings": sum(len(s.get("findings", [])) for s in scans),
            "risk_distribution": risks,
        })

    return app


# ── Helpers ──

def _list_scans(scans_dir: Path) -> list[dict]:
    if not scans_dir.is_dir():
        return []
    scans = []
    for scan_dir in sorted(scans_dir.iterdir(), reverse=True):
        if not scan_dir.is_dir():
            continue
        data = _load_scan(scan_dir)
        if data:
            scans.append(data)
    return scans


def _load_scan(scan_dir: Path) -> dict | None:
    partial = scan_dir / "partial.json"
    if not partial.exists():
        return None
    try:
        return json.loads(partial.read_text())
    except (json.JSONDecodeError, OSError):
        return None


# ── Dashboard HTML Template ──

_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Argus Dashboard</title>
<style>
  :root {{ --bg:#0d1117;--card:#161b22;--border:#30363d;--text:#e6edf3;--dim:#8b949e;--accent:#58a6ff;--green:#3fb950;--yellow:#d29922;--red:#f85149; }}
  * {{ box-sizing:border-box;margin:0;padding:0; }}
  body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--text);line-height:1.6; }}
  .container {{ max-width:1200px;margin:0 auto;padding:30px 20px; }}
  h1 {{ font-size:28px;margin-bottom:24px; }}
  h1 span {{ color:var(--accent); }}
  .cards {{ display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:28px; }}
  .card {{ background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px;text-align:center; }}
  .card .num {{ font-size:32px;font-weight:700; }}
  .card .label {{ font-size:12px;color:var(--dim);margin-top:4px; }}
  table {{ width:100%;border-collapse:collapse; }}
  th {{ text-align:left;padding:10px 12px;background:rgba(110,118,129,.08);color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:.5px; }}
  td {{ padding:10px 12px;border-top:1px solid var(--border);font-size:14px; }}
  tr:hover td {{ background:rgba(110,118,129,.06); }}
  code {{ background:rgba(110,118,129,.2);padding:1px 5px;border-radius:3px;font-size:12px; }}
  .refresh {{ float:right;color:var(--accent);text-decoration:none;font-size:14px; }}
  .api-info {{ margin-top:24px;padding:14px;background:var(--card);border:1px solid var(--border);border-radius:8px;color:var(--dim);font-size:13px; }}
  .api-info code {{ font-size:11px; }}
</style>
</head>
<body>
<div class="container">
  <h1>Argus <span>Dashboard</span> <a href="/" class="refresh">Refresh</a></h1>

  <div class="cards">
    <div class="card"><div class="num" style="color:var(--accent)">{total}</div><div class="label">Total Scans</div></div>
    <div class="card"><div class="num" style="color:var(--yellow)">{findings}</div><div class="label">Total Findings</div></div>
    <div class="card"><div class="num" style="color:var(--green)">{risk_none}</div><div class="label">NONE</div></div>
    <div class="card"><div class="num" style="color:var(--accent)">{risk_low}</div><div class="label">LOW</div></div>
    <div class="card"><div class="num" style="color:var(--yellow)">{risk_med}</div><div class="label">MEDIUM</div></div>
    <div class="card"><div class="num" style="color:var(--red)">{risk_high}</div><div class="label">HIGH</div></div>
  </div>

  <table>
    <thead><tr><th>ID</th><th>Target</th><th>Status</th><th>Date</th><th>Findings</th><th>Risk</th><th>Tools</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>

  <div class="api-info">
    <strong>REST API:</strong>
    <code>GET /api/scans</code> &middot;
    <code>GET /api/scans/{{id}}</code> &middot;
    <code>GET /api/scans/{{id}}/findings</code> &middot;
    <code>GET /api/compare?a={{id1}}&b={{id2}}</code> &middot;
    <code>GET /api/stats</code>
  </div>
</div>
</body>
</html>"""
