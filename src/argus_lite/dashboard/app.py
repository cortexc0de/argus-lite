"""Argus web dashboard — local UI for browsing scan results."""

from __future__ import annotations

import json
from pathlib import Path

from flask import Flask, abort, jsonify


def create_app(argus_home: str) -> Flask:
    """Create Flask app for the dashboard."""
    app = Flask(__name__)
    home = Path(argus_home)
    scans_dir = home / "scans"

    @app.route("/")
    def index():
        scans = _list_scans(scans_dir)
        rows = ""
        for s in scans:
            rows += f"""
            <tr onclick="window.location='/report/{s['scan_id']}';" style="cursor:pointer">
                <td><code>{s['scan_id'][:12]}...</code></td>
                <td>{s.get('target', '?')}</td>
                <td>{s.get('status', '?')}</td>
                <td>{s.get('started_at', '?')[:19] if s.get('started_at') else '-'}</td>
                <td>{len(s.get('findings', []))}</td>
            </tr>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Argus Dashboard</title>
<style>
  :root {{ --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #e6edf3; --dim: #8b949e; --accent: #58a6ff; }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: var(--bg); color: var(--text); }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 30px 20px; }}
  h1 {{ font-size: 28px; margin-bottom: 24px; }}
  h1 span {{ color: var(--accent); }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ text-align: left; padding: 12px; background: rgba(110,118,129,0.1); color: var(--dim); font-size: 12px; text-transform: uppercase; }}
  td {{ padding: 12px; border-top: 1px solid var(--border); }}
  tr:hover td {{ background: rgba(110,118,129,0.08); }}
  code {{ background: rgba(110,118,129,0.2); padding: 2px 6px; border-radius: 4px; font-size: 13px; }}
  .empty {{ text-align: center; color: var(--dim); padding: 40px; }}
</style>
</head>
<body>
<div class="container">
  <h1>Argus <span>Dashboard</span></h1>
  {"<table><tr><th>Scan ID</th><th>Target</th><th>Status</th><th>Date</th><th>Findings</th></tr>" + rows + "</table>" if scans else '<div class="empty">No scans found. Run: argus scan &lt;target&gt;</div>'}
</div>
</body>
</html>"""

    @app.route("/api/scans")
    def api_scans():
        return jsonify(_list_scans(scans_dir))

    @app.route("/api/scans/<scan_id>")
    def api_scan_detail(scan_id: str):
        scan_dir = scans_dir / scan_id
        data = _load_scan(scan_dir)
        if data is None:
            abort(404)
        return jsonify(data)

    @app.route("/report/<scan_id>")
    def view_report(scan_id: str):
        report_file = scans_dir / scan_id / "report" / "report.html"
        if not report_file.exists():
            abort(404)
        return report_file.read_text()

    return app


def _list_scans(scans_dir: Path) -> list[dict]:
    """List all scans with basic metadata."""
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
    """Load scan metadata from partial.json."""
    partial = scan_dir / "partial.json"
    if not partial.exists():
        return None
    try:
        return json.loads(partial.read_text())
    except (json.JSONDecodeError, OSError):
        return None
