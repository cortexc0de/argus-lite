"""Argus web dashboard v4 — full control panel with real-time WebSocket.

Launch with: argus --web
All operations (scan, agent, OSINT, settings) from the browser.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
from pathlib import Path

from flask import Flask, abort, jsonify, redirect, render_template, request, url_for

logger = logging.getLogger(__name__)

# Global state for running tasks
_running_tasks: dict[str, dict] = {}
_socketio = None


def create_app(argus_home: str) -> Flask:
    """Create Flask app with SocketIO for the web panel."""
    global _socketio

    from flask_socketio import SocketIO, emit

    app = Flask(
        __name__,
        template_folder=str(Path(__file__).parent / "templates"),
        static_folder=str(Path(__file__).parent / "static"),
    )
    app.config["SECRET_KEY"] = "argus-local-panel"

    socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")
    _socketio = socketio

    home = Path(argus_home)
    scans_dir = home / "scans"

    # ── HTML Pages ──

    @app.route("/")
    def index():
        scans = _list_scans(scans_dir)
        scan_rows = _format_scans(scans)
        stats = _compute_stats(scans)
        return render_template("dashboard.html", page="dashboard",
                               scans=scan_rows, stats=stats, running=_running_tasks)

    @app.route("/scan")
    def scan_page():
        return render_template("scan.html", page="scan", running=_running_tasks)

    @app.route("/results")
    def results_page():
        scans = _list_scans(scans_dir)
        scan_rows = _format_scans(scans)
        return render_template("dashboard.html", page="results",
                               scans=scan_rows, stats=_compute_stats(scans), running=_running_tasks)

    @app.route("/osint")
    def osint_page():
        return render_template("osint.html", page="osint")

    @app.route("/settings", methods=["GET", "POST"])
    def settings_page():
        config_path = home / "config.yaml"
        saved = False
        if request.method == "POST":
            _save_settings(config_path, request.form)
            saved = True
        config_data = _load_settings(config_path)
        keys = [
            ("shodan", "Shodan"), ("virustotal", "VirusTotal"),
            ("censys_id", "Censys API ID"), ("censys_secret", "Censys Secret"),
            ("zoomeye", "ZoomEye"), ("fofa_email", "FOFA Email"),
            ("fofa_key", "FOFA Key"), ("greynoise", "GreyNoise"),
            ("nvd", "NVD (CVE Lookup)"),
        ]
        return render_template("settings.html", page="settings",
                               config=config_data, keys=keys, saved=saved)

    @app.route("/report/<scan_id>")
    def view_report(scan_id: str):
        report = scans_dir / scan_id / "report" / "report.html"
        if not report.exists():
            abort(404)
        return report.read_text()

    # ── Scan API ──

    @app.route("/api/scan/start", methods=["POST"])
    def api_scan_start():
        data = request.json or request.form
        target = (data.get("target") or "").strip()
        preset = data.get("preset", "quick")
        if not target:
            return jsonify({"error": "Target required"}), 400

        task_id = f"scan-{target}"
        if task_id in _running_tasks:
            return jsonify({"error": "Scan already running for this target"}), 409

        _running_tasks[task_id] = {"type": "scan", "target": target, "status": "running"}

        def run_scan():
            from argus_lite.core.config import load_config as _load
            from argus_lite.core.orchestrator import ScanOrchestrator
            from argus_lite.core.resume import save_partial
            from argus_lite.core.risk_scorer import score_scan
            from argus_lite.modules.report.html_report import write_html_report

            config = _load(home / "config.yaml")
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            def on_progress(stage, status):
                socketio.emit("scan:progress", {
                    "target": target, "stage": stage, "status": status,
                })

            orch = ScanOrchestrator(
                target=target, config=config, preset=preset, on_progress=on_progress,
            )
            try:
                result = loop.run_until_complete(orch.run())
                result.risk_summary = score_scan(result)
                scan_dir = scans_dir / result.scan_id
                save_partial(result, scan_dir)
                report_dir = scan_dir / "report"
                report_dir.mkdir(parents=True, exist_ok=True)
                write_html_report(result, report_dir / "report.html")

                socketio.emit("scan:done", {
                    "target": target,
                    "scan_id": result.scan_id,
                    "findings": len(result.findings),
                    "risk": (result.risk_summary or {}).get("risk_level", "NONE"),
                })
            except Exception as exc:
                socketio.emit("scan:error", {"target": target, "error": str(exc)})
            finally:
                _running_tasks.pop(task_id, None)

        t = threading.Thread(target=run_scan, daemon=True)
        t.start()
        return jsonify({"status": "started", "target": target})

    @app.route("/api/scan/stop", methods=["POST"])
    def api_scan_stop():
        target = (request.json or {}).get("target", "")
        task_id = f"scan-{target}"
        if task_id in _running_tasks:
            _running_tasks.pop(task_id, None)
            return jsonify({"status": "stopped"})
        return jsonify({"error": "No scan running for this target"}), 404

    # ── Agent API ──

    @app.route("/api/agent/start", methods=["POST"])
    def api_agent_start():
        data = request.json or request.form
        target = (data.get("target") or "").strip()
        if not target:
            return jsonify({"error": "Target required"}), 400

        max_steps = int(data.get("max_steps", 8))
        mission = data.get("mission", "full_assessment")
        stealth = data.get("stealth", False)
        multi_agent = data.get("multi_agent", False)

        task_id = f"agent-{target}"
        if task_id in _running_tasks:
            return jsonify({"error": "Agent already running for this target"}), 409

        _running_tasks[task_id] = {"type": "agent", "target": target, "status": "running", "step": 0}

        def run_agent():
            from argus_lite.core.agent import PentestAgent
            from argus_lite.core.config import AIConfig, load_config as _load

            config = _load(home / "config.yaml")
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            def on_step(step):
                _running_tasks.get(task_id, {})["step"] = step.step_number
                socketio.emit("agent:step", {
                    "target": target,
                    "step": step.step_number,
                    "action": step.action,
                    "thought": step.thought,
                    "result": step.result_summary,
                    "success": step.result_success,
                    "findings": step.findings_count,
                })

            ai_config = config.ai
            agent = PentestAgent(ai_config, max_steps=max_steps, on_step=on_step)

            try:
                result = loop.run_until_complete(
                    agent.run(target, config, mission=mission, stealth=stealth)
                )
                socketio.emit("agent:done", {
                    "target": target,
                    "total_findings": result.total_findings,
                    "skills_used": result.skills_used,
                    "steps": len(result.steps),
                })
            except Exception as exc:
                socketio.emit("agent:error", {"target": target, "error": str(exc)})
            finally:
                _running_tasks.pop(task_id, None)

        t = threading.Thread(target=run_agent, daemon=True)
        t.start()
        return jsonify({"status": "started", "target": target})

    @app.route("/api/agent/stop", methods=["POST"])
    def api_agent_stop():
        target = (request.json or {}).get("target", "")
        task_id = f"agent-{target}"
        if task_id in _running_tasks:
            _running_tasks.pop(task_id, None)
            return jsonify({"status": "stopped"})
        return jsonify({"error": "No agent running for this target"}), 404

    @app.route("/api/agent/status")
    def api_agent_status():
        return jsonify({
            "running": {k: v for k, v in _running_tasks.items() if v["type"] == "agent"}
        })

    # ── OSINT API ──

    @app.route("/api/discover", methods=["POST"])
    def api_discover():
        from argus_lite.core.config import load_config as _load
        from argus_lite.core.discovery_engine import DiscoveryEngine
        from argus_lite.models.discover import DiscoverQuery

        data = request.json or request.form
        cve = (data.get("cve") or "").strip()
        tech = (data.get("tech") or "").strip()
        service = (data.get("service") or "").strip()
        port_str = (data.get("port") or "").strip()
        country = (data.get("country") or "").strip()

        if not any([cve, tech, service, port_str]):
            return jsonify({"error": "Enter at least one search field"}), 400

        port = int(port_str) if port_str.isdigit() else None
        query = DiscoverQuery(cve=cve, tech=tech, service=service, port=port, country=country)

        config = _load(home / "config.yaml")
        engine = DiscoveryEngine(config)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(engine.discover(query))

        return jsonify({
            "total": result.total_found,
            "sources": result.sources_queried,
            "failed": result.sources_failed,
            "hosts": [
                {"ip": h.ip, "port": h.port, "service": h.service,
                 "product": h.product, "country": h.country, "source": h.source}
                for h in result.hosts[:100]
            ],
        })

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
        id_a, id_b = request.args.get("a", ""), request.args.get("b", "")
        if not id_a or not id_b:
            return jsonify({"error": "Provide ?a=SCAN_ID&b=SCAN_ID"}), 400
        scan_a, scan_b = _load_scan(scans_dir / id_a), _load_scan(scans_dir / id_b)
        if not scan_a or not scan_b:
            abort(404)
        findings_a = {f.get("title", "") for f in scan_a.get("findings", [])}
        findings_b = {f.get("title", "") for f in scan_b.get("findings", [])}
        return jsonify({
            "scan_a": id_a, "scan_b": id_b,
            "new_in_b": sorted(findings_b - findings_a),
            "resolved_in_b": sorted(findings_a - findings_b),
            "unchanged": sorted(findings_a & findings_b),
        })

    @app.route("/api/stats")
    def api_stats():
        return jsonify(_compute_stats(_list_scans(scans_dir)))

    @app.route("/api/running")
    def api_running():
        return jsonify(_running_tasks)

    # ── SocketIO events ──

    @socketio.on("connect")
    def on_connect():
        emit("connected", {"status": "ok", "running": _running_tasks})

    return app, socketio


# ── Helpers ──

def _list_scans(scans_dir: Path) -> list[dict]:
    if not scans_dir.is_dir():
        return []
    scans = []
    for scan_dir in sorted(scans_dir.iterdir(), reverse=True):
        if not scan_dir.is_dir() or scan_dir.name.startswith("bulk-"):
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


def _format_scans(scans: list[dict]) -> list[dict]:
    rows = []
    for s in scans:
        rs = s.get("risk_summary") or {}
        rows.append({
            "scan_id": s.get("scan_id", ""),
            "target": s.get("target", "?"),
            "status": s.get("status", "?"),
            "date": (s.get("started_at", "") or "")[:16].replace("T", " "),
            "findings_count": len(s.get("findings", [])),
            "risk": rs.get("risk_level", "NONE"),
            "score": rs.get("overall_score", 0),
            "tools": ", ".join(s.get("tools_used", [])[:5]),
        })
    return rows


def _compute_stats(scans: list[dict]) -> dict:
    risks = {"NONE": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0}
    total_findings = 0
    total_cves = 0
    for s in scans:
        rs = s.get("risk_summary") or {}
        rl = rs.get("risk_level", "NONE")
        risks[rl] = risks.get(rl, 0) + 1
        total_findings += len(s.get("findings", []))
        total_cves += len(s.get("vulnerabilities", []))
    return {
        "total": len(scans), "findings": total_findings, "cves": total_cves,
        "risk_none": risks["NONE"], "risk_low": risks["LOW"],
        "risk_med": risks["MEDIUM"], "risk_high": risks["HIGH"],
    }


def _load_settings(config_path: Path) -> dict:
    if not config_path.exists():
        return {}
    try:
        import yaml
        raw = yaml.safe_load(config_path.read_text()) or {}
    except Exception:
        return {}
    ak = raw.get("api_keys", {})
    ai = raw.get("ai", {})
    rl = raw.get("rate_limits", {})
    n = raw.get("notifications", {})
    return {
        "shodan": ak.get("shodan", ""), "virustotal": ak.get("virustotal", ""),
        "censys_id": ak.get("censys_api_id", ""), "censys_secret": ak.get("censys_api_secret", ""),
        "zoomeye": ak.get("zoomeye_api_key", ""), "fofa_email": ak.get("fofa_email", ""),
        "fofa_key": ak.get("fofa_api_key", ""), "greynoise": ak.get("greynoise_api_key", ""),
        "nvd": ak.get("nvd_api_key", ""),
        "ai_base_url": ai.get("base_url", "https://api.openai.com/v1"),
        "ai_api_key": ai.get("api_key", ""), "ai_model": ai.get("model", "gpt-4o"),
        "ai_lang": ai.get("language", "en"),
        "rate_global": rl.get("global_rps", 50), "rate_per_target": rl.get("per_target_rps", 10),
        "rate_concurrent": rl.get("concurrent_requests", 5),
        "tg_token": n.get("telegram_token", ""), "tg_chat_id": n.get("telegram_chat_id", ""),
        "discord_webhook": n.get("discord_webhook", ""),
    }


def _save_settings(config_path: Path, form) -> None:
    import os
    import yaml
    raw = {}
    if config_path.exists():
        try:
            raw = yaml.safe_load(config_path.read_text()) or {}
        except Exception:
            raw = {}
    raw["api_keys"] = {
        "shodan": form.get("shodan", ""), "virustotal": form.get("virustotal", ""),
        "censys_api_id": form.get("censys_id", ""), "censys_api_secret": form.get("censys_secret", ""),
        "zoomeye_api_key": form.get("zoomeye", ""), "fofa_email": form.get("fofa_email", ""),
        "fofa_api_key": form.get("fofa_key", ""), "greynoise_api_key": form.get("greynoise", ""),
        "nvd_api_key": form.get("nvd", ""),
    }
    raw["ai"] = {
        "enabled": bool(form.get("ai_api_key")),
        "base_url": form.get("ai_base_url", "https://api.openai.com/v1"),
        "api_key": form.get("ai_api_key", ""), "model": form.get("ai_model", "gpt-4o"),
        "language": form.get("ai_lang", "en"),
    }
    raw["rate_limits"] = {
        "global_rps": int(form.get("rate_global", 50)),
        "per_target_rps": int(form.get("rate_per_target", 10)),
        "concurrent_requests": int(form.get("rate_concurrent", 5)),
    }
    raw["notifications"] = {
        "telegram_token": form.get("tg_token", ""), "telegram_chat_id": form.get("tg_chat_id", ""),
        "discord_webhook": form.get("discord_webhook", ""),
    }
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(yaml.dump(raw, default_flow_style=False, sort_keys=False))
    os.chmod(config_path, 0o600)
