"""Live dashboard for the network security assessment.

A small Flask app that ties the four phases together in one screen:

  * Phases 1 & 2 are READ live from the output files the other members produce
    (hosts.json, protocol_stats.json). The page auto-refreshes when those files
    change - so when Member 1 re-runs discovery during the demo, the new host
    shows up here on its own.
  * Phases 3 & 4 can be DRIVEN from here (buttons), because those scripts need
    only Python + SMAC, which live on this laptop. Each button runs the existing
    phase script via subprocess - nothing is reimplemented.

This is a wrapper. It reads the data contract from CLAUDE.md and shells out to
the phase scripts; it owns no assessment logic of its own.

Run:
    pip install -r requirements.txt      # adds flask
    python dashboard/app.py
    # then open http://127.0.0.1:5000

Security notes:
  * Binds to 127.0.0.1 only - it runs local tools, so it must not be reachable
    from the network.
  * Subprocess actions are a fixed allow-list (RUN_COMMANDS); no user input ever
    reaches a shell. shell=False throughout.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

# Make `shared` importable no matter where this is launched from.
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

try:
    from flask import Flask, jsonify, render_template, request, send_file
except ImportError:
    sys.exit("Flask is not installed. Run:  pip install -r requirements.txt")

from shared import config
from shared.utils import normalise_mac

app = Flask(__name__)

PYTHON = sys.executable  # the same interpreter that launched the dashboard


# --------------------------------------------------------------------------
# Reading the phase outputs (the data contract)
# --------------------------------------------------------------------------


def _read_json(path: Path):
    import json
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return None


def _mtime_iso(path: Path):
    from datetime import datetime
    try:
        return datetime.fromtimestamp(path.stat().st_mtime).isoformat(timespec="seconds")
    except OSError:
        return None


def _source(path: Path) -> dict:
    """Freshness envelope for one output file."""
    return {
        "path": str(path.relative_to(REPO_ROOT)) if path.is_relative_to(REPO_ROOT) else str(path),
        "exists": path.exists(),
        "updated": _mtime_iso(path),
    }


# --------------------------------------------------------------------------
# Phase data endpoints
# --------------------------------------------------------------------------


@app.get("/api/config")
def api_config():
    """Detected network + team roster, so the header can show live context."""
    try:
        network = config.target_network()
    except Exception as exc:  # noqa: BLE001 - surface, don't crash the page
        network = f"(could not detect: {exc})"
    hosts = []
    for host in config.HOSTS:
        hosts.append({
            "name": host.get("name"),
            "owner": host.get("owner"),
            "mac": normalise_mac(host.get("mac")),
            "ip": host.get("ip"),
        })
    return jsonify({
        "network": network,
        "this_host": config.this_host(),
        "local_ip": config.local_ip(),
        "capture_interface": config.capture_interface(),
        "spoof_interface": config.spoof_interface(),
        "hosts": hosts,
        "scope": "The team's own three laptops on the team's own network.",
    })


@app.get("/api/phase1")
def api_phase1():
    hosts = _read_json(config.HOSTS_JSON) or []
    up = [h for h in hosts if h.get("state") == "up" or h.get("ports")]
    open_ports = sum(1 for h in hosts for p in h.get("ports", [])
                     if p.get("state") == "open")
    # Attach our friendly label (by MAC, drift-proof) to each host.
    for host in hosts:
        host["label"] = config.host_label(host.get("ip"), mac=host.get("mac"))
    return jsonify({
        "source": _source(config.HOSTS_JSON),
        "available": bool(hosts),
        "hosts": hosts,
        "summary": {
            "hosts_total": len(hosts),
            "hosts_up": len(up),
            "open_ports": open_ports,
        },
    })


@app.get("/api/phase2")
def api_phase2():
    stats = _read_json(config.PROTOCOL_STATS_JSON) or {}
    return jsonify({
        "source": _source(config.PROTOCOL_STATS_JSON),
        "available": bool(stats),
        "stats": stats,
    })


@app.get("/api/phase3")
def api_phase3():
    log = _read_json(config.MAC_LOG_JSON) or {}
    entries = log.get("entries", []) if isinstance(log, dict) else []
    return jsonify({
        "source": _source(config.MAC_LOG_JSON),
        "available": bool(entries),
        "host": log.get("host") if isinstance(log, dict) else None,
        "entries": entries,
    })


@app.get("/api/phase4")
def api_phase4():
    doc = _read_json(config.FINDINGS_JSON) or {}
    firewall = None
    if config.FIREWALL_RULES_TXT.exists():
        try:
            firewall = config.FIREWALL_RULES_TXT.read_text(encoding="utf-8")
        except OSError:
            firewall = None
    return jsonify({
        "source": _source(config.FINDINGS_JSON),
        "available": bool(doc.get("findings")),
        "summary": doc.get("summary", {}),
        "findings": doc.get("findings", []),
        "firewall_rules": firewall,
        "report": _source(config.REPORT_XLSX),
    })


@app.get("/api/overview")
def api_overview():
    """One call the page polls: freshness of every source + headline numbers."""
    hosts = _read_json(config.HOSTS_JSON) or []
    stats = _read_json(config.PROTOCOL_STATS_JSON) or {}
    findings_doc = _read_json(config.FINDINGS_JSON) or {}
    mac_log = _read_json(config.MAC_LOG_JSON) or {}
    findings = findings_doc.get("findings", [])
    by_sev = findings_doc.get("summary", {}).get("findings_by_severity", {})

    mac_changed = False
    if isinstance(mac_log, dict):
        entries = mac_log.get("entries", [])
        before = next((e for e in entries if e.get("stage") == "before"), None)
        after = next((e for e in reversed(entries) if e.get("stage") == "after"), None)
        if before and after:
            mac_changed = normalise_mac(before.get("mac")) != normalise_mac(after.get("mac"))

    return jsonify({
        "sources": {
            "phase1": _source(config.HOSTS_JSON),
            "phase2": _source(config.PROTOCOL_STATS_JSON),
            "phase3": _source(config.MAC_LOG_JSON),
            "phase4": _source(config.FINDINGS_JSON),
        },
        "kpis": {
            "hosts_up": sum(1 for h in hosts if h.get("state") == "up" or h.get("ports")),
            "open_ports": sum(1 for h in hosts for p in h.get("ports", [])
                              if p.get("state") == "open"),
            "packets": stats.get("total_packets", 0),
            "protocols": len(stats.get("protocol_counts", {})),
            "findings_total": len(findings),
            "findings_critical_high": (by_sev.get("Critical", 0) + by_sev.get("High", 0)),
            "mac_spoof_demonstrated": mac_changed,
        },
        "is_sample": bool(findings_doc.get("summary", {}).get("sources", {}).get("sample")),
    })


# --------------------------------------------------------------------------
# Driving Phases 3 & 4 (fixed allow-list, no shell)
# --------------------------------------------------------------------------

# action id -> argv (relative to REPO_ROOT). Only these can be run.
RUN_COMMANDS: dict[str, list[str]] = {
    "phase3:view":            [PYTHON, "phase3_spoofing/mac_control.py", "view"],
    "phase3:snapshot:before": [PYTHON, "phase3_spoofing/mac_control.py", "snapshot", "--stage", "before"],
    "phase3:snapshot:after":  [PYTHON, "phase3_spoofing/mac_control.py", "snapshot", "--stage", "after"],
    "phase3:snapshot:restored": [PYTHON, "phase3_spoofing/mac_control.py", "snapshot", "--stage", "restored"],
    "phase3:verify":          [PYTHON, "phase3_spoofing/mac_control.py", "verify"],
    "phase3:report":          [PYTHON, "phase3_spoofing/mac_control.py", "report"],
    "phase4:analyze":         [PYTHON, "phase4_analysis/analyze_security.py"],
    "phase4:analyze:sample":  [PYTHON, "phase4_analysis/analyze_security.py", "--sample"],
    "phase4:report":          [PYTHON, "phase4_analysis/report.py"],
}

# 'demo' is deliberately absent - it is interactive (it pauses for the operator
# and for SMAC), so it belongs in a real terminal, not a web button.


@app.post("/api/run")
def api_run():
    payload = request.get_json(silent=True) or {}
    action = payload.get("action")
    argv = RUN_COMMANDS.get(action)
    if not argv:
        return jsonify({"ok": False, "error": f"unknown action: {action!r}"}), 400

    try:
        result = subprocess.run(
            argv, cwd=str(REPO_ROOT), capture_output=True, text=True,
            timeout=300, errors="replace",
        )
    except subprocess.TimeoutExpired:
        return jsonify({"ok": False, "action": action,
                        "error": "timed out after 300s"}), 504
    except OSError as exc:
        return jsonify({"ok": False, "action": action, "error": str(exc)}), 500

    # Keep the payload light: last chunk of output is enough for a toast/log.
    def tail(text: str, limit: int = 4000) -> str:
        text = text or ""
        return text if len(text) <= limit else "...\n" + text[-limit:]

    return jsonify({
        "ok": result.returncode == 0,
        "action": action,
        "returncode": result.returncode,
        "stdout": tail(result.stdout),
        "stderr": tail(result.stderr),
    })


@app.get("/api/chart/<name>")
def api_chart(name: str):
    """Serve a Phase 4 PNG chart if report.py has produced it."""
    safe = os.path.basename(name)  # no path traversal
    path = config.CHARTS_DIR / safe
    if path.suffix.lower() != ".png" or not path.exists():
        return jsonify({"error": "not found"}), 404
    return send_file(path, mimetype="image/png")


@app.get("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    port = int(os.environ.get("DASHBOARD_PORT", "5000"))
    print(f"\n  Network Security Assessment - dashboard")
    print(f"  open  http://127.0.0.1:{port}\n")
    # 127.0.0.1 only: this runs local tools and must not be network-reachable.
    app.run(host="127.0.0.1", port=port, debug=False)
