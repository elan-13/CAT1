# Live Dashboard (Member 3)

One screen that ties all four phases together, for the presentation. It's a
thin wrapper over the existing phase scripts and their output files — it owns no
assessment logic.

- **Phases 1 & 2** are read live from the files Members 1 & 2 produce
  (`hosts.json`, `protocol_stats.json`). The page polls every 5s and
  auto-refreshes when those files change — so when Member 1 re-runs discovery
  during the demo, the new host appears here on its own (the panel flashes).
- **Phases 3 & 4** can be *run* from here (buttons), because those scripts need
  only Python + SMAC, both on this laptop. Each button shells out to the real
  phase script; nothing is reimplemented.

## Install

```bash
pip install -r requirements.txt
```

Adds only `flask` beyond what Phase 4 already needs. No Node, no build step, no
CDN — the CSS/JS are vendored and the charts are drawn with plain SVG/CSS, so it
works with the hotspot offline.

## Run

```bash
python dashboard/app.py
```

Then open <http://127.0.0.1:5000>. It binds to `127.0.0.1` only, on purpose — it
runs local tools, so it must not be reachable from the network. Change the port
with `set DASHBOARD_PORT=5050` (PowerShell: `$env:DASHBOARD_PORT="5050"`).

## See it populated right now (sample data)

Before the teammates deliver, you can fill every panel with realistic sample
data to build and rehearse against:

```bash
python phase4_analysis/analyze_security.py --sample
```

That writes `findings.json` (Phase 4) plus sample `hosts.json` /
`protocol_stats.json` under `phase4_analysis/outputs/sample_inputs/`. To also
light up the Phase 1 & 2 panels, copy those two files into their real homes:

```bash
copy phase4_analysis\outputs\sample_inputs\hosts.json phase1_discovery\outputs\hosts.json
copy phase4_analysis\outputs\sample_inputs\protocol_stats.json phase2_capture\outputs\protocol_stats.json
```

The header banner keeps saying **sample data** until Phase 4 is re-run on real
inputs, so you can't mistake it for the real assessment.

## What each panel shows

| Panel | Source | Live actions |
|---|---|---|
| Overview | all four output files | — (KPIs + freshness table, auto-polled) |
| Phase 1 · Discovery | `phase1_discovery/outputs/hosts.json` | read-only |
| Phase 2 · Capture | `phase2_capture/outputs/protocol_stats.json` | read-only |
| Phase 3 · Spoofing | `phase3_spoofing/outputs/mac_log.json` | View adapters · Snapshot before/after/restored · Verify |
| Phase 4 · Findings | `phase4_analysis/outputs/findings.json` + `firewall_rules.txt` | Re-analyze · Re-analyze (sample) · Build report |

Team laptops are labelled by MAC (drift-proof — see `shared/config.py`), so the
right owner shows even after the hotspot reshuffles IPs.

## Presentation use

1. Launch the dashboard on your laptop, project it.
2. Members 1 & 2 drop their `hosts.json` / `protocol_stats.json` into their
   `outputs/` folders (or run their scripts there) — the panels fill in live.
3. Run the Phase 3 spoof (`python phase3_spoofing/mac_control.py demo` in a
   terminal for the guided flow, or the Snapshot buttons here), then have
   Member 1 re-run `scan.py --discovery-only` — the Phase 1 panel flashes as the
   new MAC arrives.
4. Hit **Re-analyze** then **Build report** to regenerate findings + `report.xlsx`
   from whatever data is present.

The guided `mac_control.py demo` is intentionally **not** a button — it pauses
for you and for SMAC, so it belongs in a terminal.

## How it's built (offline-safe)

- Flask serves one page; the browser calls `/api/*` for data and `/api/run` to
  execute a **fixed allow-list** of phase commands (no user input reaches a
  shell, `shell=False`).
- Design system from the `ui-ux-pro-max` skill: Data-Dense Dashboard style,
  blue/amber palette, Fira Code/Fira Sans (with system fallbacks), dark + light
  themes. Severity colours match the Phase 4 Excel charts.
- Charts are hand-drawn SVG/CSS — no Chart.js, no network dependency.
