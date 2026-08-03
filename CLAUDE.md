# CLAUDE.md — Network Security Assessment (Mid-Sem Project)

This file is the standing context for this project. Read it at the start of every session.

## What this project is

A hands-on **local network security assessment** for a mid-sem assessment (40 marks, 4 phases × 10, **must be presented**). We play the role of assessors auditing a small network, then recommend how to harden it. The four phases follow a real security-assessment workflow: recon → traffic analysis → identity spoofing → synthesis.

## Team & environment

- **3-person group**, 3 Windows laptops, all on the **same network** (one WiFi/hotspot or switch). Each laptop is both a host to be discovered and a working node.
- OS: Windows (SMAC is Windows-only — this is fine).
- Everyone clones the whole repo but works only in their own phase folder.

## Tech stack

Python is the orchestration layer over industry-standard tools. Wrap, don't reinvent.

| Purpose | Tool / library |
|---|---|
| Network scanning | Nmap, driven by `python-nmap` |
| Packet capture | Wireshark / TShark |
| Packet analysis | `pyshark` (parses `.pcap`) |
| MAC spoofing | SMAC (GUI, Windows) — orchestrated/verified via `subprocess` |
| Data / reporting | `pandas`, `matplotlib`, `openpyxl` |
| (optional) traffic gen | `scapy` |

## Repo structure

```
network-security-assessment/
├── CLAUDE.md                  # this file
├── README.md                  # repo map + who owns what + quickstart
├── requirements.txt
├── shared/
│   ├── SETUP.md               # day-one setup ALL members do
│   ├── config.py              # network config: host IPs, interface names
│   └── utils.py               # shared IO/formatting helpers
├── phase1_discovery/          # MEMBER 1 — Nmap
│   ├── README.md              # setup + how to run
│   ├── scan.py                # python-nmap automation
│   └── outputs/               # hosts.json / hosts.csv  → consumed by phase4
├── phase2_capture/            # MEMBER 2 — Wireshark/PyShark
│   ├── README.md
│   ├── capture.py             # tshark capture driver
│   ├── analyze.py             # pyshark pcap parsing
│   └── outputs/               # packets.csv, protocol_stats.json → consumed by phase4
├── phase3_spoofing/           # MEMBER 3 — SMAC
│   ├── README.md
│   ├── mac_control.py         # subprocess: verify MAC (getmac/ipconfig), orchestrate
│   └── outputs/               # before/after MAC log
├── phase4_analysis/           # MEMBER 3 — synthesis + reporting
│   ├── README.md
│   ├── analyze_security.py    # reads phase1 + phase2 outputs → findings
│   ├── report.py              # pandas/matplotlib/openpyxl → charts + report.xlsx
│   └── outputs/
└── presentation/
    └── outline.md
```

## Roles & ownership

- **Member 1 — Discovery & Scanning (Phase 1):** Nmap host discovery, OS detection, TCP port scan, service + version detection. Owns `phase1_discovery/`. Deliverable: table of active hosts → IPs → open ports → services → OS.
- **Member 2 — Capture & Analysis (Phase 2):** Generate traffic (browse, download, DNS lookup, ping) while capturing; parse the pcap for src/dst IP, protocol, packet length, TCP three-way handshake, DNS lookup. Owns `phase2_capture/`.
- **Member 3 — Privacy + Security Analysis + Reporting (Phases 3 & 4):** SMAC spoofing demo (view → change → restart adapter → verify → restore); then synthesize Phase 1 + 2 outputs into open-port/insecure-protocol findings, firewall rules, hardening recs; owns the reporting layer and slide consolidation. Owns `phase3_spoofing/` and `phase4_analysis/`.

## Sequencing / dependencies

- Phases 1 and 2 run in parallel and **produce data**.
- Phase 4 **consumes** Phase 1 + Phase 2 outputs, so it lands last. Member 3 is not idle meanwhile — SMAC, the reporting scaffold, and slide template can all be built in parallel.
- Shared `SETUP.md` is a hard prerequisite for everyone.

## Data contract (so phases interoperate)

Keep these stable so Phase 4 can consume Phases 1 & 2 without rework.

- **Phase 1 → `phase1_discovery/outputs/hosts.json`**: list of
  `{ ip, hostname, mac, os, ports: [ { port, protocol, service, version, state } ] }`
- **Phase 2 → `phase2_capture/outputs/packets.csv`**: one row per packet:
  `timestamp, src_ip, dst_ip, protocol, length, info`
  plus `protocol_stats.json` with per-protocol counts and the identified TCP handshake / DNS lookup examples.
- **Phase 4** reads both, writes `report.xlsx` + charts.

## Conventions

- Each phase writes only to its own `outputs/`.
- Each phase folder has a self-contained `README.md`: what to install, how to run, what it produces.
- Network specifics (host IPs, interface name) live in `shared/config.py` — don't hardcode elsewhere.

## Presentation cohesion trick

Have Member 3 spoof their MAC with SMAC, then Member 1 re-run Nmap host discovery live — the laptop reappears with a different MAC. This visually links Phase 3 back to Phase 1 and makes the whole thing read as one system.

## Working loop per phase

Understand the concept → run it manually so you see what's happening → automate it in Python. Don't skip the manual run; the presentation depends on the team actually understanding the output.

## Scope / ethics

Everything targets the team's own three laptops on their own network. State this explicitly in the report — Phase 4 is literally about auditing a network you're responsible for.
