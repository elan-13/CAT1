# Network Security Assessment

A local network security assessment built for a mid-sem group project (40 marks, 4 phases). Python orchestrates Nmap, Wireshark/TShark, and SMAC to discover hosts, capture and analyze traffic, test MAC spoofing, and produce a hardening report.

## Who owns what

| Folder | Owner | Phase |
|---|---|---|
| `phase1_discovery/` | Member 1 | Network discovery & port scanning (Nmap) |
| `phase2_capture/` | Member 2 | Packet capture & analysis (Wireshark/PyShark) |
| `phase3_spoofing/` | Member 3 | MAC spoofing (SMAC) |
| `phase4_analysis/` | Member 3 | Security analysis & reporting |
| `shared/` | All | Config, setup, shared helpers |

## Getting started

1. **Everyone:** clone the repo, then follow `shared/SETUP.md` (get all three laptops on the same network, note each host's IP, install Python).
2. **Then:** go to your own phase folder and follow its `README.md` for tool installs and run instructions. You don't need to install tools for phases you don't own.
3. Fill in your host IPs and interface names in `shared/config.py`.

## How the pieces connect

Phases 1 and 2 run in parallel and write their results into their `outputs/` folders. Phase 4 reads those results and produces the final report + charts. See `CLAUDE.md` for the data formats each phase must produce.

## Working agreement

- Each phase writes only to its own `outputs/`.
- Don't hardcode IPs or interface names — put them in `shared/config.py`.
- Run every tool manually once before automating it. The presentation depends on understanding the output, not just producing it.

## Scope

This assesses the team's own three laptops on their own network only.
