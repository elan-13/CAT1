# Phase 4 — Security Analysis & Reporting (Member 3)

Take what Phases 1, 2 and 3 found and turn it into an assessment: which
exposures matter, why, and what to do about each. Phases 1 and 2 report facts;
this phase applies judgement to them and produces the deliverable the whole
project is graded on.

## What you install

| What | How |
|---|---|
| Python packages | `pip install -r requirements.txt` from the repo root |

No external tools. `analyze_security.py` is stdlib only; `report.py` needs
pandas, matplotlib and openpyxl.

## You are not blocked waiting for the others

Phase 4 consumes Phases 1 and 2, but you can build and test the entire chain
before either has delivered anything:

```bash
python analyze_security.py --sample
python report.py
```

`--sample` writes realistic synthetic inputs to `outputs/sample_inputs/` and
analyses those. You get a complete `report.xlsx` and full set of charts, clearly
marked as sample data, so the reporting layer and the slide template are done
before the real data lands. Delete `outputs/` and re-run for real when it does.

## Before you automate anything: read the raw inputs

Open `phase1_discovery/outputs/hosts.json` and
`phase2_capture/outputs/protocol_stats.json` and form your own view of what is
worrying before you look at what the script says. The risk table in
`analyze_security.py` (`PORT_RISKS` and `PROTOCOL_RISKS`) is a starting policy,
not gospel — if you disagree with a severity, change it and be ready to defend
the change. That is the actual assessment skill being marked here.

## How to run it

Collect the other members' outputs into their folders first:

```
phase1_discovery/outputs/hosts.json          <- from Member 1
phase2_capture/outputs/packets.csv           <- from Member 2
phase2_capture/outputs/protocol_stats.json   <- from Member 2
phase3_spoofing/outputs/mac_log.json         <- yours, optional but do it
```

Then:

```bash
python analyze_security.py
python report.py
```

| Command | What it does |
|---|---|
| `python analyze_security.py` | Analyse the real phase outputs |
| `python analyze_security.py --sample` | Analyse synthetic data instead |
| `python analyze_security.py --min-severity High` | Only keep High and Critical |
| `python report.py` | Charts + `report.xlsx` |
| `python report.py --no-charts` | Workbook only |

`report.py` follows whatever `analyze_security.py` read, so if you analysed
sample data the report is built from sample data and says so on every run.

## What it produces

All in `outputs/`.

| File | What it is |
|---|---|
| `findings.json` | Every finding with severity, evidence, risk and recommendation, plus a summary block |
| `findings.csv` | The same, flat — good for sorting in Excel |
| `firewall_rules.txt` | Concrete `netsh` commands for the risky ports actually found, plus NetBIOS/LLMNR hardening and a rollback section |
| `charts/*.png` | Findings by severity, open ports per host, exposed services, protocol distribution, top talkers |
| `report.xlsx` | The deliverable: Summary / Findings / Hosts / Open Ports / Protocol Stats / Top Talkers / Evidence / MAC Log / Firewall Rules / Charts |

The **Evidence** sheet is worth knowing about: it isolates the TCP three-way
handshake and the DNS lookup that Phase 2 identified, so you can point straight
at them during the presentation.

## What the analysis actually does

Four passes, and each one is a different kind of finding:

1. **Open ports (Phase 1)** — every open port becomes a finding. Ports in the
   risk table (Telnet, SMB, RDP, VNC, databases, cleartext mail…) get a real
   severity and a specific recommendation; encrypted ones like SSH and HTTPS are
   logged as Info; anything unrecognised is Low, because an open port nobody can
   account for is an unknown.
2. **Observed protocols (Phase 2)** — cleartext protocols seen in the capture,
   plus the cleartext-vs-encrypted ratio, DNS privacy leakage, and corroboration
   where traffic was actually flowing to a port Phase 1 flagged. "Port 445 is
   open" is weaker than "port 445 is open *and* carrying traffic".
3. **MAC spoofing (Phase 3)** — a successful before→after change becomes a High
   finding about MAC-based access control.
4. **Cross-phase** — things only visible with two phases side by side: hosts
   that appear in the capture but not the inventory, and how easily the ping
   sweep found everyone.

## Before you present

- Re-read the Summary sheet and make sure you can say the top three findings in
  your own words without reading them off the slide.
- Check `firewall_rules.txt` — you are recommending these to a room, so know
  what each one breaks. Blocking 445 kills file sharing; blocking 3389 ends an
  active Remote Desktop session.
- If a severity looks wrong to you, change it in `PORT_RISKS` / `PROTOCOL_RISKS`
  and re-run. Defending your own rating beats reciting a generated one.

## When it does not work

**"missing input" / "neither hosts.json nor protocol_stats.json exists".** The
other phases have not delivered, or their files are not in the right folders.
Use `--sample` in the meantime.

**Only Phase 2 findings appear.** `hosts.json` is missing — the script warns and
carries on with whatever it has rather than failing outright.

**Charts are empty or missing.** Nothing to plot: no open ports found, or the
protocol counts are empty. The script says which.

**Excel will not open the file.** You have `report.xlsx` open in Excel from a
previous run — close it and re-run.

## Scope

Every finding here describes the team's own three laptops on the team's own
network. State that explicitly on the first slide and in the report — the whole
exercise is auditing a network you are responsible for, and the Summary sheet
carries that sentence for you.
