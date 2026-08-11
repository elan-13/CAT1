# Project State & Decisions Log

Companion to `CLAUDE.md`. Where CLAUDE.md is the standing brief (what the
project *is*), this file is the running record of what has been **built**, what
has been **decided**, and what is **still open**. Read both at the start of a
session.

Last updated: 2026-08-11.

---

## 1. Where the build stands

The full structure from CLAUDE.md is scaffolded and committed. Everything a
clone needs is in place; the phases just need real data run through them.

| Area | File(s) | State |
|---|---|---|
| Shared config | `shared/config.py` | Done, **filled with real team data** (see §4) |
| Shared helpers | `shared/utils.py` | Done, stdlib-only so it imports before any phase tool is installed |
| Phase 1 | `phase1_discovery/scan.py` + README | Written, **compiles only** — nmap not installed on the build machine |
| Phase 2 | `phase2_capture/capture.py`, `analyze.py` + README | Written, **compiles only** — tshark/pyshark not installed |
| Phase 3 | `phase3_spoofing/mac_control.py` + README | Written **and run** — `view`/`snapshot`/`verify`/`report` verified on the real laptop |
| Phase 4 | `phase4_analysis/analyze_security.py`, `report.py` + README | Written **and run end-to-end** on sample data |
| Setup | `shared/SETUP.md` (moved from repo root) | Done |
| Presentation | `presentation/outline.md` | Done — slide plan, demo choreography, checklist, likely Q&A |
| Repo hygiene | `.gitignore`, `outputs/.gitkeep`, `requirements.txt`, root `README.md` | Done |

### Git

- Scaffold committed on branch **`scaffold-assessment-tooling`** as `25b067d`
  (21 files, 4147 insertions). *Not yet merged to `main`.*
- The config fill-in (§4) is an **uncommitted working-tree change** as of this
  writing.
- To land it all on main:
  ```bash
  git add shared/config.py PROJECT_STATE.md
  git commit -m "Fill in team network config from ipconfig /all"
  git checkout main && git merge --ff-only scaffold-assessment-tooling
  ```

---

## 2. Verification status (be honest about this)

**Run and confirmed working:**
- `shared/config.py` auto-detection and the filled-in values resolve correctly.
- Full Phase 4 chain on `--sample`: 24 findings → 5 charts → 9-sheet
  `report.xlsx`. Opened and inspected the workbook.
- Phase 3 `view`/`snapshot`/`verify`/`report` against the real adapter
  (correctly merges `getmac` + `ipconfig`; found Wi-Fi at `B8-1E-A4-34-01-BD`).
- All three dependency-missing paths (nmap, pyshark, tshark) fail with
  actionable messages, not tracebacks.

**NOT verified (no binaries on the build machine):**
- `phase1_discovery/scan.py` beyond `py_compile` — needs Nmap + `python-nmap`.
- `phase2_capture/*.py` beyond `py_compile` — needs Wireshark/TShark + pyshark.
- Phase 3's actual **spoof** (needs SMAC + an Administrator shell + a driver
  that accepts a spoofed MAC). Only the read/verify/log path is proven.

Implication: the first real runs of Phases 1 and 2 are also their first true
tests. Budget time for that.

---

## 3. Decisions made during the build

### 3.1 Subnet is computed, not string-chopped (bug fixed)
Auto-detection first produced `192.168.0.0/19` for a laptop on
`192.168.179.32 / 255.255.224.0` — a range that **doesn't contain the laptop
itself**. Rewrote `target_network()` to use the `ipaddress` module, which yields
the correct `192.168.160.0/19`. Added `target_network_size()` and a warning in
`scan.py` when the subnet exceeds 1024 addresses.

### 3.2 pyshark robustness (couldn't be runtime-tested, fixed by review)
- `field()` now falls back to attribute access — `get_field_value()` silently
  returns `None` for dotted names like `arp.src.proto_ipv4`, which would have
  dropped ARP addresses.
- TLS handling accepts both the modern `tls` and legacy `ssl` layer names.

### 3.3 Generated evidence is gitignored
`*/outputs/*` (except `.gitkeep`) and `*.pcap`/`*.pcapng` are excluded. Reasons:
pcaps are large, and a capture of one's own traffic contains personal browsing.
Sharing a specific result is a deliberate `git add -f`.

### 3.4 Phase 4 is unblockable
`analyze_security.py --sample` writes synthetic-but-realistic inputs so the whole
reporting chain (and the slide template) can be built before Phases 1 and 2
deliver. The report marks itself as sample-based on every run until real data
replaces it.

### 3.5 Risk policy lives in code, meant to be edited
`PORT_RISKS` / `PROTOCOL_RISKS` in `analyze_security.py` are a **starting**
policy. Member 3 is expected to change severities they disagree with — defending
your own rating is the graded skill.

### 3.6 Drift-proofed for the hotspot (2026-08-11)
The hotspot changes subnet and IPs every session, so both were removed as
sources of truth:
- **Subnet auto-detects.** `TARGET_NETWORK = None`; `target_network()` computes
  the live subnet from this laptop's IP + mask on every run. Nothing reads a
  pinned constant — `scan.py` scans the currently detected subnet each time.
- **Laptops are identified by MAC, not IP.** `HOSTS` keeps each owner's Wi-Fi
  MAC (IPs set to `None`). `host_label(ip, mac=...)` matches by MAC first and
  only falls back to IP when the looked-up host has no MAC. Both sides are
  normalised (separators stripped, lower-cased) via `_mac_key()`, so Nmap's
  colon/upper, ipconfig's dash, and a no-separator config value all compare
  equal — without that, matches silently fail and every host labels 'unknown'.
  `analyze_security.py` and `report.py` pass the scanned host's MAC through when
  reading `hosts.json`. Phase 1's `scan.py` and Phase 2's `analyze.py` still
  label by IP — they run in-session where IPs are current; the drift only bites
  when a *later* session reads Jay's `hosts.json`, which is exactly the Phase 4
  boundary that now uses MAC.
- **Expected side effect:** during the Phase 3 spoof, Jayant's laptop stops
  matching by MAC and labels as 'unknown'. That is correct — the MAC changed.
  Verified across a simulated reshuffle (new IPs + mixed MAC formats all match;
  spoofed MAC and strangers resolve to unknown).

---

## 4. The real network — the laptops are fixed, the addressing is not

We run off **Jayant's phone hotspot**. The subnet and every IP change per
session (seen `10.25.254.0/24` on 2026-08-05, `10.83.176.0/24` since), so none
of that is pinned anywhere any more — see §3.6. The stable facts are the three
laptops and their Wi-Fi MACs.

| Role | Owner | Hostname | Wi-Fi MAC (stable) | Wi-Fi chipset |
|---|---|---|---|---|
| laptop-1 | Member 1 — Jay | LAPTOP-AKP1N1RO | 10-68-38-C3-E3-63 | MediaTek MT7922 |
| laptop-2 | Member 2 — Elan | LAPTOP-JREKN2VC | 20-2B-20-C0-D1-29 | Realtek RTL8821CE |
| laptop-3 | Member 3 — Jayant | Jayant | B8-1E-A4-34-01-BD | Realtek RTL8852BE |

> **Volatile — do not trust between sessions:** the subnet CIDR and every
> laptop's IPv4. Earlier drafts of this file and the config pinned
> `10.25.254.0/24` / specific IPs; those are gone. `config.py` now auto-detects
> the subnet at runtime and identifies laptops by MAC (§3.6). The IPv6 prefix
> `2409:40f4:204a:835c::/64` is Jio's and also session-dependent.

Config: `TARGET_NETWORK = None` (live-detected), `HOSTS` carries the three MACs
above with `ip = None`, `CAPTURE_INTERFACE = "Wi-Fi"` (all three name it that),
`THIS_HOST = "laptop-3"`. Verified with `python shared/config.py` → subnet
resolves live, all 3 hosts recognised by MAC.

### Role assignment rationale
- **Jay → Phase 1 (Nmap).** Fine on any machine.
- **Elan → Phase 2 (capture).** Chosen because his laptop has a **single, clean
  Wi-Fi adapter**. Jay's machine has a McAfee VPN TAP, two Wi-Fi Direct virtual
  adapters, Bluetooth PAN and Ethernet — picking the capture interface there is
  error-prone. Give the capture to the unambiguous machine.
- **Jayant (me) → Phases 3 & 4.** Per CLAUDE.md; laptop already configured as
  node 3, Realtek RTL8852BE likely to accept a spoofed MAC.

Jay and Elan do **not** edit `config.py` — `THIS_HOST` is only read by Phase 3.

---

## 5. Open items / risks to watch

### 5.1 Scan scope — RESOLVED
The network is **Jayant's own phone hotspot**, so scanning the whole subnet is
his own equipment and squarely inside CLAUDE.md scope. The earlier
"managed/shared network?" worry was a misread of the addressing (an odd gateway
octet and a short DHCP lease are normal for a phone hotspot, not evidence of a
shared LAN). No ethics gate here.

The only thing still worth a quick check is a **sanity check, not a scope
gate**: after everyone joins, confirm all three laptops actually associated to
the hotspot before Phase 1 runs, so nobody is silently missing from the results.
```bash
nmap -sn <detected-subnet>   # expect the three team MACs + the hotspot gateway
```
`python shared/config.py` prints the detected subnet if you need it.

### 5.2 Addressing drifts every session — HANDLED IN CODE
The hotspot hands out a new subnet and new IPs each session (§3.6). This is no
longer a manual chore: `config.py` auto-detects the subnet at runtime and
matches laptops by MAC, so nothing needs re-entering between sessions. Just
confirm all three joined (§5.1). MACs only change if someone swaps a laptop —
and Jayant's changes *during* Phase 3 on purpose.

### 5.3 The hotspot gateway is not a team asset
The gateway/DHCP/DNS host (whatever `.1`/`.117`/etc. the hotspot assigns) will
appear in Phase 1 results. It's the phone acting as router — exclude it from
hardening recommendations (you're auditing the three laptops, not the phone's
firmware) and say so in the report.

---

## 6. Findings already visible (before any tool runs)

Evidence straight from the `ipconfig` dumps — put these on slides.

1. **NetBIOS over TCP/IP enabled on all three laptops.** 100%-of-hosts finding,
   independent of the tooling. Phase 4 already flags NBNS (Medium) and
   `firewall_rules.txt` includes the disable command.

2. **DHCPv6 DUID leaks a MAC that spoofing doesn't change.** A DUID-LLT embeds a
   NIC's link-layer address and persists in the registry across a MAC change:
   - Jayant's DUID tail `BC-EC-A0-20-BB-15` = the **Ethernet** NIC (not the
     spoofed Wi-Fi).
   - Jay's `E8-9C-25-82-01-D6` = his Ethernet NIC.
   - Elan's `20-2B-20-C0-D1-29` = his **Wi-Fi** MAC — i.e. the exact address
     he'd spoof would still be exposed via DUID.

   **Sharpens Phase 3:** spoofing defeats naive MAC filtering but is *not*
   anonymity — a network logging DHCPv6 still correlates the device. Planned
   demo beat: after spoofing, re-run `ipconfig /all` and show the DUID
   unchanged. (Verify this live rather than asserting it.)

3. **Public IPv6 on all three (Jio).** Phase 1 scans IPv4 only; Phase 2 capture
   *will* contain IPv6. Report the asymmetry as a stated scope limitation.

---

## 7. Methodology note: Wi-Fi capture scope (Phase 2)

Elan captures from a **single node in normal mode**, so the pcap contains **his
own traffic + broadcast/multicast** (ARP, NBNS, LLMNR, mDNS, DHCP), not other
stations' unicast sessions. This is correct and defensible, not a shortfall.

**Monitor mode is effectively unavailable here:** Windows' NDIS driver model
doesn't expose raw 802.11 to userspace the way Linux does. Npcap has a monitor
toggle, but the team's built-in chipsets (Realtek RTL8821CE / RTL8852BE,
MediaTek MT7922) generally refuse it. And even with monitor mode, WPA2 encrypts
each station's traffic under a per-session key — you'd still need that station's
4-way handshake **and** the PSK to read anything.

Capture-visibility hierarchy for the report:

| Position | What you see |
|---|---|
| Normal mode (what we do) | Own traffic + broadcast domain |
| Monitor mode | All encrypted 802.11 frames — headers yes, payloads no |
| Monitor + handshake + PSK | Decrypted traffic for captured stations |
| ARP-spoof / MITM | Plaintext, by actively inserting into the path |

The presentation framing ties this back to Phase 3: reading a teammate's traffic
would require an **active** ARP-spoof position, and ARP has no authentication —
the same layer-2 weakness the MAC-spoof demonstrates. An actual ARP-spoof MITM
(bettercap/Ettercap, on our own network, with consent) is a possible extension
if there's time, but it's beyond the brief.

---

## 8. Quick-reference: what each person runs

```bash
# Everyone, once
pip install -r requirements.txt

# Member 1 (Jay) — from an Administrator shell
python phase1_discovery/scan.py                 # full scan
python phase1_discovery/scan.py --discovery-only # fast; the live-demo command
# hands over: phase1_discovery/outputs/hosts.json

# Member 2 (Elan) — flush DNS + close browser first, Administrator shell
python phase2_capture/capture.py --list
python phase2_capture/capture.py --duration 60 --generate-traffic
python phase2_capture/analyze.py
# hands over: packets.csv + protocol_stats.json (git add -f; NOT the pcap)

# Member 3 (Jayant) — me
python phase4_analysis/analyze_security.py --sample   # build now, before their data
python phase4_analysis/report.py
python phase3_spoofing/mac_control.py view            # then: demo (Administrator + SMAC)
python phase4_analysis/analyze_security.py            # for real, once their files land
python phase4_analysis/report.py
```
