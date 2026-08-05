# Phase 3 — MAC Spoofing (Member 3)

Change your laptop's hardware address, prove the network accepts the new
identity, then put it back. The point is not the trick — it is the conclusion:
**a MAC address is not an authentication credential, and anything that treats it
as one is broken.**

## What you install

| What | How |
|---|---|
| SMAC | Free version from <https://www.klcconsulting.net/smac/>. Windows only, which is fine — we are all on Windows. |
| Python packages | Nothing extra. This script is stdlib only. |

If SMAC is not at `C:\Program Files\SMAC\smac.exe`, set `SMAC_PATH` in
`shared/config.py`.

Also set `SPOOF_INTERFACE` in `shared/config.py` to your adapter name — run
`python mac_control.py view` to see the exact names.

## Before you automate anything: understand the layers

Run this and look at what comes back:

```bash
getmac /v
ipconfig /all
```

The **physical address** is burned into the network card, but Windows lets the
driver override it — that override is all SMAC does. Meanwhile the **IP address**
is assigned by DHCP and is a completely separate identity. Being clear about
which layer you are changing (layer 2, not layer 3) is the difference between
explaining this well and hand-waving.

Then do one spoof by hand in the SMAC GUI so you know the click path before you
are standing in front of the class.

## How to run it

The main event is the guided demo, which walks the whole cycle and logs every
stage:

```bash
python mac_control.py demo
```

It will: snapshot your real MAC → open SMAC and wait while you change it →
restart the adapter → verify the change actually took → pause for the live Nmap
re-scan → wait while you restore → verify you are back to the original.

| Command | What it does |
|---|---|
| `python mac_control.py view` | List adapters with their MACs and IPs |
| `python mac_control.py demo` | **The presentation script.** Guided before → spoof → verify → restore |
| `python mac_control.py snapshot --stage before` | Record current state (stages: `before`, `after`, `restored`, `adhoc`) |
| `python mac_control.py verify --expected AA-BB-CC-DD-EE-FF` | Check the adapter against an expected MAC |
| `python mac_control.py restart-adapter` | Disable + re-enable the adapter (needs Administrator) |
| `python mac_control.py launch-smac` | Just open SMAC |
| `python mac_control.py report` | Print the before/after table from the log |

**Run from an Administrator terminal.** SMAC needs it to write the driver
setting, and `restart-adapter` needs it to call `netsh`.

### Picking a plausible MAC

Keep the first three octets (the OUI) from a real vendor — e.g. `00-1C-B3-xx-xx-xx`
is Apple. A completely random address can look obviously fake to network gear,
and part of the point is that a spoofed address blends in.

## What it produces

Both in `outputs/`.

| File | What it is |
|---|---|
| `mac_log.json` | Full snapshots at every stage: timestamp, interface, MAC, IPv4, whether the shell was elevated, plus every other adapter for cross-checking |
| `mac_log.csv` | Flat before/after/restored log — this is your slide table |

Phase 4 picks `mac_log.json` up automatically if it exists and turns a
successful before→after change into a finding about MAC-based access control.

## The presentation moment

This is the bit that ties the whole project together:

1. You run `python mac_control.py demo` and change your MAC.
2. **Member 1 immediately re-runs** `python phase1_discovery/scan.py --discovery-only`.
3. Your laptop shows up under a different hardware address — from Nmap's point
   of view, a device that was never there before.
4. You restore, they re-scan, you are back.

Have Member 1's command already typed into a terminal so it is one keypress.
The demo script pauses and waits for exactly this.

## When it does not work

**The MAC does not change.** Most common by far. In order: are you running SMAC
as Administrator? Did the adapter actually restart (`python mac_control.py
restart-adapter`)? Some Wi-Fi drivers — Intel ones especially — refuse spoofed
addresses outright. If yours does, try the Ethernet adapter instead, or use a
teammate's laptop for the demo and explain the driver restriction. That
restriction is itself worth a sentence in the report.

**You lose network access after spoofing.** Expected for a few seconds while
DHCP re-leases. If it persists, the new MAC may have been rejected — restore it
in SMAC and restart the adapter.

**`getmac` and `ipconfig` disagree.** The log records both when they differ.
Usually means the adapter has not been restarted since the change, so the
change has not taken effect yet.

**You cannot get back to the original.** In SMAC, click **Remove MAC** (not
"update with the old value") — that clears the driver override entirely. Your
real MAC is in `outputs/mac_log.json` under the `before` entry.

## Scope and ethics

You are changing your own laptop's address, sitting in front of it, and putting
it back when you are done — that is the whole exercise. Spoofing a MAC to
impersonate another device, get past a filter you were not given access to, or
evade logging on a network you do not own is a different act with different
consequences, and it is not what this project does. Say the boundary out loud
during the presentation; it is part of the marks for understanding the risk.

**Always restore before you finish.** `python mac_control.py report` will tell
you plainly whether you did.
