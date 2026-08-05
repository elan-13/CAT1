"""Phase 3 - MAC address spoofing: orchestration and verification.

SMAC is a Windows GUI tool, so the *change* itself is a few clicks - there is no
CLI to wrap and pretending otherwise would be dishonest. What this script does
is everything around the change, which is the part that actually makes it an
assessment rather than a demo:

  * reads the real adapter state from Windows (`getmac /v` + `ipconfig /all`)
  * snapshots it before / after / after-restore, with timestamps
  * verifies the MAC actually changed (and actually got restored)
  * restarts the adapter so the new address takes effect
  * writes an auditable before/after log

Produces:
  outputs/mac_log.json - full snapshots, every stage, with all adapters
  outputs/mac_log.csv  - flat before/after/restored log for the report

Usage:
    python mac_control.py view                  # current adapters and MACs
    python mac_control.py demo                  # guided before -> spoof -> restore
    python mac_control.py snapshot --stage before
    python mac_control.py verify --expected 00-11-22-33-44-55
    python mac_control.py restart-adapter       # needs an elevated shell
    python mac_control.py report                # before/after table from the log

Scope: this only ever touches this laptop's own adapter, with the owner sitting
in front of it. Spoofing someone else's MAC on a network you do not own is a
different thing entirely and is not what this project does.
"""

from __future__ import annotations

import argparse
import csv as csv_module
import io
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from shared import config
from shared.utils import (
    banner, confirm, die, ensure_dir, find_tool, info, is_admin, normalise_mac,
    now_iso, ok, pause, print_table, read_json, rel, run, step, warn,
    write_csv, write_json,
)

LOG_FIELDS = ["stage", "timestamp", "host", "interface", "adapter_description",
              "mac", "ipv4", "elevated", "note"]

STAGES = ("before", "after", "restored", "adhoc")


# --------------------------------------------------------------------------
# Reading adapter state from Windows
# --------------------------------------------------------------------------


def parse_getmac() -> list[dict]:
    """`getmac /v /fo csv /nh` ->
    "Connection Name","Network Adapter","Physical Address","Transport Name"
    """
    result = run(["getmac", "/v", "/fo", "csv", "/nh"], timeout=60)
    if result.returncode != 0:
        warn(f"getmac failed: {result.stderr.strip()}")
        return []

    adapters = []
    for row in csv_module.reader(io.StringIO(result.stdout)):
        if len(row) < 3:
            continue
        connection, description, mac = row[0], row[1], row[2]
        transport = row[3] if len(row) > 3 else ""
        adapters.append({
            "interface": connection.strip(),
            "adapter_description": description.strip(),
            "mac": normalise_mac(mac) if "N/A" not in mac else None,
            "transport": transport.strip(),
            "connected": "disconnected" not in transport.lower(),
        })
    return adapters


def parse_ipconfig() -> dict[str, dict]:
    """`ipconfig /all` -> {connection name: {description, mac, ipv4}}.

    getmac gives us the MAC but no IP; ipconfig gives us both. Cross-checking
    the two is the point - if they disagree, something is stale.
    """
    result = run(["ipconfig", "/all"], timeout=60)
    if result.returncode != 0:
        return {}

    adapters: dict[str, dict] = {}
    current: str | None = None
    for line in result.stdout.splitlines():
        header = re.match(r"^[A-Za-z].*adapter\s+(.+?):\s*$", line)
        if header:
            current = header.group(1).strip()
            adapters[current] = {"description": None, "mac": None, "ipv4": None}
            continue
        if not current:
            continue
        entry = adapters[current]
        if match := re.search(r"Description[ .]*:\s*(.+)$", line):
            entry["description"] = match.group(1).strip()
        elif match := re.search(r"Physical Address[ .]*:\s*([0-9A-Fa-f:-]+)", line):
            entry["mac"] = normalise_mac(match.group(1))
        elif match := re.search(r"IPv4 Address[ .]*:\s*([0-9.]+)", line):
            entry["ipv4"] = match.group(1).strip()
    return adapters


def read_adapters() -> list[dict]:
    """Merged view: getmac as the spine, ipconfig for the IP address."""
    ipconfig = parse_ipconfig()
    adapters = parse_getmac()

    for adapter in adapters:
        match = ipconfig.get(adapter["interface"])
        if not match:
            # getmac's connection name and ipconfig's adapter name usually agree;
            # when they do not, fall back to matching on the adapter description.
            for entry in ipconfig.values():
                if entry.get("description") == adapter["adapter_description"]:
                    match = entry
                    break
        if match:
            adapter["ipv4"] = match.get("ipv4")
            if match.get("mac") and match["mac"] != adapter["mac"]:
                adapter["mac_ipconfig"] = match["mac"]
        else:
            adapter["ipv4"] = None

    if not adapters:  # getmac unavailable - fall back to ipconfig alone
        for name, entry in ipconfig.items():
            adapters.append({
                "interface": name,
                "adapter_description": entry.get("description"),
                "mac": entry.get("mac"),
                "ipv4": entry.get("ipv4"),
                "transport": "",
                "connected": bool(entry.get("ipv4")),
            })
    return adapters


def find_adapter(adapters: list[dict], wanted: str) -> dict | None:
    wanted_lower = wanted.strip().lower()
    for adapter in adapters:
        if adapter["interface"].lower() == wanted_lower:
            return adapter
    for adapter in adapters:                     # tolerate "Wi-Fi" vs "Wi-Fi 2"
        if wanted_lower in adapter["interface"].lower():
            return adapter
    for adapter in adapters:
        if wanted_lower in (adapter.get("adapter_description") or "").lower():
            return adapter
    return None


def show_adapters(adapters: list[dict], highlight: str | None = None) -> None:
    print_table(
        [[("*" if highlight and a["interface"] == highlight else " "),
          a["interface"], a.get("mac") or "-", a.get("ipv4") or "-",
          "up" if a.get("connected") else "down",
          (a.get("adapter_description") or "")[:40]]
         for a in adapters],
        ["", "INTERFACE", "MAC", "IPv4", "LINK", "ADAPTER"],
    )


# --------------------------------------------------------------------------
# The log
# --------------------------------------------------------------------------


def load_log() -> dict:
    if config.MAC_LOG_JSON.exists():
        try:
            return read_json(config.MAC_LOG_JSON)
        except (ValueError, OSError):
            warn("existing mac_log.json is unreadable - starting a new one")
    return {"host": config.this_host(), "created_at": now_iso(), "entries": []}


def save_log(log: dict) -> None:
    ensure_dir(config.PHASE3_OUTPUTS)
    log["updated_at"] = now_iso()
    write_json(config.MAC_LOG_JSON, log)
    write_csv(config.MAC_LOG_CSV, log["entries"], LOG_FIELDS)


def snapshot(stage: str, note: str | None = None,
             interface: str | None = None, quiet: bool = False) -> dict:
    """Record the current state of the target adapter (plus all others)."""
    interface = interface or config.spoof_interface()
    adapters = read_adapters()
    target = find_adapter(adapters, interface)
    if not target:
        show_adapters(adapters)
        die(f"adapter {interface!r} not found - set SPOOF_INTERFACE in "
            f"shared/config.py to one of the INTERFACE values above.")

    entry = {
        "stage": stage,
        "timestamp": now_iso(),
        "host": config.this_host(),
        "interface": target["interface"],
        "adapter_description": target.get("adapter_description"),
        "mac": target.get("mac"),
        "ipv4": target.get("ipv4"),
        "elevated": is_admin(),
        "note": note,
        "all_adapters": adapters,
    }

    log = load_log()
    log["interface"] = target["interface"]
    log["entries"].append(entry)
    save_log(log)

    if not quiet:
        ok(f"[{stage}] {target['interface']}  MAC={target.get('mac')}  "
           f"IPv4={target.get('ipv4')}")
    return entry


def last_entry(log: dict, stage: str) -> dict | None:
    matches = [e for e in log.get("entries", []) if e.get("stage") == stage]
    return matches[-1] if matches else None


# --------------------------------------------------------------------------
# Actions
# --------------------------------------------------------------------------


def restart_adapter(interface: str, assume_yes: bool = False) -> bool:
    """Disable then re-enable the adapter so a new MAC takes effect.

    SMAC does this for you when you click 'Update MAC'. Doing it explicitly is
    useful when the change did not appear to take, and it makes the step visible
    during the presentation.
    """
    if not is_admin():
        warn("restarting an adapter needs an elevated shell - skipping.\n"
             "    Re-run from PowerShell 'Run as administrator', or just let "
             "SMAC restart the adapter for you.")
        return False

    if not assume_yes and not confirm(
            f"disable and re-enable {interface!r}? You will drop off the "
            f"network for a few seconds.", default=False):
        info("skipped")
        return False

    for state in ("disabled", "enabled"):
        step(f"netsh: {state} {interface}")
        result = run(["netsh", "interface", "set", "interface",
                      f"name={interface}", f"admin={state}"], timeout=60)
        if result.returncode != 0:
            warn(f"netsh failed: {(result.stderr or result.stdout).strip()}")
            return False
    ok("adapter restarted - give Windows a few seconds to reconnect")
    return True


def launch_smac() -> bool:
    smac = find_tool("smac", config.tool_path("smac"))
    if not smac:
        warn("SMAC not found. Install the free version from "
             "https://www.klcconsulting.net/smac/ and set SMAC_PATH in "
             "shared/config.py, or just open it from the Start menu.")
        return False
    step(f"launching SMAC ({smac})")
    try:
        subprocess.Popen([smac])          # GUI - do not wait on it
        ok("SMAC launched")
        return True
    except OSError as exc:
        warn(f"could not launch SMAC: {exc}")
        return False


def verify(expected: str | None, interface: str | None = None) -> int:
    """Compare the adapter's current MAC against an expected value."""
    interface = interface or config.spoof_interface()
    expected = normalise_mac(expected or config.expected_mac())
    if not expected:
        die("nothing to verify against.\n"
            "    Pass --expected AA-BB-CC-DD-EE-FF, or record this laptop's "
            "real MAC in shared/config.py (HOSTS -> mac).")

    adapters = read_adapters()
    target = find_adapter(adapters, interface)
    if not target:
        die(f"adapter {interface!r} not found")

    current = normalise_mac(target.get("mac"))
    step(f"Verifying {target['interface']}")
    print(f"    expected : {expected}")
    print(f"    current  : {current}")

    if current == expected:
        ok("MATCH - the adapter is using the expected MAC")
        return 0
    warn("DIFFERENT - the adapter is not using the expected MAC "
         "(that is a pass if you just spoofed it, and a fail if you just "
         "restored it)")
    return 1


def print_report() -> int:
    if not config.MAC_LOG_JSON.exists():
        die(f"no log yet at {rel(config.MAC_LOG_JSON)} - run "
            f"'python mac_control.py demo' first.")
    log = read_json(config.MAC_LOG_JSON)
    entries = log.get("entries", [])
    if not entries:
        die("the log is empty")

    step(f"MAC log for {log.get('host')} ({len(entries)} entries)")
    print_table([[e["stage"], e["timestamp"][11:19], e["interface"],
                  e.get("mac") or "-", e.get("ipv4") or "-",
                  (e.get("note") or "")[:38]] for e in entries],
                ["STAGE", "TIME", "INTERFACE", "MAC", "IPv4", "NOTE"])

    before, after = last_entry(log, "before"), last_entry(log, "after")
    restored = last_entry(log, "restored")

    step("Result")
    if before and after:
        changed = normalise_mac(before.get("mac")) != normalise_mac(after.get("mac"))
        (ok if changed else warn)(
            f"spoof: {before.get('mac')} -> {after.get('mac')} "
            f"({'changed' if changed else 'UNCHANGED - the spoof did not take'})")
    if before and restored:
        back = normalise_mac(before.get("mac")) == normalise_mac(restored.get("mac"))
        (ok if back else warn)(
            f"restore: {restored.get('mac')} "
            f"({'back to the original' if back else 'NOT restored - fix this before you finish'})")
    return 0


# --------------------------------------------------------------------------
# The guided demo - this is what gets run in the presentation
# --------------------------------------------------------------------------


def demo(interface: str, assume_yes: bool) -> int:
    banner("PHASE 3 - MAC SPOOFING (GUIDED)")
    info("scope: this laptop's own adapter, changed and then restored")
    info(f"target adapter: {interface}")

    step("1. Current state (before)")
    adapters = read_adapters()
    show_adapters(adapters, highlight=interface)
    before = snapshot("before", note="pre-spoof baseline", interface=interface)
    original = before.get("mac")

    step("2. Change the MAC in SMAC")
    print("   In SMAC:")
    print(f"     a. select the {interface} adapter in the list")
    print("     b. type a new MAC in 'New Spoofed MAC Address'")
    print("        (keep the first 3 octets of a real vendor prefix so it looks")
    print("         plausible on the network - e.g. 00-1C-B3-xx-xx-xx)")
    print("     c. click 'Update MAC' and let it restart the adapter")
    launch_smac()
    pause("   Press Enter once SMAC reports the change is applied...")

    step("3. Let Windows settle")
    if not is_admin():
        info("not elevated - relying on SMAC's own adapter restart")
    else:
        restart_adapter(interface, assume_yes=assume_yes)

    step("4. Verify the change (after)")
    after = snapshot("after", note="post-spoof", interface=interface)
    changed = normalise_mac(original) != normalise_mac(after.get("mac"))
    if changed:
        ok(f"spoof confirmed: {original} -> {after.get('mac')}")
        info("this is the moment for Member 1 to re-run "
             "'python phase1_discovery/scan.py --discovery-only' - the laptop "
             "reappears under a different MAC.")
    else:
        warn("the MAC did not change. Common causes: the adapter driver refuses "
             "locally-administered addresses, SMAC needs elevation, or the "
             "adapter needs a full disable/enable.")
    pause("   Press Enter when the live Nmap re-scan is done...")

    step("5. Restore the original MAC")
    print("   In SMAC: click 'Remove MAC' (or re-enter the original) and update.")
    print(f"   Original MAC: {original}")
    pause("   Press Enter once SMAC has restored it...")
    if is_admin():
        restart_adapter(interface, assume_yes=assume_yes)

    restored = snapshot("restored", note="post-restore", interface=interface)
    if normalise_mac(restored.get("mac")) == normalise_mac(original):
        ok(f"restored to {original} - the laptop is back to its real identity")
    else:
        warn(f"still showing {restored.get('mac')}, expected {original}. "
             f"Restore it in SMAC before you finish.")

    print_report()
    step("Next")
    info(f"{rel(config.MAC_LOG_JSON)} is the evidence for the Phase 3 slide; "
         f"Phase 4 picks it up automatically if it is present.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 3 - MAC spoofing control")
    parser.add_argument("--interface", help="adapter name (default: shared/config.py)")
    parser.add_argument("--yes", action="store_true",
                        help="do not ask before restarting the adapter")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("view", help="show adapters and their MACs")
    sub.add_parser("demo", help="guided before -> spoof -> verify -> restore")
    sub.add_parser("report", help="print the before/after log")
    sub.add_parser("restart-adapter", help="disable + re-enable the adapter")
    sub.add_parser("launch-smac", help="open SMAC")

    snap = sub.add_parser("snapshot", help="record the current MAC")
    snap.add_argument("--stage", choices=STAGES, default="adhoc")
    snap.add_argument("--note")

    check = sub.add_parser("verify", help="compare current MAC to an expected one")
    check.add_argument("--expected", help="MAC to expect (default: shared/config.py)")

    args = parser.parse_args()
    interface = args.interface or config.spoof_interface()
    command = args.command or "view"

    if command == "view":
        banner("PHASE 3 - ADAPTER VIEW")
        adapters = read_adapters()
        show_adapters(adapters, highlight=interface)
        target = find_adapter(adapters, interface)
        if target:
            info(f"configured spoof target: {target['interface']} "
                 f"(MAC {target.get('mac')})")
        else:
            warn(f"adapter {interface!r} not in the list - update "
                 f"SPOOF_INTERFACE in shared/config.py")
        return 0

    if command == "snapshot":
        banner("PHASE 3 - SNAPSHOT")
        snapshot(args.stage, note=args.note, interface=interface)
        return 0

    if command == "verify":
        banner("PHASE 3 - VERIFY")
        return verify(args.expected, interface)

    if command == "restart-adapter":
        banner("PHASE 3 - RESTART ADAPTER")
        return 0 if restart_adapter(interface, assume_yes=args.yes) else 1

    if command == "launch-smac":
        return 0 if launch_smac() else 1

    if command == "report":
        banner("PHASE 3 - MAC LOG")
        return print_report()

    if command == "demo":
        return demo(interface, assume_yes=args.yes)

    parser.print_help()
    return 1


if __name__ == "__main__":
    if sys.platform != "win32":
        warn("this script uses Windows tools (getmac / ipconfig / netsh) and "
             "SMAC is Windows-only")
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print()
        warn("interrupted")
        raise SystemExit(130)
