"""Phase 2a - Packet capture driver.

Wraps TShark (the command-line Wireshark that ships with the Wireshark
installer). Wireshark's GUI is still the right place to *understand* what you
captured - this script exists so the capture itself is reproducible and so the
demo does not depend on anyone clicking the right shark fin at the right time.

Produces:
  outputs/capture.pcap      - raw capture, the input to analyze.py
  outputs/capture_meta.json - what was captured, on which interface, for how long

Usage:
    python capture.py --list                     # which interfaces can I capture on?
    python capture.py --duration 60              # capture 60s on the configured iface
    python capture.py --duration 60 --generate-traffic
                                                 # ...and make traffic while it runs
    python capture.py --duration 30 --interface "Wi-Fi"
    python capture.py --count 500                # stop after 500 packets instead

The `--generate-traffic` flag runs the four things the assessment asks for
(ping, DNS lookup, web browse, download) in the background so the pcap is
guaranteed to contain them. You can also just browse manually while it runs -
that is the more honest demo.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from shared import config
from shared.utils import (
    banner, die, ensure_dir, human_bytes, info, ok, print_table, rel,
    require_tool, run, step, warn, write_json,
)

TSHARK_HINT = ("Install Wireshark from https://www.wireshark.org/download.html "
               "and accept the Npcap driver. TShark is included. If it is "
               "installed but not on PATH, set TSHARK_PATH in shared/config.py.")


# --------------------------------------------------------------------------
# Interfaces
# --------------------------------------------------------------------------


def list_interfaces(tshark: str) -> list[dict]:
    """Parse `tshark -D`, whose lines look like:
    1. \\Device\\NPF_{GUID} (Wi-Fi)
    """
    result = run([tshark, "-D"], timeout=60)
    if result.returncode != 0:
        die(f"'tshark -D' failed: {result.stderr.strip()}\n"
            f"    On Windows this usually means Npcap is missing or the "
            f"terminal is not elevated.")

    interfaces = []
    for line in result.stdout.splitlines():
        match = re.match(r"\s*(\d+)\.\s+(\S+)(?:\s+\((.*)\))?", line.strip())
        if match:
            interfaces.append({
                "index": int(match.group(1)),
                "device": match.group(2),
                "name": (match.group(3) or match.group(2)).strip(),
            })
    return interfaces


def resolve_interface(tshark: str, wanted: str | None) -> dict:
    """Match the configured interface against index, friendly name or device."""
    interfaces = list_interfaces(tshark)
    if not interfaces:
        die("tshark reported no capture interfaces. Is Npcap installed?")

    if not wanted:
        step("Available capture interfaces")
        print_table([[i["index"], i["name"], i["device"]] for i in interfaces],
                    ["#", "NAME", "DEVICE"])
        die("no capture interface configured.\n"
            "    Set CAPTURE_INTERFACE in shared/config.py to one of the NAME "
            "values above (e.g. \"Wi-Fi\"), or pass --interface.")

    wanted_str = str(wanted).strip()
    for interface in interfaces:
        if (wanted_str == str(interface["index"])
                or wanted_str.lower() == interface["name"].lower()
                or wanted_str.lower() == interface["device"].lower()):
            return interface

    step("Available capture interfaces")
    print_table([[i["index"], i["name"], i["device"]] for i in interfaces],
                ["#", "NAME", "DEVICE"])
    die(f"interface {wanted_str!r} not found - pick one from the list above.")


# --------------------------------------------------------------------------
# Traffic generation (optional, so the pcap is guaranteed to be interesting)
# --------------------------------------------------------------------------


def generate_traffic(stop: threading.Event) -> None:
    """Ping + DNS + HTTP + a small download, on a loop until told to stop.

    Everything here is ordinary traffic to our own laptops and to public sites.
    Plain HTTP is used deliberately: Phase 4's whole point is showing that
    cleartext protocols are visible in the capture.
    """
    targets = [h["ip"] for h in config.known_hosts() if h.get("ip")]
    domains = ["example.com", "wikipedia.org", "python.org"]

    def quiet(cmd, timeout=20):
        try:
            subprocess.run(cmd, capture_output=True, timeout=timeout)
        except (OSError, subprocess.SubprocessError):
            pass

    round_number = 0
    while not stop.is_set():
        round_number += 1
        # 1. ICMP to the other laptops (and the gateway if we know none).
        for ip in targets or ["8.8.8.8"]:
            if stop.is_set():
                return
            quiet(["ping", "-n", "2", ip])

        # 2. DNS lookups - these show up as UDP/53 query + response pairs.
        for domain in domains:
            if stop.is_set():
                return
            quiet(["nslookup", domain])

        # 3+4. A cleartext HTTP fetch and an HTTPS fetch (the "browse" and
        # "download" steps). curl ships with Windows 10+.
        for url in ("http://example.com", "https://www.python.org/static/img/python-logo.png"):
            if stop.is_set():
                return
            quiet(["curl", "-s", "-o", "NUL", "--max-time", "10", url], timeout=15)

        stop.wait(2)


# --------------------------------------------------------------------------
# Capture
# --------------------------------------------------------------------------


def capture(tshark: str, interface: dict, output: Path, duration: int | None,
            count: int | None, capture_filter: str | None,
            with_traffic: bool) -> dict:
    ensure_dir(output.parent)

    cmd = [tshark, "-i", interface["device"], "-w", str(output)]
    if duration:
        cmd += ["-a", f"duration:{duration}"]
    if count:
        cmd += ["-c", str(count)]
    if capture_filter:
        cmd += ["-f", capture_filter]

    step(f"Capturing on {interface['name']}")
    info("$ " + " ".join(cmd))
    if duration:
        info(f"running for {duration}s - browse, ping, do something noisy")
    if count:
        info(f"stopping after {count} packets")
    if not duration and not count:
        info("no limit set - press Ctrl+C to stop the capture")

    stop_event = threading.Event()
    traffic_thread = None
    if with_traffic:
        info("generating background traffic (ping / DNS / HTTP / download)")
        traffic_thread = threading.Thread(target=generate_traffic,
                                          args=(stop_event,), daemon=True)
        traffic_thread.start()

    started = time.time()
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, errors="replace")
    try:
        _, stderr = process.communicate(
            timeout=(duration + 30) if duration else None)
    except KeyboardInterrupt:
        info("stopping capture ...")
        process.terminate()
        try:
            _, stderr = process.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            _, stderr = process.communicate()
    except subprocess.TimeoutExpired:
        warn("tshark overran its duration - terminating")
        process.terminate()
        _, stderr = process.communicate()
    finally:
        stop_event.set()
        if traffic_thread:
            traffic_thread.join(timeout=10)

    elapsed = round(time.time() - started, 1)

    if not output.exists() or output.stat().st_size == 0:
        die("capture file is empty.\n"
            f"    tshark said: {(stderr or '').strip()}\n"
            "    Check that you picked the adapter that actually carries your "
            "traffic, and that Npcap is installed.")

    size = output.stat().st_size
    ok(f"captured {human_bytes(size)} to {rel(output)} in {elapsed}s")

    meta = {
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "interface_name": interface["name"],
        "interface_device": interface["device"],
        "duration_requested_s": duration,
        "packet_limit": count,
        "capture_filter": capture_filter,
        "elapsed_s": elapsed,
        "pcap": str(output),
        "pcap_bytes": size,
        "traffic_generated": with_traffic,
        "scope": "team-owned laptops on the team's own network",
    }
    write_json(output.parent / "capture_meta.json", meta)
    return meta


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 2 - TShark capture driver")
    parser.add_argument("--list", action="store_true",
                        help="list capture interfaces and exit")
    parser.add_argument("--interface", help="interface name, index or device "
                                            "(default: shared/config.py)")
    parser.add_argument("--duration", type=int, default=60,
                        help="seconds to capture (default 60; 0 = until Ctrl+C)")
    parser.add_argument("--count", type=int, help="stop after N packets")
    parser.add_argument("--filter", dest="capture_filter",
                        help="BPF capture filter, e.g. 'not port 22'")
    parser.add_argument("--generate-traffic", action="store_true",
                        help="run ping/DNS/HTTP/download in the background "
                             "while capturing")
    parser.add_argument("--output", type=Path, default=config.CAPTURE_PCAP,
                        help="pcap path (default outputs/capture.pcap)")
    args = parser.parse_args()

    banner("PHASE 2 - PACKET CAPTURE")
    tshark = require_tool("tshark", config.tool_path("tshark"), TSHARK_HINT)
    info(f"using tshark at {tshark}")

    if args.list:
        interfaces = list_interfaces(tshark)
        step("Capture interfaces")
        print_table([[i["index"], i["name"], i["device"]] for i in interfaces],
                    ["#", "NAME", "DEVICE"])
        info("put the NAME you want into CAPTURE_INTERFACE in shared/config.py")
        return 0

    interface = resolve_interface(tshark, args.interface or config.capture_interface())
    capture(
        tshark=tshark,
        interface=interface,
        output=Path(args.output),
        duration=args.duration or None,
        count=args.count,
        capture_filter=args.capture_filter,
        with_traffic=args.generate_traffic,
    )

    step("Next")
    info("python analyze.py    # parse the pcap into packets.csv + protocol_stats.json")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print()
        warn("interrupted")
        raise SystemExit(130)
