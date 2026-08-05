"""Phase 1 - Network discovery and port scanning.

Drives Nmap through python-nmap in two passes, which is how you would do it by
hand:

  1. Host discovery (`nmap -sn <network>`) - who is alive on this subnet?
  2. Per-host port scan (`nmap -sV -O -p <ports> <host>`) - what is each one
     running, and what OS is it?

Splitting the passes keeps the second one fast: we only deep-scan hosts that
actually answered.

Produces (the Phase 1 half of the data contract in CLAUDE.md):
  outputs/hosts.json  - [{ip, hostname, mac, os, ports:[{port, protocol,
                          service, version, state}]}]
  outputs/hosts.csv   - the same data flattened, one row per open port

Usage:
    python scan.py                     # discovery + full scan of top 1000 ports
    python scan.py --discovery-only    # just "who is up" (fast, for the live demo)
    python scan.py --quick             # top 100 ports, no OS detection
    python scan.py --ports 1-1024      # explicit port range
    python scan.py --network 192.168.1.0/24   # override shared/config.py
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from shared import config
from shared.utils import (
    banner, die, ensure_dir, info, is_admin, normalise_mac, ok, print_table,
    rel, require_tool, step, warn, write_csv, write_json,
)

try:
    import nmap  # python-nmap
except ImportError:
    die("python-nmap is not installed.\n"
        "    Run:  pip install -r requirements.txt")


HOSTS_FIELDS = ["ip", "hostname", "mac", "vendor", "os", "os_accuracy",
                "port", "protocol", "service", "version", "state"]


def build_scanner() -> "nmap.PortScanner":
    """python-nmap needs the nmap binary; point it at ours explicitly."""
    nmap_exe = require_tool(
        "nmap",
        config.tool_path("nmap"),
        "Install Nmap from https://nmap.org/download.html (accept the Npcap "
        "driver), then reopen your terminal. If it is installed but not on "
        "PATH, set NMAP_PATH in shared/config.py.",
    )
    info(f"using nmap at {nmap_exe}")
    try:
        return nmap.PortScanner(nmap_search_path=(nmap_exe,))
    except nmap.PortScannerError as exc:
        die(f"could not start nmap: {exc}")


def discover_hosts(scanner: "nmap.PortScanner", network: str) -> list[str]:
    """Pass 1: ARP/ping sweep. Returns the IPs that answered."""
    step(f"Host discovery on {network}  (nmap -sn)")
    scanner.scan(hosts=network, arguments="-sn")
    alive = [ip for ip in scanner.all_hosts()
             if scanner[ip].state() == "up"]
    ok(f"{len(alive)} host(s) up")
    for ip in alive:
        label = config.host_label(ip)
        hostname = scanner[ip].hostname() or ""
        suffix = f"  <- {label}" if label else ""
        print(f"    {ip:<16} {hostname}{suffix}")
    return alive


def scan_host(scanner: "nmap.PortScanner", ip: str, arguments: str) -> dict:
    """Pass 2: one host, service + version (+ OS if requested)."""
    scanner.scan(hosts=ip, arguments=arguments)

    if ip not in scanner.all_hosts():
        warn(f"{ip} did not respond to the detailed scan")
        return {"ip": ip, "hostname": None, "mac": None, "os": None,
                "os_accuracy": None, "vendor": None, "state": "down", "ports": []}

    host = scanner[ip]
    addresses = host.get("addresses", {})
    mac = normalise_mac(addresses.get("mac"))
    vendor_map = host.get("vendor", {})
    vendor = vendor_map.get(addresses.get("mac")) if vendor_map else None

    os_name, os_accuracy = None, None
    matches = host.get("osmatch") or []
    if matches:
        os_name = matches[0].get("name")
        os_accuracy = matches[0].get("accuracy")

    ports: list[dict] = []
    for protocol in host.all_protocols():           # tcp, udp, ...
        for port in sorted(host[protocol].keys()):
            entry = host[protocol][port]
            version = " ".join(
                part for part in (entry.get("product"),
                                  entry.get("version"),
                                  entry.get("extrainfo"))
                if part
            ).strip()
            ports.append({
                "port": int(port),
                "protocol": protocol,
                "service": entry.get("name") or "unknown",
                "version": version or None,
                "state": entry.get("state"),
            })

    return {
        "ip": ip,
        "hostname": host.hostname() or None,
        "mac": mac,
        "vendor": vendor,
        "os": os_name,
        "os_accuracy": os_accuracy,
        "state": host.state(),
        "ports": ports,
    }


def flatten(hosts: list[dict]) -> list[dict]:
    """One CSV row per port; hosts with no open ports still get a row."""
    rows: list[dict] = []
    for host in hosts:
        base = {
            "ip": host["ip"],
            "hostname": host.get("hostname"),
            "mac": host.get("mac"),
            "vendor": host.get("vendor"),
            "os": host.get("os"),
            "os_accuracy": host.get("os_accuracy"),
        }
        if not host.get("ports"):
            rows.append({**base, "port": None, "protocol": None,
                         "service": None, "version": None, "state": "no open ports"})
            continue
        for port in host["ports"]:
            rows.append({**base, **port})
    return rows


def summarise(hosts: list[dict]) -> None:
    step("Summary")
    rows = []
    for host in hosts:
        open_ports = [p for p in host.get("ports", []) if p.get("state") == "open"]
        rows.append([
            host["ip"],
            config.host_label(host["ip"]) or host.get("hostname") or "",
            host.get("mac") or "",
            (host.get("os") or "unknown")[:34],
            len(open_ports),
            ", ".join(str(p["port"]) for p in open_ports[:8]) or "-",
        ])
    print_table(rows, ["IP", "HOST", "MAC", "OS (best guess)", "#OPEN", "OPEN PORTS"])


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 1 - Nmap discovery and port scan")
    parser.add_argument("--network", help="CIDR to scan (default: shared/config.py)")
    parser.add_argument("--ports", default=None,
                        help="port spec, e.g. '1-1024' or '22,80,443' "
                             "(default: nmap's top 1000)")
    parser.add_argument("--quick", action="store_true",
                        help="top 100 ports, skip OS detection - fast demo scan")
    parser.add_argument("--discovery-only", action="store_true",
                        help="stop after the host sweep (no port scan)")
    parser.add_argument("--no-os", action="store_true", help="skip OS detection")
    parser.add_argument("--udp", action="store_true",
                        help="also scan the top UDP ports (slow)")
    args = parser.parse_args()

    banner("PHASE 1 - DISCOVERY AND SCANNING")

    network = args.network or config.target_network()
    scanner = build_scanner()
    info(f"target network: {network}")
    info("scope: the team's own laptops on the team's own network only")

    if not args.network:
        size = config.target_network_size()
        if size > 1024:
            warn(f"this subnet holds {size} addresses - the sweep will be slow "
                 f"and will touch devices that are not ours.\n"
                 f"    Pin TARGET_NETWORK in shared/config.py to the range your "
                 f"three laptops are actually in (e.g. a /24), or pass "
                 f"--network.")

    alive = discover_hosts(scanner, network)
    if not alive:
        die("no hosts responded. Check that all laptops are on the same subnet "
            "and that Windows Firewall allows inbound ICMP echo.")

    if args.discovery_only:
        ensure_dir(config.PHASE1_OUTPUTS)
        write_json(config.PHASE1_OUTPUTS / "discovery.json",
                   {"network": network, "hosts_up": alive})
        return 0

    # Build the nmap argument string for pass 2.
    want_os = not (args.no_os or args.quick)
    if want_os and not is_admin():
        warn("not running as Administrator - OS detection needs raw sockets, "
             "so it is being skipped. Re-run from an elevated shell for OS results.")
        want_os = False

    arguments = ["-sV"]                      # service + version detection
    arguments.append("-sS" if is_admin() else "-sT")   # SYN scan needs elevation
    if want_os:
        arguments.append("-O")
    if args.udp:
        arguments.append("-sU")
    if args.quick:
        arguments.append("--top-ports 100")
        arguments.append("-T4")
    elif args.ports:
        arguments.append(f"-p {args.ports}")
    argument_string = " ".join(arguments)

    step(f"Port + service scan of {len(alive)} host(s)  (nmap {argument_string})")
    if not args.quick:
        info("this takes a few minutes per host - version and OS detection are "
             "doing real probing")

    results: list[dict] = []
    for index, ip in enumerate(alive, start=1):
        print(f"  [{index}/{len(alive)}] scanning {ip} ...")
        try:
            results.append(scan_host(scanner, ip, argument_string))
        except nmap.PortScannerError as exc:
            warn(f"{ip}: scan failed ({exc})")
            results.append({"ip": ip, "hostname": None, "mac": None, "os": None,
                            "os_accuracy": None, "vendor": None,
                            "state": "error", "ports": []})

    summarise(results)

    ensure_dir(config.PHASE1_OUTPUTS)
    write_json(config.HOSTS_JSON, results)
    write_csv(config.HOSTS_CSV, flatten(results), HOSTS_FIELDS)

    step("Next")
    info(f"{rel(config.HOSTS_JSON)} is what Phase 4 consumes - hand it to Member 3.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print()
        warn("interrupted - no output written")
        raise SystemExit(130)
