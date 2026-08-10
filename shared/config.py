"""Network configuration for the assessment.

This is the ONE place network specifics live. No IP address, subnet, adapter
name or tool path should appear anywhere else in the repo - every phase script
imports what it needs from here.

Fill in the "EDIT ME" block below on day one (see shared/SETUP.md), commit it,
and the rest of the repo just works.

Anything here can also be overridden at runtime with an environment variable,
which is handy when one laptop's adapter is named differently:

    set NSA_TARGET_NETWORK=192.168.137.0/24
    set NSA_CAPTURE_INTERFACE=Wi-Fi
"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
import subprocess
from pathlib import Path

# --------------------------------------------------------------------------
# Paths (derived - do not edit)
# --------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent

PHASE1_DIR = REPO_ROOT / "phase1_discovery"
PHASE2_DIR = REPO_ROOT / "phase2_capture"
PHASE3_DIR = REPO_ROOT / "phase3_spoofing"
PHASE4_DIR = REPO_ROOT / "phase4_analysis"

PHASE1_OUTPUTS = PHASE1_DIR / "outputs"
PHASE2_OUTPUTS = PHASE2_DIR / "outputs"
PHASE3_OUTPUTS = PHASE3_DIR / "outputs"
PHASE4_OUTPUTS = PHASE4_DIR / "outputs"

# Canonical filenames - the data contract in CLAUDE.md. Phase 4 looks for these
# exact names, so change them here (not in the phase scripts) if you must.
HOSTS_JSON = PHASE1_OUTPUTS / "hosts.json"
HOSTS_CSV = PHASE1_OUTPUTS / "hosts.csv"
CAPTURE_PCAP = PHASE2_OUTPUTS / "capture.pcap"
PACKETS_CSV = PHASE2_OUTPUTS / "packets.csv"
PROTOCOL_STATS_JSON = PHASE2_OUTPUTS / "protocol_stats.json"
MAC_LOG_JSON = PHASE3_OUTPUTS / "mac_log.json"
MAC_LOG_CSV = PHASE3_OUTPUTS / "mac_log.csv"
FINDINGS_JSON = PHASE4_OUTPUTS / "findings.json"
FINDINGS_CSV = PHASE4_OUTPUTS / "findings.csv"
FIREWALL_RULES_TXT = PHASE4_OUTPUTS / "firewall_rules.txt"
REPORT_XLSX = PHASE4_OUTPUTS / "report.xlsx"
CHARTS_DIR = PHASE4_OUTPUTS / "charts"


# ==========================================================================
# EDIT ME - everything below this line is your network
# ==========================================================================

# The subnet you are assessing, in CIDR form, e.g. "192.168.1.0/24".
# Leave as None to auto-detect from this laptop's own IP (see target_network()).
#
# Recorded 2026-08-05: all three laptops sit in 10.25.254.0/24, gateway and
# DHCP and DNS all on 10.25.254.117. Pinned rather than auto-detected so a
# laptop that wanders onto another network cannot widen the scan.
TARGET_NETWORK: str | None = "10.25.254.0/24"

# The three team laptops, from `ipconfig /all` on each (2026-08-05).
# `ip` and `mac` are used for labelling the report and for Phase 3's spoofing
# check, not for scanning - a stale IP costs you a label, not a scan.
#
# NOTE: the DHCP lease here is only 1 hour, so these addresses will drift.
# Re-check with `ipconfig` and update before the presentation.
HOSTS: list[dict] = [
    {"name": "laptop-1", "owner": "Member 1 (Jay)", "ip": "10.25.254.185",
     "mac": "10-68-38-C3-E3-63", "interface": "Wi-Fi"},
    {"name": "laptop-2", "owner": "Member 2 (Elan)", "ip": "10.25.254.37",
     "mac": "20-2B-20-C0-D1-29", "interface": "Wi-Fi"},
    {"name": "laptop-3", "owner": "Member 3 (Jayant)", "ip": "10.25.254.108",
     "mac": "B8-1E-A4-34-01-BD", "interface": "Wi-Fi"},
]

# Which laptop is running the script. Set this per-machine (or via NSA_THIS_HOST)
# so Phase 3 knows whose MAC it is looking at. Must match a "name" above.
THIS_HOST: str = "laptop-3"

# Adapter used for Phase 2 capture. TShark accepts the friendly name shown by
# `tshark -D` (e.g. "Wi-Fi", "Ethernet"). None -> capture.py will list the
# interfaces and ask you to pick one.
# All three laptops call the wireless adapter "Wi-Fi", so this is safe to share.
CAPTURE_INTERFACE: str | None = "Wi-Fi"

# Adapter whose MAC gets spoofed in Phase 3 (as shown by `getmac /v`,
# usually the same friendly name as above).
SPOOF_INTERFACE: str = "Wi-Fi"

# Tool locations. None -> look on PATH, which is right if you accepted the
# installer defaults. Set an explicit path only if a tool is not on PATH.
NMAP_PATH: str | None = None
TSHARK_PATH: str | None = None
SMAC_PATH: str | None = r"C:\Program Files\SMAC\smac.exe"

# ==========================================================================
# END EDIT ME
# ==========================================================================


# --------------------------------------------------------------------------
# Accessors - use these, not the raw globals, so env overrides are honoured
# --------------------------------------------------------------------------

_ENV_PREFIX = "NSA_"


def _env(name: str) -> str | None:
    value = os.environ.get(_ENV_PREFIX + name)
    return value.strip() if value and value.strip() else None


def local_ip() -> str | None:
    """This laptop's primary IPv4 address, as the OS would route it out."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # No packet is actually sent; this just asks the routing table.
        sock.connect(("10.255.255.255", 1))
        return sock.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return None
    finally:
        sock.close()


def local_subnet_mask() -> str | None:
    """Subnet mask of the adapter holding local_ip(), parsed from ipconfig."""
    ip = local_ip()
    if not ip:
        return None
    try:
        out = subprocess.run(
            ["ipconfig"], capture_output=True, text=True, timeout=20
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    # Find the mask that appears just after our IP inside the same adapter block.
    tail = out.split(ip, 1)[-1] if ip in out else ""
    match = re.search(r"Subnet Mask[ .]*:\s*([0-9.]+)", tail)
    return match.group(1) if match else None


def target_network() -> str:
    """The subnet to scan, in CIDR form.

    Order of precedence: NSA_TARGET_NETWORK env var -> TARGET_NETWORK above ->
    auto-detected from this laptop's own address and subnet mask.

    The network address is computed properly rather than by chopping octets -
    a laptop on 192.168.179.32/19 lives in 192.168.160.0/19, not 192.168.0.0/19,
    and scanning the wrong range is both useless and rude to whoever owns it.
    """
    explicit = _env("TARGET_NETWORK") or TARGET_NETWORK
    if explicit:
        return explicit

    ip = local_ip()
    if not ip:
        raise RuntimeError(
            "Could not auto-detect the network. Set TARGET_NETWORK in "
            "shared/config.py (e.g. \"192.168.1.0/24\")."
        )

    mask = local_subnet_mask() or "255.255.255.0"
    try:
        network = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
    except ValueError:
        network = ipaddress.ip_network(f"{ip}/24", strict=False)

    # Guard against a bad parse turning into an enormous sweep of somebody
    # else's address space.
    if network.prefixlen < 16:
        network = ipaddress.ip_network(f"{ip}/24", strict=False)
    return str(network)


def target_network_size() -> int:
    """How many addresses target_network() covers - scan.py warns on big ones."""
    try:
        return ipaddress.ip_network(target_network(), strict=False).num_addresses
    except ValueError:
        return 0


def capture_interface() -> str | None:
    """Interface name for TShark capture, or None to prompt/list."""
    return _env("CAPTURE_INTERFACE") or CAPTURE_INTERFACE


def spoof_interface() -> str:
    """Adapter name for the Phase 3 MAC demo."""
    return _env("SPOOF_INTERFACE") or SPOOF_INTERFACE


def this_host() -> str:
    return _env("THIS_HOST") or THIS_HOST


def tool_path(tool: str) -> str | None:
    """Configured absolute path for a tool, if one was set."""
    mapping = {
        "nmap": _env("NMAP_PATH") or NMAP_PATH,
        "tshark": _env("TSHARK_PATH") or TSHARK_PATH,
        "smac": _env("SMAC_PATH") or SMAC_PATH,
    }
    return mapping.get(tool.lower())


def known_hosts() -> list[dict]:
    """Team laptops with a usable entry, newest info wins over the defaults."""
    return [h for h in HOSTS if h.get("ip") or h.get("mac")]


def host_label(ip: str | None) -> str | None:
    """Friendly '<name> (Member N)' label for one of our own IPs, else None."""
    if not ip:
        return None
    for host in HOSTS:
        if host.get("ip") == ip:
            owner = host.get("owner")
            return f"{host['name']} ({owner})" if owner else host["name"]
    return None


def expected_mac(host_name: str | None = None) -> str | None:
    """The real (pre-spoof) MAC recorded for a laptop, if we know it."""
    host_name = host_name or this_host()
    for host in HOSTS:
        if host["name"] == host_name:
            return host.get("mac")
    return None


def summary() -> str:
    """One-screen dump of the effective config - handy when debugging a run."""
    lines = [
        f"repo root         : {REPO_ROOT}",
        f"this host         : {this_host()}",
        f"local ip          : {local_ip()}",
        f"target network    : {target_network()}",
        f"capture interface : {capture_interface() or '(not set - will list)'}",
        f"spoof interface   : {spoof_interface()}",
        f"nmap path         : {tool_path('nmap') or '(PATH)'}",
        f"tshark path       : {tool_path('tshark') or '(PATH)'}",
        f"smac path         : {tool_path('smac') or '(not set)'}",
    ]
    known = known_hosts()
    lines.append(f"known team hosts  : {len(known)} of {len(HOSTS)} filled in")
    for host in HOSTS:
        lines.append(
            f"  - {host['name']:<10} {host.get('owner', ''):<9} "
            f"ip={host.get('ip') or '?':<15} mac={host.get('mac') or '?'}"
        )
    return "\n".join(lines)


if __name__ == "__main__":
    print(summary())
