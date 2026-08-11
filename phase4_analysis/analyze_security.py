"""Phase 4a - Security analysis.

Reads what Phases 1, 2 and 3 produced and turns it into findings: which open
ports matter, which observed protocols leak data, and what to do about each.
This is the judgement layer - Phases 1 and 2 report facts, this file applies a
policy to them.

Inputs (per the data contract in CLAUDE.md):
  phase1_discovery/outputs/hosts.json
  phase2_capture/outputs/protocol_stats.json  (+ packets.csv for volumes)
  phase3_spoofing/outputs/mac_log.json        (optional - adds one finding)

Produces:
  outputs/findings.json       - full findings, with evidence
  outputs/findings.csv        - flat table for the report and the slides
  outputs/firewall_rules.txt  - concrete netsh commands for the risky ports

Usage:
    python analyze_security.py
    python analyze_security.py --sample     # synthetic inputs, so the reporting
                                            # chain can be built before Phases
                                            # 1 and 2 have delivered data
    python analyze_security.py --min-severity High

Stdlib only on purpose - this runs even on a laptop that has not installed
pandas yet. report.py is where the heavy libraries live.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from shared import config
from shared.utils import (
    banner, die, ensure_dir, info, now_iso, ok, print_table, read_csv,
    read_json, rel, step, truncate, warn, write_csv, write_json,
)

FINDING_FIELDS = ["id", "severity", "category", "phase", "title", "asset",
                  "evidence", "risk", "recommendation"]

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


def severity_rank(severity: str) -> int:
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return len(SEVERITY_ORDER)


# --------------------------------------------------------------------------
# The policy: what an open port or an observed protocol means
# --------------------------------------------------------------------------

# port -> (service, severity, risk, recommendation)
PORT_RISKS: dict[int, tuple[str, str, str, str]] = {
    21: ("FTP", "High",
         "FTP sends credentials and file contents in cleartext; anyone on this "
         "network can read them with the same Wireshark capture we ran in Phase 2.",
         "Disable the FTP server, or replace it with SFTP/FTPS."),
    23: ("Telnet", "Critical",
         "Telnet is entirely unencrypted, including the login. It has no safe "
         "configuration.",
         "Disable Telnet and use SSH instead."),
    25: ("SMTP", "Medium",
         "An exposed mail relay can leak mail contents and, if misconfigured, be "
         "abused as an open relay.",
         "Close the port unless this host is deliberately a mail server; require "
         "STARTTLS and authentication."),
    69: ("TFTP", "High",
         "TFTP has no authentication at all - any host on the subnet can read or "
         "write files.",
         "Disable TFTP."),
    80: ("HTTP", "Medium",
         "Unencrypted web traffic: URLs, form data and session cookies are "
         "readable by anyone capturing on this network.",
         "Serve over HTTPS and redirect port 80, or close it."),
    110: ("POP3", "High",
          "POP3 without TLS sends the mailbox password in cleartext.",
          "Use POP3S (995) or close the port."),
    111: ("RPCbind", "Medium",
          "Exposes which RPC services the host runs - useful reconnaissance for "
          "an attacker.",
          "Close unless an RPC service is genuinely needed."),
    135: ("MSRPC", "High",
          "Windows RPC endpoint mapper. Historically a rich source of remote "
          "code execution bugs and a standard lateral-movement path.",
          "Block inbound 135 from anything except trusted management hosts."),
    137: ("NetBIOS-NS", "High",
          "NetBIOS name service leaks hostnames, domain and user information, and "
          "is trivially poisoned to capture credential hashes.",
          "Disable NetBIOS over TCP/IP on the adapter."),
    139: ("NetBIOS-SSN", "High",
          "Legacy SMB session service; enables host enumeration and null-session "
          "style attacks.",
          "Disable NetBIOS over TCP/IP and block inbound 139."),
    143: ("IMAP", "High",
          "IMAP without TLS sends the mailbox password in cleartext.",
          "Use IMAPS (993) or close the port."),
    161: ("SNMP", "High",
          "SNMP v1/v2c uses a community string as its only authentication and "
          "sends it in cleartext; 'public' is still a common default.",
          "Disable SNMP, or move to SNMPv3 with authentication and privacy."),
    389: ("LDAP", "Medium",
          "Unencrypted directory queries expose usernames and group structure.",
          "Use LDAPS (636), or restrict the port to domain controllers."),
    445: ("SMB", "High",
          "File and printer sharing. The single most attacked port on a Windows "
          "LAN (EternalBlue, ransomware spread, hash relay). It should never be "
          "open to an untrusted network.",
          "Turn off File and Printer Sharing on public networks; block inbound "
          "445 at the host firewall."),
    512: ("rexec", "Critical",
          "Berkeley r-service: cleartext credentials, trivially spoofed.",
          "Disable."),
    513: ("rlogin", "Critical",
          "Berkeley r-service: cleartext credentials, host-based trust that is "
          "trivially spoofed.",
          "Disable and use SSH."),
    514: ("rsh/syslog", "High",
          "Cleartext remote shell, or unauthenticated syslog ingestion.",
          "Disable rsh; if this is syslog, restrict it to the collector."),
    1433: ("MS SQL Server", "High",
           "A database engine reachable from the LAN. Brute-forceable and a "
           "direct route to the data itself.",
           "Bind the instance to localhost, or restrict 1433 to application "
           "hosts only."),
    3306: ("MySQL", "High",
           "A database engine reachable from the LAN.",
           "Bind to localhost or restrict 3306 to application hosts only."),
    3389: ("RDP", "High",
           "Remote Desktop is a full interactive login exposed to the network - "
           "the most common brute-force and ransomware entry point on Windows.",
           "Disable Remote Desktop if unused; otherwise require NLA, a strong "
           "password, and restrict the source addresses."),
    5432: ("PostgreSQL", "High",
           "A database engine reachable from the LAN.",
           "Bind to localhost or restrict 5432 to application hosts only."),
    5900: ("VNC", "Critical",
           "VNC is unencrypted and its password scheme is weak; screen contents "
           "and keystrokes are exposed.",
           "Disable VNC, or tunnel it over SSH/VPN."),
    8080: ("HTTP-alt", "Medium",
           "An unencrypted web service, often a development or admin interface "
           "left running.",
           "Close it, or put it behind HTTPS with authentication."),
}

# protocol name as PyShark reports it -> (severity, risk, recommendation)
PROTOCOL_RISKS: dict[str, tuple[str, str, str]] = {
    "HTTP": ("Medium",
             "Cleartext web traffic was captured. Anyone on this network can read "
             "the URLs, page contents, form submissions and session cookies.",
             "Use HTTPS everywhere; enable HSTS on any service the team runs."),
    "FTP": ("High",
            "Cleartext FTP was captured, including the login exchange.",
            "Replace with SFTP/FTPS."),
    "TELNET": ("Critical",
               "Cleartext Telnet was captured, including credentials.",
               "Replace with SSH."),
    "POP": ("High", "Cleartext mail retrieval was captured.", "Use POP3S."),
    "IMAP": ("High", "Cleartext mail access was captured.", "Use IMAPS."),
    "SMTP": ("Medium", "Cleartext mail submission was captured.",
             "Require STARTTLS."),
    "SNMP": ("High",
             "SNMP traffic was captured; v1/v2c community strings travel in "
             "cleartext.",
             "Move to SNMPv3 or disable SNMP."),
    "TFTP": ("High", "Unauthenticated TFTP file transfer was captured.",
             "Disable TFTP."),
    "DNS": ("Low",
            "DNS queries were captured in cleartext, so every site the team "
            "visited is visible to anyone on this network even when the sites "
            "themselves use HTTPS.",
            "Enable DNS-over-HTTPS in the browser and OS where possible."),
    "NBNS": ("Medium",
             "NetBIOS name service broadcasts leak hostnames and are the basis "
             "of LLMNR/NBT-NS poisoning attacks that capture credential hashes.",
             "Disable NetBIOS over TCP/IP on the adapter."),
    "LLMNR": ("Medium",
              "LLMNR broadcasts are trivially spoofed to capture NTLM hashes "
              "(the classic Responder attack).",
              "Disable LLMNR via Group Policy / registry."),
    "MDNS": ("Low",
             "mDNS broadcasts advertise this host and its services to the whole "
             "subnet.",
             "Disable mDNS if no service on the network depends on it."),
    "ARP": ("Medium",
            "ARP has no authentication whatsoever, so any host on this subnet "
            "can claim any IP address (ARP spoofing) and intercept traffic. "
            "Phase 3 shows the layer-2 identity is just as forgeable.",
            "Use static ARP entries or switch-level dynamic ARP inspection for "
            "anything sensitive; do not treat the local network as trusted."),
    "NTLMSSP": ("High",
                "NTLM authentication material was observed on the wire and can "
                "be relayed or cracked offline.",
                "Prefer Kerberos; enable SMB signing to block relay."),
}

SAFE_PORTS = {22: "SSH", 443: "HTTPS", 993: "IMAPS", 995: "POP3S", 636: "LDAPS"}


# --------------------------------------------------------------------------
# Loading inputs
# --------------------------------------------------------------------------


def load_inputs(sample: bool) -> dict:
    if sample:
        return load_sample_inputs()

    hosts_path = config.HOSTS_JSON
    stats_path = config.PROTOCOL_STATS_JSON
    packets_path = config.PACKETS_CSV

    if not hosts_path.exists() and not stats_path.exists():
        die(f"neither {rel(hosts_path)} nor {rel(stats_path)} exists.\n"
            "    Phase 4 consumes Phases 1 and 2 - collect their outputs first, "
            "or run with --sample to build the reporting chain against "
            "synthetic data.")

    data: dict = {"hosts": [], "stats": {}, "packets": [], "mac_log": None,
                  "sources": {}}

    if hosts_path.exists():
        data["hosts"] = read_json(hosts_path)
        data["sources"]["phase1"] = rel(hosts_path)
        ok(f"loaded {len(data['hosts'])} host(s) from {rel(hosts_path)}")
    else:
        warn(f"{rel(hosts_path)} missing - skipping the open-port analysis")

    if stats_path.exists():
        data["stats"] = read_json(stats_path)
        data["sources"]["phase2"] = rel(stats_path)
        ok(f"loaded protocol stats from {rel(stats_path)} "
           f"({data['stats'].get('total_packets', 0)} packets)")
    else:
        warn(f"{rel(stats_path)} missing - skipping the traffic analysis")

    if packets_path.exists():
        data["packets"] = read_csv(packets_path)
        data["sources"]["phase2_packets"] = rel(packets_path)

    if config.MAC_LOG_JSON.exists():
        data["mac_log"] = read_json(config.MAC_LOG_JSON)
        data["sources"]["phase3"] = rel(config.MAC_LOG_JSON)
        ok(f"loaded MAC spoofing log from {rel(config.MAC_LOG_JSON)}")

    return data


def load_sample_inputs() -> dict:
    """Synthetic but realistic inputs, written to outputs/sample_inputs/ so you
    can see exactly what shape Phases 1 and 2 must deliver."""
    warn("running on SAMPLE DATA - these findings are not a real assessment")
    sample_dir = ensure_dir(config.PHASE4_OUTPUTS / "sample_inputs")

    hosts = [
        {"ip": "192.168.1.10", "hostname": "laptop-1", "mac": "3C-58-C2-11-22-33",
         "vendor": "Intel Corporate", "os": "Microsoft Windows 11", "os_accuracy": "95",
         "state": "up", "ports": [
             {"port": 135, "protocol": "tcp", "service": "msrpc",
              "version": "Microsoft Windows RPC", "state": "open"},
             {"port": 139, "protocol": "tcp", "service": "netbios-ssn",
              "version": "Microsoft Windows netbios-ssn", "state": "open"},
             {"port": 445, "protocol": "tcp", "service": "microsoft-ds",
              "version": None, "state": "open"},
         ]},
        {"ip": "192.168.1.11", "hostname": "laptop-2", "mac": "A4-C3-F0-44-55-66",
         "vendor": "Intel Corporate", "os": "Microsoft Windows 10", "os_accuracy": "92",
         "state": "up", "ports": [
             {"port": 80, "protocol": "tcp", "service": "http",
              "version": "Apache httpd 2.4.57", "state": "open"},
             {"port": 3389, "protocol": "tcp", "service": "ms-wbt-server",
              "version": "Microsoft Terminal Services", "state": "open"},
             {"port": 445, "protocol": "tcp", "service": "microsoft-ds",
              "version": None, "state": "open"},
         ]},
        {"ip": "192.168.1.12", "hostname": "laptop-3", "mac": "58-96-1D-77-88-99",
         "vendor": "Dell Inc.", "os": "Microsoft Windows 11", "os_accuracy": "97",
         "state": "up", "ports": [
             {"port": 22, "protocol": "tcp", "service": "ssh",
              "version": "OpenSSH for_Windows_9.5", "state": "open"},
             {"port": 5900, "protocol": "tcp", "service": "vnc",
              "version": "TightVNC 1.3.10", "state": "open"},
         ]},
    ]

    stats = {
        "generated_at": now_iso(),
        "pcap": "(sample)",
        "total_packets": 4820,
        "total_bytes": 3_140_000,
        "capture_start": "2026-08-03T14:00:00.000000",
        "capture_end": "2026-08-03T14:01:00.000000",
        "duration_seconds": 60.0,
        "protocol_counts": {"TCP": 2100, "TLS": 1200, "DNS": 410, "HTTP": 340,
                            "ICMP": 260, "ARP": 210, "NBNS": 180, "LLMNR": 90,
                            "MDNS": 30},
        "protocol_bytes": {"TCP": 1_400_000, "TLS": 1_100_000, "HTTP": 380_000,
                           "DNS": 90_000, "ICMP": 60_000, "ARP": 40_000,
                           "NBNS": 45_000, "LLMNR": 20_000, "MDNS": 5_000},
        "tcp_destination_ports": {"443": 1400, "80": 340, "445": 120, "3389": 60},
        "udp_destination_ports": {"53": 410, "137": 180, "5355": 90, "5353": 30},
        "top_talkers": [
            {"ip": "192.168.1.10", "packets_sent": 1600, "packets_received": 1400,
             "bytes_sent": 1_050_000, "label": "laptop-1 (Member 1)"},
            {"ip": "192.168.1.11", "packets_sent": 1300, "packets_received": 1250,
             "bytes_sent": 880_000, "label": "laptop-2 (Member 2)"},
            {"ip": "192.168.1.12", "packets_sent": 1100, "packets_received": 1000,
             "bytes_sent": 760_000, "label": "laptop-3 (Member 3)"},
        ],
        "conversations": [
            {"a": "192.168.1.10", "b": "192.168.1.11", "packets": 900},
            {"a": "192.168.1.11", "b": "192.168.1.12", "packets": 640},
        ],
        "tcp_handshakes": [
            {"stream": "3", "client": "192.168.1.10", "server": "93.184.216.34",
             "server_port": "80", "client_port": "51544", "service": "http",
             "syn": {"frame": 120, "timestamp": "2026-08-03T14:00:12.100000"},
             "syn_ack": {"frame": 122, "timestamp": "2026-08-03T14:00:12.140000"},
             "ack": {"frame": 123, "timestamp": "2026-08-03T14:00:12.141000"}},
        ],
        "tcp_handshakes_total": 46,
        "tcp_handshakes_incomplete": 3,
        "dns_lookups": [
            {"frame": 88, "timestamp": "2026-08-03T14:00:09.400000",
             "query": "example.com", "type": "1", "direction": "query",
             "client": "192.168.1.10", "server": "192.168.1.1", "answers": [],
             "transport": "UDP/53 (unencrypted)"},
        ],
        "dns_lookups_total": 205,
        "scope": "sample data",
    }

    packets = [
        {"timestamp": stats["capture_start"], "src_ip": "192.168.1.10",
         "dst_ip": "93.184.216.34", "protocol": "HTTP", "length": "512",
         "info": "GET http://example.com/  [CLEARTEXT]"},
        {"timestamp": stats["capture_start"], "src_ip": "192.168.1.10",
         "dst_ip": "192.168.1.1", "protocol": "DNS", "length": "78",
         "info": "Standard query example.com"},
    ]

    write_json(sample_dir / "hosts.json", hosts)
    write_json(sample_dir / "protocol_stats.json", stats)
    write_csv(sample_dir / "packets.csv", packets,
              ["timestamp", "src_ip", "dst_ip", "protocol", "length", "info"])

    return {"hosts": hosts, "stats": stats, "packets": packets, "mac_log": None,
            "sources": {"phase1": rel(sample_dir / "hosts.json"),
                        "phase2": rel(sample_dir / "protocol_stats.json"),
                        "sample": True}}


# --------------------------------------------------------------------------
# Finding generation
# --------------------------------------------------------------------------


class Findings:
    def __init__(self) -> None:
        self.items: list[dict] = []
        self._counter = 0

    def add(self, severity: str, category: str, phase: str, title: str,
            asset: str, evidence: str, risk: str, recommendation: str) -> None:
        self._counter += 1
        self.items.append({
            "id": f"F-{self._counter:03d}",
            "severity": severity,
            "category": category,
            "phase": phase,
            "title": title,
            "asset": asset,
            "evidence": evidence,
            "risk": risk,
            "recommendation": recommendation,
        })

    def sorted(self) -> list[dict]:
        return sorted(self.items,
                      key=lambda f: (severity_rank(f["severity"]), f["asset"]))


def analyse_open_ports(hosts: list[dict], findings: Findings) -> None:
    """Every open port becomes a finding; the risky ones get a real severity."""
    for host in hosts:
        ip = host.get("ip", "unknown")
        label = (config.host_label(ip, mac=host.get("mac"))
                 or host.get("hostname") or ip)
        asset = f"{ip} ({label})" if label != ip else ip
        open_ports = [p for p in host.get("ports", []) if p.get("state") == "open"]

        for port_entry in open_ports:
            port = int(port_entry.get("port", 0))
            service = port_entry.get("service") or "unknown"
            version = port_entry.get("version") or "version not identified"
            evidence = (f"Nmap: {port}/{port_entry.get('protocol', 'tcp')} open, "
                        f"service={service}, {version}")

            if port in PORT_RISKS:
                name, severity, risk, recommendation = PORT_RISKS[port]
                findings.add(severity, "Open port", "Phase 1",
                             f"{name} exposed on {port}/tcp", asset, evidence,
                             risk, recommendation)
            elif port in SAFE_PORTS:
                findings.add("Info", "Open port", "Phase 1",
                             f"{SAFE_PORTS[port]} exposed on {port}/tcp", asset,
                             evidence,
                             f"{SAFE_PORTS[port]} is encrypted, so exposure is "
                             f"acceptable, but it still widens the attack surface "
                             f"and can be brute-forced.",
                             "Keep it patched, require key or strong-password "
                             "auth, and restrict the source addresses if you can.")
            else:
                findings.add("Low", "Open port", "Phase 1",
                             f"Unexpected service on {port}/tcp", asset, evidence,
                             "An open port that nobody on the team can account "
                             "for is an unknown attack surface.",
                             "Identify the owning process "
                             "(`netstat -ano | findstr :%d`) and close it if it "
                             "is not needed." % port)

        if not open_ports and host.get("state") == "up":
            findings.add("Info", "Attack surface", "Phase 1",
                         "No open TCP ports found", asset,
                         "Nmap found the host up but reported no open ports in "
                         "the scanned range.",
                         "This host presents the smallest attack surface of the "
                         "three - use its configuration as the baseline.",
                         "No action. Confirm the scan covered the full port "
                         "range before treating this as final.")

        if host.get("os"):
            findings.add("Info", "Fingerprinting", "Phase 1",
                         "Operating system identifiable remotely", asset,
                         f"Nmap OS detection: {host['os']} "
                         f"({host.get('os_accuracy', '?')}% confidence)",
                         "An attacker who can fingerprint the OS can pick "
                         "exploits that match it, without any further probing.",
                         "Cannot be fully prevented, but a host firewall that "
                         "drops unsolicited probes makes fingerprinting much "
                         "less reliable.")


def analyse_traffic(stats: dict, findings: Findings) -> None:
    if not stats:
        return
    total = stats.get("total_packets", 0) or 1
    counts: dict = stats.get("protocol_counts", {})

    for protocol, count in counts.items():
        rule = PROTOCOL_RISKS.get(str(protocol).upper())
        if not rule:
            continue
        severity, risk, recommendation = rule
        share = 100 * count / total
        findings.add(
            severity, "Insecure protocol", "Phase 2",
            f"{protocol} observed in the capture",
            "network traffic",
            f"{count} {protocol} packets ({share:.1f}% of {total} captured)",
            risk, recommendation,
        )

    # Encrypted vs cleartext balance - a headline number for the slide.
    encrypted = sum(counts.get(p, 0) for p in ("TLS", "SSL", "QUIC", "SSH"))
    cleartext = sum(counts.get(p, 0) for p in
                    ("HTTP", "FTP", "TELNET", "POP", "IMAP", "SMTP", "SNMP", "TFTP"))
    if cleartext:
        ratio = 100 * cleartext / max(encrypted + cleartext, 1)
        findings.add(
            "Medium" if ratio > 20 else "Low", "Encryption", "Phase 2",
            "Part of the application traffic is unencrypted",
            "network traffic",
            f"{cleartext} cleartext application packets vs {encrypted} "
            f"encrypted ({ratio:.0f}% cleartext)",
            "Any unencrypted application traffic on a shared network is readable "
            "by every other host on it - we proved this with a 60-second capture.",
            "Move the remaining cleartext services to TLS; treat the LAN as "
            "untrusted.")

    handshakes = stats.get("tcp_handshakes_total", 0)
    if handshakes:
        example = (stats.get("tcp_handshakes") or [{}])[0]
        findings.add(
            "Info", "Traffic behaviour", "Phase 2",
            "TCP connection establishment is fully observable",
            "network traffic",
            f"{handshakes} complete three-way handshakes captured; e.g. "
            f"{example.get('client')} -> {example.get('server')}:"
            f"{example.get('server_port')} ({example.get('service', '')})",
            "Connection metadata - who talks to whom, when, and on which port - "
            "is visible even when the payload is encrypted.",
            "Accept as inherent to TCP; use a VPN if metadata exposure matters.")

    dns_total = stats.get("dns_lookups_total", 0)
    if dns_total:
        findings.add(
            "Low", "Privacy", "Phase 2",
            "Browsing history is inferable from DNS",
            "network traffic",
            f"{dns_total} cleartext DNS queries captured, e.g. " +
            ", ".join(d.get("query", "") for d in stats.get("dns_lookups", [])[:3]),
            "Every domain the team visited is visible to anyone on this network, "
            "even for sites served over HTTPS.",
            "Enable DNS-over-HTTPS in the browser and in Windows DNS settings.")

    # Anything talking on a risky port shows up in the capture too - corroborates
    # the Phase 1 findings with live evidence rather than just a port state.
    for port_str, count in (stats.get("tcp_destination_ports") or {}).items():
        try:
            port = int(port_str)
        except ValueError:
            continue
        if port in PORT_RISKS and count > 0:
            name, severity, risk, recommendation = PORT_RISKS[port]
            findings.add(
                severity, "Insecure protocol", "Phase 2",
                f"Live traffic to {name} ({port}/tcp)", "network traffic",
                f"{count} packets destined for port {port} during the capture",
                f"{risk} This port is not merely open - it is actively in use.",
                recommendation)


def analyse_spoofing(mac_log: dict | None, findings: Findings) -> None:
    if not mac_log or not mac_log.get("entries"):
        return
    entries = mac_log["entries"]
    before = next((e for e in entries if e.get("stage") == "before"), None)
    after = next((e for e in reversed(entries) if e.get("stage") == "after"), None)
    if not (before and after):
        return
    if before.get("mac") == after.get("mac"):
        return

    findings.add(
        "High", "Identity", "Phase 3",
        "MAC addresses are not a usable identity control",
        f"{mac_log.get('host', 'team laptop')} / {before.get('interface')}",
        f"Adapter MAC changed from {before.get('mac')} to {after.get('mac')} "
        f"at {after.get('timestamp')} and the host rejoined the network "
        f"(IPv4 {after.get('ipv4')}). Phase 1's re-scan saw it as a new device.",
        "Any control that trusts a MAC address - MAC filtering on the access "
        "point, DHCP reservations used as authorisation, 'known device' lists - "
        "can be defeated in about a minute with a free GUI tool. The same "
        "technique lets an attacker impersonate an allow-listed device or evade "
        "MAC-based logging.",
        "Do not use MAC filtering as a security control. Authenticate devices "
        "with WPA2/WPA3-Enterprise (802.1X) or per-device credentials, and treat "
        "MAC addresses as a convenience identifier only.")


def cross_phase(data: dict, findings: Findings) -> None:
    """Findings that only exist because we have more than one phase's data."""
    hosts = data.get("hosts") or []
    stats = data.get("stats") or {}
    if not hosts or not stats:
        return

    talker_ips = {t.get("ip") for t in stats.get("top_talkers", [])}
    scanned_ips = {h.get("ip") for h in hosts}
    unknown = {ip for ip in talker_ips if ip and ip not in scanned_ips
               and not str(ip).startswith(("224.", "239.", "255."))}
    if unknown:
        findings.add(
            "Medium", "Unknown host", "Phase 1 + 2",
            "Traffic seen from hosts the scan did not cover",
            ", ".join(sorted(unknown)[:5]),
            f"{len(unknown)} address(es) appear in the packet capture but not in "
            f"the Phase 1 host inventory: {', '.join(sorted(unknown)[:5])}",
            "An inventory that misses active hosts leaves blind spots - you "
            "cannot harden a device you do not know is there. Some of these will "
            "be external servers, but any local one is a gap.",
            "Re-run discovery across the full subnet and account for every local "
            "address before signing off the assessment.")

    if any(h.get("state") == "up" for h in hosts):
        icmp = stats.get("protocol_counts", {}).get("ICMP", 0)
        if icmp:
            findings.add(
                "Low", "Attack surface", "Phase 1 + 2",
                "Hosts answer ICMP echo, making discovery trivial",
                "all team laptops",
                f"Phase 1 discovered every host with a ping sweep; the capture "
                f"contains {icmp} ICMP packets.",
                "Responding to unsolicited pings tells an attacker exactly which "
                "addresses are worth scanning.",
                "Leave the default Windows Firewall behaviour of dropping "
                "inbound echo requests on Public networks, and only allow ICMP "
                "on trusted networks where you need it for diagnostics.")


# --------------------------------------------------------------------------
# Firewall rules
# --------------------------------------------------------------------------


def firewall_rules(findings: list[dict], hosts: list[dict]) -> list[str]:
    """Concrete, copy-pasteable netsh rules for the ports we flagged."""
    risky_ports: dict[int, str] = {}
    for host in hosts:
        for port_entry in host.get("ports", []):
            if port_entry.get("state") != "open":
                continue
            port = int(port_entry.get("port", 0))
            if port in PORT_RISKS:
                risky_ports[port] = PORT_RISKS[port][0]

    lines = [
        "Phase 4 - Recommended host firewall rules",
        "=" * 60,
        f"Generated {now_iso()}",
        "",
        "Run these in an ELEVATED PowerShell / cmd on each laptop. Read each one",
        "before you run it - blocking 445 will break file sharing, and blocking",
        "3389 will end an active Remote Desktop session.",
        "",
        "-- 1. Make sure the firewall is actually on, on every profile --",
        "netsh advfirewall set allprofiles state on",
        "netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound",
        "",
        "-- 2. Treat the network as Public (Windows then blocks most inbound) --",
        'powershell -Command "Set-NetConnectionProfile -NetworkCategory Public"',
        "",
    ]

    if risky_ports:
        lines.append("-- 3. Block the specific risky ports we found open --")
        for port in sorted(risky_ports):
            name = risky_ports[port]
            lines.append(f"REM {name} on {port}/tcp - "
                         f"{PORT_RISKS[port][1].lower()} severity")
            lines.append(
                f'netsh advfirewall firewall add rule name="Block {name} inbound" '
                f'dir=in action=block protocol=TCP localport={port}')
        lines.append("")
    else:
        lines += ["-- 3. No high-risk ports were found open on the scanned hosts --",
                  "REM Nothing to block here. Keep the default deny-inbound policy.",
                  ""]

    lines += [
        "-- 4. Turn off the legacy name-resolution protocols --",
        "REM NetBIOS over TCP/IP (stops NBT-NS poisoning)",
        'powershell -Command "Get-ChildItem '
        '\'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces\' '
        '| ForEach-Object { Set-ItemProperty -Path $_.PSPath -Name NetbiosOptions -Value 2 }"',
        "REM LLMNR (stops the Responder-style hash capture)",
        'powershell -Command "New-Item -Path '
        '\'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\' -Force; '
        'Set-ItemProperty -Path \'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\' '
        '-Name EnableMulticast -Value 0"',
        "",
        "-- 5. Turn off File and Printer Sharing on untrusted networks --",
        'netsh advfirewall firewall set rule group="File and Printer Sharing" '
        'new enable=No',
        "",
        "-- 6. Verify --",
        "netsh advfirewall show allprofiles",
        "netstat -ano | findstr LISTENING",
        "REM then re-run Phase 1 from another laptop and confirm the ports are gone:",
        "REM   python phase1_discovery/scan.py",
        "",
        "-- Rollback (if you break something) --",
        'netsh advfirewall firewall delete rule name="Block <name> inbound"',
        "netsh advfirewall reset",
    ]
    return lines


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------


def summarise(findings: list[dict], data: dict) -> dict:
    counts = Counter(f["severity"] for f in findings)
    stats = data.get("stats") or {}
    hosts = data.get("hosts") or []
    open_ports = sum(1 for h in hosts for p in h.get("ports", [])
                     if p.get("state") == "open")
    return {
        "generated_at": now_iso(),
        "scope": "The team's own three Windows laptops on the team's own "
                 "network. No third-party system was scanned, captured or "
                 "modified.",
        "sources": data.get("sources", {}),
        "hosts_assessed": len(hosts),
        "open_ports_found": open_ports,
        "packets_analysed": stats.get("total_packets", 0),
        "protocols_seen": len(stats.get("protocol_counts", {})),
        "mac_spoofing_demonstrated": bool(data.get("mac_log")),
        "findings_total": len(findings),
        "findings_by_severity": {s: counts.get(s, 0) for s in SEVERITY_ORDER},
        "top_risks": [f["title"] for f in findings[:5]],
    }


def print_findings(findings: list[dict], summary: dict) -> None:
    step("Findings by severity")
    print_table([[s, c] for s, c in summary["findings_by_severity"].items()],
                ["SEVERITY", "COUNT"])

    step("Findings")
    print_table(
        [[f["id"], f["severity"], f["asset"][:22], truncate(f["title"], 44)]
         for f in findings],
        ["ID", "SEVERITY", "ASSET", "FINDING"],
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 4 - security analysis")
    parser.add_argument("--sample", action="store_true",
                        help="analyse synthetic data instead of real phase "
                             "outputs (for building the report before the data "
                             "exists)")
    parser.add_argument("--min-severity", choices=SEVERITY_ORDER,
                        help="only keep findings at this severity or worse")
    args = parser.parse_args()

    banner("PHASE 4 - SECURITY ANALYSIS")
    info("scope: the team's own laptops on the team's own network")

    step("Loading Phase 1 / 2 / 3 outputs")
    data = load_inputs(args.sample)

    step("Applying the risk policy")
    findings = Findings()
    analyse_open_ports(data.get("hosts") or [], findings)
    analyse_traffic(data.get("stats") or {}, findings)
    analyse_spoofing(data.get("mac_log"), findings)
    cross_phase(data, findings)

    items = findings.sorted()
    if args.min_severity:
        cutoff = severity_rank(args.min_severity)
        items = [f for f in items if severity_rank(f["severity"]) <= cutoff]
        info(f"filtered to {args.min_severity} and above")

    if not items:
        warn("no findings generated - check that the inputs actually contain data")

    summary = summarise(items, data)
    print_findings(items, summary)

    ensure_dir(config.PHASE4_OUTPUTS)
    write_json(config.FINDINGS_JSON, {"summary": summary, "findings": items})
    write_csv(config.FINDINGS_CSV, items, FINDING_FIELDS)

    rules = firewall_rules(items, data.get("hosts") or [])
    config.FIREWALL_RULES_TXT.write_text("\n".join(rules) + "\n", encoding="utf-8")
    ok(f"wrote {rel(config.FIREWALL_RULES_TXT)}")

    step("Next")
    info("python report.py    # charts + report.xlsx")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print()
        warn("interrupted")
        raise SystemExit(130)
