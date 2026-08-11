"""Phase 2b - Packet analysis.

Parses the .pcap from capture.py with PyShark (which is itself a wrapper around
TShark, so what you see here is exactly what Wireshark would show you) and
turns it into two files Phase 4 can consume.

Produces (the Phase 2 half of the data contract in CLAUDE.md):
  outputs/packets.csv         - one row per packet:
                                timestamp, src_ip, dst_ip, protocol, length, info
  outputs/protocol_stats.json - per-protocol counts, top talkers, conversations,
                                the TCP three-way handshakes we identified, and
                                the DNS lookups we identified

Usage:
    python analyze.py                      # reads outputs/capture.pcap
    python analyze.py --pcap other.pcap
    python analyze.py --limit 5000         # stop after N packets (big captures)
    python analyze.py --display-filter "dns or http"

Note: this reports facts about the traffic. Deciding which of those facts are
security *findings* is Phase 4's job - keep the policy out of here.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from shared import config
from shared.utils import (
    banner, die, ensure_dir, find_tool, human_bytes, info, now_iso, ok,
    print_table, rel, require_file, step, truncate, warn, write_csv, write_json,
)

try:
    import pyshark
except ImportError:
    die("pyshark is not installed.\n"
        "    Run:  pip install -r requirements.txt")

PACKET_FIELDS = ["timestamp", "src_ip", "dst_ip", "protocol", "length", "info"]

# TCP flag bit positions, used to spot the three-way handshake.
FLAG_SYN = 0x02
FLAG_ACK = 0x10


def _prepare_event_loop() -> None:
    """PyShark drives TShark over asyncio. When it is imported outside an async
    context there may be no event loop in this thread, which surfaces as a
    confusing 'no current event loop' error on Windows."""
    try:
        asyncio.get_event_loop()
    except (RuntimeError, DeprecationWarning):
        asyncio.set_event_loop(asyncio.new_event_loop())


def field(layer, name: str, default=None):
    """Safe field read.

    Two lookups on purpose: get_field_value() misses some dotted field names
    (arp.src.proto_ipv4 and friends) and quietly returns None, while attribute
    access resolves them. Trying only the first silently loses ARP addresses.
    """
    value = None
    try:
        value = layer.get_field_value(name)
    except Exception:
        value = None
    if value is None:
        try:
            value = getattr(layer, name)
        except Exception:
            return default
    return default if value is None else value


def int_field(layer, name: str, default: int | None = None) -> int | None:
    value = field(layer, name)
    if value is None:
        return default
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return default


# --------------------------------------------------------------------------
# Per-packet extraction
# --------------------------------------------------------------------------


def addresses(packet) -> tuple[str | None, str | None]:
    """Source/destination. Falls back to ARP or MAC addresses for L2 frames."""
    if hasattr(packet, "ip"):
        return field(packet.ip, "src"), field(packet.ip, "dst")
    if hasattr(packet, "ipv6"):
        return field(packet.ipv6, "src"), field(packet.ipv6, "dst")
    if hasattr(packet, "arp"):
        return (field(packet.arp, "src_proto_ipv4"),
                field(packet.arp, "dst_proto_ipv4"))
    if hasattr(packet, "eth"):
        return field(packet.eth, "src"), field(packet.eth, "dst")
    return None, None


def protocol_of(packet) -> str:
    """Highest protocol in the stack - the same value Wireshark's Protocol
    column shows (DNS, TLS, HTTP, TCP, ICMP, ARP, ...)."""
    try:
        proto = packet.highest_layer
    except AttributeError:
        proto = "UNKNOWN"
    proto = str(proto).upper()
    # PyShark reports the raw dissector name for a few layers; normalise the
    # ones that would otherwise clutter the report.
    return {"DATA": "TCP-DATA", "_WS.MALFORMED": "MALFORMED"}.get(proto, proto)


def describe(packet, protocol: str) -> str:
    """Approximate Wireshark's Info column - enough to read the CSV by eye."""
    if protocol == "DNS" and hasattr(packet, "dns"):
        dns = packet.dns
        name = field(dns, "qry_name", "?")
        is_response = str(field(dns, "flags_response", "0")) == "1"
        answers = field(dns, "a") or field(dns, "aaaa") or field(dns, "cname")
        if is_response:
            return f"Standard query response {name} -> {answers or 'no answer'}"
        return f"Standard query {name}"

    if hasattr(packet, "http"):
        method = field(packet.http, "request_method")
        if method:
            host = field(packet.http, "host", "")
            uri = field(packet.http, "request_uri", "")
            return f"{method} http://{host}{uri}  [CLEARTEXT]"
        code = field(packet.http, "response_code")
        if code:
            return f"HTTP {code} response  [CLEARTEXT]"

    if protocol in ("TLS", "SSL"):
        # Wireshark renamed the dissector from 'ssl' to 'tls' in 3.0; a lab
        # laptop may have either.
        tls_layer = getattr(packet, "tls", None) or getattr(packet, "ssl", None)
        if tls_layer is not None:
            sni = field(tls_layer, "handshake_extensions_server_name")
            if sni:
                return f"TLS Client Hello (SNI={sni})"
            return "TLS application data (encrypted)"

    if hasattr(packet, "icmp"):
        icmp_type = int_field(packet.icmp, "type")
        return {8: "Echo (ping) request", 0: "Echo (ping) reply"}.get(
            icmp_type, f"ICMP type {icmp_type}")

    if hasattr(packet, "arp"):
        opcode = int_field(packet.arp, "opcode")
        sender = field(packet.arp, "src_proto_ipv4", "?")
        target = field(packet.arp, "dst_proto_ipv4", "?")
        if opcode == 1:
            return f"Who has {target}? Tell {sender}"
        return f"{sender} is at {field(packet.arp, 'src_hw_mac', '?')}"

    if hasattr(packet, "tcp"):
        tcp = packet.tcp
        flags = int_field(tcp, "flags", 0) or 0
        names = [name for bit, name in (
            (0x02, "SYN"), (0x10, "ACK"), (0x01, "FIN"),
            (0x04, "RST"), (0x08, "PSH"), (0x20, "URG"),
        ) if flags & bit]
        return (f"{field(tcp, 'srcport', '?')} -> {field(tcp, 'dstport', '?')} "
                f"[{', '.join(names) or 'none'}] Len={field(tcp, 'len', 0)}")

    if hasattr(packet, "udp"):
        return (f"{field(packet.udp, 'srcport', '?')} -> "
                f"{field(packet.udp, 'dstport', '?')} Len={field(packet.udp, 'length', 0)}")

    return protocol


# --------------------------------------------------------------------------
# Cross-packet analysis
# --------------------------------------------------------------------------


class HandshakeTracker:
    """Spots complete TCP three-way handshakes (SYN -> SYN/ACK -> ACK).

    Keyed by tcp.stream, which TShark assigns per connection, so this works even
    with several connections in flight at once.
    """

    def __init__(self) -> None:
        self.pending: dict[str, dict] = {}
        self.complete: list[dict] = []

    def observe(self, packet, frame: int, timestamp: str,
                src: str | None, dst: str | None) -> None:
        if not hasattr(packet, "tcp"):
            return
        tcp = packet.tcp
        stream = str(field(tcp, "stream", ""))
        if not stream:
            return
        flags = int_field(tcp, "flags", 0) or 0
        syn, ack = bool(flags & FLAG_SYN), bool(flags & FLAG_ACK)

        if syn and not ack:                       # 1. SYN
            self.pending[stream] = {
                "stream": stream,
                "client": src,
                "server": dst,
                "server_port": field(tcp, "dstport"),
                "client_port": field(tcp, "srcport"),
                "syn": {"frame": frame, "timestamp": timestamp},
            }
        elif syn and ack:                         # 2. SYN/ACK
            entry = self.pending.get(stream)
            if entry and "syn_ack" not in entry:
                entry["syn_ack"] = {"frame": frame, "timestamp": timestamp}
        elif ack:                                 # 3. ACK
            entry = self.pending.get(stream)
            if entry and "syn_ack" in entry and "ack" not in entry:
                entry["ack"] = {"frame": frame, "timestamp": timestamp}
                entry["service"] = protocol_hint(entry.get("server_port"))
                self.complete.append(entry)
                del self.pending[stream]


def protocol_hint(port) -> str:
    """Best-guess service name for a port, for readability only."""
    common = {
        20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
        53: "dns", 80: "http", 110: "pop3", 135: "msrpc", 139: "netbios-ssn",
        143: "imap", 443: "https", 445: "microsoft-ds", 587: "submission",
        993: "imaps", 995: "pop3s", 1433: "ms-sql", 3306: "mysql",
        3389: "ms-wbt-server", 5900: "vnc", 8080: "http-alt",
    }
    try:
        return common.get(int(port), f"port-{port}")
    except (TypeError, ValueError):
        return "unknown"


def collect_dns(packet, frame: int, timestamp: str,
                src: str | None, dst: str | None) -> dict | None:
    if not hasattr(packet, "dns"):
        return None
    dns = packet.dns
    name = field(dns, "qry_name")
    if not name:
        return None
    is_response = str(field(dns, "flags_response", "0")) == "1"
    answers: list[str] = []
    if is_response:
        for record in ("a", "aaaa", "cname"):
            value = field(dns, record)
            if value:
                answers.append(str(value))
    return {
        "frame": frame,
        "timestamp": timestamp,
        "query": str(name),
        "type": str(field(dns, "qry_type", "")),
        "direction": "response" if is_response else "query",
        "client": dst if is_response else src,
        "server": src if is_response else dst,
        "answers": answers,
        "transport": "UDP/53 (unencrypted)",
    }


# --------------------------------------------------------------------------
# Main parse
# --------------------------------------------------------------------------


def analyse(pcap: Path, limit: int | None, display_filter: str | None) -> tuple[list[dict], dict]:
    tshark = find_tool("tshark", config.tool_path("tshark"))
    _prepare_event_loop()

    step(f"Parsing {rel(pcap)} with pyshark")
    if display_filter:
        info(f"display filter: {display_filter}")

    capture = pyshark.FileCapture(
        str(pcap),
        display_filter=display_filter,
        tshark_path=tshark,
        keep_packets=False,          # stream: do not hold the whole pcap in RAM
    )

    rows: list[dict] = []
    protocol_counts: Counter = Counter()
    protocol_bytes: Counter = Counter()
    sent_packets: Counter = Counter()
    sent_bytes: Counter = Counter()
    received_packets: Counter = Counter()
    conversations: Counter = Counter()
    tcp_dst_ports: Counter = Counter()
    udp_dst_ports: Counter = Counter()
    handshakes = HandshakeTracker()
    dns_events: list[dict] = []
    first_ts: str | None = None
    last_ts: str | None = None
    first_epoch: float | None = None
    last_epoch: float | None = None

    # Privacy leak tracking variables
    http_urls: list[str] = []
    tls_snis: list[str] = []
    privacy_telemetry: list[str] = []
    
    import re
    TRACKER_PATTERN = re.compile(
        r"telemetry|analytics|tracker|doubleclick|adsystem|adsense|google-analytics|"
        r"app-measurement|adnxs|scorecardresearch|diagnostics|metrics|report|log|stats|"
        r"beacon|telemetry-service|optimizely|amplitude|mixpanel|segment|crashlytics",
        re.IGNORECASE
    )

    frame = 0
    try:
        for packet in capture:
            frame += 1
            if limit and frame > limit:
                warn(f"stopping at --limit {limit} packets")
                frame -= 1
                break

            try:
                timestamp = packet.sniff_time.isoformat(timespec="microseconds")
                epoch = float(packet.sniff_timestamp)
            except (AttributeError, ValueError, TypeError):
                timestamp, epoch = "", None

            protocol = protocol_of(packet)
            src, dst = addresses(packet)
            try:
                length = int(packet.length)
            except (AttributeError, ValueError, TypeError):
                length = 0

            rows.append({
                "timestamp": timestamp,
                "src_ip": src,
                "dst_ip": dst,
                "protocol": protocol,
                "length": length,
                "info": truncate(describe(packet, protocol), 160),
            })

            protocol_counts[protocol] += 1
            protocol_bytes[protocol] += length
            if src:
                sent_packets[src] += 1
                sent_bytes[src] += length
            if dst:
                received_packets[dst] += 1
            if src and dst:
                conversations[tuple(sorted((src, dst)))] += 1
            if hasattr(packet, "tcp"):
                port = field(packet.tcp, "dstport")
                if port:
                    tcp_dst_ports[str(port)] += 1
            elif hasattr(packet, "udp"):
                port = field(packet.udp, "dstport")
                if port:
                    udp_dst_ports[str(port)] += 1

            handshakes.observe(packet, frame, timestamp, src, dst)
            dns_event = collect_dns(packet, frame, timestamp, src, dst)
            if dns_event:
                dns_events.append(dns_event)
                if dns_event["direction"] == "query":
                    qname = dns_event["query"]
                    if TRACKER_PATTERN.search(qname) and qname not in privacy_telemetry:
                        privacy_telemetry.append(qname)

            # Extract plaintext HTTP leaks
            if hasattr(packet, "http"):
                host = field(packet.http, "host")
                uri = field(packet.http, "request_uri")
                method = field(packet.http, "request_method")
                if host and uri and method:
                    url = f"{method} http://{host}{uri}"
                    if url not in http_urls:
                        http_urls.append(url)
                    host_str = str(host)
                    if TRACKER_PATTERN.search(host_str) and host_str not in privacy_telemetry:
                        privacy_telemetry.append(host_str)

            # Extract plaintext TLS SNI leaks
            if protocol in ("TLS", "SSL"):
                tls_layer = getattr(packet, "tls", None) or getattr(packet, "ssl", None)
                if tls_layer is not None:
                    sni = field(tls_layer, "handshake_extensions_server_name")
                    if sni:
                        sni_str = str(sni)
                        if sni_str not in tls_snis:
                            tls_snis.append(sni_str)
                        if TRACKER_PATTERN.search(sni_str) and sni_str not in privacy_telemetry:
                            privacy_telemetry.append(sni_str)

            if first_ts is None and timestamp:
                first_ts, first_epoch = timestamp, epoch
            if timestamp:
                last_ts, last_epoch = timestamp, epoch

            if frame % 1000 == 0:
                print(f"    ... {frame} packets")
    finally:
        try:
            capture.close()
        except Exception:
            pass  # pyshark's asyncio teardown is noisy on Windows; harmless here

    if not rows:
        die("no packets parsed. Is the pcap empty, or did the display filter "
            "exclude everything?")

    duration = (round(last_epoch - first_epoch, 3)
                if first_epoch is not None and last_epoch is not None else None)

    stats = {
        "generated_at": now_iso(),
        "pcap": str(pcap),
        "display_filter": display_filter,
        "total_packets": len(rows),
        "total_bytes": sum(protocol_bytes.values()),
        "capture_start": first_ts,
        "capture_end": last_ts,
        "duration_seconds": duration,
        "protocol_counts": dict(protocol_counts.most_common()),
        "protocol_bytes": dict(protocol_bytes.most_common()),
        "tcp_destination_ports": dict(tcp_dst_ports.most_common(25)),
        "udp_destination_ports": dict(udp_dst_ports.most_common(25)),
        "top_talkers": [
            {
                "ip": ip,
                "packets_sent": count,
                "packets_received": received_packets.get(ip, 0),
                "bytes_sent": sent_bytes.get(ip, 0),
                "label": config.host_label(ip),
            }
            for ip, count in sent_packets.most_common(15)
        ],
        "conversations": [
            {"a": pair[0], "b": pair[1], "packets": count}
            for pair, count in conversations.most_common(20)
        ],
        "tcp_handshakes": handshakes.complete[:25],
        "tcp_handshakes_total": len(handshakes.complete),
        "tcp_handshakes_incomplete": len(handshakes.pending),
        "dns_lookups": [d for d in dns_events if d["direction"] == "query"][:25],
        "dns_responses": [d for d in dns_events if d["direction"] == "response"][:25],
        "dns_lookups_total": sum(1 for d in dns_events if d["direction"] == "query"),
        "http_leaks": http_urls,
        "tls_sni_leaks": tls_snis,
        "privacy_telemetry_leaks": privacy_telemetry,
        "scope": "team-owned laptops on the team's own network",
    }
    return rows, stats


def report(rows: list[dict], stats: dict) -> None:
    step("Capture summary")
    info(f"{stats['total_packets']} packets, "
         f"{human_bytes(stats['total_bytes'])}, "
         f"{stats['duration_seconds']}s of traffic")

    step("Protocol distribution")
    total = stats["total_packets"]
    print_table(
        [[proto, count, f"{100 * count / total:.1f}%",
          human_bytes(stats["protocol_bytes"].get(proto, 0))]
         for proto, count in list(stats["protocol_counts"].items())[:12]],
        ["PROTOCOL", "PACKETS", "SHARE", "BYTES"],
    )

    step("Top talkers")
    print_table(
        [[t["ip"], t.get("label") or "", t["packets_sent"], t["packets_received"],
          human_bytes(t["bytes_sent"])] for t in stats["top_talkers"][:8]],
        ["IP", "TEAM HOST", "SENT", "RECEIVED", "BYTES SENT"],
    )

    step(f"TCP three-way handshakes ({stats['tcp_handshakes_total']} complete)")
    if stats["tcp_handshakes"]:
        print_table(
            [[h["client"], h["server"], h["server_port"], h.get("service", ""),
              f"#{h['syn']['frame']} -> #{h['syn_ack']['frame']} -> #{h['ack']['frame']}"]
             for h in stats["tcp_handshakes"][:8]],
            ["CLIENT", "SERVER", "PORT", "SERVICE", "SYN -> SYN/ACK -> ACK"],
        )
    else:
        warn("none found - the capture may not contain a new TCP connection. "
             "Open a website while capturing.")

    step(f"DNS lookups ({stats['dns_lookups_total']} queries)")
    if stats["dns_lookups"]:
        print_table([[d["timestamp"][11:19], d["client"], d["server"], d["query"]]
                     for d in stats["dns_lookups"][:8]],
                    ["TIME", "CLIENT", "RESOLVER", "QUERY"])
    else:
        warn("none found - run `nslookup example.com` while capturing.")

    step("PRIVACY LEAK ASSESSMENT (Advanced Privacy Profiling)")
    # 1. Plaintext HTTP leaks
    http_leaks = stats.get("http_leaks", [])
    if http_leaks:
        info("[!] Plaintext HTTP URLs leaked (unencrypted web activity):")
        for url in http_leaks[:8]:
            warn(f"  - {url}")
        if len(http_leaks) > 8:
            info(f"  ... and {len(http_leaks) - 8} more URLs")
    else:
        ok("[+] No plaintext HTTP web URLs leaked in the capture.")

    # 2. TLS SNI leaks
    tls_leaks = stats.get("tls_sni_leaks", [])
    if tls_leaks:
        info("[!] Plaintext TLS SNI Hostnames leaked (revealed before HTTPS encryption starts):")
        for sni in tls_leaks[:8]:
            warn(f"  - {sni}")
        if len(tls_leaks) > 8:
            info(f"  ... and {len(tls_leaks) - 8} more hostnames")
    else:
        ok("[+] No TLS SNI hostnames leaked (no encrypted TLS sessions captured).")

    # 3. Telemetry and Tracking leaks
    telemetry_leaks = stats.get("privacy_telemetry_leaks", [])
    if telemetry_leaks:
        warn(f"[!] Silent Telemetry/Tracker activity detected ({len(telemetry_leaks)} domains):")
        for domain in telemetry_leaks[:8]:
            warn(f"  - {domain}  [Telemetry/Tracker]")
        if len(telemetry_leaks) > 8:
            info(f"  ... and {len(telemetry_leaks) - 8} more background trackers")
    else:
        ok("[+] No background telemetry/trackers detected in the capture.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 2 - PyShark pcap analysis")
    parser.add_argument("--pcap", type=Path, default=config.CAPTURE_PCAP,
                        help="pcap to parse (default outputs/capture.pcap)")
    parser.add_argument("--limit", type=int, help="only parse the first N packets")
    parser.add_argument("--display-filter", help="Wireshark display filter, "
                                                 "e.g. 'dns or http'")
    args = parser.parse_args()

    banner("PHASE 2 - PACKET ANALYSIS")
    pcap = require_file(Path(args.pcap), "phase2_capture/capture.py")

    rows, stats = analyse(pcap, args.limit, args.display_filter)
    report(rows, stats)

    ensure_dir(config.PHASE2_OUTPUTS)
    write_csv(config.PACKETS_CSV, rows, PACKET_FIELDS)
    write_json(config.PROTOCOL_STATS_JSON, stats)

    step("Next")
    info(f"{rel(config.PACKETS_CSV)} and {rel(config.PROTOCOL_STATS_JSON)} "
         f"are what Phase 4 consumes - hand them to Member 3.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print()
        warn("interrupted - no output written")
        raise SystemExit(130)
