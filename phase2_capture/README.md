# Phase 2 — Capture & Analysis (Member 2)

Capture live traffic off the network, then pull it apart: who talked to whom,
over what protocol, and what was readable. Phase 1 shows what *could* be
attacked; you show what is actually crossing the wire.

## What you install

| What | How |
|---|---|
| Wireshark | <https://www.wireshark.org/download.html>. **Accept the Npcap driver.** TShark (the CLI) is included — you do not install it separately. |
| Python packages | `pip install -r requirements.txt` from the repo root |

Confirm TShark is on your PATH — open a **new** terminal after installing:

```bash
tshark -v
```

Not found? It is usually at `C:\Program Files\Wireshark\tshark.exe`. Either add
that folder to PATH or set `TSHARK_PATH` in `shared/config.py`.

## Before you automate anything: use the GUI

Open Wireshark, double-click your Wi-Fi adapter, browse a site for ten seconds,
hit stop. Then find these three things by hand, because you will be asked about
them:

1. **A TCP three-way handshake.** Filter `tcp.flags.syn==1`. You want the
   SYN → SYN/ACK → ACK trio that opens a connection. Right-click one → Follow →
   TCP Stream to see the whole conversation.
2. **A DNS lookup.** Filter `dns`. Note the query going out in cleartext and the
   answer coming back — this is how "which sites did you visit" leaks even when
   the sites themselves are HTTPS.
3. **Something unencrypted.** Filter `http`. Compare it to `tls`: with HTTP you
   can read the URL and the page; with TLS you get nothing but metadata.

Those three screenshots are your slide. The script reproduces the findings, but
the GUI is what makes you able to explain them.

## How to run it

**Step 1 — find your interface.**

```bash
python capture.py --list
```

Put the NAME you want (usually `Wi-Fi`) into `CAPTURE_INTERFACE` in
`shared/config.py`.

**Step 2 — capture.**

```bash
python capture.py --duration 60 --generate-traffic
```

While it runs, do things: browse a couple of sites, ping another laptop,
`nslookup example.com`, download a file. `--generate-traffic` does a ping / DNS /
HTTP / download loop in the background so the capture is guaranteed to contain
all four even if you freeze up during the demo — but doing it manually as well
makes for a better story.

| Command | What it does |
|---|---|
| `python capture.py --list` | Show capture interfaces and exit |
| `python capture.py --duration 60` | Capture for 60 seconds |
| `python capture.py --duration 60 --generate-traffic` | ...and make ping/DNS/HTTP traffic while it runs |
| `python capture.py --count 500` | Stop after 500 packets instead of on a timer |
| `python capture.py --duration 0` | Run until you press Ctrl+C |
| `python capture.py --filter "not port 22"` | BPF capture filter |

**Step 3 — analyse.**

```bash
python analyze.py
```

| Command | What it does |
|---|---|
| `python analyze.py` | Parse `outputs/capture.pcap` |
| `python analyze.py --pcap other.pcap` | Parse a different file |
| `python analyze.py --limit 5000` | Only the first N packets (big captures) |
| `python analyze.py --display-filter "dns or http"` | Wireshark display filter |

It prints a protocol breakdown, the top talkers, the handshakes it found and the
DNS lookups it found — read that output, it is most of your slide.

## What it produces

All in `outputs/`.

| File | What it is |
|---|---|
| `capture.pcap` | The raw capture. Open it in Wireshark — same file, nicer UI. |
| `capture_meta.json` | Which interface, how long, what filter — so the run is reproducible |
| `packets.csv` | **Contract:** one row per packet — `timestamp, src_ip, dst_ip, protocol, length, info` |
| `protocol_stats.json` | **Contract:** per-protocol counts and bytes, top talkers, conversations, destination ports, and the identified TCP handshakes and DNS lookups |

`protocol_stats.json` looks like this:

```json
{
  "total_packets": 4820,
  "duration_seconds": 60.0,
  "protocol_counts": { "TCP": 2100, "TLS": 1200, "DNS": 410, "HTTP": 340 },
  "top_talkers": [ { "ip": "192.168.1.10", "packets_sent": 1600, "bytes_sent": 1050000 } ],
  "tcp_handshakes": [
    { "client": "192.168.1.10", "server": "93.184.216.34", "server_port": "80",
      "syn": { "frame": 120 }, "syn_ack": { "frame": 122 }, "ack": { "frame": 123 } }
  ],
  "dns_lookups": [
    { "query": "example.com", "client": "192.168.1.10", "server": "192.168.1.1" }
  ]
}
```

## Your deliverable

Hand `outputs/packets.csv` and `outputs/protocol_stats.json` to Member 3. Phase 4
reads both.

Note that `analyze.py` reports *facts* — counts, addresses, protocols. Deciding
which of those facts are security findings is Phase 4's job, so do not worry
about the risk framing here.

## When it does not work

**`capture.pcap` is empty.** Wrong adapter — a laptop often has several,
including virtual ones from VirtualBox/WSL. Re-run `--list` and pick the one
carrying your actual traffic (the one whose IP matches `ipconfig`).

**"You don't have permission to capture."** Npcap was installed without the
"support raw 802.11" / admin option, or you need an elevated terminal. Try
running the terminal as Administrator.

**pyshark hangs or throws an asyncio error.** It shells out to TShark, so
confirm `tshark -v` works first. On some Python builds you also need to close
and reopen the terminal after installing Wireshark so PATH refreshes.

**No handshakes found.** Your capture only caught traffic on connections that
were already open. Close the browser, start the capture, *then* open a site.

**No DNS found.** Windows caches aggressively. Run `ipconfig /flushdns` before
capturing, then `nslookup example.com`.

## Scope and privacy

You are capturing real traffic on a network you own, and it will contain your
own browsing. `.gitignore` excludes `*.pcap` from the repo for that reason —
keep the capture local, share only the derived CSV/JSON, and do not capture on
a network you do not control.
