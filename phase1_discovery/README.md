# Phase 1 — Discovery & Scanning (Member 1)

Find every host on our network, then work out what each one is running. This is
the reconnaissance step: everything Phase 4 says about attack surface comes from
what you produce here.

## What you install

| What | How |
|---|---|
| Nmap | Download from <https://nmap.org/download.html>. **Accept the Npcap driver** when the installer offers it — without it Nmap cannot do ARP discovery or OS detection. |
| Python packages | `pip install -r requirements.txt` from the repo root |

Confirm Nmap is on your PATH — open a **new** terminal after installing:

```bash
nmap --version
```

If that fails but Nmap is installed, set `NMAP_PATH` in `shared/config.py` to
the full path of `nmap.exe`.

## Before you automate anything: run it by hand

The presentation depends on you being able to explain the output, so do this
first and actually read what comes back.

```bash
nmap -sn 192.168.1.0/24
```

That is a ping sweep — no ports, just "who is alive". You should see all three
laptops. Then pick one and go deeper:

```bash
nmap -sV -O 192.168.1.11
```

`-sV` asks each open port what it is and what version it is running; `-O`
guesses the operating system from TCP/IP stack quirks. Note how much slower this
is than the sweep — that is why the script does discovery first and only
deep-scans hosts that answered.

**Run the detailed scan from an Administrator terminal.** OS detection and SYN
scanning need raw sockets. Without elevation the script silently falls back to a
TCP connect scan and skips `-O`, and you lose the OS column.

## How to run it

Fill in `TARGET_NETWORK` in `shared/config.py` first (or let it auto-detect —
it will tell you what it picked, and warn you if the subnet is huge).

```bash
python scan.py
```

| Command | What it does |
|---|---|
| `python scan.py` | Discovery, then service + version + OS scan of the top 1000 ports |
| `python scan.py --discovery-only` | Ping sweep only — seconds, not minutes. **This is the one to use in the live demo.** |
| `python scan.py --quick` | Top 100 ports, no OS detection |
| `python scan.py --ports 1-1024` | Explicit port range |
| `python scan.py --network 192.168.1.0/24` | Override the configured subnet |
| `python scan.py --udp` | Also sweep top UDP ports (slow — leave this for a spare moment) |

A full scan of three laptops takes a few minutes. `--discovery-only` takes
seconds, which matters for the live re-scan during Phase 3.

## What it produces

Both files land in `outputs/`.

**`hosts.json`** — the contract Phase 4 reads:

```json
[
  {
    "ip": "192.168.1.11",
    "hostname": "laptop-2",
    "mac": "A4-C3-F0-44-55-66",
    "vendor": "Intel Corporate",
    "os": "Microsoft Windows 10",
    "os_accuracy": "92",
    "state": "up",
    "ports": [
      { "port": 445, "protocol": "tcp", "service": "microsoft-ds",
        "version": null, "state": "open" }
    ]
  }
]
```

**`hosts.csv`** — the same data flattened, one row per port. This is the table
that goes on your slide: host → IP → open ports → services → OS.

`--discovery-only` writes `discovery.json` instead (just the list of live IPs)
and leaves `hosts.json` alone, so a live demo re-scan cannot clobber your real
results.

## Your deliverable

Hand `outputs/hosts.json` to Member 3 — Phase 4 cannot run without it. Keep the
console output from a full scan too; the version strings make good slide
material.

## The Phase 3 tie-in

During the presentation, Member 3 spoofs their MAC with SMAC and you re-run:

```bash
python scan.py --discovery-only
```

Their laptop reappears under a different MAC address. Have this command already
typed in a terminal so you only have to hit Enter.

## When it does not work

**No hosts found.** All three laptops must be on the same subnet — check with
`ipconfig` on each. Windows Firewall blocks inbound ICMP by default on Public
networks, so hosts can look dead: on each laptop, allow "File and Printer
Sharing (Echo Request — ICMPv4-In)" inbound, or set the network to Private.

**No OS column in the results.** You are not running elevated. Re-open the
terminal as Administrator.

**Everything shows as `filtered`.** That is the host firewall doing its job.
Say so in the report — it is a finding in your favour, not a failed scan.

**`nmap` found but scans hang.** Npcap was not installed. Re-run the Nmap
installer and tick it.

## Scope

Only ever scan the three team laptops on the team's own network. Point the tool
at someone else's network and you are no longer doing coursework.
