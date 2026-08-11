# Elan — Your Part of the Project (Phase 2)

Hey Elan. Everything you need is here — you don't need to read the other docs. (You've already poked at Wireshark, so some of this will look familiar.)

---

## What the project is (30 seconds)

It's our mid-sem security project: **40 marks, 4 phases, presented at the end.** We take our own little network (the three of our laptops), poke at it with standard security tools, and write up how safe it is and how to lock it down. The three of us each own a part. **The code is already written** and in the repo — your job is to run *your* part on your laptop and hand over the results.

## Your part: Phase 2 — Capture & Analysis

You record what actually travels across the network while normal things happen, then break it down by protocol. You use **Wireshark / TShark** (the command-line version) to capture packets, and a Python script parses them.

The project needs you to capture traffic during four activities — **browsing a website, downloading a file, a DNS lookup, and a ping** — and pull out the details (source/destination IP, protocol, packet length, the TCP handshake, the DNS lookup). The scripts do the heavy lifting; you drive the activities and hand over two result files.

Your deliverables: **`packets.csv`** and **`protocol_stats.json`**.

---

## Before you start

1. **Be on the team Wi-Fi** (same network as Jay and Jayant).
2. **Clone the repo** and open a terminal *inside the repo folder*.
3. Make sure **Python** is installed, then run:
   ```
   pip install -r requirements.txt
   ```
4. **Wireshark installed** — you've got this already. It includes TShark. (If it ever asks about the **Npcap** driver, say yes.)
5. **Don't edit `config.py`** — your capture interface is already set to `Wi-Fi` for you.
6. **Open your terminal as Administrator** (right-click → *Run as administrator*). Capturing packets needs admin rights.

---

## Step 1 — Prep the machine (this is the part people forget)

Two quick things right before you capture, or the capture comes out useless:

- **Flush the DNS cache:**
  ```
  ipconfig /flushdns
  ```
  This forces fresh DNS lookups during the capture. Without it, your PC uses cached answers and **no DNS packets show up** — and analysing a DNS lookup is one of the graded items.

- **Close your browser completely**, then reopen a single fresh window when you're ready. Otherwise background tabs and telemetry flood the capture with noise and you can't find the packets that matter.

---

## Step 2 — Confirm the interface is detected

```
python phase2_capture/capture.py --list
```

You should see **Wi-Fi** in the list. If it's there, you're good.

---

## Step 3 — Capture (and do the four activities while it runs)

Start the capture:

```
python phase2_capture/capture.py --duration 60 --generate-traffic
```

You've got a 60-second window. **While it's running, actually do the four things the project needs**, so they're guaranteed to be in the capture:

1. **Browse** — open a website in your fresh browser window (a plain `http://` site is a bonus for later analysis).
2. **Download** — grab a small file (any small download works).
3. **DNS** — visiting a couple of new sites covers this; or run `nslookup example.com`.
4. **Ping** — ping one of our own laptops, e.g. `ping 10.25.254.185` (Jay) or `ping 10.25.254.108` (Jayant).

(The `--generate-traffic` flag also auto-creates some traffic, so doing these yourself is belt-and-suspenders — between the two, all four are covered.)

---

## Step 4 — Analyse

```
python phase2_capture/analyze.py
```

This reads the capture and writes your two deliverables:
```
phase2_capture/outputs/packets.csv
phase2_capture/outputs/protocol_stats.json
```

**Heads up:** this is the *first time* the capture/analyse scripts run for real (so far only syntax-checked). If either throws an error, don't force it — **copy the full error and send it to the group.** Expected, we'll fix it fast.

---

## Step 5 — Hand off

Get **`packets.csv`** and **`protocol_stats.json`** to Jayant. They're not auto-committed (result files are git-ignored on purpose), so send them directly or force-add:

```
git add -f phase2_capture/outputs/packets.csv phase2_capture/outputs/protocol_stats.json
```

**Do NOT share or commit the `.pcap` file** — it's a raw recording of your own browsing (personal), and it's large. Just the two result files.

---

## Two things you'll see and shouldn't worry about

- **You'll only see *your own* traffic plus network "broadcast" chatter** (ARP, name-lookups, etc.) — not the other laptops' web browsing. That's normal and correct: Wi-Fi encrypts each device's traffic separately, so a normal capture can't read other people's sessions. Nothing to fix; we actually explain this in the report.
- **You'll see IPv6 addresses** in the capture (the long ones with colons). That's fine — expected on our network.

*(If the group ends up switching to a phone hotspot for Jay's scan, just run your capture on that hotspot instead — same steps.)*

---

## TL;DR

Open terminal as Admin → **`ipconfig /flushdns` + close browser** → `capture.py --list` → `capture.py --duration 60 --generate-traffic` and *browse / download / nslookup / ping* during the 60s → `analyze.py` → send **`packets.csv`** + **`protocol_stats.json`** to Jayant (not the pcap). Ping the group if anything errors.
