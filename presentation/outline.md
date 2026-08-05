# Presentation Outline

40 marks, 4 phases × 10. Every member presents their own phase. Budget roughly
12–15 minutes plus questions.

The through-line: **we assessed a network we are responsible for, and here is
what we found and what we would change.** Not four separate tool demos.

---

## Slide 1 — Scope and method (whoever opens)

- Three Windows laptops, one network, all ours.
- Four phases: discovery → traffic analysis → identity spoofing → synthesis.
- Say the scope sentence out loud: nothing outside our own three machines was
  scanned, captured or modified. Get this in early; it frames everything after.

## Slides 2–3 — Phase 1: Discovery (Member 1)

- **The question:** what is on this network, and what is each host running?
- Method: `nmap -sn` sweep to find live hosts, then `-sV -O` on each to get
  services, versions and OS.
- **The table** from `hosts.csv`: host → IP → open ports → services → OS.
- Point at one specific surprise — an open port nobody knew was listening is the
  best thing you can show here.

## Slides 4–5 — Phase 2: Capture & Analysis (Member 2)

- **The question:** what is actually crossing the wire?
- Method: TShark capture while generating ping / DNS / browse / download traffic;
  parsed with PyShark.
- **Protocol distribution chart** — encrypted vs cleartext at a glance.
- **The two set pieces**, from the Evidence sheet:
  - a TCP three-way handshake, SYN → SYN/ACK → ACK, with frame numbers;
  - a DNS lookup in cleartext — "every site we visited is visible here, even the
    HTTPS ones".
- Side-by-side Wireshark screenshot: an HTTP request you can read next to a TLS
  session you cannot.

## Slides 6–7 — Phase 3: MAC Spoofing (Member 3)

- **The question:** how solid is a device's identity on this network?
- Layer clarity: the MAC is layer 2 and driver-overridable; the IP is layer 3 and
  DHCP-assigned. We are changing the first one.
- **Live demo** (see below).
- **The conclusion, which is the actual point:** MAC filtering, DHCP
  reservations used as authorisation, and "known device" lists are not security
  controls. Use WPA2/WPA3-Enterprise or per-device credentials.
- State the ethical boundary: own laptop, restored afterwards.

## Slides 8–10 — Phase 4: Findings & Hardening (Member 3)

- **Findings by severity** chart — the headline number.
- Top three findings in plain language: what is exposed, why it matters, what an
  attacker does with it.
- Where two phases agree: "445 was open *and* carrying traffic" is a stronger
  claim than either phase alone.
- **Hardening recommendations** — walk through `firewall_rules.txt`, and be
  honest about what each rule costs (blocking 445 breaks file sharing).
- Close on the assessment framing: this is what we would hand to whoever owns
  this network.

---

## The live demo

This is the thing that makes it read as one system instead of four assignments.
Rehearse it once end to end.

1. Member 1 has `python phase1_discovery/scan.py --discovery-only` typed and
   ready. Run it — note the MAC on Member 3's laptop.
2. Member 3 runs `python phase3_spoofing/mac_control.py demo` and changes the
   MAC in SMAC.
3. Member 1 hits Enter again. **The laptop reappears under a different hardware
   address** — a device Nmap has never seen.
4. Member 3 restores. Member 1 re-scans. Back to normal.

**Have a fallback.** Some Wi-Fi drivers refuse spoofed addresses. If yours does,
have a screen recording of a successful run ready, and explain the driver
restriction — that is a legitimate finding, not a failure.

---

## Before you walk in

- [ ] `report.xlsx` regenerated from **real** data, not `--sample`
- [ ] All three laptops on the same network, IPs filled into `shared/config.py`
- [ ] Member 1's re-scan command typed and waiting in a terminal
- [ ] Member 3's MAC **restored** — check `mac_control.py report`
- [ ] Charts exported from `outputs/charts/` into the deck
- [ ] Demo rehearsed once, with the fallback recording to hand
- [ ] Everyone can answer "why does this finding matter?" for their own phase
      without reading the slide

## Questions you should expect

- *Why is an open port a problem if there is a password on the service?* —
  Attack surface, brute force, unpatched versions; the version strings from
  Phase 1 are your evidence.
- *If the site is HTTPS, what did the DNS capture actually leak?* — The domain,
  the timing, and the pattern. Contents no, behaviour yes.
- *Is MAC spoofing illegal?* — On your own device on your own network it is a
  configuration change. Impersonating a device to bypass a control on a network
  you do not own is a different act. Know where that line is.
- *What would you fix first?* — Have a ranked answer ready, and a reason.
