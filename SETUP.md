# Shared Setup (all three members, day one)

Do this together before anyone splits off into their phase. Everything downstream depends on it.

## 1. Get all three laptops on one network

Use a single WiFi network, a phone hotspot, or a switch — whatever puts all three laptops on the **same subnet**. A dedicated hotspot is cleanest for a demo (predictable, no other devices).

## 2. Record each laptop's IP and MAC

On each laptop (Windows):

```
ipconfig /all
```

Note the IPv4 address, the physical (MAC) address, and the active adapter name (e.g. "Wi-Fi"). Put the three IPs and interface names into `shared/config.py`.

## 3. Confirm the laptops can see each other

From one laptop, ping the other two by IP:

```
ping <other-laptop-ip>
```

If pings fail, check that Windows Firewall isn't blocking ICMP (you can allow "File and Printer Sharing (Echo Request)" inbound), and that all three are on the same subnet.

## 4. Install Python (everyone)

Install Python 3.11+ and confirm:

```
python --version
pip install -r requirements.txt
```

## 5. Install your phase's tools (only your own)

- **Member 1:** Nmap (the installer includes the Npcap driver — accept it).
- **Member 2:** Wireshark (includes TShark; accept the Npcap driver during install).
- **Member 3:** SMAC (free version) for Phase 3; Phase 4 needs no extra tools beyond Python.

## 6. Smoke test

From Member 1's laptop, confirm Nmap sees the other two:

```
nmap -sn <your-subnet>.0/24
```

You should see all three laptops (and anything else on the network) listed as up. If that works, the foundation is solid — split off into your phases.
