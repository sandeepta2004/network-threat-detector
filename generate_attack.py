"""
Attack Traffic Generator
=========================
Generates a synthetic PCAP file containing three attack scenarios
for testing the Network Threat Detection Tool.

Scenarios
---------
1. Port Scan        — 50 SYN packets to sequential ports   (T1046)
2. SSH Brute Force  — 15 SYN packets to port 22            (T1110)
3. DNS C2 Beaconing — 25 DNS queries for a fake C2 domain  (T1071.004)
"""

from scapy.all import IP, TCP, UDP, DNS, DNSQR, wrpcap

OUTPUT_FILE = "attack_simulation.pcap"
packets = []

# ── Scenario 1: Port Scan (T1046) ─────────────────────────────────────────────
print("[*] Generating port scan traffic (ports 1–50)…")
for port in range(1, 51):
    pkt = IP(src="10.0.0.5", dst="192.168.1.1") / TCP(dport=port, flags="S")
    packets.append(pkt)

# ── Scenario 2: SSH Brute Force (T1110) ───────────────────────────────────────
print("[*] Generating SSH brute force traffic (15 attempts to port 22)…")
for _ in range(15):
    pkt = IP(src="10.0.0.6", dst="192.168.1.1") / TCP(dport=22, flags="S")
    packets.append(pkt)

# ── Scenario 3: DNS C2 Beaconing (T1071.004) ──────────────────────────────────
print("[*] Generating suspicious DNS beaconing traffic (25 queries)…")
for _ in range(25):
    pkt = (
        IP(src="10.0.0.7", dst="8.8.8.8")
        / UDP(dport=53)
        / DNS(rd=1, qd=DNSQR(qname="suspicious-c2-domain.xyz"))
    )
    packets.append(pkt)

# ── Write PCAP ────────────────────────────────────────────────────────────────
wrpcap(OUTPUT_FILE, packets)
print(f"\n[✔] {OUTPUT_FILE} created successfully!")
print(f"[✔] Total packets : {len(packets)}")
print("\nRun detector against it:")
print(f"  python3 detector.py {OUTPUT_FILE}\n")
