# ============================================================
# Network Threat Detection Tool
# Built by: Sandeepta Mahanta
# What it does: Reads a PCAP file and flags suspicious activity
# ============================================================

from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR
from collections import defaultdict
from colorama import Fore, Style, init
import sys

init(autoreset=True)

# ── Settings ─────────────────────────────────────────────────
PORT_SCAN_THRESHOLD   = 10
BRUTE_FORCE_THRESHOLD = 10
DNS_THRESHOLD         = 20

# ── Counters ─────────────────────────────────────────────────
port_scan_tracker   = defaultdict(set)
brute_force_tracker = defaultdict(int)
dns_tracker         = defaultdict(int)
findings            = []

def banner():
    print(Fore.CYAN + """
╔══════════════════════════════════════════╗
║    🔍 Network Threat Detection Tool     ║
║         SOC Analyst Portfolio           ║
╚══════════════════════════════════════════╝
""")

def analyse(pcap_file):
    print(Fore.YELLOW + f"[*] Loading PCAP: {pcap_file}\n")
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(Fore.RED + f"[!] File not found: {pcap_file}")
        sys.exit(1)

    print(Fore.YELLOW + f"[*] Analysing {len(packets)} packets...\n")

    for pkt in packets:

        # ── Port Scan Detection ───────────────────────────────
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            src = pkt[IP].src
            dst_port = pkt[TCP].dport
            port_scan_tracker[src].add(dst_port)

        # ── Brute Force Detection (SSH = port 22) ─────────────
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            if pkt[TCP].dport == 22:
                brute_force_tracker[pkt[IP].src] += 1

        # ── DNS Tunneling Detection ───────────────────────────
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            domain = pkt[DNSQR].qname.decode(errors="ignore")
            dns_tracker[domain] += 1

    evaluate_results()

def evaluate_results():

    # ── Check Port Scans ──────────────────────────────────────
    for ip, ports in port_scan_tracker.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            msg = (f"PORT SCAN DETECTED | Source IP: {ip} "
                   f"| Ports hit: {len(ports)} "
                   f"| MITRE: T1046 – Network Service Scanning")
            findings.append(("HIGH", msg))

    # ── Check Brute Force ─────────────────────────────────────
    for ip, count in brute_force_tracker.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            msg = (f"BRUTE FORCE DETECTED | Source IP: {ip} "
                   f"| SSH attempts: {count} "
                   f"| MITRE: T1110 – Brute Force")
            findings.append(("HIGH", msg))

    # ── DNS Anomalies ─────────────────────────────────────────
    for domain, count in dns_tracker.items():
        if count >= DNS_THRESHOLD:
            msg = (f"SUSPICIOUS DNS | Domain: {domain} "
                   f"| Queries: {count} "
                   f"| MITRE: T1071.004 – DNS C2")
            findings.append(("MEDIUM", msg))

    print_report()

def print_report():
    print(Fore.CYAN + "=" * 60)
    print(Fore.CYAN + "           THREAT DETECTION REPORT")
    print(Fore.CYAN + "=" * 60)

    if not findings:
        print(Fore.GREEN + "\n[✔] No threats detected in this PCAP.\n")
    else:
        for severity, msg in findings:
            if severity == "HIGH":
                print(Fore.RED    + f"\n[🔴 HIGH]   {msg}")
            elif severity == "MEDIUM":
                print(Fore.YELLOW + f"\n[🟡 MEDIUM] {msg}")

    print(Fore.CYAN + "\n" + "=" * 60)
    print(Fore.WHITE + f"  Total findings: {len(findings)}")
    print(Fore.CYAN + "=" * 60 + "\n")

# ── Entry Point ───────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(Fore.RED + "\n[!] Usage: python3 detector.py <your_file.pcap>\n")
        sys.exit(1)
    banner()
    analyse(sys.argv[1])
