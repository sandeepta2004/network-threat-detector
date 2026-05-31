"""
Network Threat Detection Tool
==============================
Author  : Sandeepta Mahanta
GitHub  : https://github.com/sandeeptam2004
Purpose : Reads a PCAP file, detects common attack patterns,
          and maps findings to the MITRE ATT&CK framework.

Detections
----------
- Port Scan        → MITRE T1046  (Network Service Scanning)
- SSH Brute Force  → MITRE T1110  (Brute Force)
- DNS C2 Beaconing → MITRE T1071.004 (Application Layer Protocol: DNS)
"""

import sys
import json
import argparse
from collections import defaultdict
from datetime import datetime

from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR
from colorama import Fore, Style, init

init(autoreset=True)

# ── Detection Thresholds ──────────────────────────────────────────────────────
PORT_SCAN_THRESHOLD   = 10   # unique dest ports from one source IP
BRUTE_FORCE_THRESHOLD = 10   # repeated TCP SYN packets to port 22
DNS_THRESHOLD         = 20   # repeated queries for the same domain

# ── Internal State ────────────────────────────────────────────────────────────
port_scan_tracker   = defaultdict(set)   # src_ip → {ports}
brute_force_tracker = defaultdict(int)   # src_ip → count
dns_tracker         = defaultdict(int)   # domain  → count
findings            = []                 # list of (severity, message, mitre_id)


# ── Banner ────────────────────────────────────────────────────────────────────
def banner() -> None:
    print(Fore.CYAN + """
╔══════════════════════════════════════════════╗
║      🔍 Network Threat Detection Tool       ║
║    MITRE ATT&CK Mapped  |  SOC Portfolio    ║
╚══════════════════════════════════════════════╝
""")


# ── Packet Analysis ───────────────────────────────────────────────────────────
def analyse(pcap_file: str) -> None:
    """Load and analyse every packet in the given PCAP file."""
    print(Fore.YELLOW + f"[*] Loading PCAP: {pcap_file}")
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(Fore.RED + f"[!] File not found: {pcap_file}")
        sys.exit(1)
    except Exception as e:
        print(Fore.RED + f"[!] Failed to read PCAP: {e}")
        sys.exit(1)

    print(Fore.YELLOW + f"[*] Analysing {len(packets)} packets…\n")

    for pkt in packets:
        _detect_port_scan(pkt)
        _detect_brute_force(pkt)
        _detect_dns_tunneling(pkt)

    _evaluate_results()


def _detect_port_scan(pkt) -> None:
    """Track unique destination ports per source IP (T1046)."""
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        src      = pkt[IP].src
        dst_port = pkt[TCP].dport
        port_scan_tracker[src].add(dst_port)


def _detect_brute_force(pkt) -> None:
    """Count repeated TCP connections to port 22 per source IP (T1110)."""
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        if pkt[TCP].dport == 22:
            brute_force_tracker[pkt[IP].src] += 1


def _detect_dns_tunneling(pkt) -> None:
    """Flag domains queried an abnormal number of times (T1071.004)."""
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        domain = pkt[DNSQR].qname.decode(errors="ignore")
        dns_tracker[domain] += 1


# ── Threshold Evaluation ──────────────────────────────────────────────────────
def _evaluate_results() -> None:
    """Compare collected metrics against thresholds and build the findings list."""

    for ip, ports in port_scan_tracker.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            findings.append((
                "HIGH",
                f"PORT SCAN DETECTED | Source IP: {ip} | Ports hit: {len(ports)}",
                "T1046 – Network Service Scanning",
            ))

    for ip, count in brute_force_tracker.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            findings.append((
                "HIGH",
                f"SSH BRUTE FORCE DETECTED | Source IP: {ip} | Attempts: {count}",
                "T1110 – Brute Force",
            ))

    for domain, count in dns_tracker.items():
        if count >= DNS_THRESHOLD:
            findings.append((
                "MEDIUM",
                f"SUSPICIOUS DNS BEACONING | Domain: {domain} | Queries: {count}",
                "T1071.004 – Application Layer Protocol: DNS",
            ))

    _print_report()


# ── Reporting ─────────────────────────────────────────────────────────────────
def _print_report() -> None:
    """Print a colour-coded threat report to stdout."""
    print(Fore.CYAN + "=" * 65)
    print(Fore.CYAN + "               THREAT DETECTION REPORT")
    print(Fore.CYAN + "=" * 65)

    if not findings:
        print(Fore.GREEN + "\n[✔] No threats detected in this PCAP.\n")
    else:
        for severity, msg, mitre in findings:
            mitre_tag = Fore.WHITE + f" | MITRE: {mitre}"
            if severity == "HIGH":
                print(Fore.RED    + f"\n[🔴 HIGH]   {msg}" + mitre_tag)
            elif severity == "MEDIUM":
                print(Fore.YELLOW + f"\n[🟡 MEDIUM] {msg}" + mitre_tag)

    print(Fore.CYAN + "\n" + "=" * 65)
    print(Fore.WHITE + f"  Total findings : {len(findings)}")
    highs   = sum(1 for s, _, _ in findings if s == "HIGH")
    mediums = sum(1 for s, _, _ in findings if s == "MEDIUM")
    print(Fore.RED    + f"  HIGH           : {highs}")
    print(Fore.YELLOW + f"  MEDIUM         : {mediums}")
    print(Fore.CYAN + "=" * 65 + "\n")


def _export_json(output_path: str) -> None:
    """Write findings to a JSON file for SIEM ingestion or further triage."""
    timestamp = datetime.utcnow().isoformat() + "Z"
    report = {
        "tool"      : "Network Threat Detection Tool",
        "author"    : "Sandeepta Mahanta",
        "timestamp" : timestamp,
        "total"     : len(findings),
        "findings"  : [
            {"severity": s, "description": m, "mitre": t}
            for s, m, t in findings
        ],
    }
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(Fore.GREEN + f"[✔] Report exported → {output_path}\n")


# ── CLI Entry Point ───────────────────────────────────────────────────────────
def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="PCAP-based network threat detector with MITRE ATT&CK mapping.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 detector.py attack_simulation.pcap
  python3 detector.py capture.pcap --output report.json
        """,
    )
    parser.add_argument("pcap", help="Path to the PCAP file to analyse")
    parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Export findings as JSON (e.g. report.json)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    banner()
    analyse(args.pcap)
    if args.output:
        _export_json(args.output)
