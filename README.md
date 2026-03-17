# 🔍 Network Threat Detection Tool

A Python-based network traffic analyser that detects common attack
patterns in PCAP files and maps findings to the MITRE ATT&CK framework.

Built as part of my SOC Analyst portfolio.

---

## 🚨 What It Detects

| Threat | Method | MITRE Technique |
|---|---|---|
| Port Scan | Counts unique destination ports per source IP | T1046 |
| SSH Brute Force | Counts repeated connections to port 22 | T1110 |
| DNS Tunneling / C2 | Flags domains queried abnormally often | T1071.004 |

---

## ⚙️ How to Run It

### 1. Install requirements
pip3 install scapy colorama

### 2. Run against a PCAP file
python3 detector.py yourfile.pcap

---

## 🧪 Sample Output
```
[🔴 HIGH]   PORT SCAN DETECTED | Source IP: 10.0.0.5 | Ports hit: 50 | MITRE: T1046
[🔴 HIGH]   BRUTE FORCE DETECTED | Source IP: 10.0.0.6 | SSH attempts: 15 | MITRE: T1110
[🟡 MEDIUM] SUSPICIOUS DNS | Domain: suspicious-c2-domain.xyz | Queries: 25 | MITRE: T1071.004
```

---

## 🛠️ Tools Used
- Python 3
- Scapy
- Wireshark
- MITRE ATT&CK Framework

---

## 👤 Author
**Sandeepta Mahanta** — Aspiring SOC Analyst

[LinkedIn](https://linkedin.com/in/sandeepta-mahanta)
[GitHub](https://github.com/sandeepta2004)
