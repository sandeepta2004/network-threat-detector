# 🔍 Network Threat Detection Tool

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-2.5%2B-green)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

A Python-based PCAP analyser that detects real attack patterns from raw network traffic and maps every finding to the **MITRE ATT&CK** framework — built to simulate the triage workflow of an L1 SOC Analyst.

---

## 🚨 Detections

| Threat | Detection Method | Severity | MITRE Technique |
|--------|-----------------|----------|-----------------|
| Port Scan | Counts unique destination ports per source IP | 🔴 HIGH | [T1046 – Network Service Scanning](https://attack.mitre.org/techniques/T1046/) |
| SSH Brute Force | Counts repeated TCP SYN packets to port 22 | 🔴 HIGH | [T1110 – Brute Force](https://attack.mitre.org/techniques/T1110/) |
| DNS C2 Beaconing | Flags domains queried abnormally often | 🟡 MEDIUM | [T1071.004 – Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/) |

---

## ⚙️ Setup

### Prerequisites
- Python 3.8+
- `pip3`

### Install dependencies

```bash
pip3 install -r requirements.txt
```

---

## 🚀 Usage

### Step 1 — Generate test attack traffic (optional)

```bash
python3 generate_attack.py
```

This creates `attack_simulation.pcap` containing all three attack scenarios.

### Step 2 — Run the detector

```bash
python3 detector.py attack_simulation.pcap
```

### Step 3 — Export findings as JSON (optional)

```bash
python3 detector.py attack_simulation.pcap --output report.json
```

---

## 🧪 Sample Output

```
╔══════════════════════════════════════════════╗
║      🔍 Network Threat Detection Tool       ║
║    MITRE ATT&CK Mapped  |  SOC Portfolio    ║
╚══════════════════════════════════════════════╝

[*] Loading PCAP: attack_simulation.pcap
[*] Analysing 90 packets…

═════════════════════════════════════════════════════════════════
               THREAT DETECTION REPORT
═════════════════════════════════════════════════════════════════

[🔴 HIGH]   PORT SCAN DETECTED | Source IP: 10.0.0.5 | Ports hit: 50 | MITRE: T1046 – Network Service Scanning

[🔴 HIGH]   SSH BRUTE FORCE DETECTED | Source IP: 10.0.0.6 | Attempts: 15 | MITRE: T1110 – Brute Force

[🟡 MEDIUM] SUSPICIOUS DNS BEACONING | Domain: suspicious-c2-domain.xyz | Queries: 25 | MITRE: T1071.004 – Application Layer Protocol: DNS

═════════════════════════════════════════════════════════════════
  Total findings : 3
  HIGH           : 2
  MEDIUM         : 1
═════════════════════════════════════════════════════════════════
```

---

## 📁 Project Structure

```
network-threat-detector/
├── detector.py           # Main threat detection engine
├── generate_attack.py    # Synthetic PCAP generator for testing
├── requirements.txt      # Python dependencies
├── .gitignore
└── README.md
```

---

## 🛠️ Tools & Technologies

| Tool | Purpose |
|------|---------|
| Python 3 | Core language |
| Scapy | Packet parsing and PCAP generation |
| Colorama | Colour-coded terminal output |
| Wireshark | Manual validation of detections |
| MITRE ATT&CK | Threat mapping framework |

---

## 🔬 How It Works

1. **Load** — Reads every packet from the supplied PCAP file using Scapy
2. **Track** — Builds per-IP counters for ports touched, SSH attempts, and DNS queries
3. **Evaluate** — Compares metrics against configurable thresholds
4. **Report** — Prints a colour-coded report with severity levels and MITRE technique IDs
5. **Export** *(optional)* — Writes findings to JSON for SIEM ingestion or further analysis

---

## ⚙️ Configuration

Thresholds can be adjusted at the top of `detector.py`:

```python
PORT_SCAN_THRESHOLD   = 10   # unique destination ports from one IP
BRUTE_FORCE_THRESHOLD = 10   # repeated connections to port 22
DNS_THRESHOLD         = 20   # repeated queries for the same domain
```

---

## 👤 Author

**Sandeepta Mahanta** — Final-year B.Tech IT student specialising in SOC operations, threat detection, and incident response.

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?logo=linkedin)](https://linkedin.com/in/sandeeptamahanta)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-black?logo=github)](https://github.com/sandeeptam2004)

---

## 📄 License

This project is licensed under the MIT License.
