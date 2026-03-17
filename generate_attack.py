from scapy.all import *

packets = []

print("[*] Generating port scan traffic...")
for port in range(1, 51):
    pkt = IP(src="10.0.0.5", dst="192.168.1.1") / TCP(dport=port, flags="S")
    packets.append(pkt)

print("[*] Generating SSH brute force traffic...")
for i in range(15):
    pkt = IP(src="10.0.0.6", dst="192.168.1.1") / TCP(dport=22, flags="S")
    packets.append(pkt)

print("[*] Generating suspicious DNS traffic...")
for i in range(25):
    pkt = (IP(src="10.0.0.7", dst="8.8.8.8") /
           UDP(dport=53) /
           DNS(rd=1, qd=DNSQR(qname="suspicious-c2-domain.xyz")))
    packets.append(pkt)

wrpcap("attack_simulation.pcap", packets)
print("\n[✔] attack_simulation.pcap created!")
print(f"[✔] Total packets: {len(packets)}")
