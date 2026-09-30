"""
create_sample_pcap.py — Generate a test PCAP file containing all 4 attack types.
Run this script once to create 'sample.pcap', then run:
    python run.py --pcap sample.pcap
"""
from scapy.all import IP, TCP, UDP, Raw, wrpcap

pkts = []

# 1. Normal benign traffic
pkts.append(IP(src="192.168.1.50", dst="192.168.1.1")/TCP(sport=4433, dport=80, flags="S"))
pkts.append(IP(src="192.168.1.1", dst="192.168.1.50")/TCP(sport=80, dport=4433, flags="SA"))

# 2. Port Scan (TRW attack) from 192.168.1.77
for port in [21, 22, 23, 25, 80, 443, 8080, 3306, 5432]:
    pkts.append(IP(src="192.168.1.77", dst="192.168.1.1")/TCP(sport=50000+port, dport=port, flags="S"))

# 3. SYN Flood (EWMA attack) from 192.168.1.44
for i in range(160):
    pkts.append(IP(src="192.168.1.44", dst="192.168.1.1")/TCP(sport=10000+i, dport=80, flags="S"))

# 4. Brute Force SSH attempts from 192.168.1.101
for i in range(7):
    pkts.append(IP(src="192.168.1.101", dst="192.168.1.1")/TCP(sport=60000+i, dport=22, flags="S"))

# 5. Signature payload match (e.g. /etc/passwd or cmd.exe) from 192.168.1.150
pkts.append(IP(src="192.168.1.150", dst="192.168.1.1")/TCP(sport=12345, dport=80, flags="PA")/Raw(load=b"GET /etc/passwd HTTP/1.1\r\nHost: example.com\r\n\r\n"))
pkts.append(IP(src="192.168.1.151", dst="192.168.1.1")/TCP(sport=12346, dport=80, flags="PA")/Raw(load=b"POST /api?cmd=cmd.exe HTTP/1.1\r\nHost: example.com\r\n\r\n"))

wrpcap("sample.pcap", pkts)
print(f"Generated sample.pcap with {len(pkts)} packets.")
