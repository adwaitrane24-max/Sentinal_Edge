"""
capture.py — Packet capture via scapy.
Supports:
  - Live sniff on a network interface
  - Offline PCAP replay (for demo/testing)
"""
import threading
from typing import Callable

from scapy.all import IP, TCP, UDP, sniff, rdpcap
from scapy.packet import Packet

from .detector import FlowRecord


def _scapy_to_flow(pkt: Packet) -> FlowRecord | None:
    """Convert a scapy packet to a FlowRecord. Returns None if not parseable."""
    if not pkt.haslayer(IP):
        return None

    ip = pkt[IP]
    src_ip = ip.src
    dst_ip = ip.dst
    length = len(pkt)
    payload = bytes(ip.payload.payload) if ip.payload and ip.payload.payload else b""

    protocol = "OTHER"
    src_port = dst_port = 0
    flags = ""
    is_syn = False
    conn_success = False

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        protocol = "TCP"
        src_port = tcp.sport
        dst_port = tcp.dport
        flags = str(tcp.flags)
        is_syn = "S" in flags and "A" not in flags
        # SYN+ACK = connection accepted = success indicator
        conn_success = "S" in flags and "A" in flags

    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        protocol = "UDP"
        src_port = udp.sport
        dst_port = udp.dport

    return FlowRecord(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        flags=flags,
        payload=payload,
        length=length,
        is_syn=is_syn,
        conn_success=conn_success,
    )


class CaptureEngine:
    def __init__(self, config: dict, flow_callback: Callable[[FlowRecord], None]):
        self.iface = config.get("capture", {}).get("interface", "eth0")
        self.pcap_file = config.get("capture", {}).get("pcap_file", None)
        self.callback = flow_callback
        self._stop = threading.Event()

    def _handle_packet(self, pkt: Packet):
        flow = _scapy_to_flow(pkt)
        if flow:
            self.callback(flow)

    def start(self):
        """Start capture in a background thread."""
        t = threading.Thread(target=self._run, daemon=True)
        t.start()

    def _run(self):
        if self.pcap_file:
            print(f"[CAPTURE] Replaying PCAP: {self.pcap_file}")
            pkts = rdpcap(self.pcap_file)
            for pkt in pkts:
                if self._stop.is_set():
                    break
                self._handle_packet(pkt)
            print(f"[CAPTURE] PCAP replay complete ({len(pkts)} packets)")
        else:
            print(f"[CAPTURE] Live sniff on interface: {self.iface}")
            sniff(
                iface=self.iface,
                prn=self._handle_packet,
                store=False,
                stop_filter=lambda _: self._stop.is_set(),
            )

    def stop(self):
        self._stop.set()
