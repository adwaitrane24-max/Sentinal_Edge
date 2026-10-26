"""
capture.py — Packet capture via scapy.
Supports:
  - Live sniff on a network interface
  - Offline PCAP replay (for demo/testing)
"""
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Callable

from scapy.all import IP, TCP, UDP, sniff, rdpcap
from scapy.packet import Packet

from .detector import FlowRecord

log = logging.getLogger(__name__)


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
        timestamp=float(pkt.time),
    )


class CaptureEngine:
    def __init__(self, config: dict, flow_callback: Callable[[FlowRecord], None],
                 end_callback: Callable[[], None] | None = None):
        self.iface = config.get("capture", {}).get("interface", "eth0")
        self.pcap_file = config.get("capture", {}).get("pcap_file", None)
        self.callback = flow_callback
        self.end_callback = end_callback   # called once the packet source is exhausted
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._started = time.monotonic()
        self._interval_start = self._started
        self._interval = [0, 0, 0]
        self._rates = [0.0, 0.0, 0.0]
        self._state = "starting"
        self._error = None
        self._stats = dict.fromkeys(("total_packets", "analysed_packets", "total_bytes",
                                    "tcp_packets", "udp_packets", "other_packets",
                                    "tcp_syn_packets", "tcp_syn_ack_packets"), 0)
        self._stats["last_packet_timestamp"] = None

    def snapshot(self) -> dict:
        """Atomic telemetry snapshot; monotonic interval rates decay during idle time."""
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._interval_start
            if elapsed >= 1.0:
                self._rates = [count / elapsed for count in self._interval]
                self._interval = [0, 0, 0]
                self._interval_start = now
            return {**self._stats, "timestamp": datetime.now(timezone.utc).isoformat(),
                    "packets_per_second": self._rates[0], "bytes_per_second": self._rates[1],
                    "syn_per_second": self._rates[2], "status": self._state,
                    "error": self._error, "mode": "pcap" if self.pcap_file else "live",
                    "interface": None if self.pcap_file else self.iface,
                    "pcap_file": str(self.pcap_file) if self.pcap_file else None,
                    "rate_basis": "replay_processing" if self.pcap_file else "live",
                    "uptime_seconds": now - self._started}

    def _handle_packet(self, pkt: Packet):
        try:
            flow = _scapy_to_flow(pkt)
        except (ValueError, TypeError, AttributeError, IndexError):
            flow = None
        length = len(pkt)
        protocol = "tcp" if pkt.haslayer(TCP) else "udp" if pkt.haslayer(UDP) else "other"
        syn = bool(flow and flow.is_syn)
        with self._lock:
            self._stats["total_packets"] += 1
            self._stats["total_bytes"] += length
            self._stats[protocol + "_packets"] += 1
            self._stats["analysed_packets"] += int(flow is not None)
            self._stats["tcp_syn_packets"] += int(syn)
            self._stats["tcp_syn_ack_packets"] += int(bool(flow and flow.conn_success))
            self._stats["last_packet_timestamp"] = datetime.now(timezone.utc).isoformat()
            self._interval[0] += 1
            self._interval[1] += length
            self._interval[2] += int(syn)
        if flow:
            self.callback(flow)

    def start(self):
        """Start capture in a background thread."""
        t = threading.Thread(target=self._run, daemon=True)
        t.start()

    def _run(self):
        with self._lock:
            self._state = "running"
        try:
            self._capture()
            with self._lock:
                self._state = "stopped" if self._stop.is_set() else "completed"
        except Exception as exc:
            with self._lock:
                self._state = "error"
                self._error = str(exc)
            log.error("[CAPTURE] Failed: %s", exc)

    def _capture(self):
        if self.pcap_file:
            log.info("[CAPTURE] Replaying PCAP: %s", self.pcap_file)
            pkts = rdpcap(self.pcap_file)
            for pkt in pkts:
                if self._stop.is_set():
                    break
                self._handle_packet(pkt)
            log.info("[CAPTURE] PCAP replay complete (%d packets)", len(pkts))
        else:
            log.info("[CAPTURE] Live sniff on interface: %s", self.iface)
            if not self.iface:
                raise ValueError("No capture interface configured")
            sniff(iface=self.iface, prn=self._handle_packet, store=False,
                  stop_filter=lambda _: self._stop.is_set())
        if self.end_callback:
            self.end_callback()

    def stop(self):
        self._stop.set()
