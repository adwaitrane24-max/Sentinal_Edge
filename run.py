"""
run.py — SentinelEdge entry point.

Usage:
  python run.py [--iface eth0] [--pcap sample.pcap] [--dry-run] [--port 8000]

Starts:
  1. SQLite DB init
  2. Capture thread (scapy)
  3. FastAPI + Uvicorn server (blocking)
"""
import argparse
import asyncio
import threading
import uvicorn
import yaml

from datetime import datetime, timezone

from sentineledge.database import init_db, add_whitelist
from sentineledge.detector import Detector, FlowRecord, Alert
from sentineledge.capture import CaptureEngine
from sentineledge.decision import handle_alert
from sentineledge.dashboard import app, push_alert_from_thread


def parse_args():
    p = argparse.ArgumentParser(description="SentinelEdge NIDS")
    p.add_argument("--iface",   default=None, help="Network interface for live capture")
    p.add_argument("--pcap",    default=None, help="Path to a .pcap file for replay")
    p.add_argument("--dry-run", action="store_true", default=None, help="Log-only mode (no firewall rules)")
    p.add_argument("--port",    type=int, default=8000, help="Dashboard port (default 8000)")
    p.add_argument("--config",  default="config.yaml", help="Config file path")
    return p.parse_args()


def load_config(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def alert_callback(alert: Alert):
    """Called from capture thread — bridge to async push_alert."""
    dry_run = _config.get("capture", {}).get("dry_run", True)
    handle_alert(alert, dry_run=dry_run)

    alert_dict = {
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "alert_id":   alert.alert_id,
        "category":   alert.category,
        "src_ip":     alert.src_ip,
        "detail":     alert.detail,
        "severity":   alert.severity,
        "action":     alert.action,
    }
    push_alert_from_thread(alert_dict)


_config: dict = {}


def main():
    global _config

    args = parse_args()
    _config = load_config(args.config)

    # CLI overrides
    if args.iface:
        _config.setdefault("capture", {})["interface"] = args.iface
    if args.pcap:
        _config.setdefault("capture", {})["pcap_file"] = args.pcap
    if args.dry_run is not None:
        _config.setdefault("capture", {})["dry_run"] = args.dry_run

    # Init DB
    init_db()

    # Seed whitelist from config
    for ip in _config.get("whitelist", []):
        add_whitelist(ip, note="config")

    # Build detector
    detector = Detector(_config, alert_callback)

    def flow_handler(flow: FlowRecord):
        detector.process(flow)

    # Start capture in background thread
    capture = CaptureEngine(_config, flow_handler)
    capture.start()

    dry = _config.get("capture", {}).get("dry_run", True)
    pcap = _config.get("capture", {}).get("pcap_file")
    print(f"""
╔══════════════════════════════════════════════╗
║         SentinelEdge NIDS — Starting         ║
╠══════════════════════════════════════════════╣
║  Mode   : {'DRY-RUN (log only)' if dry else 'LIVE (nftables active)'}
║  Source  : {'PCAP: ' + pcap if pcap else 'Live: ' + _config.get('capture',{}).get('interface','eth0')}
║  Dashboard: http://localhost:{args.port}
╚══════════════════════════════════════════════╝
""")

    uvicorn.run(app, host="0.0.0.0", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
