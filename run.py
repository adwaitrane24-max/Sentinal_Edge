"""
run.py — SentinelEdge entry point.

Usage:
  python run.py [--iface eth0] [--pcap sample.pcap] [--dry-run] [--host 127.0.0.1] [--port 8000]

The dashboard needs an access token: set SENTINELEDGE_TOKEN, or a random one is
generated and printed as part of the dashboard link at startup. On a desktop
session that link is also opened in the browser (disable with --no-browser).

Starts:
  1. SQLite DB init
  2. Capture thread (scapy)
  3. FastAPI + Uvicorn server (blocking)
"""
import argparse
import logging
import os
import secrets
import sys
import threading
import webbrowser
import uvicorn
import yaml

from sentineledge.database import init_db, add_whitelist, get_blocks, prune_alerts
from sentineledge.detector import Detector, FlowRecord, Alert
from sentineledge.capture import CaptureEngine
from sentineledge.decision import handle_alert, configure_response, setup_firewall
from sentineledge.dashboard import (app, push_alert_from_thread, configure_capture, configure_auth,
                                    configure_protected)


def parse_args():
    p = argparse.ArgumentParser(description="SentinelEdge NIDS")
    p.add_argument("--iface",   default=None, help="Network interface for live capture")
    p.add_argument("--pcap",    default=None, help="Path to a .pcap file for replay")
    p.add_argument("--dry-run", action="store_true", default=None, help="Log-only mode (no firewall rules)")
    p.add_argument("--host",    default="127.0.0.1",
                   help="Dashboard bind address (default 127.0.0.1 = this machine only; 0.0.0.0 = whole network)")
    p.add_argument("--port",    type=int, default=8000, help="Dashboard port (default 8000)")
    p.add_argument("--config",  default="config.yaml", help="Config file path")
    p.add_argument("--no-browser", action="store_true", help="Don't open the dashboard in a browser")
    return p.parse_args()


def can_open_browser() -> bool:
    """Only on an interactive desktop session: never as root or on a server without a display."""
    if sys.platform.startswith("linux"):
        return os.geteuid() != 0 and bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    return True


def load_config(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            config = yaml.safe_load(f)
        if not isinstance(config, dict) or not isinstance(config.get("capture", {}), dict):
            raise ValueError("configuration must contain a mapping")
        return config
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise SystemExit(f"Unable to load configuration {path}: {exc}")


def alert_callback(alert: Alert):
    """Called from capture thread — bridge to async push_alert."""
    dry_run = _config.get("capture", {}).get("dry_run", True)
    # Push the stored row itself: its id and timestamp let reconnecting dashboards deduplicate
    push_alert_from_thread(handle_alert(alert, dry_run=dry_run))


_config: dict = {}


def main():
    global _config

    args = parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(message)s",
                        datefmt="%H:%M:%S")
    _config = load_config(args.config)

    # CLI overrides
    if args.iface:
        _config.setdefault("capture", {})["interface"] = args.iface
        _config["capture"]["pcap_file"] = None
    if args.pcap:
        _config.setdefault("capture", {})["pcap_file"] = args.pcap
    if args.dry_run is not None:
        _config.setdefault("capture", {})["dry_run"] = args.dry_run

    # Init DB and drop alerts past the retention period
    init_db()
    removed = prune_alerts((_config.get("alerts") or {}).get("retention_days", 30))
    if removed:
        logging.info("[DB] Removed %d alerts older than the retention period", removed)

    # Seed whitelist from config; those addresses can never be blocked from the dashboard
    whitelist = _config.get("whitelist") or []
    for ip in whitelist:
        add_whitelist(ip, note="config")
    configure_protected(whitelist)

    # Live mode: (re)create the firewall table and restore unexpired blocks
    configure_response((_config.get("response") or {}).get("block_expiry_sec"))
    if not _config.get("capture", {}).get("dry_run", True):
        try:
            setup_firewall(get_blocks())
        except RuntimeError as exc:
            raise SystemExit(f"Live mode needs nftables: {exc}. Use --dry-run to run without it.")

    # Build detector
    detector = Detector(_config, alert_callback)

    def flow_handler(flow: FlowRecord):
        detector.process(flow)

    # Start capture in background thread
    capture = CaptureEngine(_config, flow_handler, end_callback=detector.flush)
    configure_capture(capture, _config.get("capture", {}).get("dry_run", True))
    capture.start()

    # Dashboard access token: stable if set in the environment, otherwise new each run
    token = os.environ.get("SENTINELEDGE_TOKEN") or secrets.token_urlsafe(24)
    configure_auth(token)
    exposed = args.host not in ("127.0.0.1", "localhost", "::1")
    link_host = "127.0.0.1" if args.host in ("0.0.0.0", "::", "") else args.host
    link = f"http://{link_host}:{args.port}/#token={token}"
    browser = not args.no_browser and can_open_browser()

    dry = _config.get("capture", {}).get("dry_run", True)
    pcap = _config.get("capture", {}).get("pcap_file")
    print(f"""
+----------------------------------------------+
|         SentinelEdge NIDS - Starting            |
+----------------------------------------------+
|  Mode   : {'DRY-RUN (log only)' if dry else 'LIVE (nftables active)'}
|  Source  : {'PCAP: ' + pcap if pcap else 'Live: ' + _config.get('capture',{}).get('interface','eth0')}
|  Listening: {args.host}:{args.port}{'  (WARNING: reachable from the network)' if exposed else '  (this machine only)'}
|  Dashboard: {link}
|      Open this exact link{' (opening it in your browser now)' if browser else ''}.
|      It contains the access token; plain http://{link_host}:{args.port} will ask for it.
+----------------------------------------------+
""", flush=True)   # the link carries the token: show it even when output goes to a log file

    if browser:   # give the server a moment to start listening first
        threading.Timer(1.5, webbrowser.open, [link]).start()

    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
