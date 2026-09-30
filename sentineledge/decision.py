"""
decision.py — Evaluates alerts against whitelist/cooldown, then
applies response: dry-run log OR nftables block/rate-limit.
"""
import subprocess
import time
from typing import Set

from .database import (
    add_block, insert_alert, is_blocked, is_whitelisted
)
from .detector import Alert

# ── Cooldown table: avoid repeated blocks for same IP in short window ─────────
_cooldown: dict[str, float] = {}
COOLDOWN_SEC = 60          # seconds before re-acting on same IP
BLOCK_EXPIRY_SEC = 600     # 10-minute auto-expiry on nftables rule (informational)


def _in_cooldown(src_ip: str) -> bool:
    expire = _cooldown.get(src_ip, 0)
    return time.time() < expire


def _set_cooldown(src_ip: str):
    _cooldown[src_ip] = time.time() + COOLDOWN_SEC


# ── nftables helpers (Linux only) ─────────────────────────────────────────────

def _nft_block(src_ip: str):
    """Add a drop rule to nftables input chain."""
    cmd = ["nft", "add", "rule", "inet", "filter", "input",
           f"ip saddr {src_ip}", "drop"]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        print(f"[RESPONSE] nftables: blocked {src_ip}")
    except Exception as e:
        print(f"[RESPONSE] nftables error: {e}")


def _nft_rate_limit(src_ip: str):
    """Add a rate-limit rule (50 packets/second) for src_ip."""
    cmd = ["nft", "add", "rule", "inet", "filter", "input",
           f"ip saddr {src_ip}", "limit rate over 50/second", "drop"]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        print(f"[RESPONSE] nftables: rate-limited {src_ip}")
    except Exception as e:
        print(f"[RESPONSE] nftables error: {e}")


# ── Main decision function ────────────────────────────────────────────────────

def handle_alert(alert: Alert, dry_run: bool = True, ws_broadcast=None):
    """
    Evaluate an alert and apply the appropriate response.
    ws_broadcast: optional async coroutine to push alert to WebSocket clients.
    """
    src_ip = alert.src_ip

    # Always insert into DB for dashboard display
    insert_alert(
        alert_id=alert.alert_id,
        category=alert.category,
        src_ip=src_ip,
        detail=alert.detail,
        severity=alert.severity,
        action=alert.action,
    )

    print(f"[ALERT] {alert.alert_id} | {alert.severity.upper()} | {src_ip} | {alert.detail}")

    # Skip response if whitelisted
    if is_whitelisted(src_ip):
        print(f"[DECISION] {src_ip} is whitelisted — no action taken")
        return

    # Skip if already blocked
    if is_blocked(src_ip):
        return

    # Skip if in cooldown
    if _in_cooldown(src_ip):
        return

    if alert.action == "alert_only":
        _set_cooldown(src_ip)
        return

    if dry_run:
        print(f"[DRY-RUN] Would {alert.action} {src_ip} (rule: {alert.alert_id})")
        add_block(src_ip, reason=f"[DRY-RUN] {alert.alert_id}")
        _set_cooldown(src_ip)
        return

    # Live mode — apply nftables rule
    if alert.action == "block":
        _nft_block(src_ip)
        add_block(src_ip, reason=alert.alert_id)
    elif alert.action == "rate_limit":
        _nft_rate_limit(src_ip)
        add_block(src_ip, reason=f"rate-limit:{alert.alert_id}")

    _set_cooldown(src_ip)
