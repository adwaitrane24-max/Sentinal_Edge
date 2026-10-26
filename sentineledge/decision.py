"""
decision.py — Evaluates alerts against whitelist/cooldown, then
applies response: dry-run log OR nftables block/rate-limit (auto-expiring).
"""
import subprocess
import time
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address

from .database import (
    add_block, insert_alert, is_blocked, is_whitelisted
)
from .detector import Alert

# ── Cooldown table: avoid repeated blocks for same IP in short window ─────────
_cooldown: dict[str, float] = {}
COOLDOWN_SEC = 60          # seconds before re-acting on same IP
BLOCK_EXPIRY_SEC = 600     # automatic blocks expire after this (config: response.block_expiry_sec)


def configure_response(block_expiry_sec: int | None = None):
    global BLOCK_EXPIRY_SEC
    if block_expiry_sec:
        BLOCK_EXPIRY_SEC = int(block_expiry_sec)


def _in_cooldown(src_ip: str) -> bool:
    expire = _cooldown.get(src_ip, 0)
    return time.time() < expire


def _set_cooldown(src_ip: str):
    _cooldown[src_ip] = time.time() + COOLDOWN_SEC


# ── nftables (Linux only) ─────────────────────────────────────────────────────
# Everything lives in a dedicated table, so SentinelEdge never touches other rules.
# Blocked IPs are set elements: the kernel expires them on their own timeout, and
# unblocking is a single "delete element". Setup replaces the table atomically,
# so restarts never pile up duplicate rules.
NFT_TABLE = "sentineledge"
_NFT_SETUP = """\
add table inet sentineledge
delete table inet sentineledge
table inet sentineledge {
    set blocked { type ipv4_addr; flags timeout; }
    set ratelimited { type ipv4_addr; flags timeout; }
    set rl_meter { type ipv4_addr; flags dynamic,timeout; timeout 1m; }
    chain input {
        type filter hook input priority -10; policy accept;
        ip saddr @blocked drop
        ip saddr @ratelimited update @rl_meter { ip saddr limit rate over 50/second } drop
    }
}
"""


def _nft(*args: str, script: str | None = None, quiet: bool = False) -> bool:
    """Run `nft <args>` (or `nft -f -` with a script); True on success."""
    cmd = ["nft", "-f", "-"] if script is not None else ["nft", *args]
    try:
        subprocess.run(cmd, input=script, text=True, check=True, capture_output=True)
        return True
    except (OSError, subprocess.CalledProcessError) as exc:
        if not quiet:
            detail = (getattr(exc, "stderr", None) or str(exc)).strip()
            print(f"[RESPONSE] nftables {' '.join(args) or 'setup'} failed: {detail}")
        return False


def setup_firewall(blocks: list) -> None:
    """(Re)create the SentinelEdge table and restore unexpired live blocks.

    Raises RuntimeError when nftables is unavailable, so live mode never runs unprotected.
    """
    script = [_NFT_SETUP]
    now = datetime.now(timezone.utc)
    for b in blocks:
        reason = b.get("reason") or ""
        try:
            ip = str(IPv4Address(b["src_ip"]))
        except ValueError:
            continue
        if reason.startswith("[DRY-RUN]"):
            continue                                   # never enforced; don't start now
        timeout = ""
        if b.get("expires_at"):
            remaining = int((datetime.fromisoformat(b["expires_at"]) - now).total_seconds())
            if remaining <= 0:
                continue
            timeout = f" timeout {remaining}s"
        set_name = "ratelimited" if reason.startswith("rate-limit:") else "blocked"
        script.append(f"add element inet {NFT_TABLE} {set_name} {{ {ip}{timeout} }}\n")
    if not _nft(script="".join(script)):
        raise RuntimeError("could not set up nftables (is nft installed and running as root?)")


def firewall_block(src_ip: str, rate_limit: bool = False, timeout_sec: int | None = None) -> bool:
    """Drop (or rate-limit) src_ip; no timeout = until unblocked."""
    ip = str(IPv4Address(src_ip))
    timeout = f" timeout {int(timeout_sec)}s" if timeout_sec else ""
    set_name = "ratelimited" if rate_limit else "blocked"
    ok = _nft("add", "element", "inet", NFT_TABLE, set_name, f"{{ {ip}{timeout} }}")
    if ok:
        print(f"[RESPONSE] nftables: {'rate-limited' if rate_limit else 'blocked'} {ip}{timeout}")
    return ok


def firewall_unblock(src_ip: str) -> None:
    """Remove src_ip from both sets (missing elements are not an error)."""
    ip = str(IPv4Address(src_ip))
    for set_name in ("blocked", "ratelimited"):
        _nft("delete", "element", "inet", NFT_TABLE, set_name, f"{{ {ip} }}", quiet=True)


# ── Main decision function ────────────────────────────────────────────────────

def handle_alert(alert: Alert, dry_run: bool = True) -> dict:
    """Store an alert, apply the appropriate response, and return the stored row."""
    src_ip = alert.src_ip

    # Always insert into DB for dashboard display
    row = insert_alert(
        alert_id=alert.alert_id,
        category=alert.category,
        src_ip=src_ip,
        detail=alert.detail,
        severity=alert.severity,
        action=alert.action,
    )

    print(f"[ALERT] {alert.alert_id} | {alert.severity.upper()} | {src_ip} | {alert.detail}")
    _respond(alert, dry_run)
    return row


def _respond(alert: Alert, dry_run: bool):
    src_ip = alert.src_ip

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

    if alert.action not in ("block", "rate_limit"):
        return

    rate_limit = alert.action == "rate_limit"
    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=BLOCK_EXPIRY_SEC)).isoformat()
    if dry_run:
        print(f"[DRY-RUN] Would {alert.action} {src_ip} (rule: {alert.alert_id})")
        add_block(src_ip, reason=f"[DRY-RUN] {alert.alert_id}", expires_at=expires_at)
    elif firewall_block(src_ip, rate_limit=rate_limit, timeout_sec=BLOCK_EXPIRY_SEC):
        # Only record blocks the firewall actually applied, so the dashboard never lies
        add_block(src_ip, reason=f"rate-limit:{alert.alert_id}" if rate_limit else alert.alert_id,
                  expires_at=expires_at)

    _set_cooldown(src_ip)
