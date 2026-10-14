"""
detector.py — All 4 detection algorithms.

  1. Aho-Corasick   — payload signature matching
  2. TRW            — port-scan detection (sequential hypothesis testing)
  3. EWMA           — SYN flood detection (dynamic threshold)
  4. Brute-force    — failed auth attempt counter
  5. Exfil          — abnormal outbound data volume
"""
import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, List, Optional

import ahocorasick


# ── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class FlowRecord:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str          # TCP / UDP / ICMP
    flags: str             # e.g. "S", "SA", "R"
    payload: bytes
    length: int
    is_syn: bool
    conn_success: bool     # True if SYN+ACK received / False if RST or no reply
    timestamp: float = 0.0  # packet capture time (epoch seconds); 0 = use wall clock


@dataclass
class Alert:
    alert_id: str
    category: str
    src_ip: str
    detail: str
    severity: str
    action: str


# ── 1. Aho-Corasick signature matcher ─────────────────────────────────────────

class SignatureMatcher:
    def __init__(self, signatures: List[dict]):
        self.automaton = ahocorasick.Automaton()
        for sig in signatures:
            self.automaton.add_word(sig["pattern"], (sig["id"], sig["severity"]))
        if self.automaton:
            self.automaton.make_automaton()
        self._has_sigs = bool(signatures)

    def match(self, payload: bytes) -> Optional[tuple]:
        if not self._has_sigs or not payload:
            return None
        text = payload.decode("utf-8", errors="ignore")
        for _, (sig_id, severity) in self.automaton.iter(text):
            return sig_id, severity   # return first match
        return None


# ── 2. TRW port-scan detector ─────────────────────────────────────────────────

class TRWState:
    """Per-source-IP likelihood ratio tracker (Jung et al., 2004).

    Evidence comes from first-contact TCP connection attempts only: a SYN to a
    (dst_ip, dst_port) the source has not tried before opens a pending attempt.
    It resolves as a success on the target's SYN-ACK, or as a failure on the
    target's RST or when no reply arrives within timeout_sec. Other packets
    (data, ACKs, retransmitted SYNs, UDP) are not evidence.
    """

    def __init__(self, alpha=0.01, beta=0.01, theta0=0.8, theta1=0.2, timeout_sec=3.0):
        self.eta0 = beta / (1 - alpha)           # clear-benign threshold
        self.eta1 = (1 - beta) / alpha           # flag-scanner threshold
        self.theta0 = theta0                     # P(success | benign)
        self.theta1 = theta1                     # P(success | scanner)
        self.timeout_sec = timeout_sec           # unanswered SYN → failure
        self._ratio: dict[str, float] = defaultdict(lambda: 1.0)
        self._flagged: set = set()
        # {src_ip: {(dst_ip, dst_port), ...}} targets already tried
        self._contacted: dict[str, set] = defaultdict(set)
        # {(src_ip, dst_ip, dst_port): SYN time}, insertion-ordered ≈ time-ordered
        self._pending: dict[tuple, float] = {}

    def observe(self, flow: FlowRecord) -> List[str]:
        """Feed one packet; return source IPs that just crossed the scanner threshold."""
        now = flow.timestamp or time.time()
        flagged = self._expire(now)
        if flow.protocol != "TCP":
            return flagged
        if flow.is_syn:
            target = (flow.dst_ip, flow.dst_port)
            if flow.src_ip not in self._flagged and target not in self._contacted[flow.src_ip]:
                self._contacted[flow.src_ip].add(target)
                self._pending[(flow.src_ip, *target)] = now
        elif flow.conn_success or "R" in flow.flags:
            # Replies travel target → initiator, so swap endpoints to find the attempt
            key = (flow.dst_ip, flow.src_ip, flow.src_port)
            if self._pending.pop(key, None) is not None and self.update(key[0], flow.conn_success):
                flagged.append(key[0])
        return flagged

    def flush(self) -> List[str]:
        """Resolve all pending attempts as failures (the packet source has ended)."""
        return self._expire(math.inf)

    def _expire(self, now: float) -> List[str]:
        flagged = []
        while self._pending:
            key, started = next(iter(self._pending.items()))
            if now - started < self.timeout_sec:
                break
            del self._pending[key]
            if self.update(key[0], False):
                flagged.append(key[0])
        return flagged

    def update(self, src_ip: str, conn_success: bool) -> bool:
        """Record one resolved attempt; return True only when src_ip first crosses the scanner threshold.

        Likelihood ratio Λ = P(obs|scanner) / P(obs|benign).
          - Connection SUCCESS:  P(success|scanner)/P(success|benign) = θ1/θ0  < 1  → ratio drops
          - Connection FAILURE:  P(fail|scanner)/P(fail|benign) = (1-θ1)/(1-θ0) > 1 → ratio rises
        Flag as scanner when Λ ≥ η1; clear as benign when Λ ≤ η0.
        """
        if src_ip in self._flagged:
            return False                     # already reported
        if conn_success:
            # Success: evidence of benign — ratio drops
            lr = self.theta1 / self.theta0          # < 1 for θ1 < θ0
        else:
            # Failure: evidence of scanning — ratio rises
            lr = (1 - self.theta1) / (1 - self.theta0)  # > 1 for θ1 < θ0
        self._ratio[src_ip] *= lr
        ratio = self._ratio[src_ip]
        if ratio <= self.eta0:
            self._ratio.pop(src_ip, None)   # cleared as benign
            return False
        if ratio >= self.eta1:
            self._flagged.add(src_ip)
            self._ratio.pop(src_ip, None)
            self._contacted.pop(src_ip, None)   # no longer tracked once flagged
            return True
        return False

    def clear(self, src_ip: str):
        self._flagged.discard(src_ip)
        self._ratio.pop(src_ip, None)
        self._contacted.pop(src_ip, None)


# ── 3. EWMA SYN-flood detector ────────────────────────────────────────────────

class EWMAFloodDetector:
    """Dynamic threshold based on SYNGuard (Rahouti et al., 2021)."""

    def __init__(self, lam=0.2, k_sigma=4, hard_ceiling=150, window_sec=1.0):
        self.lam = lam
        self.k_sigma = k_sigma
        self.hard_ceiling = hard_ceiling
        self.window_sec = window_sec

        self._ewma = 0.0
        self._ewmv = 0.0          # exponentially weighted variance
        self._count = 0
        self._window_start = time.time()

    def update(self, is_syn: bool) -> bool:
        """Call for every packet. Returns True if SYN flood detected."""
        if is_syn:
            self._count += 1
        now = time.time()
        elapsed = now - self._window_start
        if elapsed >= self.window_sec:
            rate = self._count / elapsed
            # Update EWMA and EWMV
            delta = rate - self._ewma
            self._ewma += self.lam * delta
            self._ewmv = (1 - self.lam) * (self._ewmv + self.lam * delta ** 2)
            sigma = math.sqrt(self._ewmv) if self._ewmv > 0 else 1.0
            threshold = self._ewma + self.k_sigma * sigma
            # Reset window
            self._count = 0
            self._window_start = now
            return rate > threshold or rate > self.hard_ceiling
        return False


# ── 4. Brute-force detector ───────────────────────────────────────────────────

AUTH_SERVICES = {22: "ssh", 21: "ftp", 3389: "rdp"}
_LEVELS = {"none": 0, "alert": 1, "block": 2}


class BruteForceDetector:
    """Sliding-window login-attempt counter per (src_ip, service).

    Logins are encrypted, so a failed password is invisible on the wire. Instead
    each new TCP connection to an auth service counts as one attempt: guessing
    tools reconnect every few tries, while a normal session is one connection
    however many packets it carries. A retransmitted SYN is not counted twice.
    """

    def __init__(self, fail_alert=6, win_alert=60, fail_block=10, win_block=300):
        self.fail_alert = fail_alert
        self.win_alert = win_alert
        self.fail_block = fail_block
        self.win_block = win_block
        # {(src_ip, service): [(timestamp, conn_id), ...]}
        self._events: dict = {}
        # {(src_ip, service): highest level already reported}
        self._reported: dict = {}

    def record_attempt(self, src_ip: str, service: str, conn_id: tuple, now: float = 0.0) -> str:
        """Return 'block' or 'alert' when src_ip first reaches that level, else 'none'."""
        now = now or time.time()
        key = (src_ip, service)
        cutoff = now - max(self.win_alert, self.win_block)
        events = [(t, c) for t, c in self._events.get(key, []) if t >= cutoff]
        if all(c != conn_id for _, c in events):     # skip SYN retransmits
            events.append((now, conn_id))
        self._events[key] = events

        recent_block = sum(1 for t, _ in events if t >= now - self.win_block)
        recent_alert = sum(1 for t, _ in events if t >= now - self.win_alert)
        level = ("block" if recent_block >= self.fail_block
                 else "alert" if recent_alert >= self.fail_alert else "none")

        # Report escalations only; drop back when activity subsides so it can re-alert later
        previous = self._reported.get(key, "none")
        self._reported[key] = level
        return level if _LEVELS[level] > _LEVELS[previous] else "none"


# ── 5. Exfiltration volume monitor ───────────────────────────────────────────

class ExfilDetector:
    """Flags internal IPs whose outbound bytes spike far above their own baseline."""

    def __init__(self, multiplier=5, window_sec=300, floor_bytes=524_288_000):
        self.multiplier = multiplier
        self.window_sec = window_sec
        self.floor_bytes = floor_bytes
        # {ip: [(timestamp, bytes)]}
        self._log: dict = defaultdict(list)

    def record(self, src_ip: str, byte_count: int) -> bool:
        now = time.time()
        self._log[src_ip].append((now, byte_count))
        # Keep last 24 h of data
        cutoff_24h = now - 86_400
        self._log[src_ip] = [(t, b) for t, b in self._log[src_ip] if t >= cutoff_24h]

        cutoff_win = now - self.window_sec
        recent = sum(b for t, b in self._log[src_ip] if t >= cutoff_win)
        baseline = sum(b for _, b in self._log[src_ip]) / max(len(self._log[src_ip]), 1)
        threshold = max(baseline * self.multiplier, self.floor_bytes)
        return recent > threshold


# ── Detector orchestrator ─────────────────────────────────────────────────────

class Detector:
    def __init__(self, config: dict, alert_callback: Callable[[Alert], None]):
        self.callback = alert_callback
        self._dry_run = config.get("capture", {}).get("dry_run", True)

        # Repeats of the same (rule, source, action) within this window are dropped
        self.suppress_sec = (config.get("alerts") or {}).get("suppress_sec", 60)
        self._last_alert: dict[tuple, float] = {}
        self._now = 0.0   # timestamp of the packet being processed

        rules = {r["id"]: r for r in config.get("rules", []) if r.get("enabled")}
        sigs = config.get("signatures", [])

        self.sig_matcher = SignatureMatcher(sigs)

        trw_cfg = rules.get("PORTSCAN-001", {}).get("params", {})
        self.trw = TRWState(**{k: trw_cfg[k] for k in ("alpha", "beta", "theta0", "theta1", "timeout_sec") if k in trw_cfg})

        ewma_cfg = rules.get("SYNFLOOD-001", {}).get("params", {})
        self.ewma = EWMAFloodDetector(
            lam=ewma_cfg.get("lambda", 0.2),
            k_sigma=ewma_cfg.get("k_sigma", 4),
            hard_ceiling=ewma_cfg.get("hard_ceiling_per_sec", 150),
        )

        bf_cfg = rules.get("BRUTEFORCE-001", {}).get("params", {})
        self.brute = BruteForceDetector(
            fail_alert=bf_cfg.get("fail_threshold_alert", 6),
            win_alert=bf_cfg.get("fail_window_alert_sec", 60),
            fail_block=bf_cfg.get("fail_threshold_block", 10),
            win_block=bf_cfg.get("fail_window_block_sec", 300),
        )

        exfil_cfg = rules.get("EXFIL-001", {}).get("params", {})
        self.exfil = ExfilDetector(
            multiplier=exfil_cfg.get("multiplier", 5),
            window_sec=exfil_cfg.get("window_sec", 300),
            floor_bytes=exfil_cfg.get("absolute_floor_bytes", 524_288_000),
        )

        self._rules = rules

    def process(self, flow: FlowRecord):
        self._now = flow.timestamp or time.time()

        # 1. Signature match
        match = self.sig_matcher.match(flow.payload)
        if match:
            sig_id, severity = match
            self._emit(Alert(
                alert_id=f"SIG-{sig_id}",
                category="signature",
                src_ip=flow.src_ip,
                detail=f"Signature hit: {sig_id}",
                severity=severity,
                action="alert_only",
            ))

        # 2. TRW port scan (may flag a source other than this packet's, via timeouts)
        for scanner_ip in self.trw.observe(flow):
            self._portscan_alert(scanner_ip)

        # 3. EWMA SYN flood
        if self.ewma.update(flow.is_syn):
            r = self._rules.get("SYNFLOOD-001", {})
            self._emit(Alert(
                alert_id="SYNFLOOD-001",
                category="dos",
                src_ip=flow.src_ip,
                detail="SYN rate exceeded EWMA baseline + 4σ",
                severity=r.get("severity", "high"),
                action=r.get("action", "block"),
            ))

        # 4. Brute force: each new connection (SYN) to an auth service is one login attempt
        service = AUTH_SERVICES.get(flow.dst_port)
        if service and flow.protocol == "TCP" and flow.is_syn:
            result = self.brute.record_attempt(flow.src_ip, service,
                                               (flow.dst_ip, flow.src_port), flow.timestamp)
            if result in ("alert", "block"):
                r = self._rules.get("BRUTEFORCE-001", {})
                self._emit(Alert(
                    alert_id="BRUTEFORCE-001",
                    category="auth",
                    src_ip=flow.src_ip,
                    detail=f"Brute-force detected on {service}",
                    severity=r.get("severity", "high"),
                    action=r.get("action", "block") if result == "block" else "alert_only",
                ))

        # 5. Exfiltration check
        if self.exfil.record(flow.src_ip, flow.length):
            r = self._rules.get("EXFIL-001", {})
            self._emit(Alert(
                alert_id="EXFIL-001",
                category="exfil",
                src_ip=flow.src_ip,
                detail="Outbound volume exceeds 5× 24h baseline",
                severity=r.get("severity", "medium"),
                action=r.get("action", "alert_only"),
            ))

    def flush(self):
        """Call when the packet source ends; unanswered connection attempts count as failures."""
        for scanner_ip in self.trw.flush():
            self._portscan_alert(scanner_ip)

    def _emit(self, alert: Alert):
        """Forward an alert unless the same rule fired for the same source and action recently."""
        now = self._now or time.time()
        key = (alert.alert_id, alert.src_ip, alert.action)
        last = self._last_alert.get(key)
        if last is not None and now - last < self.suppress_sec:
            return
        if len(self._last_alert) > 10_000:   # keep memory bounded on busy networks
            self._last_alert = {k: t for k, t in self._last_alert.items()
                                if now - t < self.suppress_sec}
        self._last_alert[key] = now
        self.callback(alert)

    def _portscan_alert(self, src_ip: str):
        r = self._rules.get("PORTSCAN-001", {})
        self._emit(Alert(
            alert_id="PORTSCAN-001",
            category="recon",
            src_ip=src_ip,
            detail="TRW likelihood ratio exceeded scanner threshold",
            severity=r.get("severity", "medium"),
            action=r.get("action", "rate_limit"),
        ))
