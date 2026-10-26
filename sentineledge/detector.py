"""
detector.py — All 5 detection algorithms.

  1. Aho-Corasick   — payload signature matching
  2. TRW            — port-scan detection (sequential hypothesis testing)
  3. EWMA           — SYN flood detection (dynamic threshold)
  4. Brute-force    — failed auth attempt counter
  5. Exfil          — abnormal outbound data volume
"""
import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network
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
    """Per-victim SYN-flood detector with a dynamic threshold (after SYNGuard, Rahouti et al., 2021).

    SYNs are counted per destination IP in fixed windows of packet time. A window
    is a flood once its count exceeds hard_ceiling, or — after warmup_windows of
    baseline — max(EWMA + k·σ, min_rate), both per second × window_sec. The check
    runs on every SYN, so floods are caught mid-window. The flood is blamed on each
    source that sent at least `share` of the window's SYNs; if none did (spoofed or
    distributed), the victim is reported instead. Flood windows stay out of the baseline.
    """

    def __init__(self, lam=0.2, k_sigma=4, hard_ceiling=150, window_sec=1.0,
                 min_rate=20, warmup_windows=5, share=0.2):
        self.lam = lam
        self.k_sigma = k_sigma
        self.hard_ceiling = hard_ceiling
        self.window_sec = window_sec
        self.min_rate = min_rate
        self.warmup_windows = warmup_windows
        self.share = share
        self._victims: dict[str, dict] = {}

    def update(self, flow: FlowRecord) -> List[tuple]:
        """Feed one packet; return [(ip, is_victim), ...] when a flood is first detected in a window."""
        if not flow.is_syn:
            return []
        now = flow.timestamp or time.time()
        v = self._victims.get(flow.dst_ip)
        if v is None:
            if len(self._victims) > 10_000:   # forget victims idle for 10 minutes
                self._victims = {ip: s for ip, s in self._victims.items() if now - s["start"] < 600}
            v = self._victims[flow.dst_ip] = {"start": now, "count": 0, "sources": defaultdict(int),
                                              "alerted": False, "ewma": 0.0, "ewmv": 0.0, "windows": 0}
        elif now - v["start"] >= self.window_sec:
            self._close_window(v, now)

        v["count"] += 1
        v["sources"][flow.src_ip] += 1
        if v["alerted"] or v["count"] <= self._limit_per_sec(v) * self.window_sec:
            return []
        v["alerted"] = True
        offenders = [ip for ip, n in v["sources"].items() if n >= self.share * v["count"]]
        return [(ip, False) for ip in offenders] or [(flow.dst_ip, True)]

    def _limit_per_sec(self, v: dict) -> float:
        if v["windows"] < self.warmup_windows:
            return self.hard_ceiling                 # still learning the baseline
        dynamic = v["ewma"] + self.k_sigma * math.sqrt(v["ewmv"])
        return min(self.hard_ceiling, max(dynamic, self.min_rate))

    def _close_window(self, v: dict, now: float):
        if not v["alerted"]:                         # flood windows would poison the baseline
            rate = v["count"] / (now - v["start"])
            if v["windows"] == 0:
                v["ewma"] = rate
            else:
                delta = rate - v["ewma"]
                v["ewma"] += self.lam * delta
                v["ewmv"] = (1 - self.lam) * (v["ewmv"] + self.lam * delta ** 2)
            v["windows"] += 1
        v.update(start=now, count=0, sources=defaultdict(int), alerted=False)


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
    """Flags internal hosts whose outbound volume spikes far above their own baseline.

    Only internal → external traffic counts (internal = internal_networks, default
    every private address range). Bytes are summed into per-minute buckets of packet
    time, kept for 24 h per host with running totals, so each packet costs O(1).
    The last window_sec is a spike when it exceeds both multiplier × the host's
    average per-window volume over the rest of that history and floor_bytes.
    Reports once per spike, re-arming when the volume drops back under the threshold.
    """

    BUCKET_SEC = 60
    HISTORY_SEC = 86_400

    def __init__(self, multiplier=5, window_sec=300, floor_bytes=524_288_000, internal_networks=None):
        self.multiplier = multiplier
        self.floor_bytes = floor_bytes
        self.window_slots = max(1, int(window_sec // self.BUCKET_SEC))
        self.history_slots = self.HISTORY_SEC // self.BUCKET_SEC
        self._nets = [ip_network(n) for n in internal_networks] if internal_networks else None
        self._internal_cache: dict[str, bool] = {}
        # {ip: {"first": slot, "recent"/"older": deque[[slot, bytes]], sums, "spiking"}}
        self._hosts: dict[str, dict] = {}

    def _internal(self, ip: str) -> bool:
        hit = self._internal_cache.get(ip)
        if hit is None:
            if len(self._internal_cache) > 100_000:
                self._internal_cache.clear()
            addr = ip_address(ip)
            hit = any(addr in n for n in self._nets) if self._nets else addr.is_private
            self._internal_cache[ip] = hit
        return hit

    def record(self, flow: FlowRecord) -> bool:
        """Feed one packet; True when its source starts an outbound spike."""
        if not self._internal(flow.src_ip) or self._internal(flow.dst_ip):
            return False
        slot = int((flow.timestamp or time.time()) // self.BUCKET_SEC)
        h = self._hosts.get(flow.src_ip)
        if h is None:
            if len(self._hosts) > 10_000:   # forget hosts silent for a whole history
                self._hosts = {ip: s for ip, s in self._hosts.items()
                               if s["recent"][-1][0] > slot - self.history_slots}
            h = self._hosts[flow.src_ip] = {"first": slot, "recent": deque(), "older": deque(),
                                            "recent_sum": 0, "older_sum": 0, "spiking": False}

        recent, older = h["recent"], h["older"]
        if recent and recent[-1][0] >= slot:      # same minute (or slightly out of order)
            recent[-1][1] += flow.length
        else:
            recent.append([slot, flow.length])
        h["recent_sum"] += flow.length
        while recent[0][0] <= slot - self.window_slots:      # slide minutes out of the window
            s, b = recent.popleft()
            h["recent_sum"] -= b
            older.append((s, b))
            h["older_sum"] += b
        while older and older[0][0] <= slot - self.history_slots:
            h["older_sum"] -= older.popleft()[1]

        # Average volume per window over the history before the current window
        span = (slot - self.window_slots) - max(h["first"], slot - self.history_slots) + 1
        baseline = h["older_sum"] * self.window_slots / span if span > 0 else 0.0
        spike = h["recent_sum"] > max(self.multiplier * baseline, self.floor_bytes)
        started, h["spiking"] = spike and not h["spiking"], spike
        return started


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
            window_sec=ewma_cfg.get("window_sec", 1.0),
            min_rate=ewma_cfg.get("min_rate_per_sec", 20),
            warmup_windows=ewma_cfg.get("warmup_windows", 5),
            share=ewma_cfg.get("source_share", 0.2),
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
            internal_networks=exfil_cfg.get("internal_networks"),
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

        # 3. EWMA SYN flood: per victim, blamed on the sources that sent most of it
        for ip, is_victim in self.ewma.update(flow):
            r = self._rules.get("SYNFLOOD-001", {})
            self._emit(Alert(
                alert_id="SYNFLOOD-001",
                category="dos",
                src_ip=ip,
                detail=(f"Distributed SYN flood against {ip}: no dominant source" if is_victim
                        else f"SYN flood against {flow.dst_ip} exceeded its threshold"),
                severity=r.get("severity", "high"),
                # Blocking the victim or a random spoofed source would not help
                action="alert_only" if is_victim else r.get("action", "block"),
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

        # 5. Exfiltration: internal host's outbound volume far above its own baseline
        if self.exfil.record(flow):
            r = self._rules.get("EXFIL-001", {})
            self._emit(Alert(
                alert_id="EXFIL-001",
                category="exfil",
                src_ip=flow.src_ip,
                detail=(f"Outbound volume over {self.exfil.window_slots} min exceeds "
                        f"{self.exfil.multiplier}x this host's 24h baseline"),
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
