"""
evaluate.py — measure SentinelEdge's detection quality on labelled scenarios.

Each scenario is a short, synthetic packet trace with a known answer: either
normal traffic (must raise no alert) or an attack (must raise the right kind of
alert for the right IP, and nothing else). Every scenario runs through a fresh
Detector exactly as run.py wires it, using config.yaml.

  python evaluate.py                    # this code; writes docs/evaluation.md
  python evaluate.py --baseline ddb182e # also run an older commit and compare
  python evaluate.py --code DIR         # run the code checked out in DIR
  python evaluate.py --json             # machine-readable results only
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
T0 = 1_700_000_000.0            # scenario start time (packet timestamps)
SERVER = "10.0.0.1"
EXTERNAL = "93.184.216.34"      # an Internet address
BIG = b"x" * 1400               # payload of a full-size data packet

# The exfiltration floor is scaled down from 500 MB so its scenarios stay small.
CONFIG_OVERRIDES = {"EXFIL-001": {"absolute_floor_bytes": 1_000_000}}


@dataclass
class Scenario:
    name: str
    kind: str                    # "normal" or "attack"
    packets: list
    expect: set = field(default_factory=set)   # {(category, ip)} that must be alerted
    what: str = ""


class Traffic:
    """Builds a timestamped packet trace."""

    def __init__(self):
        self.items = []

    def tcp(self, t, src, dst, sport, dport, flags, payload=b""):
        from scapy.all import IP, TCP, Raw
        p = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
        if payload:
            p = p / Raw(load=payload)
        p.time = t
        self.items.append(p)
        return self

    def connection(self, t, client, server, sport, dport, exchanges=0,
                   request=b"GET / HTTP/1.1\r\n\r\n", response=b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * 500):
        """A complete TCP connection: handshake, request/response exchanges, close."""
        self.tcp(t, client, server, sport, dport, "S")
        self.tcp(t + 0.001, server, client, dport, sport, "SA")
        self.tcp(t + 0.002, client, server, sport, dport, "A")
        for i in range(exchanges):
            ti = t + 0.003 + i * 0.01
            self.tcp(ti, client, server, sport, dport, "PA", request)
            self.tcp(ti + 0.001, server, client, dport, sport, "PA", response)
        end = t + 0.004 + exchanges * 0.01
        self.tcp(end, client, server, sport, dport, "FA")
        self.tcp(end + 0.001, server, client, dport, sport, "FA")
        return self

    def packets(self):
        return sorted(self.items, key=lambda p: float(p.time))


def build_scenarios():
    s = []

    def add(name, kind, traffic, expect=(), what=""):
        s.append(Scenario(name, kind, traffic.packets(), set(expect), what))

    # ── Normal traffic: any alert is a false alarm ──
    t = Traffic()
    for c in range(20):
        t.connection(T0 + c * 0.5, f"10.0.1.{c + 10}", SERVER, 40000 + c, 443, exchanges=10)
    add("Web browsing", "normal", t, what="20 clients, 10 requests each")

    add("Long SSH session", "normal",
        Traffic().connection(T0, "10.0.1.5", SERVER, 41000, 22, exchanges=200),
        what="one admin, 200 exchanges")

    t = Traffic()
    for i in range(120):
        t.connection(T0 + i * 0.008, f"10.0.2.{i % 30 + 10}", SERVER, 42000 + i, 80, exchanges=1)
    add("Busy web server", "normal", t, what="120 connections in one second")

    t = Traffic().connection(T0, "10.0.1.7", "10.0.1.8", 43000, 445)
    for i in range(1100):
        t.tcp(T0 + 0.01 + i * 0.001, "10.0.1.7", "10.0.1.8", 43000, 445, "PA", BIG)
    add("LAN file copy", "normal", t, what="1.5 MB between two internal hosts")

    t = Traffic().connection(T0, "10.0.1.9", EXTERNAL, 44000, 443)
    for i in range(1100):
        t.tcp(T0 + 0.01 + i * 0.001, EXTERNAL, "10.0.1.9", 443, 44000, "PA", BIG)
    add("Large download", "normal", t, what="1.5 MB from the Internet")

    # ── Attacks: the expected alert must appear, and nothing else ──
    scanner = "10.0.0.66"
    t = Traffic()
    for i, port in enumerate(range(1, 101)):
        t.tcp(T0 + i * 0.002, scanner, SERVER, 50000, port, "S")
        t.tcp(T0 + i * 0.002 + 0.001, SERVER, scanner, port, 50000, "RA")
    add("Port scan (closed ports)", "attack", t, {("recon", scanner)}, "100 ports, answered with RST")

    t = Traffic()
    for i, port in enumerate(range(1, 101)):
        t.tcp(T0 + i * 0.002, scanner, SERVER, 50000, port, "S")
    add("Port scan (filtered)", "attack", t, {("recon", scanner)}, "100 ports, no replies")

    t = Traffic().connection(T0 + 0.2, "10.0.1.5", SERVER, 45000, 80, exchanges=2)
    for i in range(400):
        t.tcp(T0 + i * 0.001, scanner, SERVER, 20000 + i, 80, "S")
    add("SYN flood", "attack", t, {("dos", scanner)}, "400 SYN/s, one innocent user connects meanwhile")

    t = Traffic()
    for i in range(300):
        t.tcp(T0 + i * 0.001, f"172.16.{i // 250}.{i % 250 + 1}", SERVER, 30000 + i, 80, "S")
    add("Distributed SYN flood", "attack", t, {("dos", SERVER)},
        "300 sources x 1 SYN; expect a warning naming the victim")

    for attempts in (6, 12):
        t = Traffic()
        for i in range(attempts):
            t.connection(T0 + i * 5, "10.0.0.77", SERVER, 46000 + i, 22, exchanges=3,
                         request=b"x" * 64, response=b"x" * 64)
        add(f"SSH brute force ({attempts} logins)", "attack", t, {("auth", "10.0.0.77")},
            f"{attempts} connections, 5 s apart")

    t = Traffic()
    for minute in range(10):                       # baseline: ~28 KB per minute
        for i in range(20):
            t.tcp(T0 + minute * 60 + i, "10.0.0.20", EXTERNAL, 47000, 443, "PA", BIG)
    for i in range(860):                           # spike: 1.2 MB in one minute
        t.tcp(T0 + 600 + i * 0.05, "10.0.0.20", EXTERNAL, 47000, 443, "PA", BIG)
    add("Data exfiltration", "attack", t, {("exfil", "10.0.0.20")}, "10 quiet minutes, then a 1.2 MB upload")

    payloads = {"10.0.0.81": b"GET /../../etc/passwd HTTP/1.1\r\n\r\n",
                "10.0.0.82": b"GET /run?c=cmd.exe HTTP/1.1\r\n\r\n",
                "10.0.0.83": b"GET /q?id=1 UNION SELECT * FROM users HTTP/1.1\r\n\r\n",
                "10.0.0.84": b"GET / HTTP/1.1\r\nUser-Agent: nmap scripting engine\r\n\r\n"}
    t = Traffic()
    for i, (ip, req) in enumerate(payloads.items()):
        t.connection(T0 + i, ip, SERVER, 48000 + i, 80, exchanges=1, request=req)
    add("Malicious web requests", "attack", t, {("signature", ip) for ip in payloads},
        "/etc/passwd, cmd.exe, SQL injection, nmap user agent")

    t = Traffic()
    for c in range(20):
        t.connection(T0 + c * 0.5, f"10.0.1.{c + 10}", SERVER, 40000 + c, 443, exchanges=10)
    for i, port in enumerate(range(1, 51)):
        t.tcp(T0 + 1 + i * 0.1, scanner, SERVER, 50000, port, "S")
        t.tcp(T0 + 1 + i * 0.1 + 0.001, SERVER, scanner, port, 50000, "RA")
    add("Port scan hidden in browsing", "attack", t, {("recon", scanner)}, "50 ports among 20 normal clients")

    t = Traffic()
    for u in range(5):
        t.connection(T0 + u, f"10.0.1.{u + 30}", SERVER, 49000 + u, 22, exchanges=50)
    for i in range(12):
        t.connection(T0 + i * 5, "10.0.0.77", SERVER, 46000 + i, 22, exchanges=3,
                     request=b"x" * 64, response=b"x" * 64)
    add("Brute force among SSH users", "attack", t, {("auth", "10.0.0.77")}, "5 normal admins + 12 attacker logins")
    return s


def load_config():
    import yaml
    with open(HERE / "config.yaml", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    for rule in config.get("rules", []):
        rule.setdefault("params", {}).update(CONFIG_OVERRIDES.get(rule["id"], {}))
    return config


def run_scenarios():
    """Run every scenario through a fresh detector; return one result dict per scenario."""
    from sentineledge.capture import CaptureEngine
    from sentineledge.detector import Detector

    config, results = load_config(), []
    for sc in build_scenarios():
        alerts = []
        detector = Detector(config, alerts.append)
        engine = CaptureEngine({"capture": {"interface": "eval0"}}, detector.process)
        for pkt in sc.packets:
            engine._handle_packet(pkt)
        if hasattr(detector, "flush"):      # older code has no end-of-capture step
            detector.flush()
        found = {(a.category, a.src_ip) for a in alerts}
        missing, unexpected = sc.expect - found, found - sc.expect
        results.append({"name": sc.name, "kind": sc.kind, "what": sc.what, "packets": len(sc.packets),
                        "alerts_raised": len(alerts), "expected": sorted(sc.expect),
                        "missing": sorted(missing), "false_alarms": sorted(unexpected),
                        "passed": not missing and not unexpected})
    return results


def summary(results):
    attacks = [r for r in results if r["kind"] == "attack"]
    normal = [r for r in results if r["kind"] == "normal"]
    return {"attacks_detected": sum(not r["missing"] for r in attacks), "attacks": len(attacks),
            "normal_clean": sum(not r["false_alarms"] for r in normal), "normal": len(normal),
            "false_alarms": sum(len(r["false_alarms"]) for r in results),
            "alerts_raised": sum(r["alerts_raised"] for r in results),
            "passed": sum(r["passed"] for r in results), "scenarios": len(results)}


def run_other_code(code_dir):
    out = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--code", str(code_dir), "--json"],
                         capture_output=True, text=True, encoding="utf-8", check=True)
    return json.loads(out.stdout)


def run_commit(ref):
    """Check out `ref` into a temporary git worktree, evaluate it, then remove the worktree."""
    tmp = Path(tempfile.mkdtemp(prefix="sentineledge-eval-")) / "code"
    subprocess.run(["git", "-C", str(HERE), "worktree", "add", "--detach", str(tmp), ref],
                   check=True, capture_output=True)
    try:
        return run_other_code(tmp)
    finally:
        subprocess.run(["git", "-C", str(HERE), "worktree", "remove", "--force", str(tmp)], capture_output=True)


# ── Reporting ────────────────────────────────────────────────────────────────

def n_alerts(n):
    return f"{n} alert" + ("" if n == 1 else "s")


def fmt(items):
    return ", ".join(f"{c} {ip}" for c, ip in items) or "-"


def verdict(r, emoji):
    ok, bad = ("✅", "❌") if emoji else ("PASS", "FAIL")
    if r["passed"]:
        return f"{ok} " + ("detected" if r["kind"] == "attack" else "no alerts")
    parts = (["missed"] if r["missing"] else []) + (["false alarm"] if r["false_alarms"] else [])
    return f"{bad} " + " + ".join(parts)


def print_table(results, title):
    s = summary(results)
    print(f"\n{title}")
    print(f"{'Scenario':<32}{'Result':<26}{'Alerts':>7}  False alarms")
    for r in results:
        print(f"{r['name']:<32}{verdict(r, False):<26}{r['alerts_raised']:>7}  {fmt(r['false_alarms'])}")
    print(f"Attacks detected {s['attacks_detected']}/{s['attacks']} | normal scenarios without alarms "
          f"{s['normal_clean']}/{s['normal']} | false alarms {s['false_alarms']} | alerts raised {s['alerts_raised']}")


def markdown(results, baseline=None, baseline_ref=None):
    s = summary(results)
    lines = ["# Detection evaluation", "",
             "Generated by `python evaluate.py" + (f" --baseline {baseline_ref}" if baseline_ref else "") + "`. "
             "Each scenario is a labelled synthetic packet trace run through a fresh detector with `config.yaml` "
             "(exfiltration floor scaled to 1 MB). An attack passes when the expected alert type is raised for the "
             "right IP and nothing else; normal traffic passes when no alert is raised.", ""]
    if baseline:
        b = summary(baseline)
        lines += ["## Summary", "", f"| Measure | Original (`{baseline_ref}`) | Current |", "|---|---|---|",
                  f"| Attacks detected | {b['attacks_detected']} / {b['attacks']} | {s['attacks_detected']} / {s['attacks']} |",
                  f"| Normal scenarios without false alarms | {b['normal_clean']} / {b['normal']} | {s['normal_clean']} / {s['normal']} |",
                  f"| False alarms (wrong type or wrong IP) | {b['false_alarms']} | {s['false_alarms']} |",
                  f"| Alerts raised in total | {b['alerts_raised']} | {s['alerts_raised']} |",
                  f"| Scenarios passed | {b['passed']} / {b['scenarios']} | {s['passed']} / {s['scenarios']} |", "",
                  "## Per scenario", "", "| Scenario | Traffic | Original | Current |", "|---|---|---|---|"]
        for r, o in zip(results, baseline):
            lines.append(f"| {r['name']} | {r['what']} | {verdict(o, True)} ({n_alerts(o['alerts_raised'])}) "
                         f"| {verdict(r, True)} ({n_alerts(r['alerts_raised'])}) |")
        lines += ["", "*False alarm* = an alert of the wrong type or for the wrong IP (e.g. a normal client labelled "
                  "a port scanner). Code that times its checks with the computer clock instead of packet "
                  "timestamps can give slightly different flood results from run to run."]
    else:
        lines += [f"**{s['attacks_detected']}/{s['attacks']} attacks detected, "
                  f"{s['normal_clean']}/{s['normal']} normal scenarios without alarms, "
                  f"{s['false_alarms']} false alarms.**", "",
                  "| Scenario | Traffic | Result | Alerts raised |", "|---|---|---|---|"]
        for r in results:
            lines.append(f"| {r['name']} | {r['what']} | {verdict(r, True)} | {r['alerts_raised']} |")
    return "\n".join(lines) + "\n"


def main():
    p = argparse.ArgumentParser(description="Evaluate SentinelEdge detection on labelled scenarios")
    p.add_argument("--code", help="evaluate the SentinelEdge code in this folder instead")
    p.add_argument("--baseline", metavar="GIT_REF", help="also evaluate this commit and compare (e.g. ddb182e)")
    p.add_argument("--json", action="store_true", help="print results as JSON only")
    p.add_argument("--no-write", action="store_true", help="don't write docs/evaluation.md")
    args = p.parse_args()

    if args.code:   # import that checkout's sentineledge instead of ours
        sys.path.insert(0, str(Path(args.code).resolve()))
    import logging
    logging.disable(logging.CRITICAL)      # alerts are counted, not printed
    results = run_scenarios()
    if args.json:
        print(json.dumps(results))
        return

    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    baseline = run_commit(args.baseline) if args.baseline else None
    if baseline:
        print_table(baseline, f"Original code ({args.baseline})")
    print_table(results, "Current code" if not args.code else f"Code in {args.code}")
    if not args.code and not args.no_write:
        out = HERE / "docs" / "evaluation.md"
        out.parent.mkdir(exist_ok=True)
        out.write_text(markdown(results, baseline, args.baseline), encoding="utf-8")
        print(f"\nWrote {out.relative_to(HERE)}")
    sys.exit(0 if all(r["passed"] for r in results) else 1)


if __name__ == "__main__":
    main()
