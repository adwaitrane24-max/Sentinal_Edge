# SentinelEdge

A small network intrusion detection system (NIDS) for a lab network. It watches
packets, spots common attacks, can block attackers with the Linux firewall
(nftables), and shows everything on a live web dashboard.

| Detects | How |
|---|---|
| Port scans | Threshold Random Walk over first-contact TCP connection attempts |
| SYN floods | Per-victim SYN rate against a learned (EWMA) baseline, blaming only the dominant sources |
| SSH / FTP / RDP brute force | New login connections per source in sliding windows |
| Data exfiltration | A host's outbound volume compared with its own 24 h baseline |
| Known-bad payloads | Keyword signatures (Aho-Corasick), e.g. `/etc/passwd`, `cmd.exe` |

It runs in **dry-run mode by default**: it logs what it *would* block and never touches the firewall.

## Quick start (Windows, macOS or Linux): replay the sample capture

Needs Python 3.10 or newer (tested with 3.13); Node.js only for the dashboard tests.

```bash
python -m venv .venv
# Windows:      .\.venv\Scripts\Activate.ps1
# macOS/Linux:  source .venv/bin/activate
python -m pip install -r requirements-test.txt

python run.py --pcap sample.pcap
```

Your browser opens the dashboard automatically. If it doesn't (or you closed it), open
the **Dashboard:** link printed in the terminal, for example
`http://127.0.0.1:8000/#token=...`. Use that exact link: plain `http://localhost:8000`
shows an "Access token needed" panel, where you can paste the link instead.
`sample.pcap` contains one of each attack, so you should see 5 alerts (port scan,
SYN flood, brute force, two signatures).

## Live capture and blocking (Linux only)

```bash
sudo .venv/bin/python run.py --iface eth0             # dry run: detect + log only
```

To enforce blocks, set `dry_run: false` in `config.yaml`. SentinelEdge then manages
its own nftables table, `inet sentineledge`. Automatic blocks lift after
`response.block_expiry_sec`; manual dashboard blocks last until you remove them.
Inspect it with `sudo nft list table inet sentineledge`. If nftables isn't available,
live mode refuses to start rather than running unprotected.

## The dashboard

- It listens on **127.0.0.1 only** by default. `--host 0.0.0.0` exposes it to the
  network on purpose (there is no HTTPS, so do this only on a trusted lab network).
- Every API call needs an access token. A new random one is generated each run and
  included in the printed link (old links stop working after a restart); set
  `SENTINELEDGE_TOKEN` to keep the same one.
- On a desktop session the link opens in your browser by default. `--no-browser` turns
  that off; it never happens when running as root or without a display.
- From the dashboard you can block or unblock IPs and manage the whitelist.

## Configuration (`config.yaml`)

| Section | What it controls |
|---|---|
| `capture` | Interface, PCAP file, `dry_run` |
| `alerts` | `suppress_sec` (drop repeats of the same alert), `retention_days` |
| `response` | `block_expiry_sec` for automatic blocks |
| `whitelist` | IPs that are never blocked |
| `rules` | One entry per detector: `enabled`, `params`, `severity`, `action` (`block`, `rate_limit` or `alert_only`) |
| `signatures` | Keyword patterns; each can be switched off with `enabled: false` |

Environment variables: `SENTINELEDGE_TOKEN` (dashboard token), `SENTINELEDGE_DB`
(database path; default `sentineledge.db` in the project folder).

## Running the tests

```bash
python -m unittest test_telemetry -v
node test_dashboard.cjs
```

GitHub Actions runs both on every push and pull request (`.github/workflows/tests.yml`).
See [TESTING.md](TESTING.md) for what is and isn't covered.

## Project layout

```
run.py                  entry point: wires everything together and starts the server
config.yaml             settings, rules and signatures
sentineledge/
  capture.py            reads packets (live or from a .pcap) and counts traffic
  detector.py           the five detectors
  decision.py           whitelist, cooldown, dry-run log or nftables response
  database.py           SQLite storage: alerts, blocks, whitelist
  dashboard.py          FastAPI web server, REST API and WebSocket
templates/index.html    the dashboard page
create_sample_pcap.py   regenerates sample.pcap
test_telemetry.py       Python tests
test_dashboard.cjs      dashboard JavaScript tests (no browser needed)
```

## Limitations

- Brute-force detection counts login *connections*; it cannot see whether a password
  was wrong (SSH and RDP are encrypted). Tools that legitimately open many SSH
  connections (e.g. Ansible) may need whitelisting.
- Floods from spoofed addresses are reported but can't usefully be blocked by IP;
  enable SYN cookies (`net.ipv4.tcp_syncookies`) on the protected host.
- The nftables integration and live capture have only been exercised with the
  firewall stubbed out, not against a real kernel in CI.
