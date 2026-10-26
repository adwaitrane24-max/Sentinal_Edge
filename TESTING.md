# SentinelEdge telemetry verification

Run commands from the directory containing run.py and config.yaml.

Install application and test dependencies:

    python -m pip install -r requirements-test.txt

Run the Python regression suite and dependency-free JavaScript state tests:

    python -m unittest test_telemetry -v
    node test_dashboard.cjs

Live capture (Linux, capture privileges required):

    sudo python run.py --iface eth0
    sudo python run.py --iface eth0 --dry-run

Offline replay:

    python run.py --pcap sample.pcap

The "Dashboard:" link printed at startup, e.g. http://127.0.0.1:8000/#token=...
(the port follows --port), opens in the browser automatically on a desktop session
(not as root or without a display; --no-browser disables it). Without a valid token
the page shows an "Access token needed" panel that accepts the pasted link. The dashboard API and
WebSocket require that access token; a new random one is generated each run unless
SENTINELEDGE_TOKEN is set. The server listens on 127.0.0.1 (this machine only) by
default; pass --host 0.0.0.0 to expose it to the network deliberately.

Packet totals are per capture session; alert totals/high severity are stored SQLite
history. Protocol totals include non-IP packets as OTHER when applicable. Analysed
packets are those converted to an IPv4 FlowRecord. Backend interval rates use
monotonic wall-clock time. PCAP replay runs at its original unpaced speed, so its
rates are labeled replay processing throughput, not recorded network bandwidth.
Rates return to zero after the replay finishes; cumulative totals remain visible.

GET /api/status and packet_stats WebSocket messages share CaptureEngine.snapshot().
An asyncio lifespan task broadcasts snapshots once per second. The callback only
updates counters under a short lock and invokes the existing detector pipeline.
There are no per-packet database writes or per-packet WebSocket messages for telemetry.
Alert events retain type=alert and include the persisted ID for reconnect deduplication.

Live mode (dry_run: false) owns a dedicated nftables table, `inet sentineledge`,
replaced atomically at startup (startup aborts if nft is unavailable). Blocked and
rate-limited IPs are elements of its `blocked` / `ratelimited` sets: automatic ones
expire after response.block_expiry_sec (default 600 s), manual dashboard blocks last
until removed, and removing a block or whitelisting an IP deletes the element.
Unexpired live blocks are restored on restart; dry-run blocks are never enforced.
Inspect with `sudo nft list table inet sentineledge`. Configured whitelist and
protected host addresses are rejected by the manual block API.

Automated checks cover benign packets without alerts, alert/packet independence,
TCP/UDP/non-IP and SYN flags, rate decay, synthetic and sample PCAP replay, capture
errors, status before startup, API status, malformed/protected management requests,
WebSocket schema/reconnection, and frontend state/reconnect scheduling.

Real privileged live capture on Linux eth0 and nftables enforcement were not exercised
in the Windows development environment. Verify ordinary traffic increments Packets
without Alerts and that traffic/idle periods change rates on the target Linux host.
