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

Open http://localhost:8000 (or the port supplied with --port).

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

Manual block/remove actions retain the prototype's SQLite management behavior;
they do not add or remove nftables rules. Configured whitelist and protected host
addresses are rejected by the manual block API. Detection/response policies are unchanged.

Automated checks cover benign packets without alerts, alert/packet independence,
TCP/UDP/non-IP and SYN flags, rate decay, synthetic and sample PCAP replay, capture
errors, status before startup, API status, malformed/protected management requests,
WebSocket schema/reconnection, and frontend state/reconnect scheduling.

Real privileged live capture on Linux eth0 and nftables enforcement were not exercised
in the Windows development environment. Verify ordinary traffic increments Packets
without Alerts and that traffic/idle periods change rates on the target Linux host.
