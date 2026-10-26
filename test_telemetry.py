"""Regression checks using temporary databases and synthetic packets."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from scapy.all import IP, TCP, UDP, ARP, Raw, wrpcap, rdpcap
from sentineledge.capture import CaptureEngine
from sentineledge.detector import Detector, Alert
from sentineledge import database, dashboard, decision
from sentineledge.decision import handle_alert, _cooldown


class TelemetryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_patch = patch.object(database, 'DB_PATH', str(Path(self.temp.name) / 'test.db'))
        self.db_patch.start()
        database.init_db()
        _cooldown.clear()
        self.alerts = []
        self.detector = Detector({'signatures': [{'id': 'test', 'pattern': 'attack', 'severity': 'high'}]}, self.on_alert)
        self.capture = CaptureEngine({'capture': {'interface': 'test0'}}, self.detector.process)
        dashboard.configure_capture(self.capture)
        dashboard.configure_auth('test-token')
        dashboard.configure_protected([])

    def client(self, token='test-token'):
        return TestClient(dashboard.app, headers={'Authorization': f'Bearer {token}'} if token else {})

    def tearDown(self):
        dashboard.configure_capture(None)
        self.db_patch.stop()
        self.temp.cleanup()

    def on_alert(self, alert):
        self.alerts.append(alert)
        handle_alert(alert, dry_run=True)

    def test_normal_packet_independent_of_alerts(self):
        self.capture._handle_packet(IP()/TCP(flags='SA'))
        self.assertEqual(self.capture.snapshot()['total_packets'], 1)
        self.assertEqual(database.get_alert_summary()['total_alerts'], 0)

    def test_alert_does_not_double_count_packet(self):
        self.capture._handle_packet(IP()/TCP(flags='SA')/Raw(load=b'attack'))
        self.assertEqual(self.capture.snapshot()['total_packets'], 1)
        self.assertEqual(database.get_alert_summary()['total_alerts'], 1)

    def test_protocols_flags_and_non_ip(self):
        for p in [IP()/TCP(flags='S'), IP()/TCP(flags='SA'), IP()/UDP(), ARP()]:
            self.capture._handle_packet(p)
        s = self.capture.snapshot()
        self.assertEqual([s[k] for k in ['total_packets','analysed_packets','tcp_packets','udp_packets','other_packets','tcp_syn_packets','tcp_syn_ack_packets']], [4,3,2,1,1,1,1])
        self.assertGreater(s['total_bytes'], 0)

    def test_rate_and_idle_decay(self):
        with patch('sentineledge.capture.time.monotonic', return_value=self.capture._interval_start + 1):
            self.capture._handle_packet(IP()/UDP())
            s = self.capture.snapshot()
            self.assertEqual(s['packets_per_second'], 1)
            self.assertGreater(s['bytes_per_second'], 0)
        with patch('sentineledge.capture.time.monotonic', return_value=self.capture._interval_start + 1):
            self.assertEqual(self.capture.snapshot()['packets_per_second'], 0)

    def test_pcap_replay_and_failure(self):
        p = Path(self.temp.name)/'test.pcap'
        wrpcap(str(p), [IP()/TCP(flags='SA'), IP()/UDP()/Raw(load=b'attack')])
        c = CaptureEngine({'capture': {'pcap_file': str(p)}}, self.detector.process)
        c._run()
        self.assertEqual(c.snapshot()['total_packets'], 2)
        self.assertEqual(c.snapshot()['status'], 'completed')
        self.assertEqual(c.snapshot()['rate_basis'], 'replay_processing')
        self.assertEqual(len(self.alerts), 1)
        c = CaptureEngine({'capture': {'pcap_file': str(p)+'missing'}}, lambda f: None)
        c._run()
        self.assertEqual(c.snapshot()['status'], 'error')

    def test_sample_pcap_preserves_detection(self):
        c = CaptureEngine({'capture': {'pcap_file': 'sample.pcap'}}, self.detector.process)
        c._run()
        self.assertEqual(c.snapshot()['total_packets'], len(rdpcap('sample.pcap')))
        self.assertGreater(len(self.alerts), 0)

    def test_status_websocket_reconnect_and_alert_schema(self):
        self.capture._handle_packet(IP()/UDP())
        with self.client() as client:
            status = client.get('/api/status').json()
            self.assertEqual(status['total_packets'], 1)
            self.assertEqual(status['total_alerts'], 0)
            self.assertTrue(status['dry_run'])
            self.assertGreaterEqual(status['uptime_seconds'], 0)
            for _ in range(2):
                with client.websocket_connect('/ws?token=test-token') as ws:
                    m = ws.receive_json()
                    self.assertEqual(m['type'], 'packet_stats')
                    self.assertIn('bytes_per_second', m['data'])
                    payload = dict(timestamp='2026-01-01T00:00:00+00:00',alert_id='TEST',category='test',src_ip='10.0.0.1',detail='test',severity='high',action='alert_only')
                    dashboard.push_alert_from_thread(payload)
                    while True:
                        m = ws.receive_json()
                        if m['type'] == 'alert':
                            break
                    self.assertEqual(m, {'type': 'alert', 'data': payload})
            self.assertEqual(client.get('/').status_code, 200)

    def test_management_validation_and_protected_addresses(self):
        with self.client() as client:
            self.assertEqual(client.post('/api/blocks', json={'ip':'bad'}).status_code, 422)
            self.assertEqual(client.post('/api/blocks', json={'ip':'127.0.0.1'}).status_code, 409)
            self.assertEqual(client.post('/api/whitelist', json={'ip':'10.0.0.1','note':'trusted'}).status_code, 200)
            self.assertEqual(client.post('/api/blocks', json={'ip':'10.0.0.1'}).status_code, 409)
            self.assertEqual(client.delete('/api/whitelist/10.0.0.1').status_code, 200)
            self.assertEqual(client.post('/api/blocks', json={'ip':'10.0.0.1'}).status_code, 200)
            self.assertEqual(len(client.get('/api/blocks').json()), 1)
            self.assertEqual(client.delete('/api/blocks/10.0.0.1').status_code, 200)
            self.assertEqual(client.get('/api/blocks').json(), [])

    def portscan_ips(self):
        return [a.src_ip for a in self.alerts if a.alert_id == 'PORTSCAN-001']

    def feed(self, *pkts, start=1000.0):
        for i, p in enumerate(pkts):
            p.time = start + i * 0.001
            self.capture._handle_packet(p)

    def test_portscan_ignores_normal_client_traffic(self):
        c, s = '10.0.0.5', '10.0.0.1'
        self.feed(IP(src=c, dst=s)/TCP(sport=40000, dport=443, flags='S'),
                  IP(src=s, dst=c)/TCP(sport=443, dport=40000, flags='SA'),
                  *[IP(src=c, dst=s)/TCP(sport=40000, dport=443, flags='PA') for _ in range(20)])
        self.detector.flush()
        self.assertEqual(self.portscan_ips(), [])

    def test_portscan_detects_rst_answered_scan_once(self):
        a, s = '10.0.0.66', '10.0.0.1'
        pkts = []
        for port in range(20, 40):
            pkts += [IP(src=a, dst=s)/TCP(sport=50000, dport=port, flags='S'),
                     IP(src=s, dst=a)/TCP(sport=port, dport=50000, flags='RA')]
        self.feed(*pkts)
        self.assertEqual(self.portscan_ips(), [a])

    def test_portscan_unanswered_attempts_fail_after_timeout(self):
        a, s = '10.0.0.66', '10.0.0.1'
        self.feed(*[IP(src=a, dst=s)/TCP(dport=p, flags='S') for p in range(1, 6)])
        self.assertEqual(self.portscan_ips(), [])   # replies may still arrive
        self.feed(IP(src='10.0.0.9', dst=s)/UDP(), start=1010.0)
        self.assertEqual(self.portscan_ips(), [a])

    def test_sample_pcap_flags_only_the_port_scanner(self):
        c = CaptureEngine({'capture': {'pcap_file': 'sample.pcap'}}, self.detector.process, self.detector.flush)
        c._run()
        # SYN flood (.44) and SSH brute force (.101) hit a single port, so they are not scans
        self.assertEqual(self.portscan_ips(), ['192.168.1.77'])

    def bruteforce_alerts(self):
        return [(a.src_ip, a.action) for a in self.alerts if a.alert_id == 'BRUTEFORCE-001']

    def test_bruteforce_ignores_normal_ssh_session(self):
        c, s = '10.0.0.5', '10.0.0.1'
        self.feed(IP(src=c, dst=s)/TCP(sport=40000, dport=22, flags='S'),
                  IP(src=s, dst=c)/TCP(sport=22, dport=40000, flags='SA'),
                  *[IP(src=c, dst=s)/TCP(sport=40000, dport=22, flags='PA') for _ in range(50)])
        self.assertEqual(self.bruteforce_alerts(), [])

    def test_bruteforce_ignores_syn_retransmits(self):
        c, s = '10.0.0.5', '10.0.0.1'
        self.feed(*[IP(src=c, dst=s)/TCP(sport=40000, dport=22, flags='S') for _ in range(12)])
        self.assertEqual(self.bruteforce_alerts(), [])

    def test_bruteforce_alerts_once_per_level(self):
        a, s = '10.0.0.66', '10.0.0.1'
        self.feed(*[IP(src=a, dst=s)/TCP(sport=50000 + i, dport=22, flags='S') for i in range(15)])
        self.assertEqual(self.bruteforce_alerts(), [(a, 'alert_only'), (a, 'block')])

    def test_sample_pcap_bruteforce_alerts_once(self):
        c = CaptureEngine({'capture': {'pcap_file': 'sample.pcap'}}, self.detector.process, self.detector.flush)
        c._run()
        self.assertEqual(self.bruteforce_alerts(), [('192.168.1.101', 'alert_only')])

    def test_repeated_signature_alerts_are_suppressed(self):
        a, b, s = '10.0.0.66', '10.0.0.67', '10.0.0.1'
        self.feed(*[IP(src=a, dst=s)/UDP()/Raw(load=b'attack') for _ in range(20)],
                  IP(src=b, dst=s)/UDP()/Raw(load=b'attack'))
        self.assertEqual([x.src_ip for x in self.alerts], [a, b])   # other sources still alert
        self.feed(IP(src=a, dst=s)/UDP()/Raw(load=b'attack'), start=1061.0)
        self.assertEqual([x.src_ip for x in self.alerts], [a, b, a])   # window expired

    def test_suppression_can_be_disabled(self):
        alerts = []
        d = Detector({'alerts': {'suppress_sec': 0},
                      'signatures': [{'id': 'test', 'pattern': 'attack', 'severity': 'high'}]}, alerts.append)
        c = CaptureEngine({'capture': {'interface': 'test0'}}, d.process)
        for _ in range(5):
            c._handle_packet(IP()/UDP()/Raw(load=b'attack'))
        self.assertEqual(len(alerts), 5)

    def test_exfil_does_not_alert_on_every_packet(self):
        alerts = []
        d = Detector({'rules': [{'id': 'EXFIL-001', 'enabled': True,
                                 'params': {'absolute_floor_bytes': 1000}}]}, alerts.append)
        c = CaptureEngine({'capture': {'interface': 'test0'}}, d.process)
        for i in range(50):
            p = IP(src='10.0.0.66', dst='8.8.8.8')/UDP()/Raw(load=b'x' * 200)
            p.time = 1000.0 + i * 0.001
            c._handle_packet(p)
        self.assertEqual([a.alert_id for a in alerts], ['EXFIL-001'])

    # ── Exfiltration (fix #7) ──
    def exfil_run(self, schedule, params=None):
        """schedule: [(minute, src, dst, packets)], 1000-byte payloads; returns alerting sources."""
        alerts = []
        d = Detector({'rules': [{'id': 'EXFIL-001', 'enabled': True, 'params': {
            'window_sec': 60, 'multiplier': 5, 'absolute_floor_bytes': 2000, **(params or {})}}]}, alerts.append)
        c = CaptureEngine({'capture': {'interface': 'test0'}}, d.process)
        for minute, src, dst, n in schedule:
            for i in range(n):
                p = IP(src=src, dst=dst)/UDP()/Raw(load=b'x' * 1000)
                p.time = 60_000.0 + minute * 60 + i * 0.01
                c._handle_packet(p)
        return [a.src_ip for a in alerts if a.alert_id == 'EXFIL-001']

    def test_exfil_flags_spike_above_host_baseline_once(self):
        quiet = [(m, '10.0.0.5', '8.8.8.8', 1) for m in range(10)]      # ~1 KB/min for 10 min
        self.assertEqual(self.exfil_run(quiet + [(10, '10.0.0.5', '8.8.8.8', 10)]), ['10.0.0.5'])

    def test_exfil_steady_traffic_alerts_only_before_a_baseline_exists(self):
        # ~2 KB/min every minute is above the 1 KB floor, but only the very first minute
        # (no history yet, so only the floor applies) counts; after that it's normal
        steady = [(m, '10.0.0.5', '8.8.8.8', 2) for m in range(20)]
        self.assertEqual(self.exfil_run(steady, {'absolute_floor_bytes': 1000}), ['10.0.0.5'])

    def test_exfil_counts_only_internal_to_external(self):
        self.assertEqual(self.exfil_run([(0, '10.0.0.5', '10.0.0.9', 50),      # LAN copy
                                         (0, '8.8.8.8', '10.0.0.5', 50)]), [])  # download
        # With a narrower internal range, another private network counts as outside
        self.assertEqual(self.exfil_run([(0, '10.0.0.5', '10.0.1.9', 50)],
                                        {'internal_networks': ['10.0.0.0/24']}), ['10.0.0.5'])

    def synflood_alerts(self):
        return [(a.src_ip, a.action) for a in self.alerts if a.alert_id == 'SYNFLOOD-001']

    def syns(self, sources, dst='10.0.0.1', start=1000.0, spacing=0.001):
        for i, src in enumerate(sources):
            p = IP(src=src, dst=dst)/TCP(sport=20000 + i % 40000, dport=80, flags='S')
            p.time = start + i * spacing
            self.capture._handle_packet(p)

    def test_sample_pcap_synflood_blames_the_flooder(self):
        c = CaptureEngine({'capture': {'pcap_file': 'sample.pcap'}}, self.detector.process, self.detector.flush)
        c._run()
        self.assertEqual(self.synflood_alerts(), [('192.168.1.44', 'block')])

    def test_synflood_does_not_blame_bystanders(self):
        attacker, bystander = '10.0.0.66', '10.0.0.5'
        self.syns([bystander] + [attacker] * 200 + [bystander])
        self.assertEqual(self.synflood_alerts(), [(attacker, 'block')])

    def test_synflood_ignores_busy_but_normal_traffic(self):
        # 20 clients x 5 connections inside one second stays under the 150/s ceiling
        self.syns([f'10.0.1.{i}' for i in range(20)] * 5)
        self.assertEqual(self.synflood_alerts(), [])

    def test_distributed_synflood_reports_victim_without_blocking(self):
        self.syns([f'10.{i // 250}.{i % 250}.9' for i in range(300)])
        self.assertEqual(self.synflood_alerts(), [('10.0.0.1', 'alert_only')])

    def test_synflood_dynamic_threshold_after_baseline(self):
        # 10 quiet seconds at 10 SYN/s teach the baseline; then 60 SYNs in one second
        self.syns([f'10.0.1.{i % 50}' for i in range(100)], spacing=0.1)
        self.assertEqual(self.synflood_alerts(), [])
        self.syns(['10.0.0.66'] * 60, start=1010.0, spacing=0.01)
        self.assertEqual(self.synflood_alerts(), [('10.0.0.66', 'block')])   # 60 < 150 ceiling

    # ── Housekeeping (fix #10) ──
    def test_old_alerts_are_pruned(self):
        handle_alert(self.alert(action='alert_only'), dry_run=True)
        with database._conn() as c:
            c.execute("UPDATE alerts SET timestamp='2000-01-01T00:00:00+00:00'")
        handle_alert(self.alert(action='alert_only'), dry_run=True)
        self.assertEqual(database.prune_alerts(0), 0)               # 0 = keep everything
        self.assertEqual(database.prune_alerts(30), 1)
        self.assertEqual(len(database.get_alerts()), 1)

    def test_protected_addresses_come_from_config(self):
        dashboard.configure_protected(['10.9.9.9'])
        with self.client() as client:
            self.assertEqual(client.post('/api/blocks', json={'ip': '10.9.9.9'}).status_code, 409)
            self.assertEqual(client.post('/api/blocks', json={'ip': '127.0.0.1'}).status_code, 409)
            # No longer hard-coded: only protected when configured
            self.assertEqual(client.post('/api/blocks', json={'ip': '192.168.56.1'}).status_code, 200)

    def test_database_lives_in_project_folder_unless_overridden(self):
        import os, subprocess, sys
        code = 'from sentineledge import database; print(database.DB_PATH)'
        env = {k: v for k, v in os.environ.items() if k != 'SENTINELEDGE_DB'}
        env['PYTHONPATH'] = str(Path.cwd())
        run = lambda e: subprocess.run([sys.executable, '-c', code], cwd=self.temp.name, env=e,
                                       capture_output=True, text=True, check=True).stdout.strip()
        self.assertEqual(Path(run(env)), Path.cwd().resolve() / 'sentineledge.db')   # not the cwd
        self.assertEqual(run({**env, 'SENTINELEDGE_DB': 'custom.db'}), 'custom.db')

    def test_alerts_are_logged(self):
        with self.assertLogs('sentineledge.decision', 'WARNING') as logs:
            handle_alert(self.alert(), dry_run=True)
        self.assertTrue(any('[ALERT] TEST-001' in line for line in logs.output))

    # ── Alert push (fix #9) ──
    def test_dashboard_receives_the_alert_that_was_stored(self):
        import run
        run._config = {'capture': {'dry_run': True}}
        real_insert = decision.insert_alert

        def insert_then_race(**kw):
            row = real_insert(**kw)
            real_insert(**{**kw, 'alert_id': 'OTHER-THREAD'})   # another alert lands right after
            return row
        with patch('sentineledge.decision.insert_alert', side_effect=insert_then_race), \
             patch.object(run, 'push_alert_from_thread') as push:
            run.alert_callback(self.alert())
        [[pushed], _] = push.call_args
        self.assertEqual(pushed['alert_id'], 'TEST-001')        # old code pushed OTHER-THREAD
        self.assertEqual(pushed, next(a for a in database.get_alerts() if a['id'] == pushed['id']))

    # ── Rule switches (fix #8) ──
    def sample_alert_ids(self, config):
        alerts = []
        d = Detector(config, alerts.append)
        CaptureEngine({'capture': {'pcap_file': 'sample.pcap'}}, d.process, d.flush)._run()
        return sorted({a.alert_id for a in alerts})

    def test_disabled_rules_do_not_run(self):
        import yaml
        with open('config.yaml', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        self.assertEqual(self.sample_alert_ids(config),
                         ['BRUTEFORCE-001', 'PORTSCAN-001', 'SIG-SIG-001', 'SIG-SIG-002', 'SYNFLOOD-001'])
        for rule in config['rules']:
            rule['enabled'] = False
        config['signatures'][0]['enabled'] = False                     # SIG-001
        self.assertEqual(self.sample_alert_ids(config), ['SIG-SIG-002'])

    # ── Firewall response (fix #6); nft is replaced by a recorder ──
    def nft_calls(self, run):
        return [c.args[0][1:] if c.args[0][1] != '-f' else ['-f', c.kwargs['input']] for c in run.call_args_list]

    def alert(self, ip='10.0.0.66', action='block'):
        return Alert(alert_id='TEST-001', category='test', src_ip=ip, detail='t', severity='high', action=action)

    def test_automatic_blocks_expire(self):
        handle_alert(self.alert(), dry_run=True)
        [block] = database.get_blocks()
        self.assertIsNotNone(block['expires_at'])             # was always NULL (never expired)
        database.add_block('10.0.0.66', 'old', expires_at='2000-01-01T00:00:00+00:00')
        self.assertEqual(database.get_blocks(), [])
        self.assertFalse(database.is_blocked('10.0.0.66'))   # can be blocked again later

    def test_live_block_and_rate_limit_use_expiring_set_elements(self):
        with patch('sentineledge.decision.subprocess.run') as run:
            handle_alert(self.alert('10.0.0.66', 'block'), dry_run=False)
            handle_alert(self.alert('10.0.0.67', 'rate_limit'), dry_run=False)
        self.assertEqual(self.nft_calls(run), [
            ['add', 'element', 'inet', 'sentineledge', 'blocked', '{ 10.0.0.66 timeout 600s }'],
            ['add', 'element', 'inet', 'sentineledge', 'ratelimited', '{ 10.0.0.67 timeout 600s }']])
        self.assertEqual({b['src_ip'] for b in database.get_blocks()}, {'10.0.0.66', '10.0.0.67'})

    def test_live_block_not_recorded_when_firewall_fails(self):
        with patch('sentineledge.decision.subprocess.run', side_effect=FileNotFoundError('nft')):
            handle_alert(self.alert(), dry_run=False)
        self.assertEqual(database.get_blocks(), [])

    def test_dashboard_unblock_and_whitelist_remove_firewall_entry(self):
        dashboard.configure_capture(self.capture, dry_run=False)
        with patch('sentineledge.decision.subprocess.run') as run, self.client() as client:
            self.assertEqual(client.post('/api/blocks', json={'ip': '10.0.0.66'}).status_code, 200)
            self.assertEqual(client.delete('/api/blocks/10.0.0.66').status_code, 200)
            database.add_block('10.0.0.67', 'TEST-001')
            self.assertEqual(client.post('/api/whitelist', json={'ip': '10.0.0.67'}).status_code, 200)
            self.assertEqual(client.delete('/api/blocks/not-an-ip').status_code, 422)
        self.assertEqual(self.nft_calls(run), [
            ['add', 'element', 'inet', 'sentineledge', 'blocked', '{ 10.0.0.66 }'],     # manual: no expiry
            ['delete', 'element', 'inet', 'sentineledge', 'blocked', '{ 10.0.0.66 }'],
            ['delete', 'element', 'inet', 'sentineledge', 'ratelimited', '{ 10.0.0.66 }'],
            ['delete', 'element', 'inet', 'sentineledge', 'blocked', '{ 10.0.0.67 }'],
            ['delete', 'element', 'inet', 'sentineledge', 'ratelimited', '{ 10.0.0.67 }']])
        self.assertEqual(database.get_blocks(), [])

    def test_setup_firewall_replaces_table_and_restores_active_blocks(self):
        future = '2999-01-01T00:00:00+00:00'
        blocks = [{'src_ip': '10.0.0.66', 'reason': 'SYNFLOOD-001', 'expires_at': future},
                  {'src_ip': '10.0.0.67', 'reason': 'rate-limit:PORTSCAN-001', 'expires_at': None},
                  {'src_ip': '10.0.0.68', 'reason': 'old', 'expires_at': '2000-01-01T00:00:00+00:00'},
                  {'src_ip': '10.0.0.69', 'reason': '[DRY-RUN] SYNFLOOD-001', 'expires_at': future},
                  {'src_ip': '1.2.3.4 } ; flush ruleset', 'reason': 'manual', 'expires_at': None}]
        with patch('sentineledge.decision.subprocess.run') as run:
            decision.setup_firewall(blocks)
        [[flag, script]] = self.nft_calls(run)
        self.assertEqual(flag, '-f')
        self.assertTrue(script.startswith('add table inet sentineledge\ndelete table inet sentineledge\n'))
        self.assertRegex(script, r'add element inet sentineledge blocked \{ 10\.0\.0\.66 timeout \d+s \}')
        self.assertIn('add element inet sentineledge ratelimited { 10.0.0.67 }', script)
        for skipped in ('10.0.0.68', '10.0.0.69', 'flush ruleset'):   # expired, dry-run, invalid
            self.assertNotIn(skipped, script)
        with patch('sentineledge.decision.subprocess.run', side_effect=FileNotFoundError('nft')), \
             self.assertRaises(RuntimeError):
            decision.setup_firewall([])

    def test_live_mode_refuses_to_start_without_nftables(self):
        import run
        cfg = Path(self.temp.name) / 'live.yaml'
        cfg.write_text('capture:\n  pcap_file: sample.pcap\n  dry_run: false\n')
        with patch('sys.argv', ['run.py', '--config', str(cfg)]), patch('logging.basicConfig'), \
             patch('sentineledge.decision.subprocess.run', side_effect=FileNotFoundError('nft')), \
             patch.object(run.uvicorn, 'run') as server, self.assertRaises(SystemExit):
            run.main()
        server.assert_not_called()

    def test_api_rejects_missing_or_wrong_token(self):
        for token in (None, 'wrong-token'):
            with self.client(token) as client:
                for method, path, body in [('get', '/api/alerts', None), ('get', '/api/status', None),
                                           ('post', '/api/whitelist', {'ip': '10.0.0.66'}),
                                           ('delete', '/api/blocks/10.0.0.66', None)]:
                    r = client.request(method, path, json=body)
                    self.assertEqual(r.status_code, 401, (token, method, path))
        self.assertEqual(database.get_whitelist(), [])   # the rejected write did nothing
        with self.client(None) as client:
            r = client.get('/api/alerts', headers={'Authorization': 'Basic test-token'})
            self.assertEqual(r.status_code, 401)        # only the Bearer scheme is accepted
            self.assertEqual(client.get('/').status_code, 200)   # page itself holds no data

    def test_websocket_rejects_missing_or_wrong_token(self):
        from starlette.websockets import WebSocketDisconnect
        with self.client(None) as client:
            for url in ('/ws', '/ws?token=wrong-token'):
                with self.assertRaises(WebSocketDisconnect):
                    with client.websocket_connect(url) as ws:
                        ws.receive_json()

    def test_empty_token_is_refused(self):
        with self.assertRaises(ValueError):
            dashboard.configure_auth('')

    def test_missing_config(self):
        from run import load_config
        with self.assertRaises(SystemExit):
            load_config(str(Path(self.temp.name)/'missing.yaml'))

    def test_live_capture_callback_and_failure_status(self):
        def sniff_packets(**kwargs):
            self.assertEqual(kwargs['iface'], 'test0')
            kwargs['prn'](IP()/UDP())
        with patch('sentineledge.capture.sniff', side_effect=sniff_packets):
            self.capture._run()
        self.assertEqual(self.capture.snapshot()['total_packets'], 1)
        self.assertEqual(len(self.alerts), 0)
        with patch('sentineledge.capture.sniff', side_effect=OSError('interface unavailable')):
            self.capture._run()
        self.assertEqual(self.capture.snapshot()['status'], 'error')

    def test_status_before_capture_is_configured(self):
        dashboard.configure_capture(None)
        with self.client() as client:
            self.assertEqual(client.get('/api/status').json()['status'], 'starting')

    def test_entry_point_pcap_wiring_and_cli_overrides(self):
        import run
        with patch('sys.argv', ['run.py', '--pcap', 'sample.pcap', '--dry-run', '--port', '8123']), \
             patch('logging.basicConfig'), \
             patch.dict('os.environ', {'SENTINELEDGE_TOKEN': 'env-token'}), \
             patch.object(CaptureEngine, 'start', CaptureEngine._run), \
             patch.object(run, 'can_open_browser', return_value=True), \
             patch('run.threading.Timer') as timer, \
             patch.object(run.uvicorn, 'run') as server:
            run.main()
        self.assertEqual(dashboard.capture_status()['total_packets'], len(rdpcap('sample.pcap')))
        self.assertGreater(database.get_alert_summary()['total_alerts'], 0)
        self.assertTrue(dashboard.capture_status()['dry_run'])
        self.assertEqual(server.call_args.kwargs['port'], 8123)
        self.assertEqual(server.call_args.kwargs['host'], '127.0.0.1')   # private by default
        self.assertTrue(dashboard.token_ok('env-token'))
        # The browser is opened on the exact link, token included, so nobody has to type it
        _delay, opener, [link] = timer.call_args.args
        self.assertEqual((opener, link), (run.webbrowser.open, 'http://127.0.0.1:8123/#token=env-token'))

    def test_entry_point_host_override_and_generated_token(self):
        import run
        with patch('sys.argv', ['run.py', '--pcap', 'sample.pcap', '--host', '0.0.0.0', '--no-browser']), \
             patch('logging.basicConfig'), \
             patch.dict('os.environ', {}, clear=True), \
             patch.object(CaptureEngine, 'start', lambda self: None), \
             patch.object(run, 'can_open_browser', return_value=True), \
             patch('run.threading.Timer') as timer, \
             patch.object(run.uvicorn, 'run') as server:
            run.main()
        self.assertEqual(server.call_args.kwargs['host'], '0.0.0.0')
        self.assertFalse(dashboard.token_ok('test-token'))   # a fresh random token replaced it
        timer.assert_not_called()                             # --no-browser

    def test_browser_never_opened_as_root_or_without_display(self):
        import run
        with patch.object(run.sys, 'platform', 'linux'):
            for euid, env, expected in [(0, {'DISPLAY': ':0'}, False), (1000, {}, False),
                                        (1000, {'DISPLAY': ':0'}, True), (1000, {'WAYLAND_DISPLAY': 'w'}, True)]:
                with patch.object(run.os, 'geteuid', return_value=euid, create=True), \
                     patch.dict('os.environ', env, clear=True):
                    self.assertEqual(run.can_open_browser(), expected, (euid, env))


if __name__ == '__main__':
    unittest.main()
