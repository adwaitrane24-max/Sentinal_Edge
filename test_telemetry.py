"""Regression checks using temporary databases and synthetic packets."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from scapy.all import IP, TCP, UDP, ARP, Raw, wrpcap, rdpcap
from sentineledge.capture import CaptureEngine
from sentineledge.detector import Detector
from sentineledge import database, dashboard
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
            p = IP(src='10.0.0.66', dst='10.0.0.1')/UDP()/Raw(load=b'x' * 200)
            p.time = 1000.0 + i * 0.001
            c._handle_packet(p)
        self.assertEqual([a.alert_id for a in alerts], ['EXFIL-001'])

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
             patch.dict('os.environ', {'SENTINELEDGE_TOKEN': 'env-token'}), \
             patch.object(CaptureEngine, 'start', CaptureEngine._run), \
             patch.object(run.uvicorn, 'run') as server:
            run.main()
        self.assertEqual(dashboard.capture_status()['total_packets'], len(rdpcap('sample.pcap')))
        self.assertGreater(database.get_alert_summary()['total_alerts'], 0)
        self.assertTrue(dashboard.capture_status()['dry_run'])
        self.assertEqual(server.call_args.kwargs['port'], 8123)
        self.assertEqual(server.call_args.kwargs['host'], '127.0.0.1')   # private by default
        self.assertTrue(dashboard.token_ok('env-token'))

    def test_entry_point_host_override_and_generated_token(self):
        import run
        with patch('sys.argv', ['run.py', '--pcap', 'sample.pcap', '--host', '0.0.0.0']), \
             patch.dict('os.environ', {}, clear=True), \
             patch.object(CaptureEngine, 'start', lambda self: None), \
             patch.object(run.uvicorn, 'run') as server:
            run.main()
        self.assertEqual(server.call_args.kwargs['host'], '0.0.0.0')
        self.assertFalse(dashboard.token_ok('test-token'))   # a fresh random token replaced it


if __name__ == '__main__':
    unittest.main()
