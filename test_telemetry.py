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
        with TestClient(dashboard.app) as client:
            status = client.get('/api/status').json()
            self.assertEqual(status['total_packets'], 1)
            self.assertEqual(status['total_alerts'], 0)
            self.assertTrue(status['dry_run'])
            self.assertGreaterEqual(status['uptime_seconds'], 0)
            for _ in range(2):
                with client.websocket_connect('/ws') as ws:
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
        with TestClient(dashboard.app) as client:
            self.assertEqual(client.post('/api/blocks', json={'ip':'bad'}).status_code, 422)
            self.assertEqual(client.post('/api/blocks', json={'ip':'127.0.0.1'}).status_code, 409)
            self.assertEqual(client.post('/api/whitelist', json={'ip':'10.0.0.1','note':'trusted'}).status_code, 200)
            self.assertEqual(client.post('/api/blocks', json={'ip':'10.0.0.1'}).status_code, 409)
            self.assertEqual(client.delete('/api/whitelist/10.0.0.1').status_code, 200)
            self.assertEqual(client.post('/api/blocks', json={'ip':'10.0.0.1'}).status_code, 200)
            self.assertEqual(len(client.get('/api/blocks').json()), 1)
            self.assertEqual(client.delete('/api/blocks/10.0.0.1').status_code, 200)
            self.assertEqual(client.get('/api/blocks').json(), [])

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
        with TestClient(dashboard.app) as client:
            self.assertEqual(client.get('/api/status').json()['status'], 'starting')

    def test_entry_point_pcap_wiring_and_cli_overrides(self):
        import run
        with patch('sys.argv', ['run.py', '--pcap', 'sample.pcap', '--dry-run', '--port', '8123']), \
             patch.object(CaptureEngine, 'start', CaptureEngine._run), \
             patch.object(run.uvicorn, 'run') as server:
            run.main()
        self.assertEqual(dashboard.capture_status()['total_packets'], len(rdpcap('sample.pcap')))
        self.assertGreater(database.get_alert_summary()['total_alerts'], 0)
        self.assertTrue(dashboard.capture_status()['dry_run'])
        self.assertEqual(server.call_args.kwargs['port'], 8123)


if __name__ == '__main__':
    unittest.main()
