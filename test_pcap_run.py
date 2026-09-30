import yaml
from sentineledge.database import init_db, get_alerts, get_blocks
from sentineledge.detector import Detector
from sentineledge.capture import CaptureEngine
from sentineledge.decision import handle_alert

init_db()
with open('config.yaml') as f:
    config = yaml.safe_load(f)

config['capture']['pcap_file'] = 'sample.pcap'

def on_alert(alert):
    handle_alert(alert, dry_run=True)

detector = Detector(config, on_alert)
capture = CaptureEngine(config, detector.process)
capture._run()

alerts = get_alerts()
print("\n--- TEST SUMMARY ---")
print(f"Total alerts recorded in DB: {len(alerts)}")
for a in alerts:
    sev = a['severity'].upper()
    aid = a['alert_id']
    ip = a['src_ip']
    det = a['detail']
    print(f"[{sev}] {aid} from {ip}: {det}")

blocks = get_blocks()
print(f"\nTotal blocked IPs: {len(blocks)}")
for b in blocks:
    print(f"Blocked {b['src_ip']} (Reason: {b['reason']})")
