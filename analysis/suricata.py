# your_project/analysis/suricata.py

import os
import json

def run_suricata_analysis():
    if os.path.exists("capture.pcap"):
        os.system("suricata -r capture.pcap -l suricata_logs")
    else:
        print("Error: capture.pcap not found. Suricata analysis skipped.")

def analyze_suricata_logs():
    alerts = []
    suricata_log_file = "suricata_logs/eve.json"
    if os.path.exists(suricata_log_file):
        with open(suricata_log_file, "r") as f:
            for line in f:
                event = json.loads(line)
                if event.get("event_type") == "alert":
                    alert_info = {
                        "signature": event["alert"].get("signature", "Unknown"),
                        "category": event["alert"].get("category", "N/A"),
                        "severity": event["alert"].get("severity", "N/A"),
                        "src_ip": event.get("src_ip", "Unknown"),
                        "dest_ip": event.get("dest_ip", "Unknown"),
                    }
                    alerts.append(alert_info)
    return alerts
