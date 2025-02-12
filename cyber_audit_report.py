import os
import subprocess
import json
import xml.etree.ElementTree as ET
import pandas as pd
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import time
import sys

# === Step 1: Collect Network Data ===

def run_nmap_scan():
    output_file = "nmap_scan.xml"
    cmd = f"nmap -sV -O -oX {output_file} 192.168.1.0/24"
    subprocess.run(cmd, shell=True)
    return output_file

def run_zeek_capture(duration):
    print(f"Starting Zeek capture for {duration} minutes...")
    cmd = f"timeout {duration * 60} zeek -i eth0 local"
    os.system(cmd)
    print("Zeek capture complete.")

def run_suricata_analysis():
    os.system("suricata -r capture.pcap -l suricata_logs")

# === Step 2: Parse and Analyze Data ===

def parse_nmap_results(file):
    tree = ET.parse(file)
    root = tree.getroot()
    findings = {"Open Ports": 0, "Devices": []}
    
    for host in root.findall(".//host"):        
        ip_address = host.find("address").get("addr")
        os_info = host.find("os/osmatch")
        os_name = os_info.get("name") if os_info is not None else "Unknown"
        
        ports = []
        for port in host.findall(".//port"):            
            port_id = port.get("portid")
            service = port.find("service")
            service_name = service.get("name") if service is not None else "Unknown"
            ports.append(f"{port_id} ({service_name})")
        
        findings["Devices"].append({"IP": ip_address, "OS": os_name, "Ports": ports})
        findings["Open Ports"] += len(ports)
    
    return findings

def analyze_suricata_logs():
    alerts = []
    suricata_log_file = "suricata_logs/eve.json"
    if os.path.exists(suricata_log_file):
        with open(suricata_log_file, "r") as f:
            for line in f:
                event = json.loads(line)
                if event.get("event_type") == "alert":
                    alerts.append(event["alert"]["signature"])
    return alerts

# === Step 3: Generate PDF Report ===

def generate_pdf_report(findings, alerts, output_file="security_audit_report.pdf"):
    c = canvas.Canvas(output_file, pagesize=letter)
    c.setFont("Helvetica", 12)
    c.drawString(100, 750, "Home Network Security Audit Report")
    c.drawString(100, 730, "Findings:")
    y = 710
    c.drawString(120, y, f"Total Open Ports: {findings['Open Ports']}")
    y -= 20
    
    for device in findings["Devices"]:
        c.drawString(120, y, f"Device IP: {device['IP']}")
        y -= 15
        c.drawString(140, y, f"OS: {device['OS']}")
        y -= 15
        for port in device['Ports']:
            c.drawString(160, y, f"Open Port: {port}")
            y -= 15
        y -= 10  # Extra spacing between devices
    
    y -= 20
    c.drawString(100, y, "Intrusion Alerts:")
    y -= 20
    for alert in alerts:
        c.drawString(120, y, f"- {alert}")
        y -= 15
    
    c.save()

# === Run Full Process ===
if __name__ == "__main__":
    duration = int(sys.argv[1]) if len(sys.argv) > 1 else 60  # Default to 60 minutes if no argument
    
    nmap_output = run_nmap_scan()
    findings = parse_nmap_results(nmap_output)
    run_zeek_capture(duration)
    run_suricata_analysis()
    alerts = analyze_suricata_logs()
    generate_pdf_report(findings, alerts)
    
    print("Report generated: security_audit_report.pdf")
