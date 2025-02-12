import os
import subprocess
import json
import xml.etree.ElementTree as ET
import pandas as pd
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                Table, TableStyle)
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
import time
import sys

############################################################
# This script now accepts two command-line arguments:
# 1) duration (minutes) for packet capture (default: 60)
# 2) subnets to scan (default: "10.0.0.0/8 172.16.0.0/12 192.168.0.0/16")
# Example usage:
#   python3 cyber_audit_report.py 60 "192.168.1.0/24"
############################################################


# === Step 1: Collect Network Data ===

def run_nmap_scan(subnets):
    output_file = "nmap_scan.xml"
    cmd = f"nmap -sV -O -oX {output_file} {subnets}"
    subprocess.run(cmd, shell=True)
    return output_file


def run_packet_capture(duration):
    print(f"Starting packet capture for {duration} minutes...")
    os.system(f"timeout {duration * 60} tcpdump -i eth0 -w capture.pcap")
    print("Packet capture complete. Running Zeek analysis...")
    os.system("zeek -r capture.pcap")


def run_suricata_analysis():
    if os.path.exists("capture.pcap"):
        os.system("suricata -r capture.pcap -l suricata_logs")
    else:
        print("Error: capture.pcap not found. Suricata analysis skipped.")


def run_shodan_lookup():
    shodan_results = {}
    try:
        # Grab the external IP address from Shodan CLI
        output = subprocess.run("shodan myip", shell=True, capture_output=True, text=True)
        public_ip = output.stdout.strip()
        if public_ip:
            # Query Shodan for the external IP's details
            shodan_scan = subprocess.run(f"shodan host {public_ip}", shell=True, capture_output=True, text=True)
            shodan_results = json.loads(shodan_scan.stdout) if shodan_scan.stdout else {"error": "No data from Shodan"}
    except Exception as e:
        shodan_results = {"error": str(e)}
    return shodan_results


# === Step 2: Parse and Analyze Data ===

def parse_nmap_results(file):
    tree = ET.parse(file)
    root = tree.getroot()
    findings = {"Open Ports": 0, "Devices": []}

    for host in root.findall(".//host"):
        ip_element = host.find("address")
        if ip_element is None:
            continue
        ip_address = ip_element.get("addr", "Unknown")

        os_info = host.find("os/osmatch")
        os_name = os_info.get("name") if os_info is not None else "Unknown"

        ports = []
        for port in host.findall(".//port"):
            port_id = port.get("portid")
            service = port.find("service")
            service_name = service.get("name") if service is not None else "Unknown"
            ports.append(f"{port_id} ({service_name})")

        findings["Devices"].append({
            "IP": ip_address,
            "OS": os_name,
            "Ports": ports
        })
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


# === Step 3: Generate PDF Report with Enhanced Layout ===

def generate_pdf_report(findings, alerts, shodan_results, output_file="security_audit_report.pdf"):
    doc = SimpleDocTemplate(output_file, pagesize=letter)
    styles = getSampleStyleSheet()
    flowables = []

    # Title
    title = Paragraph("<strong>Home Network Security Audit Report</strong>", styles["Title"])
    flowables.append(title)
    flowables.append(Spacer(1, 0.25*inch))

    # Intro Paragraph
    intro_text = ("This report provides an overview of devices discovered on your network, open ports, "
                  "intrusion alerts captured by Suricata, and Shodan results for external exposure.")
    flowables.append(Paragraph(intro_text, styles["Normal"]))
    flowables.append(Spacer(1, 0.25*inch))

    # Summary of Open Ports
    summary_text = f"<b>Total Open Ports Detected:</b> {findings['Open Ports']}"
    flowables.append(Paragraph(summary_text, styles["Normal"]))
    flowables.append(Spacer(1, 0.25*inch))

    # Device Table
    device_table_data = [["IP Address", "Operating System", "Open Ports"]]
    for device in findings["Devices"]:
        ports_str = ", ".join(device["Ports"])
        device_table_data.append([
            device["IP"],
            device["OS"],
            ports_str
        ])

    device_table = Table(device_table_data, colWidths=[2.2*inch, 1.4*inch, 2.0*inch])
    device_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.grey),
        ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
        ('ALIGN',(0,0),(-1,-1),'LEFT'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('BOTTOMPADDING',(0,0),(-1,0),12),
        ('BACKGROUND',(0,1),(-1,-1),colors.beige),
        ('GRID', (0,0), (-1,-1), 1, colors.black),
    ]))

    flowables.append(Paragraph("<b>Discovered Devices</b>", styles["Heading2"]))
    flowables.append(Spacer(1, 0.1*inch))
    flowables.append(device_table)
    flowables.append(Spacer(1, 0.25*inch))

    # Suricata Alerts Section
    flowables.append(Paragraph("<b>Intrusion Alerts</b>", styles["Heading2"]))
    flowables.append(Spacer(1, 0.1*inch))

    if alerts:
        alert_list_data = [["Alert"]]
        for alert in alerts:
            alert_list_data.append([alert])
        alert_table = Table(alert_list_data, colWidths=[5.5*inch])
        alert_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.grey),
            ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING',(0,0),(-1,0),12),
            ('GRID', (0,0), (-1,-1), 1, colors.black),
        ]))
        flowables.append(alert_table)
    else:
        flowables.append(Paragraph("No intrusion alerts detected.", styles["Normal"]))

    flowables.append(Spacer(1, 0.25*inch))

    # Shodan Results Section
    flowables.append(Paragraph("<b>Shodan Internet Exposure</b>", styles["Heading2"]))
    flowables.append(Spacer(1, 0.1*inch))

    if "error" in shodan_results:
        flowables.append(Paragraph(f"Error: {shodan_results['error']}", styles["Normal"]))
    else:
        public_ip = shodan_results.get('ip_str', 'N/A')
        flowables.append(Paragraph(f"<b>Public IP:</b> {public_ip}", styles["Normal"]))
        flowables.append(Spacer(1, 0.1*inch))

        # Ports
        ports_data = [["Open Ports"]]
        for port in shodan_results.get("ports", []):
            ports_data.append([port])
        if len(ports_data) > 1:
            port_table = Table(ports_data, colWidths=[5.5*inch])
            port_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.grey),
                ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('BOTTOMPADDING',(0,0),(-1,0),12),
                ('GRID', (0,0), (-1,-1), 1, colors.black),
            ]))
            flowables.append(port_table)
        else:
            flowables.append(Paragraph("No open ports listed by Shodan.", styles["Normal"]))

        flowables.append(Spacer(1, 0.2*inch))

        # Vulnerabilities
        vuln_data = [["Vulnerabilities"]]
        for vuln in shodan_results.get("vulns", []):
            vuln_data.append([vuln])
        if len(vuln_data) > 1:
            vuln_table = Table(vuln_data, colWidths=[5.5*inch])
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.grey),
                ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('BOTTOMPADDING',(0,0),(-1,0),12),
                ('GRID', (0,0), (-1,-1), 1, colors.black),
            ]))
            flowables.append(vuln_table)
        else:
            flowables.append(Paragraph("No vulnerabilities reported by Shodan.", styles["Normal"]))

    flowables.append(Spacer(1, 0.25*inch))

    # Build the PDF
    doc.build(flowables)


# === Run Full Process ===
if __name__ == "__main__":
    # 1) Duration argument
    duration = 60  # default
    if len(sys.argv) > 1:
        try:
            duration = int(sys.argv[1])
        except ValueError:
            print("Invalid duration argument, using default 60 minutes.")

    # 2) Subnets argument
    subnets = "10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"  # default
    if len(sys.argv) > 2:
        subnets = sys.argv[2]

    nmap_output = run_nmap_scan(subnets)
    findings = parse_nmap_results(nmap_output)
    run_packet_capture(duration)
    run_suricata_analysis()
    alerts = analyze_suricata_logs()
    shodan_results = run_shodan_lookup()
    generate_pdf_report(findings, alerts, shodan_results)

    print("Report generated: security_audit_report.pdf")
