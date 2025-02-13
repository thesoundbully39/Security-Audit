import os
import subprocess
import json
import xml.etree.ElementTree as ET
import csv
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
# 1) Host discovery (nmap -sn)
# 2) Detailed scan (nmap -sV -O)
# 3) Packet capture & analysis (tcpdump -> Zeek -> Suricata)
# 4) Parse Zeek conn.log and dns.log
# 5) Generate PDF report with Suricata, Shodan, & new Zeek data
#
# This version includes:
#  - Suricata alerts with Signature, Category, Severity, Src IP, Dest IP
#  - Zeek top talkers from conn.log
#  - Zeek top queried domains from dns.log
#  - JSON output (final_results.json) aggregating all data
############################################################


# === Step 1: Collect Network Data ===
def run_nmap_discovery(subnets):
    """Perform a host discovery scan and return a list of live hosts."""
    discovery_file = "host_discovery.gnmap"
    cmd = f"nmap --stats-every 5s -sn --host-timeout 30s -oG {discovery_file} {subnets}"
    print(f"Running discovery scan: {cmd}")
    subprocess.run(cmd, shell=True)

    discovered_ips = []
    if os.path.exists(discovery_file):
        with open(discovery_file, 'r') as f:
            for line in f:
                # Lines with 'Up' typically indicate a live host
                if "Up" in line and line.startswith("Host:"):
                    parts = line.split()
                    if len(parts) > 1:
                        ip_addr = parts[1]
                        discovered_ips.append(ip_addr)

    return discovered_ips

def run_nmap_details(live_hosts):
    """Perform a deeper Nmap scan on discovered hosts."""
    output_file = "nmap_scan.xml"
    if not live_hosts:
        print("No live hosts discovered. Creating an empty Nmap XML file.")
        with open(output_file, 'w') as f:
            f.write("<nmaprun></nmaprun>")
        return output_file

    ip_list = " ".join(live_hosts)
    cmd = f"nmap --stats-every 5s -T4 -sV -O -oX {output_file} {ip_list}"
    print(f"Running detailed scan: {cmd}")
    subprocess.run(cmd, shell=True)
    return output_file

def run_packet_capture(duration):
    """Capture packets for duration (minutes) and run Zeek."""
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
    """Check public IP exposure using Shodan CLI."""
    shodan_results = {}
    try:
        output = subprocess.run("shodan myip", shell=True, capture_output=True, text=True)
        public_ip = output.stdout.strip()
        if public_ip:
            shodan_scan = subprocess.run(f"shodan host {public_ip}", shell=True, capture_output=True, text=True)
            if shodan_scan.stdout:
                try:
                    shodan_results = json.loads(shodan_scan.stdout)
                except json.JSONDecodeError:
                    shodan_results = {"error": "Invalid JSON from Shodan"}
            else:
                shodan_results = {"error": "No data from Shodan"}
    except Exception as e:
        shodan_results = {"error": str(e)}
    return shodan_results


# === Step 2: Parse and Analyze Data ===
def parse_nmap_results(file):
    """Parse Nmap XML results for open ports, OS info, and hostnames."""
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

        hostname_elem = host.find("hostnames/hostname")
        hostname = hostname_elem.get("name", "Unknown") if hostname_elem is not None else "Unknown"

        ports = []
        for port in host.findall(".//port"):
            port_id = port.get("portid")
            service = port.find("service")
            service_name = service.get("name") if service is not None else "Unknown"
            ports.append(f"{port_id} ({service_name})")

        findings["Devices"].append({
            "IP": ip_address,
            "Hostname": hostname,
            "OS": os_name,
            "Ports": ports
        })
        findings["Open Ports"] += len(ports)

    return findings

def analyze_suricata_logs():
    """Parse Suricata's eve.json for alerts with signature, category, severity, etc."""
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
                        "dest_ip": event.get("dest_ip", "Unknown")
                    }
                    alerts.append(alert_info)
    return alerts


# === Zeek Parsing ===
def parse_zeek_conn_log(logfile="conn.log", top_n=5):
    """
    Parse Zeek's conn.log to identify top talkers (src IP).
    Return a list of tuples: [(ip, connections, total_bytes), ...]
    """
    if not os.path.exists(logfile):
        return []

    talkers = {}  # ip -> {"connections": 0, "bytes": 0}
    with open(logfile, "r") as f:
        reader = csv.reader(f, delimiter='\t')
        for row in reader:
            # Skip comments (#)
            if not row or row[0].startswith("#"):
                continue

            if len(row) < 11:
                continue

            src_ip = row[2]
            orig_bytes = row[9]
            resp_bytes = row[10]

            try:
                orig_bytes = int(orig_bytes)
            except ValueError:
                orig_bytes = 0

            try:
                resp_bytes = int(resp_bytes)
            except ValueError:
                resp_bytes = 0

            if src_ip not in talkers:
                talkers[src_ip] = {"connections": 0, "bytes": 0}
            talkers[src_ip]["connections"] += 1
            talkers[src_ip]["bytes"] += (orig_bytes + resp_bytes)

    sorted_talkers = sorted(talkers.items(), key=lambda x: x[1]["bytes"], reverse=True)
    results = []
    for ip, data in sorted_talkers[:top_n]:
        results.append((ip, data["connections"], data["bytes"]))
    return results

def parse_zeek_dns_log(logfile="dns.log", top_n=5):
    """
    Parse Zeek's dns.log to identify top queried domains.
    Return a list of tuples: [(domain, count), ...]
    """
    if not os.path.exists(logfile):
        return []

    domain_counts = {}
    with open(logfile, "r") as f:
        reader = csv.reader(f, delimiter='\t')
        for row in reader:
            if not row or row[0].startswith("#"):
                continue

            if len(row) < 10:
                continue

            query = row[9]
            if query not in domain_counts:
                domain_counts[query] = 0
            domain_counts[query] += 1

    sorted_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)
    return sorted_domains[:top_n]


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
    intro_text = (
        "This report provides an overview of devices discovered on your network, open ports, "
        "intrusion alerts captured by Suricata, Zeek traffic summaries, and Shodan results for external exposure."
    )
    flowables.append(Paragraph(intro_text, styles["Normal"]))
    flowables.append(Spacer(1, 0.25*inch))

    # Summary of Open Ports
    summary_text = f"<b>Total Open Ports Detected:</b> {findings['Open Ports']}"
    flowables.append(Paragraph(summary_text, styles["Normal"]))
    flowables.append(Spacer(1, 0.25*inch))

    # Device Table
    device_table_data = [["IP Address", "Hostname", "Operating System", "Open Ports"]]
    for device in findings["Devices"]:
        ip_para = Paragraph(device["IP"], styles["Normal"])
        hostname_para = Paragraph(device["Hostname"], styles["Normal"])
        os_para = Paragraph(device["OS"], styles["Normal"])
        ports_str = ", ".join(device["Ports"])
        ports_para = Paragraph(ports_str, styles["Normal"])

        device_table_data.append([ip_para, hostname_para, os_para, ports_para])

    device_table = Table(device_table_data, colWidths=[1.5*inch, 1.5*inch, 1.5*inch, 2.0*inch])
    device_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.grey),
        ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
        ('ALIGN',(0,0),(-1,-1),'LEFT'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('BOTTOMPADDING',(0,0),(-1,0),12),
        ('BACKGROUND',(0,1),(-1,-1),colors.beige),
        ('GRID', (0,0), (-1,-1), 1, colors.black),
        ('WORDWRAP', (0,0), (-1,-1), 'LTR'),
    ]))

    flowables.append(Paragraph("<b>Discovered Devices</b>", styles["Heading2"]))
    flowables.append(Spacer(1, 0.1*inch))
    flowables.append(device_table)
    flowables.append(Spacer(1, 0.25*inch))

    # ZEEK CONNECTION SUMMARY
    flowables.append(Paragraph("<b>Zeek Connection Summary (Top Talkers)</b>", styles["Heading2"]))
    flowables.append(Spacer(1, 0.1*inch))
    conn_results = parse_zeek_conn_log()
    if conn_results:
        conn_data = [["Source IP", "Connections", "Total Bytes"]]
        for item in conn_results:
            src_ip, conn_count, total_bytes = item
            conn_data.append([src_ip, str(conn_count), str(total_bytes)])
        conn_table = Table(conn_data, colWidths=[2.0*inch, 1.0*inch, 2.0*inch])
        conn_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.grey),
            ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING',(0,0),(-1,0),12),
            ('GRID', (0,0), (-1,-1), 1, colors.black),
            ('WORDWRAP', (0,0), (-1,-1), 'LTR'),
        ]))
        flowables.append(conn_table)
    else:
        flowables.append(Paragraph("No conn.log data or file not found.", styles["Normal"]))
    flowables.append(Spacer(1, 0.25*inch))

    # ZEEK DNS SUMMARY
    flowables.append(Paragraph("<b>Zeek DNS Summary (Top Queried Domains)</b>", styles["Heading2"]))
    flowables.append(Spacer(1, 0.1*inch))
    dns_results = parse_zeek_dns_log()
    if dns_results:
        dns_data = [["Domain", "Query Count"]]
        for domain, count in dns_results:
            dns_data.append([domain, str(count)])
        dns_table = Table(dns_data, colWidths=[4.0*inch, 1.5*inch])
        dns_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.grey),
            ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING',(0,0),(-1,0),12),
            ('GRID', (0,0), (-1,-1), 1, colors.black),
            ('WORDWRAP', (0,0), (-1,-1), 'LTR'),
        ]))
        flowables.append(dns_table)
    else:
        flowables.append(Paragraph("No dns.log data or file not found.", styles["Normal"]))
    flowables.append(Spacer(1, 0.25*inch))

    # SURICATA ALERTS
    flowables.append(Paragraph("<b>Intrusion Alerts (Suricata)</b>", styles["Heading2"]))
    flowables.append(Spacer(1, 0.1*inch))

    if alerts:
        alert_list_data = [["Signature", "Category", "Severity", "Source IP", "Destination IP"]]
        for alert in alerts:
            sig_para = Paragraph(alert["signature"], styles["Normal"])
            cat_para = Paragraph(alert["category"], styles["Normal"])
            sev_para = Paragraph(str(alert["severity"]), styles["Normal"])
            src_para = Paragraph(alert["src_ip"], styles["Normal"])
            dst_para = Paragraph(alert["dest_ip"], styles["Normal"])
            alert_list_data.append([sig_para, cat_para, sev_para, src_para, dst_para])

        alert_table = Table(alert_list_data, colWidths=[2.0*inch, 1.2*inch, 0.6*inch, 1.2*inch, 1.2*inch])
        alert_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.grey),
            ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING',(0,0),(-1,0),12),
            ('GRID', (0,0), (-1,-1), 1, colors.black),
            ('WORDWRAP', (0,0), (-1,-1), 'LTR'),
        ]))
        flowables.append(alert_table)
    else:
        flowables.append(Paragraph("No intrusion alerts detected.", styles["Normal"]))

    flowables.append(Spacer(1, 0.25*inch))

    # SHODAN RESULTS
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
            port_para = Paragraph(str(port), styles["Normal"])
            ports_data.append([port_para])
        if len(ports_data) > 1:
            port_table = Table(ports_data, colWidths=[5.5*inch])
            port_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.grey),
                ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('BOTTOMPADDING',(0,0),(-1,0),12),
                ('GRID', (0,0), (-1,-1), 1, colors.black),
                ('WORDWRAP', (0,0), (-1,-1), 'LTR'),
            ]))
            flowables.append(port_table)
        else:
            flowables.append(Paragraph("No open ports listed by Shodan.", styles["Normal"]))

        flowables.append(Spacer(1, 0.2*inch))

        # Vulnerabilities
        vuln_data = [["Vulnerabilities"]]
        for vuln in shodan_results.get("vulns", []):
            vuln_para = Paragraph(vuln, styles["Normal"])
            vuln_data.append([vuln_para])
        if len(vuln_data) > 1:
            vuln_table = Table(vuln_data, colWidths=[5.5*inch])
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.grey),
                ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('BOTTOMPADDING',(0,0),(-1,0),12),
                ('GRID', (0,0), (-1,-1), 1, colors.black),
                ('WORDWRAP', (0,0), (-1,-1), 'LTR'),
            ]))
            flowables.append(vuln_table)
        else:
            flowables.append(Paragraph("No vulnerabilities reported by Shodan.", styles["Normal"]))

    flowables.append(Spacer(1, 0.25*inch))

    # Build the PDF
    doc.build(flowables)


############################################################
# Main Execution
############################################################
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

    # 3) Run Steps
    live_hosts = run_nmap_discovery(subnets)
    nmap_output = run_nmap_details(live_hosts)

    findings = parse_nmap_results(nmap_output)
    run_packet_capture(duration)
    run_suricata_analysis()
    alerts = analyze_suricata_logs()
    shodan_results = run_shodan_lookup()

    # 4) Generate PDF (includes Zeek data)
    generate_pdf_report(findings, alerts, shodan_results)
    print("Report generated: security_audit_report.pdf")

    # 5) Create final JSON data (includes all findings)
    conn_results = parse_zeek_conn_log()
    dns_results = parse_zeek_dns_log()

    final_data = {
        "nmap": findings,
        "suricata": alerts,
        "shodan": shodan_results,
        "zeek": {
            "top_talkers": conn_results,
            "top_domains": dns_results
        }
    }

    # Write to final_results.json
    with open("final_results.json", "w") as jf:
        json.dump(final_data, jf, indent=2)

    print("Created final_results.json with consolidated data.")
