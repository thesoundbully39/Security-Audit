# file: reporting/pdf_builder.py

import json
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle)
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch

# Import your IoT detection or other analysis modules if needed for direct calls here
# Typically, you'll just pass data from 'audit.py' or call certain analysis functions if you prefer.
# For example:
# from analysis.iot_detection import assess_iot_risk, find_iot_devices, correlate_iot_alerts

def generate_pdf_report(
    findings,           # dict from parse_nmap_results
    alerts,             # list from analyze_suricata_logs
    shodan_results,     # dict from run_shodan_lookup
    conn_results=None,  # list of (ip, conn_count, bytes) from parse_zeek_conn_log
    dns_results=None,   # list of (domain, count) from parse_zeek_dns_log
    iot_devices=None,   # optional list of iot devices from find_iot_devices
    output_file="security_audit_report.pdf"
):
    """
    Build the PDF. 
    'findings' typically has:
        { 'Open Ports': <int>, 'Devices': [ { 'IP':..., 'Ports':...}, ... ] }
    'alerts': Suricata alert list
    'shodan_results': from run_shodan_lookup
    'conn_results' and 'dns_results': from parse_zeek_conn_log / parse_zeek_dns_log
    'iot_devices': from find_iot_devices (optional if you prefer to do it here)
    """

    doc = SimpleDocTemplate(output_file, pagesize=letter)
    styles = getSampleStyleSheet()
    flowables = []

    # --- Title ---
    title = Paragraph("<strong>Home Network Security Audit Report</strong>", styles["Title"])
    flowables.append(title)
    flowables.append(Spacer(1, 0.25*inch))

    # --- Intro Paragraph ---
    intro_text = (
        "This report provides an overview of devices discovered on your network, open ports, "
        "intrusion alerts captured by Suricata, Zeek traffic summaries, and Shodan results. "
        "Potential IoT devices have been flagged, along with any high-risk ports."
    )
    flowables.append(Paragraph(intro_text, styles["Normal"]))
    flowables.append(Spacer(1, 0.25*inch))

    # --- Open Ports Summary ---
    summary_text = f"<b>Total Open Ports Detected:</b> {findings.get('Open Ports', 0)}"
    flowables.append(Paragraph(summary_text, styles["Normal"]))
    flowables.append(Spacer(1, 0.25*inch))

    # --- Discovered Devices Table ---
    device_table_data = [["IP", "MAC", "Vendor", "Hostname", "OS", "Open Ports"]]
    for device in findings.get("Devices", []):
        device_table_data.append([
            Paragraph(device.get("IP", "Unknown"), styles["Normal"]),
            Paragraph(device.get("MAC", "Unknown"), styles["Normal"]),
            Paragraph(device.get("Vendor", "Unknown"), styles["Normal"]),
            Paragraph(device.get("Hostname", "Unknown"), styles["Normal"]),
            Paragraph(device.get("OS", "Unknown"), styles["Normal"]),
            Paragraph(", ".join(device.get("Ports", [])), styles["Normal"]),
        ])

    device_table = Table(device_table_data, colWidths=[1.1*inch, 1.1*inch, 1.2*inch, 1.4*inch, 1.2*inch, 2.2*inch])
    device_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.grey),
        ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
        ('ALIGN',(0,0),(-1,-1),'LEFT'),
        ('VALIGN',(0,0),(-1,-1),'TOP'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('BOTTOMPADDING',(0,0),(-1,0),12),
        ('BACKGROUND',(0,1),(-1,-1),colors.beige),
        ('GRID', (0,0), (-1,-1), 1, colors.black),
        ('WORDWRAP', (0,0), (-1,-1), 'CJK'),  # Ensures text wraps
    ]))

    flowables.append(Paragraph("<b>Discovered Devices</b>", styles["Heading2"]))
    flowables.append(Spacer(1, 0.1*inch))
    flowables.append(device_table)
    flowables.append(Spacer(1, 0.25*inch))

    # --- IoT Devices (optional) ---
    if iot_devices is not None:
        flowables.append(Paragraph("<b>Potential IoT Devices</b>", styles["Heading2"]))
        flowables.append(Spacer(1, 0.1*inch))
        if iot_devices:
            iot_table_data = [["IP", "Vendor", "OS", "Risk", "Open Ports"]]
            for dev in iot_devices:
                # Suppose you also pass a "risk_level" or call assess_iot_risk(dev) here
                risk_level = "LOW"  # or dev["risk"], etc.
                iot_table_data.append([
                    dev.get("IP", "Unknown"),
                    dev.get("Vendor", "Unknown"),
                    dev.get("OS", "Unknown"),
                    risk_level,
                    ", ".join(dev.get("Ports", []))
                ])
            iot_table = Table(iot_table_data, colWidths=[1.2*inch, 1.5*inch, 1.3*inch, 0.8*inch, 2.0*inch])
            iot_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.grey),
                ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
                ('ALIGN',(0,0),(-1,-1),'LEFT'),
                ('VALIGN',(0,0),(-1,-1),'TOP'),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('BOTTOMPADDING',(0,0),(-1,0),12),
                ('GRID', (0,0), (-1,-1), 1, colors.black),
                ('WORDWRAP', (0,0), (-1,-1), 'CJK'),
            ]))
            flowables.append(iot_table)
        else:
            flowables.append(Paragraph("No potential IoT devices identified.", styles["Normal"]))
        flowables.append(Spacer(1, 0.25*inch))

    # --- Zeek Connection Summary ---
    if conn_results is not None:
        flowables.append(Paragraph("<b>Zeek Connection Summary (Top Talkers)</b>", styles["Heading2"]))
        flowables.append(Spacer(1, 0.1*inch))
        if conn_results:
            conn_data = [["Source IP", "Connections", "Total Bytes"]]
            for (src_ip, conn_count, total_bytes) in conn_results:
                conn_data.append([src_ip, str(conn_count), str(total_bytes)])
            conn_table = Table(conn_data, colWidths=[2.0*inch, 1.0*inch, 2.0*inch])
            conn_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.grey),
                ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
                ('ALIGN',(0,0),(-1,-1),'LEFT'),
                ('VALIGN',(0,0),(-1,-1),'TOP'),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('BOTTOMPADDING',(0,0),(-1,0),12),
                ('GRID', (0,0), (-1,-1), 1, colors.black),
                ('WORDWRAP', (0,0), (-1,-1), 'CJK'),
            ]))
            flowables.append(conn_table)
        else:
            flowables.append(Paragraph("No conn.log data or file not found.", styles["Normal"]))
        flowables.append(Spacer(1, 0.25*inch))

    # --- Zeek DNS Summary ---
    if dns_results is not None:
        flowables.append(Paragraph("<b>Zeek DNS Summary (Top Queried Domains)</b>", styles["Heading2"]))
        flowables.append(Spacer(1, 0.1*inch))
        if dns_results:
            dns_data = [["Domain", "Query Count"]]
            for (domain, count) in dns_results:
                dns_data.append([domain, str(count)])
            dns_table = Table(dns_data, colWidths=[4.0*inch, 1.5*inch])
            dns_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.grey),
                ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
                ('ALIGN',(0,0),(-1,-1),'LEFT'),
                ('VALIGN',(0,0),(-1,-1),'TOP'),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('BOTTOMPADDING',(0,0),(-1,0),12),
                ('GRID', (0,0), (-1,-1), 1, colors.black),
                ('WORDWRAP', (0,0), (-1,-1), 'CJK'),
            ]))
            flowables.append(dns_table)
        else:
            flowables.append(Paragraph("No dns.log data or file not found.", styles["Normal"]))
        flowables.append(Spacer(1, 0.25*inch))

    # --- Suricata Alerts ---
    flowables.append(Paragraph("<b>Intrusion Alerts (Suricata)</b>", styles["Heading2"]))
    flowables.append(Spacer(1, 0.1*inch))
    if alerts:
        alert_list_data = [["Signature", "Category", "Severity", "Source IP", "Destination IP"]]
        # Optionally add "IoT?" if you correlated them
        # alert_list_data = [["Signature", "Category", "Severity", "Source IP", "Destination IP", "IoT?"]]
        for alert in alerts:
            sig_para = Paragraph(alert.get("signature", "Unknown"), styles["Normal"])
            cat_para = Paragraph(alert.get("category", "N/A"), styles["Normal"])
            sev_para = Paragraph(str(alert.get("severity", "N/A")), styles["Normal"])
            src_para = Paragraph(alert.get("src_ip", "Unknown"), styles["Normal"])
            dst_para = Paragraph(alert.get("dest_ip", "Unknown"), styles["Normal"])
            # iot_flag = "Yes" if alert.get("iot_related") else "No"
            # alert_list_data.append([sig_para, cat_para, sev_para, src_para, dst_para, iot_flag])
            alert_list_data.append([sig_para, cat_para, sev_para, src_para, dst_para])

        # If you added "IoT?" above, adjust colWidths for 6 columns
        alert_table = Table(alert_list_data, colWidths=[2.0*inch, 1.2*inch, 0.6*inch, 1.2*inch, 1.2*inch])
        alert_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.grey),
            ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
            ('ALIGN',(0,0),(-1,-1),'LEFT'),
            ('VALIGN',(0,0),(-1,-1),'TOP'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING',(0,0),(-1,0),12),
            ('GRID', (0,0), (-1,-1), 1, colors.black),
            ('WORDWRAP', (0,0), (-1,-1), 'CJK'),
        ]))
        flowables.append(alert_table)
    else:
        flowables.append(Paragraph("No intrusion alerts detected.", styles["Normal"]))
    flowables.append(Spacer(1, 0.25*inch))

    # --- Shodan Results ---
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
                ('WORDWRAP', (0,0), (-1,-1), 'CJK'),
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
                ('WORDWRAP', (0,0), (-1,-1), 'CJK'),
            ]))
            flowables.append(vuln_table)
        else:
            flowables.append(Paragraph("No vulnerabilities reported by Shodan.", styles["Normal"]))

    flowables.append(Spacer(1, 0.25*inch))

    # Finally, build the PDF
    doc.build(flowables)
