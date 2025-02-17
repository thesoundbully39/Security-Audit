# file: reporting/pdf_builder.py

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
)
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch

# Import IoT risk assessment functions
from analysis.iot_detection import assess_iot_risk, correlate_iot_alerts


def generate_pdf_report(
    findings,
    alerts,
    shodan_results,
    conn_results=None,
    dns_results=None,
    iot_devices=None,
    output_file="security_audit_report.pdf"
):
    """
    Generates a detailed security audit report in PDF format.
    """
    doc = SimpleDocTemplate(output_file, pagesize=letter)
    styles = getSampleStyleSheet()
    flowables = []

    # --- Title ---
    title = Paragraph("<strong>Home Network Security Audit Report</strong>", styles["Title"])
    flowables.append(title)
    flowables.append(Spacer(1, 0.25 * inch))

    # --- Introduction ---
    intro_text = (
        "This report provides an overview of devices discovered on your network, open ports, "
        "intrusion alerts captured by Suricata, Zeek traffic summaries, and Shodan results. "
        "Potential IoT devices have been flagged, along with any high-risk ports and known vulnerabilities (CVEs)."
    )
    flowables.append(Paragraph(intro_text, styles["Normal"]))
    flowables.append(Spacer(1, 0.25 * inch))

    # --- Summary of Open Ports ---
    total_ports = findings.get("Open Ports", 0)
    summary_text = f"<b>Total Open Ports Detected:</b> {total_ports}"
    flowables.append(Paragraph(summary_text, styles["Normal"]))
    flowables.append(Spacer(1, 0.25 * inch))

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

    device_table = Table(device_table_data, colWidths=[1.1 * inch, 1.1 * inch, 1.2 * inch, 1.4 * inch, 1.2 * inch, 2.2 * inch])
    device_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('WORDWRAP', (0, 0), (-1, -1), 'CJK'),
    ]))

    flowables.append(Paragraph("<b>Discovered Devices</b>", styles["Heading2"]))
    flowables.append(Spacer(1, 0.1 * inch))
    flowables.append(device_table)
    flowables.append(Spacer(1, 0.25 * inch))

    # --- Potential IoT Devices ---
    flowables.append(Paragraph("<b>Potential IoT Devices</b>", styles["Heading2"]))
    flowables.append(Spacer(1, 0.1 * inch))
    if iot_devices:
        correlate_iot_alerts(iot_devices, alerts)
        iot_table_data = [["IP", "Vendor", "OS", "Risk", "CVEs", "Open Ports"]]
        for dev in iot_devices:
            risk = assess_iot_risk(dev)
            cves = dev.get("CVEs", [])
            cves_str = ", ".join(cves) if cves else "None"

            iot_table_data.append([
                Paragraph(dev["IP"], styles["Normal"]),
                Paragraph(dev["Vendor"], styles["Normal"]),
                Paragraph(dev["OS"], styles["Normal"]),
                risk,
                Paragraph(cves_str, styles["Normal"]),
                Paragraph(", ".join(dev.get("Ports", [])), styles["Normal"]),
            ])

        iot_table = Table(iot_table_data, colWidths=[1.2 * inch, 1.2 * inch, 1.2 * inch, 0.8 * inch, 2.0 * inch, 2.0 * inch])
        iot_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('WORDWRAP', (0, 0), (-1, -1), 'CJK'),
        ]))
        flowables.append(iot_table)
    else:
        flowables.append(Paragraph("No potential IoT devices identified.", styles["Normal"]))
    flowables.append(Spacer(1, 0.25 * inch))

    # --- Suricata Alerts ---
    flowables.append(Paragraph("<b>Intrusion Alerts (Suricata)</b>", styles["Heading2"]))
    flowables.append(Spacer(1, 0.1 * inch))
    if alerts:
        alert_list_data = [["Signature", "Category", "Severity", "Source IP", "Destination IP"]]
        for alert in alerts:
            alert_list_data.append([
                Paragraph(alert.get("signature", "Unknown"), styles["Normal"]),
                Paragraph(alert.get("category", "N/A"), styles["Normal"]),
                Paragraph(str(alert.get("severity", "N/A")), styles["Normal"]),
                Paragraph(alert.get("src_ip", "Unknown"), styles["Normal"]),
                Paragraph(alert.get("dest_ip", "Unknown"), styles["Normal"]),
            ])

        alert_table = Table(alert_list_data, colWidths=[2.0 * inch, 1.2 * inch, 0.6 * inch, 1.2 * inch, 1.2 * inch])
        alert_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('WORDWRAP', (0, 0), (-1, -1), 'CJK'),
        ]))
        flowables.append(alert_table)
    else:
        flowables.append(Paragraph("No intrusion alerts detected.", styles["Normal"]))
    flowables.append(Spacer(1, 0.25 * inch))

    # --- Finalize PDF ---
    doc.build(flowables)
