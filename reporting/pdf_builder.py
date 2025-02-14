# file: reporting/pdf_builder.py

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle)
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch

# Import your iot_detection if you want to call assess_iot_risk here
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
    doc = SimpleDocTemplate(output_file, pagesize=letter)
    styles = getSampleStyleSheet()
    flowables = []

    # (Omitted: Title, Device table, Suricata alerts, etc. for brevity)
    # ...

    # Potential IoT Devices
    flowables.append(Paragraph("<b>Potential IoT Devices</b>", styles["Heading2"]))
    flowables.append(Spacer(1, 0.1*inch))
    if iot_devices:
        correlate_iot_alerts(iot_devices, alerts)  # mark alerts
        iot_table_data = [["IP", "Vendor", "OS", "Risk", "CVEs", "Ports"]]
        for dev in iot_devices:
            risk = assess_iot_risk(dev)
            cves = dev.get("CVEs", [])
            cves_str = ", ".join(cves) if cves else "None"
            ports_str = ", ".join(dev.get("Ports", []))

            iot_table_data.append([
                dev.get("IP","Unknown"),
                dev.get("Vendor","Unknown"),
                dev.get("OS","Unknown"),
                risk,
                cves_str,
                ports_str
            ])

        iot_table = Table(iot_table_data, colWidths=[1.2*inch,1.2*inch,1.2*inch,0.8*inch,2.0*inch,2.0*inch])
        iot_table.setStyle(TableStyle([
            ('BACKGROUND',(0,0),(-1,0),colors.grey),
            ('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),
            ('ALIGN',(0,0),(-1,-1),'LEFT'),
            ('VALIGN',(0,0),(-1,-1),'TOP'),
            ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),
            ('BOTTOMPADDING',(0,0),(-1,0),12),
            ('GRID',(0,0),(-1,-1),1, colors.black),
            ('WORDWRAP',(0,0),(-1,-1),'CJK'),
        ]))
        flowables.append(iot_table)
    else:
        flowables.append(Paragraph("No potential IoT devices identified.", styles["Normal"]))
    flowables.append(Spacer(1, 0.25*inch))

    # (Omitted: Suricata alerts, Shodan, Zeek tables, etc.)
    doc.build(flowables)
