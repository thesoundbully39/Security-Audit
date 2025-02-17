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
    Ensures all tables are displayed, including Zeek Connection & DNS summaries.
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

    # --- Zeek Connection Summary (Top Talkers) ---
    flowables.append(Paragraph("<b>Zeek Connection Summary (Top 5 Talkers)</b>", styles["Heading2"]))
    flowables.append(Spacer(1, 0.1 * inch))

    if conn_results:
        conn_table_data = [["Source IP", "Connections", "Total Bytes"]]
        for src_ip, connections, total_bytes in conn_results:
            conn_table_data.append([
                Paragraph(src_ip, styles["Normal"]),
                Paragraph(str(connections), styles["Normal"]),
                Paragraph(str(total_bytes), styles["Normal"])
            ])
    else:
        conn_table_data = [["No connection data available"] * 3]

    conn_table = Table(conn_table_data, colWidths=[2.0 * inch, 1.5 * inch, 2.0 * inch])
    conn_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('WORDWRAP', (0, 0), (-1, -1), 'CJK'),
    ]))

    flowables.append(conn_table)
    flowables.append(Spacer(1, 0.25 * inch))

    # --- Zeek DNS Summary (Top Queried Domains) ---
    flowables.append(Paragraph("<b>Zeek DNS Summary (Top Queried Domains)</b>", styles["Heading2"]))
    flowables.append(Spacer(1, 0.1 * inch))

    if dns_results:
        dns_table_data = [["Domain", "Query Count"]]
        for domain, count in dns_results:
            dns_table_data.append([
                Paragraph(domain, styles["Normal"]),
                Paragraph(str(count), styles["Normal"])
            ])
    else:
        dns_table_data = [["No DNS data available"] * 2]

    dns_table = Table(dns_table_data, colWidths=[4.0 * inch, 1.5 * inch])
    dns_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('WORDWRAP', (0, 0), (-1, -1), 'CJK'),
    ]))

    flowables.append(dns_table)
    flowables.append(Spacer(1, 0.25 * inch))

    # --- Finalize PDF ---
    doc.build(flowables)
