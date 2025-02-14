# your_project/audit.py

import sys
import json
from scan.network_scans import (
    run_nmap_discovery, run_nmap_details,
    parse_nmap_results, run_shodan_lookup
)
from scan.packet_capture import run_packet_capture
from analysis.suricata import run_suricata_analysis, analyze_suricata_logs
from analysis.zeek import parse_zeek_conn_log, parse_zeek_dns_log
from reporting.pdf_builder import generate_pdf_report

def main():
    # 1) Duration argument
    duration = 60
    if len(sys.argv) > 1:
        try:
            duration = int(sys.argv[1])
        except ValueError:
            print("Invalid duration argument, using default 60 minutes.")

    # 2) Subnets argument
    subnets = "10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"
    if len(sys.argv) > 2:
        subnets = sys.argv[2]

    # Nmap
    live_hosts = run_nmap_discovery(subnets)
    nmap_output = run_nmap_details(live_hosts)
    findings = parse_nmap_results(nmap_output)

    # Packet capture & Suricata
    run_packet_capture(duration)
    run_suricata_analysis()
    alerts = analyze_suricata_logs()

    # Shodan
    shodan_results = run_shodan_lookup()

    # Zeek
    conn_zeek = parse_zeek_conn_log()
    dns_zeek = parse_zeek_dns_log()

    # PDF Report
    generate_pdf_report(
        findings=findings,
        alerts=alerts,
        shodan_results=shodan_results,
        conn_results=conn_zeek,
        dns_results=dns_zeek,
        output_file="security_audit_report.pdf"
    )
    print("Report generated: security_audit_report.pdf")

    # JSON output
    final_data = {
        "nmap": findings,
        "suricata": alerts,
        "shodan": shodan_results,
        "zeek": {
            "top_talkers": conn_zeek,
            "top_domains": dns_zeek
        }
    }
    with open("final_results.json", "w") as jf:
        json.dump(final_data, jf, indent=2)
    print("Created final_results.json with consolidated data.")

if __name__ == "__main__":
    main()
