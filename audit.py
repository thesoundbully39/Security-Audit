#!/usr/bin/env python3

import sys
import json

# Imports from your custom modules
# --------------------------------
# 1) SCAN MODULES
from scan.network_scans import (
    run_nmap_discovery,
    run_nmap_details,
    parse_nmap_results,
    run_shodan_lookup
)
from scan.packet_capture import run_packet_capture

# 2) ANALYSIS MODULES
from analysis.suricata import run_suricata_analysis, analyze_suricata_logs
from analysis.zeek import parse_zeek_conn_log, parse_zeek_dns_log

# 3) REPORTING MODULE
from reporting.pdf_builder import generate_pdf_report


def main():
    """
    Main orchestration of the security audit:
      - Optionally parse command-line arguments
      - If --regen is passed, skip scanning/capturing & rebuild the PDF from final_results.json
      - Otherwise, run Nmap, packet capture, Suricata, etc.
      - Generate final JSON data & PDF report
    """

    # ---------------
    # 1. Check for --regen
    # ---------------
    if "--regen" in sys.argv:
        # Attempt to load data from final_results.json
        try:
            with open("final_results.json", "r") as f:
                data = json.load(f)
        except FileNotFoundError:
            print("Error: final_results.json not found. Cannot regenerate report.")
            sys.exit(1)
        except json.JSONDecodeError:
            print("Error: final_results.json is invalid JSON.")
            sys.exit(1)

        # Extract the data
        findings = data.get("nmap", {})
        alerts = data.get("suricata", [])
        shodan_results = data.get("shodan", {})
        zeek_data = data.get("zeek", {})
        conn_zeek = zeek_data.get("top_talkers", [])
        dns_zeek = zeek_data.get("top_domains", [])

        # Re-generate PDF using previously saved data
        print("Regenerating PDF from existing final_results.json data...")
        # If your generate_pdf_report requires conn_results/dns_results:
        # generate_pdf_report(findings, alerts, shodan_results, conn_zeek, dns_zeek, ...)
        #
        # If your pdf_builder is set to re-parse logs on its own, you can pass fewer args.
        # Example below assumes we have an extended version that accepts them:
        generate_pdf_report(
            findings=findings,
            alerts=alerts,
            shodan_results=shodan_results,
            # If your pdf_builder doesn't take these, remove them:
            conn_results=conn_zeek,
            dns_results=dns_zeek,
            output_file="security_audit_report.pdf"
        )

        print("Report regenerated: security_audit_report.pdf")
        sys.exit(0)

    # ---------------
    # 2. Otherwise, normal scanning flow
    # ---------------
    # Default duration for packet capture
    duration = 60
    # Default subnets to scan
    subnets = "10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"

    # Basic argument handling (example):
    if len(sys.argv) > 1:
        # If the user provided a numeric arg (like 60)
        try:
            duration = int(sys.argv[1])
        except ValueError:
            print("Invalid duration argument, using default 60 minutes.")

    if len(sys.argv) > 2:
        # If the user provided a subnet arg (like "192.168.1.0/24")
        subnets = sys.argv[2]

    # ---------------
    # 3. Nmap scanning
    # ---------------
    print(f"Discovering hosts in {subnets}...")
    live_hosts = run_nmap_discovery(subnets)
    nmap_output = run_nmap_details(live_hosts)
    findings = parse_nmap_results(nmap_output)

    # ---------------
    # 4. Packet capture & Suricata
    # ---------------
    run_packet_capture(duration)
    run_suricata_analysis()
    alerts = analyze_suricata_logs()

    # ---------------
    # 5. Shodan
    # ---------------
    shodan_results = run_shodan_lookup()

    # ---------------
    # 6. Zeek analysis
    # ---------------
    conn_zeek = parse_zeek_conn_log()
    dns_zeek = parse_zeek_dns_log()

    # ---------------
    # 7. Generate PDF
    # ---------------
    generate_pdf_report(
        findings=findings,
        alerts=alerts,
        shodan_results=shodan_results,
        conn_results=conn_zeek,
        dns_results=dns_zeek,
        output_file="security_audit_report.pdf"
    )
    print("Report generated: security_audit_report.pdf")

    # ---------------
    # 8. Save final JSON
    # ---------------
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
