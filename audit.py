#!/usr/bin/env python3

import sys
import json

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
from analysis.iot_detection import find_iot_devices  # or assess_iot_risk if needed

# 3) REPORTING
from reporting.pdf_builder import generate_pdf_report


def main():
    """
    Main orchestration for the modular security audit script.

    Usage:
      python audit.py 60 "192.168.1.0/24"
      -- or --
      python audit.py --regen

    If --regen is passed, we skip new scans and only regenerate the PDF from final_results.json.
    """

    # --- Check for --regen flag ---
    if "--regen" in sys.argv:
        try:
            with open("final_results.json", "r") as f:
                data = json.load(f)
        except FileNotFoundError:
            print("Error: final_results.json not found. Cannot regenerate report.")
            sys.exit(1)
        except json.JSONDecodeError:
            print("Error: final_results.json is invalid JSON.")
            sys.exit(1)

        # Extract data
        findings = data.get("nmap", {})
        alerts = data.get("suricata", [])
        shodan_results = data.get("shodan", {})
        zeek_data = data.get("zeek", {})
        conn_zeek = zeek_data.get("top_talkers", [])
        dns_zeek = zeek_data.get("top_domains", [])

        # Derive iot_devices from existing findings if needed
        # (If your pdf_builder calls `find_iot_devices` internally, you can skip this.)
        devices = findings.get("Devices", [])
        iot_devices = find_iot_devices(devices)

        # Re-generate PDF
        print("Regenerating PDF from existing final_results.json data...")
        generate_pdf_report(
            findings=findings,
            alerts=alerts,
            shodan_results=shodan_results,
            conn_results=conn_zeek,
            dns_results=dns_zeek,
            iot_devices=iot_devices,
            output_file="security_audit_report.pdf"
        )
        print("Report regenerated: security_audit_report.pdf")
        sys.exit(0)

    # --- Not --regen, so do normal scanning workflow ---
    # 1) Parse args for duration & subnets
    duration = 60
    if len(sys.argv) > 1:
        try:
            duration = int(sys.argv[1])
        except ValueError:
            print("Invalid duration argument, using default 60 minutes.")

    subnets = "10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"
    if len(sys.argv) > 2:
        subnets = sys.argv[2]

    # 2) Nmap scanning
    print(f"Discovering hosts in {subnets} ...")
    live_hosts = run_nmap_discovery(subnets)
    nmap_output = run_nmap_details(live_hosts)
    findings = parse_nmap_results(nmap_output)

    # 3) Packet capture & Suricata
    run_packet_capture(duration)
    run_suricata_analysis()
    alerts = analyze_suricata_logs()

    # 4) Shodan
    shodan_results = run_shodan_lookup()

    # 5) Zeek parsing
    conn_zeek = parse_zeek_conn_log()
    dns_zeek = parse_zeek_dns_log()

    # 6) IoT detection
    devices = findings.get("Devices", [])
    iot_devices = find_iot_devices(devices)
    # If you want to do correlation with Suricata alerts to mark iot alerts, do:
    # from analysis.iot_detection import correlate_iot_alerts
    # correlate_iot_alerts(iot_devices, alerts)

    # 7) Generate PDF
    generate_pdf_report(
        findings=findings,
        alerts=alerts,
        shodan_results=shodan_results,
        conn_results=conn_zeek,
        dns_results=dns_zeek,
        iot_devices=iot_devices,
        output_file="security_audit_report.pdf"
    )
    print("Report generated: security_audit_report.pdf")

    # 8) Save final JSON data
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
