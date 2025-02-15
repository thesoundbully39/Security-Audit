#!/usr/bin/env python3
import sys
import json
import os

# SCAN MODULES
from scan.network_scans import (
    run_nmap_discovery,
    run_nmap_details,
    parse_nmap_results,
    run_shodan_lookup
)
from scan.packet_capture import run_packet_capture

# ANALYSIS MODULES
from analysis.suricata import run_suricata_analysis, analyze_suricata_logs
from analysis.zeek import parse_zeek_conn_log, parse_zeek_dns_log
from analysis.iot_detection import find_iot_devices

# REPORTING MODULE
from reporting.pdf_builder import generate_pdf_report

def main():
    # Check for --regen flag
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

        # Optional: Get NVD API key from command-line (last argument)
        nvd_api_key = ""
        if len(sys.argv) > 2:
            nvd_api_key = sys.argv[-1]

        findings = data.get("nmap", {})
        alerts = data.get("suricata", [])
        shodan_res = data.get("shodan", {})
        zeek_data = data.get("zeek", {})
        conn_zeek = zeek_data.get("top_talkers", [])
        dns_zeek = zeek_data.get("top_domains", [])

        # Define all_devs from the findings before calling find_iot_devices
        all_devs = findings.get("Devices", [])
        iot_devs = find_iot_devices(all_devs, nvd_api_key)

        print("Regenerating PDF from existing final_results.json data...")
        generate_pdf_report(
            findings=findings,
            alerts=alerts,
            shodan_results=shodan_res,
            conn_results=conn_zeek,
            dns_results=dns_zeek,
            iot_devices=iot_devs,
            output_file="security_audit_report.pdf"
        )
        print("Report regenerated: security_audit_report.pdf")
        sys.exit(0)

    # Normal run: parse duration and subnets from args
    duration = 60
    if len(sys.argv) > 1:
        try:
            duration = int(sys.argv[1])
        except ValueError:
            print("Invalid duration argument, using default 60 minutes.")

    subnets = "10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"
    if len(sys.argv) > 2:
        subnets = sys.argv[2]

    # Optional: NVD API key as 3rd argument
    nvd_api_key = ""
    if len(sys.argv) > 3:
        nvd_api_key = sys.argv[3]

    # 1. Nmap scanning
    print(f"Discovering hosts in {subnets} ...")
    live_hosts = run_nmap_discovery(subnets)
    nmap_output = run_nmap_details(live_hosts)
    findings = parse_nmap_results(nmap_output)

    # 2. Packet capture & Suricata
    run_packet_capture(duration)
    run_suricata_analysis()
    alerts = analyze_suricata_logs()

    # 3. Shodan lookup
    shodan_res = run_shodan_lookup()

    # 4. Zeek parsing
    conn_zeek = parse_zeek_conn_log()
    dns_zeek = parse_zeek_dns_log()

    # 5. IoT detection with CVEs via NVD API
    all_devs = findings.get("Devices", [])
    iot_devs = find_iot_devices(all_devs, nvd_api_key)

    # 6. Generate PDF report
    generate_pdf_report(
        findings=findings,
        alerts=alerts,
        shodan_results=shodan_res,
        conn_results=conn_zeek,
        dns_results=dns_zeek,
        iot_devices=iot_devs,
        output_file="security_audit_report.pdf"
    )
    print("Report generated: security_audit_report.pdf")

    # 7. Save final JSON data
    final_data = {
        "nmap": findings,
        "suricata": alerts,
        "shodan": shodan_res,
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
