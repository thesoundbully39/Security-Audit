# file: audit.py

import sys
import json
import os

# SCAN
from scan.network_scans import run_nmap_discovery, run_nmap_details, parse_nmap_results, run_shodan_lookup
from scan.packet_capture import run_packet_capture

# ANALYSIS
from analysis.suricata import run_suricata_analysis, analyze_suricata_logs
from analysis.zeek import parse_zeek_conn_log, parse_zeek_dns_log
from analysis.iot_detection import find_iot_devices

# REPORTING
from reporting.pdf_builder import generate_pdf_report

def main():
    # Check for optional --regen
    if "--regen" in sys.argv:
        try:
            with open("final_results.json","r") as f:
                data = json.load(f)
        except FileNotFoundError:
            print("No final_results.json found, cannot --regen.")
            sys.exit(1)

        # If we want to pass an NVD key again, parse from environment or sys.argv
        # or do nvd_api_key = os.getenv("NVD_API_KEY")
        # For now, assume the last arg is the key
        nvd_api_key = ""
        if len(sys.argv) > 2:
            nvd_api_key = sys.argv[-1]

        findings = data["nmap"]
        alerts = data["suricata"]
        shodan_res = data["shodan"]
        z_data = data["zeek"]
        conn_zeek = z_data["top_talkers"]
        dns_zeek = z_data["top_domains"]

        # Re-derive iot devices if you want them updated with new CVEs
        all_devs = findings["Devices"]
        from analysis.iot_detection import find_iot_devices
        iot_devs = find_iot_devices(all_devs, nvd_api_key)

        generate_pdf_report(
            findings=findings,
            alerts=alerts,
            shodan_results=shodan_res,
            conn_results=conn_zeek,
            dns_results=dns_zeek,
            iot_devices=iot_devs
        )
        print("Regenerated PDF from existing data. Exiting.")
        sys.exit(0)

    # Normal flow
    duration = 60
    if len(sys.argv) > 1:
        try:
            duration = int(sys.argv[1])
        except ValueError:
            pass

    subnets = "10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"
    if len(sys.argv) > 2:
        subnets = sys.argv[2]

    # optional 4th arg is nvd api key
    nvd_api_key = ""
    if len(sys.argv) > 3:
        nvd_api_key = sys.argv[3]

    # Nmap scanning
    live_hosts = run_nmap_discovery(subnets)
    nmap_output = run_nmap_details(live_hosts)
    findings = parse_nmap_results(nmap_output)

    # Packet capture & Suricata
    run_packet_capture(duration)
    run_suricata_analysis()
    alerts = analyze_suricata_logs()

    # Shodan
    shodan_res = run_shodan_lookup()

    # Zeek
    conn_zeek = parse_zeek_conn_log()
    dns_zeek = parse_zeek_dns_log()

    # IoT detection w/ CVEs from NVD
    all_devs = findings["Devices"]
    iot_devs = find_iot_devices(all_devs, nvd_api_key)

    # Generate PDF
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

    # Save final JSON
    final_data = {
        "nmap": findings,
        "suricata": alerts,
        "shodan": shodan_res,
        "zeek": {
            "top_talkers": conn_zeek,
            "top_domains": dns_zeek
        }
    }
    with open("final_results.json","w") as jf:
        json.dump(final_data, jf, indent=2)
    print("Created final_results.json with consolidated data.")


if __name__ == "__main__":
    main()
