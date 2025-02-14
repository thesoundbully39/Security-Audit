# Security-Audit

Initial Commit 2-11-2025

The purpose of the Security Audit (Cyber Audit) python3 script is to automate the collection, analysis, and reporting on home network security posture. Developed for potential use as a service provided by Florida Web Architects LLC and released open source for the home/commercial use of others.

Our goal is to be able to build out a completely automated reporting system for home cyber security posture analysis, potentially even branching into use in the commercial space.

Current Testing Performed:

The script performs several security-related “tests” or checks on the target network:

1. Host Discovery (Nmap -sn)
- Discovers live hosts in the specified subnets.
- The script uses nmap -sn to send pings/ARP requests and stores the output in a host_discovery.gnmap file.
- Any hosts that respond as “Up” are deemed alive and fed into the second phase.

2. Detailed Scan (Nmap -sV -O)
- For each live host discovered, it performs a service version scan (-sV) and attempts OS detection (-O).
- Ports discovered open are logged, along with OS guesses, hostnames, and basic service names.
- Results are saved in nmap_scan.xml, which the script later parses to build a devices list for the report.

3. Packet Capture (tcpdump)
- The script captures all network traffic for the specified duration (in minutes).
- It uses timeout <duration> to run tcpdump -i eth0 -w capture.pcap.
- After the capture completes, the pcap file is handed off to Zeek.

4. Zeek Analysis
- Zeek (formerly Bro) inspects the captured traffic (zeek -r capture.pcap) and can generate its own logs for deeper traffic analysis (HTTP logs, DNS logs, etc.).
- The script doesn’t parse Zeek logs in detail right now—mainly it’s there to let you keep Zeek data if you want more advanced correlation.

5. Suricata Analysis
- Suricata runs in offline mode (suricata -r capture.pcap) using the same traffic capture (capture.pcap).
- If Suricata is configured with rules, it will log intrusion alerts to suricata_logs/eve.json.
- The script parses that JSON to display alert signatures, categories, and severity in the final PDF report.

6. Shodan Lookup
- The script attempts to discover the public IP by running shodan myip.
- It then checks Shodan for open ports, exposures, or known vulnerabilities for that IP and includes the details in the final PDF.

7. PDF Report Generation
- Gathers data from:
  Nmap (Devices, hostnames, OS info, open ports)
  Suricata (Alerts)
  Shodan (Internet exposure)
- Produces security_audit_report.pdf with tables that summarize the findings.

Usage
1. Install dependencies (e.g. pip install reportlab shodan pandas).
2. Ensure nmap, tcpdump, suricata, and zeek are installed on your system.
Run:
python3 audit.py 60 "192.168.1.0/24"
- This will do a 60-minute capture on 192.168.1.0/24 (or the default subnets if not provided).
- Generate security_audit_report.pdf.
- Save consolidated data in final_results.json.

