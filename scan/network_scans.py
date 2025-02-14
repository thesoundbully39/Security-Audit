# your_project/scan/network_scans.py

import os
import subprocess
import xml.etree.ElementTree as ET
import json

def run_nmap_discovery(subnets):
    """Perform a host discovery scan and return a list of live hosts."""
    discovery_file = "host_discovery.gnmap"
    cmd = f"nmap --stats-every 5s -sn --host-timeout 30s -oG {discovery_file} {subnets}"
    print(f"Running discovery scan: {cmd}")
    subprocess.run(cmd, shell=True)

    discovered_ips = []
    if os.path.exists(discovery_file):
        with open(discovery_file, 'r') as f:
            for line in f:
                if "Up" in line and line.startswith("Host:"):
                    parts = line.split()
                    if len(parts) > 1:
                        ip_addr = parts[1]
                        discovered_ips.append(ip_addr)
    return discovered_ips

def run_nmap_details(live_hosts):
    """Perform a deeper Nmap scan on discovered hosts."""
    output_file = "nmap_scan.xml"
    if not live_hosts:
        print("No live hosts discovered. Creating an empty Nmap XML file.")
        with open(output_file, 'w') as f:
            f.write("<nmaprun></nmaprun>")
        return output_file

    ip_list = " ".join(live_hosts)
    cmd = f"nmap --stats-every 5s -T4 -sV -O -oX {output_file} {ip_list}"
    print(f"Running detailed scan: {cmd}")
    subprocess.run(cmd, shell=True)
    return output_file

def parse_nmap_results(file):
    """Parse Nmap XML results for open ports, OS info, and hostnames."""
    tree = ET.parse(file)
    root = tree.getroot()
    findings = {"Open Ports": 0, "Devices": []}

    for host in root.findall(".//host"):
        # IPv4 address
        ip_element = host.find("address[@addrtype='ipv4']")
        if ip_element is None:
            ip_element = host.find("address")
        if ip_element is None:
            continue
        ip_address = ip_element.get("addr", "Unknown")

        # MAC address & vendor
        mac_element = host.find("address[@addrtype='mac']")
        mac_address = mac_element.get("addr", "Unknown") if mac_element is not None else "Unknown"
        mac_vendor = mac_element.get("vendor", "Unknown") if mac_element is not None else "Unknown"

        # OS info
        os_info = host.find("os/osmatch")
        os_name = os_info.get("name") if os_info is not None else "Unknown"

        # Hostname
        hostname_elem = host.find("hostnames/hostname")
        hostname = hostname_elem.get("name", "Unknown") if hostname_elem is not None else "Unknown"

        # Ports
        ports = []
        for port in host.findall(".//port"):
            port_id = port.get("portid")
            service = port.find("service")
            service_name = service.get("name") if service is not None else "Unknown"
            ports.append(f"{port_id} ({service_name})")

        device_record = {
            "IP": ip_address,
            "MAC": mac_address,
            "Vendor": mac_vendor,
            "Hostname": hostname,
            "OS": os_name,
            "Ports": ports,
        }
        findings["Devices"].append(device_record)
        findings["Open Ports"] += len(ports)

    return findings

def run_shodan_lookup():
    shodan_results = {}
    try:
        output = subprocess.run("shodan myip", shell=True, capture_output=True, text=True)
        public_ip = output.stdout.strip()
        if public_ip:
            shodan_scan = subprocess.run(
                f"shodan host {public_ip}",
                shell=True,
                capture_output=True,
                text=True
            )
            if shodan_scan.stdout:
                try:
                    shodan_results = json.loads(shodan_scan.stdout)
                except json.JSONDecodeError:
                    shodan_results = {"error": "Invalid JSON from Shodan"}
            else:
                shodan_results = {"error": "No data from Shodan"}
    except Exception as e:
        shodan_results = {"error": str(e)}
    return shodan_results
