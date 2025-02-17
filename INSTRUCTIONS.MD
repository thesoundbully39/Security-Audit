# Host Configuration & Usage Instructions

Below is a step-by-step host setup guide so you can successfully run and get the most out of the Cyber Audit Script.
These instructions assume you’re using a Linux environment (e.g., Ubuntu, Debian, CentOS) with root/sudo access.

We tested this with a Raspberry Pi 5 8GB.
Ubuntu 24.10 Desktop

## 1. Update & Install System Packages

### Update package lists & upgrade existing packages:

```
sudo apt update && sudo apt upgrade -y
```
(Use the equivalent for your distro, e.g., dnf, yum, etc.)

### Install common tools (if they aren’t already):

```
sudo apt install -y wget curl git
```
These are handy for grabbing additional software.

## 2. Install the Required Security Tools

This script currently uses Nmap, tcpdump, Zeek, and Suricata:

### Nmap

```
sudo apt install -y nmap
```
This provides the network/port scanning and OS detection.

### tcpdump

```
sudo apt install -y tcpdump
```
Used to capture network traffic in capture.pcap.

### Zeek (formerly Bro)

Some distros provide zeek in default repos (e.g., sudo apt install zeek).
If not, see Zeek Documentation for up-to-date install methods.

### Suricata

```
sudo apt install -y suricata
```

Or follow official instructions if your distro has older versions.

Ensure these tools work by running commands like nmap --version, tcpdump --version, etc.

## 3. Configure Python Environment

### Check Python 3

Confirm Python 3 is installed:

```
python3 --version
```
If missing, install (e.g., sudo apt install python3 python3-pip).

### Install Python Libraries

The script uses:
reportlab for PDFs
pandas (light usage)
shodan (CLI + Python integration)

```
pip3 install reportlab pandas shodan
```

### Initialize Shodan (optional, but recommended)

If you want the Shodan lookup part to work:

```
shodan init YOUR_SHODAN_API_KEY
```

Test with:

```
shodan myip
```

## 4. NIC Offloading (Optional)

Suricata may detect “invalid checksums” if your network card offloading is enabled.
If you see lots of “SURICATA TCPv4 invalid checksum” alerts:

```
sudo ethtool --offload eth0 rx off tx off
```
Replace eth0 with your actual interface name (ip a to find it). This is optional but can help reduce false positives.

## 5. Permissions & Capabilities

Run as root (recommended)
Nmap OS detection and packet capture typically need elevated privileges.

### Easiest approach:
```
sudo python3 security_audit_script.py
```

### Alternatively: Grant capabilities

If you prefer not to run entire Python script as root, you can grant capabilities to certain binaries:

```
sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)
sudo setcap cap_net_raw,cap_net_admin=eip $(which nmap)
```
But it’s simpler to run the script via sudo if you trust it fully.

## 6. (Optional) Suricata Rule Updates
Suricata depends on rule sets. For better detection:

### Install/enable suricata-update:

```
sudo apt install suricata-update
```

### Update Suricata rules:

```
sudo suricata-update
sudo systemctl restart suricata
```
Customize your /etc/suricata/suricata.yaml if needed (e.g., disabling invalid-checksum alerts or enabling specific rule sets).

## 7. Usage

When your system is prepared:

1. Clone or place the script on your host.
2. Run the script with desired parameters:

```
sudo python3 security_audit_script.py 60 "192.168.1.0/24"
```
Ie.
60 => the number of minutes to capture traffic.
"192.168.1.0/24" => subnets to scan with Nmap (optional; defaults to all private IP ranges).

If IP ranges in use are known, I recommend limiting the IP ranges for the fastest completion time.

The script will:

1. Run Nmap host discovery & detail scan.
2. Capture traffic with tcpdump for 60 minutes (or how long you specifc), then run Zeek & Suricata on that PCAP.
3. Lookup your public IP via Shodan (if configured).
4. Produce security_audit_report.pdf with results and create a consolidated final_results.json.

Future use will be to upload the final_results.json file to a web frontent for consumption.
