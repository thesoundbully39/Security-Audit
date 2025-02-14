# your_project/scan/packet_capture.py

import os

def run_packet_capture(duration):
    """Capture packets for duration (minutes) and run Zeek on the pcap."""
    print(f"Starting packet capture for {duration} minutes...")
    os.system(f"timeout {duration * 60} tcpdump -i eth0 -w capture.pcap")
    print("Packet capture complete. Running Zeek analysis...")
    os.system("zeek -r capture.pcap")
