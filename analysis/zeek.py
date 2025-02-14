# your_project/analysis/zeek.py

import os
import csv

def parse_zeek_conn_log(logfile="conn.log", top_n=5):
    if not os.path.exists(logfile):
        return []
    talkers = {}
    with open(logfile, "r") as f:
        reader = csv.reader(f, delimiter='\t')
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            if len(row) < 11:
                continue
            src_ip = row[2]
            orig_bytes = row[9]
            resp_bytes = row[10]

            try:
                orig_bytes = int(orig_bytes)
            except ValueError:
                orig_bytes = 0

            try:
                resp_bytes = int(resp_bytes)
            except ValueError:
                resp_bytes = 0

            if src_ip not in talkers:
                talkers[src_ip] = {"connections": 0, "bytes": 0}
            talkers[src_ip]["connections"] += 1
            talkers[src_ip]["bytes"] += (orig_bytes + resp_bytes)

    sorted_talkers = sorted(talkers.items(), key=lambda x: x[1]["bytes"], reverse=True)
    results = []
    for ip, data in sorted_talkers[:top_n]:
        results.append((ip, data["connections"], data["bytes"]))
    return results

def parse_zeek_dns_log(logfile="dns.log", top_n=5):
    if not os.path.exists(logfile):
        return []
    domain_counts = {}
    with open(logfile, "r") as f:
        reader = csv.reader(f, delimiter='\t')
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            if len(row) < 10:
                continue
            query = row[9]
            domain_counts[query] = domain_counts.get(query, 0) + 1

    sorted_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)
    return sorted_domains[:top_n]
