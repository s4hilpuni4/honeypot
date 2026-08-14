#!/usr/bin/env python3
"""
Aegis Honeypot Log Parser & Threat Analytics
Author: Senior Cybersecurity Engineer
Description: Analyzes structured JSON honeypot logs to identify metrics,
             detect brute-force patterns, map attacks to MITRE ATT&CK,
             and generate clean Markdown summary reports.
"""

import sys
import os
import json
import argparse
from collections import Counter, defaultdict
from datetime import datetime

# Global default configurations
DEFAULT_LOG_PATH = "/var/log/honeypot.log"

# MITRE ATT&CK Matrix Mapping configurations
MITRE_MAPPING = {
    "brute_force_attempt": {
        "id": "T1110",
        "name": "Brute Force",
        "description": "Adversaries may use brute force access attempts to log in to target systems."
    },
    "connection_established": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "description": "Adversaries may attempt to find active services and ports on target infrastructure."
    },
    "client_handshake": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "description": "Analyzing banners and handshakes to gather service info."
    },
    "http_request": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "description": "Adversaries may attempt to exploit vulnerabilities in internet-facing web apps."
    },
    "exploit_attempt": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "description": "Direct attempts to exploit application bugs or administrative pages."
    },
    "directory_traversal": {
        "id": "T1083",
        "name": "File and Directory Discovery",
        "description": "Adversaries may search files and directories to gain information about host layouts."
    },
    "command_execution": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "description": "Adversaries may abuse command and execution tools to execute malicious commands."
    }
}

# Detection settings
BRUTE_FORCE_COUNT_THRESHOLD = 5
BRUTE_FORCE_WINDOW_SECONDS = 60

def parse_iso_time(time_str):
    """
    Parses ISO timestamps from logs, supporting decimal variations.
    """
    # Normalize Z
    if time_str.endswith('Z'):
        time_str = time_str[:-1]
    
    # Strip microsecond precision if standard formatting differs
    if '.' in time_str:
        base, micro = time_str.split('.')
        micro = micro[:6] # keep max 6 digits
        time_str = f"{base}.{micro}"
        return datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%S.%f")
    else:
        return datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%S")


def analyze_logs(log_filepath):
    """
    Reads and parses JSON log entries, performing metrics extraction and threat calculations.
    """
    logs = []
    
    if not os.path.exists(log_filepath):
        print(f"[-] Error: Log file '{log_filepath}' does not exist.")
        sys.exit(1)
        
    with open(log_filepath, 'r') as f:
        for idx, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                logs.append(json.loads(line))
            except json.JSONDecodeError:
                print(f"[!] Skipping unparseable log entry at line {idx}")
                
    if not logs:
        print("[!] Warning: No log records found in file.")
        return None

    # Containers for metrics
    attacker_ips = Counter()
    targeted_ports = Counter()
    credentials = Counter()
    mitre_counts = Counter()
    
    # Time-sequence container for tracking IPs
    ip_timeline = defaultdict(list)
    
    for log in logs:
        ip = log.get("attacker_ip")
        port = log.get("target_port")
        event = log.get("event_type")
        payload = log.get("raw_payload", "")
        
        # Accumulate metrics
        if ip:
            attacker_ips[ip] += 1
        if port:
            targeted_ports[port] += 1
            
        # Extract service credentials
        creds = log.get("credentials")
        if creds and isinstance(creds, dict):
            user = creds.get("username", "")
            password = creds.get("password", "")
            if user or password:
                credentials[(user, password)] += 1
                
        # Analyze heuristic sub-types inside HTTP/FTP raw payloads
        inferred_event = event
        if event == "http_request" or event == "exploit_attempt":
            payload_upper = payload.upper()
            if "../" in payload or "..\\" in payload or "ETC/PASSWD" in payload_upper:
                inferred_event = "directory_traversal"
            elif "CMD=" in payload_upper or "EVAL(" in payload_upper or "PING -C" in payload_upper:
                inferred_event = "command_execution"
        
        # Map MITRE ATT&CK
        if inferred_event in MITRE_MAPPING:
            tech_id = MITRE_MAPPING[inferred_event]["id"]
            mitre_counts[tech_id] += 1
            
        # Track timeline for brute force detection
        timestamp_str = log.get("timestamp")
        if ip and timestamp_str:
            try:
                dt = parse_iso_time(timestamp_str)
                ip_timeline[ip].append(dt)
            except Exception:
                pass

    # Heuristic: Check for high frequency brute force connection thresholds
    high_freq_attackers = {}
    for ip, times in ip_timeline.items():
        times = sorted(times)
        if len(times) < BRUTE_FORCE_COUNT_THRESHOLD:
            continue
            
        # Sliding window check
        for i in range(len(times) - BRUTE_FORCE_COUNT_THRESHOLD + 1):
            window_start = times[i]
            window_end = times[i + BRUTE_FORCE_COUNT_THRESHOLD - 1]
            diff = (window_end - window_start).total_seconds()
            
            if diff <= BRUTE_FORCE_WINDOW_SECONDS:
                # Count total events inside this window
                events_in_window = sum(
                    1 for t in times if 0 <= (t - window_start).total_seconds() <= BRUTE_FORCE_WINDOW_SECONDS
                )
                high_freq_attackers[ip] = {
                    "occurrences": events_in_window,
                    "window_sec": BRUTE_FORCE_WINDOW_SECONDS,
                    "first_seen": window_start.strftime("%Y-%m-%d %H:%M:%S"),
                }
                break # trigger alarm check once per ip

    return {
        "total_records": len(logs),
        "top_ips": attacker_ips.most_common(10),
        "top_ports": targeted_ports.most_common(5),
        "top_creds": credentials.most_common(10),
        "mitre_stats": mitre_counts,
        "brute_force_alerts": high_freq_attackers
    }


def generate_markdown_report(metrics, log_file):
    """
    Renders analytics metrics into an executive-grade Markdown summary.
    """
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    md = []
    md.append(f"# Aegis Threat Analytics Report")
    md.append(f"**Generated Time**: {now}  ")
    md.append(f"**Source Log File**: `{log_file}`  ")
    md.append(f"**Total Log Incidents**: {metrics['total_records']}\n")
    
    md.append(f"## 1. Top Attacker IP Addresses (Top 10)")
    md.append(f"| Rank | IP Address | Activity Count |")
    md.append(f"| :--- | :--- | :--- |")
    for rank, (ip, count) in enumerate(metrics["top_ips"], 1):
        md.append(f"| {rank} | `{ip}` | {count} |")
    md.append("")

    md.append(f"## 2. Most Targeted Ports")
    md.append(f"| Port | Hits | Protocol Hint |")
    md.append(f"| :--- | :--- | :--- |")
    port_hints = {22: "SSH", 80: "HTTP", 21: "FTP", 2222: "SSH (Alt)", 8080: "HTTP (Alt)", 2121: "FTP (Alt)"}
    for port, count in metrics["top_ports"]:
        hint = port_hints.get(port, "Unknown / Non-standard")
        md.append(f"| `{port}` | {count} | {hint} |")
    md.append("")

    md.append(f"## 3. High-Frequency Connection & Brute Force Alerts")
    alerts = metrics["brute_force_alerts"]
    if not alerts:
        md.append(f"> [!NOTE]  \n> No high-frequency brute force behaviors exceeded the alerting threshold ({BRUTE_FORCE_COUNT_THRESHOLD} connections inside {BRUTE_FORCE_WINDOW_SECONDS}s).")
    else:
        md.append(f"> [!WARNING]  \n> **{len(alerts)} Attacker IPs flagged** for triggering rapid connection thresholds:")
        md.append("\n| Flagged IP | Connections in Window | Time Range Window | Trigger Time (UTC) |")
        md.append("| :--- | :--- | :--- | :--- |")
        for ip, detail in alerts.items():
            md.append(f"| `{ip}` | **{detail['occurrences']}** | {detail['window_sec']}s | {detail['first_seen']} |")
    md.append("")

    md.append(f"## 4. Top Captured Credentials (SSH / FTP)")
    md.append(f"| Rank | Username | Password | Access Attempts |")
    md.append(f"| :--- | :--- | :--- | :--- |")
    if not metrics["top_creds"]:
        md.append(f"| - | *No credentials captured* | - | - |")
    else:
        for rank, ((user, password), count) in enumerate(metrics["top_creds"], 1):
            md.append(f"| {rank} | `{user}` | `{password}` | {count} |")
    md.append("")

    md.append(f"## 5. MITRE ATT&CK Matrix Mapping")
    md.append(f"| Technique ID | Tech Name | Observed Incidents | Strategy Reference |")
    md.append(f"| :--- | :--- | :--- | :--- |")
    
    # Reverse lookup for mapping description
    mapped_any = False
    for tech_id, count in metrics["mitre_stats"].items():
        # find mapping info
        info = next((v for k, v in MITRE_MAPPING.items() if v["id"] == tech_id), None)
        if info:
            mapped_any = True
            md.append(f"| [{tech_id}](https://attack.mitre.org/techniques/{tech_id}/) | {info['name']} | {count} | *{info['description']}* |")
            
    if not mapped_any:
         md.append(f"| - | *No mapped techniques observed* | - | - |")
    md.append("")
    
    return "\n".join(md)


def main():
    parser = argparse.ArgumentParser(
        description="Aegis Threat Log Parser & MITRE Classifier"
    )
    parser.add_argument(
        "--log-file", type=str, default=DEFAULT_LOG_PATH,
        help="JSON log filepath to analyze"
    )
    parser.add_argument(
        "--output", type=str,
        help="Path to write the output Markdown report (prints to stdout if omitted)"
    )
    args = parser.parse_args()

    # Determine log file path (with fallbacks if /var/log is inaccessible)
    log_file = args.log_file
    if not os.path.exists(log_file):
        # Fallback to local files
        local_py = "./honeypot_py.log"
        local_raw = "./honeypot.log"
        if os.path.exists(local_py):
            log_file = local_py
        elif os.path.exists(local_raw):
            log_file = local_raw

    # Perform calculations
    metrics = analyze_logs(log_file)
    if not metrics:
        print("[-] Parse completed: No incident entries available to evaluate.")
        return

    # Generate Markdown content
    report_content = generate_markdown_report(metrics, log_file)

    # Write output
    if args.output:
        try:
            with open(args.output, "w") as f:
                f.write(report_content)
            print(f"[+] Security report successfully saved to: {args.output}")
        except Exception as e:
            print(f"[-] Failed to write report file: {e}")
    else:
        print(report_content)


if __name__ == "__main__":
    main()
