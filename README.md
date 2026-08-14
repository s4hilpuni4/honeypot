# Aegis|Honeypot-Based Intrusion Detection System (HIDS)

Aegis is an interactive, high-fidelity **Honeypot-Based Intrusion Detection System (HIDS)**. It simulates common vulnerable network service interfaces (SSH, FTP, HTTP) to lure port scanners and scripts, parses intrusion attempts in real-time, maps attackers' behaviors to MITRE ATT&CK techniques, and displays logs in a real-time web command dashboard.

---

## Key Features

- **Multi-Port Simulated Honeypots**:
  - **SSH (2222)**: Fakes SSH protocol banners, processes interactive authentication credentials (capturing brute force targets), and mimics a responsive Linux shell.
  - **FTP (2121)**: Emulates a standard anonymous FTP control terminal.
  - **HTTP (8080)**: Serves a mock router administration login dashboard, capturing query parameter exploits, directories scanning, and SQLi/XSS requests.
- **Dynamic Rule-Based Detection**: Maps anomalous actions to SQL Injection, Cross-Site Scripting (XSS), Directory Traversal, Remote Code Execution (RCE), and high-frequency Brute Force attempts.
- **Stunning Analytics Dashboard**:
  - Built with glassmorphism and cyber-neon styling.
  - Displays real-time charts powered by Chart.js (Timeline Trends, Target Port Distributions, Severity Ratios).
  - Scrolling live-telemetry feed featuring detailed payload inspection overlays.
  - Programmatic Web Audio alerts synthesizing warning beeps directly in the browser when threats are blocked.
- **Log Collection & Analysis**:
  - Emits logs in structured JSON format.
  - Includes a standalone **Threat Analytics Log Parser (`log_parser.py`)** to count metrics, detect sliding-window brute force connections, and output formatted Markdown executive summaries.
- **Dockerized & Hardened**:
  - Minimal Docker builds running under non-privileged system users.
  - Clear egress firewall configurations (`iptables` & AWS Security Groups) to prevent container pivoting (anti-egress).
  - Ready-to-go Logstash pipeline configuration mapping logs with GeoIP lookups.

---

## Project Structure

```text
honeypot-ids/
├── package.json          # Express and WS server dependencies
├── server.js             # Main server orchestrator & honeypots simulator
├── db.js                 # JSON file logger database & metrics compiler
├── detection.js          # Intrusion detection signatures & rules
├── honeypot.py           # Senior standalone Python honeypot script
├── log_parser.py         # Dynamic log parser & MITRE ATT&CK compiler
├── Dockerfile            # Safe non-root container builder
├── docker-compose.yml    # Mounts, port configurations, and capacity limits
├── logstash.conf         # ELK stack GeoIP lookup pipeline
├── .gitignore            # Keeps logs and node_modules out of repositories
└── public/               # Frontend Dashboard client assets
    ├── index.html        # Premium single-page glassmorphism markup
    ├── style.css         # Cyber command styles & visual indicators
    └── app.js            # WebSockets client, Chart.js handler, & sound alarm
```

---

## Getting Started

### 1. Manual Launch
Ensure Node.js is installed, then:
```bash
# Install dependencies
npm install

# Start HIDS backend
node server.js
```
Open `http://localhost:3000` to view the HIDS command center.

### 2. Containerized Launch (Docker)
Build and run Aegis in a safe sandbox:
```bash
docker-compose up --build -d
```
Logs will persist on your host machine under `./logs/honeypot.log`.

---

## Testing & Verifying
Send mock malicious payloads to trigger real-time dashboard events:

```bash
# SQL Injection attempt on HTTP Honeypot
curl "http://localhost:8080/admin?user='OR'1'='1"

# Directory Traversal attempt on HTTP Honeypot
curl "http://localhost:8080/../../etc/passwd"

# RCE command attempt on HTTP Honeypot
curl "http://localhost:8080/api/upload?cmd=rm%20-rf%20/"

# SSH Login connection attempt
(echo "SSH-2.0-OpenSSH_8.4"; sleep 1; echo "root"; sleep 1; echo "secret123"; sleep 1; echo "exit") | nc localhost 2222
```

---

## Threat Analytics Log Parser
Parse captured logs and generate Markdown security summaries:
```bash
python3 log_parser.py --log-file ./logs/honeypot.log --output security_report.md
```

---

## Production Egress Network Isolation (Anti-Pivoting)
To ensure that a compromised honeypot cannot initiate network scans or pivot internally:

### 1. Linux firewall (`iptables`)
```bash
# Allow return packets for existing connections
sudo iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# Drop new outbound connections from the Docker subnet
sudo iptables -A FORWARD -s 172.18.0.0/16 -m conntrack --ctstate NEW -j DROP
```

### 2. AWS VPC Security Groups
Simply delete the default outbound rule (`All traffic: 0.0.0.0/0`) on your EC2 instance's Security Group. AWS Security Groups are stateful; replies to incoming port probes will still route correctly, but the EC2 cannot initiate outbound calls.
