# RED RECON FRAMEWORK

```
██████╗ ███████╗██████╗     ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔══██╗    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██████╔╝█████╗  ██║  ██║    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██╔══██╗██╔══╝  ██║  ██║    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██║  ██║███████╗██████╔╝    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚══════╝╚═════╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
```

> *"Confirm the door is unlocked, don't walk through it."*

---

## What This Is

Red Recon is a professional-grade, fully interactive command-line penetration
testing framework built for authorized testing of your own systems. It is
modular, stateful, and operator-controlled at every step.

No flags. No config files. No automation without your approval.
Every decision is a prompt. Every finding is yours to act on.

---

## Philosophy

This tool is built around proof-of-concept validation.

What belongs here:
- Confirming a vulnerability exists to the level a finding report requires
- Connecting to a service and testing default credentials — reporting confirmed or denied
- Scanning, fingerprinting, enumerating — and stopping there

What does not belong here:
- Command execution beyond confirmation
- Persistence, lateral movement, or exploitation chains
- Anything beyond: *the door is unlocked*

---

## Requirements

### System Tools (must be installed on your system)
These are Kali Linux native tools. On Kali they are pre-installed.
On other Debian/Ubuntu systems install with:

```bash
sudo apt update
sudo apt install subfinder amass nmap nikto dnsutils whois netcat-openbsd
```

### Python
Python 3.10 or higher required.

```bash
python3 --version
```

---

## Setup — Virtual Environment (REQUIRED)

This tool will not run outside a virtual environment.
All Python dependencies install inside the environment only.
Deleting the environment folder removes everything cleanly.

```bash
# Step 1 — Create the environment (do this once)
python3 -m venv red_env

# Step 2 — Activate it (do this every session)
source red_env/bin/activate

# Step 3 — Launch the framework
python3 brain.py

# To deactivate when done
deactivate
```

When activated your terminal prompt will show `(red_env)` at the left.

Dependencies install automatically on first run inside the environment.
Nothing is installed to your system Python.

---

## Project Structure

```
red_recon/
├── brain.py                  ← Central brain — launch here
├── modules/
│   ├── env_check.py          ← venv enforcement + auto dependency install
│   ├── display.py            ← all color output routes through here
│   ├── subdomains.py         ← subfinder + amass subdomain discovery
│   ├── dns_intel.py          ← dig + whois + service classifier
│   ├── port_scan.py          ← nmap with tiered scan profiles
│   ├── web_scan.py           ← nikto web vulnerability scanning
│   ├── ping_sweep.py         ← ICMP connectivity and latency
│   ├── connection_intel.py   ← active connection analysis + threat intel
│   ├── cred_check.py         ← default credential proof-of-concept
│   ├── cve_lookup.py         ← NVD API v2.0 CVE cross-reference
│   ├── honeypot.py           ← attacker detection and profiling
│   └── save_manager.py       ← nothing saves without your approval
├── README.md
├── .gitignore
└── requirements.txt
```

---

## Navigation

Red Recon is fully menu-driven. Use arrow keys to navigate, Enter to select.

```
At any prompt:
  ↑ ↓         Navigate options
  Enter       Select
  ?           Context-sensitive help for current module
  h           Full help menu
  q           Quit current module, return to main menu
  Ctrl+C      Emergency stop — returns to main menu safely
```

No flags. No arguments. Everything is a prompt.

---

## Modules

### Subdomain Discovery
Runs subfinder and amass against your target domain.
Each subdomain is numbered and classified (web server, mail server,
database server, CDN, nameserver). Option to load from file.

### DNS Intelligence
Runs dig and whois on each subdomain. Extracts A, AAAA, MX, NS, TXT,
SOA, CNAME records. Identifies mail servers, nameservers, and CDN providers.

### Port Scanning
Five scan profiles:
- Quick         — Top 100 ports
- Standard      — Top 1000 ports (nmap default)
- Developer     — Engineer-focused port list (Redis, Mongo, Elastic, Docker, K8s, etc.)
- Full          — All 65535 ports
- Custom        — You define the range

Per-subdomain prompts. Timing control T2 through T5. Service and version detection.

### Web Scanning
Nikto against web-facing subdomains. Checks headers, dangerous files,
outdated server software, misconfigurations.

### Connection Intelligence
SSH into your server to pull live connection data using ss and lsof.
Cross-references all connected IPs against AbuseIPDB, GreyNoise, and Shodan.
Log analysis for timeline reconstruction. Detects unexpected outbound connections.

### Default Credential Check
Tests top default credentials against discovered services.
SSH, Telnet, HTTP Basic Auth, FTP. Reports confirmed or denied.
Stops at confirmation — does not proceed further.

### CVE Lookup
Takes service name and version from nmap results.
Queries NVD API v2.0. Returns CVE IDs, CVSS scores, descriptions.
Color-coded by severity.

### Honeypot
Deploy fake services on chosen ports. Capture attacker details in real time:
source IP, TCP fingerprint, credentials attempted, commands sent, tools used.
Auto-enriches with threat intel. Canary token generation for planted decoys.

### Ping Sweep
ICMP connectivity check across discovered subdomains.
Latency display, host-up confirmation.

---

## Color Reference

```
RED         Critical — open dangerous port, confirmed vulnerability,
            default credentials accepted, known malicious IP
YELLOW      Warning — interesting service, unusual configuration,
            suspicious behavior
GREEN       Clean — port closed, credentials denied, no finding
CYAN        Information headers — subdomain names, module titles
BLUE        Field labels — IP address, record type, service name
MAGENTA     Tool names, section dividers
WHITE       Normal output
DIM         Secondary / verbose output
```

---

## Saving Findings

Nothing is written to disk during a session without your explicit approval.
All findings accumulate in memory.

At the end of any module or the full session:
```
Save findings? [y/N]
Enter save path: /your/chosen/path/
Format: [1] txt  [2] json  [3] html report
```

---

## Legal

This tool is built for authorized testing of systems you own or have
explicit written permission to test.

Unauthorized use against systems you do not own is illegal under the
Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act (UK),
and equivalent laws in every jurisdiction.

---

## Help

At any point during a session type `?` or `h` for context-sensitive help.
From the main menu select `[H] Help` for the full reference.

---

*Built for engineers who test their own infrastructure.*
