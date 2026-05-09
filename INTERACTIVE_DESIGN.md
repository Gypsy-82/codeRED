# Interactive UX Design — Red Recon Framework

## Core Library: InquirerPy

InquirerPy is the engine behind every user interaction in this tool.
Built on prompt_toolkit — the same engine powering IPython and pgcli.
Arrow keys, fuzzy search, multi-select checkboxes, all out of the box.

pip install InquirerPy   ← auto-installed in venv on first run

## Interaction Types Used

### List Select (single choice, arrow keys)
Used for: scan type, module selection, format choice

  ? Select scan profile
  ❯ Quick       — Top 100 ports
    Standard    — Top 1000 ports
    Developer   — Engineer port profile
    Full        — All 65535 ports
    Custom      — Define your own range

### Checkbox Select (multi-select, spacebar to toggle)
Used for: selecting which subdomains to scan, which modules to run

  ? Select subdomains to scan (space to toggle, enter to confirm)
  ❯ ◉  [1] api.example.com          (web server)
    ◉  [2] mail.example.com         (mail server)
    ○  [3] dev.example.com          (web server)
    ◉  [4] db.example.com           (database server)
    ○  [5] cdn.example.com          (CDN)

### Confirm (y/N)
Used for: save prompts, running nmap, deploying honeypot

  ? Run nmap on api.example.com? (y/N)

### Text Input with Validation
Used for: target domain, save path, custom port range

  ? Enter target domain: _
  ? Enter save path: /home/user/findings/_

### Password Input (masked)
Used for: SSH credentials when connecting for connection_intel

  ? SSH password: ********

## Navigation Model

Every screen follows the same pattern:

  ┌─────────────────────────────────────┐
  │  [Module Name]                      │
  │  Target: example.com                │
  │  ─────────────────────────────────  │
  │  [Results displayed above]          │
  │                                     │
  │  ? What do you want to do next?     │
  │  ❯ Act on finding #3               │
  │    Run next module                  │
  │    Save findings so far             │
  │    ? Help                           │
  │    ← Back to main menu              │
  │    ✕ Exit                           │
  └─────────────────────────────────────┘

The user is never stranded. Every screen has a back option and a help option.

## Help System

### Trigger
At any InquirerPy prompt, typing ? or selecting [? Help] shows help.
Ctrl+C always returns safely to the main menu — never crashes.

### Context-Sensitive Help
Help content changes based on which module is active.

  Example — inside port_scan.py:

  ┌─── PORT SCAN HELP ──────────────────────────────────────┐
  │                                                         │
  │  SCAN PROFILES                                          │
  │  Quick     Top 100 ports. Good for fast triage.        │
  │  Standard  Top 1000 (nmap default). Balanced.          │
  │  Developer Engineer-focused: Redis, Mongo, Docker,     │
  │            Elasticsearch, Kubernetes, Kafka, etc.      │
  │  Full      All 65535. Thorough but slow.               │
  │  Custom    Enter your own: 80,443,8080-8090            │
  │                                                        │
  │  TIMING                                                 │
  │  T2  Polite — low noise on the network                 │
  │  T3  Normal — nmap default                             │
  │  T4  Aggressive — recommended for your own systems     │
  │  T5  Insane — fastest, may miss results                │
  │                                                        │
  │  WHAT FEEDS THIS MODULE                                 │
  │  Subdomain list from subfinder/amass or your file.     │
  │                                                        │
  │  WHAT THIS FEEDS                                        │
  │  CVE lookup uses service+version from these results.   │
  │  Cred checker uses open service ports from results.    │
  │                                                        │
  │  Press Enter to return                                  │
  └────────────────────────────────────────────────────────┘

### Global Help (from main menu)

  ┌─── RED RECON — FULL REFERENCE ─────────────────────────┐
  │                                                        │
  │  MODULES                                               │
  │  [1] Subdomain Discovery   subfinder + amass           │
  │  [2] DNS Intelligence      dig + whois + classifier    │
  │  [3] Port Scan             nmap — 5 scan profiles      │
  │  [4] Web Scan              nikto                       │
  │  [5] Connection Intel      ss + lsof + threat intel    │
  │  [6] Default Cred Check    SSH/Telnet/HTTP/FTP         │
  │  [7] CVE Lookup            NVD API v2.0                │
  │  [8] Honeypot              deploy + capture + profile  │
  │  [9] Ping Sweep            ICMP sweep                  │
  │                                                        │
  │  NAVIGATION                                            │
  │  ↑ ↓     Move between options                         │
  │  Enter   Select                                        │
  │  Space   Toggle checkbox (multi-select screens)        │
  │  ?       Help for current screen                       │
  │  q       Back to main menu                             │
  │  Ctrl+C  Safe exit to main menu                        │
  │                                                        │
  │  COLOR GUIDE                                           │
  │  RED      Critical finding                             │
  │  YELLOW   Warning / investigate                        │
  │  GREEN    Clean / no finding                           │
  │  CYAN     Info headers                                 │
  │  BLUE     Field labels                                 │
  │  MAGENTA  Tool names / dividers                        │
  │                                                        │
  │  SAVING                                                │
  │  Nothing saves without your yes.                       │
  │  You choose the path and format at save time.          │
  │                                                        │
  └────────────────────────────────────────────────────────┘

## Why This Is as Powerful as a GUI

A GUI gives you:
  - Visual navigation without memorizing flags     ✓ Arrow key menus
  - See all options at once                        ✓ List + checkbox prompts
  - Multi-select                                   ✓ Checkbox with spacebar
  - Context-sensitive help                         ✓ ? at every prompt
  - Status feedback                                ✓ Rich progress bars + spinners
  - Color-coded results                            ✓ Full Rich color engine
  - Click to drill down                            ✓ Numbered findings, select to act

What the CLI gives you that a GUI cannot:
  - Runs over SSH on a headless server
  - Scriptable if needed later
  - Zero GUI overhead — faster, lighter
  - Pipe output anywhere
  - Lives entirely in the terminal where your other tools live
