import os
import subprocess
import xml.etree.ElementTree as ET

from modules.display import (
    console, section_header, success, warning, critical, info, label, dim,
    port_table, spinner, rule, help_panel, finding,
    confirm, select, text_input, checkbox,
)

_DEV_PORTS = (
    "21,22,23,25,53,80,110,143,389,443,465,587,636,993,995,"
    "1433,1521,2049,2181,2375,2376,2377,2379,2380,"
    "3000,3001,3306,3389,4200,4369,"
    "5000,5001,5173,5432,5601,5672,5900,5985,5986,"
    "6379,6380,6443,7474,7687,"
    "8000,8001,8008,8080,8081,8443,8888,8983,"
    "9000,9090,9092,9200,9300,9418,"
    "10250,10255,11211,15672,27017,27018,50000,61616"
)

_SCAN_PROFILES = {
    "quick":     (["--top-ports", "100"],  "Top 100 ports"),
    "standard":  (["--top-ports", "1000"], "Top 1000 ports"),
    "developer": (["-p", _DEV_PORTS],      "Developer / Engineer profile"),
    "full":      (["-p-"],                  "All 65535 ports"),
}

_TIMING = {
    "T2": ("-T2", "Polite — low noise"),
    "T3": ("-T3", "Normal — nmap default"),
    "T4": ("-T4", "Aggressive — recommended for own systems"),
    "T5": ("-T5", "Insane — fastest, may miss results"),
}

# Ports that trigger automatic findings
_DANGEROUS_PORTS = {
    "21":    ("WARNING",  "FTP open — plaintext credentials, consider SFTP/FTPS"),
    "23":    ("CRITICAL", "Telnet open — unencrypted protocol, credentials in cleartext"),
    "2375":  ("CRITICAL", "Docker daemon exposed without TLS — full container control possible"),
    "2376":  ("WARNING",  "Docker daemon with TLS — verify certificate requirements"),
    "2379":  ("CRITICAL", "etcd exposed — Kubernetes cluster state, secrets readable"),
    "3306":  ("WARNING",  "MySQL/MariaDB exposed — verify firewall restricts access"),
    "5432":  ("WARNING",  "PostgreSQL exposed — verify firewall restricts access"),
    "5900":  ("WARNING",  "VNC exposed — remote desktop access"),
    "3389":  ("WARNING",  "RDP exposed — common brute-force target"),
    "6379":  ("CRITICAL", "Redis exposed — no authentication by default"),
    "8888":  ("WARNING",  "Jupyter Notebook port — may have no authentication"),
    "9090":  ("WARNING",  "Prometheus metrics exposed — potential config disclosure"),
    "9200":  ("CRITICAL", "Elasticsearch exposed — no authentication by default"),
    "10250": ("CRITICAL", "Kubernetes kubelet API exposed — pod/node control possible"),
    "10255": ("WARNING",  "Kubernetes kubelet read-only API exposed"),
    "11211": ("WARNING",  "Memcached exposed — DDoS amplification risk"),
    "15672": ("WARNING",  "RabbitMQ management UI exposed"),
    "27017": ("CRITICAL", "MongoDB exposed — no authentication by default"),
    "50000": ("WARNING",  "Jenkins agent port exposed"),
}


def _run_nmap(target, port_args, timing, sv, os_detect, scripts):
    cmd = ["nmap"] + port_args + [timing]
    if sv:
        cmd.append("-sV")
    if os_detect:
        cmd.append("-O")
    if scripts:
        cmd += ["--script", "default,vuln"]
    cmd += ["-oX", "-", target]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        warning(f"nmap timed out scanning {target}")
        return "", ""
    except FileNotFoundError:
        critical("nmap not found — install: sudo apt install nmap")
        return "", ""


def _parse_nmap_xml(xml_data):
    if not xml_data or not xml_data.strip().startswith("<"):
        return [], None, []

    ports    = []
    os_guess = None
    scripts  = []

    try:
        root = ET.fromstring(xml_data)

        for osmatch in root.findall(".//osmatch"):
            name     = osmatch.get("name", "")
            accuracy = osmatch.get("accuracy", "?")
            os_guess = f"{name}  ({accuracy}% confidence)"
            break

        for host in root.findall("host"):
            for port_elem in host.findall(".//port"):
                state_elem = port_elem.find("state")
                if state_elem is None:
                    continue
                state = state_elem.get("state", "unknown")
                if state not in ("open", "filtered"):
                    continue

                port_id  = port_elem.get("portid", "?")
                protocol = port_elem.get("protocol", "tcp")

                svc     = port_elem.find("service")
                service = version = ""
                if svc is not None:
                    service = svc.get("name", "")
                    parts   = [svc.get("product", ""), svc.get("version", ""), svc.get("extrainfo", "")]
                    version = " ".join(p for p in parts if p)

                # NSE script output per port
                for script_elem in port_elem.findall("script"):
                    scripts.append({
                        "port":   port_id,
                        "script": script_elem.get("id", ""),
                        "output": script_elem.get("output", "")[:200],
                    })

                ports.append({
                    "port":     port_id,
                    "protocol": protocol,
                    "state":    state,
                    "service":  service,
                    "version":  version,
                })

    except ET.ParseError as e:
        warning(f"nmap XML parse error: {e}")

    return ports, os_guess, scripts


def _auto_flag(session, target, ports):
    flagged = False
    for p in ports:
        if p["state"] != "open":
            continue
        port_num = str(p["port"])
        if port_num in _DANGEROUS_PORTS:
            severity, message = _DANGEROUS_PORTS[port_num]
            if severity == "CRITICAL":
                critical(f"Port {port_num}/{p['protocol']} — {message}")
            else:
                warning(f"Port {port_num}/{p['protocol']} — {message}")
            session.add_finding(
                severity, "Port Scan", target,
                f"Port {port_num}/{p['protocol']} open — {message}",
                {"port": port_num, "service": p["service"], "version": p["version"]},
            )
            flagged = True
    return flagged


def run(session):
    section_header("PORT SCAN", "nmap")

    if not session.target:
        warning("No target set.")
        return

    if "nmap" not in session.available_tools:
        critical("nmap not found. Install: sudo apt install nmap")
        confirm("Return to main menu?", default=True)
        return

    # ── Target selection ──────────────────────────────────────────────────────

    scope = select("Scan scope:", [
        {"name": f"Root target only — {session.target}",   "value": "root"},
        {"name": "Select from subdomain list",              "value": "select"} if session.subdomains else None,
        {"name": "? Help",                                  "value": "help"},
        {"name": "← Back",                                 "value": "back"},
    ])

    if scope == "back":
        return
    if scope == "help":
        _show_help()
        return run(session)

    if scope == "root" or not session.subdomains:
        scan_targets = [session.target]
    else:
        choices = [
            {"name": f"[{sd['num']}] {sd['subdomain']}  {sd['ip']}  ({sd['type']})",
             "value": sd["subdomain"]}
            for sd in session.subdomains
        ]
        choices.insert(0, {"name": f"Root: {session.target}", "value": session.target})
        selected = checkbox("Select scan targets:", choices)
        if not selected:
            warning("Nothing selected.")
            return
        scan_targets = selected

    # ── Scan profile ──────────────────────────────────────────────────────────

    profile_key = select("Scan profile:", [
        {"name": "Quick      — Top 100 ports                (fastest)",            "value": "quick"},
        {"name": "Standard   — Top 1000 ports               (nmap default)",       "value": "standard"},
        {"name": "Developer  — Engineer port profile        (Redis, Mongo, Docker, K8s, Kafka…)", "value": "developer"},
        {"name": "Full       — All 65535 ports              (thorough, slow)",      "value": "full"},
        {"name": "Custom     — Enter your own range",                               "value": "custom"},
    ])

    if profile_key == "custom":
        def _validate_ports(val):
            if not val.strip():
                return "Enter a port range"
            return True
        port_range    = text_input("Port range (e.g. 80,443  or  8000-9000  or  22,80,443,8080-8090)", validate=_validate_ports).strip()
        port_args     = ["-p", port_range]
        profile_label = f"Custom: {port_range}"
    else:
        port_args, profile_label = _SCAN_PROFILES[profile_key]

    # ── Timing ────────────────────────────────────────────────────────────────

    timing_key = select("Scan timing:", [
        {"name": "T2 — Polite      (low noise on the network)",          "value": "T2"},
        {"name": "T3 — Normal      (nmap default balance)",              "value": "T3"},
        {"name": "T4 — Aggressive  (recommended for own systems)",       "value": "T4"},
        {"name": "T5 — Insane      (fastest, may miss SYN responses)",   "value": "T5"},
    ])
    timing_flag, _ = _TIMING[timing_key]

    # ── Detection options ─────────────────────────────────────────────────────

    sv = confirm("Service + version detection? (-sV)", default=True)

    is_root    = os.geteuid() == 0
    os_detect  = False
    if is_root:
        os_detect = confirm("OS detection? (-O, requires root)", default=False)
    else:
        dim("OS detection skipped (requires root/sudo)")

    scripts = confirm("Run default NSE scripts? (checks for common vulns, slower)", default=False)

    # ── Confirm ───────────────────────────────────────────────────────────────

    console.print()
    label("Profile", profile_label)
    label("Timing",  timing_key)
    label("Targets", str(len(scan_targets)))
    console.print()

    if not confirm("Start scan?", default=True):
        dim("Scan cancelled.")
        return

    # ── Run ───────────────────────────────────────────────────────────────────

    for target in scan_targets:
        console.print()
        rule(f" nmap — {target}")

        with spinner(f"  Scanning {target}  [{profile_label}]  [{timing_key}]"):
            xml_out, stderr = _run_nmap(target, port_args, timing_flag, sv, os_detect, scripts)

        ports, os_guess, nse_scripts = _parse_nmap_xml(xml_out)

        if not ports:
            warning(f"No open/filtered ports on {target}")
            continue

        if os_guess:
            label("OS Guess", os_guess)
            console.print()

        port_table(ports)
        console.print()

        _auto_flag(session, target, ports)

        if nse_scripts:
            console.print()
            console.rule("[dim_text]  NSE Script Output[/dim_text]")
            for s in nse_scripts[:10]:
                dim(f"  [{s['port']}] {s['script']}: {s['output'][:120]}")

        open_count = sum(1 for p in ports if p["state"] == "open")
        success(f"{open_count} open port(s) on {target}")

        session.port_results[target] = {
            "ports":    ports,
            "os_guess": os_guess,
            "scripts":  nse_scripts,
        }

    console.print()
    success(f"Port scan complete — {len(scan_targets)} target(s)")


def _show_help():
    help_panel("PORT SCAN — HELP", {
        "SCAN PROFILES": [
            "Quick      Top 100 most common ports. Fast triage.",
            "Standard   Top 1000 ports — nmap default ranking by internet frequency.",
            "Developer  Custom engineer-focused list. Critical ports NOT in top-1000:",
            "             Redis 6379, MongoDB 27017, Elasticsearch 9200,",
            "             Docker daemon 2375, Kubernetes API 6443,",
            "             etcd 2379, Jupyter 8888, Kafka 9092, RabbitMQ 5672,",
            "             Kibana 5601, Neo4j 7474, Vite 5173, Angular 4200",
            "Full       All 65535 ports. Use T4, expect 5-20+ minutes.",
            "Custom     Any range: 80,443  /  8000-9000  /  22,80,443,8080-8090",
        ],
        "TIMING": [
            "T2  Polite — slow, minimal IDS noise",
            "T3  Normal — nmap default",
            "T4  Aggressive — use on your own systems, fast",
            "T5  Insane — maximum speed, some packets may be dropped",
        ],
        "AUTO-FLAGGED DANGEROUS PORTS": [
            "2375  Docker daemon (no TLS)  →  CRITICAL",
            "2379  etcd                   →  CRITICAL",
            "6379  Redis                  →  CRITICAL",
            "9200  Elasticsearch          →  CRITICAL",
            "27017 MongoDB                →  CRITICAL",
            "10250 Kubernetes kubelet     →  CRITICAL",
            "23    Telnet                 →  CRITICAL",
            "21    FTP                    →  WARNING",
            "3306  MySQL                  →  WARNING",
            "5432  PostgreSQL             →  WARNING",
            "8888  Jupyter Notebook       →  WARNING",
            "3389  RDP                    →  WARNING",
        ],
        "WHAT THIS FEEDS": [
            "CVE Lookup uses service + version strings from scan results.",
            "Cred Check uses open service ports to target default creds.",
        ],
    })
