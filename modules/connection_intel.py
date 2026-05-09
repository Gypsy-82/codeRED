import os
import re

import paramiko
import requests

from rich.table import Table
from rich import box

from modules.display import (
    console, section_header, success, warning, critical, info, label, dim,
    spinner, help_panel, rule,
    confirm, select, text_input,
)

_GREYNOISE_URL  = "https://api.greynoise.io/v3/community/{ip}"
_ABUSEIPDB_URL  = "https://api.abuseipdb.com/api/v2/check"

_PRIVATE_RE = [
    re.compile(r"^10\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^127\."),
    re.compile(r"^::1$"),
    re.compile(r"^fd[0-9a-f]{2}:", re.I),
]


def _is_private(ip):
    return any(p.match(ip) for p in _PRIVATE_RE)


def _ssh_connect(host, user, password=None, key_path=None):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        if key_path:
            client.connect(host, username=user, key_filename=key_path, timeout=10)
        else:
            client.connect(host, username=user, password=password,
                           timeout=10, look_for_keys=False, allow_agent=False)
        return client
    except Exception:
        return None


def _remote(client, cmd):
    try:
        _, stdout, _ = client.exec_command(cmd, timeout=20)
        return stdout.read().decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _parse_ss(raw):
    conns = []
    for line in raw.strip().split("\n"):
        if not line.strip() or line.startswith("Netid"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        netid   = parts[0]
        state   = parts[1]
        local   = parts[3]
        peer    = parts[4]
        process = " ".join(parts[5:]) if len(parts) > 5 else ""

        m         = re.search(r'"([^"]+)",pid=(\d+)', process)
        proc_name = m.group(1) if m else ""
        proc_pid  = m.group(2) if m else ""

        # Strip IPv6 brackets, extract IP only
        peer_ip = re.sub(r":\d+$", "", peer).strip("[]") if peer not in ("*", "") else peer

        conns.append({
            "proto": netid, "state": state,
            "local": local, "peer":  peer,
            "peer_ip": peer_ip,
            "process": proc_name, "pid": proc_pid,
        })
    return conns


def _parse_who(raw):
    users = []
    for line in raw.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 3:
            users.append({
                "user": parts[0],
                "tty":  parts[1],
                "from": parts[4].strip("()") if len(parts) > 4 else "local",
                "time": f"{parts[2]} {parts[3]}" if len(parts) > 3 else parts[2],
            })
    return users


def _parse_last(raw):
    sessions = []
    for line in raw.strip().split("\n")[:25]:
        if not line.strip() or "wtmp" in line or "btmp" in line:
            continue
        parts = line.split()
        if len(parts) >= 3:
            sessions.append({
                "user": parts[0],
                "tty":  parts[1],
                "from": parts[2],
                "when": " ".join(parts[3:7]) if len(parts) > 6 else "",
            })
    return sessions


def _render_connections(conns):
    established = [c for c in conns if c["state"] == "ESTAB"]
    listening   = [c for c in conns if c["state"] == "LISTEN"]
    foreign_ips = set()

    if established:
        console.print(f"\n  [header]Established Connections  ({len(established)})[/header]")
        t = Table(box=box.SIMPLE_HEAVY, header_style="header", padding=(0, 1))
        t.add_column("Proto",   width=5)
        t.add_column("Local",   min_width=22)
        t.add_column("Peer",    min_width=22, style="info")
        t.add_column("Process", min_width=14, style="tool")
        t.add_column("PID",     width=7,  style="dim_text")

        for c in established:
            ip = c.get("peer_ip", "")
            if ip and not _is_private(ip) and ip not in ("*", "0.0.0.0", "[::]", ""):
                foreign_ips.add(ip)
            t.add_row(c["proto"], c["local"], c["peer"], c["process"], c["pid"])
        console.print(t)

    if listening:
        console.print(f"\n  [header]Listening Ports  ({len(listening)})[/header]")
        t = Table(box=box.SIMPLE_HEAVY, header_style="header", padding=(0, 1))
        t.add_column("Proto",   width=5)
        t.add_column("Address", min_width=24)
        t.add_column("Process", min_width=14, style="tool")
        t.add_column("PID",     width=7,  style="dim_text")

        for c in listening:
            t.add_row(c["proto"], c["local"], c["process"], c["pid"])
        console.print(t)

    return foreign_ips


def _greynoise(ip):
    try:
        r = requests.get(
            _GREYNOISE_URL.format(ip=ip),
            timeout=5,
            headers={"User-Agent": "red-recon/1.0"},
        )
        if r.status_code == 200:
            d = r.json()
            return {
                "noise":  d.get("noise", False),
                "riot":   d.get("riot",  False),
                "name":   d.get("name",  ""),
                "class":  d.get("classification", ""),
                "msg":    d.get("message", ""),
            }
        return {"msg": f"HTTP {r.status_code}"}
    except Exception:
        return {"msg": "GreyNoise unavailable"}


def _abuseipdb(ip, key):
    try:
        r = requests.get(
            _ABUSEIPDB_URL,
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": key, "Accept": "application/json"},
            timeout=5,
        )
        if r.status_code == 200:
            d = r.json().get("data", {})
            return {
                "score":   d.get("abuseConfidenceScore", 0),
                "reports": d.get("totalReports", 0),
                "country": d.get("countryCode", "?"),
                "isp":     d.get("isp", "?"),
                "tor":     d.get("isTor", False),
                "seen":    (d.get("lastReportedAt") or "")[:10],
            }
        return {}
    except Exception:
        return {}


def run(session):
    section_header("CONNECTION INTELLIGENCE", "ss + lsof + threat intel")

    if not session.target:
        warning("No target set.")
        return

    action = select("Action:", [
        {"name": "SSH into server — pull live connection data", "value": "ssh"},
        {"name": "? Help",                                      "value": "help"},
        {"name": "← Back",                                     "value": "back"},
    ])

    if action == "back":
        return
    if action == "help":
        _show_help()
        return run(session)

    # SSH auth
    console.print()
    info("Credentials for YOUR server (used to read live connection state):")
    ssh_host = text_input("SSH host / IP", default=session.target).strip()
    ssh_user = text_input("Username",      default="root").strip()

    auth = select("Authentication:", [
        {"name": "Password",   "value": "password"},
        {"name": "SSH key",    "value": "key"},
    ])

    if auth == "password":
        from InquirerPy import inquirer
        ssh_pass = inquirer.secret(message="Password").execute()
        key_path = None
    else:
        ssh_pass = None
        key_path = os.path.expanduser(text_input("Key path", default="~/.ssh/id_rsa").strip())

    with spinner(f"  Connecting to {ssh_host}…"):
        client = _ssh_connect(ssh_host, ssh_user, ssh_pass, key_path)

    if not client:
        critical(f"SSH connection failed to {ssh_host}")
        return

    success(f"Connected — {ssh_host}")
    console.print()

    # Collect remote data
    with spinner("  ss -antp"):
        ss_raw   = _remote(client, "ss -antp 2>/dev/null || netstat -antp 2>/dev/null")
    with spinner("  who"):
        who_raw  = _remote(client, "who 2>/dev/null")
    with spinner("  last -n 25"):
        last_raw = _remote(client, "last -n 25 2>/dev/null")
    with spinner("  lsof -i (top 40 lines)"):
        lsof_raw = _remote(client, "lsof -i 2>/dev/null | head -40")

    client.close()

    # Parse and render
    conns       = _parse_ss(ss_raw)
    foreign_ips = _render_connections(conns)

    # Active users
    users = _parse_who(who_raw)
    if users:
        console.print(f"\n  [header]Currently Logged In  ({len(users)})[/header]")
        for u in users:
            c = "warning" if u["from"] not in ("local", "") else "dim_text"
            console.print(
                f"    [{c}]→[/{c}]  [highlight]{u['user']:<12}[/highlight]  "
                f"from [info]{u['from']:<20}[/info]  {u['time']}"
            )

    # Login history
    sessions = _parse_last(last_raw)
    if sessions:
        console.print(f"\n  [header]Recent Login History  (last 25)[/header]")
        t = Table(box=box.SIMPLE_HEAVY, header_style="header", padding=(0, 1))
        t.add_column("User",   style="highlight", width=14)
        t.add_column("From",   style="info",      min_width=20)
        t.add_column("When",   style="dim_text",  min_width=24)
        for s in sessions[:15]:
            t.add_row(s["user"], s["from"], s["when"])
        console.print(t)

    # lsof snapshot
    if lsof_raw.strip():
        console.print(f"\n  [header]Open Network Connections (lsof)[/header]")
        for line in lsof_raw.strip().split("\n")[:20]:
            dim(f"  {line}")

    # Store
    session.conn_results[ssh_host] = {
        "connections": conns,
        "users":       users,
        "sessions":    sessions,
    }

    # Flag active logins from external IPs
    for u in users:
        if u["from"] not in ("local", "", "console", "pts/0"):
            session.add_finding(
                "WARNING", "Connection Intel", ssh_host,
                f"Active session from {u['from']} — user: {u['user']}",
            )

    # Threat intel on foreign IPs
    if not foreign_ips:
        console.print()
        info("No external IPs found in established connections.")
        success("Connection intelligence complete.")
        return

    console.print()
    info(f"{len(foreign_ips)} external IP(s) in established connections.")

    if not confirm("Run threat intel on these IPs? (GreyNoise free, optional AbuseIPDB)", default=True):
        success("Connection intelligence complete.")
        return

    abuseipdb_key = None
    if confirm("AbuseIPDB API key available?", default=False):
        abuseipdb_key = text_input("AbuseIPDB API key").strip() or None

    for ip in sorted(foreign_ips):
        console.print()
        rule(f" Threat Intel — {ip}")

        with spinner(f"  GreyNoise → {ip}"):
            gn = _greynoise(ip)

        if gn.get("noise"):
            critical(f"GreyNoise: KNOWN SCANNER/ATTACKER — {gn.get('name', '')}  [{gn.get('class', '')}]")
            session.add_finding(
                "CRITICAL", "Connection Intel", ssh_host,
                f"Active connection from known attacker {ip} — {gn.get('name', '')}",
                {"ip": ip, "greynoise": gn},
            )
        elif gn.get("riot"):
            success(f"GreyNoise: RIOT — trusted service  ({gn.get('name', '')})")
        else:
            label("GreyNoise", gn.get("msg", "not in database"))

        if abuseipdb_key:
            with spinner(f"  AbuseIPDB → {ip}"):
                ab = _abuseipdb(ip, abuseipdb_key)
            if ab:
                score = ab.get("score", 0)
                c     = "critical" if score > 50 else "warning" if score > 10 else "clean"
                console.print(
                    f"  [label]AbuseIPDB[/label]  [{c}]{score}%[/{c}]  "
                    f"reports: {ab['reports']}  country: {ab['country']}  ISP: {ab['isp']}"
                )
                if ab.get("tor"):
                    warning("TOR exit node")
                if score > 50:
                    session.add_finding(
                        "CRITICAL", "Connection Intel", ssh_host,
                        f"High-abuse IP {ip} in active connection — AbuseIPDB score {score}%",
                        {"ip": ip, "abuseipdb": ab},
                    )

    console.print()
    success("Connection intelligence complete.")


def _show_help():
    help_panel("CONNECTION INTELLIGENCE — HELP", {
        "WHAT IT COLLECTS (via SSH)": [
            "ss -antp     All TCP connections — state, local port, peer IP, process name + PID",
            "who          Currently logged-in users with source IP",
            "last -n 25   Recent login history — user, source IP, timestamp",
            "lsof -i      Open network file descriptors per process",
        ],
        "THREAT INTEL SOURCES": [
            "GreyNoise  (free, no key required)",
            "  Classifies IPs: mass-scanner, targeted attacker, RIOT (trusted service)",
            "AbuseIPDB  (free tier API key — abuseipdb.com)",
            "  Abuse confidence score 0–100%, total reports, ISP, country, TOR flag",
        ],
        "RED FLAGS TO LOOK FOR": [
            "ESTABLISHED connection to unknown external IP from unknown process",
            "Active login from unrecognised source IP",
            "GreyNoise 'noise=true' — this IP is scanning the internet",
            "AbuseIPDB score > 50% — this IP has significant report history",
            "Process name missing in connection — possible rootkit indicator",
        ],
    })
