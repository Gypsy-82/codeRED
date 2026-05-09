import ftplib
import socket
import warnings

import paramiko
import requests
from urllib3.exceptions import InsecureRequestWarning

from modules.display import (
    console, section_header, success, warning, critical, info, label, dim,
    spinner, help_panel, rule,
    confirm, select, text_input, checkbox,
)

warnings.filterwarnings("ignore", category=InsecureRequestWarning)

_DEFAULT_CREDS = [
    ("admin",         "admin"),
    ("admin",         "password"),
    ("admin",         ""),
    ("admin",         "1234"),
    ("admin",         "12345"),
    ("root",          "root"),
    ("root",          ""),
    ("root",          "password"),
    ("root",          "toor"),
    ("user",          "user"),
    ("guest",         "guest"),
    ("test",          "test"),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("pi",            "raspberry"),
    ("ubnt",          "ubnt"),
    ("cisco",         "cisco"),
    ("admin",         "admin123"),
    ("service",       "service"),
    ("support",       "support"),
]

_SSH_PORTS    = {22, 2222}
_FTP_PORTS    = {21}
_TELNET_PORTS = {23}
_HTTP_PORTS   = {80, 8080, 8000, 8001, 8008, 8081, 3000, 5000, 9000}
_HTTPS_PORTS  = {443, 8443}


def _try_ssh(host, port, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host, port=port, username=username, password=password,
            timeout=5, look_for_keys=False, allow_agent=False,
            banner_timeout=10,
        )
        client.close()
        return True
    except paramiko.AuthenticationException:
        return False
    except Exception:
        return None


def _try_ftp(host, port, username, password):
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=5)
        ftp.login(username, password)
        ftp.quit()
        return True
    except ftplib.error_perm:
        return False
    except Exception:
        return None


def _try_http_basic(host, port, username, password, ssl=False):
    scheme = "https" if ssl else "http"
    try:
        r = requests.get(
            f"{scheme}://{host}:{port}/",
            auth=(username, password),
            timeout=5, verify=False, allow_redirects=True,
        )
        if r.status_code == 200:
            return True
        if r.status_code == 401:
            return False
        return None
    except requests.RequestException:
        return None


def _try_telnet(host, port, username, password):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host, port))
        s.recv(1024)
        s.sendall(f"{username}\r\n".encode())
        s.recv(1024)
        s.sendall(f"{password}\r\n".encode())
        resp = s.recv(2048).decode("utf-8", errors="ignore").lower()
        s.close()
        if any(w in resp for w in ["incorrect", "failed", "denied", "invalid", "error", "login:"]):
            return False
        if any(w in resp for w in ["welcome", "$", "#", ">", "last login"]):
            return True
        return None
    except Exception:
        return None


_CHECKERS = {
    "ssh":    _try_ssh,
    "ftp":    _try_ftp,
    "telnet": _try_telnet,
    "http":   lambda h, p, u, pw: _try_http_basic(h, p, u, pw, ssl=False),
    "https":  lambda h, p, u, pw: _try_http_basic(h, p, u, pw, ssl=True),
}


def _services_from_session(session):
    services = []
    for target, result in session.port_results.items():
        for p in result.get("ports", []):
            if p["state"] != "open":
                continue
            port = int(p["port"])
            svc  = p.get("service", "").lower()

            if "ssh"    in svc or port in _SSH_PORTS:    services.append((target, port, "ssh"))
            elif "ftp"  in svc or port in _FTP_PORTS:    services.append((target, port, "ftp"))
            elif "telnet" in svc or port in _TELNET_PORTS: services.append((target, port, "telnet"))
            elif port in _HTTPS_PORTS or "https" in svc:  services.append((target, port, "https"))
            elif port in _HTTP_PORTS  or "http"  in svc:  services.append((target, port, "http"))

    return services


def run(session):
    section_header("DEFAULT CREDENTIAL CHECK", "SSH / Telnet / HTTP / FTP")

    console.print()
    console.print("  [dim_text]Confirm the door is unlocked — don't walk through it.[/dim_text]")
    console.print("  [dim_text]Connects, attempts default credentials, reports confirmed/denied.[/dim_text]")
    console.print("  [dim_text]Stops at first confirmed hit. No session retained. No command execution.[/dim_text]")
    console.print()

    if not session.target:
        warning("No target set.")
        return

    detected = _services_from_session(session)

    choices = []
    if detected:
        choices.append({
            "name":  f"From port scan results  ({len(detected)} services detected)",
            "value": "scan",
        })
    choices += [
        {"name": "Manual — enter host, port, service", "value": "manual"},
        {"name": "? Help",                             "value": "help"},
        {"name": "← Back",                            "value": "back"},
    ]

    mode = select("Target source:", choices)

    if mode == "back":
        return
    if mode == "help":
        _show_help()
        return run(session)

    if mode == "manual" or not detected:
        host = text_input("Host / IP", default=session.target).strip()

        def _val_port(v):
            return True if v.strip().isdigit() and 1 <= int(v.strip()) <= 65535 else "Enter a valid port number"

        port = int(text_input("Port", validate=_val_port).strip())
        svc  = select("Service type:", [
            {"name": "SSH",         "value": "ssh"},
            {"name": "FTP",         "value": "ftp"},
            {"name": "Telnet",      "value": "telnet"},
            {"name": "HTTP Basic",  "value": "http"},
            {"name": "HTTPS Basic", "value": "https"},
        ])
        targets = [(host, port, svc)]
    else:
        svc_choices = [{"name": f"{t[0]}:{t[1]}  ({t[2]})", "value": i} for i, t in enumerate(detected)]
        selected    = checkbox("Select services to test:", svc_choices)
        if not selected:
            warning("Nothing selected.")
            return
        targets = [detected[i] for i in selected]

    cred_mode = select("Credential set:", [
        {"name": "Top 20 defaults  (recommended)",   "value": "top20"},
        {"name": "Top 5 only       (fastest)",        "value": "top5"},
        {"name": "Custom pair      (specific test)",  "value": "custom"},
    ])

    if cred_mode == "top5":
        creds = _DEFAULT_CREDS[:5]
    elif cred_mode == "custom":
        u     = text_input("Username").strip()
        p     = text_input("Password (leave blank for empty)").strip()
        creds = [(u, p)]
    else:
        creds = _DEFAULT_CREDS

    console.print()
    label("Targets",    str(len(targets)))
    label("Cred pairs", str(len(creds)))
    console.print()

    if not confirm("Start credential check?", default=True):
        dim("Cancelled.")
        return

    for host, port, svc in targets:
        console.print()
        rule(f" {svc.upper()} — {host}:{port}")

        checker   = _CHECKERS.get(svc)
        confirmed = False

        for username, password in creds:
            pw_display = "(empty)" if password == "" else password

            result = checker(host, port, username, password) if checker else None

            if result is True:
                critical(f"CONFIRMED  {username} : {pw_display}")
                session.add_finding(
                    "CRITICAL", "Cred Check", f"{host}:{port}",
                    f"{svc.upper()} default credentials accepted — {username}:{pw_display}",
                    {"host": host, "port": str(port), "service": svc,
                     "username": username, "password": pw_display},
                )
                confirmed = True
                break
            elif result is False:
                dim(f"  denied   {username} : {pw_display}")
            else:
                dim(f"  no conn  {username} : {pw_display}")

        if not confirmed:
            success(f"No default credentials accepted on {host}:{port}")

        session.cred_results[f"{host}:{port}"] = {
            "service":   svc,
            "confirmed": confirmed,
        }

    console.print()
    success("Credential check complete.")


def _show_help():
    help_panel("DEFAULT CREDENTIAL CHECK — HELP", {
        "PHILOSOPHY": [
            "Proof-of-concept only. Confirm the door is unlocked — don't walk through it.",
            "Connects, attempts credentials, reports confirmed or denied.",
            "Stops immediately on first confirmed hit. No session is retained.",
            "No command execution. No privilege escalation.",
        ],
        "SERVICES": [
            "SSH     paramiko full handshake. No host key verification (testing own system).",
            "FTP     ftplib standard Python login.",
            "Telnet  Raw socket — reads banner, sends creds, parses response.",
            "HTTP    requests Basic Auth header — checks for 200 vs 401.",
            "HTTPS   Same as HTTP with TLS, verify=False (testing own cert).",
        ],
        "DEFAULT CREDENTIALS (top 5)": [
            "admin:admin  admin:password  admin:(empty)  root:root  root:(empty)",
            "Full list of 20 includes: pi:raspberry, ubnt:ubnt, cisco:cisco,",
            "  service:service, administrator:administrator, and common variations.",
        ],
    })
