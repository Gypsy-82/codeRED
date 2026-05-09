import os
import queue
import re
import secrets
import socket
import string
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

import paramiko
import requests

from modules.display import (
    console, section_header, success, warning, critical, info, label, dim,
    spinner, help_panel, rule, panel,
    confirm, select, text_input, checkbox,
)

_EVENT_QUEUE   = queue.Queue()
_STOP_EVENT    = threading.Event()
_CAPTURED      = []
_HOST_KEY      = None


# ── SSH honeypot ────────────────────────────────────────────────────────────────

class _SSHInterface(paramiko.ServerInterface):
    def __init__(self, ip, port):
        self.ip   = ip
        self.port = port
        self._e   = threading.Event()

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        _EVENT_QUEUE.put({
            "type": "ssh_cred", "service": "SSH",
            "ip": self.ip, "port": self.port,
            "time": _ts(), "data": f"{username}:{password}",
        })
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        _EVENT_QUEUE.put({
            "type": "ssh_pubkey", "service": "SSH",
            "ip": self.ip, "port": self.port,
            "time": _ts(), "data": f"{username} [{key.get_name()}]",
        })
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password,publickey"


def _handle_ssh_conn(sock, addr):
    global _HOST_KEY
    try:
        transport = paramiko.Transport(sock)
        transport.add_server_key(_HOST_KEY)
        server = _SSHInterface(addr[0], addr[1])
        _EVENT_QUEUE.put({
            "type": "connect", "service": "SSH",
            "ip": addr[0], "port": addr[1], "time": _ts(), "data": "",
        })
        try:
            transport.start_server(server=server)
            transport.accept(20)
        except Exception:
            pass
        client_ver = getattr(transport, "remote_version", "unknown")
        if client_ver and client_ver != "unknown":
            _EVENT_QUEUE.put({
                "type": "ssh_banner", "service": "SSH",
                "ip": addr[0], "port": addr[1], "time": _ts(),
                "data": client_ver,
            })
    except Exception:
        pass
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _ssh_listener(bind_port):
    global _HOST_KEY
    if _HOST_KEY is None:
        _HOST_KEY = paramiko.RSAKey.generate(2048)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.settimeout(1.0)
    try:
        srv.bind(("0.0.0.0", bind_port))
        srv.listen(5)
        while not _STOP_EVENT.is_set():
            try:
                conn, addr = srv.accept()
                threading.Thread(target=_handle_ssh_conn, args=(conn, addr), daemon=True).start()
            except socket.timeout:
                continue
    except OSError as e:
        _EVENT_QUEUE.put({"type": "error", "service": f"SSH:{bind_port}", "data": str(e),
                          "ip": "", "port": bind_port, "time": _ts()})
    finally:
        srv.close()


# ── HTTP honeypot ───────────────────────────────────────────────────────────────

def _make_http_handler(service_label):
    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _capture(self, body=""):
            ev = {
                "type":    "http_request",
                "service": service_label,
                "ip":      self.client_address[0],
                "port":    self.client_address[1],
                "time":    _ts(),
                "data":    f"{self.command} {self.path}",
            }
            ua = self.headers.get("User-Agent", "")
            if ua:
                ev["data"] += f"  UA: {ua[:60]}"
            if body:
                ev["data"] += f"  BODY: {body[:120]}"
            _EVENT_QUEUE.put(ev)

        def do_GET(self):
            self._capture()
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="Admin"')
            self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>401 Unauthorized</h1></body></html>")

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length).decode("utf-8", errors="ignore") if length else ""
            self._capture(body)
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="Admin"')
            self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>401 Unauthorized</h1></body></html>")

    return _Handler


def _http_listener(bind_port, label="HTTP"):
    try:
        srv = HTTPServer(("0.0.0.0", bind_port), _make_http_handler(label))
        srv.timeout = 1.0
        while not _STOP_EVENT.is_set():
            srv.handle_request()
        srv.server_close()
    except OSError as e:
        _EVENT_QUEUE.put({"type": "error", "service": f"HTTP:{bind_port}", "data": str(e),
                          "ip": "", "port": bind_port, "time": _ts()})


# ── Generic TCP honeypot ────────────────────────────────────────────────────────

def _handle_tcp_conn(conn, addr, banner, service_label):
    try:
        conn.settimeout(10)
        conn.sendall(banner.encode() + b"\r\n")
        data = b""
        try:
            data = conn.recv(2048)
        except Exception:
            pass
        _EVENT_QUEUE.put({
            "type":    "tcp_data",
            "service": service_label,
            "ip":      addr[0],
            "port":    addr[1],
            "time":    _ts(),
            "data":    data.decode("utf-8", errors="ignore")[:200].strip(),
        })
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _tcp_listener(bind_port, banner, service_label):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.settimeout(1.0)
    try:
        srv.bind(("0.0.0.0", bind_port))
        srv.listen(5)
        while not _STOP_EVENT.is_set():
            try:
                conn, addr = srv.accept()
                _EVENT_QUEUE.put({
                    "type": "connect", "service": service_label,
                    "ip": addr[0], "port": addr[1], "time": _ts(), "data": "",
                })
                threading.Thread(
                    target=_handle_tcp_conn, args=(conn, addr, banner, service_label),
                    daemon=True,
                ).start()
            except socket.timeout:
                continue
    except OSError as e:
        _EVENT_QUEUE.put({"type": "error", "service": f"{service_label}:{bind_port}",
                          "data": str(e), "ip": "", "port": bind_port, "time": _ts()})
    finally:
        srv.close()


# ── Threat intel enrichment ─────────────────────────────────────────────────────

def _greynoise(ip):
    try:
        r = requests.get(
            f"https://api.greynoise.io/v3/community/{ip}",
            timeout=4, headers={"User-Agent": "red-recon/1.0"},
        )
        if r.status_code == 200:
            d = r.json()
            return f"noise={d.get('noise')} riot={d.get('riot')} name={d.get('name','')} [{d.get('classification','')}]"
        return f"HTTP {r.status_code}"
    except Exception:
        return "unavailable"


# ── Display ────────────────────────────────────────────────────────────────────

def _ts():
    return datetime.utcnow().strftime("%H:%M:%S")


_TYPE_STYLE = {
    "connect":     ("cyan",       "CONNECT"),
    "ssh_cred":    ("bold red",   "CRED ATTEMPT"),
    "ssh_pubkey":  ("yellow",     "PUBKEY ATTEMPT"),
    "ssh_banner":  ("blue",       "CLIENT VERSION"),
    "http_request":("yellow",     "HTTP REQUEST"),
    "tcp_data":    ("cyan",       "DATA RECEIVED"),
    "error":       ("dim",        "LISTENER ERROR"),
}


def _render_event(ev):
    style, label_str = _TYPE_STYLE.get(ev.get("type", ""), ("white", ev.get("type", "?")))
    ip      = ev.get("ip", "")
    service = ev.get("service", "")
    data    = ev.get("data", "")
    ts      = ev.get("time", _ts())

    console.print(
        f"  [dim_text]{ts}[/dim_text]  "
        f"[{style}]{label_str:<16}[/{style}]  "
        f"[info]{service:<8}[/info]  "
        f"[highlight]{ip:<18}[/highlight]  "
        f"[white]{data[:80]}[/white]"
    )


# ── Canary tokens ───────────────────────────────────────────────────────────────

def _random_token(length=32):
    return secrets.token_hex(length // 2)


def _generate_canary_files(save_dir):
    db_pass  = _random_token(16)
    api_key  = _random_token(20)
    secret   = _random_token(24)

    env_content = f"""# Database
DATABASE_URL=postgresql://admin:{db_pass}@db.internal:5432/production
DB_PASSWORD={db_pass}

# API Keys
API_SECRET_KEY={api_key}
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7{_random_token(6).upper()}
AWS_SECRET_ACCESS_KEY={secret}

# App
SECRET_KEY={_random_token(16)}
DEBUG=False
"""

    files = {
        ".env":            env_content,
        ".env.production": env_content.replace("DEBUG=False", "DEBUG=False\nENV=production"),
        "config.backup":   f"[credentials]\nusername=admin\npassword={db_pass}\napi_key={api_key}\n",
    }

    created = []
    for filename, content in files.items():
        path = os.path.join(save_dir, filename)
        with open(path, "w") as f:
            f.write(content)
        created.append(path)

    return created, db_pass, api_key


# ── Main entry ─────────────────────────────────────────────────────────────────

def run(session):
    section_header("HONEYPOT", "deploy + capture + profile")

    action = select("Action:", [
        {"name": "Deploy fake service listener(s)", "value": "deploy"},
        {"name": "Generate canary token files",     "value": "canary"},
        {"name": "? Help",                          "value": "help"},
        {"name": "← Back",                         "value": "back"},
    ])

    if action == "back":
        return
    if action == "help":
        _show_help()
        return run(session)

    if action == "canary":
        _run_canary()
        return

    _run_deploy(session)


def _run_canary():
    section_header("CANARY TOKEN FILES", "plant decoy credentials")

    console.print()
    console.print("  [dim_text]Canary files contain fake credentials that look real.[/dim_text]")
    console.print("  [dim_text]If an attacker finds and uses them, you see the attempt.[/dim_text]")
    console.print("  [dim_text]Plant these in web roots, backup dirs, or dev folders.[/dim_text]")
    console.print()

    save_dir = text_input(
        "Directory to save canary files",
        default=os.path.expanduser("~/canary_tokens/"),
    ).strip()

    os.makedirs(save_dir, exist_ok=True)

    if not confirm(f"Generate canary files in {save_dir}?", default=True):
        dim("Cancelled.")
        return

    files, db_pass, api_key = _generate_canary_files(save_dir)

    success("Canary files created:")
    for f in files:
        info(f"  {f}")

    console.print()
    warning("These credentials are FAKE — do not use them anywhere real.")
    label("Fake DB password", db_pass)
    label("Fake API key",     api_key)
    console.print()
    info("Monitor: if these credentials appear in your connection logs, an attacker has your files.")


def _run_deploy(session):
    services = checkbox("Select fake services to deploy:", [
        {"name": "SSH    (port 22 or custom)",      "value": "ssh"},
        {"name": "HTTP   (port 80 or custom)",      "value": "http"},
        {"name": "Telnet (port 23 or custom)",      "value": "telnet"},
        {"name": "FTP    (port 21 or custom)",      "value": "ftp"},
        {"name": "Custom TCP port + banner",        "value": "custom"},
    ])

    if not services:
        warning("Nothing selected.")
        return

    listeners = []
    for svc in services:
        if svc == "ssh":
            port = int(text_input("SSH listen port", default="22").strip())
            listeners.append(("SSH", port, _ssh_listener, (port,)))
        elif svc == "http":
            port = int(text_input("HTTP listen port", default="80").strip())
            listeners.append(("HTTP", port, _http_listener, (port, "HTTP")))
        elif svc == "telnet":
            port   = int(text_input("Telnet listen port", default="23").strip())
            banner = "Debian GNU/Linux telnetd"
            listeners.append(("Telnet", port, _tcp_listener, (port, banner, "Telnet")))
        elif svc == "ftp":
            port   = int(text_input("FTP listen port", default="21").strip())
            banner = "220 FTP server ready"
            listeners.append(("FTP", port, _tcp_listener, (port, banner, "FTP")))
        elif svc == "custom":
            port   = int(text_input("Custom TCP port").strip())
            banner = text_input("Fake banner to send on connect", default="220 Service Ready").strip()
            listeners.append(("Custom", port, _tcp_listener, (port, banner, f"TCP:{port}")))

    duration = select("Run for:", [
        {"name": "30 minutes",             "value": 1800},
        {"name": "1 hour",                 "value": 3600},
        {"name": "Until manually stopped", "value": 0},
    ])

    console.print()
    for svc, port, _, _ in listeners:
        label(f"{svc}", f"listening on port {port}")
    console.print()

    if not confirm("Deploy honeypot listeners?", default=True):
        dim("Cancelled.")
        return

    # Start listeners
    _STOP_EVENT.clear()
    _CAPTURED.clear()
    while not _EVENT_QUEUE.empty():
        _EVENT_QUEUE.get_nowait()

    threads = []
    for _, _, fn, args in listeners:
        t = threading.Thread(target=fn, args=args, daemon=True)
        t.start()
        threads.append(t)

    console.print()
    console.rule("[bold red]  HONEYPOT ACTIVE[/bold red]")
    console.print()
    console.print("  [dim_text]Listening for connections. Press Ctrl+C to stop.[/dim_text]")
    console.print("  [dim_text]TIMESTAMP        EVENT            SERVICE   SOURCE IP          DATA[/dim_text]")
    console.rule()
    console.print()

    start  = time.time()
    try:
        while True:
            if duration > 0 and (time.time() - start) >= duration:
                break

            try:
                ev = _EVENT_QUEUE.get(timeout=0.5)
                _render_event(ev)
                _CAPTURED.append(ev)

                # Auto-enrich new unique IPs
                ip = ev.get("ip", "")
                if ip and ev.get("type") in ("connect", "ssh_cred"):
                    existing = [c.get("ip") for c in _CAPTURED if c.get("_enriched")]
                    if ip not in existing:
                        ev["_enriched"] = True
                        with spinner(f"  GreyNoise → {ip}"):
                            gn = _greynoise(ip)
                        console.print(f"  [dim_text]  GreyNoise: {gn}[/dim_text]")
                        if "noise=True" in gn:
                            session.add_finding(
                                "CRITICAL", "Honeypot", session.target or "honeypot",
                                f"Known scanner/attacker hit honeypot — {ip}",
                                {"ip": ip, "greynoise": gn, "events": len(_CAPTURED)},
                            )

            except queue.Empty:
                continue

    except KeyboardInterrupt:
        pass

    _STOP_EVENT.set()
    console.print()
    console.rule("[dim_text]  Honeypot stopped[/dim_text]")
    console.print()
    info(f"Captured {len(_CAPTURED)} event(s) during session.")

    if _CAPTURED:
        unique_ips = {e.get("ip") for e in _CAPTURED if e.get("ip")}
        info(f"Unique source IPs: {len(unique_ips)}")
        for ip in sorted(unique_ips):
            console.print(f"    [info]{ip}[/info]")

        console.print()
        if confirm("Add honeypot events to session findings?", default=True):
            for ev in _CAPTURED:
                ip = ev.get("ip", "unknown")
                session.add_finding(
                    "WARNING", "Honeypot",
                    session.target or "honeypot",
                    f"{ev.get('type', '?')} — {ev.get('service', '?')} from {ip} — {ev.get('data', '')}[:80]",
                    ev,
                )
            success(f"{len(_CAPTURED)} honeypot events added to findings.")


def _show_help():
    help_panel("HONEYPOT — HELP", {
        "FAKE SERVICES": [
            "SSH     paramiko fake server — captures client version, username, password attempts.",
            "        Always fails auth. No shell given. Ever.",
            "HTTP    Fake Apache server — logs method, path, headers, POST body, User-Agent.",
            "        Returns 401 to encourage credential submission.",
            "Telnet  Raw TCP socket with fake banner — logs everything sent.",
            "FTP     Raw TCP socket with 220 banner — logs commands sent.",
            "Custom  Any port + any banner string — logs raw data sent.",
        ],
        "WHAT GETS CAPTURED": [
            "Source IP + timestamp",
            "SSH: client version string (reveals tooling), all username:password pairs",
            "HTTP: full request path, headers, POST body (credential submissions)",
            "TCP: raw data sent — reveals exploit payloads, commands, tools",
            "Auto threat intel on every new source IP (GreyNoise)",
        ],
        "CANARY TOKEN FILES": [
            "Generates fake .env and config files with plausible-looking credentials.",
            "Plant in web roots, backup directories, or dev folders.",
            "If an attacker finds and uses them, the attempt shows up in your",
            "SSH/HTTP/database connection logs — you'll know they have the files.",
        ],
        "PHILOSOPHY": [
            "The honeypot confirms the attacker's identity and tooling.",
            "It does not trap them, harm them, or retaliate.",
            "You are gathering defensive intelligence on your own infrastructure.",
        ],
    })
