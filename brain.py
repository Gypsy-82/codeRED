#!/usr/bin/env python3
"""
Red Recon Framework
Launch: python3 brain.py  (inside red_env virtual environment)
"""
import sys
import os
import re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ── Step 1: enforce venv + auto-install deps (stdlib only at this point) ──────
import modules.env_check as _env_check
AVAILABLE_TOOLS = _env_check.run()

# ── Step 2: all third-party imports (deps guaranteed installed above) ──────────
from InquirerPy.separator import Separator

from modules.display import (
    console,
    banner,
    section_header,
    rule,
    critical,
    warning,
    success,
    info,
    label,
    dim,
    panel,
    finding,
    subdomain_table,
    port_table,
    findings_summary,
    spinner,
    help_panel,
    confirm,
    select,
    text_input,
    checkbox,
)

from modules.subdomains       import run as _run_subdomains
from modules.dns_intel        import run as _run_dns
from modules.port_scan        import run as _run_ports
from modules.web_scan         import run as _run_web
from modules.connection_intel import run as _run_connections
from modules.cred_check       import run as _run_creds
from modules.cve_lookup       import run as _run_cve
from modules.honeypot         import run as _run_honeypot
from modules.ping_sweep       import run as _run_ping


# ── Session state ──────────────────────────────────────────────────────────────

class Session:
    def __init__(self):
        self.target         = None
        self.subdomains     = []      # list of dicts: num, subdomain, ip, type, status
        self.findings       = []      # accumulated findings across all modules
        self.dns_results    = {}      # keyed by subdomain
        self.port_results   = {}      # keyed by subdomain
        self.web_results    = {}      # keyed by subdomain
        self.conn_results   = {}      # keyed by subdomain
        self.cve_results    = {}      # keyed by service+version
        self.cred_results   = {}      # keyed by subdomain
        self.available_tools = AVAILABLE_TOOLS

    def add_finding(self, severity, module, target, finding_text, details=None):
        self.findings.append({
            "severity": severity,
            "module":   module,
            "target":   target,
            "finding":  finding_text,
            "details":  details or {},
        })

    def has_subdomains(self):
        return len(self.subdomains) > 0

    def status_line(self):
        target_str = f"[cyan]{self.target}[/cyan]" if self.target else "[dim]not set[/dim]"
        subs_str   = f"[cyan]{len(self.subdomains)}[/cyan]" if self.subdomains else "[dim]0[/dim]"
        finds_str  = f"[yellow]{len(self.findings)}[/yellow]" if self.findings else "[dim]0[/dim]"
        console.print(
            f"\n  Target: {target_str}   "
            f"Subdomains: {subs_str}   "
            f"Findings: {finds_str}"
        )


session = Session()


# ── Helpers ────────────────────────────────────────────────────────────────────

def _require_target():
    if not session.target:
        warning("No target set. Set a target first.")
        if confirm("Set target now?", default=True):
            set_target()
        return session.target is not None
    return True


def _require_subdomains():
    if not session.has_subdomains():
        warning("No subdomains loaded. Run Subdomain Discovery first.")
        return False
    return True


# ── Target setting ─────────────────────────────────────────────────────────────

def set_target():
    section_header("SET TARGET")

    mode = select(
        "Target type:",
        [
            {"name": "Domain          (e.g. example.com)",    "value": "domain"},
            {"name": "IP Address      (e.g. 192.168.1.1)",    "value": "ip"},
            {"name": "IP Range (CIDR) (e.g. 192.168.1.0/24)", "value": "cidr"},
        ],
    )

    prompts = {
        "domain": "Enter target domain",
        "ip":     "Enter target IP address",
        "cidr":   "Enter CIDR range",
    }

    def _validate(val):
        val = val.strip()
        if not val:
            return "Target cannot be empty"
        if mode == "domain":
            if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$", val):
                return "Enter a valid domain (e.g. example.com)"
        if mode == "ip":
            parts = val.split(".")
            if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                return "Enter a valid IPv4 address"
        if mode == "cidr":
            if "/" not in val:
                return "Include subnet mask (e.g. /24)"
        return True

    target = text_input(prompts[mode], validate=_validate).strip()
    session.target = target
    session.subdomains = []
    session.findings   = []
    session.dns_results = {}
    session.port_results = {}

    success(f"Target set: {target}")

    if mode == "domain":
        if confirm("Load subdomains from a file instead of running discovery?", default=False):
            _load_subdomains_from_file()


def _load_subdomains_from_file():
    section_header("LOAD SUBDOMAINS FROM FILE")
    path = text_input("Enter path to subdomain file (one per line)").strip()

    if not os.path.isfile(path):
        critical(f"File not found: {path}")
        return

    with open(path, "r") as f:
        lines = [l.strip() for l in f if l.strip()]

    session.subdomains = [
        {"num": i + 1, "subdomain": sub, "ip": "—", "type": "unknown", "status": "?"}
        for i, sub in enumerate(lines)
    ]

    success(f"Loaded {len(session.subdomains)} subdomains from file.")
    subdomain_table(session.subdomains)


# ── Module stubs (replaced as modules are built) ───────────────────────────────

def _stub(name, description=""):
    def _run():
        section_header(name, description)
        panel(
            f"[yellow]Module under construction.[/yellow]\n"
            f"[dim_text]'{name}' will be available in the next build.[/dim_text]",
            title="Coming Soon",
            border_style="yellow",
        )
        confirm("Return to main menu?", default=True)
    return _run


def module_subdomains():
    _run_subdomains(session)

def module_dns():
    _run_dns(session)

def module_ports():
    _run_ports(session)


def module_web():         _run_web(session)
def module_connections(): _run_connections(session)
def module_creds():       _run_creds(session)
def module_cve():         _run_cve(session)
def module_honeypot():    _run_honeypot(session)
def module_ping():        _run_ping(session)


# ── Save session ───────────────────────────────────────────────────────────────

def save_session():
    section_header("SAVE SESSION")

    if not session.findings and not session.subdomains:
        info("Nothing to save yet — no findings or subdomains recorded this session.")
        return

    console.print()
    findings_summary(session.findings)

    if not confirm("Save session findings?", default=False):
        dim("Save cancelled.")
        return

    path = text_input("Enter save directory path", default=os.path.expanduser("~/")).strip()

    if not os.path.isdir(path):
        try:
            os.makedirs(path, exist_ok=True)
        except OSError as e:
            critical(f"Could not create directory: {e}")
            return

    fmt = select(
        "Output format:",
        [
            {"name": "Text (.txt)",        "value": "txt"},
            {"name": "JSON (.json)",       "value": "json"},
            {"name": "HTML report (.html)","value": "html"},
        ],
    )

    target_safe = (session.target or "session").replace(".", "_").replace("/", "_")
    filename = os.path.join(path, f"recon_{target_safe}.{fmt}")

    try:
        if fmt == "txt":
            _save_txt(filename)
        elif fmt == "json":
            _save_json(filename)
        elif fmt == "html":
            _save_html(filename)
        success(f"Saved: {filename}")
    except Exception as e:
        critical(f"Save failed: {e}")


def _save_txt(path):
    lines = [
        "RED RECON — SESSION FINDINGS",
        f"Target: {session.target}",
        f"Subdomains: {len(session.subdomains)}",
        f"Findings: {len(session.findings)}",
        "",
        "── SUBDOMAINS ──",
    ]
    for sd in session.subdomains:
        lines.append(f"  [{sd['num']}] {sd['subdomain']}  {sd['ip']}  {sd['type']}  {sd['status']}")
    lines += ["", "── FINDINGS ──"]
    for f in session.findings:
        lines.append(f"  [{f['severity']}] {f['module']} — {f['target']} — {f['finding']}")
    with open(path, "w") as fh:
        fh.write("\n".join(lines))


def _save_json(path):
    import json
    data = {
        "target":     session.target,
        "subdomains": session.subdomains,
        "findings":   session.findings,
        "dns":        session.dns_results,
        "ports":      session.port_results,
    }
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)


def _save_html(path):
    rows = ""
    for f in session.findings:
        color = {"CRITICAL": "#ff4444", "WARNING": "#ffaa00", "CLEAN": "#44ff88"}.get(
            f["severity"].upper(), "#ffffff"
        )
        rows += (
            f"<tr><td style='color:{color}'>{f['severity']}</td>"
            f"<td>{f['module']}</td><td>{f['target']}</td>"
            f"<td>{f['finding']}</td></tr>\n"
        )

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Red Recon — {session.target}</title>
<style>
  body {{background:#111;color:#eee;font-family:monospace;padding:2rem;}}
  h1 {{color:#ff4444;}} h2 {{color:#00cccc;}}
  table {{width:100%;border-collapse:collapse;margin-top:1rem;}}
  th {{background:#222;color:#00cccc;padding:.5rem 1rem;text-align:left;}}
  td {{padding:.4rem 1rem;border-bottom:1px solid #333;}}
</style>
</head>
<body>
<h1>RED RECON</h1>
<p>Target: <strong>{session.target}</strong></p>
<h2>Findings</h2>
<table>
<tr><th>Severity</th><th>Module</th><th>Target</th><th>Finding</th></tr>
{rows}
</table>
</body>
</html>"""

    with open(path, "w") as fh:
        fh.write(html)


# ── Help ───────────────────────────────────────────────────────────────────────

def show_help():
    help_panel("RED RECON — HELP", {
        "MODULES": [
            "Set Target            domain, IP, or CIDR range",
            "Subdomain Discovery   subfinder + amass (passive + active)",
            "DNS Intelligence      dig + whois + service classifier",
            "Port Scan             nmap — Quick / Standard / Developer / Full / Custom",
            "Web Scan              nikto — headers, files, misconfigs",
            "Connection Intel      ss + lsof via SSH + threat intel enrichment",
            "Default Cred Check    SSH / Telnet / HTTP Basic / FTP — confirm only",
            "CVE Lookup            NVD API v2.0 — service + version cross-reference",
            "Honeypot              fake service listeners + canary tokens + attacker profiling",
            "Ping Sweep            ICMP connectivity across all subdomains",
        ],
        "NAVIGATION": [
            "↑ ↓       Navigate options",
            "Enter     Select",
            "Space     Toggle checkbox (multi-select screens)",
            "?         Help for current screen",
            "q         Back to main menu",
            "Ctrl+C    Safe exit to main menu",
        ],
        "COLOR GUIDE": [
            "RED       Critical finding — confirmed vuln, default creds accepted, malicious IP",
            "YELLOW    Warning — investigate, unusual service, suspicious behavior",
            "GREEN     Clean — closed port, creds denied, no finding",
            "CYAN      Info headers — subdomain names, module titles, IP addresses",
            "BLUE      Field labels",
            "MAGENTA   Tool names, section dividers",
        ],
        "SAVING": [
            "Nothing writes to disk without your explicit yes.",
            "All findings accumulate in memory during the session.",
            "You choose the path and format (txt / json / html) at save time.",
        ],
        "PHILOSOPHY": [
            "Confirm the door is unlocked, don't walk through it.",
            "Proof-of-concept validation only — connect, test, report confirmed/denied.",
            "No command execution beyond confirmation. No persistence. No lateral movement.",
        ],
    })


# ── Main menu ──────────────────────────────────────────────────────────────────

_MENU_CHOICES = [
    {"name": "Set Target",                           "value": "target"},
    Separator(),
    {"name": "Subdomain Discovery   subfinder + amass",      "value": "subdomains"},
    {"name": "DNS Intelligence      dig + whois",             "value": "dns"},
    {"name": "Port Scan             nmap",                    "value": "ports"},
    {"name": "Web Scan              nikto",                   "value": "web"},
    {"name": "Connection Intel      ss + lsof + threat intel","value": "connections"},
    {"name": "Default Cred Check    SSH / Telnet / HTTP / FTP","value": "creds"},
    {"name": "CVE Lookup            NVD API v2.0",            "value": "cve"},
    {"name": "Honeypot              deploy + capture",        "value": "honeypot"},
    {"name": "Ping Sweep            ICMP",                    "value": "ping"},
    Separator(),
    {"name": "Save Session",                         "value": "save"},
    {"name": "? Help",                               "value": "help"},
    {"name": "Exit",                                 "value": "exit"},
]

_DISPATCH = {
    "target":      set_target,
    "subdomains":  module_subdomains,
    "dns":         module_dns,
    "ports":       module_ports,
    "web":         module_web,
    "connections": module_connections,
    "creds":       module_creds,
    "cve":         module_cve,
    "honeypot":    module_honeypot,
    "ping":        module_ping,
    "save":        save_session,
    "help":        show_help,
}


def main():
    banner()

    while True:
        try:
            session.status_line()

            choice = select("Select module", _MENU_CHOICES)

            if choice == "exit":
                if session.findings and not confirm(
                    f"You have {len(session.findings)} unsaved findings. Exit anyway?",
                    default=False,
                ):
                    continue
                console.print("\n[dim_text]  Stay sharp.[/dim_text]\n")
                sys.exit(0)

            handler = _DISPATCH.get(choice)
            if handler:
                handler()

        except KeyboardInterrupt:
            console.print("\n[dim_text]  Ctrl+C — back to main menu[/dim_text]")
            continue


if __name__ == "__main__":
    main()
