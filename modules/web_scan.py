import os
import subprocess
import tempfile
import warnings

import requests
from urllib3.exceptions import InsecureRequestWarning

from modules.display import (
    console, section_header, success, warning, critical, info, label, dim,
    spinner, help_panel, rule,
    confirm, select, text_input, checkbox,
)

warnings.filterwarnings("ignore", category=InsecureRequestWarning)

_SECURITY_HEADERS = [
    ("Strict-Transport-Security",  "HSTS — forces HTTPS",             "CRITICAL"),
    ("X-Frame-Options",            "Clickjacking protection",         "WARNING"),
    ("X-Content-Type-Options",     "MIME-type sniffing prevention",   "WARNING"),
    ("Content-Security-Policy",    "XSS / injection mitigation",      "WARNING"),
    ("Referrer-Policy",            "Referrer data control",           "INFO"),
    ("Permissions-Policy",         "Browser feature permissions",     "INFO"),
    ("X-XSS-Protection",           "Legacy XSS filter (IE/Chrome)",   "INFO"),
]

_DISCLOSURE_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Generator", "X-Drupal-Cache", "X-WordPress", "Via", "X-Runtime",
]


def _run_nikto(url):
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as tf:
        outfile = tf.name
    try:
        subprocess.run(
            ["nikto", "-h", url, "-output", outfile, "-Format", "txt", "-nointeractive"],
            capture_output=True, timeout=300,
        )
        if os.path.exists(outfile):
            with open(outfile) as f:
                return f.read()
        return ""
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""
    finally:
        if os.path.exists(outfile):
            os.unlink(outfile)


def _fetch_headers(url):
    try:
        r = requests.get(
            url, timeout=10, verify=False,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; security-scan/1.0)"},
        )
        return r.headers, r.status_code, r.url
    except requests.RequestException:
        return {}, None, url


def _analyse_headers(headers, url):
    header_lower = {k.lower(): v for k, v in headers.items()}

    missing    = []
    present    = []
    disclosure = []

    for hdr, desc, severity in _SECURITY_HEADERS:
        if hdr.lower() in header_lower:
            present.append((hdr, header_lower[hdr.lower()]))
        else:
            missing.append((hdr, desc, severity))

    for hdr in _DISCLOSURE_HEADERS:
        val = header_lower.get(hdr.lower())
        if val:
            disclosure.append((hdr, val))

    console.print(f"\n  [header]Security Headers — {url}[/header]")

    if missing:
        console.print("\n  [warning]Missing headers:[/warning]")
        for hdr, desc, sev in missing:
            c = "critical" if sev == "CRITICAL" else "warning" if sev == "WARNING" else "info"
            console.print(f"    [{c}]✖[/{c}]  [label]{hdr:<38}[/label]{desc}")

    if present:
        console.print("\n  [clean]Present headers:[/clean]")
        for hdr, val in present:
            val_disp = (val[:58] + "…") if len(val) > 58 else val
            console.print(f"    [clean]✓[/clean]  [label]{hdr:<38}[/label][dim_text]{val_disp}[/dim_text]")

    if disclosure:
        console.print("\n  [warning]Information disclosure:[/warning]")
        for hdr, val in disclosure:
            console.print(f"    [warning]ℹ[/warning]  [label]{hdr:<38}[/label]{val}")

    return missing, disclosure


def _parse_nikto(raw):
    findings = []
    for line in raw.split("\n"):
        line = line.strip()
        if line.startswith("+ ") and len(line) > 4:
            findings.append(line[2:])
    return findings


def run(session):
    section_header("WEB SCAN", "nikto + header analysis")

    if not session.target:
        warning("No target set.")
        return

    nikto_available = "nikto" in session.available_tools
    if not nikto_available:
        warning("nikto not installed — header analysis will still run.")
        info("Install: sudo apt install nikto")

    # Auto-detect web targets from subdomains
    web_targets = [
        sd["subdomain"] for sd in session.subdomains
        if sd.get("type") in ("web server", "unknown", "docker", "kubernetes")
        and sd.get("status") == "up"
    ]
    if session.target not in web_targets:
        web_targets.insert(0, session.target)

    scope = select("Scan scope:", [
        {"name": f"All web-facing subdomains  ({len(web_targets)} detected)", "value": "all"},
        {"name": "Select specific targets",    "value": "select"},
        {"name": "Manual URL entry",           "value": "manual"},
        {"name": "? Help",                     "value": "help"},
        {"name": "← Back",                    "value": "back"},
    ])

    if scope == "back":
        return
    if scope == "help":
        _show_help()
        return run(session)

    if scope == "manual":
        url = text_input("Enter full URL  (e.g. https://example.com)").strip()
        if not url:
            return
        scan_targets = [url.rstrip("/")]
    elif scope == "select":
        choices  = [{"name": t, "value": t} for t in web_targets]
        selected = checkbox("Select targets:", choices)
        if not selected:
            warning("Nothing selected.")
            return
        scan_targets = selected
    else:
        scan_targets = web_targets

    protocol = select("Protocol:", [
        {"name": "HTTPS  (port 443)",  "value": "https"},
        {"name": "HTTP   (port 80)",   "value": "http"},
        {"name": "Both",               "value": "both"},
    ])

    run_nikto = nikto_available and confirm(
        "Run nikto? (thorough — allow 5-10 min per target)", default=True
    )

    console.print()

    for target in scan_targets:
        host = target.replace("https://", "").replace("http://", "").rstrip("/")

        urls = []
        if protocol in ("https", "both"):
            urls.append(f"https://{host}")
        if protocol in ("http", "both"):
            urls.append(f"http://{host}")

        for url in urls:
            console.print()
            rule(f" {url}")

            with spinner(f"  Fetching headers → {url}"):
                headers, status, final_url = _fetch_headers(url)

            if status is None:
                warning(f"Could not connect to {url}")
                continue

            color = "clean" if status == 200 else "warning"
            label("Status", str(status), color)
            if final_url != url:
                label("Redirected", final_url, "dim_text")

            missing, disclosure = _analyse_headers(headers, final_url)

            for hdr, desc, sev in missing:
                if sev in ("CRITICAL", "WARNING"):
                    session.add_finding(sev, "Web Scan", url, f"Missing header: {hdr} — {desc}")

            for hdr, val in disclosure:
                session.add_finding(
                    "WARNING", "Web Scan", url,
                    f"Information disclosure: {hdr}: {val}",
                )

            session.web_results[url] = {
                "status":          status,
                "missing_headers": [h for h, _, _ in missing],
                "disclosure":      {h: v for h, v in disclosure},
            }

            if run_nikto:
                console.print()
                with spinner(f"  nikto → {url}"):
                    raw = _run_nikto(url)

                nikto_findings = _parse_nikto(raw)
                if nikto_findings:
                    console.print(f"\n  [header]Nikto — {len(nikto_findings)} findings[/header]")
                    hi_words = {"vuln", "dangerous", "xss", "injection", "remote", "rce", "cve"}
                    for nf in nikto_findings[:25]:
                        if any(w in nf.lower() for w in hi_words):
                            critical(nf[:130])
                            session.add_finding("WARNING", "Nikto", url, nf[:150])
                        else:
                            info(nf[:130])
                else:
                    success("Nikto: no significant findings.")

    console.print()
    success("Web scan complete.")


def _show_help():
    help_panel("WEB SCAN — HELP", {
        "HEADER ANALYSIS": [
            "Fetches HTTP headers and checks for OWASP-recommended security headers.",
            "Critical: Strict-Transport-Security (HSTS)",
            "Warning:  X-Frame-Options, X-Content-Type-Options, Content-Security-Policy",
            "Also flags information disclosure headers that reveal software versions:",
            "  Server, X-Powered-By, X-AspNet-Version, X-Generator",
        ],
        "NIKTO": [
            "Comprehensive web server vulnerability scanner.",
            "Checks: dangerous files, outdated software, default configs,",
            "  misconfigured headers, CGI vulnerabilities, known bad paths.",
            "Typical runtime: 2-10 minutes per target.",
            "Install: sudo apt install nikto",
        ],
        "WHAT THIS FEEDS": [
            "Findings flow into the session finding log.",
            "Disclosure headers feed into CVE Lookup query suggestions.",
        ],
    })
