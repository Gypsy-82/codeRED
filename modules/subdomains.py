import os
import socket
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed

from modules.display import (
    console, section_header, success, warning, critical, info, dim,
    subdomain_table, spinner, help_panel,
    confirm, select, text_input, checkbox,
)

_KEYWORD_MAP = [
    (["mail", "smtp", "mx", "pop", "imap", "webmail", "email", "exchange", "postfix", "relay"], "mail server"),
    (["db", "database", "mysql", "mongo", "postgres", "pgsql", "redis", "elastic", "cassandra", "couch", "memcache", "mariadb"], "database server"),
    (["ns", "ns1", "ns2", "ns3", "ns4", "dns", "nameserver", "resolver"], "nameserver"),
    (["cdn", "static", "assets", "media", "img", "images", "files", "storage", "s3", "blob", "cache"], "cdn"),
    (["ftp", "sftp", "ftps", "transfer"], "ftp server"),
    (["vpn", "tunnel", "remote", "openvpn", "wireguard"], "vpn"),
    (["k8s", "kube", "kubernetes", "rancher", "helm"], "kubernetes"),
    (["docker", "registry", "container", "harbor"], "docker"),
]


def _classify(subdomain):
    prefix = subdomain.split(".")[0].lower()
    for keywords, stype in _KEYWORD_MAP:
        if any(kw in prefix for kw in keywords):
            return stype
    return "web server"


def _resolve_ip(subdomain):
    try:
        return socket.getaddrinfo(subdomain, None, socket.AF_INET)[0][4][0]
    except (socket.gaierror, IndexError, OSError):
        return "—"


def _resolve_all(subdomains):
    results = {}
    with ThreadPoolExecutor(max_workers=30) as ex:
        futures = {ex.submit(_resolve_ip, s): s for s in subdomains}
        for future in as_completed(futures):
            results[futures[future]] = future.result()
    return results


def _run_subfinder(domain):
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tf:
        outfile = tf.name
    try:
        subprocess.run(
            ["subfinder", "-d", domain, "-silent", "-o", outfile],
            capture_output=True, timeout=120,
        )
        if os.path.exists(outfile):
            with open(outfile) as f:
                return [l.strip() for l in f if l.strip()]
        return []
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []
    finally:
        if os.path.exists(outfile):
            os.unlink(outfile)


def _run_amass(domain):
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tf:
        outfile = tf.name
    try:
        subprocess.run(
            ["amass", "enum", "-passive", "-d", domain, "-o", outfile],
            capture_output=True, timeout=300,
        )
        if os.path.exists(outfile):
            with open(outfile) as f:
                return [l.strip() for l in f if l.strip()]
        return []
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []
    finally:
        if os.path.exists(outfile):
            os.unlink(outfile)


def _load_from_file(session):
    path = text_input("Path to subdomain file (one subdomain per line)").strip()
    if not os.path.isfile(path):
        critical(f"File not found: {path}")
        return

    with open(path) as f:
        lines = [l.strip() for l in f if l.strip()]

    if not lines:
        warning("File is empty.")
        return

    info(f"Resolving IPs for {len(lines)} subdomains...")
    ip_map = _resolve_all(lines)

    session.subdomains = [
        {
            "num":       i + 1,
            "subdomain": sub,
            "ip":        ip_map.get(sub, "—"),
            "type":      _classify(sub),
            "status":    "up" if ip_map.get(sub, "—") != "—" else "down",
        }
        for i, sub in enumerate(lines)
    ]

    success(f"Loaded {len(session.subdomains)} subdomains from file.")
    console.print()
    subdomain_table(session.subdomains)


def _build_subdomain_list(all_subs, target):
    ip_map = _resolve_all(list(all_subs))
    return [
        {
            "num":       i,
            "subdomain": sub,
            "ip":        ip_map.get(sub, "—"),
            "type":      _classify(sub),
            "status":    "up" if ip_map.get(sub, "—") != "—" else "down",
        }
        for i, sub in enumerate(sorted(all_subs), 1)
    ]


def run(session):
    section_header("SUBDOMAIN DISCOVERY", "subfinder + amass")

    if not session.target:
        warning("No target set — set a target from the main menu first.")
        return

    has_subfinder = "subfinder" in session.available_tools
    has_amass     = "amass"     in session.available_tools

    if not has_subfinder and not has_amass:
        critical("Neither subfinder nor amass is installed.")
        info("Install amass:     sudo apt install amass")
        info("Install subfinder: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
        confirm("Return to main menu?", default=True)
        return

    choices = []
    if has_subfinder and has_amass:
        choices.append({"name": "Both           (most complete — recommended)", "value": "both"})
    if has_subfinder:
        choices.append({"name": "subfinder      (fast, passive, API-driven)", "value": "subfinder"})
    if has_amass:
        choices.append({"name": "amass          (thorough, active + passive)", "value": "amass"})
    choices += [
        {"name": "Load from file (skip discovery)", "value": "file"},
        {"name": "? Help",                          "value": "help"},
        {"name": "← Back",                          "value": "back"},
    ]

    source = select(f"Discovery source for {session.target}:", choices)

    if source == "back":
        return
    if source == "help":
        _show_help()
        return run(session)
    if source == "file":
        _load_from_file(session)
        return

    all_subs = set()

    if source in ("subfinder", "both") and has_subfinder:
        with spinner(f"  subfinder → {session.target}"):
            subs = _run_subfinder(session.target)
        success(f"subfinder: {len(subs)} subdomains found")
        all_subs.update(subs)

    if source in ("amass", "both") and has_amass:
        with spinner(f"  amass → {session.target}  (this may take a few minutes)"):
            subs = _run_amass(session.target)
        success(f"amass: {len(subs)} subdomains found")
        all_subs.update(subs)

    all_subs.discard(session.target)

    if not all_subs:
        warning("No subdomains discovered. Try a different source or load from file.")
        return

    info(f"Resolving IPs for {len(all_subs)} unique subdomains...")
    subdomains = _build_subdomain_list(all_subs, session.target)
    session.subdomains = subdomains

    console.print()
    subdomain_table(subdomains)

    up = sum(1 for s in subdomains if s["status"] == "up")
    info(f"{len(subdomains)} total  —  {up} resolving  —  {len(subdomains) - up} no DNS")

    session.add_finding(
        "INFO", "Subdomain Discovery", session.target,
        f"{len(subdomains)} subdomains discovered ({up} resolving)",
    )


def _show_help():
    help_panel("SUBDOMAIN DISCOVERY — HELP", {
        "TOOLS": [
            "subfinder   ProjectDiscovery — passive, certificate transparency logs,",
            "            passive DNS, multiple APIs. Fast.",
            "amass       OWASP — active + passive, ASN traversal, brute-force optional.",
            "            Slower, but finds subdomains subfinder misses.",
            "Both        Recommended. Results are combined and deduplicated.",
        ],
        "FILE INPUT": [
            "One subdomain per line. IPs are resolved automatically.",
            "Useful when you already have a list or want to work with a subset.",
        ],
        "SUBDOMAIN TYPES (keyword-based)": [
            "mail server    Keywords: mail, smtp, mx, imap, pop, webmail",
            "database server  Keywords: db, mysql, mongo, postgres, redis, elastic",
            "nameserver     Keywords: ns, ns1, ns2, dns",
            "cdn            Keywords: cdn, static, assets, media, img, s3",
            "kubernetes     Keywords: k8s, kube, kubernetes",
            "docker         Keywords: docker, registry, container",
            "web server     Default for anything not matched",
            "Note: DNS Intelligence will refine these from actual DNS records.",
        ],
        "WHAT THIS FEEDS": [
            "DNS Intelligence — enriches each subdomain with DNS records.",
            "Port Scan        — select subdomains to scan.",
            "Ping Sweep       — ICMP check across all subdomains.",
            "Connection Intel — SSH in to check active connections.",
        ],
    })
