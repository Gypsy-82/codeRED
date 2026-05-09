import subprocess

from modules.display import (
    console, section_header, success, warning, critical, info, label, dim,
    subdomain_table, spinner, rule, help_panel, finding,
    confirm, select, checkbox,
)

_CDN_SIGNATURES = [
    "cloudflare", "akamai", "fastly", "cloudfront", "edgecast",
    "incapsula", "imperva", "sucuri", "stackpath", "cdn77",
]

_RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]

_WHOIS_FIELDS = {
    "registrar":    ["Registrar:", "registrar:"],
    "created":      ["Creation Date:", "created:", "Registered On:"],
    "expires":      ["Expiry Date:", "Registry Expiry Date:", "expires:"],
    "updated":      ["Updated Date:", "last-modified:"],
    "org":          ["Registrant Organization:", "org:", "Organisation:"],
    "country":      ["Registrant Country:", "country:"],
    "name_servers": ["Name Server:", "nserver:"],
    "status":       ["Domain Status:", "status:"],
}


def _dig(host, record_type):
    try:
        result = subprocess.run(
            ["dig", "+short", "+time=5", record_type, host],
            capture_output=True, text=True, timeout=10,
        )
        return [
            l.strip() for l in result.stdout.strip().split("\n")
            if l.strip() and not l.strip().startswith(";")
        ]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def _whois(target):
    try:
        result = subprocess.run(
            ["whois", target],
            capture_output=True, text=True, timeout=15,
        )
        return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def _parse_whois(raw):
    fields = {}
    ns_list = []

    for line in raw.split("\n"):
        line = line.strip()
        if not line or line.startswith("%") or line.startswith("#"):
            continue

        for field, prefixes in _WHOIS_FIELDS.items():
            for prefix in prefixes:
                if line.lower().startswith(prefix.lower()):
                    value = line[len(prefix):].strip()
                    if not value:
                        continue
                    if field == "name_servers":
                        ns_list.append(value.lower())
                    elif field not in fields:
                        fields[field] = value[:80]

    if ns_list:
        fields["name_servers"] = ", ".join(sorted(set(ns_list))[:4])

    return fields


def _query_all_records(subdomain):
    records = {}
    for rtype in _RECORD_TYPES:
        records[rtype] = _dig(subdomain, rtype)
    return records


def _classify_from_records(subdomain, records):
    if records.get("MX"):
        return "mail server"

    for cname in records.get("CNAME", []):
        for sig in _CDN_SIGNATURES:
            if sig in cname.lower():
                return "cdn"

    for ns in records.get("NS", []):
        prefix = subdomain.split(".")[0].lower()
        if any(kw in prefix for kw in ["ns", "ns1", "ns2", "dns"]):
            return "nameserver"

    return None


def _display_subdomain_records(subdomain, records, whois_data=None):
    console.print(f"\n  [header]{subdomain}[/header]")

    displayed = False
    for rtype in ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]:
        vals = records.get(rtype, [])
        if vals:
            for i, v in enumerate(vals[:5]):
                display_val = v[:90] + ("…" if len(v) > 90 else "")
                label(rtype if i == 0 else "", display_val,
                      "blue" if rtype == "MX" else "info" if rtype == "A" else "white")
            displayed = True

    if not displayed:
        dim("  No DNS records found")

    if whois_data:
        console.print()
        console.print("  [header]WHOIS[/header]")
        for field, value in whois_data.items():
            label(field.replace("_", " ").title(), str(value))


def _flag_findings(session, subdomain, records):
    mx = records.get("MX", [])
    if mx:
        session.add_finding(
            "INFO", "DNS Intelligence", subdomain,
            f"Mail server — MX: {mx[0]}",
        )

    txt = records.get("TXT", [])
    for t in txt:
        if "v=spf1" in t.lower():
            if "~all" in t or "?all" in t:
                session.add_finding(
                    "WARNING", "DNS Intelligence", subdomain,
                    f"SPF uses soft-fail (~all) or neutral (?all) — spoofing may be possible",
                    {"txt": t},
                )

    if not records.get("A") and not records.get("CNAME"):
        session.add_finding(
            "INFO", "DNS Intelligence", subdomain,
            "No A or CNAME record — subdomain does not resolve",
        )

    for cname in records.get("CNAME", []):
        if any(sig in cname.lower() for sig in _CDN_SIGNATURES):
            session.add_finding(
                "INFO", "DNS Intelligence", subdomain,
                f"CDN/proxy detected via CNAME — {cname}",
            )


def run(session):
    section_header("DNS INTELLIGENCE", "dig + whois + classifier")

    if not session.target:
        warning("No target set.")
        return

    if not session.subdomains:
        warning("No subdomains loaded. Run Subdomain Discovery first.")
        confirm("Return to main menu?", default=True)
        return

    if "dig" not in session.available_tools:
        critical("'dig' not found. Install: sudo apt install dnsutils")
        return

    action = select("Scope:", [
        {"name": "All subdomains",      "value": "all"},
        {"name": "Select specific",     "value": "select"},
        {"name": "? Help",              "value": "help"},
        {"name": "← Back",             "value": "back"},
    ])

    if action == "back":
        return
    if action == "help":
        _show_help()
        return run(session)

    if action == "select":
        choices = [
            {
                "name":  f"[{sd['num']}] {sd['subdomain']}  ({sd['type']})",
                "value": sd["subdomain"],
            }
            for sd in session.subdomains
        ]
        selected = checkbox("Select subdomains:", choices)
        if not selected:
            warning("Nothing selected.")
            return
        targets = [sd for sd in session.subdomains if sd["subdomain"] in selected]
    else:
        targets = session.subdomains

    # Whois on root domain (once)
    whois_data = {}
    if "whois" in session.available_tools:
        if confirm(f"Run whois on {session.target}?", default=True):
            with spinner(f"  whois → {session.target}"):
                raw = _whois(session.target)
            whois_data = _parse_whois(raw)

    # Query each subdomain
    first = True
    for sd in targets:
        with spinner(f"  dig → {sd['subdomain']}"):
            records = _query_all_records(sd["subdomain"])

        _display_subdomain_records(
            sd["subdomain"],
            records,
            whois_data if first and whois_data else None,
        )
        first = False

        session.dns_results[sd["subdomain"]] = records

        refined = _classify_from_records(sd["subdomain"], records)
        if refined:
            for s in session.subdomains:
                if s["subdomain"] == sd["subdomain"]:
                    s["type"] = refined

        _flag_findings(session, sd["subdomain"], records)

    console.print()

    if whois_data:
        console.rule("[header]  WHOIS SUMMARY[/header]")
        for field, value in whois_data.items():
            label(field.replace("_", " ").title(), str(value))
        console.print()

    success(f"DNS intelligence complete for {len(targets)} subdomain(s).")

    if confirm("View updated subdomain table?", default=True):
        console.print()
        subdomain_table(session.subdomains)


def _show_help():
    help_panel("DNS INTELLIGENCE — HELP", {
        "RECORD TYPES QUERIED": [
            "A      IPv4 address — the primary IP",
            "AAAA   IPv6 address",
            "CNAME  Canonical name — reveals CDN, load balancer, hosting provider",
            "MX     Mail exchange — identifies mail infrastructure",
            "NS     Nameserver — who controls DNS for this subdomain",
            "TXT    Text records — SPF, DKIM, DMARC, site verification tokens",
            "SOA    Start of Authority — zone admin contact, serial, TTLs",
        ],
        "AUTO-CLASSIFICATION (from actual DNS)": [
            "MX record present     → reclassified as mail server",
            "CNAME to CDN provider → reclassified as CDN",
            "  CDN signatures: cloudflare, akamai, fastly, cloudfront, edgecast",
        ],
        "AUTO-FLAGGED FINDINGS": [
            "SPF soft-fail (~all) or neutral (?all) — email spoofing possible",
            "No A/CNAME record — dangling subdomain",
            "CDN/proxy in CNAME chain",
            "MX records — mail infrastructure identified",
        ],
        "WHOIS": [
            "Queries registrar data for the root domain.",
            "Reveals: registrar, creation/expiry dates, org, nameservers.",
        ],
    })
