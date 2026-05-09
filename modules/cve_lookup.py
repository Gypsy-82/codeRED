import time

import requests

from rich.table import Table
from rich import box

from modules.display import (
    console, section_header, success, warning, critical, info, label, dim,
    spinner, help_panel, rule,
    confirm, select, text_input, checkbox,
)

_NVD_URL      = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_RATE_DELAY   = 6   # seconds between requests without API key

_CVSS_STYLE = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "dim cyan",
    "NONE":     "dim",
}


def _score_to_severity(score):
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score >  0.0: return "LOW"
    return "NONE"


def _query(keyword, api_key=None, limit=10):
    headers = {"apiKey": api_key} if api_key else {}
    params  = {"keywordSearch": keyword, "resultsPerPage": limit}
    try:
        r = requests.get(_NVD_URL, params=params, headers=headers, timeout=15)
        if r.status_code == 200:
            return r.json()
        return {"error": f"HTTP {r.status_code}"}
    except requests.RequestException as e:
        return {"error": str(e)}


def _parse_cves(data):
    cves = []
    for vuln in data.get("vulnerabilities", []):
        cve    = vuln.get("cve", {})
        cve_id = cve.get("id", "?")

        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            "",
        )

        score    = 0.0
        severity = "NONE"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metrics = cve.get("metrics", {}).get(key, [])
            if metrics:
                cvss      = metrics[0].get("cvssData", {})
                score     = float(cvss.get("baseScore", 0))
                severity  = cvss.get("baseSeverity", _score_to_severity(score)).upper()
                break

        cves.append({
            "id":        cve_id,
            "score":     score,
            "severity":  severity,
            "published": cve.get("published", "")[:10],
            "desc":      desc,
        })

    return sorted(cves, key=lambda x: x["score"], reverse=True)


def _render_cve_table(keyword, cves, total):
    console.print(
        f"\n  [header]{keyword}[/header]  "
        f"[dim_text]{total} total  —  showing {len(cves)}[/dim_text]"
    )

    if not cves:
        dim("  No CVEs found.")
        return

    t = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="header", padding=(0, 1))
    t.add_column("CVE ID",      style="highlight",  width=18)
    t.add_column("Score",       width=7,  justify="center")
    t.add_column("Severity",    width=10)
    t.add_column("Published",   width=12, style="dim_text")
    t.add_column("Description", min_width=40)

    for c in cves:
        style     = _CVSS_STYLE.get(c["severity"], "white")
        score_str = f"[{style}]{c['score']:.1f}[/{style}]"
        sev_str   = f"[{style}]{c['severity']}[/{style}]"
        desc      = c["desc"]
        desc_out  = (desc[:88] + "…") if len(desc) > 88 else desc
        t.add_row(c["id"], score_str, sev_str, c["published"], desc_out)

    console.print(t)


def run(session):
    section_header("CVE LOOKUP", "NVD API v2.0")

    # Build query list from port scan results
    auto_queries = []
    for target_data in session.port_results.values():
        for p in target_data.get("ports", []):
            if p["state"] != "open":
                continue
            svc = p.get("service", "").strip()
            ver = p.get("version", "").strip()
            q   = f"{svc} {ver}".strip() if ver else svc
            if q and q not in auto_queries:
                auto_queries.append(q)

    choices = []
    if auto_queries:
        choices.append({"name": f"From port scan results  ({len(auto_queries)} services)", "value": "scan"})
    choices += [
        {"name": "Manual entry",  "value": "manual"},
        {"name": "? Help",        "value": "help"},
        {"name": "← Back",       "value": "back"},
    ]

    mode = select("Query source:", choices)

    if mode == "back":
        return
    if mode == "help":
        _show_help()
        return run(session)

    if mode == "manual" or not auto_queries:
        q = text_input("Service + version  (e.g. 'nginx 1.18.0'  or  'openssl 1.0.2k')").strip()
        if not q:
            return
        selected_queries = [q]
    else:
        q_choices        = [{"name": q, "value": q} for q in auto_queries[:20]]
        selected_queries = checkbox("Select services to look up:", q_choices)
        if not selected_queries:
            warning("Nothing selected.")
            return

    # Optional API key
    api_key = None
    if confirm("NVD API key available? (raises rate limit 5 → 50 req/30s)", default=False):
        api_key = text_input("NVD API key").strip() or None

    limit = select("Results per query:", [
        {"name": "5  — overview",  "value": 5},
        {"name": "10 — default",   "value": 10},
        {"name": "20 — thorough",  "value": 20},
    ])

    console.print()

    for i, query in enumerate(selected_queries):
        if i > 0 and not api_key:
            dim(f"  Waiting {_RATE_DELAY}s — NVD rate limit…")
            time.sleep(_RATE_DELAY)

        with spinner(f"  NVD → {query}"):
            data = _query(query, api_key, limit)

        if "error" in data:
            warning(f"NVD query error: {data['error']}")
            continue

        cves  = _parse_cves(data)
        total = data.get("totalResults", len(cves))
        _render_cve_table(query, cves, total)

        session.cve_results[query] = cves

        for c in cves:
            if c["severity"] in ("CRITICAL", "HIGH"):
                session.add_finding(
                    c["severity"], "CVE Lookup", query,
                    f"{c['id']} CVSS {c['score']} — {c['desc'][:100]}",
                    c,
                )

    console.print()
    success("CVE lookup complete.")


def _show_help():
    help_panel("CVE LOOKUP — HELP", {
        "DATA SOURCE": [
            "NIST National Vulnerability Database — NVD API v2.0.",
            "The authoritative CVE database. Updated continuously.",
        ],
        "RATE LIMITS": [
            "No API key:   5 requests / 30 seconds (6s delay auto-added).",
            "With API key: 50 requests / 30 seconds.",
            "Free key: nvd.nist.gov/developers/request-an-api-key",
        ],
        "SEARCH TIPS": [
            "More specific = better results:",
            "  'nginx 1.18.0'    'openssl 1.0.2k'    'apache httpd 2.4.49'",
            "Results sorted highest CVSS score first.",
        ],
        "CVSS SCORING": [
            "9.0 – 10.0  CRITICAL  (bold red)",
            "7.0 – 8.9   HIGH      (red)",
            "4.0 – 6.9   MEDIUM    (yellow)",
            "0.1 – 3.9   LOW       (dim cyan)",
        ],
        "WHAT FEEDS THIS": [
            "Port scan service + version strings are auto-loaded as query options.",
        ],
    })
