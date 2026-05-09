import subprocess
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.table import Table
from rich import box

from modules.display import (
    console, section_header, success, warning, info, dim,
    spinner, help_panel, rule,
    confirm, select,
)


def _ping(host, count):
    try:
        result = subprocess.run(
            ["ping", "-c", str(count), "-W", "2", host],
            capture_output=True, text=True, timeout=count * 3 + 2,
        )
        if result.returncode == 0:
            match = re.search(r"min/avg/max[^=]+=\s*[\d.]+/([\d.]+)/", result.stdout)
            rtt = f"{match.group(1)} ms" if match else "< 2 ms"
            return True, rtt
        return False, "—"
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False, "timeout"


def _ping_all(hosts, count):
    results = {}
    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(_ping, h, count): h for h in hosts}
        for future in as_completed(futures):
            results[futures[future]] = future.result()
    return results


def _render_table(results):
    t = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="header", padding=(0, 1))
    t.add_column("Host",    style="highlight", min_width=32)
    t.add_column("Status",  width=8, justify="center")
    t.add_column("Avg RTT", width=12, justify="right")

    up = 0
    for host in sorted(results):
        alive, rtt = results[host]
        status = "[clean]UP[/clean]" if alive else "[critical]DOWN[/critical]"
        if alive:
            up += 1
        t.add_row(host, status, rtt if alive else "[dim_text]—[/dim_text]")

    console.print(t)
    return up


def run(session):
    section_header("PING SWEEP", "ICMP")

    if not session.target:
        warning("No target set.")
        return

    scope = select("Scope:", [
        {"name": "All subdomains + root target", "value": "all"} if session.subdomains else None,
        {"name": f"Root target only — {session.target}", "value": "root"},
        {"name": "? Help",  "value": "help"},
        {"name": "← Back", "value": "back"},
    ])

    if scope == "back":
        return
    if scope == "help":
        _show_help()
        return run(session)

    if scope == "all" and session.subdomains:
        hosts = [session.target] + [sd["subdomain"] for sd in session.subdomains]
    else:
        hosts = [session.target]

    count = select("Packets per host:", [
        {"name": "1 — fastest",         "value": 1},
        {"name": "3 — recommended",     "value": 3},
        {"name": "5 — most accurate",   "value": 5},
    ])

    if not confirm(f"Ping {len(hosts)} host(s)?", default=True):
        dim("Cancelled.")
        return

    with spinner(f"  Pinging {len(hosts)} host(s)..."):
        results = _ping_all(hosts, count)

    console.print()
    up = _render_table(results)
    console.print()
    info(f"{up} / {len(hosts)} hosts responding to ICMP")

    # Update subdomain status from results
    for sd in session.subdomains:
        if sd["subdomain"] in results:
            alive, _ = results[sd["subdomain"]]
            sd["status"] = "up" if alive else "down"

    down_hosts = [h for h, (alive, _) in results.items() if not alive]
    if down_hosts:
        session.add_finding(
            "INFO", "Ping Sweep", session.target,
            f"{len(down_hosts)} host(s) not responding to ICMP (may still have open ports)",
        )

    success("Ping sweep complete.")


def _show_help():
    help_panel("PING SWEEP — HELP", {
        "WHAT IT DOES": [
            "Sends ICMP echo requests (-c N packets, -W 2 second timeout).",
            "Runs all pings in parallel — fast even across large subdomain lists.",
            "Updates the subdomain table status column (up/down).",
        ],
        "IMPORTANT": [
            "A DOWN result does NOT confirm the host is offline.",
            "Many hosts and firewalls block ICMP while still serving TCP.",
            "Use Port Scan to confirm — open TCP ports mean the host is alive.",
        ],
    })
