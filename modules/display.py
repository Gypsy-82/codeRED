from contextlib import contextmanager
from rich.console import Console
from rich.theme import Theme
from rich.table import Table
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich import box
from InquirerPy import inquirer
from InquirerPy.separator import Separator

_THEME = Theme({
    "critical":  "bold red",
    "warning":   "yellow",
    "clean":     "bold green",
    "info":      "cyan",
    "label":     "blue",
    "tool":      "bold magenta",
    "header":    "bold cyan",
    "dim_text":  "dim white",
    "highlight": "bold white",
    "severity.critical": "bold red",
    "severity.high":     "red",
    "severity.warning":  "yellow",
    "severity.medium":   "yellow",
    "severity.info":     "cyan",
    "severity.clean":    "bold green",
})

console = Console(theme=_THEME)

_SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "WARNING":  "yellow",
    "MEDIUM":   "yellow",
    "INFO":     "cyan",
    "LOW":      "dim cyan",
    "CLEAN":    "bold green",
}

_TYPE_STYLE = {
    "web server":      "cyan",
    "mail server":     "blue",
    "database server": "magenta",
    "cdn":             "yellow",
    "nameserver":      "green",
    "kubernetes":      "bold cyan",
    "docker":          "bold red",
    "unknown":         "dim",
}

_BANNER = """\
[bold red]
██████╗ ███████╗██████╗     ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔══██╗    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██████╔╝█████╗  ██║  ██║    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██╔══██╗██╔══╝  ██║  ██║    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██║  ██║███████╗██████╔╝    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚══════╝╚═════╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
[/bold red][dim]  Confirm the door is unlocked, don't walk through it.[/dim]
"""


def banner():
    console.clear()
    console.print(_BANNER)


def section_header(title, subtitle=""):
    console.print()
    text = f"[tool]{title}[/tool]"
    if subtitle:
        text += f"  [dim_text]{subtitle}[/dim_text]"
    console.rule(text)
    console.print()


def rule(title=""):
    if title:
        console.rule(f"[dim_text]{title}[/dim_text]")
    else:
        console.rule()


def critical(message):
    console.print(f"  [critical]✖  {message}[/critical]")


def warning(message):
    console.print(f"  [warning]⚠  {message}[/warning]")


def success(message):
    console.print(f"  [clean]✓  {message}[/clean]")


def info(message):
    console.print(f"  [info]ℹ  {message}[/info]")


def label(field, value, value_style="white"):
    console.print(f"  [label]{field:<16}[/label] [{value_style}]{value}[/{value_style}]")


def dim(message):
    console.print(f"  [dim_text]{message}[/dim_text]")


def panel(content, title="", border_style="cyan"):
    console.print(Panel(content, title=title, border_style=border_style, padding=(0, 1)))


def finding(severity, title, details: dict):
    sev = severity.upper()
    style = _SEVERITY_STYLE.get(sev, "white")
    border = style.replace("bold ", "")

    lines = []
    for key, val in details.items():
        lines.append(f"[label]{key:<14}[/label]{val}")

    console.print(Panel(
        "\n".join(lines),
        title=f"[{style}] {sev} [/{style}]  [highlight]{title}[/highlight]",
        border_style=border,
        padding=(0, 1),
    ))


def type_badge(service_type: str) -> str:
    style = _TYPE_STYLE.get(service_type.lower(), "dim")
    return f"[{style}]{service_type}[/{style}]"


def severity_badge(severity: str) -> str:
    sev = severity.upper()
    style = _SEVERITY_STYLE.get(sev, "white")
    return f"[{style}]{sev}[/{style}]"


def subdomain_table(subdomains: list):
    """
    subdomains: list of dicts with keys:
        num, subdomain, ip, type, status
    """
    t = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="header", padding=(0, 1))
    t.add_column("#",          style="dim",       width=4,  justify="right")
    t.add_column("Subdomain",  style="highlight", min_width=30)
    t.add_column("IP",         style="info",      width=16)
    t.add_column("Type",       min_width=16)
    t.add_column("Status",     width=8,           justify="center")

    for sd in subdomains:
        status_style = "clean" if sd.get("status", "").lower() == "up" else "dim_text"
        t.add_row(
            str(sd.get("num", "")),
            sd.get("subdomain", ""),
            sd.get("ip", "—"),
            type_badge(sd.get("type", "unknown")),
            f"[{status_style}]{sd.get('status', '?')}[/{status_style}]",
        )

    console.print(t)


def port_table(ports: list):
    """
    ports: list of dicts with keys:
        port, protocol, state, service, version
    """
    t = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="header", padding=(0, 1))
    t.add_column("Port",     style="highlight", width=8)
    t.add_column("Proto",    style="dim_text",  width=6)
    t.add_column("State",    width=10)
    t.add_column("Service",  style="info",      min_width=14)
    t.add_column("Version",  style="dim_text",  min_width=20)

    for p in ports:
        state = p.get("state", "unknown").lower()
        if state == "open":
            state_str = "[clean]open[/clean]"
        elif state == "filtered":
            state_str = "[warning]filtered[/warning]"
        else:
            state_str = "[dim_text]closed[/dim_text]"

        t.add_row(
            str(p.get("port", "")),
            p.get("protocol", "tcp"),
            state_str,
            p.get("service", ""),
            p.get("version", ""),
        )

    console.print(t)


def findings_summary(findings: list):
    if not findings:
        success("No findings recorded this session.")
        return

    t = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="header", padding=(0, 1))
    t.add_column("Severity", width=10)
    t.add_column("Module",   style="tool",      width=20)
    t.add_column("Target",   style="info",      min_width=24)
    t.add_column("Finding",  style="highlight", min_width=30)

    for f in findings:
        t.add_row(
            severity_badge(f.get("severity", "INFO")),
            f.get("module", ""),
            f.get("target", ""),
            f.get("finding", ""),
        )

    console.print(t)


@contextmanager
def spinner(message):
    with console.status(f"[info]{message}[/info]", spinner="dots") as status:
        yield status


@contextmanager
def progress_bar(description="Working"):
    with Progress(
        SpinnerColumn(),
        TextColumn("[info]{task.description}[/info]"),
        BarColumn(bar_width=40),
        TaskProgressColumn(),
        console=console,
        transient=True,
    ) as prog:
        yield prog


# ── Interactive prompt helpers ─────────────────────────────────────────────────

def confirm(message, default=False):
    return inquirer.confirm(message=message, default=default).execute()


def select(message, choices, instruction="(↑↓ navigate  Enter select)"):
    return inquirer.select(
        message=message,
        choices=choices,
        pointer="❯",
        instruction=instruction,
    ).execute()


def text_input(message, validate=None, default=""):
    return inquirer.text(
        message=message,
        default=default,
        validate=validate,
    ).execute()


def checkbox(message, choices, instruction="(↑↓ navigate  Space toggle  Enter confirm)"):
    return inquirer.checkbox(
        message=message,
        choices=choices,
        pointer="❯",
        instruction=instruction,
        transformer=lambda result: f"{len(result)} selected",
    ).execute()


# ── Help panel ─────────────────────────────────────────────────────────────────

def help_panel(title: str, sections: dict):
    """
    sections: dict of { "Section Title": ["line1", "line2", ...] }
    """
    lines = []
    for section_title, content_lines in sections.items():
        lines.append(f"\n[header]{section_title}[/header]")
        for line in content_lines:
            lines.append(f"  [dim_text]{line}[/dim_text]")

    console.print(Panel(
        "\n".join(lines).strip(),
        title=f"[tool]{title}[/tool]",
        border_style="magenta",
        padding=(1, 2),
    ))
