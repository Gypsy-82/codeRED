import sys
import subprocess
import shutil

REQUIRED_PACKAGES = [
    ("rich",        "rich>=13.0.0"),
    ("InquirerPy",  "InquirerPy>=0.3.4"),
    ("paramiko",    "paramiko>=3.0.0"),
    ("requests",    "requests>=2.31.0"),
]

SYSTEM_TOOLS = [
    ("subfinder", "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    ("amass",     "sudo apt install amass"),
    ("nmap",      "sudo apt install nmap"),
    ("nikto",     "sudo apt install nikto"),
    ("dig",       "sudo apt install dnsutils"),
    ("whois",     "sudo apt install whois"),
    ("ping",      "sudo apt install iputils-ping"),
]

_VENV_MSG = """
\033[1;31m
  ╔══════════════════════════════════════════════════════════╗
  ║         VIRTUAL ENVIRONMENT REQUIRED                    ║
  ╠══════════════════════════════════════════════════════════╣
  ║                                                         ║
  ║  Red Recon will not run outside a virtual environment.  ║
  ║  All dependencies stay isolated — clean uninstall.      ║
  ║                                                         ║
  ║  Run these commands:                                    ║
  ║                                                         ║
  ║    python3 -m venv red_env                              ║
  ║    source red_env/bin/activate                          ║
  ║    python3 brain.py                                     ║
  ║                                                         ║
  ║  Your prompt will show (red_env) when active.           ║
  ║  To deactivate when done: deactivate                    ║
  ║                                                         ║
  ╚══════════════════════════════════════════════════════════╝
\033[0m"""


def is_venv():
    return (
        hasattr(sys, "real_prefix") or
        (hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix)
    )


def _install(package_spec):
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", "-q", package_spec],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _check_python_deps():
    # Install rich first so all further output can use it
    try:
        import rich  # noqa: F401
    except ImportError:
        print("  Installing rich...")
        _install("rich>=13.0.0")

    from rich.console import Console
    c = Console()
    c.print("\n[cyan]  Python dependencies[/cyan]")

    for import_name, package_spec in REQUIRED_PACKAGES:
        try:
            __import__(import_name)
            c.print(f"    [green]✓[/green]  {import_name}")
        except ImportError:
            c.print(f"    [yellow]⟳[/yellow]  {import_name} — installing...")
            try:
                _install(package_spec)
                c.print(f"    [green]✓[/green]  {import_name}")
            except subprocess.CalledProcessError:
                c.print(f"    [bold red]✗[/bold red]  {import_name} — install failed")
                c.print(f"       [dim]pip install {package_spec}[/dim]")
                sys.exit(1)


def _check_system_tools():
    from rich.console import Console
    c = Console()
    c.print("\n[cyan]  System tools[/cyan]")

    available = {}
    for tool, install_cmd in SYSTEM_TOOLS:
        path = shutil.which(tool)
        if path:
            c.print(f"    [green]✓[/green]  {tool:<12} [dim]{path}[/dim]")
            available[tool] = path
        else:
            c.print(f"    [yellow]⚠[/yellow]  {tool:<12} [dim]not found — {install_cmd}[/dim]")

    return available


def run():
    if not is_venv():
        print(_VENV_MSG)
        sys.exit(1)

    _check_python_deps()
    available = _check_system_tools()

    from rich.console import Console
    Console().print()
    return available
