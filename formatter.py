from __future__ import annotations

from typing import Dict, List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def print_banner() -> None:
    console.print(
        Panel.fit(
            "[bold]Web Fingerprinting Tool[/bold]\nPassive HTTP-based technology identification",
            border_style="cyan",
        )
    )


def print_summary(target: str, final_url: str, status_code: int, reason: str, elapsed_ms: float) -> None:
    table = Table(title="Summary")
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")
    table.add_row("Target", target)
    table.add_row("Final URL", final_url)
    table.add_row("Status", f"{status_code} {reason}")
    table.add_row("Response Time", f"{elapsed_ms} ms")
    console.print(table)


def print_fingerprint(server: str, powered_by: str, technologies: List[str], confidence: str) -> None:
    table = Table(title="Fingerprint")
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")
    table.add_row("Server", server)
    table.add_row("Powered By", powered_by)
    table.add_row("Detected Technologies", ", ".join(technologies) if technologies else "No strong indicators")
    table.add_row("Confidence", confidence)
    console.print(table)


def print_security(security_headers: Dict[str, str]) -> None:
    table = Table(title="Security Headers")
    table.add_column("Header", style="cyan")
    table.add_column("Status", style="white")
    for key, value in security_headers.items():
        table.add_row(key, value)
    console.print(table)


def print_cookies(cookie_names: List[str]) -> None:
    table = Table(title="Cookies")
    table.add_column("Cookie Name", style="white")
    if cookie_names:
        for cookie in cookie_names:
            table.add_row(cookie)
    else:
        table.add_row("No cookies detected")
    console.print(table)


def print_redirects(redirect_chain: List[str]) -> None:
    table = Table(title="Redirect Chain")
    table.add_column("URL", style="white")
    for url in redirect_chain:
        table.add_row(url)
    console.print(table)