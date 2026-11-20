"""Rich-powered CLI for LaptopShield Pro."""

from __future__ import annotations

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from laptopshield import __version__
from laptopshield.core.hardening import HardeningEngine
from laptopshield.core.privilege import is_admin
from laptopshield.core.scanner import (
    export_audit_report,
    kill_all_remote_tools,
    scan_hosts_file,
    scan_local_accounts,
    scan_network_connections,
    scan_remote_tools,
    scan_scheduled_tasks,
    scan_startup_entries,
)

app = typer.Typer(
    name="laptopshield",
    help="LaptopShield Pro — Windows Endpoint Hardening, Privacy Kill-Switch & Threat Audit CLI",
    add_completion=False,
)
console = Console()


@app.command()
def status() -> None:
    """Display current hardening posture, security score, and admin status."""
    engine = HardeningEngine()
    statuses = engine.list_controls()
    score = engine.calculate_score(statuses)

    admin_badge = "[bold green]ADMIN[/bold green]" if is_admin() else "[bold yellow]LIMITED USER[/bold yellow]"
    score_color = "green" if score >= 80 else ("yellow" if score >= 50 else "red")

    console.print(
        Panel.fit(
            f"[bold cyan]LaptopShield Pro v{__version__}[/bold cyan]  |  "
            f"Privilege: {admin_badge}  |  "
            f"Hardening Score: [bold {score_color}]{score}%[/bold {score_color}]",
            border_style="cyan",
        )
    )

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("ID", style="dim", width=14)
    table.add_column("Control", width=34)
    table.add_column("State", width=12)
    table.add_column("Details")

    for st in statuses:
        state_str = "[bold green]LOCKED[/bold green]" if st.is_locked else "[bold red]EXPOSED[/bold red]"
        table.add_row(st.control_id, st.name, state_str, st.detail)

    console.print(table)


@app.command()
def lockdown() -> None:
    """Apply full emergency endpoint lockdown and kill remote-access tools."""
    engine = HardeningEngine()
    console.print("[bold red]Initiating full endpoint lockdown...[/bold red]")
    results = engine.lockdown_all()
    for r in results:
        icon = "[green]OK[/green]" if r.success else "[red]ERR[/red]"
        console.print(f"  {icon} [{r.control_id}] {r.message}")

    killed = kill_all_remote_tools()
    if killed:
        for pid, name, ok, msg in killed:
            console.print(f"  [yellow]KILLED[/yellow] {name} (PID {pid}): {msg}")
    else:
        console.print("  [green]OK[/green] No active remote-access tools found.")

    score = engine.calculate_score()
    console.print(f"\n[bold cyan]New Hardening Score: {score}%[/bold cyan]")


@app.command("restore-all")
def restore_all() -> None:
    """Restore all reversible privacy and network controls (Windows Firewall remains ON)."""
    engine = HardeningEngine()
    console.print("[bold yellow]Restoring all reversible controls...[/bold yellow]")
    for r in engine.restore_all():
        icon = "[green]OK[/green]" if r.success else "[red]ERR[/red]"
        console.print(f"  {icon} [{r.control_id}] {r.message}")
    console.print(f"\n[bold cyan]Current Hardening Score: {engine.calculate_score()}%[/bold cyan]")


@app.command("kill-remote")
def kill_remote() -> None:
    """Terminate all running remote-access tools (AnyDesk, TeamViewer, RustDesk, VNC, etc.)."""
    killed = kill_all_remote_tools()
    if not killed:
        console.print("[green]No remote-access tools are currently running.[/green]")
        return
    for pid, name, ok, msg in killed:
        tag = "[green]KILLED[/green]" if ok else "[red]FAILED[/red]"
        console.print(f"{tag} {name} (PID {pid}): {msg}")


@app.command()
def audit(export: str = typer.Option("", "--export", "-e", help="Optional JSON report output path")) -> None:
    """Run a deep audit of remote tools, active network sockets, and startup persistence."""
    remote = scan_remote_tools()
    conns = scan_network_connections(25)
    startup = scan_startup_entries()

    console.print(f"\n[bold cyan]1. Running Remote Tools ({len(remote)})[/bold cyan]")
    if remote:
        for r in remote:
            console.print(f"  [red]! {r.name}[/red] (PID {r.pid}) -> {r.exe}")
    else:
        console.print("  [green]None detected.[/green]")

    console.print(f"\n[bold cyan]2. Top Network Connections ({len(conns)})[/bold cyan]")
    net_tbl = Table(show_header=True)
    net_tbl.add_column("Risk")
    net_tbl.add_column("Process")
    net_tbl.add_column("PID")
    net_tbl.add_column("Remote")
    for c in conns[:15]:
        color = "red" if c.risk == "HIGH" else ("yellow" if c.risk == "MEDIUM" else "green")
        net_tbl.add_row(f"[{color}]{c.risk}[/{color}]", c.process, str(c.pid), c.remote_addr)
    console.print(net_tbl)

    flagged = [s for s in startup if s.flagged]
    console.print(f"\n[bold cyan]3. Startup Entries ({len(startup)} total, {len(flagged)} flagged)[/bold cyan]")
    for s in startup:
        prefix = "[red]FLAGGED[/red]" if s.flagged else "[green]OK[/green]"
        console.print(f"  {prefix} [{s.scope}] {s.name}: {s.command}")

    if export:
        engine = HardeningEngine()
        statuses = engine.list_controls()
        err = export_audit_report(export, statuses, engine.calculate_score(statuses))
        if err:
            console.print(f"[red]Export failed: {err}[/red]")
        else:
            console.print(f"\n[green]Report saved to {export}[/green]")


@app.command()
def forensics() -> None:
    """Deep forensic audit: non-Microsoft scheduled tasks, local admin accounts & hosts file."""
    tasks = scan_scheduled_tasks(30)
    accounts = scan_local_accounts()
    hosts = scan_hosts_file()

    console.print(f"\n[bold cyan]1. Local Accounts ({len(accounts)})[/bold cyan]")
    acct_tbl = Table(show_header=True)
    acct_tbl.add_column("Account")
    acct_tbl.add_column("Enabled")
    acct_tbl.add_column("Role")
    acct_tbl.add_column("Last Logon")
    for a in accounts:
        role = "[yellow]Admin[/yellow]" if a.is_admin else "Standard"
        acct_tbl.add_row(a.name, "Yes" if a.enabled else "No", role, a.last_logon)
    console.print(acct_tbl)

    flagged_tasks = [t for t in tasks if t.flagged]
    console.print(f"\n[bold cyan]2. Non-Microsoft Scheduled Tasks ({len(tasks)} total, {len(flagged_tasks)} flagged)[/bold cyan]")
    for t in tasks[:20]:
        tag = "[red]FLAGGED[/red]" if t.flagged else "[green]OK[/green]"
        console.print(f"  {tag} {t.name} ({t.state}) -> {t.action}")

    console.print(f"\n[bold cyan]3. Hosts File Overrides ({len(hosts)})[/bold cyan]")
    if hosts:
        for h in hosts:
            console.print(f"  [yellow]{h}[/yellow]")
    else:
        console.print("  [green]Clean (no custom host overrides).[/green]")


@app.command()
def gui() -> None:
    """Launch the LaptopShield Pro PyQt5 Graphical Interface."""
    from laptopshield.ui.app import main as launch_gui

    launch_gui()


if __name__ == "__main__":
    app()
