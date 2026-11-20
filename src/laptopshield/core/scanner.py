"""Live endpoint telemetry: remote-access process guard, network monitor & startup auditor."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import psutil

from laptopshield.core.privilege import run_powershell

try:
    import winreg
except ImportError:  # pragma: no cover
    winreg = None  # type: ignore[assignment]

REMOTE_TOOL_KEYWORDS: Tuple[str, ...] = (
    "teamviewer",
    "anydesk",
    "screenconnect",
    "logmein",
    "rustdesk",
    "ngrok",
    "tightvnc",
    "ultravnc",
    "tvnserver",
    "winvnc",
    "parsec",
    "splashtop",
    "ultraviewer",
    "radmin",
    "ammyy",
    "supremo",
    "meshagent",
    "tacticalrmm",
    "awesun",
)

SUSPICIOUS_PATH_MARKERS: Tuple[str, ...] = (
    "\\temp\\",
    "\\appdata\\local\\temp\\",
    "\\downloads\\",
    "powershell",
    "wscript",
    "cscript",
    "mshta",
    "rundll32",
    "regsvr32",
    "-encodedcommand",
    " -enc ",
)


@dataclass
class RemoteProcessInfo:
    pid: int
    name: str
    exe: str
    username: str


@dataclass
class NetworkConnectionInfo:
    pid: int
    process: str
    exe: str
    local_addr: str
    remote_addr: str
    status: str
    risk: str  # "LOW", "MEDIUM", "HIGH"


@dataclass
class StartupEntryInfo:
    scope: str
    name: str
    command: str
    flagged: bool
    reason: str


def scan_remote_tools() -> List[RemoteProcessInfo]:
    """Return all currently running remote administration / screen-sharing processes."""
    found: List[RemoteProcessInfo] = []
    for proc in psutil.process_iter(["pid", "name", "exe", "username"]):
        try:
            pname = (proc.info.get("name") or "").lower()
            pexe = (proc.info.get("exe") or "").lower()
            if any(kw in pname or kw in pexe for kw in REMOTE_TOOL_KEYWORDS):
                found.append(
                    RemoteProcessInfo(
                        pid=proc.info["pid"],
                        name=proc.info.get("name") or "unknown",
                        exe=proc.info.get("exe") or "N/A",
                        username=proc.info.get("username") or "N/A",
                    )
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return found


def kill_process_tree(pid: int) -> Tuple[bool, str]:
    """Terminate a process and its child processes by PID."""
    try:
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
        for child in children:
            try:
                child.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        parent.kill()
        parent.wait(timeout=3)
        return True, f"Terminated PID {pid} ({parent.name()})"
    except psutil.NoSuchProcess:
        return True, f"PID {pid} already exited"
    except psutil.AccessDenied:
        return False, f"Access denied terminating PID {pid} (run as Administrator)"
    except Exception as exc:
        return False, str(exc)


def kill_all_remote_tools() -> List[Tuple[int, str, bool, str]]:
    """Kill all detected remote-access tools and return per-process results."""
    results = []
    for item in scan_remote_tools():
        ok, msg = kill_process_tree(item.pid)
        results.append((item.pid, item.name, ok, msg))
    return results


def _classify_connection(proc_name: str, exe_path: str, remote_ip: str, remote_port: int) -> str:
    low_name = proc_name.lower()
    low_exe = exe_path.lower()
    if any(kw in low_name or kw in low_exe for kw in REMOTE_TOOL_KEYWORDS):
        return "HIGH"
    if any(m in low_exe for m in ("\\temp\\", "\\downloads\\", "\\public\\")):
        return "HIGH"
    if remote_ip and remote_port not in (80, 443, 53, 123, 5228, 8443):
        return "MEDIUM"
    return "LOW"


def scan_network_connections(limit: int = 80) -> List[NetworkConnectionInfo]:
    """Inspect active TCP/UDP connections excluding loopback-only traffic."""
    conns: List[NetworkConnectionInfo] = []
    proc_cache: Dict[int, Tuple[str, str]] = {}

    try:
        raw_conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        raw_conns = []

    for c in raw_conns:
        if c.status not in ("ESTABLISHED", "LISTEN"):
            continue
        r_ip = c.raddr.ip if c.raddr else ""
        r_port = c.raddr.port if c.raddr else 0
        if r_ip in ("127.0.0.1", "::1", "0.0.0.0", "::"):
            continue
        if c.status == "LISTEN" and c.laddr.ip in ("127.0.0.1", "::1"):
            continue

        pid = c.pid or 0
        if pid not in proc_cache:
            try:
                p = psutil.Process(pid)
                proc_cache[pid] = (p.name(), p.exe())
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                proc_cache[pid] = ("System/Protected", "")

        pname, pexe = proc_cache[pid]
        local_str = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-"
        remote_str = f"{r_ip}:{r_port}" if c.raddr else "LISTENING"
        risk = _classify_connection(pname, pexe, r_ip, r_port)

        conns.append(
            NetworkConnectionInfo(
                pid=pid,
                process=pname,
                exe=pexe or "N/A",
                local_addr=local_str,
                remote_addr=remote_str,
                status=c.status,
                risk=risk,
            )
        )

    risk_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    conns.sort(key=lambda x: (risk_order.get(x.risk, 3), x.status != "ESTABLISHED", x.process.lower()))
    return conns[:limit]


def scan_startup_entries() -> List[StartupEntryInfo]:
    """Audit Windows Run registry keys for persistence and suspicious launchers."""
    entries: List[StartupEntryInfo] = []
    if winreg is None:
        return entries

    targets = [
        ("HKCU\\Run", winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ("HKCU\\RunOnce", winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ("HKLM\\Run", winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ("HKLM\\RunOnce", winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]

    for scope, hive, subkey in targets:
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        name, val, _ = winreg.EnumValue(key, i)
                        cmd_str = str(val)
                        low_cmd = cmd_str.lower()
                        flagged = False
                        reason = "Normal"
                        for marker in SUSPICIOUS_PATH_MARKERS:
                            if marker in low_cmd:
                                flagged = True
                                reason = f"Suspicious marker: {marker.strip()}"
                                break
                        if not flagged and any(kw in low_cmd for kw in REMOTE_TOOL_KEYWORDS):
                            flagged = True
                            reason = "Remote access tool auto-start"
                        entries.append(
                            StartupEntryInfo(
                                scope=scope,
                                name=name,
                                command=cmd_str,
                                flagged=flagged,
                                reason=reason,
                            )
                        )
                        i += 1
                    except OSError:
                        break
        except OSError:
            continue
    return entries


def get_defender_summary() -> Dict[str, Any]:
    """Query Windows Defender Real-Time Protection and active threat count."""
    ps_cmd = (
        "$s = Get-MpComputerStatus -ErrorAction SilentlyContinue; "
        "$t = @(Get-MpThreat -ErrorAction SilentlyContinue | Where-Object { $_.IsActive -eq $true }); "
        "[PSCustomObject]@{ "
        "Enabled = [bool]$s.AntivirusEnabled; "
        "RealTime = [bool]$s.RealTimeProtectionEnabled; "
        "Behavior = [bool]$s.BehaviorMonitorEnabled; "
        "ActiveThreats = $t.Count "
        "} | ConvertTo-Json -Compress"
    )
    rc, out, _ = run_powershell(ps_cmd, timeout=10)
    if rc == 0 and out:
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            pass
    return {"Enabled": None, "RealTime": None, "Behavior": None, "ActiveThreats": None}


def build_audit_report(hardening_statuses: List[Any], score: int) -> Dict[str, Any]:
    """Compile a structured security audit report dictionary."""
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "security_score": score,
        "controls": [asdict(s) for s in hardening_statuses],
        "remote_tools_running": [asdict(r) for r in scan_remote_tools()],
        "network_connections": [asdict(c) for c in scan_network_connections(50)],
        "startup_entries": [asdict(e) for e in scan_startup_entries()],
        "defender": get_defender_summary(),
    }


def export_audit_report(filepath: str, hardening_statuses: List[Any], score: int) -> Optional[str]:
    """Write the JSON audit report to disk. Returns None on success or error message."""
    try:
        report = build_audit_report(hardening_statuses, score)
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        return None
    except Exception as exc:
        return str(exc)
