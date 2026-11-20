"""Windows privilege, registry, and safe command execution helpers."""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from typing import Any, Optional, Tuple

try:
    import winreg
except ImportError:  # pragma: no cover - non-Windows CI
    winreg = None  # type: ignore[assignment]


def is_admin() -> bool:
    """Return True if the current process has Administrator privileges."""
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def elevate_self(script_args: Optional[list[str]] = None) -> bool:
    """Relaunch the current Python script with UAC Administrator elevation."""
    if os.name != "nt" or is_admin():
        return False
    args = script_args if script_args is not None else sys.argv[1:]
    params = subprocess.list2cmdline([os.path.abspath(sys.argv[0]), *args])
    ret = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, params, None, 1
    )
    return int(ret) > 32


def run_powershell(command: str, timeout: int = 15) -> Tuple[int, str, str]:
    """Execute a PowerShell command safely without spawning a visible console window."""
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        proc = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                command,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=creation_flags,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as exc:
        return -1, "", str(exc)


def read_reg_value(hive_name: str, subkey: str, value_name: str) -> Optional[Any]:
    """Read a Windows registry value, returning None if missing or inaccessible."""
    if winreg is None:
        return None
    hive = getattr(winreg, hive_name, None)
    if hive is None:
        return None
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
            val, _ = winreg.QueryValueEx(key, value_name)
            return val
    except OSError:
        return None


def write_reg_value(
    hive_name: str,
    subkey: str,
    value_name: str,
    value: Any,
    reg_type: str = "REG_DWORD",
) -> Tuple[bool, str]:
    """Create or update a Windows registry value cleanly."""
    if winreg is None:
        return False, "winreg unavailable on this platform"
    hive = getattr(winreg, hive_name, None)
    rtype = getattr(winreg, reg_type, None)
    if hive is None or rtype is None:
        return False, f"Invalid hive or type: {hive_name}/{reg_type}"
    try:
        with winreg.CreateKeyEx(hive, subkey, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, value_name, 0, rtype, value)
        return True, "OK"
    except PermissionError:
        return False, "Administrator privileges required"
    except OSError as exc:
        return False, str(exc)
