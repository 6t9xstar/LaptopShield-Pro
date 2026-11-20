"""Windows endpoint hardening engine with live state inspection and kill-switches."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List, Tuple

from laptopshield.core.privilege import read_reg_value, run_powershell, write_reg_value


@dataclass(frozen=True)
class ControlResult:
    """Result of applying or reverting a hardening control."""

    control_id: str
    success: bool
    locked: bool
    message: str


@dataclass(frozen=True)
class ControlStatus:
    """Live state of a single hardening control."""

    control_id: str
    name: str
    category: str
    description: str
    risk_weight: int
    is_locked: bool
    detail: str


class HardeningEngine:
    """Inspects and enforces Windows security & privacy hardening controls."""

    # Registry paths
    _RDP_KEY = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
    _RA_KEY = r"SYSTEM\CurrentControlSet\Control\Remote Assistance"
    _CAM_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam"
    _CAM_NP_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\NonPackaged"
    _MIC_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone"
    _MIC_NP_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\NonPackaged"
    _LOC_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
    _APP_PRIVACY_KEY = r"SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
    _DNS_POLICY_KEY = r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    _WSH_KEY = r"SOFTWARE\Microsoft\Windows Script Host\Settings"
    _AUTORUN_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    _SMB_PARAMS_KEY = r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    _FIREWALL_DOMAIN = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"
    _FIREWALL_STANDARD = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"
    _FIREWALL_PUBLIC = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"

    def __init__(self) -> None:
        self._controls: List[Dict] = [
            {
                "id": "rdp",
                "name": "Remote Desktop (RDP) & Assistance",
                "category": "network",
                "description": "Blocks incoming RDP (port 3389), TermService connections & Remote Assistance.",
                "weight": 15,
                "check": self._check_rdp,
                "lock": self._lock_rdp,
                "unlock": self._unlock_rdp,
            },
            {
                "id": "camera",
                "name": "Webcam Global Kill-Switch",
                "category": "privacy",
                "description": "Denies system-wide camera access (HKLM & HKCU ConsentStore) for all apps.",
                "weight": 15,
                "check": self._check_camera,
                "lock": self._lock_camera,
                "unlock": self._unlock_camera,
            },
            {
                "id": "microphone",
                "name": "Microphone Global Kill-Switch",
                "category": "privacy",
                "description": "Blocks background eavesdropping and unauthorized audio capture.",
                "weight": 15,
                "check": self._check_microphone,
                "lock": self._lock_microphone,
                "unlock": self._unlock_microphone,
            },
            {
                "id": "location",
                "name": "Device Location Tracking",
                "category": "privacy",
                "description": "Denies system-wide GPS/Wi-Fi geolocation access to apps and services.",
                "weight": 5,
                "check": self._check_location,
                "lock": self._lock_location,
                "unlock": self._unlock_location,
            },
            {
                "id": "smb",
                "name": "SMB File Sharing & SMBv1",
                "category": "network",
                "description": "Disables legacy SMBv1 and blocks inbound File & Printer Sharing (ports 445/139).",
                "weight": 15,
                "check": self._check_smb,
                "lock": self._lock_smb,
                "unlock": self._unlock_smb,
            },
            {
                "id": "winrm",
                "name": "WinRM / PowerShell Remoting",
                "category": "network",
                "description": "Stops WinRM service and blocks remote PowerShell execution (ports 5985/5986).",
                "weight": 10,
                "check": self._check_winrm,
                "lock": self._lock_winrm,
                "unlock": self._unlock_winrm,
            },
            {
                "id": "llmnr",
                "name": "LLMNR Spoofing Protection",
                "category": "network",
                "description": "Disables Link-Local Multicast Name Resolution to stop Wi-Fi credential theft.",
                "weight": 10,
                "check": self._check_llmnr,
                "lock": self._lock_llmnr,
                "unlock": self._unlock_llmnr,
            },
            {
                "id": "wsh_autorun",
                "name": "Windows Script Host & USB AutoRun",
                "category": "system",
                "description": "Blocks .vbs/.js script malware droppers and disables removable drive AutoRun.",
                "weight": 10,
                "check": self._check_wsh_autorun,
                "lock": self._lock_wsh_autorun,
                "unlock": self._unlock_wsh_autorun,
            },
            {
                "id": "firewall",
                "name": "Windows Defender Firewall (All Profiles)",
                "category": "system",
                "description": "Enforces active Windows Firewall across Domain, Private, and Public networks.",
                "weight": 5,
                "check": self._check_firewall,
                "lock": self._lock_firewall,
                "unlock": self._lock_firewall,
            },
        ]

    def list_controls(self) -> List[ControlStatus]:
        """Return live status for all hardening controls."""
        statuses: List[ControlStatus] = []
        for ctrl in self._controls:
            locked, detail = ctrl["check"]()
            statuses.append(
                ControlStatus(
                    control_id=ctrl["id"],
                    name=ctrl["name"],
                    category=ctrl["category"],
                    description=ctrl["description"],
                    risk_weight=ctrl["weight"],
                    is_locked=locked,
                    detail=detail,
                )
            )
        return statuses

    def set_control(self, control_id: str, lock: bool) -> ControlResult:
        """Enable (lock=True) or disable (lock=False) a specific control."""
        for ctrl in self._controls:
            if ctrl["id"] == control_id:
                fn: Callable[[], Tuple[bool, str]] = ctrl["lock"] if lock else ctrl["unlock"]
                ok, msg = fn()
                locked_now, _ = ctrl["check"]()
                return ControlResult(
                    control_id=control_id,
                    success=ok,
                    locked=locked_now,
                    message=msg,
                )
        return ControlResult(
            control_id=control_id,
            success=False,
            locked=False,
            message=f"Unknown control: {control_id}",
        )

    def lockdown_all(self) -> List[ControlResult]:
        """Activate every hardening control in the suite."""
        return [self.set_control(ctrl["id"], True) for ctrl in self._controls]

    def restore_privacy_only(self) -> List[ControlResult]:
        """Re-enable Camera and Microphone for legitimate calls while keeping network locks."""
        return [
            self.set_control("camera", False),
            self.set_control("microphone", False),
        ]

    def calculate_score(self, statuses: List[ControlStatus] | None = None) -> int:
        """Compute 0-100 hardening score from live control states."""
        items = statuses if statuses is not None else self.list_controls()
        total = sum(s.risk_weight for s in items)
        earned = sum(s.risk_weight for s in items if s.is_locked)
        if total == 0:
            return 0
        return round((earned / total) * 100)

    # --- Individual Checks & Enforcers ---

    def _check_rdp(self) -> Tuple[bool, str]:
        rdp = read_reg_value("HKEY_LOCAL_MACHINE", self._RDP_KEY, "fDenyTSConnections")
        ra = read_reg_value("HKEY_LOCAL_MACHINE", self._RA_KEY, "fAllowToGetHelp")
        if rdp == 1 and (ra in (0, None)):
            return True, "RDP & Remote Assistance disabled"
        return False, "RDP or Remote Assistance enabled"

    def _lock_rdp(self) -> Tuple[bool, str]:
        ok1, msg1 = write_reg_value("HKEY_LOCAL_MACHINE", self._RDP_KEY, "fDenyTSConnections", 1)
        ok2, msg2 = write_reg_value("HKEY_LOCAL_MACHINE", self._RA_KEY, "fAllowToGetHelp", 0)
        run_powershell('Disable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue')
        if ok1 and ok2:
            return True, "RDP, Remote Assistance & Firewall rules locked"
        return False, f"Partial/Denied: {msg1}; {msg2}"

    def _unlock_rdp(self) -> Tuple[bool, str]:
        ok, msg = write_reg_value("HKEY_LOCAL_MACHINE", self._RDP_KEY, "fDenyTSConnections", 0)
        return ok, "RDP re-enabled" if ok else msg

    def _check_consent(self, subkey: str, label: str) -> Tuple[bool, str]:
        hklm = read_reg_value("HKEY_LOCAL_MACHINE", subkey, "Value")
        hkcu = read_reg_value("HKEY_CURRENT_USER", subkey, "Value")
        if str(hklm).lower() == "deny" or str(hkcu).lower() == "deny":
            scope = "System + User" if (str(hklm).lower() == "deny" and str(hkcu).lower() == "deny") else "User/System"
            return True, f"{label} denied ({scope})"
        return False, f"{label} allowed"

    def _set_consent(self, subkey: str, value: str, label: str) -> Tuple[bool, str]:
        ok_u, msg_u = write_reg_value("HKEY_CURRENT_USER", subkey, "Value", value, "REG_SZ")
        ok_m, msg_m = write_reg_value("HKEY_LOCAL_MACHINE", subkey, "Value", value, "REG_SZ")
        if ok_m or ok_u:
            return True, f"{label} set to {value}"
        return False, f"Failed: {msg_m} / {msg_u}"

    def _check_camera(self) -> Tuple[bool, str]:
        hklm = str(read_reg_value("HKEY_LOCAL_MACHINE", self._CAM_KEY, "Value") or "").lower()
        hkcu_np = str(read_reg_value("HKEY_CURRENT_USER", self._CAM_NP_KEY, "Value") or "").lower()
        policy = read_reg_value("HKEY_LOCAL_MACHINE", self._APP_PRIVACY_KEY, "LetAppsAccessCamera")
        if hklm == "deny" and hkcu_np == "deny" and policy == 2:
            return True, "Camera fully locked (Driver + NonPackaged + Policy)"
        if hkcu_np == "allow" or policy != 2:
            return False, "Desktop apps (Chrome/Win32) can still access Camera"
        return False, "Camera allowed"

    def _lock_camera(self) -> Tuple[bool, str]:
        self._set_consent(self._CAM_KEY, "Deny", "Camera")
        ok_np, _ = self._set_consent(self._CAM_NP_KEY, "Deny", "Camera (Desktop Apps)")
        ok_pol, msg_pol = write_reg_value(
            "HKEY_LOCAL_MACHINE", self._APP_PRIVACY_KEY, "LetAppsAccessCamera", 2
        )
        rc, _, err = run_powershell(
            "Get-PnpDevice -Class Camera,Image -ErrorAction SilentlyContinue | "
            "Where-Object { $_.Status -eq 'OK' } | "
            "Disable-PnpDevice -Confirm:$false -ErrorAction Stop"
        )
        if ok_pol and rc == 0:
            return True, "Camera hardware driver + Policy + Chrome/Desktop apps BLOCKED"
        if ok_np:
            return (
                ok_pol,
                f"Registry/Desktop apps blocked; hardware driver lock needs Admin ({err or msg_pol})",
            )
        return False, f"Failed: {msg_pol} {err}"

    def _unlock_camera(self) -> Tuple[bool, str]:
        self._set_consent(self._CAM_KEY, "Allow", "Camera")
        self._set_consent(self._CAM_NP_KEY, "Allow", "Camera (Desktop Apps)")
        write_reg_value("HKEY_LOCAL_MACHINE", self._APP_PRIVACY_KEY, "LetAppsAccessCamera", 0)
        rc, _, err = run_powershell(
            "Get-PnpDevice -Class Camera,Image -ErrorAction SilentlyContinue | "
            "Enable-PnpDevice -Confirm:$false -ErrorAction SilentlyContinue"
        )
        return (True, "Camera hardware driver & app access RESTORED") if rc == 0 else (
            True,
            f"App access restored (run as Admin if hardware driver stays off: {err})",
        )

    def _check_microphone(self) -> Tuple[bool, str]:
        hklm = str(read_reg_value("HKEY_LOCAL_MACHINE", self._MIC_KEY, "Value") or "").lower()
        hkcu_np = str(read_reg_value("HKEY_CURRENT_USER", self._MIC_NP_KEY, "Value") or "").lower()
        policy = read_reg_value("HKEY_LOCAL_MACHINE", self._APP_PRIVACY_KEY, "LetAppsAccessMicrophone")
        if hklm == "deny" and hkcu_np == "deny" and policy == 2:
            return True, "Microphone fully locked (Policy + NonPackaged + System)"
        return False, "Microphone allowed for desktop/UWP apps"

    def _lock_microphone(self) -> Tuple[bool, str]:
        self._set_consent(self._MIC_KEY, "Deny", "Microphone")
        ok_np, _ = self._set_consent(self._MIC_NP_KEY, "Deny", "Microphone (Desktop Apps)")
        ok_pol, msg_pol = write_reg_value(
            "HKEY_LOCAL_MACHINE", self._APP_PRIVACY_KEY, "LetAppsAccessMicrophone", 2
        )
        if ok_pol and ok_np:
            return True, "Microphone Policy + Chrome/Desktop apps BLOCKED"
        return ok_np, f"User-level blocked; system policy needs Admin ({msg_pol})"

    def _unlock_microphone(self) -> Tuple[bool, str]:
        self._set_consent(self._MIC_KEY, "Allow", "Microphone")
        self._set_consent(self._MIC_NP_KEY, "Allow", "Microphone (Desktop Apps)")
        write_reg_value("HKEY_LOCAL_MACHINE", self._APP_PRIVACY_KEY, "LetAppsAccessMicrophone", 0)
        return True, "Microphone access RESTORED"

    def _check_location(self) -> Tuple[bool, str]:
        return self._check_consent(self._LOC_KEY, "Location")

    def _lock_location(self) -> Tuple[bool, str]:
        return self._set_consent(self._LOC_KEY, "Deny", "Location")

    def _unlock_location(self) -> Tuple[bool, str]:
        return self._set_consent(self._LOC_KEY, "Allow", "Location")

    def _check_smb(self) -> Tuple[bool, str]:
        smb1 = read_reg_value("HKEY_LOCAL_MACHINE", self._SMB_PARAMS_KEY, "SMB1")
        if smb1 == 0:
            return True, "SMBv1 disabled & SMB-In hardened"
        return False, "SMBv1 policy not explicitly disabled"

    def _lock_smb(self) -> Tuple[bool, str]:
        ok, msg = write_reg_value("HKEY_LOCAL_MACHINE", self._SMB_PARAMS_KEY, "SMB1", 0)
        run_powershell(
            'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue; '
            'Set-NetFirewallRule -DisplayGroup "File and Printer Sharing" -Enabled False -ErrorAction SilentlyContinue'
        )
        return (True, "SMBv1 & File Sharing blocked") if ok else (False, msg)

    def _unlock_smb(self) -> Tuple[bool, str]:
        run_powershell(
            'Set-NetFirewallRule -DisplayGroup "File and Printer Sharing" -Enabled True -ErrorAction SilentlyContinue'
        )
        return True, "File and Printer Sharing firewall rules restored"

    def _check_winrm(self) -> Tuple[bool, str]:
        start_val = read_reg_value(
            "HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\WinRM", "Start"
        )
        # 4 = Disabled
        if start_val == 4:
            return True, "WinRM service disabled"
        return False, "WinRM service not disabled (Manual/Auto)"

    def _lock_winrm(self) -> Tuple[bool, str]:
        rc, _, err = run_powershell(
            "Stop-Service WinRM -Force -ErrorAction SilentlyContinue; "
            "Set-Service WinRM -StartupType Disabled -ErrorAction SilentlyContinue"
        )
        ok, msg = write_reg_value(
            "HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\WinRM", "Start", 4
        )
        if ok or rc == 0:
            return True, "WinRM stopped & disabled"
        return False, msg or err

    def _unlock_winrm(self) -> Tuple[bool, str]:
        ok, msg = write_reg_value(
            "HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services\WinRM", "Start", 3
        )
        return ok, "WinRM set to Manual" if ok else msg

    def _check_llmnr(self) -> Tuple[bool, str]:
        val = read_reg_value("HKEY_LOCAL_MACHINE", self._DNS_POLICY_KEY, "EnableMulticast")
        if val == 0:
            return True, "LLMNR disabled (EnableMulticast=0)"
        return False, "LLMNR active (vulnerable to LAN spoofing)"

    def _lock_llmnr(self) -> Tuple[bool, str]:
        ok, msg = write_reg_value("HKEY_LOCAL_MACHINE", self._DNS_POLICY_KEY, "EnableMulticast", 0)
        return (True, "LLMNR disabled") if ok else (False, msg)

    def _unlock_llmnr(self) -> Tuple[bool, str]:
        ok, msg = write_reg_value("HKEY_LOCAL_MACHINE", self._DNS_POLICY_KEY, "EnableMulticast", 1)
        return (True, "LLMNR restored") if ok else (False, msg)

    def _check_wsh_autorun(self) -> Tuple[bool, str]:
        wsh = read_reg_value("HKEY_LOCAL_MACHINE", self._WSH_KEY, "Enabled")
        ar = read_reg_value("HKEY_LOCAL_MACHINE", self._AUTORUN_KEY, "NoDriveTypeAutoRun")
        if wsh == 0 and ar == 255:
            return True, "WSH & USB AutoRun disabled"
        return False, "WSH or USB AutoRun still permitted"

    def _lock_wsh_autorun(self) -> Tuple[bool, str]:
        ok1, msg1 = write_reg_value("HKEY_LOCAL_MACHINE", self._WSH_KEY, "Enabled", 0)
        ok2, msg2 = write_reg_value("HKEY_LOCAL_MACHINE", self._AUTORUN_KEY, "NoDriveTypeAutoRun", 255)
        if ok1 and ok2:
            return True, "WSH (.vbs/.js) & USB AutoRun blocked"
        return False, f"Failed: {msg1}; {msg2}"

    def _unlock_wsh_autorun(self) -> Tuple[bool, str]:
        ok, msg = write_reg_value("HKEY_LOCAL_MACHINE", self._WSH_KEY, "Enabled", 1)
        return (True, "Windows Script Host re-enabled") if ok else (False, msg)

    def _check_firewall(self) -> Tuple[bool, str]:
        d = read_reg_value("HKEY_LOCAL_MACHINE", self._FIREWALL_DOMAIN, "EnableFirewall")
        s = read_reg_value("HKEY_LOCAL_MACHINE", self._FIREWALL_STANDARD, "EnableFirewall")
        p = read_reg_value("HKEY_LOCAL_MACHINE", self._FIREWALL_PUBLIC, "EnableFirewall")
        if d == 1 and s == 1 and p == 1:
            return True, "Domain, Private & Public Firewalls ON"
        return False, "One or more Windows Firewall profiles OFF"

    def _lock_firewall(self) -> Tuple[bool, str]:
        rc, _, err = run_powershell(
            "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction Stop"
        )
        if rc == 0:
            return True, "All 3 Windows Firewall profiles enforced ON"
        return False, err or "Administrator privileges required to enforce Firewall"
