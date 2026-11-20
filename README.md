<div align="center">

# LaptopShield Pro

**Open-Source Windows Endpoint Hardening, 3-Layer Hardware Camera Kill-Switch & Live Threat Forensics Suite**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Windows 10 / 11](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0078D6?style=flat-square&logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![PyQt5 GUI](https://img.shields.io/badge/GUI-PyQt5%20Graphite-41CD52?style=flat-square&logo=qt&logoColor=white)](https://riverbankcomputing.com/software/pyqt/)
[![CI](https://img.shields.io/github/actions/workflow/status/6t9xstar/LaptopShield-Pro/ci.yml?style=flat-square&label=CI)](https://github.com/6t9xstar/LaptopShield-Pro/actions)
[![License: MIT](https://img.shields.io/badge/license-MIT-10b981?style=flat-square)](LICENSE)

*Stop unauthorized remote access, lock down your webcam & microphone at the hardware driver level, kill rogue RAT/screen-sharing tools, and audit persistence mechanisms in seconds.*

</div>

---

## Why LaptopShield Pro?

Standard Windows privacy toggles only restrict Microsoft Store (UWP) apps—leaving **Win32 desktop browsers (Chrome, Edge, Electron)** and background malware free to access your webcam, microphone, or open remote ports.

**LaptopShield Pro** closes that gap with **11 real-time endpoint hardening controls**, a **3-layer hardware + policy + desktop-consent camera kill-switch**, a **live socket & process terminator**, and a **deep forensic auditor**—available in both a **Graphite Instrument PyQt5 GUI** and a **Rich-powered CLI**.

---

## Key Features

### 1. 11 Endpoint Hardening Controls (`Lock all` / `Restore all`)
| Control ID | Category | What It Locks Down |
| :--- | :--- | :--- |
| `camera` | Privacy | **3-Layer Kill-Switch:** Disables PnP Camera hardware drivers (`Disable-PnpDevice`), forces `AppPrivacy` Group Policy (`LetAppsAccessCamera=2`), and denies `ConsentStore\webcam` + `NonPackaged` (blocks Chrome/Win32). |
| `microphone` | Privacy | Blocks `ConsentStore\microphone`, `NonPackaged` desktop apps, and sets `LetAppsAccessMicrophone=2`. |
| `location` | Privacy | Denies system-wide geolocation access across apps and background services. |
| `clipboard_guard` | Privacy | Disables Windows Clipboard History & Cross-Device Cloud Sync to protect copied passwords, API keys, and crypto addresses. |
| `rdp` | Network | Disables Remote Desktop (`fDenyTSConnections=1`), Remote Assistance, and Remote Desktop Firewall rules (port `3389`). |
| `smb` | Network | Disables legacy SMBv1 and blocks inbound File & Printer Sharing (ports `445`/`139`). |
| `winrm` | Network | Stops and disables `WinRM` / PowerShell Remoting (ports `5985`/`5986`). |
| `llmnr` | Network | Disables Link-Local Multicast Name Resolution (`EnableMulticast=0`) to mitigate LAN credential spoofing. |
| `remote_registry` | Network | Stops and disables the `RemoteRegistry` service (`Start=4`). |
| `wsh_autorun` | System | Disables Windows Script Host (`.vbs`/`.js` malware droppers) and blocks removable drive AutoRun (`NoDriveTypeAutoRun=255`). |
| `firewall` | System | Enforces Windows Defender Firewall **ON** across Domain, Private, and Public profiles. |

> **Call Mode:** Need your webcam and microphone for a Zoom or WhatsApp call? Click **Restore camera and mic** to re-enable sensors without lowering your network/RDP/SMB defenses.

---

### 2. Live Threat Guard & Deep Forensics
* **Remote Access Process Killer:** Instantly detects and terminates running instances of `AnyDesk`, `TeamViewer`, `RustDesk`, `ScreenConnect`, `UltraViewer`, `VNC`, `Parsec`, `Splashtop`, `LogMeIn`, `Ngrok`, `Radmin`, `MeshAgent`, and `TacticalRMM`.
* **Live Socket Monitor (`Processes and sockets`):** Lists active `ESTABLISHED` and `LISTEN` TCP/UDP connections with real-time risk classification (`HIGH`, `MEDIUM`, `LOW`), search/risk filtering, and one-click process-tree termination.
* **Startup Persistence Auditor:** Scans `HKCU` and `HKLM` `Run` / `RunOnce` keys for suspicious paths (`\Temp\`, `\Downloads\`, encoded PowerShell, `mshta`, `wscript`).
* **Deep Forensics (`Ctrl+6` / `laptopshield forensics`):** Audits non-Microsoft **Scheduled Tasks**, **Local Users & Administrators Group**, and **Windows `hosts` file** overrides.
* **JSON Posture Report Export:** Export a complete point-in-time security snapshot for incident response or compliance.

---

## Quick Start

### Option A: Launch the Production GUI (Windows)
1. Clone the repository:
   ```powershell
   git clone https://github.com/6t9xstar/LaptopShield-Pro.git
   cd LaptopShield-Pro
   ```
2. Install dependencies:
   ```powershell
   pip install -e .
   ```
3. Double-click **`RUN_LAPTOPSHIELD_PRO.bat`** (auto-requests Administrator UAC elevation for hardware PnP driver & Group Policy locks).

### Option B: Use the CLI (`laptopshield`)
```powershell
laptopshield status       # View 0-100% hardening score & all 11 control states
laptopshield lockdown     # Apply full emergency lockdown & kill remote tools
laptopshield restore-all  # Restore reversible controls (keeps Firewall ON)
laptopshield kill-remote  # Terminate running remote-control tools
laptopshield audit        # Inspect sockets, remote tools & startup Run keys
laptopshield forensics    # Audit Scheduled Tasks, Local Admins & hosts file
laptopshield gui          # Launch the PyQt5 Graphite GUI
```

---

## Keyboard Shortcuts (GUI)
* `Ctrl + R` — Refresh live telemetry
* `Ctrl + 1` to `Ctrl + 6` — Switch between Overview, Privacy, Network, Sockets, Startup, and Deep Forensics

---

## Project Architecture
```text
LaptopShield-Pro/
├── src/laptopshield/
│   ├── core/
│   │   ├── hardening.py   # 11 Windows registry, policy & PnP driver controls
│   │   ├── privilege.py   # UAC elevation, winreg & silent PowerShell helpers
│   │   └── scanner.py     # Sockets, remote tools, startup, tasks, accounts & hosts
│   ├── ui/
│   │   ├── app.py         # 6-tab PyQt5 Graphite Instrument GUI + QThread workers
│   │   ├── icons.py       # Crisp 1.5px-stroke QPainter vector icons
│   │   └── theme.py       # Graphite dark QSS & ScoreGaugeWidget
│   └── cli.py             # Typer + Rich CLI
├── tests/                 # Unit tests (mocked winreg/PowerShell/psutil)
├── RUN_LAPTOPSHIELD_PRO.bat
└── pyproject.toml
```

---

## Development & Testing
```powershell
pip install -e ".[dev]"
ruff check src tests
pytest -v
```

## Contributing
Contributions, bug reports, and security hardening suggestions are welcome! Open an issue or submit a pull request.

## License
Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.
