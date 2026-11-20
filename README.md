# LaptopShield Pro

**Production-grade Windows Endpoint Hardening, Privacy Kill-Switch & Live Threat Audit Suite.**

LaptopShield Pro gives Windows users and administrators a fast PyQt5 Cyber-Ops GUI and Rich CLI to lock down remote access vectors, disable camera/microphone/location sensors globally, terminate unauthorized remote-control tools, and audit live network sockets and startup persistence.

---

## Key Features

### 1. One-Click Endpoint Hardening (`HardeningEngine`)
- **Remote Desktop (RDP) & Remote Assistance Lock**: Disables `fDenyTSConnections`, `fAllowToGetHelp`, and Windows Firewall Remote Desktop inbound rules.
- **Global Privacy Kill-Switches**: Blocks Camera, Microphone, and Location access across both `HKLM` and `HKCU` ConsentStore policies—with a **Call Mode Restore** option when you need Cam/Mic for legitimate meetings.
- **WinRM / PowerShell Remoting Lock**: Stops and disables the `WinRM` service (ports `5985`/`5986`).
- **SMB & File Sharing Hardening**: Disables legacy SMBv1 and blocks inbound File and Printer Sharing (`ports 445/139`).
- **LLMNR Spoofing Protection**: Disables Link-Local Multicast Name Resolution (`EnableMulticast=0`) to mitigate LAN credential harvesting.
- **Windows Script Host & USB AutoRun Block**: Disables `.vbs`/`.js` script execution via WSH and blocks removable drive AutoRun (`NoDriveTypeAutoRun=255`).
- **Windows Firewall Enforcement**: Ensures Domain, Private, and Public firewall profiles are active.

### 2. Live Threat & Network Telemetry (`scanner`)
- **Remote Access Process Killer**: Detects and terminates running instances of TeamViewer, AnyDesk, RustDesk, ScreenConnect, UltraViewer, VNC, Parsec, Splashtop, LogMeIn, Ngrok, Radmin, and more.
- **Live Socket Monitor**: Lists active `ESTABLISHED` and `LISTEN` connections with risk classification (`HIGH`, `MEDIUM`, `LOW`) and one-click process tree termination.
- **Startup Persistence Auditor**: Scans `HKCU`/`HKLM` `Run` and `RunOnce` keys for suspicious paths (`\Temp\`, `\Downloads\`, encoded PowerShell, script hosts).
- **JSON Security Report Export**: Save full point-in-time endpoint posture and telemetry reports.

---

## Quick Start

### Launch the Production GUI (Windows)
Double-click [`RUN_LAPTOPSHIELD_PRO.bat`](RUN_LAPTOPSHIELD_PRO.bat) (auto-requests Administrator UAC elevation).

### Install as a Python Package (CLI + GUI)
```powershell
pip install -e .
```

### CLI Commands
```powershell
laptopshield status       # View hardening score & live control states
laptopshield lockdown     # Apply full emergency lockdown + kill remote tools
laptopshield audit        # Inspect remote tools, network sockets & startup keys
laptopshield kill-remote  # Kill any running remote-control software
laptopshield gui          # Launch the PyQt5 GUI
```

---

## Development & Testing
```powershell
pip install -e ".[dev]"
ruff check src tests
pytest -v
```

## License
MIT License — see [LICENSE](LICENSE).
