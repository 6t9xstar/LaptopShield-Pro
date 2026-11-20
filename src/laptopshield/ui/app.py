"""Main PyQt5 application window for LaptopShield Pro."""

from __future__ import annotations

import os
import sys
from datetime import datetime
from typing import Callable, List

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import (
    QApplication,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from laptopshield import __version__
from laptopshield.core.hardening import ControlStatus, HardeningEngine
from laptopshield.core.privilege import elevate_self, is_admin
from laptopshield.core.scanner import (
    export_audit_report,
    get_defender_summary,
    kill_all_remote_tools,
    kill_process_tree,
    scan_network_connections,
    scan_remote_tools,
    scan_startup_entries,
)
from laptopshield.ui.theme import STYLESHEET, ScoreGaugeWidget


class WorkerThread(QThread):
    """Run blocking system/registry/network operations off the UI thread."""

    finished_with_data = pyqtSignal(object)

    def __init__(self, fn: Callable[[], object]) -> None:
        super().__init__()
        self._fn = fn

    def run(self) -> None:
        result = self._fn()
        self.finished_with_data.emit(result)


class ControlCard(QFrame):
    """Card widget representing a single Windows hardening switch."""

    def __init__(
        self,
        status: ControlStatus,
        on_toggle: Callable[[str, bool], None],
    ) -> None:
        super().__init__()
        self.setObjectName("Card")
        self.control_id = status.control_id
        self._on_toggle = on_toggle

        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(12)

        info_col = QVBoxLayout()
        info_col.setSpacing(4)

        top_row = QHBoxLayout()
        title_lbl = QLabel(status.name)
        title_lbl.setStyleSheet("font-size: 14px; font-weight: 700; color: #f8fafc;")

        self.badge = QLabel("LOCKED" if status.is_locked else "EXPOSED")
        self.badge.setAlignment(Qt.AlignCenter)
        self.badge.setFixedWidth(78)

        top_row.addWidget(title_lbl)
        top_row.addWidget(self.badge)
        top_row.addStretch()

        desc_lbl = QLabel(status.description)
        desc_lbl.setWordWrap(True)
        desc_lbl.setStyleSheet("font-size: 12px; color: #94a3b8;")

        self.detail_lbl = QLabel(f"State: {status.detail}")
        self.detail_lbl.setStyleSheet("font-size: 11px; color: #64748b;")

        info_col.addLayout(top_row)
        info_col.addWidget(desc_lbl)
        info_col.addWidget(self.detail_lbl)

        btn_col = QHBoxLayout()
        btn_col.setSpacing(8)

        self.lock_btn = QPushButton("BLOCK / LOCK")
        self.lock_btn.setObjectName("LockBtn")
        self.lock_btn.setCursor(Qt.PointingHandCursor)
        self.lock_btn.clicked.connect(lambda: self._on_toggle(self.control_id, True))

        self.unlock_btn = QPushButton("RESTORE")
        self.unlock_btn.setObjectName("UnlockBtn")
        self.unlock_btn.setCursor(Qt.PointingHandCursor)
        self.unlock_btn.clicked.connect(lambda: self._on_toggle(self.control_id, False))

        btn_col.addWidget(self.lock_btn)
        if status.control_id != "firewall":
            btn_col.addWidget(self.unlock_btn)

        layout.addLayout(info_col, stretch=1)
        layout.addLayout(btn_col)

        self.update_state(status)

    def update_state(self, status: ControlStatus) -> None:
        if status.is_locked:
            self.badge.setText("LOCKED")
            self.badge.setStyleSheet(
                "background-color: #064e3b; color: #34d399; border-radius: 5px; "
                "padding: 3px 6px; font-size: 10px; font-weight: 700;"
            )
        else:
            self.badge.setText("EXPOSED")
            self.badge.setStyleSheet(
                "background-color: #7f1d1d; color: #fca5a5; border-radius: 5px; "
                "padding: 3px 6px; font-size: 10px; font-weight: 700;"
            )
        self.detail_lbl.setText(f"State: {status.detail}")


class MainWindow(QMainWindow):
    """Production Cyber-Ops GUI for LaptopShield Pro."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"LaptopShield Pro v{__version__} — Endpoint Hardening & Threat Guard")
        self.resize(1160, 760)
        self.setMinimumSize(980, 660)

        self.engine = HardeningEngine()
        self._workers: List[WorkerThread] = []
        self._control_cards: dict[str, ControlCard] = {}
        self._latest_statuses: List[ControlStatus] = []

        root = QWidget()
        self.setCentralWidget(root)
        main_layout = QHBoxLayout(root)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # --- Sidebar ---
        self.sidebar = QFrame()
        self.sidebar.setObjectName("Sidebar")
        self.sidebar.setFixedWidth(245)
        sb_layout = QVBoxLayout(self.sidebar)
        sb_layout.setContentsMargins(16, 20, 16, 16)
        sb_layout.setSpacing(10)

        brand = QLabel("LAPTOPSHIELD PRO")
        brand.setObjectName("BrandTitle")
        brand_sub = QLabel(f"v{__version__}  |  Endpoint Defense")
        brand_sub.setObjectName("BrandSub")

        sb_layout.addWidget(brand)
        sb_layout.addWidget(brand_sub)

        self.gauge = ScoreGaugeWidget()
        gauge_wrap = QHBoxLayout()
        gauge_wrap.addStretch()
        gauge_wrap.addWidget(self.gauge)
        gauge_wrap.addStretch()
        sb_layout.addLayout(gauge_wrap)

        # Admin status pill
        admin = is_admin()
        admin_lbl = QLabel("● ADMIN ACTIVE" if admin else "▲ LIMITED USER")
        admin_lbl.setAlignment(Qt.AlignCenter)
        admin_lbl.setStyleSheet(
            "background-color: #064e3b; color: #34d399; border-radius: 6px; padding: 6px; font-weight: 700; font-size: 11px;"
            if admin
            else "background-color: #78350f; color: #fcd34d; border-radius: 6px; padding: 6px; font-weight: 700; font-size: 11px;"
        )
        sb_layout.addWidget(admin_lbl)

        if not admin:
            elevate_btn = QPushButton("Relaunch as Admin")
            elevate_btn.setObjectName("PrimaryBtn")
            elevate_btn.setCursor(Qt.PointingHandCursor)
            elevate_btn.clicked.connect(self._handle_elevate)
            sb_layout.addWidget(elevate_btn)

        sb_layout.addSpacing(8)

        # Navigation Buttons
        self.nav_buttons: List[QPushButton] = []
        nav_items = [
            ("Dashboard", 0),
            ("Privacy & Hardware", 1),
            ("Network & Remote", 2),
            ("Process & Net Guard", 3),
            ("Startup & Audit Logs", 4),
        ]
        for label, idx in nav_items:
            btn = QPushButton(label)
            btn.setObjectName("NavBtn")
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(lambda checked, i=idx: self._switch_page(i))
            self.nav_buttons.append(btn)
            sb_layout.addWidget(btn)

        sb_layout.addStretch()

        refresh_btn = QPushButton("↻ Refresh Telemetry")
        refresh_btn.setObjectName("SafeBtn")
        refresh_btn.setCursor(Qt.PointingHandCursor)
        refresh_btn.clicked.connect(self.refresh_all)
        sb_layout.addWidget(refresh_btn)

        main_layout.addWidget(self.sidebar)

        # --- Stacked Content Pages ---
        self.pages = QStackedWidget()
        main_layout.addWidget(self.pages, stretch=1)

        self._build_dashboard_page()
        self._build_controls_page(
            "Privacy & Hardware Kill-Switches",
            "Disable Camera, Microphone, and Location tracking across all apps and background services.",
            category="privacy",
        )
        self._build_controls_page(
            "Network, Remote Access & System Hardening",
            "Lock down RDP, WinRM, SMB file sharing, LLMNR spoofing, Script Host, and Windows Firewall.",
            category="network_system",
        )
        self._build_process_net_page()
        self._build_startup_logs_page()

        self._switch_page(0)
        self.log_event("LaptopShield Pro initialized. Scanning endpoint posture...")
        self.refresh_all()

    # --- Page Builders ---

    def _make_page_header(self, title: str, subtitle: str) -> QVBoxLayout:
        header = QVBoxLayout()
        header.setSpacing(3)
        t = QLabel(title)
        t.setObjectName("PageTitle")
        s = QLabel(subtitle)
        s.setObjectName("PageSub")
        header.addWidget(t)
        header.addWidget(s)
        return header

    def _make_kpi_card(self, label: str, initial: str = "...") -> tuple[QFrame, QLabel]:
        card = QFrame()
        card.setObjectName("Card")
        lay = QVBoxLayout(card)
        lay.setContentsMargins(16, 14, 16, 14)
        lay.setSpacing(4)
        lbl = QLabel(label)
        lbl.setObjectName("KpiLabel")
        val = QLabel(initial)
        val.setObjectName("KpiValue")
        lay.addWidget(lbl)
        lay.addWidget(val)
        return card, val

    def _build_dashboard_page(self) -> None:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(24, 22, 24, 22)
        lay.setSpacing(16)

        lay.addLayout(
            self._make_page_header(
                "Security Command Center",
                "Real-time Windows hardening posture, remote backdoor kill-switches, and threat telemetry.",
            )
        )

        # KPI Row
        kpi_row = QHBoxLayout()
        kpi_row.setSpacing(12)
        c1, self.kpi_controls = self._make_kpi_card("HARDENING LOCKS")
        c2, self.kpi_remote = self._make_kpi_card("REMOTE TOOLS")
        c3, self.kpi_net = self._make_kpi_card("ACTIVE CONNECTIONS")
        c4, self.kpi_defender = self._make_kpi_card("DEFENDER THREATS")
        for c in (c1, c2, c3, c4):
            kpi_row.addWidget(c)
        lay.addLayout(kpi_row)

        # Action Banner
        action_card = QFrame()
        action_card.setObjectName("Card")
        ac_lay = QVBoxLayout(action_card)
        ac_lay.setContentsMargins(18, 16, 18, 16)
        ac_lay.setSpacing(12)

        ac_title = QLabel("Emergency Response & Quick Profiles")
        ac_title.setStyleSheet("font-size: 15px; font-weight: 700; color: #f8fafc;")
        ac_desc = QLabel(
            "Lock down all remote entry points (RDP, WinRM, SMB, LLMNR), disable Camera/Mic globally, "
            "and terminate any running remote-control tools in one click."
        )
        ac_desc.setWordWrap(True)
        ac_desc.setStyleSheet("color: #94a3b8; font-size: 12px;")

        btn_row = QHBoxLayout()
        btn_row.setSpacing(12)

        panic_btn = QPushButton("🚨 INSTANT TOTAL LOCKDOWN")
        panic_btn.setObjectName("PanicBtn")
        panic_btn.setCursor(Qt.PointingHandCursor)
        panic_btn.clicked.connect(self._run_total_lockdown)

        kill_remote_btn = QPushButton("🔪 Kill Remote Tools Now")
        kill_remote_btn.setObjectName("SafeBtn")
        kill_remote_btn.setCursor(Qt.PointingHandCursor)
        kill_remote_btn.clicked.connect(self._run_kill_remote_tools)

        call_mode_btn = QPushButton("🎥 Restore Cam & Mic (Call Mode)")
        call_mode_btn.setObjectName("SafeBtn")
        call_mode_btn.setCursor(Qt.PointingHandCursor)
        call_mode_btn.clicked.connect(self._run_restore_privacy)

        btn_row.addWidget(panic_btn, stretch=2)
        btn_row.addWidget(kill_remote_btn, stretch=1)
        btn_row.addWidget(call_mode_btn, stretch=1)

        ac_lay.addWidget(ac_title)
        ac_lay.addWidget(ac_desc)
        ac_lay.addLayout(btn_row)
        lay.addWidget(action_card)

        # Live feed preview
        feed_lbl = QLabel("Live Security Activity")
        feed_lbl.setStyleSheet("font-size: 14px; font-weight: 700; color: #cbd5e1;")
        lay.addWidget(feed_lbl)

        self.dashboard_log = QTextEdit()
        self.dashboard_log.setObjectName("LogBox")
        self.dashboard_log.setReadOnly(True)
        lay.addWidget(self.dashboard_log, stretch=1)

        self.pages.addWidget(page)

    def _build_controls_page(self, title: str, subtitle: str, category: str) -> None:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(24, 22, 24, 22)
        lay.setSpacing(14)

        lay.addLayout(self._make_page_header(title, subtitle))

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        container = QWidget()
        cards_lay = QVBoxLayout(container)
        cards_lay.setSpacing(10)
        cards_lay.setContentsMargins(0, 0, 6, 0)

        for st in self.engine.list_controls():
            match = (
                st.category == "privacy"
                if category == "privacy"
                else st.category in ("network", "system")
            )
            if match:
                card = ControlCard(st, self._handle_toggle_control)
                self._control_cards[st.control_id] = card
                cards_lay.addWidget(card)

        cards_lay.addStretch()
        scroll.setWidget(container)
        lay.addWidget(scroll, stretch=1)
        self.pages.addWidget(page)

    def _build_process_net_page(self) -> None:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(24, 22, 24, 22)
        lay.setSpacing(14)

        header_row = QHBoxLayout()
        header_row.addLayout(
            self._make_page_header(
                "Live Process & Network Connection Guard",
                "Inspect active outbound/listening sockets and terminate suspicious or remote-control processes.",
            )
        )
        header_row.addStretch()

        kill_sel_btn = QPushButton("Terminate Selected PID")
        kill_sel_btn.setObjectName("LockBtn")
        kill_sel_btn.setCursor(Qt.PointingHandCursor)
        kill_sel_btn.clicked.connect(self._kill_selected_connection_pid)

        kill_all_btn = QPushButton("Kill All Remote Tools")
        kill_all_btn.setObjectName("PrimaryBtn")
        kill_all_btn.setCursor(Qt.PointingHandCursor)
        kill_all_btn.clicked.connect(self._run_kill_remote_tools)

        header_row.addWidget(kill_all_btn)
        header_row.addWidget(kill_sel_btn)
        lay.addLayout(header_row)

        self.net_table = QTableWidget(0, 6)
        self.net_table.setHorizontalHeaderLabels(
            ["Risk", "Process", "PID", "Status", "Local Address", "Remote Address"]
        )
        self.net_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.net_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.net_table.setEditTriggers(QTableWidget.NoEditTriggers)
        lay.addWidget(self.net_table, stretch=1)

        self.pages.addWidget(page)

    def _build_startup_logs_page(self) -> None:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(24, 22, 24, 22)
        lay.setSpacing(14)

        top_row = QHBoxLayout()
        top_row.addLayout(
            self._make_page_header(
                "Startup Persistence & Audit Export",
                "Audit Windows Run/RunOnce auto-start entries and export a full JSON security report.",
            )
        )
        top_row.addStretch()

        export_btn = QPushButton("⬇ Export JSON Audit Report")
        export_btn.setObjectName("PrimaryBtn")
        export_btn.setCursor(Qt.PointingHandCursor)
        export_btn.clicked.connect(self._export_report)
        top_row.addWidget(export_btn)
        lay.addLayout(top_row)

        self.startup_table = QTableWidget(0, 4)
        self.startup_table.setHorizontalHeaderLabels(["Status", "Scope", "Name", "Command"])
        self.startup_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.startup_table.setEditTriggers(QTableWidget.NoEditTriggers)
        lay.addWidget(self.startup_table, stretch=1)

        self.pages.addWidget(page)

    # --- Helpers & Actions ---

    def _switch_page(self, idx: int) -> None:
        self.pages.setCurrentIndex(idx)
        for i, btn in enumerate(self.nav_buttons):
            btn.setProperty("active", "true" if i == idx else "false")
            btn.style().unpolish(btn)
            btn.style().polish(btn)

    def log_event(self, text: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self.dashboard_log.append(f"[{ts}] {text}")

    def _run_async(self, fn: Callable[[], object], cb: Callable[[object], None]) -> None:
        worker = WorkerThread(fn)
        worker.finished_with_data.connect(cb)
        worker.finished.connect(lambda: self._workers.remove(worker) if worker in self._workers else None)
        self._workers.append(worker)
        worker.start()

    def refresh_all(self) -> None:
        def gather():
            statuses = self.engine.list_controls()
            score = self.engine.calculate_score(statuses)
            remote = scan_remote_tools()
            conns = scan_network_connections(60)
            startup = scan_startup_entries()
            defender = get_defender_summary()
            return statuses, score, remote, conns, startup, defender

        self._run_async(gather, self._apply_telemetry)

    def _apply_telemetry(self, data: object) -> None:
        statuses, score, remote, conns, startup, defender = data  # type: ignore[misc]
        self._latest_statuses = statuses

        self.gauge.set_score(score)
        locked_cnt = sum(1 for s in statuses if s.is_locked)
        self.kpi_controls.setText(f"{locked_cnt} / {len(statuses)}")
        self.kpi_remote.setText(str(len(remote)))
        self.kpi_remote.setStyleSheet(
            "font-size: 24px; font-weight: 700; color: #ef4444;"
            if remote
            else "font-size: 24px; font-weight: 700; color: #10b981;"
        )
        self.kpi_net.setText(str(len(conns)))

        threats = defender.get("ActiveThreats")
        if threats is None:
            self.kpi_defender.setText("N/A")
        elif threats > 0:
            self.kpi_defender.setText(f"{threats} ACTIVE")
            self.kpi_defender.setStyleSheet("font-size: 24px; font-weight: 700; color: #ef4444;")
        else:
            self.kpi_defender.setText("0 Active")
            self.kpi_defender.setStyleSheet("font-size: 24px; font-weight: 700; color: #10b981;")

        for st in statuses:
            card = self._control_cards.get(st.control_id)
            if card:
                card.update_state(st)

        # Populate Network Table
        self.net_table.setRowCount(len(conns))
        for r, c in enumerate(conns):
            risk_item = QTableWidgetItem(c.risk)
            if c.risk == "HIGH":
                risk_item.setForeground(QColor("#ef4444"))
            elif c.risk == "MEDIUM":
                risk_item.setForeground(QColor("#f59e0b"))
            else:
                risk_item.setForeground(QColor("#10b981"))

            self.net_table.setItem(r, 0, risk_item)
            self.net_table.setItem(r, 1, QTableWidgetItem(c.process))
            self.net_table.setItem(r, 2, QTableWidgetItem(str(c.pid)))
            self.net_table.setItem(r, 3, QTableWidgetItem(c.status))
            self.net_table.setItem(r, 4, QTableWidgetItem(c.local_addr))
            self.net_table.setItem(r, 5, QTableWidgetItem(c.remote_addr))

        # Populate Startup Table
        self.startup_table.setRowCount(len(startup))
        for r, entry in enumerate(startup):
            flag_item = QTableWidgetItem("FLAGGED" if entry.flagged else "OK")
            flag_item.setForeground(QColor("#ef4444") if entry.flagged else QColor("#10b981"))
            self.startup_table.setItem(r, 0, flag_item)
            self.startup_table.setItem(r, 1, QTableWidgetItem(entry.scope))
            self.startup_table.setItem(r, 2, QTableWidgetItem(entry.name))
            self.startup_table.setItem(r, 3, QTableWidgetItem(entry.command))

    def _handle_toggle_control(self, control_id: str, lock: bool) -> None:
        action = "Locking" if lock else "Restoring"
        self.log_event(f"{action} control '{control_id}'...")

        def task():
            return self.engine.set_control(control_id, lock)

        def done(res):
            prefix = "✅" if res.success else "❌"
            self.log_event(f"{prefix} [{res.control_id}] {res.message}")
            self.refresh_all()

        self._run_async(task, done)

    def _run_total_lockdown(self) -> None:
        self.log_event("🚨 INITIATING FULL ENDPOINT LOCKDOWN...")

        def task():
            results = self.engine.lockdown_all()
            killed = kill_all_remote_tools()
            return results, killed

        def done(payload):
            results, killed = payload
            for r in results:
                prefix = "✅" if r.success else "❌"
                self.log_event(f"{prefix} [{r.control_id}] {r.message}")
            if killed:
                for pid, name, ok, msg in killed:
                    self.log_event(f"🔪 {name} (PID {pid}): {msg}")
            else:
                self.log_event("✅ No rogue remote-access processes found running.")
            self.refresh_all()
            QMessageBox.information(
                self,
                "Lockdown Complete",
                "Total Endpoint Lockdown has been applied.\n"
                "Check the Live Security Activity log for per-control results.",
            )

        self._run_async(task, done)

    def _run_restore_privacy(self) -> None:
        self.log_event("🎥 Restoring Camera & Microphone for legitimate calls...")

        def task():
            return self.engine.restore_privacy_only()

        def done(results):
            for r in results:
                self.log_event(f"{'✅' if r.success else '❌'} [{r.control_id}] {r.message}")
            self.refresh_all()

        self._run_async(task, done)

    def _run_kill_remote_tools(self) -> None:
        self.log_event("🔪 Scanning & killing remote-access processes...")

        def task():
            return kill_all_remote_tools()

        def done(killed):
            if not killed:
                self.log_event("✅ No running remote-access tools detected.")
            else:
                for pid, name, ok, msg in killed:
                    self.log_event(f"{'✅' if ok else '❌'} {name} (PID {pid}): {msg}")
            self.refresh_all()

        self._run_async(task, done)

    def _kill_selected_connection_pid(self) -> None:
        row = self.net_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "No Selection", "Select a row in the connection table first.")
            return
        pid_item = self.net_table.item(row, 2)
        proc_item = self.net_table.item(row, 1)
        if not pid_item:
            return
        pid = int(pid_item.text())
        pname = proc_item.text() if proc_item else "process"
        reply = QMessageBox.question(
            self,
            "Confirm Terminate",
            f"Terminate {pname} (PID {pid}) and its child processes?",
        )
        if reply == QMessageBox.Yes:
            ok, msg = kill_process_tree(pid)
            self.log_event(f"{'✅' if ok else '❌'} {msg}")
            self.refresh_all()

    def _export_report(self) -> None:
        default_path = os.path.join(
            os.path.expanduser("~"),
            "Desktop",
            f"LaptopShield_Audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        )
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Security Audit Report", default_path, "JSON Files (*.json)"
        )
        if not path:
            return
        score = self.engine.calculate_score(self._latest_statuses)
        err = export_audit_report(path, self._latest_statuses, score)
        if err:
            QMessageBox.critical(self, "Export Failed", err)
        else:
            self.log_event(f"📄 Audit report exported to {path}")
            QMessageBox.information(self, "Exported", f"Security report saved to:\n{path}")

    def _handle_elevate(self) -> None:
        if elevate_self():
            QApplication.quit()
        else:
            QMessageBox.warning(
                self,
                "Elevation Failed",
                "Could not launch elevated instance. Please right-click RUN_LAPTOPSHIELD_PRO.bat and choose 'Run as administrator'.",
            )


def main() -> None:
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    app = QApplication(sys.argv)
    app.setStyleSheet(STYLESHEET)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
