"""Production PyQt5 application window for LaptopShield Pro."""

from __future__ import annotations

import os
import sys
from datetime import datetime
from typing import Callable, List

from PyQt5.QtCore import QSize, Qt, QThread, QTimer, pyqtSignal
from PyQt5.QtGui import QColor, QFont, QKeySequence
from PyQt5.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QShortcut,
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
    NetworkConnectionInfo,
    export_audit_report,
    get_defender_summary,
    kill_all_remote_tools,
    kill_process_tree,
    scan_network_connections,
    scan_remote_tools,
    scan_startup_entries,
)
from laptopshield.ui.icons import (
    icon_activity,
    icon_camera,
    icon_list,
    icon_network,
    icon_refresh,
    icon_shield,
)
from laptopshield.ui.theme import STYLESHEET, ScoreGaugeWidget


class WorkerThread(QThread):
    """Run blocking system, registry, and network operations off the UI thread."""

    finished_with_data = pyqtSignal(object)

    def __init__(self, fn: Callable[[], object]) -> None:
        super().__init__()
        self._fn = fn

    def run(self) -> None:
        result = self._fn()
        self.finished_with_data.emit(result)


class ControlCard(QFrame):
    """Card widget representing a single Windows hardening control."""

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
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(16)

        info_col = QVBoxLayout()
        info_col.setSpacing(4)

        top_row = QHBoxLayout()
        top_row.setSpacing(10)

        self.dot = QLabel()
        self.dot.setFixedSize(8, 8)

        title_lbl = QLabel(status.name)
        title_lbl.setStyleSheet("font-size: 14px; font-weight: 600; color: #f4f4f5;")

        self.badge = QLabel("Locked" if status.is_locked else "Exposed")
        self.badge.setAlignment(Qt.AlignCenter)
        self.badge.setFixedWidth(68)

        top_row.addWidget(self.dot)
        top_row.addWidget(title_lbl)
        top_row.addWidget(self.badge)
        top_row.addStretch()

        desc_lbl = QLabel(status.description)
        desc_lbl.setWordWrap(True)
        desc_lbl.setStyleSheet("font-size: 12px; color: #a1a1aa;")

        self.detail_lbl = QLabel(status.detail)
        self.detail_lbl.setStyleSheet("font-size: 12px; color: #71717a;")

        info_col.addLayout(top_row)
        info_col.addWidget(desc_lbl)
        info_col.addWidget(self.detail_lbl)

        btn_col = QHBoxLayout()
        btn_col.setSpacing(8)

        self.lock_btn = QPushButton("Block")
        self.lock_btn.setObjectName("LockBtn")
        self.lock_btn.setCursor(Qt.PointingHandCursor)
        self.lock_btn.clicked.connect(lambda: self._on_toggle(self.control_id, True))

        self.unlock_btn = QPushButton("Restore")
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
            self.dot.setStyleSheet("background-color: #10b981; border-radius: 4px;")
            self.badge.setText("Locked")
            self.badge.setStyleSheet(
                "background-color: #052e16; color: #34d399; border: 1px solid #065f46; "
                "border-radius: 4px; padding: 2px 6px; font-size: 11px; font-weight: 500;"
            )
        else:
            self.dot.setStyleSheet("background-color: #ef4444; border-radius: 4px;")
            self.badge.setText("Exposed")
            self.badge.setStyleSheet(
                "background-color: #450a0a; color: #fca5a5; border: 1px solid #7f1d1d; "
                "border-radius: 4px; padding: 2px 6px; font-size: 11px; font-weight: 500;"
            )
        self.detail_lbl.setText(status.detail)


class MainWindow(QMainWindow):
    """Production Graphite Instrument GUI for LaptopShield Pro."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"LaptopShield Pro {__version__}")
        self.resize(1180, 760)
        self.setMinimumSize(980, 660)

        self.engine = HardeningEngine()
        self._workers: List[WorkerThread] = []
        self._control_cards: dict[str, ControlCard] = {}
        self._latest_statuses: List[ControlStatus] = []
        self._all_conns: List[NetworkConnectionInfo] = []

        root = QWidget()
        self.setCentralWidget(root)
        main_layout = QHBoxLayout(root)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # --- Sidebar ---
        self.sidebar = QFrame()
        self.sidebar.setObjectName("Sidebar")
        self.sidebar.setFixedWidth(244)
        sb_layout = QVBoxLayout(self.sidebar)
        sb_layout.setContentsMargins(16, 20, 16, 16)
        sb_layout.setSpacing(4)

        brand = QLabel("LaptopShield")
        brand.setObjectName("BrandTitle")
        brand_sub = QLabel(f"v{__version__} · Windows endpoint")
        brand_sub.setObjectName("BrandSub")

        sb_layout.addWidget(brand)
        sb_layout.addWidget(brand_sub)
        sb_layout.addSpacing(12)

        self.gauge = ScoreGaugeWidget()
        gauge_wrap = QHBoxLayout()
        gauge_wrap.addStretch()
        gauge_wrap.addWidget(self.gauge)
        gauge_wrap.addStretch()
        sb_layout.addLayout(gauge_wrap)
        sb_layout.addSpacing(8)

        admin = is_admin()
        admin_row = QHBoxLayout()
        admin_row.setContentsMargins(8, 6, 8, 6)
        admin_dot = QLabel()
        admin_dot.setFixedSize(8, 8)
        admin_dot.setStyleSheet(
            "background-color: #10b981; border-radius: 4px;"
            if admin
            else "background-color: #f59e0b; border-radius: 4px;"
        )
        admin_txt = QLabel("Administrator" if admin else "Limited user")
        admin_txt.setStyleSheet("color: #e4e4e7; font-size: 12px; font-weight: 500;")
        admin_row.addWidget(admin_dot)
        admin_row.addWidget(admin_txt)
        admin_row.addStretch()

        admin_box = QFrame()
        admin_box.setStyleSheet(
            "background-color: #18181b; border: 1px solid #27272a; border-radius: 6px;"
        )
        admin_box.setLayout(admin_row)
        sb_layout.addWidget(admin_box)

        if not admin:
            elevate_btn = QPushButton("Relaunch as admin")
            elevate_btn.setObjectName("PrimaryBtn")
            elevate_btn.setCursor(Qt.PointingHandCursor)
            elevate_btn.clicked.connect(self._handle_elevate)
            sb_layout.addSpacing(4)
            sb_layout.addWidget(elevate_btn)

        sec_lbl = QLabel("Navigation")
        sec_lbl.setObjectName("SectionLabel")
        sb_layout.addWidget(sec_lbl)

        self.nav_buttons: List[QPushButton] = []
        nav_items = [
            ("Overview", icon_shield("#a1a1aa"), 0),
            ("Privacy and sensors", icon_camera("#a1a1aa"), 1),
            ("Network and remote", icon_network("#a1a1aa"), 2),
            ("Processes and sockets", icon_activity("#a1a1aa"), 3),
            ("Startup and audit", icon_list("#a1a1aa"), 4),
        ]
        for label, ico, idx in nav_items:
            btn = QPushButton(label)
            btn.setObjectName("NavBtn")
            btn.setIcon(ico)
            btn.setIconSize(QSize(16, 16))
            btn.setFixedHeight(36)
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(lambda checked, i=idx: self._switch_page(i))
            self.nav_buttons.append(btn)
            sb_layout.addWidget(btn)

        sb_layout.addStretch()

        self.last_scan_lbl = QLabel("Last scan: pending")
        self.last_scan_lbl.setStyleSheet("color: #71717a; font-size: 11px; padding-left: 4px;")
        sb_layout.addWidget(self.last_scan_lbl)
        sb_layout.addSpacing(4)

        refresh_btn = QPushButton("Refresh telemetry")
        refresh_btn.setObjectName("SecondaryBtn")
        refresh_btn.setIcon(icon_refresh("#e4e4e7"))
        refresh_btn.setIconSize(QSize(15, 15))
        refresh_btn.setCursor(Qt.PointingHandCursor)
        refresh_btn.clicked.connect(self.refresh_all)
        sb_layout.addWidget(refresh_btn)

        main_layout.addWidget(self.sidebar)

        # --- Stacked Content Pages ---
        self.pages = QStackedWidget()
        main_layout.addWidget(self.pages, stretch=1)

        self._build_dashboard_page()
        self._build_controls_page(
            "Privacy and sensors",
            "Block camera hardware drivers, desktop app consent, microphone capture, and location services",
            category="privacy",
        )
        self._build_controls_page(
            "Network and remote access",
            "Close RDP, WinRM, SMB file sharing, LLMNR spoofing, Script Host, and enforce Windows Firewall",
            category="network_system",
        )
        self._build_process_net_page()
        self._build_startup_logs_page()

        self._setup_shortcuts()
        self._switch_page(0)

        # Quiet 15-second background telemetry refresh
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.refresh_all)
        self._timer.start(15000)

        self.log_event("LaptopShield initialized. Scanning endpoint posture.")
        self.refresh_all()

    def _setup_shortcuts(self) -> None:
        QShortcut(QKeySequence("Ctrl+R"), self, self.refresh_all)
        for idx in range(5):
            QShortcut(QKeySequence(f"Ctrl+{idx + 1}"), self, lambda i=idx: self._switch_page(i))

    def _make_page_header(self, title: str, subtitle: str) -> QVBoxLayout:
        header = QVBoxLayout()
        header.setSpacing(4)
        t = QLabel(title)
        t.setObjectName("PageTitle")
        s = QLabel(subtitle)
        s.setObjectName("PageSub")
        header.addWidget(t)
        header.addWidget(s)
        return header

    def _make_kpi_card(self, label: str, initial: str = "--") -> tuple[QFrame, QLabel]:
        card = QFrame()
        card.setObjectName("Card")
        lay = QVBoxLayout(card)
        lay.setContentsMargins(16, 16, 16, 16)
        lay.setSpacing(6)
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
        lay.setContentsMargins(24, 24, 24, 24)
        lay.setSpacing(16)

        lay.addLayout(
            self._make_page_header(
                "Endpoint overview",
                "Live hardening controls, active remote tools, and network posture",
            )
        )

        kpi_row = QHBoxLayout()
        kpi_row.setSpacing(12)
        c1, self.kpi_controls = self._make_kpi_card("Hardening locks")
        c2, self.kpi_remote = self._make_kpi_card("Remote tools")
        c3, self.kpi_net = self._make_kpi_card("Active sockets")
        c4, self.kpi_defender = self._make_kpi_card("Defender threats")
        for c in (c1, c2, c3, c4):
            kpi_row.addWidget(c)
        lay.addLayout(kpi_row)

        action_card = QFrame()
        action_card.setObjectName("Card")
        ac_lay = QVBoxLayout(action_card)
        ac_lay.setContentsMargins(20, 16, 20, 16)
        ac_lay.setSpacing(12)

        ac_title = QLabel("Quick posture controls")
        ac_title.setStyleSheet("font-size: 14px; font-weight: 600; color: #f4f4f5;")
        ac_desc = QLabel(
            "Lock down all remote entry points, disable camera hardware and desktop consent, "
            "or restore camera and microphone temporarily for a call."
        )
        ac_desc.setWordWrap(True)
        ac_desc.setStyleSheet("color: #a1a1aa; font-size: 12px;")

        btn_row = QHBoxLayout()
        btn_row.setSpacing(12)

        panic_btn = QPushButton("Lock all")
        panic_btn.setObjectName("PanicBtn")
        panic_btn.setCursor(Qt.PointingHandCursor)
        panic_btn.clicked.connect(self._run_total_lockdown)

        restore_all_btn = QPushButton("Restore all")
        restore_all_btn.setObjectName("SecondaryBtn")
        restore_all_btn.setCursor(Qt.PointingHandCursor)
        restore_all_btn.clicked.connect(self._run_restore_all)

        kill_remote_btn = QPushButton("Terminate remote tools")
        kill_remote_btn.setObjectName("SecondaryBtn")
        kill_remote_btn.setCursor(Qt.PointingHandCursor)
        kill_remote_btn.clicked.connect(self._run_kill_remote_tools)

        call_mode_btn = QPushButton("Restore camera and mic")
        call_mode_btn.setObjectName("SecondaryBtn")
        call_mode_btn.setCursor(Qt.PointingHandCursor)
        call_mode_btn.clicked.connect(self._run_restore_privacy)

        btn_row.addWidget(panic_btn)
        btn_row.addWidget(restore_all_btn)
        btn_row.addWidget(kill_remote_btn)
        btn_row.addWidget(call_mode_btn)
        btn_row.addStretch()

        ac_lay.addWidget(ac_title)
        ac_lay.addWidget(ac_desc)
        ac_lay.addLayout(btn_row)
        lay.addWidget(action_card)

        feed_lbl = QLabel("Activity log")
        feed_lbl.setStyleSheet("font-size: 13px; font-weight: 500; color: #a1a1aa;")
        lay.addWidget(feed_lbl)

        self.dashboard_log = QTextEdit()
        self.dashboard_log.setObjectName("LogBox")
        self.dashboard_log.setReadOnly(True)
        lay.addWidget(self.dashboard_log, stretch=1)

        self.pages.addWidget(page)

    def _build_controls_page(self, title: str, subtitle: str, category: str) -> None:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(24, 24, 24, 24)
        lay.setSpacing(16)

        lay.addLayout(self._make_page_header(title, subtitle))

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        container = QWidget()
        cards_lay = QVBoxLayout(container)
        cards_lay.setSpacing(12)
        cards_lay.setContentsMargins(0, 0, 8, 0)

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
        lay.setContentsMargins(24, 24, 24, 24)
        lay.setSpacing(16)

        header_row = QHBoxLayout()
        header_row.addLayout(
            self._make_page_header(
                "Processes and sockets",
                "Inspect active outbound and listening sockets, filter by risk, and terminate processes",
            )
        )
        header_row.addStretch()

        kill_all_btn = QPushButton("Terminate remote tools")
        kill_all_btn.setObjectName("SecondaryBtn")
        kill_all_btn.setCursor(Qt.PointingHandCursor)
        kill_all_btn.clicked.connect(self._run_kill_remote_tools)

        kill_sel_btn = QPushButton("Terminate selected PID")
        kill_sel_btn.setObjectName("LockBtn")
        kill_sel_btn.setCursor(Qt.PointingHandCursor)
        kill_sel_btn.clicked.connect(self._kill_selected_connection_pid)

        header_row.addWidget(kill_all_btn)
        header_row.addWidget(kill_sel_btn)
        lay.addLayout(header_row)

        # Search & filter bar
        filter_row = QHBoxLayout()
        filter_row.setSpacing(12)
        self.net_search = QLineEdit()
        self.net_search.setPlaceholderText("Filter by process name, PID, or remote IP")
        self.net_search.textChanged.connect(self._render_net_table)

        self.net_risk_filter = QComboBox()
        self.net_risk_filter.addItems(["All risks", "HIGH", "MEDIUM", "LOW"])
        self.net_risk_filter.setFixedWidth(130)
        self.net_risk_filter.currentTextChanged.connect(self._render_net_table)

        filter_row.addWidget(self.net_search, stretch=1)
        filter_row.addWidget(self.net_risk_filter)
        lay.addLayout(filter_row)

        self.net_table = QTableWidget(0, 6)
        self.net_table.setHorizontalHeaderLabels(
            ["Risk", "Process", "PID", "Status", "Local address", "Remote address"]
        )
        self.net_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.net_table.verticalHeader().setVisible(False)
        self.net_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.net_table.setEditTriggers(QTableWidget.NoEditTriggers)
        lay.addWidget(self.net_table, stretch=1)

        self.pages.addWidget(page)

    def _build_startup_logs_page(self) -> None:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(24, 24, 24, 24)
        lay.setSpacing(16)

        top_row = QHBoxLayout()
        top_row.addLayout(
            self._make_page_header(
                "Startup persistence and audit",
                "Review Windows Run/RunOnce auto-start entries and export a JSON posture report",
            )
        )
        top_row.addStretch()

        export_btn = QPushButton("Export JSON report")
        export_btn.setObjectName("PrimaryBtn")
        export_btn.setCursor(Qt.PointingHandCursor)
        export_btn.clicked.connect(self._export_report)
        top_row.addWidget(export_btn)
        lay.addLayout(top_row)

        self.startup_table = QTableWidget(0, 4)
        self.startup_table.setHorizontalHeaderLabels(["Status", "Scope", "Name", "Command"])
        self.startup_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.startup_table.verticalHeader().setVisible(False)
        self.startup_table.setEditTriggers(QTableWidget.NoEditTriggers)
        lay.addWidget(self.startup_table, stretch=1)

        self.pages.addWidget(page)

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
        worker.finished.connect(
            lambda: self._workers.remove(worker) if worker in self._workers else None
        )
        self._workers.append(worker)
        worker.start()

    def refresh_all(self) -> None:
        def gather():
            statuses = self.engine.list_controls()
            score = self.engine.calculate_score(statuses)
            remote = scan_remote_tools()
            conns = scan_network_connections(80)
            startup = scan_startup_entries()
            defender = get_defender_summary()
            return statuses, score, remote, conns, startup, defender

        self._run_async(gather, self._apply_telemetry)

    def _apply_telemetry(self, data: object) -> None:
        statuses, score, remote, conns, startup, defender = data  # type: ignore[misc]
        self._latest_statuses = statuses
        self._all_conns = conns

        self.last_scan_lbl.setText(f"Last scan: {datetime.now().strftime('%H:%M:%S')}")
        self.gauge.set_score(score)
        locked_cnt = sum(1 for s in statuses if s.is_locked)
        self.kpi_controls.setText(f"{locked_cnt} / {len(statuses)}")
        self.kpi_remote.setText(str(len(remote)))
        self.kpi_remote.setStyleSheet(
            "font-size: 24px; font-weight: 600; color: #ef4444;"
            if remote
            else "font-size: 24px; font-weight: 600; color: #10b981;"
        )
        self.kpi_net.setText(str(len(conns)))

        threats = defender.get("ActiveThreats")
        if threats is None:
            self.kpi_defender.setText("Unavailable")
        elif threats > 0:
            self.kpi_defender.setText(f"{threats} active")
            self.kpi_defender.setStyleSheet("font-size: 24px; font-weight: 600; color: #ef4444;")
        else:
            self.kpi_defender.setText("0 active")
            self.kpi_defender.setStyleSheet("font-size: 24px; font-weight: 600; color: #10b981;")

        for st in statuses:
            card = self._control_cards.get(st.control_id)
            if card:
                card.update_state(st)

        self._render_net_table()

        self.startup_table.setRowCount(len(startup))
        mono_font = QFont("Cascadia Code", 9)
        for r, entry in enumerate(startup):
            flag_item = QTableWidgetItem("Flagged" if entry.flagged else "Normal")
            flag_item.setForeground(QColor("#ef4444") if entry.flagged else QColor("#10b981"))
            self.startup_table.setItem(r, 0, flag_item)
            self.startup_table.setItem(r, 1, QTableWidgetItem(entry.scope))
            self.startup_table.setItem(r, 2, QTableWidgetItem(entry.name))
            cmd_item = QTableWidgetItem(entry.command)
            cmd_item.setFont(mono_font)
            self.startup_table.setItem(r, 3, cmd_item)

    def _render_net_table(self) -> None:
        query = self.net_search.text().strip().lower()
        risk_sel = self.net_risk_filter.currentText()

        filtered = [
            c
            for c in self._all_conns
            if (risk_sel == "All risks" or c.risk == risk_sel)
            and (
                not query
                or query in c.process.lower()
                or query in str(c.pid)
                or query in c.remote_addr.lower()
            )
        ]

        mono_font = QFont("Cascadia Code", 9)
        self.net_table.setRowCount(len(filtered))
        for r, c in enumerate(filtered):
            risk_item = QTableWidgetItem(c.risk)
            if c.risk == "HIGH":
                risk_item.setForeground(QColor("#ef4444"))
            elif c.risk == "MEDIUM":
                risk_item.setForeground(QColor("#f59e0b"))
            else:
                risk_item.setForeground(QColor("#10b981"))

            pid_item = QTableWidgetItem(str(c.pid))
            pid_item.setFont(mono_font)
            local_item = QTableWidgetItem(c.local_addr)
            local_item.setFont(mono_font)
            remote_item = QTableWidgetItem(c.remote_addr)
            remote_item.setFont(mono_font)

            self.net_table.setItem(r, 0, risk_item)
            self.net_table.setItem(r, 1, QTableWidgetItem(c.process))
            self.net_table.setItem(r, 2, pid_item)
            self.net_table.setItem(r, 3, QTableWidgetItem(c.status))
            self.net_table.setItem(r, 4, local_item)
            self.net_table.setItem(r, 5, remote_item)

    def _handle_toggle_control(self, control_id: str, lock: bool) -> None:
        action = "Locking" if lock else "Restoring"
        self.log_event(f"{action} {control_id}...")

        def task():
            return self.engine.set_control(control_id, lock)

        def done(res):
            tag = "OK" if res.success else "ERR"
            self.log_event(f"[{tag}] {res.control_id}: {res.message}")
            self.refresh_all()

        self._run_async(task, done)

    def _run_total_lockdown(self) -> None:
        self.log_event("Applying full endpoint lockdown...")

        def task():
            results = self.engine.lockdown_all()
            killed = kill_all_remote_tools()
            return results, killed

        def done(payload):
            results, killed = payload
            for r in results:
                tag = "OK" if r.success else "ERR"
                self.log_event(f"[{tag}] {r.control_id}: {r.message}")
            if killed:
                for pid, name, ok, msg in killed:
                    self.log_event(f"[KILLED] {name} (PID {pid}): {msg}")
            else:
                self.log_event("[OK] No running remote-access tools found.")
            self.refresh_all()
            QMessageBox.information(
                self,
                "Lockdown complete",
                "Endpoint hardening controls have been applied. Review the activity log for details.",
            )

        self._run_async(task, done)

    def _run_restore_all(self) -> None:
        reply = QMessageBox.question(
            self,
            "Confirm restore all",
            "Restore all reversible privacy and network controls to default (Windows Firewall remains ON)?",
        )
        if reply != QMessageBox.Yes:
            return
        self.log_event("Restoring all reversible controls...")

        def task():
            return self.engine.restore_all()

        def done(results):
            for r in results:
                tag = "OK" if r.success else "ERR"
                self.log_event(f"[{tag}] {r.control_id}: {r.message}")
            self.refresh_all()
            QMessageBox.information(
                self,
                "Restore complete",
                "All reversible controls have been restored (Windows Firewall kept ON).",
            )

        self._run_async(task, done)

    def _run_restore_privacy(self) -> None:
        self.log_event("Restoring camera and microphone access...")

        def task():
            return self.engine.restore_privacy_only()

        def done(results):
            for r in results:
                tag = "OK" if r.success else "ERR"
                self.log_event(f"[{tag}] {r.control_id}: {r.message}")
            self.refresh_all()

        self._run_async(task, done)

    def _run_kill_remote_tools(self) -> None:
        self.log_event("Scanning for remote-access tools...")

        def task():
            return kill_all_remote_tools()

        def done(killed):
            if not killed:
                self.log_event("[OK] No running remote-access tools detected.")
            else:
                for pid, name, ok, msg in killed:
                    tag = "OK" if ok else "ERR"
                    self.log_event(f"[{tag}] {name} (PID {pid}): {msg}")
            self.refresh_all()

        self._run_async(task, done)

    def _kill_selected_connection_pid(self) -> None:
        row = self.net_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "No selection", "Select a row in the socket table first.")
            return
        pid_item = self.net_table.item(row, 2)
        proc_item = self.net_table.item(row, 1)
        if not pid_item:
            return
        pid = int(pid_item.text())
        pname = proc_item.text() if proc_item else "process"
        reply = QMessageBox.question(
            self,
            "Confirm termination",
            f"Terminate {pname} (PID {pid}) and its child processes?",
        )
        if reply == QMessageBox.Yes:
            ok, msg = kill_process_tree(pid)
            self.log_event(f"[{'OK' if ok else 'ERR'}] {msg}")
            self.refresh_all()

    def _export_report(self) -> None:
        default_path = os.path.join(
            os.path.expanduser("~"),
            "Desktop",
            f"LaptopShield_Audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        )
        path, _ = QFileDialog.getSaveFileName(
            self, "Save security audit report", default_path, "JSON Files (*.json)"
        )
        if not path:
            return
        score = self.engine.calculate_score(self._latest_statuses)
        err = export_audit_report(path, self._latest_statuses, score)
        if err:
            QMessageBox.critical(self, "Export failed", err)
        else:
            self.log_event(f"[OK] Audit report exported to {path}")
            QMessageBox.information(self, "Report exported", f"Saved to:\n{path}")

    def _handle_elevate(self) -> None:
        if elevate_self():
            QApplication.quit()
        else:
            QMessageBox.warning(
                self,
                "Elevation failed",
                "Right-click RUN_LAPTOPSHIELD_PRO.bat and choose Run as administrator.",
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
