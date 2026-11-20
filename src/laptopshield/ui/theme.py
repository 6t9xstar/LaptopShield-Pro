"""Graphite Instrument Dark Theme QSS and custom QPainter Posture Gauge."""

from __future__ import annotations

from PyQt5.QtCore import QRectF, Qt
from PyQt5.QtGui import QColor, QFont, QPainter, QPen
from PyQt5.QtWidgets import QWidget

STYLESHEET = """
QMainWindow, QWidget {
    background-color: #111113;
    color: #f4f4f5;
    font-family: "Segoe UI", "Inter", sans-serif;
    font-size: 13px;
    font-weight: 400;
}

#Sidebar {
    background-color: #141417;
    border-right: 1px solid #27272a;
}

#BrandTitle {
    color: #f4f4f5;
    font-size: 16px;
    font-weight: 600;
}

#BrandSub {
    color: #71717a;
    font-size: 12px;
}

#SectionLabel {
    color: #71717a;
    font-size: 11px;
    font-weight: 500;
    padding-left: 12px;
    margin-top: 8px;
    margin-bottom: 4px;
}

QPushButton#NavBtn {
    background-color: transparent;
    color: #a1a1aa;
    border: none;
    border-radius: 6px;
    padding: 8px 12px;
    text-align: left;
    font-weight: 500;
    font-size: 13px;
}

QPushButton#NavBtn:hover {
    background-color: #1f1f24;
    color: #f4f4f5;
}

QPushButton#NavBtn[active="true"] {
    background-color: #27272a;
    color: #f4f4f5;
}

QFrame#Card {
    background-color: #18181b;
    border: 1px solid #27272a;
    border-radius: 8px;
}

QFrame#Card:hover {
    border: 1px solid #3f3f46;
}

QLabel#PageTitle {
    font-size: 20px;
    font-weight: 600;
    color: #f4f4f5;
}

QLabel#PageSub {
    font-size: 13px;
    color: #a1a1aa;
}

QLabel#KpiValue {
    font-size: 24px;
    font-weight: 600;
    color: #f4f4f5;
}

QLabel#KpiLabel {
    font-size: 12px;
    font-weight: 500;
    color: #a1a1aa;
}

QPushButton#PanicBtn {
    background-color: #dc2626;
    color: #ffffff;
    border: none;
    border-radius: 6px;
    padding: 10px 18px;
    font-size: 13px;
    font-weight: 600;
}

QPushButton#PanicBtn:hover {
    background-color: #b91c1c;
}

QPushButton#PrimaryBtn {
    background-color: #f4f4f5;
    color: #111113;
    border: none;
    border-radius: 6px;
    padding: 8px 14px;
    font-size: 13px;
    font-weight: 600;
}

QPushButton#PrimaryBtn:hover {
    background-color: #e4e4e7;
}

QPushButton#SecondaryBtn {
    background-color: #202024;
    color: #e4e4e7;
    border: 1px solid #2e2e34;
    border-radius: 6px;
    padding: 8px 14px;
    font-size: 13px;
    font-weight: 500;
}

QPushButton#SecondaryBtn:hover {
    background-color: #27272a;
    border-color: #3f3f46;
}

QPushButton#LockBtn {
    background-color: #27272a;
    color: #fca5a5;
    border: 1px solid #3f3f46;
    border-radius: 6px;
    padding: 6px 12px;
    font-weight: 500;
    font-size: 12px;
}

QPushButton#LockBtn:hover {
    background-color: #7f1d1d;
    border-color: #991b1b;
    color: #ffffff;
}

QPushButton#UnlockBtn {
    background-color: transparent;
    color: #a1a1aa;
    border: 1px solid #27272a;
    border-radius: 6px;
    padding: 6px 12px;
    font-weight: 500;
    font-size: 12px;
}

QPushButton#UnlockBtn:hover {
    background-color: #202024;
    color: #f4f4f5;
}

QLineEdit, QComboBox {
    background-color: #18181b;
    color: #f4f4f5;
    border: 1px solid #27272a;
    border-radius: 6px;
    padding: 6px 10px;
    font-size: 13px;
}

QLineEdit:focus, QComboBox:focus {
    border-color: #52525b;
}

QTableWidget {
    background-color: #18181b;
    border: 1px solid #27272a;
    border-radius: 8px;
    gridline-color: #27272a;
    selection-background-color: #27272a;
    selection-color: #f4f4f5;
}

QTableWidget::item {
    padding: 6px 8px;
}

QHeaderView::section {
    background-color: #141417;
    color: #a1a1aa;
    padding: 8px 10px;
    border: none;
    border-bottom: 1px solid #27272a;
    font-weight: 500;
    font-size: 12px;
}

QTextEdit#LogBox {
    background-color: #0d0d0f;
    color: #a1a1aa;
    border: 1px solid #27272a;
    border-radius: 8px;
    font-family: "Cascadia Code", "Consolas", monospace;
    font-size: 12px;
    padding: 12px;
}

QScrollArea {
    border: none;
    background-color: transparent;
}
"""


class ScoreGaugeWidget(QWidget):
    """Circular security posture gauge — the single bright focal instrument."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._score = 0
        self.setMinimumSize(136, 136)
        self.setMaximumSize(152, 152)

    def set_score(self, score: int) -> None:
        self._score = max(0, min(100, int(score)))
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        size = min(self.width(), self.height()) - 20
        rect = QRectF(
            (self.width() - size) / 2,
            (self.height() - size) / 2,
            size,
            size,
        )

        # Quiet graphite track
        bg_pen = QPen(QColor("#27272a"), 9, Qt.SolidLine, Qt.RoundCap)
        painter.setPen(bg_pen)
        painter.drawArc(rect, 0, 360 * 16)

        if self._score >= 80:
            color = QColor("#10b981")
            label = "Hardened"
        elif self._score >= 50:
            color = QColor("#f59e0b")
            label = "Partial"
        else:
            color = QColor("#ef4444")
            label = "Exposed"

        fg_pen = QPen(color, 9, Qt.SolidLine, Qt.RoundCap)
        painter.setPen(fg_pen)
        span_angle = int(-360 * (self._score / 100.0) * 16)
        painter.drawArc(rect, 90 * 16, span_angle)

        painter.setPen(QColor("#f4f4f5"))
        painter.setFont(QFont("Segoe UI", 21, QFont.DemiBold))
        painter.drawText(rect.adjusted(0, -8, 0, -8), Qt.AlignCenter, f"{self._score}%")

        painter.setPen(QColor("#a1a1aa"))
        painter.setFont(QFont("Segoe UI", 9, QFont.Medium))
        painter.drawText(rect.adjusted(0, 24, 0, 24), Qt.AlignCenter, label)
