"""High-end Cyber-Ops Dark Theme QSS and custom QPainter widgets."""

from __future__ import annotations

from PyQt5.QtCore import QRectF, Qt
from PyQt5.QtGui import QColor, QFont, QPainter, QPen
from PyQt5.QtWidgets import QWidget

STYLESHEET = """
QMainWindow, QWidget {
    background-color: #0b0f17;
    color: #e2e8f0;
    font-family: "Segoe UI", "Inter", sans-serif;
    font-size: 13px;
}

#Sidebar {
    background-color: #111827;
    border-right: 1px solid #1f2937;
}

#BrandTitle {
    color: #f8fafc;
    font-size: 17px;
    font-weight: 700;
    letter-spacing: 0.5px;
}

#BrandSub {
    color: #64748b;
    font-size: 11px;
}

QPushButton#NavBtn {
    background-color: transparent;
    color: #94a3b8;
    border: none;
    border-radius: 8px;
    padding: 10px 14px;
    text-align: left;
    font-weight: 600;
    font-size: 13px;
}

QPushButton#NavBtn:hover {
    background-color: #1e293b;
    color: #f1f5f9;
}

QPushButton#NavBtn[active="true"] {
    background-color: #1d4ed8;
    color: #ffffff;
}

QFrame#Card {
    background-color: #131a26;
    border: 1px solid #1e293b;
    border-radius: 12px;
}

QFrame#Card:hover {
    border: 1px solid #334155;
}

QLabel#PageTitle {
    font-size: 20px;
    font-weight: 700;
    color: #f8fafc;
}

QLabel#PageSub {
    font-size: 12px;
    color: #94a3b8;
}

QLabel#KpiValue {
    font-size: 24px;
    font-weight: 700;
    color: #f8fafc;
}

QLabel#KpiLabel {
    font-size: 11px;
    font-weight: 600;
    color: #94a3b8;
    text-transform: uppercase;
}

QPushButton#PanicBtn {
    background-color: #dc2626;
    color: #ffffff;
    border: 1px solid #ef4444;
    border-radius: 10px;
    padding: 14px 20px;
    font-size: 14px;
    font-weight: 700;
}

QPushButton#PanicBtn:hover {
    background-color: #b91c1c;
}

QPushButton#SafeBtn {
    background-color: #1e293b;
    color: #e2e8f0;
    border: 1px solid #334155;
    border-radius: 10px;
    padding: 12px 16px;
    font-size: 13px;
    font-weight: 600;
}

QPushButton#SafeBtn:hover {
    background-color: #334155;
}

QPushButton#LockBtn {
    background-color: #dc2626;
    color: #ffffff;
    border: none;
    border-radius: 6px;
    padding: 7px 14px;
    font-weight: 700;
    font-size: 12px;
}

QPushButton#LockBtn:hover {
    background-color: #b91c1c;
}

QPushButton#UnlockBtn {
    background-color: #1e293b;
    color: #cbd5e1;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 7px 12px;
    font-weight: 600;
    font-size: 12px;
}

QPushButton#UnlockBtn:hover {
    background-color: #334155;
}

QPushButton#PrimaryBtn {
    background-color: #0284c7;
    color: #ffffff;
    border: none;
    border-radius: 7px;
    padding: 8px 14px;
    font-weight: 600;
}

QPushButton#PrimaryBtn:hover {
    background-color: #0369a1;
}

QTableWidget {
    background-color: #131a26;
    border: 1px solid #1e293b;
    border-radius: 10px;
    gridline-color: #1e293b;
    selection-background-color: #1e3a5f;
}

QHeaderView::section {
    background-color: #0f172a;
    color: #94a3b8;
    padding: 8px;
    border: none;
    border-bottom: 1px solid #1e293b;
    font-weight: 700;
    font-size: 11px;
}

QTextEdit#LogBox {
    background-color: #090d14;
    color: #4ade80;
    border: 1px solid #1e293b;
    border-radius: 10px;
    font-family: "Consolas", "Cascadia Code", monospace;
    font-size: 12px;
    padding: 10px;
}

QScrollArea {
    border: none;
    background-color: transparent;
}
"""


class ScoreGaugeWidget(QWidget):
    """Circular security posture gauge drawn with QPainter."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._score = 0
        self.setMinimumSize(140, 140)
        self.setMaximumSize(160, 160)

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

        # Background track
        bg_pen = QPen(QColor("#1e293b"), 11, Qt.SolidLine, Qt.RoundCap)
        painter.setPen(bg_pen)
        painter.drawArc(rect, 0, 360 * 16)

        # Score color
        if self._score >= 80:
            color = QColor("#10b981")
            label = "SECURED"
        elif self._score >= 50:
            color = QColor("#f59e0b")
            label = "MODERATE"
        else:
            color = QColor("#ef4444")
            label = "AT RISK"

        fg_pen = QPen(color, 11, Qt.SolidLine, Qt.RoundCap)
        painter.setPen(fg_pen)
        span_angle = int(-360 * (self._score / 100.0) * 16)
        painter.drawArc(rect, 90 * 16, span_angle)

        # Center percentage text
        painter.setPen(QColor("#f8fafc"))
        painter.setFont(QFont("Segoe UI", 22, QFont.Bold))
        painter.drawText(rect.adjusted(0, -8, 0, -8), Qt.AlignCenter, f"{self._score}%")

        painter.setPen(color)
        painter.setFont(QFont("Segoe UI", 8, QFont.Bold))
        painter.drawText(rect.adjusted(0, 26, 0, 26), Qt.AlignCenter, label)
