"""Crisp 1.5px-stroke vector line icons rendered via QPainter (no emoji slop)."""

from __future__ import annotations

from PyQt5.QtCore import QPointF, QRectF, Qt
from PyQt5.QtGui import QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap


def _make_icon(draw_fn, color: str = "#a1a1aa", size: int = 18) -> QIcon:
    pix = QPixmap(size, size)
    pix.fill(Qt.transparent)
    painter = QPainter(pix)
    painter.setRenderHint(QPainter.Antialiasing)
    pen = QPen(QColor(color), 1.5, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)
    painter.setPen(pen)
    painter.setBrush(Qt.NoBrush)
    draw_fn(painter, size)
    painter.end()
    return QIcon(pix)


def icon_shield(color: str = "#a1a1aa") -> QIcon:
    def draw(p: QPainter, s: int) -> None:
        path = QPainterPath()
        path.moveTo(s * 0.5, s * 0.12)
        path.lineTo(s * 0.82, s * 0.25)
        path.lineTo(s * 0.82, s * 0.52)
        path.quadTo(s * 0.82, s * 0.78, s * 0.5, s * 0.88)
        path.quadTo(s * 0.18, s * 0.78, s * 0.18, s * 0.52)
        path.lineTo(s * 0.18, s * 0.25)
        path.closeSubpath()
        p.drawPath(path)

    return _make_icon(draw, color)


def icon_camera(color: str = "#a1a1aa") -> QIcon:
    def draw(p: QPainter, s: int) -> None:
        p.drawRoundedRect(QRectF(s * 0.14, s * 0.28, s * 0.52, s * 0.44), 2.5, 2.5)
        tri = QPainterPath()
        tri.moveTo(s * 0.66, s * 0.42)
        tri.lineTo(s * 0.86, s * 0.30)
        tri.lineTo(s * 0.86, s * 0.70)
        tri.lineTo(s * 0.66, s * 0.58)
        tri.closeSubpath()
        p.drawPath(tri)

    return _make_icon(draw, color)


def icon_network(color: str = "#a1a1aa") -> QIcon:
    def draw(p: QPainter, s: int) -> None:
        p.drawEllipse(QRectF(s * 0.16, s * 0.16, s * 0.68, s * 0.68))
        p.drawLine(QPointF(s * 0.16, s * 0.5), QPointF(s * 0.84, s * 0.5))
        p.drawEllipse(QRectF(s * 0.36, s * 0.16, s * 0.28, s * 0.68))

    return _make_icon(draw, color)


def icon_activity(color: str = "#a1a1aa") -> QIcon:
    def draw(p: QPainter, s: int) -> None:
        path = QPainterPath()
        path.moveTo(s * 0.12, s * 0.52)
        path.lineTo(s * 0.32, s * 0.52)
        path.lineTo(s * 0.43, s * 0.22)
        path.lineTo(s * 0.57, s * 0.78)
        path.lineTo(s * 0.68, s * 0.52)
        path.lineTo(s * 0.88, s * 0.52)
        p.drawPath(path)

    return _make_icon(draw, color)


def icon_list(color: str = "#a1a1aa") -> QIcon:
    def draw(p: QPainter, s: int) -> None:
        for y in (0.30, 0.50, 0.70):
            p.drawLine(QPointF(s * 0.20, s * y), QPointF(s * 0.82, s * y))

    return _make_icon(draw, color)


def icon_refresh(color: str = "#a1a1aa") -> QIcon:
    def draw(p: QPainter, s: int) -> None:
        rect = QRectF(s * 0.20, s * 0.20, s * 0.60, s * 0.60)
        p.drawArc(rect, 35 * 16, 285 * 16)
        p.drawLine(QPointF(s * 0.72, s * 0.22), QPointF(s * 0.80, s * 0.36))
        p.drawLine(QPointF(s * 0.72, s * 0.22), QPointF(s * 0.60, s * 0.28))

    return _make_icon(draw, color)
