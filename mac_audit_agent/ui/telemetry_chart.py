from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QColor, QFontMetrics, QMouseEvent, QPainter, QPainterPath, QPaintEvent, QPen
from PySide6.QtWidgets import QSizePolicy, QWidget


@dataclass(frozen=True)
class TelemetryChartPoint:
    timestamp: str
    observed: float | None
    expected: float | None
    normal_low: float | None
    normal_high: float | None
    anomaly_score: int = 0
    anomaly_id: str = ""


class TelemetryChart(QWidget):
    """Small theme-aware time-series renderer for aggregated telemetry only."""

    anomaly_selected = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("behavioralTelemetryChart")
        self.setAccessibleName("Activity versus normal baseline chart")
        self.setMinimumHeight(300)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self._points: list[TelemetryChartPoint] = []
        self._markers: list[tuple[QPointF, str]] = []
        self._empty_message = "MSAA is establishing the behavioral baseline."

    def set_series(self, points: list[TelemetryChartPoint], *, empty_message: str = "") -> None:
        self._points = list(points[-1500:])
        if empty_message:
            self._empty_message = empty_message
        self.update()

    def paintEvent(self, event: QPaintEvent) -> None:  # noqa: N802 - Qt API
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)
        palette = self.palette()
        background = palette.color(palette.ColorRole.Base)
        foreground = palette.color(palette.ColorRole.Text)
        muted = palette.color(palette.ColorRole.PlaceholderText)
        grid = palette.color(palette.ColorRole.Mid)
        painter.fillRect(self.rect(), background)

        plot = QRectF(58, 20, max(20, self.width() - 78), max(40, self.height() - 64))
        values = [
            float(value)
            for point in self._points
            for value in (point.observed, point.expected, point.normal_low, point.normal_high)
            if value is not None
        ]
        if len(self._points) < 2 or not values:
            painter.setPen(foreground)
            painter.drawText(self.rect().adjusted(24, 24, -24, -24), Qt.AlignCenter | Qt.TextWordWrap, self._empty_message)
            return

        maximum = max(1.0, max(values) * 1.12)
        minimum = min(0.0, min(values))
        span = max(1.0, maximum - minimum)

        painter.setPen(QPen(grid, 1, Qt.DotLine))
        metrics = QFontMetrics(painter.font())
        for index in range(5):
            ratio = index / 4
            y = plot.bottom() - ratio * plot.height()
            painter.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y))
            label = f"{minimum + ratio * span:.0f}"
            painter.setPen(muted)
            painter.drawText(QRectF(2, y - metrics.height() / 2, 50, metrics.height()), Qt.AlignRight, label)
            painter.setPen(QPen(grid, 1, Qt.DotLine))

        def location(index: int, value: float) -> QPointF:
            x = plot.left() + index * plot.width() / max(1, len(self._points) - 1)
            y = plot.bottom() - ((value - minimum) / span) * plot.height()
            return QPointF(x, y)

        # Calm blue-green is reserved for the expected envelope; observed data
        # remains high-contrast and anomaly colors keep their security meaning.
        expected_color = QColor("#2A9D8F")
        observed_color = QColor("#4F7CAC")
        threshold_color = QColor("#D97706")
        anomaly_color = QColor("#C2413A")

        upper = [location(index, float(point.normal_high)) for index, point in enumerate(self._points) if point.normal_high is not None]
        lower = [location(index, float(point.normal_low)) for index, point in enumerate(self._points) if point.normal_low is not None]
        if len(upper) == len(self._points) and len(lower) == len(self._points):
            band = QPainterPath(upper[0])
            for point in upper[1:]:
                band.lineTo(point)
            for point in reversed(lower):
                band.lineTo(point)
            band.closeSubpath()
            fill = QColor(expected_color)
            fill.setAlpha(45)
            painter.fillPath(band, fill)

        self._draw_line(painter, self._points, location, "expected", expected_color, Qt.DashLine)
        self._draw_line(painter, self._points, location, "observed", observed_color, Qt.SolidLine)

        threshold_values = [point.normal_high for point in self._points if point.normal_high is not None]
        if threshold_values:
            threshold = max(threshold_values) * 1.25
            y = location(0, threshold).y()
            if plot.top() <= y <= plot.bottom():
                painter.setPen(QPen(threshold_color, 1.5, Qt.DashDotLine))
                painter.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y))

        self._markers = []
        for index, point in enumerate(self._points):
            if point.anomaly_score < 40 or point.observed is None:
                continue
            marker = location(index, float(point.observed))
            self._markers.append((marker, point.anomaly_id))
            painter.setBrush(anomaly_color if point.anomaly_score >= 60 else threshold_color)
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(marker, 5.0, 5.0)

        painter.setPen(foreground)
        painter.drawText(QRectF(plot.left(), plot.bottom() + 10, plot.width(), 24), Qt.AlignCenter, "Time")
        painter.save()
        painter.translate(8, plot.center().y())
        painter.rotate(-90)
        painter.drawText(QRectF(-plot.height() / 2, 0, plot.height(), 24), Qt.AlignCenter, "Activity / anomaly context")
        painter.restore()

        self._draw_legend(painter, plot, foreground, observed_color, expected_color, threshold_color, anomaly_color)
        self._draw_time_labels(painter, plot, muted)

    @staticmethod
    def _draw_line(painter: QPainter, points: list[TelemetryChartPoint], location, attribute: str, color: QColor, style: Qt.PenStyle) -> None:
        path = QPainterPath()
        active = False
        for index, point in enumerate(points):
            value = getattr(point, attribute)
            if value is None:
                active = False
                continue
            current = location(index, float(value))
            if not active:
                path.moveTo(current)
                active = True
            else:
                path.lineTo(current)
        painter.setPen(QPen(color, 2.2, style))
        painter.setBrush(Qt.NoBrush)
        painter.drawPath(path)

    @staticmethod
    def _draw_legend(painter: QPainter, plot: QRectF, foreground: QColor, observed: QColor, expected: QColor, threshold: QColor, anomaly: QColor) -> None:
        labels = (("Observed", observed), ("Expected", expected), ("Normal range", expected), ("Anomaly threshold", threshold), ("Event marker", anomaly))
        x = plot.left() + 6
        y = plot.top() + 6
        metrics = QFontMetrics(painter.font())
        for label, color in labels:
            painter.setPen(QPen(color, 3))
            painter.drawLine(QPointF(x, y + 7), QPointF(x + 18, y + 7))
            painter.setPen(foreground)
            painter.drawText(QRectF(x + 24, y, metrics.horizontalAdvance(label) + 5, metrics.height()), Qt.AlignLeft, label)
            x += 34 + metrics.horizontalAdvance(label)

    def _draw_time_labels(self, painter: QPainter, plot: QRectF, color: QColor) -> None:
        painter.setPen(color)
        for index in (0, len(self._points) // 2, len(self._points) - 1):
            try:
                stamp = datetime.fromisoformat(self._points[index].timestamp.replace("Z", "+00:00"))
                label = stamp.astimezone().strftime("%b %d %H:%M")
            except ValueError:
                label = self._points[index].timestamp[:16]
            x = plot.left() + index * plot.width() / max(1, len(self._points) - 1)
            painter.drawText(QRectF(x - 60, plot.bottom() + 28, 120, 20), Qt.AlignCenter, label)

    def mousePressEvent(self, event: QMouseEvent) -> None:  # noqa: N802 - Qt API
        for marker, anomaly_id in self._markers:
            if anomaly_id and (marker - event.position()).manhattanLength() <= 12:
                self.anomaly_selected.emit(anomaly_id)
                event.accept()
                return
        super().mousePressEvent(event)


__all__ = ["TelemetryChart", "TelemetryChartPoint"]
