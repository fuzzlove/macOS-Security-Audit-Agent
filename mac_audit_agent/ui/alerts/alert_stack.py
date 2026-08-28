from __future__ import annotations

from datetime import datetime, timezone

from PySide6.QtCore import Qt
from PySide6.QtGui import QCursor
from PySide6.QtWidgets import QApplication, QLabel, QVBoxLayout, QWidget

from .alert_card import AlertCard
from .clickfix_alert_card import ClickFixAlertCard


class AlertStack(QWidget):
    """Strong-reference alert stack; cards are removed only by explicit workflow."""
    def __init__(self,parent:QWidget|None=None)->None:
        super().__init__(parent);self.cards:dict[str,AlertCard]={};self.setWindowFlags(Qt.WindowType.Tool|Qt.WindowType.WindowStaysOnTopHint|Qt.WindowType.FramelessWindowHint);self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating,True);self.layout=QVBoxLayout(self);self.layout.setSpacing(10);self.summary=QLabel();self.summary.setAccessibleName("Additional queued security alerts");self.summary.hide();self.layout.addWidget(self.summary)

    def add_alert(self,alert:dict)->AlertCard:
        event_id=str(alert.get("alert_id") or alert["event_id"])
        if event_id in self.cards:return self.cards[event_id]
        if str(alert.get("severity","")).lower()=="medium" and str(alert.get("event_id","")).startswith("cfx-"):
            current_time=self._timestamp(alert.get("timestamp"))
            for existing in reversed(list(self.cards.values())):
                if isinstance(existing,ClickFixAlertCard) and str(existing.alert.get("severity","")).lower()=="medium" and existing.alert.get("title")==alert.get("title"):
                    existing_time=self._timestamp(existing.alert.get("timestamp"))
                    if abs((current_time-existing_time).total_seconds())<=60:
                        existing.add_grouped_occurrence(str(alert.get("event_id")),str(alert.get("timestamp") or ""));return existing
        card=ClickFixAlertCard(alert,self) if str(alert.get("event_id","")).startswith("cfx-") else AlertCard(alert,self)
        self.cards[event_id]=card;self.layout.addWidget(card);self._reflow();self.show();return card

    def remove_acknowledged(self,event_id:str)->None:
        card=self.cards.pop(event_id,None)
        if card is not None:self.layout.removeWidget(card);card.deleteLater()
        self._reflow()

    def _reflow(self)->None:
        screen=QApplication.screenAt(QCursor.pos()) or QApplication.primaryScreen()
        if screen is None:return
        available=screen.availableGeometry();max_height=max(240,available.height()-48);used=self.sizeHint().height();overflow=0
        if used>max_height:
            for card in self.cards.values():
                severity=str(card.alert.get("severity","")).lower()
                if severity in {"informational","low","medium"} and used>max_height:
                    card.hide();overflow+=1;used-=card.sizeHint().height()+self.layout.spacing()
                else:card.show()
        else:
            for card in self.cards.values():card.show()
        self.summary.setText(f"{overflow} additional lower-severity alerts remain in the Alert Center") if overflow else self.summary.setText("");self.summary.setVisible(bool(overflow));self.adjustSize();self.move(available.right()-self.width()-24,available.bottom()-self.height()-24)

    @staticmethod
    def _timestamp(value:object)->datetime:
        try:return datetime.fromisoformat(str(value).replace("Z","+00:00")).astimezone(timezone.utc)
        except (TypeError,ValueError):return datetime.now(timezone.utc)
