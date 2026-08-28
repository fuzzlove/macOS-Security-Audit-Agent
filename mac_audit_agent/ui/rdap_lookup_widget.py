from __future__ import annotations
import json
from PySide6.QtCore import QObject,QThread,Signal,Slot
from PySide6.QtWidgets import QFileDialog,QHBoxLayout,QLabel,QLineEdit,QMessageBox,QPushButton,QTextBrowser,QVBoxLayout,QWidget
from mac_audit_agent.network_rdap import lookup_ip_rdap

class _Worker(QObject):
    completed=Signal(object);failed=Signal(str)
    def __init__(self,address,provider):super().__init__();self.address=address;self.provider=provider
    @Slot()
    def run(self):
        try:self.completed.emit(lookup_ip_rdap(self.address,self.provider))
        except Exception as exc:self.failed.emit(f"{type(exc).__name__}: {exc}")

class RDAPLookupWidget(QWidget):
    def __init__(self,parent=None):
        super().__init__(parent);self.thread=None;self.worker=None;self.result=None;self._shutting_down=False;layout=QVBoxLayout(self);notice=QLabel("Look up a current or historical public IP using ARIN bootstrap or RIPE RDAP. The address is sent to the selected registry only after you click Lookup. Registration data does not establish connection intent or reputation.");notice.setWordWrap(True);layout.addWidget(notice);row=QHBoxLayout();self.address=QLineEdit();self.address.setPlaceholderText("Public IPv4 or IPv6 from live or prior evidence");self.arin=QPushButton("Lookup with ARIN");self.ripe=QPushButton("Lookup with RIPE");self.export=QPushButton("Export RDAP Evidence");self.export.setEnabled(False);row.addWidget(self.address,1);row.addWidget(self.arin);row.addWidget(self.ripe);row.addWidget(self.export);layout.addLayout(row);self.output=QTextBrowser();layout.addWidget(self.output);self.arin.clicked.connect(lambda:self.lookup("ARIN bootstrap"));self.ripe.clicked.connect(lambda:self.lookup("RIPE"));self.export.clicked.connect(self.export_result)
    def set_address(self,value):self.address.setText(str(value or "").split("%",1)[0])
    def lookup(self,provider):
        if self._shutting_down:return
        if self.thread and self.thread.isRunning():return
        if QMessageBox.question(self,"External RDAP Lookup",f"Send IP address {self.address.text().strip()} to {provider} for registration lookup?",QMessageBox.Yes|QMessageBox.No,QMessageBox.No)!=QMessageBox.Yes:return
        self.thread=QThread(self);self.worker=_Worker(self.address.text(),provider);self.worker.moveToThread(self.thread);self.thread.started.connect(self.worker.run);self.worker.completed.connect(self._done);self.worker.failed.connect(self._failed);self.worker.completed.connect(self.thread.quit);self.worker.failed.connect(self.thread.quit);self.thread.finished.connect(self.worker.deleteLater);self.thread.finished.connect(self._finished);self.thread.start()
    def _done(self,result):self.result=result;self.output.setPlainText(json.dumps(result.to_dict(),indent=2,sort_keys=True));self.export.setEnabled(True)
    def _failed(self,error):QMessageBox.warning(self,"RDAP Lookup Failed",error)
    def _finished(self):
        if self.thread:self.thread.deleteLater()
        self.thread=None;self.worker=None
    def shutdown(self,timeout_ms=3000):
        self._shutting_down=True;thread=self.thread
        if thread is None or not thread.isRunning():return True
        thread.requestInterruption();thread.quit()
        if thread.wait(timeout_ms):return True
        thread.terminate();return thread.wait(500)
    def closeEvent(self,event):self.shutdown();super().closeEvent(event)
    def export_result(self):
        if not self.result:return
        path,_=QFileDialog.getSaveFileName(self,"Export RDAP Evidence",f"rdap-{self.result.address.replace(':','_')}.json","JSON (*.json)")
        if path:open(path,"w",encoding="utf-8").write(json.dumps({"schema_version":"1.0","rdap":self.result.to_dict()},indent=2,sort_keys=True)+"\n")
