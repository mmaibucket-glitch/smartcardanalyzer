"""Main window hosting the tool tabs."""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QMainWindow, QMessageBox, QTabWidget

from app.core import apdu, identify, pcsc
from app.gui.console_tab import ConsoleTab
from app.gui.fuzz_tab import FuzzTab
from app.gui.help_tab import HelpTab
from app.gui.inspector_tab import InspectorTab
from app.gui.script_tab import ScriptTab
from app.gui.workers import Runner


class MainWindow(QMainWindow):
    session_changed = Signal(object)
    safety_changed = Signal(bool)

    def __init__(self) -> None:
        super().__init__()
        self.session = None
        self.safe_mode = True
        self.setWindowTitle("Smartcard Tool")
        self.resize(960, 620)
        self._build_ui()

    def set_safe_mode(self, enabled: bool) -> None:
        if enabled == self.safe_mode:
            return
        self.safe_mode = enabled
        self.safety_changed.emit(enabled)

    def _build_ui(self) -> None:
        self.tabs = QTabWidget(self)
        self.console_tab = ConsoleTab(self)
        self.tabs.addTab(self.console_tab, "Console")
        self.tabs.addTab(InspectorTab(self), "Inspector")
        self.tabs.addTab(ScriptTab(self), "Script")
        self.tabs.addTab(FuzzTab(self), "Fuzz")
        self.tabs.addTab(HelpTab(self), "Help")
        self.setCentralWidget(self.tabs)

    def set_session(self, session) -> None:
        self.session = session
        self.session_changed.emit(session)

    def connect_reader(self, reader_name: str) -> None:
        if not reader_name or self.session is not None:
            return
        session = pcsc.CardSession(reader_name)
        try:
            session.connect()
        except pcsc.PcscError as exc:
            QMessageBox.warning(self, "Connect failed", str(exc))
            self.console_tab.log.log_message(f"! {exc}", "error")
            return
        self.set_session(session)
        self.console_tab.log.log_message(
            f"Connected to {reader_name} (ATR {apdu.format_hex(session.atr)})", "info"
        )
        self._identify_in_background()

    def _identify_in_background(self) -> None:
        session = self.session
        if session is None:
            return
        runner = Runner(
            lambda emit, should_stop: identify.identify_card(
                session, emit=emit, should_stop=should_stop
            )
        )
        runner.step.connect(self._on_identify_event)
        runner.completed.connect(self._on_identify_done)
        runner.failed.connect(self._on_identify_failed)
        self._identify_runner = runner
        runner.start()

    def _on_identify_event(self, event) -> None:
        if isinstance(event, tuple) and len(event) == 2 and event[0] == "progress":
            self.console_tab.log.log_message(f"Identifying: {event[1]}", "info")

    def _on_identify_done(self, profile) -> None:
        log = self.console_tab.log
        log.log_message(f"Card identified: {profile.label}", "sw")
        if profile.atr_summary:
            log.log_message(profile.atr_summary, "info")
        for note in profile.notes:
            log.log_message(note, "info")
        for suggestion in profile.suggestions[:3]:
            log.log_message(f"Try next: {suggestion}", "info")

    def _on_identify_failed(self, message) -> None:
        self.console_tab.log.log_message(f"! Identification failed: {message}", "error")

    def disconnect_card(self) -> None:
        if self.session is None:
            return
        self.session.disconnect()
        self.set_session(None)
        self.console_tab.log.log_message("Disconnected.", "info")

    def closeEvent(self, event) -> None:
        if self.session is not None:
            self.session.disconnect()
        super().closeEvent(event)
