"""Inspector tab: read-only card identification with a plain-language explainer."""

from __future__ import annotations

from typing import Callable, Optional

from PySide6.QtCore import QObject
from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import (
    QApplication,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.core import apdu, identify, readout, tlv
from app.core.identify import AppInfo, CardProfile
from app.gui.logview import LogView
from app.gui.workers import Runner

EXPLAINER_TEXT = (
    "Inspect card identifies applications. Read accessible data shows available "
    "records, account fields and raw responses using read commands only."
)
READOUT_PLACEHOLDER = (
    "Inspect the card, then choose Read accessible data. "
    "Returned data may include personal card details."
)


class InspectorTab(QWidget):
    """Identify the card in the reader and list its applications."""

    def __init__(self, main_window: QObject) -> None:
        super().__init__()
        self.main_window = main_window
        self._runner: Optional[Runner] = None
        self._running = False
        self._apps: list[AppInfo] = []
        self._readout_session = None
        self._build_ui()
        main_window.session_changed.connect(self._on_session_changed)
        main_window.operation_changed.connect(lambda _busy: self._update_state())
        self._update_state()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        explainer = QLabel(EXPLAINER_TEXT, self)
        explainer.setWordWrap(True)
        explainer.setStyleSheet("color: #7f8c8d;")
        layout.addWidget(explainer)

        self.inspect_button = QPushButton("Inspect card", self)
        button_font = self.inspect_button.font()
        button_font.setBold(True)
        self.inspect_button.setFont(button_font)
        controls = QHBoxLayout()
        controls.addWidget(self.inspect_button)
        self.read_button = QPushButton("Read accessible data", self)
        self.read_button.setToolTip("Inspect the card first, then read available application data without a PIN.")
        controls.addWidget(self.read_button)
        self.stop_button = QPushButton("Stop", self)
        controls.addWidget(self.stop_button)
        layout.addLayout(controls)

        self.details_tabs = QTabWidget(self)
        overview = QWidget(self)
        overview_layout = QVBoxLayout(overview)
        atr_group = QGroupBox("ATR", overview)
        atr_layout = QVBoxLayout(atr_group)
        self.atr_label = QLabel("Not inspected yet.", atr_group)
        self.atr_label.setWordWrap(True)
        self.atr_label.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        atr_layout.addWidget(self.atr_label)
        overview_layout.addWidget(atr_group)

        apps_group = QGroupBox("Applications", overview)
        apps_layout = QVBoxLayout(apps_group)
        self.app_tree = QTreeWidget(apps_group)
        self.app_tree.setHeaderLabels(["AID", "Label (from card)", "Known as"])
        self.app_tree.setColumnWidth(0, 260)
        self.app_tree.setColumnWidth(1, 200)
        self.app_tree.setRootIsDecorated(False)
        apps_layout.addWidget(self.app_tree)
        overview_layout.addWidget(apps_group, 1)

        self.suggestions_group = QGroupBox("Try next", overview)
        suggestions_layout = QVBoxLayout(self.suggestions_group)
        self.suggestions_label = QLabel("", self.suggestions_group)
        self.suggestions_label.setWordWrap(True)
        suggestions_layout.addWidget(self.suggestions_label)
        overview_layout.addWidget(self.suggestions_group)
        self.suggestions_group.hide()
        self.notes_label = QLabel("", overview)
        self.notes_label.setWordWrap(True)
        overview_layout.addWidget(self.notes_label)
        self.copy_button = QPushButton("Copy SELECT script", overview)
        overview_layout.addWidget(self.copy_button)
        self.details_tabs.addTab(overview, "Overview")

        data_page = QWidget(self)
        data_layout = QVBoxLayout(data_page)
        self.read_summary = QPlainTextEdit(READOUT_PLACEHOLDER, data_page)
        self.read_summary.setReadOnly(True)
        self.read_summary.setMaximumHeight(75)
        data_layout.addWidget(self.read_summary)
        self.account_summary = QPlainTextEdit(data_page)
        self.account_summary.setReadOnly(True)
        self.account_summary.setMaximumHeight(100)
        self.account_summary.hide()
        data_layout.addWidget(self.account_summary)
        self.data_tree = QTreeWidget(data_page)
        self.data_tree.setHeaderLabels(["Source / field", "Decoded value", "Raw hex / status"])
        self.data_tree.setColumnWidth(0, 300)
        self.data_tree.setColumnWidth(1, 240)
        self.data_tree.setSelectionMode(QTreeWidget.ExtendedSelection)
        data_layout.addWidget(self.data_tree, 1)
        self.copy_data_button = QPushButton("Copy selected data", data_page)
        self.copy_data_button.setEnabled(False)
        data_layout.addWidget(self.copy_data_button)
        self.details_tabs.addTab(data_page, "Accessible data")
        layout.addWidget(self.details_tabs, 1)
        self.data_tree.itemSelectionChanged.connect(self._update_copy_state)

        self.log = LogView(self)
        self.log.setMaximumHeight(70)
        layout.addWidget(self.log, 1)

        self.inspect_button.clicked.connect(self._inspect)
        self.copy_button.clicked.connect(self._copy_select_script)
        self.copy_data_button.clicked.connect(self._copy_selected_data)
        self.read_button.clicked.connect(self._read_accessible)
        self.stop_button.clicked.connect(self._stop)

    def _read_accessible(self) -> None:
        session = self.main_window.session
        if session is None or self._running or self.main_window.operation_busy or not self._apps:
            return
        apps = list(self._apps)
        runner = Runner(lambda emit, should_stop: readout.read_accessible_data(
            session, apps, emit=emit, should_stop=should_stop
        ))
        runner.step.connect(self._on_read_progress)
        runner.completed.connect(self._on_read_completed)
        runner.failed.connect(self._on_read_failed)
        if not self.main_window.register_runner(runner):
            return
        self._runner = runner
        self._readout_session = session
        self.data_tree.clear()
        self.account_summary.clear()
        self.account_summary.hide()
        self.details_tabs.setCurrentIndex(1)
        self.read_summary.setPlainText("Reading accessible data…")
        self._set_running(True)
        runner.start()

    def _stop(self) -> None:
        if self._runner is not None and self._running:
            self._runner.stop()
            self.read_summary.setPlainText("Stopping after the current card response…")

    def _on_read_progress(self, event) -> None:
        if self.main_window.session is not self._readout_session:
            return
        if isinstance(event, tuple) and len(event) >= 2 and event[0] == "progress":
            self.read_summary.setPlainText(str(event[1]))

    def _on_read_completed(self, result) -> None:
        self._set_running(False)
        if self.main_window.session is not self._readout_session:
            return
        if not isinstance(result, readout.ReadoutResult):
            self.read_summary.setPlainText("The scan returned an unexpected result.")
            return
        self.data_tree.clear()
        groups = {}
        returned_bytes = 0
        successful_reads = 0
        for entry in result.entries:
            if entry.aid not in groups:
                app = next((app for app in self._apps if app.aid == entry.aid), None)
                label = (app.known_name or app.label or "Application") if app else "Application"
                group = QTreeWidgetItem([label, "", entry.aid.hex().upper()])
                self.data_tree.addTopLevelItem(group)
                groups[entry.aid] = group
            if entry.error:
                status_text = entry.error
            elif entry.sw1 is None or entry.sw2 is None:
                status_text = "No response (scan stopped before transmission)"
            else:
                sw = f"{entry.sw1:02X}{entry.sw2:02X}"
                status_text = f"SW {sw} — {apdu.describe_sw(entry.sw1, entry.sw2)}"
            item = QTreeWidgetItem([entry.source, f"{len(entry.data)} byte(s)", status_text])
            groups[entry.aid].addChild(item)
            item.addChild(QTreeWidgetItem(["Command", "", apdu.format_hex(entry.command)]))
            if entry.data:
                returned_bytes += len(entry.data)
                successful_reads += 1
                item.addChild(QTreeWidgetItem(["Raw response", "", apdu.format_hex(entry.data)]))
                for node in tlv.parse_tlv(entry.data):
                    item.addChild(self._field_item(node))
                item.setExpanded(True)
            groups[entry.aid].setExpanded(True)
        status = "Stopped" if result.stopped else "Scan finished"
        if result.limited:
            status += " (scan limit reached)"
        summary = f"{status}: {successful_reads} response(s) with data, {returned_bytes} bytes, {result.exchanges} exchange(s)."
        self.read_summary.setPlainText(summary + ("\n" + "\n".join(result.notes) if result.notes else ""))
        self.data_tree.expandToDepth(2)
        account_details = self._account_details(result)
        if account_details:
            self.account_summary.setPlainText(account_details)
            self.account_summary.show()
        self.log.log_message(summary, "info")
        self._status(status)
        self._update_copy_state()

    def _account_details(self, result) -> str:
        """Summarize only returned fields; leave unavailable account data explicit."""
        applications = {}

        def collect(nodes, values):
            for node in nodes:
                values.setdefault(node.tag, node.value)
                collect(node.children, values)

        for entry in result.entries:
            values = applications.setdefault(entry.aid, {})
            collect(tlv.parse_tlv(entry.data), values)
        lines = []
        for aid, values in applications.items():
            if not values.keys() & {0x5A, 0x57, 0x5F20, 0x5F24}:
                continue
            pan = readout.decode_value(0x5A, values[0x5A]) if 0x5A in values else ""
            expiry = readout.decode_value(0x5F24, values[0x5F24]) if 0x5F24 in values else ""
            if 0x57 in values:
                track_pan, separator, track_rest = values[0x57].hex().upper().rstrip("F").partition("D")
                if separator:
                    pan = pan or track_pan
                    if not expiry and len(track_rest) >= 4:
                        expiry = f"20{track_rest[:2]}-{track_rest[2:4]}"
            name = readout.decode_value(0x5F20, values[0x5F20]) if 0x5F20 in values else ""
            lines.extend([
                f"Application {aid.hex().upper()}",
                f"Account number: {pan or 'Not returned by the card'}",
                f"Cardholder name: {name or 'Not returned by the card'}",
                f"Expiry: {expiry or 'Not returned by the card'}",
                "",
            ])
        return "\n".join(lines).strip()

    def _field_item(self, node: tlv.Tlv) -> QTreeWidgetItem:
        item = QTreeWidgetItem([f"{node.tag:X} {readout.field_name(node.tag)}", readout.decode_value(node.tag, node.value), apdu.format_hex(node.value)])
        for child in node.children:
            item.addChild(self._field_item(child))
        item.setExpanded(bool(node.children))
        return item

    def _on_read_failed(self, message: str) -> None:
        self._set_running(False)
        if self.main_window.session is self._readout_session:
            self.read_summary.setPlainText(f"Read failed: {message}")

    def _update_copy_state(self) -> None:
        self.copy_data_button.setEnabled(bool(self.data_tree.selectedItems()))

    def _copy_selected_data(self) -> None:
        lines = ["\t".join(item.text(column) for column in range(3)) for item in self.data_tree.selectedItems()]
        if lines:
            QApplication.clipboard().setText("\n".join(lines))

    def _clear_readout(self) -> None:
        self.data_tree.clear()
        self.account_summary.clear()
        self.account_summary.hide()
        self.read_summary.setPlainText(READOUT_PLACEHOLDER)
        self._update_copy_state()

    def _inspect(self) -> None:
        session = self.main_window.session
        if session is None or self._running:
            return
        if self.main_window.operation_busy:
            return

        def work(
            emit: Callable[[object], None], should_stop: Callable[[], bool]
        ) -> CardProfile:
            def publish(*args: object) -> None:
                emit(args)

            return identify.identify_card(
                session, emit=publish, should_stop=should_stop
            )

        runner = Runner(work)
        self._run_session = session
        runner.step.connect(self._on_step)
        runner.completed.connect(self._on_completed)
        runner.failed.connect(self._on_failed)
        if not self.main_window.register_runner(runner):
            return
        self._runner = runner
        self._set_running(True)
        self._clear_readout()
        self._clear_suggestions()
        self.log.log_message("Inspecting card (read-only scan)...", "info")
        runner.start()

    def _on_step(self, event: object) -> None:
        """Log one progress event.

        identify_card emits ("progress", text) as a single tuple, which
        publish() re-packs as emit(args), so a nested one-element tuple may
        arrive here; direct emits arrive un-nested.
        """
        if isinstance(event, tuple) and len(event) == 1 and isinstance(event[0], tuple):
            event = event[0]
        if isinstance(event, tuple) and len(event) >= 2 and event[0] == "progress":
            self.log.log_message(str(event[1]), "info")

    def _on_completed(self, result: object) -> None:
        self._set_running(False)
        if self.main_window.session is not getattr(self, "_run_session", None):
            return
        if not isinstance(result, CardProfile):
            self.log.log_message("! Inspection returned an unexpected result.", "error")
            return
        self.apply_profile(result)

    def apply_profile(self, result: CardProfile) -> None:
        self._apps = list(result.apps)
        self.atr_label.setText(result.atr_summary or "ATR could not be read.")
        self.app_tree.clear()
        for app in result.apps:
            self.app_tree.addTopLevelItem(
                QTreeWidgetItem(
                    [
                        app.aid.hex().upper(),
                        app.label or "-",
                        app.known_name or "-",
                    ]
                )
            )
        self.notes_label.setText("\n".join(result.notes))
        self._show_suggestions(list(result.suggestions))
        self.log.log_message(result.label, "rx")
        self.log.log_message(
            f"{len(result.apps)} application(s) found, {len(result.notes)} note(s).",
            "info",
        )
        self._status(f"Inspection finished: {result.label}")
        self._update_state()

    def _on_failed(self, message: str) -> None:
        self._set_running(False)
        if self.main_window.session is not getattr(self, "_run_session", None):
            return
        self.log.log_message(f"! Inspection failed: {message}", "error")
        self._status("Inspection failed.", 3000)

    def _show_suggestions(self, suggestions: list[str]) -> None:
        self.suggestions_label.setText("\n".join(f"- {item}" for item in suggestions))
        self.suggestions_group.setVisible(bool(suggestions))

    def _clear_suggestions(self) -> None:
        self.suggestions_label.clear()
        self.suggestions_group.hide()

    def _copy_select_script(self) -> None:
        if not self._apps:
            return
        lines = [
            "# SELECT commands for the applications found on this card.",
            "# Paste into the Script tab (or gscriptor) and run with the card inserted.",
        ]
        for app in self._apps:
            comment = app.known_name or app.label or f"Application {app.aid.hex().upper()}"
            lines.append(f"# {comment}")
            lines.append(f"00 A4 04 00 {len(app.aid):02X} {apdu.format_hex(app.aid)}")
        QApplication.clipboard().setText("\n".join(lines) + "\n")
        self.log.log_message("SELECT script copied to the clipboard.", "info")
        self._status("SELECT script copied to the clipboard.")

    def _set_running(self, running: bool) -> None:
        self._running = running
        self._update_state()

    def _on_session_changed(self, session: object) -> None:
        self._apps.clear()
        self.atr_label.setText("Not inspected yet.")
        self.app_tree.clear()
        self.notes_label.clear()
        self._clear_suggestions()
        self._clear_readout()
        self._update_state()
        if session is None:
            self.log.log_message("Card session closed.", "info")

    def _update_state(self) -> None:
        session_ready = self.main_window.session is not None
        self.inspect_button.setEnabled(
            session_ready and not self._running and not self.main_window.operation_busy
        )
        self.copy_button.setEnabled(bool(self._apps))
        self.read_button.setEnabled(session_ready and bool(self._apps) and not self._running and not self.main_window.operation_busy)
        self.stop_button.setEnabled(self._running)

    def _status(self, message: str, timeout: int = 0) -> None:
        if hasattr(self.main_window, "statusBar"):
            self.main_window.statusBar().showMessage(message, timeout)
