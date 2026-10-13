"""Inspector tab: read-only card identification with a plain-language explainer."""

from __future__ import annotations

from typing import Callable, Optional

from PySide6.QtCore import QObject
from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import (
    QApplication,
    QGroupBox,
    QLabel,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.core import apdu, identify
from app.core.identify import AppInfo, CardProfile
from app.gui.logview import LogView
from app.gui.workers import Runner

EXPLAINER_TEXT = (
    "Runs a safe, read-only scan: selects EF.DIR, reads the application list "
    "and matches AIDs against well-known card types."
)


class InspectorTab(QWidget):
    """Identify the card in the reader and list its applications."""

    def __init__(self, main_window: QObject) -> None:
        super().__init__()
        self.main_window = main_window
        self._runner: Optional[Runner] = None
        self._running = False
        self._apps: list[AppInfo] = []
        self._build_ui()
        main_window.session_changed.connect(self._on_session_changed)
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
        layout.addWidget(self.inspect_button)

        atr_group = QGroupBox("ATR", self)
        atr_layout = QVBoxLayout(atr_group)
        self.atr_label = QLabel("Not inspected yet.", atr_group)
        self.atr_label.setWordWrap(True)
        self.atr_label.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        atr_layout.addWidget(self.atr_label)
        layout.addWidget(atr_group)

        apps_group = QGroupBox("Applications", self)
        apps_layout = QVBoxLayout(apps_group)
        self.app_tree = QTreeWidget(apps_group)
        self.app_tree.setHeaderLabels(["AID", "Label (from card)", "Known as"])
        self.app_tree.setRootIsDecorated(False)
        apps_layout.addWidget(self.app_tree)
        layout.addWidget(apps_group, 1)

        self.suggestions_group = QGroupBox("Try next", self)
        suggestions_layout = QVBoxLayout(self.suggestions_group)
        self.suggestions_label = QLabel("", self.suggestions_group)
        self.suggestions_label.setWordWrap(True)
        suggestions_layout.addWidget(self.suggestions_label)
        layout.addWidget(self.suggestions_group)
        self.suggestions_group.hide()

        self.notes_label = QLabel("", self)
        self.notes_label.setWordWrap(True)
        layout.addWidget(self.notes_label)

        self.copy_button = QPushButton("Copy SELECT script", self)
        layout.addWidget(self.copy_button)

        self.log = LogView(self)
        layout.addWidget(self.log, 1)

        self.inspect_button.clicked.connect(self._inspect)
        self.copy_button.clicked.connect(self._copy_select_script)

    def _inspect(self) -> None:
        session = self.main_window.session
        if session is None or self._running:
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
        runner.step.connect(self._on_step)
        runner.completed.connect(self._on_completed)
        runner.failed.connect(self._on_failed)
        self._runner = runner
        self._set_running(True)
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
        if not isinstance(result, CardProfile):
            self.log.log_message("! Inspection returned an unexpected result.", "error")
            return
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
        self._update_state()
        if session is None:
            self.log.log_message("Card session closed.", "info")

    def _update_state(self) -> None:
        session_ready = self.main_window.session is not None
        self.inspect_button.setEnabled(session_ready and not self._running)
        self.copy_button.setEnabled(bool(self._apps))

    def _status(self, message: str, timeout: int = 0) -> None:
        if hasattr(self.main_window, "statusBar"):
            self.main_window.statusBar().showMessage(message, timeout)
