"""Scripting tab: edit and run gscriptor-style APDU scripts, with a library panel."""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Optional

from PySide6.QtCore import QObject, Qt
from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from app.core import library, safety, script
from app.gui.logview import LogView
from app.gui.workers import Runner

FILE_FILTER = "Smartcard scripts (*.gscl);;All files (*)"
EDITOR_PLACEHOLDER = (
    "One APDU per line, in hex.\n"
    "Lines starting with '#' are comments; inline '# comment' is allowed too.\n"
    "00 A4 00 00 02 3F 00  # select the master file (MF)"
)


class ScriptTab(QWidget):
    """Editor, bundled script library, and runner controls for APDU scripts."""

    def __init__(self, main_window: QObject) -> None:
        super().__init__()
        self.main_window = main_window
        self._runner: Optional[Runner] = None
        self._running = False
        self._build_ui()
        self._populate_library()
        main_window.session_changed.connect(self._on_session_changed)
        self._update_run_state()

    def _build_ui(self) -> None:
        root_layout = QVBoxLayout(self)

        top_layout = QHBoxLayout()
        top_layout.addWidget(self._build_editor_panel(), 3)
        top_layout.addWidget(self._build_library_panel(), 1)
        root_layout.addLayout(top_layout, 2)

        controls_layout = QHBoxLayout()
        self.run_button = QPushButton("Run", self)
        self.stop_button = QPushButton("Stop", self)
        self.delay_spin = QSpinBox(self)
        self.delay_spin.setRange(0, 5000)
        self.delay_spin.setValue(0)
        self.delay_spin.setSuffix(" ms")
        self.delay_spin.setToolTip("Pause between steps, in milliseconds.")
        self.stop_on_error_check = QCheckBox("Stop on error (SW != 9000)", self)
        controls_layout.addWidget(self.run_button)
        controls_layout.addWidget(self.stop_button)
        controls_layout.addWidget(QLabel("Delay:", self))
        controls_layout.addWidget(self.delay_spin)
        controls_layout.addWidget(self.stop_on_error_check)
        controls_layout.addStretch(1)
        root_layout.addLayout(controls_layout)

        self.log = LogView(self)
        root_layout.addWidget(self.log, 3)

        self.run_button.clicked.connect(self._run)
        self.stop_button.clicked.connect(self._stop_run)

    def _build_editor_panel(self) -> QGroupBox:
        editor_group = QGroupBox("Script", self)
        editor_layout = QVBoxLayout(editor_group)
        toolbar_layout = QHBoxLayout()
        open_button = QPushButton("Open...", editor_group)
        save_button = QPushButton("Save...", editor_group)
        toolbar_layout.addWidget(open_button)
        toolbar_layout.addWidget(save_button)
        toolbar_layout.addStretch(1)
        editor_layout.addLayout(toolbar_layout)
        self.editor = QPlainTextEdit(editor_group)
        self.editor.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        self.editor.setPlaceholderText(EDITOR_PLACEHOLDER)
        editor_layout.addWidget(self.editor, 1)
        open_button.clicked.connect(self._open_script)
        save_button.clicked.connect(self._save_script)
        return editor_group

    def _build_library_panel(self) -> QGroupBox:
        library_group = QGroupBox("Library", self)
        library_layout = QVBoxLayout(library_group)
        self.library_list = QListWidget(library_group)
        self.library_list.setToolTip("Bundled scripts. Double-click or use Load to edit one.")
        library_layout.addWidget(self.library_list, 1)
        load_button = QPushButton("Load", library_group)
        library_layout.addWidget(load_button)
        load_button.clicked.connect(self._load_selected)
        self.library_list.itemDoubleClicked.connect(self._load_item)
        return library_group

    def _populate_library(self) -> None:
        current_category: Optional[str] = None
        for meta in library.list_scripts():
            if meta.category != current_category:
                current_category = meta.category
                header = QListWidgetItem(meta.category.capitalize(), self.library_list)
                header.setFlags(Qt.ItemFlag.NoItemFlags)
            item = QListWidgetItem(f"{meta.name} — {meta.description}", self.library_list)
            item.setToolTip(meta.description)
            item.setData(Qt.ItemDataRole.UserRole, meta.name)

    def _open_script(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Open script", "", FILE_FILTER)
        if not path:
            return
        try:
            text = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            self.log.log_message(f"! Could not open '{path}': {exc}", "error")
            return
        self.editor.setPlainText(text)
        self._status(f"Opened {path}")

    def _save_script(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Save script", "", FILE_FILTER)
        if not path:
            return
        if not Path(path).suffix:
            path = str(Path(path).with_suffix(".gscl"))
        try:
            Path(path).write_text(self.editor.toPlainText(), encoding="utf-8")
        except OSError as exc:
            self.log.log_message(f"! Could not save '{path}': {exc}", "error")
            return
        self._status(f"Saved {path}")

    def _load_selected(self) -> None:
        self._load_item(self.library_list.currentItem())

    def _load_item(self, item: QListWidgetItem) -> None:
        name = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
        if not isinstance(name, str):
            return
        try:
            text = library.load_script_text(name)
        except (FileNotFoundError, OSError) as exc:
            self.log.log_message(f"! Could not load '{name}': {exc}", "error")
            return
        self.editor.setPlainText(text)
        self._status(f"Loaded library script '{name}'.")

    def _run(self) -> None:
        session = self.main_window.session
        if session is None:
            self._status("Connect to a reader first.", 3000)
            self.log.log_message("! Connect to a reader before running a script.", "error")
            return
        try:
            steps = script.parse_script(self.editor.toPlainText())
        except ValueError as exc:
            self.log.log_message(f"! {exc}", "error")
            self._status("Script contains errors.", 3000)
            return
        if self.main_window.safe_mode:
            blocked = self._blocked_write_steps(steps)
            if blocked:
                self.log.log_message(
                    "Safe mode blocked the run - the script contains "
                    "card-modifying commands:",
                    "error",
                )
                for line_no, name in blocked:
                    self.log.log_message(f"line {line_no}: {name}", "error")
                self._status(
                    "Disable safe mode in the Console tab to run this script.", 3000
                )
                return
        if not steps:
            self.log.log_message("! Script has no APDU lines to run.", "error")
            self._status("Script has no APDU lines.", 3000)
            return
        delay_ms = self.delay_spin.value()
        stop_on_error = self.stop_on_error_check.isChecked()

        def work(
            emit: Callable[[tuple], None], should_stop: Callable[[], bool]
        ) -> dict[str, object]:
            return script.run_script(
                session,
                steps,
                emit=emit,
                should_stop=should_stop,
                delay_ms=delay_ms,
                stop_on_error=stop_on_error,
            )

        runner = Runner(work)
        runner.step.connect(self._on_step)
        runner.completed.connect(self._on_completed)
        runner.failed.connect(self._on_failed)
        self._runner = runner
        self._set_running(True)
        self.log.log_message(f"Running script: {len(steps)} step(s)...", "info")
        runner.start()

    def _blocked_write_steps(
        self, steps: list[script.ScriptStep]
    ) -> list[tuple[int, str]]:
        """Return (line number, command name) for steps that modify the card."""
        blocked: list[tuple[int, str]] = []
        for step in steps:
            category, name = safety.classify_apdu(step.apdu)
            if category == "write":
                blocked.append((step.line_no, name))
        return blocked

    def _stop_run(self) -> None:
        if self._runner is not None:
            self._runner.stop()
            self.log.log_message("Stopping after the current step...", "info")

    def _on_step(self, event: object) -> None:
        kind = event[0]
        if kind == "tx":
            _, line_no, hex_text = event
            self.log.log_message(f"line {line_no}: > {hex_text}", "tx")
        elif kind == "rx":
            _, line_no, data_text, sw1, sw2, description = event
            if data_text:
                self.log.log_message(data_text, "rx")
            self.log.log_message(
                f"line {line_no}: < SW {sw1:02X} {sw2:02X} - {description}", "rx"
            )
        elif kind == "abort":
            _, line_no, message = event
            self.log.log_message(f"line {line_no}: {message}", "error")
        elif kind == "error":
            _, line_no, message = event
            self.log.log_message(f"line {line_no}: {message}", "error")

    def _on_completed(self, summary: object) -> None:
        message = (
            f"Script finished: {summary['run']} of {summary['total']} step(s) executed."
        )
        if summary["aborted"]:
            message += " Aborted on a non-9000 status word."
        elif summary["stopped"]:
            message += " Stopped by user."
        self.log.log_message(message, "info")
        sw_counts: dict[str, int] = summary["sw_counts"]
        if sw_counts:
            counts = ", ".join(
                f"SW {key} x{count}" for key, count in sorted(sw_counts.items())
            )
            self.log.log_message(f"Status words: {counts}", "info")
        self._set_running(False)
        self._status("Script finished.")

    def _on_failed(self, message: str) -> None:
        self.log.log_message(f"! Script failed: {message}", "error")
        self._set_running(False)
        self._status("Script failed.", 3000)

    def _set_running(self, running: bool) -> None:
        self._running = running
        self._update_run_state()

    def _on_session_changed(self, session: object) -> None:
        self._update_run_state()
        if session is None:
            self.log.log_message("Card session closed.", "info")

    def _update_run_state(self) -> None:
        session_ready = self.main_window.session is not None
        self.run_button.setEnabled(session_ready and not self._running)
        self.stop_button.setEnabled(self._running)

    def _status(self, message: str, timeout: int = 0) -> None:
        if hasattr(self.main_window, "statusBar"):
            self.main_window.statusBar().showMessage(message, timeout)
