"""Fuzzing tab: mutation and protocol-aware APDU fuzzing against the card."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from PySide6.QtWidgets import (
    QCheckBox,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from app.core import apdu, fuzz, safety
from app.gui import workers
from app.gui.logview import LogView

if TYPE_CHECKING:
    from app.gui.main_window import MainWindow

SEED_PLACEHOLDER = "Seed APDU in hex, e.g. 00 A4 04 00 07 A0 00 00 00 04 10 10"
SEED_IGNORED_PLACEHOLDER = "Ignored in protocol-aware mode."
SAFE_MODE_ON_MESSAGE = "Safe mode on - card-modifying cases are skipped"
SAFE_MODE_OFF_MESSAGE = "Safe mode off - all known instructions may be sent"


class FuzzTab(QWidget):
    """Tab for running mutation and protocol-aware fuzzing against the card."""

    def __init__(self, main_window: MainWindow) -> None:
        super().__init__()
        self.main_window = main_window
        self._runner: workers.Runner | None = None
        self._running = False
        self._stride = 1
        self._syncing_safe_mode = False
        self._build_ui()
        main_window.session_changed.connect(self._on_session_changed)
        main_window.safety_changed.connect(self._on_safety_changed)
        self._update_run_state()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        config_group = QGroupBox("Configuration", self)
        form = QFormLayout(config_group)
        self.seed_input = QLineEdit(config_group)
        self.seed_input.setPlaceholderText(SEED_PLACEHOLDER)
        self.iterations_spin = QSpinBox(config_group)
        self.iterations_spin.setRange(1, 100000)
        self.iterations_spin.setValue(100)
        self.seed_spin = QSpinBox(config_group)
        self.seed_spin.setRange(0, 2147483647)
        self.seed_spin.setValue(0)
        self.seed_spin.setToolTip("The same seed reproduces the same fuzzing cases.")
        self.delay_spin = QSpinBox(config_group)
        self.delay_spin.setRange(0, 5000)
        self.delay_spin.setValue(50)
        self.delay_spin.setSuffix(" ms")
        form.addRow("Seed APDU", self.seed_input)
        self.protocol_aware_check = QCheckBox(
            "Protocol-aware (generate valid commands)", config_group
        )
        self.protocol_aware_check.setToolTip(
            "Generate well-formed commands from known instruction codes instead of "
            "mutating the seed APDU. The seed field is ignored in this mode."
        )
        self.protocol_aware_check.toggled.connect(self._on_protocol_aware_toggled)
        form.addRow(self.protocol_aware_check)
        form.addRow("Iterations", self.iterations_spin)
        form.addRow("RNG seed", self.seed_spin)
        form.addRow("Delay", self.delay_spin)
        layout.addWidget(config_group)

        strategies_group = QGroupBox("Strategies", self)
        strategies_group.setToolTip(
            "Used in mutation mode; protocol-aware mode generates its own commands."
        )
        grid = QGridLayout(strategies_group)
        self._strategy_checks: dict[str, QCheckBox] = {}
        for position, name in enumerate(fuzz.STRATEGIES):
            check = QCheckBox(name, strategies_group)
            check.setChecked(True)
            self._strategy_checks[name] = check
            grid.addWidget(check, position // 3, position % 3)
        layout.addWidget(strategies_group)

        self.warning_label = QLabel(
            "Sends malformed APDUs to the real card - may modify card state", self
        )
        self.warning_label.setStyleSheet("color: #c47f17;")
        layout.addWidget(self.warning_label)
        self.safe_mode_check = QCheckBox("Safe mode", self)
        self.safe_mode_check.setChecked(
            bool(getattr(self.main_window, "safe_mode", True))
        )
        self.safe_mode_check.setToolTip(
            "Restrict fuzzing to read-only commands so nothing on the card can be "
            "modified."
        )
        self.safe_mode_check.toggled.connect(self._on_safe_mode_toggled)
        layout.addWidget(self.safe_mode_check)
        self.restriction_label = QLabel(
            self._restriction_text(self.main_window.safe_mode), self
        )
        layout.addWidget(self.restriction_label)

        buttons = QHBoxLayout()
        self.start_button = QPushButton("Start", self)
        self.stop_button = QPushButton("Stop", self)
        buttons.addWidget(self.start_button)
        buttons.addWidget(self.stop_button)
        buttons.addStretch(1)
        layout.addLayout(buttons)

        self.log = LogView(self)
        layout.addWidget(self.log, 1)

        self.start_button.clicked.connect(self._start)
        self.stop_button.clicked.connect(self._stop)

    def _start(self) -> None:
        session = self.main_window.session
        if session is None:
            self._status("Connect to a reader first.", 3000)
            return
        if self._running:
            self._status("Fuzzing is already running.", 3000)
            return
        protocol_aware = self.protocol_aware_check.isChecked()
        seed_apdu = b""
        if not protocol_aware:
            seed_text = self.seed_input.text().strip()
            if not seed_text:
                self._status("A seed APDU is required in mutation mode.", 3000)
                self.log.log_message(
                    "! A seed APDU is required in mutation mode.", "error"
                )
                return
            try:
                seed_apdu = apdu.parse_hex(seed_text)
            except ValueError as exc:
                self._status(str(exc), 3000)
                self.log.log_message(f"! Invalid seed APDU: {exc}", "error")
                return
        strategies = [
            name for name, check in self._strategy_checks.items() if check.isChecked()
        ]
        if self.main_window.safe_mode:
            ins_pool = list(fuzz.READ_ONLY_INS_POOL)
            self.log.log_message(
                "Safe mode: fuzzing restricted to read-only commands", "info"
            )
        else:
            ins_pool = sorted(safety.INSTRUCTION_NAMES)
            self.log.log_message(
                "Safe mode is OFF: fuzzing may send card-modifying commands", "sw"
            )
        config = fuzz.FuzzConfig(
            seed_apdu=seed_apdu,
            iterations=self.iterations_spin.value(),
            strategies=strategies,
            seed=self.seed_spin.value(),
            protocol_aware=protocol_aware,
            ins_pool=ins_pool,
        )
        delay_ms = self.delay_spin.value()
        self._stride = 1 if config.iterations <= 500 else max(1, config.iterations // 500)
        if protocol_aware:
            pool_text = " ".join(f"{ins:02X}" for ins in config.ins_pool)
            self.log.log_message(
                f"Fuzzing {config.iterations} protocol-aware case(s) (RNG seed "
                f"{config.seed}, instructions: {pool_text}).",
                "info",
            )
        else:
            self.log.log_message(
                f"Fuzzing {config.iterations} case(s) from seed {apdu.format_hex(seed_apdu)} "
                f"(RNG seed {config.seed}, strategies: {', '.join(strategies) or 'none'}).",
                "info",
            )

        def run(emit: Callable[..., None], should_stop: Callable[[], bool]) -> dict[str, object]:
            def publish(*args: object) -> None:
                emit(args)

            return fuzz.run_fuzz(
                session,
                config,
                emit=publish,
                should_stop=should_stop,
                delay_ms=delay_ms,
                safe_mode=self.main_window.safe_mode,
            )

        self._runner = workers.Runner(run, self)
        self._runner.step.connect(self._on_step)
        self._runner.completed.connect(self._on_completed)
        self._runner.failed.connect(self._on_failed)
        self._running = True
        self._update_run_state()
        self._runner.start()

    def _stop(self) -> None:
        if self._running and self._runner is not None:
            self._runner.stop()

    def _on_step(self, event: object) -> None:
        if not isinstance(event, tuple) or not event:
            return
        kind = event[0]
        if kind == "case":
            _, index, total, tx_hex, sw, description = event
            if index % self._stride == 0:
                self.log.log_message(
                    f"[{index + 1}/{total}] > {tx_hex}  SW {sw} - {description}", "info"
                )
        elif kind == "skipped":
            _, index, total, tx_hex = event
            if index % self._stride == 0:
                self.log.log_message(
                    f"[{index + 1}/{total}] SKIPPED (safe mode) > {tx_hex}", "sw"
                )
        elif kind == "notable":
            _, index, tx_hex, sw, description = event
            self.log.log_message(
                f"[{index + 1}] NOTABLE > {tx_hex}  SW {sw} - {description}", "sw"
            )
        elif kind == "error":
            self.log.log_message(f"! {event[1]}", "error")

    def _on_completed(self, result: object) -> None:
        data = result if isinstance(result, dict) else {}
        sent = data.get("sent", 0)
        skipped = data.get("skipped", 0)
        sw_counts: dict[str, int] = data.get("sw_counts", {})
        notable = data.get("notable", [])
        stopped = bool(data.get("stopped", False))
        skipped_suffix = f", {skipped} case(s) skipped by safe mode" if skipped else ""
        self.log.log_message(
            f"Fuzzing {'stopped' if stopped else 'finished'}: {sent} case(s) sent, "
            f"{len(sw_counts)} unique SW(s), {len(notable)} notable{skipped_suffix}.",
            "info",
        )
        counts = sorted(sw_counts.items(), key=lambda item: (-item[1], item[0]))
        if counts:
            self.log.log_message(
                "SW counts: " + ", ".join(f"{sw} x{count}" for sw, count in counts),
                "info",
            )
        self._finish_run()

    def _on_failed(self, message: str) -> None:
        self.log.log_message(f"! Fuzzing failed: {message}", "error")
        self._finish_run()

    def _finish_run(self) -> None:
        self._running = False
        self._update_run_state()

    def _on_session_changed(self, session: object) -> None:
        self._update_run_state()

    def _on_protocol_aware_toggled(self, checked: bool) -> None:
        self.seed_input.setEnabled(not checked)
        if checked:
            self.seed_input.setPlaceholderText(SEED_IGNORED_PLACEHOLDER)
            self.seed_input.setToolTip("The seed APDU is ignored in protocol-aware mode.")
        else:
            self.seed_input.setPlaceholderText(SEED_PLACEHOLDER)
            self.seed_input.setToolTip("")

    def _on_safe_mode_toggled(self, checked: bool) -> None:
        if self._syncing_safe_mode:
            return
        self.main_window.set_safe_mode(checked)
        self.restriction_label.setText(self._restriction_text(checked))
        self.log.log_message(
            SAFE_MODE_ON_MESSAGE if checked else SAFE_MODE_OFF_MESSAGE, "info"
        )

    def _on_safety_changed(self, safe_mode: bool) -> None:
        self._syncing_safe_mode = True
        self.safe_mode_check.setChecked(safe_mode)
        self._syncing_safe_mode = False
        self.restriction_label.setText(self._restriction_text(safe_mode))

    def _restriction_text(self, safe_mode: bool) -> str:
        if safe_mode:
            return "Safe mode: card-modifying cases are skipped"
        return "Safe mode off: all known instructions"

    def _update_run_state(self) -> None:
        ready = self.main_window.session is not None and not self._running
        self.start_button.setEnabled(ready)
        self.stop_button.setEnabled(self._running)

    def _status(self, message: str, timeout: int = 0) -> None:
        if hasattr(self.main_window, "statusBar"):
            self.main_window.statusBar().showMessage(message, timeout)
