"""Console tab: reader connection, guided APDU building, and response log."""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.core import apdu, diagnose, exchange, pcsc, safety
from app.gui import tlv_view
from app.gui.builder_widget import GuidedApduBuilder
from app.gui.logview import LogView

if TYPE_CHECKING:
    from app.gui.main_window import MainWindow

READER_PLACEHOLDERS = {"No readers found", "PC/SC service unavailable", "pyscard not installed"}
SAFE_MODE_ON_MESSAGE = "Safe mode on - card-modifying commands are blocked"
SAFE_MODE_OFF_MESSAGE = "Safe mode off - card-modifying commands are allowed"


class ConsoleTab(QWidget):
    def __init__(self, main_window: MainWindow) -> None:
        super().__init__()
        self.main_window = main_window
        self._last_response_data: Optional[bytes] = None
        self._build_ui()
        main_window.session_changed.connect(self._on_session_changed)
        main_window.safety_changed.connect(self._on_safety_changed)
        self.refresh_readers()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        reader_group = QGroupBox("Reader", self)
        reader_layout = QHBoxLayout(reader_group)
        self.reader_combo = QComboBox(reader_group)
        self.refresh_button = QPushButton("Refresh", reader_group)
        self.connect_button = QPushButton("Connect", reader_group)
        self.atr_label = QLabel("Not connected", reader_group)
        reader_layout.addWidget(self.reader_combo, 1)
        reader_layout.addWidget(self.refresh_button)
        reader_layout.addWidget(self.connect_button)
        reader_layout.addWidget(self.atr_label)
        layout.addWidget(reader_group)

        command_group = QGroupBox("APDU", self)
        command_outer = QVBoxLayout(command_group)
        command_row = QHBoxLayout()
        self.command_input = QLineEdit(command_group)
        self.command_input.setPlaceholderText(
            "APDU in hex, e.g. 00 A4 04 00 07 A0 00 00 00 04 10 10"
        )
        self.send_button = QPushButton("Send", command_group)
        self.tlv_button = QPushButton("Decode TLV", command_group)
        self.tlv_button.setToolTip(
            "Decode the last response as TLV (works for FCI, EF.DIR, GET DATA responses)"
        )
        command_row.addWidget(self.command_input, 1)
        command_row.addWidget(self.send_button)
        command_row.addWidget(self.tlv_button)
        command_outer.addLayout(command_row)
        options_row = QHBoxLayout()
        self.auto_response_check = QCheckBox(
            "Auto GET RESPONSE / Le retry", command_group
        )
        self.auto_response_check.setChecked(True)
        self.auto_response_check.setToolTip(
            "Automatically chain GET RESPONSE after 61XX 'more data' and resend "
            "once with the correct Le after 6CXX"
        )
        self.safe_mode_check = QCheckBox("Safe mode", command_group)
        self.safe_mode_check.setChecked(
            bool(getattr(self.main_window, "safe_mode", True))
        )
        self.safe_mode_check.setToolTip(
            "Block card-modifying commands (UPDATE BINARY, PUT DATA, ...) so a "
            "mistake cannot change anything on the card."
        )
        options_row.addWidget(self.auto_response_check)
        options_row.addWidget(self.safe_mode_check)
        options_row.addStretch(1)
        command_outer.addLayout(options_row)
        layout.addWidget(command_group)

        self.pin_banner = QLabel("", self)
        self.pin_banner.setStyleSheet("font-weight: bold; color: #c0392b;")
        self.pin_banner.setWordWrap(True)
        self.pin_banner.hide()
        layout.addWidget(self.pin_banner)

        builder_group = QGroupBox("Guided builder", self)
        builder_layout = QVBoxLayout(builder_group)
        self.builder = GuidedApduBuilder(builder_group)
        builder_layout.addWidget(self.builder)
        layout.addWidget(builder_group)

        self.log = LogView(self)
        layout.addWidget(self.log, 1)

        self.refresh_button.clicked.connect(self.refresh_readers)
        self.connect_button.clicked.connect(self._toggle_connection)
        self.send_button.clicked.connect(self.send_apdu)
        self.tlv_button.clicked.connect(self._on_decode_tlv)
        self.command_input.returnPressed.connect(self.send_apdu)
        self.safe_mode_check.toggled.connect(self._on_safe_mode_toggled)
        self.builder.apdu_ready.connect(self._on_apdu_built)
        self._update_send_state()

    def refresh_readers(self) -> None:
        self.reader_combo.clear()
        status = diagnose.get_reader_status()
        if status == diagnose.STATUS_SERVICE_DOWN:
            self.reader_combo.addItem("PC/SC service unavailable")
            self.reader_combo.setEnabled(False)
            self.log.log_message(diagnose.describe_reader_status(status), "error")
            return
        if status == diagnose.STATUS_NO_READERS:
            self.reader_combo.addItem("No readers found")
            self.reader_combo.setEnabled(False)
            self.log.log_message(diagnose.describe_reader_status(status), "info")
            return
        try:
            reader_names = pcsc.list_readers()
        except Exception as exc:
            reader_names = []
            self.log.log_message(f"! Reader enumeration failed: {exc}", "error")
        if reader_names:
            self.reader_combo.addItems(reader_names)
            self.reader_combo.setEnabled(True)
        else:
            self.reader_combo.addItem("No readers found")
            self.reader_combo.setEnabled(False)

    def _toggle_connection(self) -> None:
        if self.main_window.session is not None:
            self.main_window.disconnect_card()
        else:
            reader_name = self.reader_combo.currentText()
            if reader_name and reader_name not in READER_PLACEHOLDERS:
                self.main_window.connect_reader(reader_name)

    def send_apdu(self) -> None:
        session = self.main_window.session
        if session is None:
            self._status("Connect to a reader first.", 3000)
            return
        text = self.command_input.text().strip()
        if not text:
            return
        try:
            command = apdu.parse_hex(text)
        except ValueError as exc:
            self._status(str(exc), 3000)
            self.log.log_message(f"! Invalid APDU: {exc}", "error")
            return
        reason = safety.blocked_reason(command, self.main_window.safe_mode)
        if reason:
            self.log.log_message(reason, "error")
            self._status("Blocked by safe mode.", 5000)
            return
        if self.auto_response_check.isChecked():
            self._send_with_auto_exchange(session, command)
        else:
            self._send_direct(session, command)

    def _send_direct(self, session: pcsc.CardSession, command: bytes) -> None:
        self.log.log_message(f"> {apdu.format_hex(command)}", "tx")
        try:
            data, sw1, sw2 = session.transmit(command)
        except pcsc.PcscError as exc:
            self.log.log_message(f"! {diagnose.translate_error(str(exc))}", "error")
            self._status("Transmit failed.", 3000)
            return
        self._log_response(data, sw1, sw2)

    def _send_with_auto_exchange(
        self, session: pcsc.CardSession, command: bytes
    ) -> None:
        state = {"initial": True}

        def on_step(sent: bytes, data: bytes, sw1: int, sw2: int) -> None:
            if state["initial"]:
                state["initial"] = False
                self.log.log_message(f"> {apdu.format_hex(command)}", "tx")
            elif len(sent) == 5 and sent[:4] == b"\x00\xc0\x00\x00":
                self.log.log_message(f"auto > {apdu.format_hex(sent)}", "tx")
            else:
                self.log.log_message(f"auto > {apdu.format_hex(sent)} (Le retry)", "tx")

        try:
            result = exchange.transmit_smart(session, command, on_step=on_step)
        except pcsc.PcscError as exc:
            self.log.log_message(f"! {diagnose.translate_error(str(exc))}", "error")
            self._status("Transmit failed.", 3000)
            return
        if result.followed_up:
            self.log.log_message(
                f"Automatically fetched {len(result.exchanges) - 1} extra response(s)",
                "info",
            )
        self._log_response(result.data, result.sw1, result.sw2)

    def _log_response(self, data: bytes, sw1: int, sw2: int) -> None:
        if len(data) > 32:
            self.log.log_message(apdu.hexdump(data), "rx")
        elif data:
            self.log.log_message(f"< {apdu.format_hex(data)}", "rx")
        if data:
            self._last_response_data = data
            self._update_send_state()
        self.log.log_message(
            f"< SW {sw1:02X} {sw2:02X} - {apdu.describe_sw(sw1, sw2)}", "sw"
        )
        self._status(f"{sw1:02X}{sw2:02X} - {apdu.describe_sw(sw1, sw2)}")
        self._update_pin_banner(sw1, sw2)

    def _on_decode_tlv(self) -> None:
        data = self._last_response_data
        if data is None:
            return
        self.log.log_message(f"Decoded {len(data)} byte(s) as TLV", "info")
        tlv_view.show_tlv_dialog(self, data)

    def _update_pin_banner(self, sw1: int, sw2: int) -> None:
        if sw1 == 0x63 and 0xC0 <= sw2 <= 0xCF:
            remaining = sw2 & 0x0F
            if remaining == 0:
                self.pin_banner.setText(
                    "Verification failed - no attempts remaining, the card may be blocked"
                )
            else:
                self.pin_banner.setText(
                    f"Verification failed - {remaining} attempt(s) remaining"
                )
            self.pin_banner.show()
        else:
            self.pin_banner.hide()

    def _on_safe_mode_toggled(self, checked: bool) -> None:
        self.main_window.set_safe_mode(checked)
        self.log.log_message(
            SAFE_MODE_ON_MESSAGE if checked else SAFE_MODE_OFF_MESSAGE, "info"
        )

    def _on_safety_changed(self, enabled: bool) -> None:
        self.safe_mode_check.setChecked(enabled)

    def _on_apdu_built(self, built: bytes) -> None:
        self.command_input.setText(apdu.format_hex(built))
        self.command_input.setFocus()
        self._status("APDU built - press Send")

    def _on_session_changed(self, session: Optional[pcsc.CardSession]) -> None:
        self._last_response_data = None
        if session is None:
            self.atr_label.setText("Not connected")
            self.connect_button.setText("Connect")
        else:
            self.atr_label.setText(f"ATR: {apdu.format_hex(session.atr)}")
            self.connect_button.setText("Disconnect")
        self._update_send_state()

    def _update_send_state(self) -> None:
        ready = self.main_window.session is not None
        self.send_button.setEnabled(ready)
        self.command_input.setEnabled(ready)
        self.tlv_button.setEnabled(ready and self._last_response_data is not None)

    def _status(self, message: str, timeout: int = 0) -> None:
        if hasattr(self.main_window, "statusBar"):
            self.main_window.statusBar().showMessage(message, timeout)
