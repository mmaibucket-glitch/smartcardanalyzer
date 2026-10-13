"""Guided APDU builder with plain-language presets for card beginners."""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import QRegularExpression, Qt, Signal
from PySide6.QtGui import QRegularExpressionValidator
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from app.core import apdu

ERROR_STYLE = "color: #c0392b;"
OK_STYLE = "color: #27ae60;"
HINT_STYLE = "color: #7f8c8d;"

PRESETS: list[dict[str, object]] = [
    {
        "name": "Custom",
        "cla": 0x00,
        "ins": 0x00,
        "p1": 0x00,
        "p2": 0x00,
        "hint": (
            "Build any command yourself: CLA, INS, P1, P2 as two hex digits each, "
            "then optional Data (hex bytes) and Le."
        ),
    },
    {
        "name": "SELECT FILE (A4)",
        "cla": 0x00,
        "ins": 0xA4,
        "p1": 0x00,
        "p2": 0x00,
        "hint": (
            "P1 04 = select by name (AID), 02 = select an EF under the current DF, "
            "00 = select MF/DF by file ID. Put the AID or file ID bytes in Data."
        ),
    },
    {
        "name": "READ BINARY (B0)",
        "cla": 0x00,
        "ins": 0xB0,
        "p1": 0x00,
        "p2": 0x00,
        "hint": (
            "P1P2 = byte offset in the selected file. "
            "Le = how many bytes to read (00 means 256)."
        ),
    },
    {
        "name": "READ RECORD (B2)",
        "cla": 0x00,
        "ins": 0xB2,
        "p1": 0x01,
        "p2": 0x04,
        "hint": (
            "P1 = record number; P2 low bits select the short file (SFI), "
            "04 = read one record. Le = length (00 = 256)."
        ),
    },
    {
        "name": "GET RESPONSE (C0)",
        "cla": 0x00,
        "ins": 0xC0,
        "p1": 0x00,
        "p2": 0x00,
        "hint": (
            "Le = how many bytes the card still owes you after a 61XX "
            "'more data' status (00 = 256)."
        ),
    },
    {
        "name": "GET DATA (CA)",
        "cla": 0x00,
        "ins": 0xCA,
        "p1": 0x00,
        "p2": 0x6F,
        "hint": (
            "P1P2 = the tag to read, e.g. 00 6F = file control info, "
            "9F 36 = application transaction counter on payment cards. "
            "Le 00 = maximum."
        ),
    },
    {
        "name": "VERIFY (20)",
        "cla": 0x00,
        "ins": 0x20,
        "p1": 0x00,
        "p2": 0x81,
        "hint": (
            "P2 81 = first PIN. Data = PIN block (often 8 bytes, e.g. ASCII "
            "digits padded with FF). Wrong attempts count down 63CX - too many "
            "can block the card."
        ),
    },
    {
        "name": "INTERNAL AUTHENTICATE (88)",
        "cla": 0x00,
        "ins": 0x88,
        "p1": 0x00,
        "p2": 0x00,
        "hint": (
            "Data = challenge (usually 8 bytes). The card returns a cryptogram "
            "computed with an internal key."
        ),
    },
    {
        "name": "GET CHALLENGE (84)",
        "cla": 0x00,
        "ins": 0x84,
        "p1": 0x00,
        "p2": 0x00,
        "le": 8,
        "hint": "Returns Le random bytes from the card (usually 8).",
    },
]


def assemble_apdu(
    cla: int,
    ins: int,
    p1: int,
    p2: int,
    data: bytes = b"",
    le: Optional[int] = None,
) -> bytes:
    """Assemble a command APDU; raise ValueError for out-of-range fields."""
    for label, value in (("CLA", cla), ("INS", ins), ("P1", p1), ("P2", p2)):
        if not 0 <= value <= 255:
            raise ValueError(f"{label} must be between 0 and 255, got {value}.")
    if le is not None and not 0 <= le <= 255:
        raise ValueError(f"Le must be between 0 and 255, got {le}.")
    if len(data) > 255:
        raise ValueError(
            f"Data is {len(data)} bytes long; at most 255 bytes fit in one APDU."
        )
    header = bytes([cla, ins, p1, p2])
    if data and le is not None:
        return header + bytes([len(data)]) + data + bytes([le])
    if data:
        return header + bytes([len(data)]) + data
    if le is not None:
        return header + bytes([le])
    return header


class GuidedApduBuilder(QWidget):
    """Form that assembles a command APDU and emits apdu_ready(bytes)."""

    apdu_ready = Signal(bytes)

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._build_ui()
        self._apply_preset(0)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        preset_row = QHBoxLayout()
        preset_row.addWidget(QLabel("Preset", self))
        self.preset_combo = QComboBox(self)
        for preset in PRESETS:
            self.preset_combo.addItem(str(preset["name"]))
        preset_row.addWidget(self.preset_combo, 1)
        layout.addLayout(preset_row)

        header_row = QHBoxLayout()
        header_row.addWidget(QLabel("CLA", self))
        self.cla_edit = self._make_hex_edit()
        header_row.addWidget(self.cla_edit)
        header_row.addWidget(QLabel("INS", self))
        self.ins_edit = self._make_hex_edit()
        header_row.addWidget(self.ins_edit)
        header_row.addWidget(QLabel("P1", self))
        self.p1_edit = self._make_hex_edit()
        header_row.addWidget(self.p1_edit)
        header_row.addWidget(QLabel("P2", self))
        self.p2_edit = self._make_hex_edit()
        header_row.addWidget(self.p2_edit)
        header_row.addWidget(QLabel("Le", self))
        self.le_spin = QSpinBox(self)
        self.le_spin.setRange(-1, 255)
        self.le_spin.setValue(-1)
        self.le_spin.setSpecialValueText("none")
        self.le_spin.setToolTip("00 requests 256 bytes")
        header_row.addWidget(self.le_spin)
        header_row.addStretch(1)
        layout.addLayout(header_row)

        data_row = QHBoxLayout()
        data_row.addWidget(QLabel("Data", self))
        self.data_edit = QLineEdit(self)
        self.data_edit.setPlaceholderText("hex bytes, e.g. A0 00 00 00 04 10 10")
        self.ascii_check = QCheckBox("data is ASCII text", self)
        data_row.addWidget(self.data_edit, 1)
        data_row.addWidget(self.ascii_check)
        layout.addLayout(data_row)

        self.hint_label = QLabel("", self)
        self.hint_label.setWordWrap(True)
        self.hint_label.setStyleSheet(HINT_STYLE)
        layout.addWidget(self.hint_label)

        action_row = QHBoxLayout()
        self.build_button = QPushButton("Build", self)
        self.status_label = QLabel("", self)
        action_row.addWidget(self.build_button)
        action_row.addWidget(self.status_label, 1)
        layout.addLayout(action_row)

        self.preset_combo.currentIndexChanged.connect(self._apply_preset)
        self.ascii_check.toggled.connect(self._on_ascii_toggled)
        self.build_button.clicked.connect(self._on_build)

    def _apply_preset(self, index: int) -> None:
        preset = PRESETS[index]
        self.cla_edit.setText(f"{preset['cla']:02X}")
        self.ins_edit.setText(f"{preset['ins']:02X}")
        self.p1_edit.setText(f"{preset['p1']:02X}")
        self.p2_edit.setText(f"{preset['p2']:02X}")
        le = preset.get("le")
        self.le_spin.setValue(int(le) if le is not None else -1)
        self.data_edit.clear()
        self.ascii_check.setChecked(False)
        self.hint_label.setText(str(preset["hint"]))
        self.status_label.clear()

    def _make_hex_edit(self) -> QLineEdit:
        edit = QLineEdit(self)
        edit.setMaxLength(2)
        edit.setMaximumWidth(56)
        edit.setAlignment(Qt.AlignCenter)
        edit.setValidator(
            QRegularExpressionValidator(QRegularExpression("[0-9a-fA-F]{0,2}"), self)
        )
        return edit

    def _on_ascii_toggled(self, checked: bool) -> None:
        if checked:
            self.data_edit.setPlaceholderText("plain text, e.g. 1234")
        else:
            self.data_edit.setPlaceholderText("hex bytes, e.g. A0 00 00 00 04 10 10")

    def _on_build(self) -> None:
        try:
            built = assemble_apdu(
                self._parse_byte_field(self.cla_edit, "CLA"),
                self._parse_byte_field(self.ins_edit, "INS"),
                self._parse_byte_field(self.p1_edit, "P1"),
                self._parse_byte_field(self.p2_edit, "P2"),
                self._collect_data(),
                self._collect_le(),
            )
        except ValueError as exc:
            self.status_label.setStyleSheet(ERROR_STYLE)
            self.status_label.setText(str(exc))
            return
        self.status_label.setStyleSheet(OK_STYLE)
        self.status_label.setText(f"{len(built)} bytes ready - press Send")
        self.apdu_ready.emit(built)

    def _parse_byte_field(self, field: QLineEdit, label: str) -> int:
        text = field.text().strip()
        if not text:
            raise ValueError(f"{label} needs one or two hex digits (e.g. A4).")
        try:
            return int(text, 16)
        except ValueError:
            raise ValueError(f"{label} must be hex digits (0-9, A-F).") from None

    def _collect_data(self) -> bytes:
        text = self.data_edit.text()
        if self.ascii_check.isChecked():
            try:
                return text.encode("ascii")
            except UnicodeEncodeError:
                raise ValueError(
                    "Data has non-ASCII characters; untick 'data is ASCII text' "
                    "or use plain ASCII text."
                ) from None
        if not text.strip():
            return b""
        try:
            return apdu.parse_hex(text)
        except ValueError as exc:
            raise ValueError(f"Data: {exc}") from None

    def _collect_le(self) -> Optional[int]:
        value = self.le_spin.value()
        return value if value >= 0 else None
