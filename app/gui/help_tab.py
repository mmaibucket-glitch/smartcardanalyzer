"""Getting-started tab: static educational content about smart cards and APDUs."""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHeaderView,
    QLabel,
    QLineEdit,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.core.apdu import STATUS_WORDS

if TYPE_CHECKING:
    from app.gui.main_window import MainWindow

HEADER_STYLE = "font-size: 15px; font-weight: 600;"
BODY_STYLE = "color: #5d6d7e;"
MONO_STYLE = "color: #34495e; background: #f4f6f7; padding: 4px;"

SW_PATTERN_ROWS: list[tuple[str, str]] = [
    (
        "61XX",
        "More data available - XX bytes; the app fetches them automatically "
        "when 'Auto GET RESPONSE' is on",
    ),
    ("63CX", "Verification failed - X attempts remaining"),
    ("6CXX", "Wrong Le - the app retries automatically with the requested Le"),
]

APDU_LAYOUT_ROWS: list[tuple[str, str, str]] = [
    ("CLA", "1 byte", "Instruction class - usually 00"),
    ("INS", "1 byte", "The command, e.g. A4 for SELECT FILE"),
    ("P1", "1 byte", "First command parameter"),
    ("P2", "1 byte", "Second command parameter"),
    ("Lc", "1 byte", "Present only when the command includes data; states its byte length"),
    ("Data", "Lc bytes", "Optional payload the command needs"),
    ("Le", "1 byte", "How many bytes you want back; 00 means 256"),
]

GLOSSARY_ROWS: list[tuple[str, str]] = [
    ("ATR", "Answer To Reset - the byte string a card sends when first powered, "
           "like a hello message that hints what kind of card it is."),
    ("AID", "Application Identifier - a unique 5 to 16 byte name that selects one "
            "application on the card."),
    ("MF", "Master File - the root folder of a classic file-based card."),
    ("DF", "Dedicated File - a folder inside the card's file tree; it can contain "
           "other folders and files."),
    ("EF", "Elementary File - an actual data file, the equivalent of a file on disk."),
    ("SFI", "Short File Identifier - a compact 5-bit file number that lets commands "
            "like READ RECORD reach a file without selecting it first."),
    ("TLV", "Tag-Length-Value - a packing scheme where every item announces what it "
            "is (tag), how long it is (length), then the value itself."),
    ("SW", "Status Word - the two-byte result code every command returns, e.g. 9000 "
           "for OK."),
    ("PIN block", "The fixed-length encoded form of a PIN (digits padded, often with "
                  "FF) that the VERIFY command sends as data."),
    ("GET RESPONSE", "The command (00 C0 00 00 Le) that fetches response data the "
                     "card still holds after a 61XX status."),
    ("PC/SC", "Personal Computer/Smart Card - the operating system service that "
              "gives programs a standard way to talk to card readers."),
    ("pcscd", "The PC/SC daemon on Linux that actually drives the reader hardware; "
              "the tool needs it running to list readers."),
    ("FCI", "File Control Information - the little template of metadata a card "
            "returns when you select a file."),
    ("EF.DIR", "A standard directory file that lists the applications (AIDs) "
               "available on the card."),
]

WALKTHROUGH_STEPS: list[str] = [
    "<b>Console tab</b>: press <b>Refresh</b>, then <b>Connect</b> (a card must be "
    "inserted in the reader). Safe mode is on by default and blocks known "
    "card-modifying instruction codes. Authentication and unknown commands remain "
    "available, so check each command before sending it.",
    "<b>Inspector tab</b>: press <b>Inspect card</b>. The read-only scan shows what "
    "the card is and which applications it carries. Then choose <b>Read accessible "
    "data</b> to view decoded fields and raw responses. Payment applications are "
    "checked for readable records and counters without a PIN or transaction "
    "initialization; other applications show selection metadata. Use <b>Stop</b> "
    "to end the scan. Returned account fields are summarized automatically. "
    "Some data may remain inaccessible.",
    "<b>Script tab</b>: in the Library panel load the bundled <b>read_ef_dir</b> "
    "script, then press <b>Run</b>. Other read-only starters: <b>select_mf</b>, "
    "<b>read_binary</b>, <b>get_data</b>, <b>get_response</b>.",
    "<b>Console tab</b>: pick the <b>GET DATA (CA)</b> preset in the guided builder, "
    "press <b>Build</b>, then <b>Send</b>. Other presets: SELECT FILE (A4), READ "
    "BINARY (B0), READ RECORD (B2), GET RESPONSE (C0), VERIFY (20), INTERNAL "
    "AUTHENTICATE (88), GET CHALLENGE (84).",
    "<b>Fuzz tab</b>: stress-tests a card by sending many commands. Safe mode there "
    "skips known card-modifying instructions. Other commands, including unknown "
    "instructions, can still be sent.",
]


def build_sw_rows() -> list[tuple[str, str]]:
    """Rows for the status-word table: pattern rows first, then STATUS_WORDS."""
    rows = list(SW_PATTERN_ROWS)
    rows.extend(sorted(STATUS_WORDS.items()))
    return rows


def filter_rows(rows: list[tuple[str, str]], query: str) -> list[tuple[str, str]]:
    """Keep rows whose SW or meaning contains the query, case-insensitively."""
    needle = query.strip().lower()
    if not needle:
        return list(rows)
    return [row for row in rows if needle in row[0].lower() or needle in row[1].lower()]


def _header_label(text: str) -> QLabel:
    label = QLabel(text)
    label.setStyleSheet(HEADER_STYLE)
    return label


def _body_label(text: str) -> QLabel:
    label = QLabel(text)
    label.setWordWrap(True)
    label.setStyleSheet(BODY_STYLE)
    return label


def _mono_label(text: str) -> QLabel:
    label = QLabel(text)
    label.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
    label.setStyleSheet(MONO_STYLE)
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return label


def _make_table(headers: list[str]) -> QTableWidget:
    table = QTableWidget(0, len(headers))
    table.setHorizontalHeaderLabels(headers)
    table.verticalHeader().setVisible(False)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
    table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
    header = table.horizontalHeader()
    for column in range(min(len(headers) - 1, 2)):
        header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
    header.setStretchLastSection(True)
    return table


def _fill_table(table: QTableWidget, rows: list[tuple[str, ...]]) -> None:
    table.setRowCount(len(rows))
    for row_index, row in enumerate(rows):
        for column_index, value in enumerate(row):
            table.setItem(row_index, column_index, QTableWidgetItem(value))


class HelpTab(QWidget):
    """Static getting-started guide; needs no card session and never transmits."""

    def __init__(self, main_window: MainWindow) -> None:
        super().__init__()
        self.main_window = main_window
        self._sw_rows = build_sw_rows()
        self._build_ui()

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(14)
        self._add_basics_section(layout)
        self._add_sw_section(layout)
        self._add_glossary_section(layout)
        self._add_walkthrough_section(layout)
        layout.addStretch(1)

        scroll.setWidget(content)
        outer.addWidget(scroll)

    def _add_basics_section(self, layout: QVBoxLayout) -> None:
        layout.addWidget(_header_label("Smart cards in 5 minutes"))
        layout.addWidget(_body_label(
            "A smart card is a tiny computer the size of a credit card. A reader is "
            "the box with a slot: it powers the card and passes messages back and "
            "forth. This tool never talks to the card directly - it uses PC/SC, the "
            "operating system service for smart card readers. On Linux the pcscd "
            "daemon does the actual work; if the Console tab shows no readers, "
            "pcscd is probably not running."
        ))
        layout.addWidget(_body_label(
            "Once connected, everything you exchange is an APDU. A command APDU is a "
            "short byte string you send; the card answers with optional data plus a "
            "two-byte status word. A typical command selects an application by its "
            "AID (SELECT FILE, class 00, instruction A4):"
        ))
        layout.addWidget(_mono_label("00 A4 04 00 07 A0 00 00 00 04 10 10"))
        layout.addWidget(_body_label("Command APDU byte layout:"))
        table = _make_table(["Field", "Size", "Meaning"])
        _fill_table(table, APDU_LAYOUT_ROWS)
        layout.addWidget(table)
        layout.addWidget(_body_label(
            "You do not have to assemble this by hand: the guided builder in the "
            "Console tab fills in every field for you. Pick a preset such as SELECT "
            "FILE (A4) or GET DATA (CA), press Build, then Send."
        ))

    def _add_sw_section(self, layout: QVBoxLayout) -> None:
        layout.addWidget(_header_label("Status word cheat sheet"))
        layout.addWidget(_body_label(
            "Every command ends with a two-byte status word (SW). 9000 means all "
            "went well; the other values tell you what happened or what to do next."
        ))
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter status words...")
        self.filter_input.setClearButtonEnabled(True)
        self.filter_input.textChanged.connect(self._apply_sw_filter)
        layout.addWidget(self.filter_input)
        self.sw_table = _make_table(["SW", "Meaning"])
        self._apply_sw_filter("")
        layout.addWidget(self.sw_table)

    def _add_glossary_section(self, layout: QVBoxLayout) -> None:
        layout.addWidget(_header_label("Glossary"))
        table = _make_table(["Term", "Meaning"])
        _fill_table(table, GLOSSARY_ROWS)
        layout.addWidget(table)

    def _add_walkthrough_section(self, layout: QVBoxLayout) -> None:
        layout.addWidget(_header_label("Try this first"))
        for number, step in enumerate(WALKTHROUGH_STEPS, start=1):
            layout.addWidget(_body_label(f"{number}. {step}"))

    def _apply_sw_filter(self, query: str) -> None:
        _fill_table(self.sw_table, filter_rows(self._sw_rows, query))
