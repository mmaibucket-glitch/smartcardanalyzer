"""Modal dialog that decodes a response as BER-TLV into a browsable tree."""

from __future__ import annotations

from typing import Optional

from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QLabel,
    QPlainTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.core import apdu, tlv

NOT_TLV_MESSAGE = (
    "Nothing could be decoded as TLV - this response is probably not TLV-encoded."
)
NO_DATA_MESSAGE = "(no response data)"
DEFAULT_TITLE = "Decode response as TLV"

COLUMNS = ["Tag", "Field", "Value (hex)", "ASCII"]
VALUE_COLUMN = 2


def show_tlv_dialog(
    parent: Optional[QWidget], data: bytes, title: str = DEFAULT_TITLE
) -> None:
    """Show *data* decoded as TLV in a modal dialog."""
    dialog = TlvDecodeDialog(parent, data, title)
    dialog.exec()


class TlvDecodeDialog(QDialog):
    """Dialog showing one response as a TLV tree, or explaining why it cannot be."""

    def __init__(
        self,
        parent: Optional[QWidget],
        data: bytes,
        title: str = DEFAULT_TITLE,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumSize(560, 360)
        layout = QVBoxLayout(self)

        nodes = tlv.parse_tlv(bytes(data))
        if nodes:
            tree = QTreeWidget(self)
            tree.setColumnCount(len(COLUMNS))
            tree.setHeaderLabels(COLUMNS)
            for node in nodes:
                tree.addTopLevelItem(_build_item(node))
            tree.expandAll()
            tree.resizeColumnToContents(0)
            tree.resizeColumnToContents(1)
            layout.addWidget(tree)
        else:
            layout.addWidget(QLabel(NOT_TLV_MESSAGE, self))
            layout.addWidget(_build_dump(data))

        buttons = QDialogButtonBox(QDialogButtonBox.Close, self)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


def _build_item(node: tlv.Tlv) -> QTreeWidgetItem:
    item = QTreeWidgetItem(
        [
            _tag_text(node.tag),
            tlv.KNOWN_TAGS.get(node.tag, "-"),
            apdu.format_hex(node.value),
            _ascii_hint(node.value),
        ]
    )
    item.setFont(VALUE_COLUMN, QFontDatabase.systemFont(QFontDatabase.FixedFont))
    for child in node.children:
        item.addChild(_build_item(child))
    return item


def _build_dump(data: bytes) -> QPlainTextEdit:
    dump = QPlainTextEdit(apdu.hexdump(bytes(data)) or NO_DATA_MESSAGE)
    dump.setReadOnly(True)
    dump.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
    return dump


def _tag_text(tag: int) -> str:
    if tag > 0xFFFF:
        return f"{tag:06X}"
    return f"{tag:04X}"


def _ascii_hint(value: bytes) -> str:
    if not value:
        return ""
    if all(0x20 <= byte < 0x7F for byte in value):
        return value.decode("ascii")
    return ""
