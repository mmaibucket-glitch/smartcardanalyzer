"""Color-coded monospace log widget shared by all tabs."""

from __future__ import annotations

import html

from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import QPlainTextEdit

LOG_COLORS = {
    "info": "#7f8c8d",
    "tx": "#2980b9",
    "rx": "#27ae60",
    "sw": "#c47f17",
    "error": "#c0392b",
}


class LogView(QPlainTextEdit):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setReadOnly(True)
        self.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))
        self.setMaximumBlockCount(5000)

    def log_message(self, text: str, kind: str = "info") -> None:
        color = LOG_COLORS.get(kind, "#000000")
        body = html.escape(text).replace("\n", "<br>")
        self.appendHtml(f'<span style="color: {color};">{body}</span>')
