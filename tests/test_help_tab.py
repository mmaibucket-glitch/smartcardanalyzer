"""Tests for the Help tab content and the Fuzz tab safe-mode toggle."""

from __future__ import annotations

from PySide6.QtCore import QObject, Signal

from app.core.apdu import STATUS_WORDS
from app.gui.fuzz_tab import FuzzTab
from app.gui.help_tab import HelpTab, build_sw_rows, filter_rows


class FakeWindow(QObject):
    """Minimal main-window stand-in: signals, safe mode, and call recording."""

    session_changed = Signal(object)
    safety_changed = Signal(bool)

    def __init__(self) -> None:
        super().__init__()
        self.session = None
        self.safe_mode = True
        self.set_calls: list[bool] = []

    def set_safe_mode(self, enabled: bool) -> None:
        self.set_calls.append(enabled)
        if enabled == self.safe_mode:
            return
        self.safe_mode = enabled
        self.safety_changed.emit(enabled)


def test_build_sw_rows_includes_patterns_and_all_status_words() -> None:
    rows = build_sw_rows()
    assert len(rows) == len(STATUS_WORDS) + 3
    assert [sw for sw, _ in rows[:3]] == ["61XX", "63CX", "6CXX"]
    for sw, meaning in STATUS_WORDS.items():
        assert (sw, meaning) in rows
    assert all(meaning for _, meaning in rows)


def test_filter_rows_matches_sw_case_insensitively() -> None:
    rows = build_sw_rows()
    assert [sw for sw, _ in filter_rows(rows, "61xx")] == ["61XX"]
    assert [sw for sw, _ in filter_rows(rows, "6a82")] == ["6A82"]
    assert [sw for sw, _ in filter_rows(rows, "6A82")] == ["6A82"]


def test_filter_rows_matches_meaning_text() -> None:
    rows = build_sw_rows()
    matched = filter_rows(rows, "not found")
    assert ("6A82", STATUS_WORDS["6A82"]) in matched


def test_filter_rows_empty_query_returns_all() -> None:
    rows = build_sw_rows()
    assert filter_rows(rows, "") == rows
    assert filter_rows(rows, "   ") == rows
    assert filter_rows(rows, "no such status") == []


def test_tabs_offscreen(monkeypatch) -> None:
    """Instantiate both tabs offscreen and exercise the fuzz safe-mode toggle."""
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    QApplication.instance() or QApplication([])

    window = FakeWindow()
    HelpTab(window)
    bare = HelpTab(object())
    assert bare.main_window is not None

    fuzz_tab = FuzzTab(window)
    assert fuzz_tab.safe_mode_check.isChecked() is True
    assert fuzz_tab.restriction_label.text() == "Safe mode: card-modifying cases are skipped"

    fuzz_tab.safe_mode_check.setChecked(False)
    assert window.safe_mode is False
    assert window.set_calls == [False]
    assert fuzz_tab.safe_mode_check.isChecked() is False
    assert fuzz_tab.restriction_label.text() == "Safe mode off: all known instructions"
    assert "Safe mode off - all known instructions may be sent" in (
        fuzz_tab.log.toPlainText()
    )

    window.set_safe_mode(True)
    assert window.safe_mode is True
    assert window.set_calls == [False, True]
    assert fuzz_tab.safe_mode_check.isChecked() is True
    assert fuzz_tab.restriction_label.text() == "Safe mode: card-modifying cases are skipped"

    window.safety_changed.emit(False)
    assert window.safe_mode is True
    assert fuzz_tab.safe_mode_check.isChecked() is False
    assert window.set_calls == [False, True]

    print("Help+Fuzz tabs OK")
