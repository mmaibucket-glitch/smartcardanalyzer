"""Tests for script parsing, script execution, and the bundled script library."""

from __future__ import annotations

from typing import Union

import pytest

from app.core import library, pcsc, script
from app.core.script import ScriptStep, parse_script, run_script

TransmitResult = Union[tuple[bytes, int, int], Exception]


class FakeSession:
    """A card session stand-in that replays canned transmit outcomes."""

    def __init__(self, responses: list[TransmitResult]) -> None:
        self.responses = list(responses)
        self.calls: list[bytes] = []

    def transmit(self, apdu: bytes) -> tuple[bytes, int, int]:
        self.calls.append(apdu)
        outcome = self.responses.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def make_steps(*hex_strings: str) -> list[ScriptStep]:
    return [
        ScriptStep(line_no=index + 1, apdu=bytes.fromhex(hex_text))
        for index, hex_text in enumerate(hex_strings)
    ]


class TestParseScript:
    def test_comments_and_blank_lines_are_skipped(self) -> None:
        text = (
            "# full-line comment\n"
            "\n"
            "   \n"
            "00 A4 00 00 02 3F 00  # inline comment\n"
            "#another comment\n"
            "00 B0 00 00\n"
        )
        steps = parse_script(text)
        assert [step.apdu for step in steps] == [
            bytes.fromhex("00A40000023F00"),
            bytes.fromhex("00B00000"),
        ]
        assert [step.line_no for step in steps] == [4, 6]
        assert steps[0].comment == "inline comment"
        assert steps[1].comment == ""

    def test_multiple_steps_keep_order_and_tolerant_hex(self) -> None:
        text = "00 a4 00 00\n0xA4 00\naa:bb:cc\n"
        steps = parse_script(text)
        assert [step.apdu for step in steps] == [
            bytes.fromhex("00A40000"),
            bytes.fromhex("A400"),
            bytes.fromhex("AABBCC"),
        ]
        assert steps[0].comment == ""

    def test_empty_script_yields_no_steps(self) -> None:
        assert parse_script("") == []
        assert parse_script("# only\n\n# comments\n") == []

    def test_error_message_includes_line_number(self) -> None:
        with pytest.raises(ValueError, match="line 3"):
            parse_script("# header\n00 A4 00 00 02 3F 00\n00 B0 00 0")

    def test_error_message_includes_reason(self) -> None:
        with pytest.raises(ValueError, match="even number of digits"):
            parse_script("00 A4 0")


class TestRunScript:
    def test_all_steps_run_and_sw_counts_accumulate(self) -> None:
        session = FakeSession(
            [
                (bytes.fromhex("3F00"), 0x90, 0x00),
                (b"", 0x61, 0x05),
            ]
        )
        events: list[tuple] = []
        steps = make_steps("00A40000023F00", "00C0000005")

        summary = run_script(
            session, steps, emit=events.append, should_stop=lambda: False
        )

        assert session.calls == [step.apdu for step in steps]
        assert summary["total"] == 2
        assert summary["run"] == 2
        assert summary["sw_counts"] == {"9000": 1, "6105": 1}
        assert summary["stopped"] is False
        assert summary["aborted"] is False
        assert events == [
            ("tx", 1, "00 A4 00 00 02 3F 00"),
            ("rx", 1, "3F 00", 0x90, 0x00, "Normal processing (OK)"),
            ("tx", 2, "00 C0 00 00 05"),
            (
                "rx",
                2,
                "",
                0x61,
                0x05,
                "More data available: 5 bytes (send GET RESPONSE)",
            ),
        ]

    def test_large_response_is_hexdumped(self) -> None:
        data = bytes(range(40))
        session = FakeSession([(data, 0x90, 0x00)])
        events: list[tuple] = []

        run_script(
            session, make_steps("AA"), emit=events.append, should_stop=lambda: False
        )

        rx_event = events[1]
        assert rx_event[0] == "rx"
        assert rx_event[1] == 1
        assert rx_event[2].startswith("0000  00 01 02 03")
        assert "\n" in rx_event[2]

    def test_stop_on_error_aborts_at_first_non_9000(self) -> None:
        session = FakeSession(
            [(b"", 0x90, 0x00), (b"", 0x6A, 0x82), (b"", 0x90, 0x00)]
        )
        events: list[tuple] = []
        steps = make_steps("00", "11", "22")

        summary = run_script(
            session,
            steps,
            emit=events.append,
            should_stop=lambda: False,
            stop_on_error=True,
        )

        assert len(session.calls) == 2
        assert summary["total"] == 3
        assert summary["run"] == 2
        assert summary["sw_counts"] == {"9000": 1, "6A82": 1}
        assert summary["aborted"] is True
        assert summary["stopped"] is False
        assert events[-1][0] == "abort"
        assert events[-1][1] == 2
        assert "6A82" in events[-1][2]

    def test_stop_on_error_ignores_9000(self) -> None:
        session = FakeSession([(b"", 0x90, 0x00), (b"", 0x90, 0x00)])
        events: list[tuple] = []

        summary = run_script(
            session,
            make_steps("00", "11"),
            emit=events.append,
            should_stop=lambda: False,
            stop_on_error=True,
        )

        assert summary["run"] == 2
        assert summary["aborted"] is False
        assert not [event for event in events if event[0] == "abort"]

    def test_should_stop_stops_before_next_step(self) -> None:
        checks = {"count": 0}

        def should_stop() -> bool:
            checks["count"] += 1
            return checks["count"] > 1

        session = FakeSession([(b"", 0x90, 0x00)] * 3)
        events: list[tuple] = []

        summary = run_script(
            session, make_steps("00", "11", "22"), emit=events.append, should_stop=should_stop
        )

        assert len(session.calls) == 1
        assert summary["total"] == 3
        assert summary["run"] == 1
        assert summary["stopped"] is True
        assert summary["aborted"] is False

    def test_pcsc_error_emits_error_event_and_stops(self) -> None:
        session = FakeSession(
            [(b"", 0x90, 0x00), pcsc.PcscError("Card was removed"), (b"", 0x90, 0x00)]
        )
        events: list[tuple] = []
        steps = make_steps("00", "11", "22")

        summary = run_script(
            session, steps, emit=events.append, should_stop=lambda: False
        )

        assert len(session.calls) == 2
        assert summary["run"] == 1
        assert summary["stopped"] is False
        assert summary["aborted"] is False
        assert events[-1] == ("error", 2, "Card was removed")

    def test_delay_sleeps_only_between_steps(self, monkeypatch: pytest.MonkeyPatch) -> None:
        slept: list[float] = []
        monkeypatch.setattr(script.time, "sleep", slept.append)
        session = FakeSession([(b"", 0x90, 0x00)] * 3)

        run_script(
            session,
            make_steps("00", "11", "22"),
            emit=lambda event: None,
            should_stop=lambda: False,
            delay_ms=250,
        )

        assert slept == [0.25, 0.25]

    def test_no_delay_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        slept: list[float] = []
        monkeypatch.setattr(script.time, "sleep", slept.append)
        session = FakeSession([(b"", 0x90, 0x00)] * 2)

        run_script(
            session, make_steps("00", "11"), emit=lambda event: None, should_stop=lambda: False
        )

        assert slept == []

    def test_empty_step_list(self) -> None:
        summary = run_script(
            FakeSession([]), [], emit=lambda event: None, should_stop=lambda: False
        )
        assert summary == {
            "total": 0,
            "run": 0,
            "sw_counts": {},
            "stopped": False,
            "aborted": False,
        }


class TestLibrary:
    def test_list_scripts_returns_metadata(self) -> None:
        metas = library.list_scripts()
        assert metas
        names = [meta.name for meta in metas]
        assert len(names) == len(set(names))
        for meta in metas:
            assert meta.description
            assert meta.category
            assert not meta.name.endswith(".gscl")

    def test_expected_scripts_are_bundled(self) -> None:
        names = {meta.name for meta in library.list_scripts()}
        expected = {
            "select_mf",
            "select_ef_dir",
            "read_ef_dir",
            "read_binary",
            "select_aid_template",
            "get_response",
            "verify_pin_template",
            "change_pin_template",
            "internal_authenticate_template",
            "get_data",
        }
        assert expected <= names

    def test_every_script_loads_and_parses(self) -> None:
        for meta in library.list_scripts():
            text = library.load_script_text(meta.name)
            steps = parse_script(text)
            assert steps, f"{meta.name} contains no APDU lines"

    def test_all_four_categories_are_represented(self) -> None:
        categories = {meta.category for meta in library.list_scripts()}
        assert {"selection", "reading", "templates", "utilities"} <= categories

    def test_load_script_text_accepts_extension_suffix(self) -> None:
        assert library.load_script_text("select_mf.gscl") == (
            library.load_script_text("select_mf")
        )

    def test_load_script_text_missing_name_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            library.load_script_text("no_such_script")

    def test_load_script_text_rejects_path_traversal(self) -> None:
        with pytest.raises(FileNotFoundError):
            library.load_script_text("../core/apdu.py")


def test_script_step_defaults() -> None:
    step = ScriptStep(line_no=1, apdu=b"\x00")
    assert step.comment == ""
