"""Parsing and execution of gscriptor-style APDU scripts (one hex APDU per line)."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable

from app.core import apdu, pcsc


@dataclass
class ScriptStep:
    """One executable APDU together with the source line it came from."""

    line_no: int
    apdu: bytes
    comment: str = ""


def parse_script(text: str) -> list[ScriptStep]:
    """Parse script text into steps; raise ValueError("line N: ...") on bad hex.

    Blank lines are ignored, and everything from the first '#' on a line is a
    comment; the remaining text is parsed as one hex APDU per line.
    """
    steps: list[ScriptStep] = []
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        code = raw_line
        comment = ""
        hash_index = raw_line.find("#")
        if hash_index >= 0:
            comment = raw_line[hash_index + 1 :].strip()
            code = raw_line[:hash_index]
        code = code.strip()
        if not code:
            continue
        try:
            apdu_bytes = apdu.parse_hex(code)
        except ValueError as exc:
            raise ValueError(f"line {line_no}: {exc}") from exc
        steps.append(ScriptStep(line_no=line_no, apdu=apdu_bytes, comment=comment))
    return steps


def run_script(
    session: pcsc.CardSession,
    steps: list[ScriptStep],
    *,
    emit: Callable[[tuple], None],
    should_stop: Callable[[], bool],
    delay_ms: int = 0,
    stop_on_error: bool = False,
) -> dict[str, object]:
    """Transmit each step against the session, publishing ("tx"/"rx"/"abort"/"error", ...) tuples.

    Stops early when ``should_stop()`` becomes True, when ``stop_on_error`` is set
    and a status word other than 9000 arrives, or when the session raises
    ``PcscError`` (the card is most likely gone).
    """
    summary: dict[str, object] = {
        "total": len(steps),
        "run": 0,
        "sw_counts": {},
        "stopped": False,
        "aborted": False,
    }
    sw_counts: dict[str, int] = {}
    run = 0
    for index, step in enumerate(steps):
        if should_stop():
            summary["stopped"] = True
            break
        emit(("tx", step.line_no, apdu.format_hex(step.apdu)))
        try:
            data, sw1, sw2 = session.transmit(step.apdu)
        except pcsc.PcscError as exc:
            emit(("error", step.line_no, str(exc)))
            break
        data_str = apdu.hexdump(data) if len(data) > 32 else apdu.format_hex(data)
        emit(("rx", step.line_no, data_str, sw1, sw2, apdu.describe_sw(sw1, sw2)))
        run += 1
        sw_key = f"{sw1:02X}{sw2:02X}"
        sw_counts[sw_key] = sw_counts.get(sw_key, 0) + 1
        if stop_on_error and (sw1, sw2) != (0x90, 0x00):
            summary["aborted"] = True
            emit(
                (
                    "abort",
                    step.line_no,
                    f"Stopped: SW {sw_key} - {apdu.describe_sw(sw1, sw2)}",
                )
            )
            break
        if delay_ms > 0 and index + 1 < len(steps):
            time.sleep(delay_ms / 1000)
    summary["run"] = run
    summary["sw_counts"] = sw_counts
    return summary
