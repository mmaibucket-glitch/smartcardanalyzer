"""Bounded, read-only collection of accessible card data."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from app.core import exchange, pcsc, tlv

MAX_EXCHANGES = 512
MAX_FOLLOWUPS_PER_COMMAND = 8
EMV_AID_PREFIXES = tuple(
    bytes.fromhex(value)
    for value in ("A0000000031010", "A0000000041010", "A0000000043060", "A000000025")
)
GET_DATA_TAGS = (0x9F36, 0x9F13, 0x9F17, 0x9F4F)
MAX_SFI = 30
MAX_RECORD = 16

_FIELD_NAMES = {
    0x4F: "Application identifier",
    0x50: "Application label",
    0x57: "Track 2 equivalent data",
    0x5A: "Primary account number",
    0x5F20: "Cardholder name",
    0x5F24: "Application expiration date",
    0x5F25: "Application effective date",
    0x5F28: "Issuer country code",
    0x5F2A: "Application currency code",
    0x5F2D: "Language preference",
    0x5F30: "Service code",
    0x5F34: "PAN sequence number",
    0x61: "Application template",
    0x70: "Record template",
    0x82: "Application interchange profile",
    0x87: "Application priority indicator",
    0x8C: "Card risk management data object list 1",
    0x8D: "Card risk management data object list 2",
    0x8E: "Cardholder verification method list",
    0x94: "Application file locator",
    0x9F07: "Application usage control",
    0x9F08: "Application version number",
    0x9F12: "Application preferred name",
    0x9F0D: "Issuer action code — default",
    0x9F0E: "Issuer action code — denial",
    0x9F0F: "Issuer action code — online",
    0x9F13: "Last online ATC",
    0x9F17: "PIN tries remaining",
    0x9F02: "Amount, Authorised (Numeric)",
    0x9F36: "Application transaction counter",
    0x9F4F: "Log format",
}


@dataclass
class ReadoutEntry:
    aid: bytes
    source: str
    command: bytes
    data: bytes
    sw1: Optional[int]
    sw2: Optional[int]
    error: str = ""


@dataclass
class ReadoutResult:
    entries: list[ReadoutEntry] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    stopped: bool = False
    limited: bool = False
    exchanges: int = 0


class _StopRequested(Exception):
    pass


class _BudgetExhausted(Exception):
    pass


class _BudgetSession:
    """Count every physical transmit, including smart-exchange followups."""

    def __init__(self, session, result: ReadoutResult, should_stop, apps):
        self._session = session
        self._result = result
        self._should_stop = should_stop
        self._aids = {bytes(app.aid) for app in apps}

    def transmit(self, command: bytes):
        if self._should_stop():
            raise _StopRequested
        command = bytes(command)
        if not _is_allowed_command(command, self._aids):
            raise ValueError(f"Readout command is outside the fixed allowlist: {command.hex().upper()}")
        if self._result.exchanges >= MAX_EXCHANGES:
            raise _BudgetExhausted
        self._result.exchanges += 1
        return self._session.transmit(command)


def read_accessible_data(
    session,
    apps,
    *,
    emit: Optional[Callable[[tuple[str, str]], None]] = None,
    should_stop: Optional[Callable[[], bool]] = None,
) -> ReadoutResult:
    """Read bounded card data using selection and read commands only.

    Only known payment AIDs receive the GET DATA and sparse-record scan.
    Other applications return SELECT metadata. No initialization, PIN,
    authentication, transaction cryptogram, or write command is sent.
    """
    result = ReadoutResult()
    result.notes.append(
        "Scan bounds: four GET DATA tags, SFIs 1–30, records 1–16. "
        f"At most {MAX_EXCHANGES} physical APDU exchanges. "
        "No transaction initialization is performed."
    )
    stop_check = should_stop or (lambda: False)
    bounded = _BudgetSession(session, result, stop_check, apps)
    seen_aids: set[bytes] = set()

    for app in apps:
        aid = bytes(app.aid)
        if aid in seen_aids:
            continue
        seen_aids.add(aid)
        if stop_check():
            result.stopped = True
            result.notes.append("Readout stopped by user; partial results are shown.")
            break

        _progress(emit, f"Selecting application {aid.hex().upper()}…")
        select = _select_apdu(aid)
        entry, terminal = _run_command(
            bounded, result, aid, "SELECT application", select, stop_check
        )
        result.entries.append(entry)
        if terminal == "stopped":
            result.stopped = True
            result.notes.append("Readout stopped by user; partial results are shown.")
            break
        if terminal == "budget":
            result.limited = True
            result.notes.append(f"Readout reached the {MAX_EXCHANGES}-exchange limit.")
            break
        if terminal == "followup-limit":
            result.limited = True
            break
        if entry.error:
            result.notes.append(f"Could not select application: {entry.error}")
            break
        if (entry.sw1, entry.sw2) != (0x90, 0x00):
            result.notes.append(
                f"SELECT for {aid.hex().upper()} returned SW {entry.sw1:02X}{entry.sw2:02X}."
            )
            continue
        if not _is_emv_aid(aid):
            result.notes.append(
                f"Application {aid.hex().upper()} was selected. Deeper data reading "
                "is unsupported for this application type."
            )
            continue

        terminal = _read_emv_app(
            bounded, result, aid, emit, stop_check
        )
        if terminal == "stopped":
            result.stopped = True
            result.notes.append("Readout stopped by user; partial results are shown.")
            break
        if terminal == "budget":
            result.limited = True
            result.notes.append(f"Readout reached the {MAX_EXCHANGES}-exchange limit.")
            break
        if terminal == "followup-limit":
            result.limited = True
            break
        if terminal == "error":
            break

    record_entries = [entry for entry in result.entries if entry.command[:2] == b"\x00\xB2"]
    if record_entries and not any(entry.data for entry in record_entries):
        result.notes.append(
            "No readable record data was returned within the scan bounds. "
            "The card may restrict access or require an unsupported application-specific sequence."
        )
    return result


def _read_emv_app(bounded, result, aid, emit, should_stop) -> str:
    for tag in GET_DATA_TAGS:
        if should_stop():
            return "stopped"
        command = bytes((0x80, 0xCA, (tag >> 8) & 0xFF, tag & 0xFF, 0x00))
        _progress(emit, f"Reading EMV data tag {tag:04X}…")
        entry, terminal = _run_command(
            bounded, result, aid, f"GET DATA {tag:04X}", command, should_stop
        )
        result.entries.append(entry)
        if terminal:
            return terminal
        if entry.error:
            result.notes.append(f"GET DATA {tag:04X} failed: {entry.error}")
            return "error"

    for sfi in range(1, MAX_SFI + 1):
        for record in range(1, MAX_RECORD + 1):
            if should_stop():
                return "stopped"
            p2 = (sfi << 3) | 0x04
            command = bytes((0x00, 0xB2, record, p2, 0x00))
            _progress(emit, f"Reading SFI {sfi}, record {record}…")
            entry, terminal = _run_command(
                bounded,
                result,
                aid,
                f"READ RECORD SFI {sfi} record {record}",
                command,
                should_stop,
            )
            result.entries.append(entry)
            if terminal:
                return terminal
            if entry.error:
                result.notes.append(
                    f"Record scan stopped after a communication error: {entry.error}"
                )
                return "error"
            if _ends_sfi(entry.sw1, entry.sw2):
                break
        else:
            result.limited = True
            result.notes.append(
                f"SFI {sfi} reached the {MAX_RECORD}-record scan limit; later records were not checked."
            )
    return ""


def _run_command(bounded, result, aid, source, command, should_stop):
    steps: list[tuple[bytes, bytes, int, int]] = []
    try:
        response = exchange.transmit_smart(
            bounded,
            command,
            max_followups=MAX_FOLLOWUPS_PER_COMMAND,
            on_step=lambda apdu, data, sw1, sw2: steps.append(
                (bytes(apdu), bytes(data), sw1, sw2)
            ),
        )
    except _StopRequested:
        data, sw1, sw2 = _partial_exchange(steps)
        return ReadoutEntry(aid, source, command, data, sw1, sw2), "stopped"
    except _BudgetExhausted:
        data, sw1, sw2 = _partial_exchange(steps)
        return ReadoutEntry(aid, source, command, data, sw1, sw2), "budget"
    except pcsc.PcscError as exc:
        data, sw1, sw2 = _partial_exchange(steps)
        return ReadoutEntry(aid, source, command, data, sw1, sw2, str(exc)), ""
    entry = ReadoutEntry(aid, source, command, response.data, response.sw1, response.sw2)
    if response.sw1 == 0x61:
        result.notes.append(
            f"GET RESPONSE for {source} reached its {MAX_FOLLOWUPS_PER_COMMAND}-follow-up limit."
        )
        return entry, "followup-limit"
    return entry, ""


def _partial_exchange(steps):
    if not steps:
        return b"", None, None
    data = b"".join(item[1] for item in steps if item[2] != 0x6C)
    _, _, sw1, sw2 = steps[-1]
    return data, sw1, sw2


def _select_apdu(aid: bytes) -> bytes:
    if not 5 <= len(aid) <= 16:
        raise ValueError("Application AID must contain 5 to 16 bytes.")
    return bytes((0x00, 0xA4, 0x04, 0x00, len(aid))) + aid + b"\x00"


def _is_emv_aid(aid: bytes) -> bool:
    return any(aid.startswith(prefix) for prefix in EMV_AID_PREFIXES)


def _ends_sfi(sw1: Optional[int], sw2: Optional[int]) -> bool:
    if sw1 is None or sw2 is None:
        return True
    return (sw1, sw2) in {
        (0x6A, 0x82),  # file not found
        # 6A83 identifies a missing record, not the end of the file. Sparse
        # record numbering must still be checked within the scan bounds.
        (0x69, 0x82),  # security status not satisfied
        (0x69, 0x85),  # conditions of use not satisfied
        (0x69, 0x86),  # command not allowed
        (0x69, 0x81),  # function incompatible with file structure
        (0x68, 0x81),  # logical channel unsupported
        (0x68, 0x82),  # secure messaging unsupported
        (0x67, 0x00),  # wrong length
        (0x6A, 0x80),  # wrong data
        (0x6A, 0x81),  # function not supported
        (0x6A, 0x86),  # incorrect P1/P2
        (0x6A, 0x87),  # Lc inconsistent with P1/P2
        (0x6B, 0x00),  # invalid offset/parameters
        (0x6D, 0x00),  # INS unsupported
        (0x6E, 0x00),  # CLA unsupported
    }


def field_name(tag: int) -> str:
    """Return a beginner-friendly name for selected EMV and BER-TLV tags."""
    return _FIELD_NAMES.get(tag) or tlv.KNOWN_TAGS.get(tag) or (
        f"Tag {tag:02X}" if tag <= 0xFF else f"Tag {tag:04X}"
    )


def decode_value(tag: int, value: bytes) -> str:
    """Render common payment fields for the Inspector's decoded tree."""
    value = bytes(value)
    if tag in (0x5F28, 0x5F2A):
        digits = _bcd_digits(value)
        if digits.isdigit():
            return digits.lstrip("0") or "0"
    if tag == 0x5F30:
        digits = _bcd_digits(value)
        if digits.isdigit():
            return digits[-3:]
    if tag in (0x5A, 0x5F34, 0x9F13, 0x9F17, 0x9F36):
        digits = _bcd_digits(value)
        if tag == 0x5A:
            return digits
        if tag in (0x9F13, 0x9F17, 0x9F36):
            return str(int.from_bytes(value, "big")) if value else "0"
        return digits
    if tag == 0x57:
        digits = _bcd_digits(value)
        return digits.replace("D", " = ", 1)
    if tag in (0x5F24, 0x5F25):
        digits = _bcd_digits(value)
        if len(digits) >= 6:
            return f"20{digits[:2]}-{digits[2:4]}-{digits[4:6]}"
        return digits
    if tag == 0x5F20:
        return value.decode("ascii", errors="replace").strip(" \x00")
    if tag in (0x50, 0x5F2D, 0x84) and value and all(0x20 <= b < 0x7F for b in value):
        return value.decode("ascii").strip()
    return value.hex(" ").upper()


def _bcd_digits(value: bytes) -> str:
    text = "".join(f"{octet:02X}" for octet in value)
    return text.rstrip("F")


def _progress(emit, message: str) -> None:
    if emit is not None:
        emit(("progress", message))


def _is_allowed_command(command: bytes, aids: set[bytes]) -> bool:
    """Validate each initial or Le-corrected APDU against read-only commands."""
    if len(command) >= 11 and command[:4] == bytes.fromhex("00A40400"):
        lc = command[4]
        return 5 <= lc <= 16 and len(command) == 6 + lc and command[5:5 + lc] in aids
    if len(command) == 5 and command[:2] == bytes.fromhex("80CA"):
        return ((command[2] << 8) | command[3]) in GET_DATA_TAGS
    if len(command) == 5 and command[:2] == bytes.fromhex("00B2"):
        sfi, record, p2 = command[3] >> 3, command[2], command[3]
        return 1 <= sfi <= MAX_SFI and 1 <= record <= MAX_RECORD and (p2 & 0x07) == 0x04
    if len(command) == 5 and command[:4] == bytes.fromhex("00C00000"):
        return True
    return False
