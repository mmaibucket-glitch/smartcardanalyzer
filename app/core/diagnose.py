"""Plain-language diagnosis of PC/SC failures: what broke and how to fix it."""

from __future__ import annotations

import platform
import re
from typing import Optional

from smartcard.System import readers as SystemReaders
from smartcard.pcsc.PCSCExceptions import EstablishContextException

readers = SystemReaders

STATUS_SERVICE_DOWN = "service-down"
STATUS_NO_READERS = "no-readers"
STATUS_READERS_PRESENT = "readers-present"

_ERROR_CODE_PATTERN = re.compile(r"\b(?:0[xX])?([0-9a-fA-F]{8})\b")


def _service_start_hint() -> str:
    """Return a per-OS instruction for getting the PC/SC service running."""
    system = platform.system()
    if system == "Windows":
        return (
            "On Windows: open services.msc and start the Smart Card service, "
            "then press Refresh."
        )
    if system == "Darwin":
        return "On macOS: the pcscd service runs automatically - try restarting."
    return (
        "On Linux: run 'sudo systemctl start pcscd' (or 'sudo service pcscd "
        "start'), then press Refresh."
    )


ERROR_HINTS: dict[str, str] = {
    "8010000c": "No card in the reader. Insert a card and press Connect again.",
    "8010001d": "The PC/SC service is not running. " + _service_start_hint(),
    "8010001e": "The PC/SC service was stopped. Restart it and try again.",
    "8010002e": "No reader is plugged in (or its driver is missing).",
    "8010000b": (
        "Another program is using this reader. Close other card applications "
        "(some browsers and GPG can hold readers) and try again."
    ),
    "80100017": "The reader is busy or unavailable. Unplug and reconnect it, then Refresh.",
    "8010000a": "The operation timed out. Make sure the card sits firmly in the reader.",
    "8010000d": "The reader does not recognize this card type (driver problem).",
    "80100002": "The operation was cancelled.",
    "80100012": "The operation was cancelled by the system.",
    "8010000f": (
        "The card communicates with a protocol the reader session does not "
        "support. Disconnect, reconnect the card, and connect again."
    ),
    "80100069": "The card was removed. Reinsert it and connect again.",
    "80100068": "The card was reset during communication. Disconnect and connect again.",
    "80100066": "The card did not respond. Reinsert it and connect again.",
}


def get_reader_status() -> str:
    """Classify the current PC/SC situation; never raises."""
    try:
        reader_list = readers()
    except EstablishContextException:
        return STATUS_SERVICE_DOWN
    except Exception:
        return STATUS_SERVICE_DOWN
    if not reader_list:
        return STATUS_NO_READERS
    return STATUS_READERS_PRESENT


def describe_reader_status(status: str) -> str:
    """Return a plain-language explanation with a fix hint for a reader status."""
    if status == STATUS_NO_READERS:
        return (
            "PC/SC is running, but no reader is plugged in (or its driver is "
            "missing). Plug in a reader and press Refresh."
        )
    if status == STATUS_READERS_PRESENT:
        return (
            "Reader(s) detected. Select one and press Connect "
            "(a card must be inserted)."
        )
    return (
        "The PC/SC smart card service is not running, so no reader can be "
        "talked to. " + _service_start_hint()
    )


def translate_error(message: str) -> str:
    """Append a plain-language hint for the first known PC/SC code in *message*."""
    for match in _ERROR_CODE_PATTERN.finditer(message):
        hint: Optional[str] = ERROR_HINTS.get(match.group(1).lower())
        if hint is not None:
            if hint in message:
                return message
            return f"{message} - {hint}"
    return message
