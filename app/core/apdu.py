"""APDU parsing, formatting, and ISO 7816-4 status word lookup."""

from __future__ import annotations

import re

_CLEAN_HEX = re.compile(r"0[xX]|[^0-9a-fA-F]")

STATUS_WORDS = {
    "9000": "Normal processing (OK)",
    "6200": "Warning: state of non-volatile memory unchanged, no information given",
    "6281": "Part of returned data may be corrupted",
    "6282": "End of file or record reached before reading Le bytes",
    "6283": "Selected file invalidated",
    "6284": "FCI not formatted according to ISO 7816-4",
    "6300": "Warning: state of non-volatile memory changed (often: verification failed)",
    "6400": "Execution error: state of non-volatile memory unchanged, no information given",
    "6500": "Execution error: state of non-volatile memory changed, no information given",
    "6581": "Memory failure",
    "6700": "Wrong length (Lc or Le)",
    "6881": "Logical channel not supported",
    "6882": "Secure messaging not supported",
    "6900": "Command not allowed, no information given",
    "6981": "Command incompatible with file structure",
    "6982": "Security status not satisfied",
    "6983": "Authentication method blocked",
    "6984": "Referenced data invalidated",
    "6985": "Conditions of use not satisfied",
    "6986": "Command not allowed (no current EF)",
    "6987": "Expected secure messaging data objects missing",
    "6A80": "Wrong data",
    "6A81": "Function not supported",
    "6A82": "File or application not found",
    "6A83": "Record not found",
    "6A84": "Not enough memory space in the file",
    "6A85": "Lc inconsistent with TLV structure",
    "6A86": "Incorrect parameters P1-P2",
    "6A87": "Lc inconsistent with parameters P1-P2",
    "6A88": "Referenced data not found (e.g. file)",
    "6B00": "Wrong parameter(s) P1-P2",
    "6D00": "Instruction code not supported or invalid",
    "6E00": "Class not supported",
    "6F00": "Technical error, no precise diagnosis given",
}

_SW1_CLASSES = {
    "62": "Warning: state of non-volatile memory unchanged",
    "63": "Warning: state of non-volatile memory changed",
    "64": "Execution error: state of non-volatile memory unchanged",
    "65": "Execution error: state of non-volatile memory changed",
    "66": "Security-related error",
    "68": "Function(s) in class not supported",
    "69": "Command not allowed",
    "6A": "Wrong parameter(s) P1-P2",
    "6B": "Wrong parameter(s) P1-P2",
}


def parse_hex(text: str) -> bytes:
    """Parse a tolerant hex string: any case, spacing, 0x prefixes or separators."""
    cleaned = _CLEAN_HEX.sub("", text)
    if not cleaned:
        raise ValueError("No hex digits found in input.")
    if len(cleaned) % 2:
        raise ValueError("Hex input must contain an even number of digits.")
    return bytes.fromhex(cleaned)


def format_hex(data: bytes) -> str:
    """Format bytes as upper-case hex, one space per byte."""
    return " ".join(f"{byte:02X}" for byte in data)


def hexdump(data: bytes, width: int = 16) -> str:
    """Format bytes as a hexdump with offsets and an ASCII column."""
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        hex_part = " ".join(f"{byte:02X}" for byte in chunk)
        ascii_part = "".join(
            chr(byte) if 0x20 <= byte < 0x7F else "." for byte in chunk
        )
        lines.append(f"{offset:04X}  {hex_part:<{width * 3 - 1}}  {ascii_part}")
    return "\n".join(lines)


def describe_sw(sw1: int, sw2: int) -> str:
    """Return a human-readable description for an ISO 7816-4 status word."""
    key = f"{sw1:02X}{sw2:02X}"
    if key in STATUS_WORDS:
        return STATUS_WORDS[key]
    prefix = f"{sw1:02X}"
    if prefix == "61":
        return f"More data available: {sw2} bytes (send GET RESPONSE)"
    if prefix == "63" and 0xC0 <= sw2 <= 0xCF:
        return f"Verification failed, {sw2 & 0x0F} attempts remaining"
    if prefix == "6C":
        return f"Wrong Le: resend the command with Le = {sw2:02X}"
    if prefix in _SW1_CLASSES:
        return f"{_SW1_CLASSES[prefix]} (SW {key}, exact value undefined)"
    return "Proprietary or undefined status word"
