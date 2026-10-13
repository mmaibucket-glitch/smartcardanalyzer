"""APDU instruction classification and safe-mode policy for beginners."""

from __future__ import annotations

from typing import Optional

INSTRUCTION_NAMES = {
    0x04: "DEACTIVATE FILE",
    0x0C: "ERASE RECORD",
    0x0E: "ERASE BINARY",
    0x0F: "ERASE BINARY (odd INS)",
    0x20: "VERIFY",
    0x22: "MANAGE SECURITY ENVIRONMENT",
    0x24: "CHANGE REFERENCE DATA",
    0x26: "DISABLE VERIFICATION",
    0x28: "ENABLE VERIFICATION",
    0x2A: "PERFORM SECURITY OPERATION",
    0x2C: "RESET RETRY COUNTER",
    0x44: "ACTIVATE FILE",
    0x46: "GENERATE ASYMMETRIC KEY PAIR",
    0x70: "MANAGE CHANNEL",
    0x82: "EXTERNAL AUTHENTICATE",
    0x84: "GET CHALLENGE",
    0x86: "GENERAL AUTHENTICATE",
    0x88: "INTERNAL AUTHENTICATE",
    0xA4: "SELECT FILE",
    0xB0: "READ BINARY",
    0xB1: "READ BINARY (odd INS)",
    0xB2: "READ RECORD",
    0xB3: "READ RECORD (odd INS)",
    0xC0: "GET RESPONSE",
    0xCA: "GET DATA",
    0xCB: "GET DATA (odd INS)",
    0xD0: "WRITE BINARY",
    0xD1: "WRITE BINARY (odd INS)",
    0xD2: "WRITE RECORD",
    0xD3: "WRITE RECORD (odd INS)",
    0xD6: "UPDATE BINARY",
    0xD7: "UPDATE BINARY (odd INS)",
    0xDA: "PUT DATA",
    0xDB: "PUT DATA (odd INS)",
    0xDC: "UPDATE RECORD",
    0xDD: "UPDATE RECORD (odd INS)",
    0xE0: "CREATE FILE",
    0xE2: "APPEND RECORD",
    0xE4: "DELETE FILE",
    0xE6: "TERMINATE DF",
    0xE8: "TERMINATE EF",
    0xF2: "STATUS",
    0xFE: "TERMINATE CARD USAGE",
}

WRITE_INSTRUCTIONS = {
    0x04, 0x0C, 0x0E, 0x0F, 0x24, 0x26, 0x28, 0x2C, 0x44, 0x46, 0x70,
    0xD0, 0xD1, 0xD2, 0xD3, 0xD6, 0xD7, 0xDA, 0xDB, 0xDC, 0xDD,
    0xE0, 0xE2, 0xE4, 0xE6, 0xE8, 0xFE,
}

AUTH_INSTRUCTIONS = {0x20, 0x22, 0x2A, 0x82, 0x86, 0x88}

CATEGORY_LABELS = {
    "read": "read-only",
    "write": "card-modifying",
    "auth": "authentication-related",
    "unknown": "unknown",
}


def classify_apdu(apdu: bytes) -> tuple[str, str]:
    """Return (category, name); category is 'read', 'write', 'auth' or 'unknown'."""
    if len(apdu) < 2:
        return ("unknown", "Truncated APDU")
    ins = apdu[1]
    name = INSTRUCTION_NAMES.get(ins, f"INS {ins:02X}")
    if ins in WRITE_INSTRUCTIONS:
        return ("write", name)
    if ins in AUTH_INSTRUCTIONS:
        return ("auth", name)
    if ins in INSTRUCTION_NAMES:
        return ("read", name)
    return ("unknown", name)


def blocked_reason(apdu: bytes, safe_mode: bool) -> Optional[str]:
    """Return a user-facing reason if safe mode blocks this APDU, else None."""
    if not safe_mode:
        return None
    category, name = classify_apdu(apdu)
    if category == "write":
        return (
            f"Safe mode blocked a card-modifying command: {name}. "
            "Disable safe mode in the Console tab if you really want to send it."
        )
    return None
