"""Tests for APDU safety classification and safe-mode blocking."""

from __future__ import annotations

from app.core import safety


def test_classify_read_binary_is_read() -> None:
    category, name = safety.classify_apdu(bytes.fromhex("00B00000"))
    assert category == "read"
    assert name == "READ BINARY"


def test_classify_update_binary_is_write() -> None:
    category, name = safety.classify_apdu(bytes.fromhex("00D60000"))
    assert category == "write"
    assert name == "UPDATE BINARY"


def test_classify_internal_authenticate_is_auth() -> None:
    category, name = safety.classify_apdu(bytes.fromhex("00880000"))
    assert category == "auth"
    assert name == "INTERNAL AUTHENTICATE"


def test_classify_general_authenticate_is_auth() -> None:
    category, name = safety.classify_apdu(bytes.fromhex("00860000"))
    assert category == "auth"
    assert name == "GENERAL AUTHENTICATE"


def test_classify_manage_channel_is_write() -> None:
    category, name = safety.classify_apdu(bytes.fromhex("00700000"))
    assert category == "write"
    assert name == "MANAGE CHANNEL"


def test_classify_delete_file_is_write() -> None:
    category, name = safety.classify_apdu(bytes.fromhex("00E40000"))
    assert category == "write"
    assert name == "DELETE FILE"


def test_classify_erase_binary_is_write() -> None:
    category, name = safety.classify_apdu(bytes.fromhex("000E0000"))
    assert category == "write"
    assert name == "ERASE BINARY"


MUST_BLOCK_INSTRUCTIONS = {
    0x04, 0x0C, 0x0E, 0x0F, 0x24, 0x26, 0x28, 0x2C, 0x44, 0x46, 0x70,
    0xD0, 0xD1, 0xD2, 0xD3, 0xD6, 0xD7, 0xDA, 0xDB, 0xDC, 0xDD,
    0xE0, 0xE2, 0xE4, 0xE6, 0xE8, 0xFE,
}


def test_every_write_instruction_is_blocked_in_safe_mode() -> None:
    for ins in sorted(MUST_BLOCK_INSTRUCTIONS):
        category, name = safety.classify_apdu(bytes((0x00, ins)))
        assert category == "write", (
            f"INS {ins:02X} ({name}) must be write-classified, got {category!r}"
        )


def test_write_instruction_set_matches_must_block_set() -> None:
    assert safety.WRITE_INSTRUCTIONS == MUST_BLOCK_INSTRUCTIONS


def test_classify_unknown_ins() -> None:
    category, name = safety.classify_apdu(bytes.fromhex("00990000"))
    assert category == "unknown"
    assert name == "INS 99"


def test_classify_truncated_apdu_is_unknown() -> None:
    category, name = safety.classify_apdu(b"\x00")
    assert category == "unknown"
    assert name == "Truncated APDU"


def test_blocked_reason_is_none_when_safe_mode_off() -> None:
    assert safety.blocked_reason(bytes.fromhex("00D60000"), False) is None


def test_blocked_reason_names_write_command_when_safe_mode_on() -> None:
    reason = safety.blocked_reason(bytes.fromhex("00D60000"), True)
    assert reason is not None
    assert "UPDATE BINARY" in reason


def test_blocked_reason_is_none_for_read_when_safe_mode_on() -> None:
    assert safety.blocked_reason(bytes.fromhex("00B00000"), True) is None
