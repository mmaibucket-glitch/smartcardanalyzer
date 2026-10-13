"""Tests for the guided APDU builder assembly and presets (no Qt)."""

from __future__ import annotations

import pytest

from app.gui.builder_widget import PRESETS, assemble_apdu

REQUIRED_PRESET_HEADERS = {
    "Custom": (0x00, 0x00, 0x00, 0x00),
    "SELECT FILE (A4)": (0x00, 0xA4, 0x00, 0x00),
    "READ BINARY (B0)": (0x00, 0xB0, 0x00, 0x00),
    "READ RECORD (B2)": (0x00, 0xB2, 0x01, 0x04),
    "GET RESPONSE (C0)": (0x00, 0xC0, 0x00, 0x00),
    "GET DATA (CA)": (0x00, 0xCA, 0x00, 0x6F),
    "VERIFY (20)": (0x00, 0x20, 0x00, 0x81),
    "INTERNAL AUTHENTICATE (88)": (0x00, 0x88, 0x00, 0x00),
    "GET CHALLENGE (84)": (0x00, 0x84, 0x00, 0x00),
}


def test_case_1_header_only() -> None:
    assert assemble_apdu(0x00, 0xA4, 0x00, 0x00) == bytes.fromhex("00A40000")


def test_case_2_le_only() -> None:
    assert assemble_apdu(0x00, 0x84, 0x00, 0x00, le=8) == bytes.fromhex("0084000008")
    assert assemble_apdu(0x00, 0xC0, 0x00, 0x00, le=0) == bytes.fromhex("00C0000000")


def test_case_3_data_only() -> None:
    built = assemble_apdu(0x00, 0xA4, 0x04, 0x00, data=bytes.fromhex("A0000000041010"))
    assert built == bytes.fromhex("00A4040007A0000000041010")


def test_case_4_data_and_le() -> None:
    built = assemble_apdu(0x00, 0x88, 0x00, 0x00, data=bytes.fromhex("0102"), le=0x10)
    assert built == bytes.fromhex("0088000002010210")


def test_maximal_fields_assemble() -> None:
    built = assemble_apdu(255, 255, 255, 255, data=bytes(255), le=255)
    assert len(built) == 261
    assert built[:5] == bytes([255, 255, 255, 255, 255])
    assert built[-1] == 255


def test_value_error_on_cla_256() -> None:
    with pytest.raises(ValueError):
        assemble_apdu(256, 0x00, 0x00, 0x00)


def test_value_error_on_negative_le() -> None:
    with pytest.raises(ValueError):
        assemble_apdu(0x00, 0x84, 0x00, 0x00, le=-1)


def test_value_error_on_data_length_256() -> None:
    with pytest.raises(ValueError):
        assemble_apdu(0x00, 0xD6, 0x00, 0x00, data=bytes(256))


def test_value_error_on_other_out_of_range_fields() -> None:
    with pytest.raises(ValueError):
        assemble_apdu(0x00, -1, 0x00, 0x00)
    with pytest.raises(ValueError):
        assemble_apdu(0x00, 0x00, 0x00, 256)
    with pytest.raises(ValueError):
        assemble_apdu(0x00, 0x00, 0x00, 0x00, le=256)


def test_presets_have_unique_names() -> None:
    names = [str(preset["name"]) for preset in PRESETS]
    assert len(names) == len(set(names))


def test_presets_cover_required_commands() -> None:
    names = {str(preset["name"]) for preset in PRESETS}
    assert set(REQUIRED_PRESET_HEADERS) <= names


def test_preset_headers_match_required_byte_values() -> None:
    by_name = {str(preset["name"]): preset for preset in PRESETS}
    for name, header in REQUIRED_PRESET_HEADERS.items():
        preset = by_name[name]
        assert (preset["cla"], preset["ins"], preset["p1"], preset["p2"]) == header


def test_preset_fields_in_range_and_hints_nonempty() -> None:
    for preset in PRESETS:
        for key in ("cla", "ins", "p1", "p2"):
            assert isinstance(preset[key], int)
            assert 0 <= preset[key] <= 255
        assert isinstance(preset["hint"], str)
        assert preset["hint"].strip()


def test_preset_keys_are_known() -> None:
    required_keys = {"name", "cla", "ins", "p1", "p2", "hint"}
    allowed_keys = required_keys | {"le"}
    for preset in PRESETS:
        assert required_keys <= set(preset) <= allowed_keys


def test_get_challenge_preset_defaults_to_le_8() -> None:
    by_name = {str(preset["name"]): preset for preset in PRESETS}
    assert by_name["GET CHALLENGE (84)"].get("le") == 8


def test_every_preset_assembles_to_its_header() -> None:
    for preset in PRESETS:
        built = assemble_apdu(
            int(preset["cla"]),
            int(preset["ins"]),
            int(preset["p1"]),
            int(preset["p2"]),
            le=preset.get("le"),
        )
        assert built[:4] == bytes(
            [preset["cla"], preset["ins"], preset["p1"], preset["p2"]]
        )
