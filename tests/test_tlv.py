"""Tests for BER-TLV parsing and formatting."""

from __future__ import annotations

from app.core import tlv

MASTERCARD_FCI = bytes.fromhex(
    "6F178407A0000000041010A50C500A4D617374657263617264"
)


def test_parse_simple_primitive() -> None:
    nodes = tlv.parse_tlv(bytes.fromhex("4F06A00000000410"))
    assert len(nodes) == 1
    assert nodes[0].tag == 0x4F
    assert nodes[0].value == bytes.fromhex("A00000000410")
    assert nodes[0].children == []


def test_parse_nested_constructed() -> None:
    nodes = tlv.parse_tlv(MASTERCARD_FCI)
    assert [node.tag for node in nodes] == [0x6F]
    fci = nodes[0]
    assert [child.tag for child in fci.children] == [0x84, 0xA5]
    assert fci.children[0].value == bytes.fromhex("A0000000041010")
    assert fci.children[0].children == []
    label = fci.children[1].children[0]
    assert label.tag == 0x50
    assert label.value == b"Mastercard"


def test_parse_two_byte_tag() -> None:
    nodes = tlv.parse_tlv(bytes.fromhex("5F5008746573742E636F6D"))
    assert len(nodes) == 1
    assert nodes[0].tag == 0x5F50
    assert nodes[0].value == b"test.com"


def test_parse_two_byte_primitive_tag_9f36() -> None:
    nodes = tlv.parse_tlv(bytes.fromhex("9F36021234"))
    assert len(nodes) == 1
    assert nodes[0].tag == 0x9F36
    assert nodes[0].value == bytes.fromhex("1234")
    assert nodes[0].children == []


def test_parse_two_byte_primitive_tag_5f2d() -> None:
    nodes = tlv.parse_tlv(bytes.fromhex("5F2D02656E"))
    assert len(nodes) == 1
    assert nodes[0].tag == 0x5F2D
    assert nodes[0].value == b"en"
    assert nodes[0].children == []


def test_parse_two_byte_primitive_tag_5f50() -> None:
    nodes = tlv.parse_tlv(bytes.fromhex("5F5008687474703A2F2F78"))
    assert len(nodes) == 1
    assert nodes[0].tag == 0x5F50
    assert nodes[0].value == b"http://x"
    assert nodes[0].children == []


def test_parse_two_byte_constructed_tag_bf0c() -> None:
    nodes = tlv.parse_tlv(bytes.fromhex("BF0C060201AA0301BB"))
    assert len(nodes) == 1
    assert nodes[0].tag == 0xBF0C
    assert [child.tag for child in nodes[0].children] == [0x02, 0x03]


def test_parse_constructed_bit_is_in_first_tag_octet() -> None:
    nodes = tlv.parse_tlv(bytes.fromhex("61044F02ABCD6F0450024F4BA5028800"))
    assert [node.tag for node in nodes] == [0x61, 0x6F, 0xA5]
    assert [[child.tag for child in node.children] for node in nodes] == [
        [0x4F],
        [0x50],
        [0x88],
    ]
    assert all(child.children == [] for node in nodes for child in node.children)


def test_parse_long_form_length() -> None:
    nodes = tlv.parse_tlv(bytes.fromhex("508200024F4B"))
    assert nodes[0].tag == 0x50
    assert nodes[0].value == b"OK"


def test_parse_skips_padding_bytes() -> None:
    nodes = tlv.parse_tlv(bytes.fromhex("004F06A00000000410FF"))
    assert [node.tag for node in nodes] == [0x4F]
    assert nodes[0].value == bytes.fromhex("A00000000410")


def test_parse_truncated_tail_returns_prefix() -> None:
    nodes = tlv.parse_tlv(bytes.fromhex("50024F4B4F06A000"))
    assert [node.tag for node in nodes] == [0x50]
    assert nodes[0].value == b"OK"


def test_parse_stops_on_impossible_lengths() -> None:
    assert tlv.parse_tlv(bytes.fromhex("5080")) == []
    assert tlv.parse_tlv(bytes.fromhex("5082FFFF00")) == []
    assert tlv.parse_tlv(bytes.fromhex("4F")) == []


def test_parse_empty_data() -> None:
    assert tlv.parse_tlv(b"") == []


def test_format_tlv_tree() -> None:
    text = tlv.format_tlv(MASTERCARD_FCI)
    lines = text.splitlines()
    assert lines[0].startswith("6F File control information (FCI) template:")
    assert lines[1].startswith("  84 DF name (AID):")
    assert lines[2].startswith("  A5 FCI proprietary template (EMV):")
    assert lines[3].startswith("    50 Application label:")
    assert lines[3].endswith("[Mastercard]")
    assert text.count("[Mastercard]") == 1
    assert "A0000000041010" not in text


def test_format_tlv_two_byte_tag_and_unknown_tag() -> None:
    text = tlv.format_tlv(bytes.fromhex("5F5008746573742E636F6D9F0102ABCD"))
    lines = text.splitlines()
    assert lines[0].startswith("5F50 Issuer URL:")
    assert "[test.com]" in lines[0]
    assert lines[1].startswith("9F01 Unknown tag:")


def test_format_tlv_indent_parameter() -> None:
    text = tlv.format_tlv(bytes.fromhex("50024F4B"), indent=2)
    assert text.startswith("    50 Application label: 4F 4B [OK]")


def test_known_tags_required_entries() -> None:
    required = {
        0x61: "Application template",
        0x4F: "Application identifier (AID)",
        0x50: "Application label",
        0x5F50: "Issuer URL",
        0x6F: "File control information (FCI) template",
        0x80: "Number of data bytes in transparent file",
        0x82: "File descriptor byte",
        0x83: "File identifier",
        0x84: "DF name (AID)",
        0x86: "Security attributes (proprietary)",
        0x88: "Short file identifier (SFI)",
        0x8A: "Life cycle status integer",
        0x73: "Discretionary template",
    }
    for tag, name in required.items():
        assert tlv.KNOWN_TAGS.get(tag) == name
