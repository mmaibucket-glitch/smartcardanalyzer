"""BER-TLV parsing and pretty-printing.

Most smart cards describe their data in BER-TLV: every piece of data is
wrapped in a small envelope holding a tag (what it is), a length, and a
value. parse_tlv turns raw response bytes into Tlv trees, tolerating the
padding bytes and truncation that real cards produce, and format_tlv
renders a tree as an indented listing with friendly tag names and an
ASCII hint for text-like values.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.core import apdu


@dataclass
class Tlv:
    """One BER-TLV data object; children is filled only for constructed tags."""

    tag: int
    value: bytes
    children: list["Tlv"] = field(default_factory=list)


KNOWN_TAGS: dict[int, str] = {
    0x61: "Application template",
    0x62: "File control parameter (FCP) template",
    0x64: "File management data (FMD) template",
    0x6F: "File control information (FCI) template",
    0x70: "Record template",
    0x73: "Discretionary template",
    0x4F: "Application identifier (AID)",
    0x50: "Application label",
    0x80: "Number of data bytes in transparent file",
    0x82: "File descriptor byte",
    0x83: "File identifier",
    0x84: "DF name (AID)",
    0x86: "Security attributes (proprietary)",
    0x88: "Short file identifier (SFI)",
    0x8A: "Life cycle status integer",
    0xA5: "FCI proprietary template (EMV)",
    0x5F50: "Issuer URL",
}


def parse_tlv(data: bytes) -> list[Tlv]:
    """Parse BER-TLV data into a list of Tlv trees.

    Lenient by design: 0x00 and 0xFF padding bytes are skipped, and parsing
    stops cleanly (returning what was parsed so far) when the data ends mid
    tag, mid length, or with a length that runs past the end of the buffer.
    """
    results: list[Tlv] = []
    index = 0
    size = len(data)
    while index < size:
        if data[index] in (0x00, 0xFF):
            index += 1
            continue
        tag, tag_end = _read_tag(data, index)
        if tag_end is None or tag_end >= size:
            break
        length, value_start = _read_length(data, tag_end)
        if value_start is None or value_start + length > size:
            break
        value = data[value_start:value_start + length]
        children = parse_tlv(value) if _is_constructed(tag) else []
        results.append(Tlv(tag=tag, value=value, children=children))
        index = value_start + length
    return results


def format_tlv(data: bytes, indent: int = 0) -> str:
    """Render BER-TLV data as an indented listing with tag names."""
    lines: list[str] = []
    for node in parse_tlv(data):
        lines.extend(_format_node(node, indent))
    return "\n".join(lines)


def _read_tag(data: bytes, index: int) -> tuple[int, int | None]:
    """Read one tag; the second result is None when the tag is truncated."""
    first = data[index]
    if first & 0x1F != 0x1F:
        return first, index + 1
    tag = first
    cursor = index + 1
    while cursor < len(data):
        octet = data[cursor]
        tag = (tag << 8) | octet
        cursor += 1
        if not octet & 0x80:
            return tag, cursor
    return first, None


def _is_constructed(tag: int) -> bool:
    """True when the first tag octet has the constructed (C) bit set."""
    octets = (tag.bit_length() + 7) // 8
    first = tag >> (8 * (octets - 1))
    return bool(first & 0x20)


def _read_length(data: bytes, index: int) -> tuple[int, int | None]:
    """Read one BER length; the second result is None when it is unusable."""
    first = data[index]
    if first < 0x80:
        return first, index + 1
    count = first & 0x7F
    if count == 0 or index + 1 + count > len(data):
        return 0, None
    length = int.from_bytes(data[index + 1:index + 1 + count], "big")
    return length, index + 1 + count


def _format_node(node: Tlv, indent: int) -> list[str]:
    pad = "  " * indent
    tag_hex = f"{node.tag:04X}" if node.tag > 0xFF else f"{node.tag:02X}"
    name = KNOWN_TAGS.get(node.tag, "Unknown tag")
    line = f"{pad}{tag_hex} {name}: {apdu.format_hex(node.value)}"
    hint = _ascii_hint(node.value)
    if hint:
        line += f" [{hint}]"
    if not node.children:
        return [line]
    lines = [line]
    for child in node.children:
        lines.extend(_format_node(child, indent + 1))
    return lines


def _ascii_hint(value: bytes) -> str:
    if not value:
        return ""
    if all(0x20 <= byte < 0x7F for byte in value):
        return value.decode("ascii")
    return ""
