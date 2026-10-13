"""Card identification: read the ATR, list applications, and name the card.

Identification is a small, read-only scan that helps people who are new to
smart cards answer "what is this card?". It looks at the ATR (the greeting
the card sent when it was connected), asks the card for EF.DIR (the
application directory most cards keep) and reads it, then matches the
application identifiers (AIDs) it finds against a short list of well-known
card types such as payment cards, OpenPGP, PIV and ePassport. When a card
keeps no EF.DIR, a handful of well-known AIDs are probed with harmless
SELECT commands instead. Nothing is ever written to the card, no
authentication is attempted, and every command sent is read-only. The
finished profile also carries a short list of plain-language suggestions
for safe things to try next, built from the app's real scripts, presets
and buttons.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from app.core import apdu, exchange, pcsc, tlv

EF_DIR_SELECT = bytes.fromhex("00A40200022F00")
READ_CHUNK_SIZE = 256
MAX_DIR_BYTES = 1024
PROBE_LIMIT = 12

KNOWN_AIDS: dict[str, str] = {
    "A0000000030000": "Visa credit/debit (EMV payment)",
    "A0000000041010": "Mastercard (EMV payment)",
    "A0000000043060": "Maestro (EMV payment)",
    "A000000025": "American Express (EMV payment)",
    "A0000000620001": "OpenPGP card",
    "A0000003080000100000": "PIV card (US Personal Identity Verification)",
    "A0000002471001": "ICAO ePassport / Machine Readable Travel Document",
}

PIN_WARNING = "Never guess PINs - wrong attempts count down and can block the card."


@dataclass
class AtrInfo:
    """The parts of an Answer To Reset the tool can explain to a beginner."""

    atr: bytes
    ts: int
    protocols: list[str]
    historical: bytes
    summary: str


@dataclass
class AppInfo:
    """One application found on the card."""

    aid: bytes
    label: str = ""
    known_name: Optional[str] = None


@dataclass
class CardProfile:
    """Everything the identification scan learned about a card."""

    atr: bytes
    atr_summary: str = ""
    apps: list[AppInfo] = field(default_factory=list)
    label: str = "Unknown card"
    notes: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)


def parse_atr(atr: bytes) -> AtrInfo:
    """Parse an ATR into protocol and historical-byte parts; never raises.

    Interface bytes are followed through the TA/TB/TC/TD chain; each TDi
    contributes protocol T = its low nibble (T=0 is offered too in
    negotiable mode, i.e. when TA2 is absent). Anything unparseable falls
    back to a summary of the raw hex.
    """
    atr = bytes(atr)
    if len(atr) < 2 or atr[0] not in (0x3B, 0x3F):
        return AtrInfo(
            atr=atr,
            ts=atr[0] if atr else 0,
            protocols=[],
            historical=b"",
            summary=_raw_summary(atr),
        )
    ts = atr[0]
    t0 = atr[1]
    historical_count = t0 & 0x0F
    ts_seen: list[int] = []
    ta2_present = False
    y = t0 >> 4
    group = 1
    index = 2
    while y:
        needed = sum(1 for bit in range(4) if y & (1 << bit))
        if index + needed > len(atr):
            return AtrInfo(
                atr=atr,
                ts=ts,
                protocols=[],
                historical=b"",
                summary=_raw_summary(atr),
            )
        td_value: Optional[int] = None
        for bit in range(4):
            if not y & (1 << bit):
                continue
            value = atr[index]
            index += 1
            if bit == 3:
                td_value = value
            elif group == 2 and bit == 0:
                ta2_present = True
        group += 1
        if td_value is None:
            break
        ts_seen.append(td_value & 0x0F)
        y = td_value >> 4
    if index + historical_count <= len(atr):
        historical = atr[index:index + historical_count]
    else:
        historical = atr[index:]
    if not ts_seen:
        protocols = ["T=0"]
    else:
        protocols = []
        for protocol in ts_seen:
            name = "T=15 (proprietary)" if protocol == 15 else f"T={protocol}"
            if name not in protocols:
                protocols.append(name)
        if 0 not in ts_seen and 15 not in ts_seen and not ta2_present:
            protocols.insert(0, "T=0")
    historical_text = apdu.format_hex(historical) if historical else "none"
    summary = f"Protocols: {', '.join(protocols)} · Historical bytes: {historical_text}"
    return AtrInfo(
        atr=atr, ts=ts, protocols=protocols, historical=historical, summary=summary
    )


def match_known_aid(aid: bytes) -> Optional[str]:
    """Return the friendly name for the longest known AID that prefixes *aid*."""
    text = aid.hex().upper()
    for key in sorted(KNOWN_AIDS, key=len, reverse=True):
        if text.startswith(key):
            return KNOWN_AIDS[key]
    return None


def identify_card(
    session: pcsc.CardSession,
    *,
    emit: Optional[Callable[[tuple[str, str]], None]] = None,
    should_stop: Optional[Callable[[], bool]] = None,
) -> CardProfile:
    """Run the read-only identification scan and return a CardProfile.

    Never raises: card or connection failures are reported as notes on the
    returned profile. emit, when given, is called with ("progress", text)
    tuples; should_stop, when given, is checked before each major step and
    the partially built profile is returned once it turns True.
    """
    profile = CardProfile(atr=bytes(session.atr) if session.atr else b"")
    try:
        _identify(session, profile, emit, should_stop)
    except pcsc.PcscError as exc:
        profile.notes.append(f"Lost connection during identification: {exc}")
    except Exception as exc:
        profile.notes.append(f"Identification stopped early: {exc}")
    profile = _finalize(profile)
    profile.suggestions = build_suggestions(profile)
    return profile


def _identify(
    session: pcsc.CardSession,
    profile: CardProfile,
    emit: Optional[Callable[[tuple[str, str]], None]],
    should_stop: Optional[Callable[[], bool]],
) -> None:
    atr_info = parse_atr(profile.atr)
    profile.atr_summary = atr_info.summary
    profile.notes.append(atr_info.summary)
    _progress(emit, f"Reading ATR: {atr_info.summary}")
    if _stopped(should_stop):
        return
    _progress(emit, "Selecting EF.DIR, the card's application directory...")
    result = exchange.transmit_smart(session, EF_DIR_SELECT)
    if (result.sw1, result.sw2) != (0x90, 0x00):
        _probe_instead_of_efdir(session, profile, emit, should_stop)
        return
    apps, content = _read_ef_dir_apps(session, emit, should_stop)
    if not content:
        _probe_instead_of_efdir(session, profile, emit, should_stop)
        return
    profile.apps = apps


def _read_ef_dir_apps(
    session: pcsc.CardSession,
    emit: Optional[Callable[[tuple[str, str]], None]],
    should_stop: Optional[Callable[[], bool]],
) -> tuple[list[AppInfo], bytes]:
    content = bytearray()
    offset = 0
    while len(content) < MAX_DIR_BYTES:
        if _stopped(should_stop):
            break
        read_apdu = bytes([0x00, 0xB0, (offset >> 8) & 0xFF, offset & 0xFF, 0x00])
        result = exchange.transmit_smart(session, read_apdu)
        if (result.sw1, result.sw2) in ((0x6B, 0x00), (0x6A, 0x82)):
            break
        if not result.data:
            break
        content += result.data
        if len(result.data) < READ_CHUNK_SIZE:
            break
        offset = len(content)
    _progress(emit, f"Read {len(content)} byte(s) of EF.DIR.")
    apps = _apps_from_dir(bytes(content))
    _progress(emit, f"EF.DIR lists {len(apps)} application(s).")
    return apps, bytes(content)


def _probe_instead_of_efdir(
    session: pcsc.CardSession,
    profile: CardProfile,
    emit: Optional[Callable[[tuple[str, str]], None]],
    should_stop: Optional[Callable[[], bool]],
) -> None:
    profile.notes.append(
        "Card does not expose EF.DIR - probing well-known applications instead"
    )
    _progress(emit, "No EF.DIR found; probing well-known applications...")
    profile.apps = _probe_known_apps(session, emit, should_stop)


def _probe_known_apps(
    session: pcsc.CardSession,
    emit: Optional[Callable[[tuple[str, str]], None]],
    should_stop: Optional[Callable[[], bool]],
) -> list[AppInfo]:
    apps: list[AppInfo] = []
    attempts = 0
    for aid_text in sorted(KNOWN_AIDS, key=len, reverse=True):
        if attempts >= PROBE_LIMIT or _stopped(should_stop):
            break
        aid = bytes.fromhex(aid_text)
        name = KNOWN_AIDS[aid_text]
        attempts += 1
        _progress(emit, f"Probing for {name}...")
        select = bytes([0x00, 0xA4, 0x04, 0x00, len(aid)]) + aid
        result = exchange.transmit_smart(session, select)
        if (result.sw1, result.sw2) == (0x90, 0x00):
            _progress(emit, f"Found {name}.")
            apps.append(AppInfo(aid=aid, known_name=name))
            break
    return apps


def _apps_from_dir(content: bytes) -> list[AppInfo]:
    apps: list[AppInfo] = []
    seen: set[bytes] = set()
    for node in _walk(tlv.parse_tlv(content)):
        if node.tag != 0x61:
            continue
        aid = _child_value(node, 0x4F)
        if not aid or aid in seen:
            continue
        seen.add(aid)
        apps.append(
            AppInfo(
                aid=aid,
                label=_child_text(node, 0x50),
                known_name=match_known_aid(aid),
            )
        )
    return apps


def _finalize(profile: CardProfile) -> CardProfile:
    known = next((app.known_name for app in profile.apps if app.known_name), None)
    if known is not None:
        profile.label = known
    elif profile.apps:
        profile.label = f"Card with {len(profile.apps)} application(s), none recognized"
    else:
        profile.label = "Unknown card"
    profile.notes.append(f"Applications found: {len(profile.apps)}")
    profile.notes.append("Identification is a best-effort, read-only probe.")
    return profile


def build_suggestions(profile: CardProfile) -> list[str]:
    """Suggest 2-4 safe next steps for the card, in plain language.

    A pure function of the profile state. Every suggestion names a real
    app affordance (a bundled library script, a guided-builder preset, the
    Inspector's "Copy SELECT script" button or a tab), and none of them
    suggests a card-modifying command or turning safe mode off.
    """
    known_names = [
        app.known_name.lower() for app in profile.apps if app.known_name
    ]
    if any("payment" in name for name in known_names):
        return [
            "In the Console tab's guided builder, pick the GET DATA (CA) preset "
            "and read tag 9F 36, the application transaction counter - a "
            "harmless read-only counter.",
            "Run the bundled read_ef_dir script from the Script tab to list "
            "the card's applications again at your own pace.",
            "Safe mode keeps every command read-only, so trying these reads "
            "cannot change anything on the card.",
            PIN_WARNING,
        ]
    if any("openpgp" in name for name in known_names):
        return [
            "Click Copy SELECT script here in the Inspector, paste it into "
            "the Script tab and run it there to select the OpenPGP "
            "application yourself.",
            "In the Console tab's guided builder, pick the GET DATA (CA) "
            "preset and read tag 4F 82, the OpenPGP AID.",
            PIN_WARNING,
        ]
    if any("piv" in name for name in known_names):
        return [
            "Run the bundled read_ef_dir script from the Script tab to see "
            "the card's directory of applications and files.",
            "In the Console tab's guided builder, pick the GET DATA (CA) "
            "preset to explore the card with read-only GET DATA commands.",
            PIN_WARNING,
        ]
    if profile.apps:
        return [
            "Click Copy SELECT script here in the Inspector, paste it into "
            "the Script tab and run it there to select the applications the "
            "card listed.",
            "Then use the guided builder in the Console tab to explore the "
            "selected application with read-only commands.",
        ]
    return [
        "Open the Getting Started tab for a beginner-friendly walkthrough "
        "of your first safe commands.",
        "Try the bundled select_mf and read_ef_dir scripts from the Script "
        "tab to select the card's root directory and read its application "
        "directory.",
    ]


def _walk(nodes: list[tlv.Tlv]):
    for node in nodes:
        yield node
        yield from _walk(node.children)


def _child_value(node: tlv.Tlv, tag: int) -> Optional[bytes]:
    for child in node.children:
        if child.tag == tag:
            return child.value
    for child in node.children:
        found = _child_value(child, tag) if child.children else None
        if found is not None:
            return found
    return None


def _child_text(node: tlv.Tlv, tag: int) -> str:
    value = _child_value(node, tag)
    if not value:
        return ""
    return value.decode("utf-8", errors="replace")


def _progress(emit: Optional[Callable[[tuple[str, str]], None]], text: str) -> None:
    if emit is not None:
        emit(("progress", text))


def _stopped(should_stop: Optional[Callable[[], bool]]) -> bool:
    return should_stop is not None and should_stop()


def _raw_summary(atr: bytes) -> str:
    hex_text = apdu.format_hex(atr) if atr else "(none)"
    return f"Raw ATR: {hex_text} (could not parse structure)"
