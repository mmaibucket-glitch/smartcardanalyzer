"""Tests for card identification: ATR parsing, AID matching, and the probe flow."""

from __future__ import annotations

from typing import Optional

from app.core import identify, pcsc
from app.core.identify import AppInfo, CardProfile

T0_ATR = bytes.fromhex("3B044F008C23")
T1_ATR = bytes.fromhex("3B900001F0")
DUAL_ATR = bytes.fromhex("3B8281015A9377")

MASTERCARD_DIR = bytes.fromhex(
    "61154F07A0000000041010500A4D617374657263617264"
)
UNKNOWN_APP_DIR = bytes.fromhex("610D4F06D276000124015003414243")
EF_DIR_FCI = bytes.fromhex("6F0884022F0080020015")


class FakeSession:
    """Scripted stand-in for pcsc.CardSession: canned responses, recorded APDUs."""

    def __init__(
        self,
        atr: Optional[bytes] = None,
        responses: Optional[list[object]] = None,
    ) -> None:
        self.atr = atr
        self.responses: list[object] = list(responses or [])
        self.sent: list[bytes] = []

    def transmit(self, apdu: bytes) -> tuple[bytes, int, int]:
        self.sent.append(bytes(apdu))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        data, sw1, sw2 = response
        return bytes(data), sw1, sw2


def test_parse_atr_t0_only() -> None:
    info = identify.parse_atr(T0_ATR)
    assert info.ts == 0x3B
    assert info.protocols == ["T=0"]
    assert info.historical == bytes.fromhex("4F008C23")
    assert len(info.historical) == 4
    assert "Protocols: T=0" in info.summary
    assert "Historical bytes: 4F 00 8C 23" in info.summary


def test_parse_atr_t1_protocols() -> None:
    info = identify.parse_atr(T1_ATR)
    assert info.ts == 0x3B
    assert info.protocols
    assert "T=1" in info.protocols
    assert info.historical == b""
    assert "Historical bytes: none" in info.summary


def test_parse_atr_dual_protocol_historical_matches_t0_nibble() -> None:
    info = identify.parse_atr(DUAL_ATR)
    assert info.ts == 0x3B
    assert info.protocols == ["T=0", "T=1"]
    assert info.historical == bytes.fromhex("5A93")
    assert len(info.historical) == 2
    assert len(info.historical) == 0x82 & 0x0F
    assert info.protocols


def test_parse_atr_falls_back_to_raw_hex() -> None:
    for atr in (b"", bytes.fromhex("3BF0"), bytes.fromhex("1234")):
        info = identify.parse_atr(atr)
        assert "Raw ATR" in info.summary
        assert "could not parse" in info.summary
        assert info.protocols == []


def test_parse_atr_lenient_on_truncated_historical_bytes() -> None:
    info = identify.parse_atr(bytes.fromhex("3B044F00"))
    assert info.protocols == ["T=0"]
    assert info.historical == bytes.fromhex("4F00")
    assert "Protocols: T=0" in info.summary


def test_match_known_aid_longest_prefix() -> None:
    assert identify.match_known_aid(bytes.fromhex("A0000000041010")) == (
        "Mastercard (EMV payment)"
    )
    assert identify.match_known_aid(bytes.fromhex("A0000000043060")) == (
        "Maestro (EMV payment)"
    )
    assert identify.match_known_aid(bytes.fromhex("A000000004101099")) == (
        "Mastercard (EMV payment)"
    )
    assert identify.match_known_aid(bytes.fromhex("A00000000300001010")) == (
        "Visa credit/debit (EMV payment)"
    )
    assert identify.match_known_aid(bytes.fromhex("D27600012401")) is None
    assert identify.match_known_aid(bytes.fromhex("A000000004")) is None


def test_identify_efdir_flow() -> None:
    session = FakeSession(
        atr=T0_ATR,
        responses=[
            (b"", 0x61, 0x15),
            (EF_DIR_FCI, 0x90, 0x00),
            (MASTERCARD_DIR, 0x90, 0x00),
            (b"", 0x6B, 0x00),
        ],
    )
    profile = identify.identify_card(session)
    assert len(profile.apps) == 1
    assert profile.apps[0].aid == bytes.fromhex("A0000000041010")
    assert profile.apps[0].label == "Mastercard"
    assert profile.apps[0].known_name == "Mastercard (EMV payment)"
    assert profile.label == "Mastercard (EMV payment)"
    assert bytes.fromhex("00A40200022F00") in session.sent
    assert bytes.fromhex("00B0000000") in session.sent
    assert bytes.fromhex("00B0001700") not in session.sent
    assert "Applications found: 1" in profile.notes
    assert "Identification is a best-effort, read-only probe." in profile.notes


def test_identify_efdir_direct_9000_with_data() -> None:
    session = FakeSession(
        atr=T1_ATR,
        responses=[
            (EF_DIR_FCI, 0x90, 0x00),
            (UNKNOWN_APP_DIR, 0x90, 0x00),
            (b"", 0x6A, 0x82),
        ],
    )
    profile = identify.identify_card(session)
    assert len(profile.apps) == 1
    assert profile.apps[0].aid == bytes.fromhex("D27600012401")
    assert profile.apps[0].label == "ABC"
    assert profile.apps[0].known_name is None
    assert profile.label == "Card with 1 application(s), none recognized"
    assert bytes.fromhex("00B0000000") in session.sent


def test_identify_efdir_select_ok_but_unreadable_falls_back_to_probe() -> None:
    session = FakeSession(
        atr=T0_ATR,
        responses=[(EF_DIR_FCI, 0x90, 0x00)]
        + [(b"", 0x6A, 0x82)] * 5
        + [(b"", 0x90, 0x00)],
    )
    profile = identify.identify_card(session)
    assert bytes.fromhex("00B0000000") in session.sent
    assert len(profile.apps) == 1
    assert profile.apps[0].aid == bytes.fromhex("A0000000620001")
    assert profile.apps[0].known_name == "OpenPGP card"
    assert profile.label == "OpenPGP card"
    assert any(
        "does not expose EF.DIR" in note for note in profile.notes
    )
    assert "Applications found: 1" in profile.notes


def test_identify_without_efdir_probes_known_aids() -> None:
    session = FakeSession(
        atr=DUAL_ATR,
        responses=[(b"", 0x6A, 0x82)] * 5 + [(b"", 0x90, 0x00)],
    )
    profile = identify.identify_card(session)
    assert len(profile.apps) == 1
    assert profile.apps[0].aid == bytes.fromhex("A0000000620001")
    assert profile.apps[0].known_name == "OpenPGP card"
    assert profile.label == "OpenPGP card"
    assert bytes.fromhex("00A404000AA0000003080000100000") in session.sent
    assert bytes.fromhex("00A4040005A000000025") not in session.sent
    assert any(
        "does not expose EF.DIR" in note for note in profile.notes
    )
    assert "Applications found: 1" in profile.notes


def test_identify_connection_lost_returns_partial_profile() -> None:
    session = FakeSession(
        atr=T0_ATR,
        responses=[pcsc.PcscError("Card was removed")],
    )
    profile = identify.identify_card(session)
    assert any(
        "Lost connection" in note and "Card was removed" in note
        for note in profile.notes
    )
    assert profile.apps == []
    assert profile.label == "Unknown card"
    assert profile.notes[0] == identify.parse_atr(T0_ATR).summary
    assert "Identification is a best-effort, read-only probe." in profile.notes


def test_identify_stops_before_any_card_access() -> None:
    session = FakeSession(atr=T0_ATR)
    profile = identify.identify_card(session, should_stop=lambda: True)
    assert session.sent == []
    assert profile.apps == []
    assert profile.label == "Unknown card"
    assert "Applications found: 0" in profile.notes


def test_identify_emits_progress_tuples() -> None:
    events: list[tuple[str, str]] = []
    session = FakeSession(
        atr=T0_ATR,
        responses=[
            (b"", 0x61, 0x15),
            (EF_DIR_FCI, 0x90, 0x00),
            (MASTERCARD_DIR, 0x90, 0x00),
            (b"", 0x6B, 0x00),
        ],
    )
    profile = identify.identify_card(session, emit=events.append)
    assert profile.apps
    assert events
    for event in events:
        assert isinstance(event, tuple)
        assert len(event) == 2
        assert event[0] == "progress"
        assert isinstance(event[1], str)
    assert any("EF.DIR" in event[1] for event in events)


def test_identify_never_raises_on_broken_responses() -> None:
    session = FakeSession(
        atr=T0_ATR,
        responses=[
            (b"\xff\x00\x61", 0x90, 0x00),
            (b"\x4f\x7f", 0x90, 0x00),
        ],
    )
    profile = identify.identify_card(session)
    assert profile.apps == []
    assert profile.label == "Unknown card"


def test_known_aids_sanity() -> None:
    required = {
        "A0000000030000": "Visa credit/debit (EMV payment)",
        "A0000000041010": "Mastercard (EMV payment)",
        "A0000000043060": "Maestro (EMV payment)",
        "A000000025": "American Express (EMV payment)",
        "A0000000620001": "OpenPGP card",
        "A0000003080000100000": "PIV card (US Personal Identity Verification)",
        "A0000002471001": "ICAO ePassport / Machine Readable Travel Document",
    }
    for key in identify.KNOWN_AIDS:
        assert key == key.upper()
        assert len(key) % 2 == 0
        assert 10 <= len(key) <= 32
        int(key, 16)
    for key, name in required.items():
        assert identify.KNOWN_AIDS.get(key) == name


def _profile_with_known_name(known_name: str) -> CardProfile:
    return CardProfile(
        atr=b"",
        apps=[AppInfo(aid=bytes.fromhex("AABBCC"), known_name=known_name)],
    )


ALL_SUGGESTION_PROFILES = [
    _profile_with_known_name("Visa credit/debit (EMV payment)"),
    _profile_with_known_name("OpenPGP card"),
    _profile_with_known_name("PIV card (US Personal Identity Verification)"),
    _profile_with_known_name("ICAO ePassport / Machine Readable Travel Document"),
    CardProfile(
        atr=b"",
        apps=[AppInfo(aid=bytes.fromhex("D27600012401"), label="ABC")],
    ),
    CardProfile(atr=b""),
]

WRITE_PHRASES = (
    "PUT DATA",
    "PUT DATA (odd INS)",
    "UPDATE",
    "ERASE",
    "RESET RETRY",
    "CHANGE REFERENCE DATA",
    "DEACTIVATE",
    "disable safe mode",
    "safe mode off",
)


def test_build_suggestions_payment_mentions_get_data_and_pin_warning() -> None:
    suggestions = identify.build_suggestions(
        _profile_with_known_name("Mastercard (EMV payment)")
    )
    assert any("GET DATA (CA)" in item for item in suggestions)
    assert any("9F 36" in item for item in suggestions)
    assert any("read_ef_dir" in item for item in suggestions)
    assert any(item == identify.PIN_WARNING for item in suggestions)


def test_build_suggestions_openpgp_mentions_copy_select_and_4f82() -> None:
    suggestions = identify.build_suggestions(_profile_with_known_name("OpenPGP card"))
    assert any("Copy SELECT script" in item for item in suggestions)
    assert any("Script tab" in item for item in suggestions)
    assert any("GET DATA (CA)" in item for item in suggestions)
    assert any("4F 82" in item for item in suggestions)
    assert any(item == identify.PIN_WARNING for item in suggestions)


def test_build_suggestions_piv_mentions_read_ef_dir_and_builder() -> None:
    suggestions = identify.build_suggestions(
        _profile_with_known_name("PIV card (US Personal Identity Verification)")
    )
    assert any("read_ef_dir" in item for item in suggestions)
    assert any("GET DATA (CA)" in item for item in suggestions)
    assert any("Script tab" in item for item in suggestions)
    assert any(item == identify.PIN_WARNING for item in suggestions)


def test_build_suggestions_unknown_with_apps_mentions_copy_select_script() -> None:
    profile = CardProfile(
        atr=b"", apps=[AppInfo(aid=bytes.fromhex("D27600012401"), label="ABC")]
    )
    suggestions = identify.build_suggestions(profile)
    assert any("Copy SELECT script" in item for item in suggestions)
    assert any("Script tab" in item for item in suggestions)
    assert any("guided builder" in item for item in suggestions)


def test_build_suggestions_empty_profile_points_to_getting_started() -> None:
    suggestions = identify.build_suggestions(CardProfile(atr=b""))
    assert any("Getting Started" in item for item in suggestions)
    assert any("select_mf" in item for item in suggestions)
    assert any("read_ef_dir" in item for item in suggestions)


def test_build_suggestions_shape_is_two_to_four_nonempty_sentences() -> None:
    for profile in ALL_SUGGESTION_PROFILES:
        suggestions = identify.build_suggestions(profile)
        assert 2 <= len(suggestions) <= 4
        for item in suggestions:
            assert item.strip() == item
            assert item[0].isupper()
            assert item.rstrip().endswith((".", "!", "?"))


def test_build_suggestions_never_suggest_writes_or_unsafe_mode() -> None:
    for profile in ALL_SUGGESTION_PROFILES:
        for item in identify.build_suggestions(profile):
            lowered = item.lower()
            for phrase in WRITE_PHRASES:
                assert phrase.lower() not in lowered


def test_build_suggestions_is_pure_function_of_profile_state() -> None:
    profile = _profile_with_known_name("Mastercard (EMV payment)")
    first = identify.build_suggestions(profile)
    assert first == identify.build_suggestions(profile)
    assert profile.suggestions == []


def test_card_profile_suggestions_field_defaults_to_empty() -> None:
    profile = CardProfile(atr=T0_ATR)
    assert profile.suggestions == []


def test_identify_efdir_profile_carries_suggestions() -> None:
    session = FakeSession(
        atr=T0_ATR,
        responses=[
            (b"", 0x61, 0x15),
            (EF_DIR_FCI, 0x90, 0x00),
            (MASTERCARD_DIR, 0x90, 0x00),
            (b"", 0x6B, 0x00),
        ],
    )
    profile = identify.identify_card(session)
    assert profile.suggestions
    assert any("GET DATA (CA)" in item for item in profile.suggestions)
    assert any(item == identify.PIN_WARNING for item in profile.suggestions)


def test_identify_probe_path_carries_suggestions() -> None:
    session = FakeSession(
        atr=DUAL_ATR,
        responses=[(b"", 0x6A, 0x82)] * 5 + [(b"", 0x90, 0x00)],
    )
    profile = identify.identify_card(session)
    assert profile.suggestions
    assert any("Copy SELECT script" in item for item in profile.suggestions)
    assert any("GET DATA (CA)" in item for item in profile.suggestions)


def test_identify_connection_lost_profile_still_has_suggestions() -> None:
    session = FakeSession(
        atr=T0_ATR,
        responses=[pcsc.PcscError("Card was removed")],
    )
    profile = identify.identify_card(session)
    assert 2 <= len(profile.suggestions) <= 4
    assert any("Getting Started" in item for item in profile.suggestions)
