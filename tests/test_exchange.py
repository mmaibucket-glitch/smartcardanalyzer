"""Tests for the smart exchange logic (no hardware, no Qt)."""

from __future__ import annotations

import pytest

from app.core import exchange
from app.core.exchange import transmit_smart


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.sent = []

    def transmit(self, apdu):
        self.sent.append(bytes(apdu))
        return self.responses.pop(0)


def test_plain_exchange_passthrough():
    session = FakeSession([(b"\x61\x01", 0x90, 0x00)])
    result = transmit_smart(session, bytes.fromhex("00A40000"))
    assert result.data == b"\x61\x01"
    assert (result.sw1, result.sw2) == (0x90, 0x00)
    assert not result.followed_up
    assert session.sent == [bytes.fromhex("00A40000")]


def test_get_response_chaining_accumulates_data():
    session = FakeSession(
        [
            (b"AB", 0x61, 0x02),
            (b"CD", 0x61, 0x01),
            (b"EF", 0x90, 0x00),
        ]
    )
    result = transmit_smart(session, bytes.fromhex("00B0000010"))
    assert result.data == b"ABCDEF"
    assert (result.sw1, result.sw2) == (0x90, 0x00)
    assert result.followed_up
    assert session.sent[1] == bytes.fromhex("00C0000002")
    assert session.sent[2] == bytes.fromhex("00C0000001")


def test_le_retry_appends_when_missing():
    session = FakeSession(
        [
            (b"", 0x6C, 0x20),
            (b"XY", 0x90, 0x00),
        ]
    )
    result = transmit_smart(session, bytes.fromhex("00B00000"))
    assert session.sent[1] == bytes.fromhex("00B0000020")
    assert result.data == b"XY"


def test_le_retry_replaces_existing_le():
    session = FakeSession(
        [
            (b"", 0x6C, 0x40),
            (b"Z", 0x90, 0x00),
        ]
    )
    result = transmit_smart(session, bytes.fromhex("00B0000010"))
    assert session.sent[1] == bytes.fromhex("00B0000040")
    assert result.data == b"Z"


def test_le_retry_after_command_with_data():
    session = FakeSession(
        [
            (b"", 0x6C, 0x08),
            (b"Q", 0x90, 0x00),
        ]
    )
    result = transmit_smart(session, bytes.fromhex("00CA006F00"))
    assert session.sent[1] == bytes.fromhex("00CA006F08")
    assert result.data == b"Q"


def test_on_step_called_for_every_transmit():
    session = FakeSession(
        [
            (b"A", 0x61, 0x01),
            (b"B", 0x90, 0x00),
        ]
    )
    steps = []
    transmit_smart(session, bytes.fromhex("00A40000"), on_step=lambda *s: steps.append(s))
    assert len(steps) == 2
    assert steps[0][2:] == (0x61, 0x01)
    assert steps[1][2:] == (0x90, 0x00)


def test_max_followups_cap():
    session = FakeSession([(b"", 0x61, 0x01)] * (exchange.MAX_AUTO_FOLLOWUPS + 5))
    result = transmit_smart(session, bytes.fromhex("00A40000"))
    assert len(result.exchanges) == exchange.MAX_AUTO_FOLLOWUPS + 1
    assert (result.sw1, result.sw2) == (0x61, 0x01)


def test_errors_propagate():
    from app.core import pcsc

    class ErrorSession:
        def transmit(self, apdu):
            raise pcsc.PcscError("Transmit failed")

    with pytest.raises(pcsc.PcscError):
        transmit_smart(ErrorSession(), bytes.fromhex("00A40000"))
