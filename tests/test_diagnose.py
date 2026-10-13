"""Tests for plain-language PC/SC failure diagnosis (no Qt, no hardware)."""

from __future__ import annotations

import pytest
from smartcard.pcsc.PCSCExceptions import EstablishContextException
from smartcard.scard import SCARD_E_NO_SERVICE

from app.core import diagnose

NO_CARD_HINT = "No card in the reader. Insert a card and press Connect again."


def _raise_context_failure() -> list:
    raise EstablishContextException(SCARD_E_NO_SERVICE)


def test_service_down_when_context_cannot_be_established(monkeypatch) -> None:
    monkeypatch.setattr(diagnose, "readers", _raise_context_failure)
    assert diagnose.get_reader_status() == diagnose.STATUS_SERVICE_DOWN


def test_service_down_on_any_unexpected_failure(monkeypatch) -> None:
    def explode() -> list:
        raise RuntimeError("pcscd vanished mid-call")

    monkeypatch.setattr(diagnose, "readers", explode)
    assert diagnose.get_reader_status() == diagnose.STATUS_SERVICE_DOWN


def test_no_readers(monkeypatch) -> None:
    monkeypatch.setattr(diagnose, "readers", lambda: [])
    assert diagnose.get_reader_status() == diagnose.STATUS_NO_READERS


def test_readers_present(monkeypatch) -> None:
    monkeypatch.setattr(diagnose, "readers", lambda: ["Reader A"])
    assert diagnose.get_reader_status() == diagnose.STATUS_READERS_PRESENT


def test_describe_reader_status_distinct_and_non_empty() -> None:
    texts = [
        diagnose.describe_reader_status(status)
        for status in (
            diagnose.STATUS_SERVICE_DOWN,
            diagnose.STATUS_NO_READERS,
            diagnose.STATUS_READERS_PRESENT,
        )
    ]
    assert all(texts)
    assert len(set(texts)) == 3


def test_service_down_description_suggests_a_fix() -> None:
    text = diagnose.describe_reader_status(diagnose.STATUS_SERVICE_DOWN)
    assert "pcscd" in text or "service" in text


def test_no_readers_description_suggests_plugging_a_reader() -> None:
    text = diagnose.describe_reader_status(diagnose.STATUS_NO_READERS)
    assert "plug" in text


def test_translate_error_appends_no_card_hint() -> None:
    message = "Could not connect to a card in 'Reader A': No card. (0x8010000C)"
    translated = diagnose.translate_error(message)
    assert translated.startswith(message)
    assert translated.endswith(f" - {NO_CARD_HINT}")


def test_translate_error_is_case_insensitive() -> None:
    message = "Transmit failed: No card. (0x8010000c)"
    assert NO_CARD_HINT in diagnose.translate_error(message)


def test_translate_error_leaves_unknown_messages_unchanged() -> None:
    message = "Something entirely different went wrong."
    assert diagnose.translate_error(message) == message


def test_translate_error_uses_first_matching_hint() -> None:
    message = "Failed twice: (0x80100018) then (0x8010000C)"
    translated = diagnose.translate_error(message)
    assert translated.startswith(message)
    assert "The PC/SC service is not running." in translated
    assert NO_CARD_HINT not in translated
