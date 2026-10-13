"""PC/SC reader enumeration and card sessions built on pyscard."""

from __future__ import annotations

from typing import Optional

from smartcard.CardConnection import CardConnection
from smartcard.Exceptions import SmartcardException
from smartcard.System import readers

from app.core import diagnose


class PcscError(Exception):
    """A PC/SC reader or card communication failure with a user-presentable message."""


def list_readers() -> list[str]:
    """Return the names of all PC/SC readers currently attached to the system."""
    try:
        return [str(reader) for reader in readers()]
    except SmartcardException:
        return []


class CardSession:
    """A connection to the card inserted in one named reader."""

    def __init__(self, reader_name: str) -> None:
        self._reader_name = reader_name
        self._connection: Optional[CardConnection] = None
        self.atr: Optional[bytes] = None

    @property
    def reader_name(self) -> str:
        return self._reader_name

    @property
    def connected(self) -> bool:
        return self._connection is not None

    def connect(self) -> bytes:
        """Connect to the card in the reader and return its ATR."""
        if self._connection is not None:
            raise PcscError(f"Already connected to '{self._reader_name}'.")
        connection = self._find_reader(self._reader_name).createConnection()
        try:
            connection.connect()
            atr = connection.getAtr()
        except SmartcardException as exc:
            raise PcscError(
                diagnose.translate_error(
                    f"Could not connect to a card in '{self._reader_name}': {exc}"
                )
            ) from exc
        self._connection = connection
        self.atr = bytes(atr)
        return self.atr

    def transmit(self, apdu: bytes) -> tuple[bytes, int, int]:
        """Send one APDU and return (response data, SW1, SW2)."""
        if self._connection is None:
            raise PcscError("Not connected to a card.")
        try:
            data, sw1, sw2 = self._connection.transmit(bytes(apdu))
        except SmartcardException as exc:
            raise PcscError(f"Transmit failed: {exc}") from exc
        return bytes(data), sw1, sw2

    def disconnect(self) -> None:
        if self._connection is None:
            return
        try:
            self._connection.disconnect()
        except SmartcardException:
            pass
        self._connection = None
        self.atr = None

    def _find_reader(self, name: str):
        for reader in readers():
            if str(reader) == name:
                return reader
        raise PcscError(f"Reader '{name}' is no longer available.")

    def __enter__(self) -> "CardSession":
        self.connect()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.disconnect()
