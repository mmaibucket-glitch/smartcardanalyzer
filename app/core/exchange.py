"""Smart APDU exchange: automatic GET RESPONSE chaining and Le retry."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

MAX_AUTO_FOLLOWUPS = 8


@dataclass
class ExchangeResult:
    apdu: bytes
    data: bytes
    sw1: int
    sw2: int
    exchanges: list[tuple[bytes, bytes, int, int]] = field(default_factory=list)

    @property
    def followed_up(self) -> bool:
        return len(self.exchanges) > 1


def transmit_smart(
    session,
    apdu: bytes,
    *,
    max_followups: int = MAX_AUTO_FOLLOWUPS,
    on_step: Optional[Callable[[bytes, bytes, int, int], None]] = None,
) -> ExchangeResult:
    """Transmit one APDU and act on the status words.

    After a 61XX status, GET RESPONSE (00 C0 00 00 XX) is chained automatically
    and the response data is accumulated. After a 6CXX status, the original
    command is resent once with the requested Le; for 5-byte APDUs the fifth
    byte is treated as Le (case 2) and replaced. Other status words end the
    exchange unchanged. Each transmit is reported via on_step(apdu, data, sw1,
    sw2). Only simple (one-byte) Lc/Le encodings are handled.
    """
    result = ExchangeResult(apdu=bytes(apdu), data=b"", sw1=0x00, sw2=0x00)
    current = bytes(apdu)
    for _ in range(max_followups + 1):
        data, sw1, sw2 = session.transmit(current)
        result.exchanges.append((current, data, sw1, sw2))
        if on_step is not None:
            on_step(current, data, sw1, sw2)
        if sw1 == 0x6C:
            current = _with_le(current, sw2)
            continue
        result.data += data
        result.sw1, result.sw2 = sw1, sw2
        if sw1 != 0x61:
            return result
        current = bytes([0x00, 0xC0, 0x00, 0x00, sw2])
    return result


def _with_le(apdu: bytes, le: int) -> bytes:
    if len(apdu) == 4:
        return apdu + bytes([le])
    if len(apdu) == 5:
        return apdu[:-1] + bytes([le])
    lc = apdu[4]
    if len(apdu) == 5 + lc:
        return apdu + bytes([le])
    return apdu[:-1] + bytes([le])
