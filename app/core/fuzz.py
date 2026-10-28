"""APDU fuzzing against a connected card: mutation and protocol-aware modes.

Mutation mode corrupts a seed APDU with strategies such as bit flips and
boundary values. Protocol-aware mode ignores the seed and generates
well-formed commands from a pool of known instruction codes. Safe mode skips
instruction codes classified as card-modifying; authentication and unknown
commands remain available in mutation mode.

WARNING: fuzzing sends APDUs to a real card and can trigger state changes on
some cards (e.g. burning verification-failure counters or writing
non-volatile memory). Only fuzz cards that may safely be reset.
"""

from __future__ import annotations

import random
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

from app.core import apdu, pcsc, safety

MAX_APDU_LENGTH = 261
BOUNDARY_BYTES = (0x00, 0xFF, 0x7F, 0x80)
COMMON_PARAMETERS = (0x00, 0x01, 0x02, 0x04)
SW_NOTABLE_EXCLUDED = {"9000", "6D00", "6E00", "6700", "6A86", "6A87"}

READ_ONLY_INS_POOL: list[int] = sorted(
    ins
    for ins in safety.INSTRUCTION_NAMES
    if safety.classify_apdu(bytes((0x00, ins)))[0] == "read"
)

Strategy = Callable[[random.Random, bytes], bytes]


def bit_flip(rng: random.Random, apdu: bytes) -> bytes:
    """Flip 1-4 random bits anywhere in the APDU."""
    data = bytearray(apdu)
    if not data:
        return bytes(data)
    for _ in range(rng.randint(1, 4)):
        data[rng.randrange(len(data))] ^= 1 << rng.randrange(8)
    return bytes(data)


def byte_set(rng: random.Random, apdu: bytes) -> bytes:
    """Set 1-3 random bytes to 0x00, 0xFF or a random value."""
    data = bytearray(apdu)
    if not data:
        return bytes(data)
    for _ in range(rng.randint(1, 3)):
        index = rng.randrange(len(data))
        value = rng.choice((0x00, 0xFF, None))
        data[index] = rng.randrange(256) if value is None else value
    return bytes(data)


def append(rng: random.Random, apdu: bytes) -> bytes:
    """Append 1-8 random bytes, capping total length at 261."""
    extra = bytes(rng.randrange(256) for _ in range(rng.randint(1, 8)))
    return (apdu + extra)[:MAX_APDU_LENGTH]


def truncate(rng: random.Random, apdu: bytes) -> bytes:
    """Remove 1-4 trailing bytes, never going below the 4-byte header."""
    if len(apdu) <= 4:
        return apdu
    return apdu[: max(4, len(apdu) - rng.randint(1, 4))]


def header_tamper(rng: random.Random, apdu: bytes) -> bytes:
    """Replace P1, P2 and/or Lc with random or boundary values; length unchanged."""
    if len(apdu) < 5:
        return apdu
    data = bytearray(apdu)
    for index in rng.sample((2, 3, 4), rng.randint(1, 3)):
        value = rng.choice((0x00, 0xFF, None))
        data[index] = rng.randrange(256) if value is None else value
    return bytes(data)


def boundary_fill(rng: random.Random, apdu: bytes) -> bytes:
    """Replace 1-4 data bytes at index >= 5 with boundary values."""
    if len(apdu) <= 5:
        return apdu
    data = bytearray(apdu)
    for _ in range(rng.randint(1, 4)):
        data[rng.randint(5, len(data) - 1)] = rng.choice(BOUNDARY_BYTES)
    return bytes(data)


STRATEGIES: dict[str, Strategy] = {
    "bit_flip": bit_flip,
    "byte_set": byte_set,
    "append": append,
    "truncate": truncate,
    "header_tamper": header_tamper,
    "boundary_fill": boundary_fill,
}


@dataclass
class FuzzConfig:
    """Settings for one fuzzing run against the connected card.

    In mutation mode ``seed_apdu`` is corrupted with the configured
    strategies. With ``protocol_aware`` set, well-formed commands are
    generated from ``ins_pool`` instead and ``seed_apdu`` is ignored.
    """

    seed_apdu: bytes
    iterations: int = 100
    strategies: list[str] = field(default_factory=lambda: list(STRATEGIES))
    seed: int = 0
    protocol_aware: bool = False
    ins_pool: list[int] = field(default_factory=lambda: list(READ_ONLY_INS_POOL))


def _protocol_aware_case(rng: random.Random, ins_pool: list[int]) -> bytes:
    """Build one well-formed command from the instruction pool.

    CLA is always 0x00. Data (1-16 bytes) and Le are each included with about
    50% probability; when neither is selected, Le is appended so every case
    is at least five bytes long.
    """
    ins = rng.choice(ins_pool)
    p1 = rng.choice(COMMON_PARAMETERS) if rng.random() < 0.5 else rng.randrange(256)
    p2 = rng.choice(COMMON_PARAMETERS) if rng.random() < 0.5 else rng.randrange(256)
    data = b""
    if rng.random() < 0.5:
        data = bytes(rng.randrange(256) for _ in range(rng.randint(1, 16)))
    case = bytes([0x00, ins, p1, p2])
    if data:
        case += bytes([len(data)]) + data
    if rng.random() < 0.5 or not data:
        le_choices = [0x00, 0x08, 0x10, 0xFF, rng.randint(1, 255)]
        case += bytes([rng.choice(le_choices)])
    return case


def generate_cases(config: FuzzConfig) -> Iterator[bytes]:
    """Yield fuzzing cases deterministically: same config, same cases.

    In mutation mode the seed APDU is corrupted with the configured
    strategies. In protocol-aware mode the seed is ignored and well-formed
    commands are generated from ``config.ins_pool`` (falling back to the
    read-only pool when that is empty).
    """
    if config.protocol_aware:
        pool = config.ins_pool or list(READ_ONLY_INS_POOL)
        rng = random.Random(config.seed)
        for _ in range(config.iterations):
            yield _protocol_aware_case(rng, pool)
        return
    rng = random.Random(config.seed)
    names = [name for name in config.strategies if name in STRATEGIES]
    if not names:
        return
    for index in range(config.iterations):
        strategy = STRATEGIES[names[index % len(names)]]
        yield strategy(rng, config.seed_apdu)


def run_fuzz(
    session: pcsc.CardSession,
    config: FuzzConfig,
    *,
    emit: Callable[..., None],
    should_stop: Callable[[], bool],
    delay_ms: int = 50,
    safe_mode: bool = False,
) -> dict[str, object]:
    """Fuzz the session with mutated cases, reporting progress via emit.

    emit receives ("case", index, total, tx_hex, sw, description) per case,
    ("skipped", index, total, tx_hex) when safe mode blocks a case before it
    is sent, ("notable", index, tx_hex, sw, description) for noteworthy
    status words and ("error", message) when the card or reader disappears.

    With ``safe_mode`` True, card-modifying cases are never transmitted:
    each blocked case is reported via the skipped event and counted in the
    returned summary under ``"skipped"``.
    """
    cases = list(generate_cases(config))
    total = len(cases)
    sent = 0
    skipped = 0
    sw_counts: dict[str, int] = {}
    notable: list[tuple[str, str, str]] = []
    stopped = False
    for index, case in enumerate(cases):
        if should_stop():
            stopped = True
            break
        if safe_mode and safety.blocked_reason(case, True) is not None:
            skipped += 1
            emit("skipped", index, total, apdu.format_hex(case))
            continue
        try:
            _, sw1, sw2 = session.transmit(case)
        except pcsc.PcscError as exc:
            emit("error", str(exc))
            break
        sent += 1
        sw = f"{sw1:02X}{sw2:02X}"
        description = apdu.describe_sw(sw1, sw2)
        sw_counts[sw] = sw_counts.get(sw, 0) + 1
        emit("case", index, total, apdu.format_hex(case), sw, description)
        if sw not in SW_NOTABLE_EXCLUDED:
            notable.append((apdu.format_hex(case), sw, description))
            emit("notable", index, apdu.format_hex(case), sw, description)
        if delay_ms > 0:
            _interruptible_delay(delay_ms, should_stop)
    return {
        "sent": sent,
        "skipped": skipped,
        "sw_counts": sw_counts,
        "notable": notable,
        "stopped": stopped,
    }


def _interruptible_delay(delay_ms: int, should_stop: Callable[[], bool]) -> None:
    remaining = delay_ms / 1000
    while remaining > 0 and not should_stop():
        interval = min(remaining, 0.05)
        time.sleep(interval)
        remaining -= interval
