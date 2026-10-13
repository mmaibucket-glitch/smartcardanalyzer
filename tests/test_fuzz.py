"""Tests for APDU fuzzing: determinism, mutation bounds, and run bookkeeping."""

from __future__ import annotations

from app.core import fuzz, pcsc, safety

SEED_APDU = bytes.fromhex("00A4040007A0000000041010")
WRITE_SEED_APDU = bytes.fromhex("00D6000004DEADBEEF")


class FakeSession:
    """Duck-typed CardSession returning pre-programmed status words in rotation."""

    def __init__(self, responses: list[tuple[bytes, int, int]]) -> None:
        self.responses = responses
        self.sent: list[bytes] = []
        self._next = 0

    def transmit(self, apdu: bytes) -> tuple[bytes, int, int]:
        self.sent.append(apdu)
        response = self.responses[self._next % len(self.responses)]
        self._next += 1
        return response


class FailingSession:
    """Duck-typed CardSession whose transmit always raises PcscError."""

    def __init__(self) -> None:
        self.sent: list[bytes] = []

    def transmit(self, apdu: bytes) -> tuple[bytes, int, int]:
        self.sent.append(apdu)
        raise pcsc.PcscError("Transmit failed: reader gone")


def test_generate_cases_is_deterministic() -> None:
    config = fuzz.FuzzConfig(seed_apdu=SEED_APDU, iterations=25, seed=42)
    first = list(fuzz.generate_cases(config))
    second = list(fuzz.generate_cases(config))
    assert first == second


def test_generate_cases_is_deterministic_with_strategies() -> None:
    config = fuzz.FuzzConfig(
        seed_apdu=SEED_APDU, iterations=15, strategies=["byte_set", "truncate"], seed=7
    )
    first = list(fuzz.generate_cases(config))
    second = list(fuzz.generate_cases(config))
    assert first == second


def test_cases_are_bytes_within_bounds() -> None:
    config = fuzz.FuzzConfig(seed_apdu=SEED_APDU, iterations=200, seed=7)
    for case in fuzz.generate_cases(config):
        assert isinstance(case, bytes)
        assert 4 <= len(case) <= 261


def test_append_caps_total_length() -> None:
    long_seed = bytes(range(256)) + b"\x01\x02\x03\x04"
    config = fuzz.FuzzConfig(
        seed_apdu=long_seed, iterations=50, strategies=["append"], seed=1
    )
    cases = list(fuzz.generate_cases(config))
    assert all(len(case) <= 261 for case in cases)
    assert any(len(case) == 261 for case in cases)


def test_truncate_never_below_header() -> None:
    short = bytes.fromhex("00A4040008")
    config = fuzz.FuzzConfig(
        seed_apdu=short, iterations=50, strategies=["truncate"], seed=5
    )
    cases = list(fuzz.generate_cases(config))
    assert all(4 <= len(case) <= len(short) for case in cases)


def test_truncate_leaves_short_apdu_unchanged() -> None:
    header = bytes.fromhex("00A40400")
    config = fuzz.FuzzConfig(
        seed_apdu=header, iterations=20, strategies=["truncate"], seed=5
    )
    assert all(case == header for case in fuzz.generate_cases(config))


def test_header_tamper_preserves_length_and_class() -> None:
    config = fuzz.FuzzConfig(
        seed_apdu=SEED_APDU, iterations=50, strategies=["header_tamper"], seed=11
    )
    for case in fuzz.generate_cases(config):
        assert len(case) == len(SEED_APDU)
        assert case[0] == SEED_APDU[0]
        assert case[1] == SEED_APDU[1]


def test_header_tamper_leaves_short_apdu_unchanged() -> None:
    header = bytes.fromhex("00A404")
    config = fuzz.FuzzConfig(
        seed_apdu=header, iterations=20, strategies=["header_tamper"], seed=2
    )
    assert all(case == header for case in fuzz.generate_cases(config))


def test_boundary_fill_only_touches_data_bytes() -> None:
    config = fuzz.FuzzConfig(
        seed_apdu=SEED_APDU, iterations=50, strategies=["boundary_fill"], seed=11
    )
    for case in fuzz.generate_cases(config):
        assert len(case) == len(SEED_APDU)
        assert case[:5] == SEED_APDU[:5]
        assert all(
            original == mutated or mutated in (0x00, 0xFF, 0x7F, 0x80)
            for original, mutated in zip(SEED_APDU[5:], case[5:])
        )


def test_boundary_fill_leaves_short_apdu_unchanged() -> None:
    short = bytes.fromhex("00A4040008")
    config = fuzz.FuzzConfig(
        seed_apdu=short, iterations=20, strategies=["boundary_fill"], seed=2
    )
    assert all(case == short for case in fuzz.generate_cases(config))


def test_generated_cases_differ_from_seed() -> None:
    config = fuzz.FuzzConfig(seed_apdu=SEED_APDU, iterations=50, seed=3)
    cases = list(fuzz.generate_cases(config))
    assert any(case != SEED_APDU for case in cases)


def test_run_fuzz_counts_and_notable() -> None:
    session = FakeSession([(b"", 0x90, 0x00), (b"", 0x6A, 0x82)])
    config = fuzz.FuzzConfig(seed_apdu=SEED_APDU, iterations=10, seed=1)
    events: list[tuple[object, ...]] = []
    result = fuzz.run_fuzz(
        session,
        config,
        emit=lambda *args: events.append(args),
        should_stop=lambda: False,
        delay_ms=0,
    )
    assert result["sent"] == 10
    assert sum(result["sw_counts"].values()) == 10
    assert result["sw_counts"] == {"9000": 5, "6A82": 5}
    notable_sws = [sw for _, sw, _ in result["notable"]]
    assert "6A82" in notable_sws
    assert "9000" not in notable_sws
    assert result["stopped"] is False
    assert len(session.sent) == 10
    assert [event[0] for event in events].count("notable") == 5


def test_run_fuzz_stops_early() -> None:
    session = FakeSession([(b"", 0x90, 0x00)])
    config = fuzz.FuzzConfig(seed_apdu=SEED_APDU, iterations=20, seed=1)
    checks = {"count": 0}

    def should_stop() -> bool:
        checks["count"] += 1
        return checks["count"] > 3

    result = fuzz.run_fuzz(
        session,
        config,
        emit=lambda *args: None,
        should_stop=should_stop,
        delay_ms=0,
    )
    assert result["sent"] == 3
    assert result["sent"] < 20
    assert result["stopped"] is True


def test_run_fuzz_reports_pcsc_error_and_stops() -> None:
    session = FailingSession()
    config = fuzz.FuzzConfig(seed_apdu=SEED_APDU, iterations=10, seed=1)
    events: list[tuple[object, ...]] = []
    result = fuzz.run_fuzz(
        session,
        config,
        emit=lambda *args: events.append(args),
        should_stop=lambda: False,
        delay_ms=0,
    )
    assert result["sent"] == 0
    assert result["stopped"] is False
    assert len(session.sent) == 1
    assert len(events) == 1
    assert events[0][0] == "error"
    assert "reader gone" in events[0][1]


def test_run_fuzz_safe_mode_skips_card_modifying_cases() -> None:
    session = FakeSession([(b"", 0x90, 0x00)])
    config = fuzz.FuzzConfig(
        seed_apdu=WRITE_SEED_APDU, iterations=3, strategies=["append"], seed=1
    )
    events: list[tuple[object, ...]] = []
    result = fuzz.run_fuzz(
        session,
        config,
        emit=lambda *args: events.append(args),
        should_stop=lambda: False,
        delay_ms=0,
        safe_mode=True,
    )
    assert result["sent"] == 0
    assert result["skipped"] == 3
    assert session.sent == []
    assert [event[0] for event in events].count("skipped") == 3


def test_run_fuzz_without_safe_mode_sends_card_modifying_cases() -> None:
    session = FakeSession([(b"", 0x90, 0x00)])
    config = fuzz.FuzzConfig(
        seed_apdu=WRITE_SEED_APDU, iterations=3, strategies=["append"], seed=1
    )
    result = fuzz.run_fuzz(
        session,
        config,
        emit=lambda *args: None,
        should_stop=lambda: False,
        delay_ms=0,
    )
    assert result["sent"] == 3
    assert result["skipped"] == 0
    assert len(session.sent) == 3


def test_read_only_ins_pool_classifies_as_read() -> None:
    assert fuzz.READ_ONLY_INS_POOL == sorted(fuzz.READ_ONLY_INS_POOL)
    for ins in fuzz.READ_ONLY_INS_POOL:
        category, _ = safety.classify_apdu(bytes([0x00, ins]))
        assert category == "read"


def test_fuzz_config_defaults_keep_mutation_mode() -> None:
    config = fuzz.FuzzConfig(seed_apdu=SEED_APDU)
    assert config.protocol_aware is False
    assert config.ins_pool == list(fuzz.READ_ONLY_INS_POOL)


def test_default_ins_pool_is_independent_copy() -> None:
    config = fuzz.FuzzConfig(seed_apdu=SEED_APDU)
    config.ins_pool.append(0x99)
    assert 0x99 not in fuzz.READ_ONLY_INS_POOL


def test_protocol_aware_cases_are_deterministic() -> None:
    config = fuzz.FuzzConfig(
        seed_apdu=SEED_APDU, iterations=60, seed=42, protocol_aware=True
    )
    first = list(fuzz.generate_cases(config))
    second = list(fuzz.generate_cases(config))
    assert first == second


def test_protocol_aware_cases_ignore_seed_apdu() -> None:
    first = fuzz.FuzzConfig(
        seed_apdu=SEED_APDU, iterations=40, seed=9, protocol_aware=True
    )
    second = fuzz.FuzzConfig(
        seed_apdu=b"\xff" * 12, iterations=40, seed=9, protocol_aware=True
    )
    assert list(fuzz.generate_cases(first)) == list(fuzz.generate_cases(second))


def test_protocol_aware_cases_use_pool_and_stay_well_formed() -> None:
    pool = [0xB0, 0xA4, 0xCA]
    config = fuzz.FuzzConfig(
        seed_apdu=b"", iterations=300, seed=3, protocol_aware=True, ins_pool=pool
    )
    cases = list(fuzz.generate_cases(config))
    assert len(cases) == 300
    for case in cases:
        assert case[0] == 0x00
        assert case[1] in pool
        assert 5 <= len(case) <= 261


def test_run_fuzz_sends_protocol_aware_cases() -> None:
    session = FakeSession([(b"", 0x90, 0x00)])
    config = fuzz.FuzzConfig(
        seed_apdu=b"", iterations=5, seed=1, protocol_aware=True
    )
    result = fuzz.run_fuzz(
        session,
        config,
        emit=lambda *args: None,
        should_stop=lambda: False,
        delay_ms=0,
    )
    assert result["sent"] == 5
    assert all(case[0] == 0x00 and 5 <= len(case) <= 261 for case in session.sent)
