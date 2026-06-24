"""Tests for the DRBG and threshold ECDSA module."""

import secrets

import pytest

from src.crypto.drbg import (
    DRBG,
    SECP256K1_ORDER,
    ThresholdECDSANode,
    TransportPayload,
    extract_seed_from_payload,
)


# ---------------------------------------------------------------------------
# DRBG core tests
# ---------------------------------------------------------------------------


class TestDRBG:
    def test_seed_length_validation(self):
        with pytest.raises(ValueError, match="32 bytes"):
            DRBG(b"short")

    def test_deterministic_output(self):
        seed = secrets.token_bytes(32)
        a = DRBG(seed)
        b = DRBG(seed)
        for _ in range(10):
            assert a.generate(SECP256K1_ORDER) == b.generate(SECP256K1_ORDER)

    def test_different_seeds_different_output(self):
        a = DRBG(b"\x00" * 32)
        b = DRBG(b"\x01" * 32)
        assert a.generate(SECP256K1_ORDER) != b.generate(SECP256K1_ORDER)

    def test_output_bounded_by_modulus(self):
        drbg = DRBG(secrets.token_bytes(32))
        for _ in range(50):
            val = drbg.generate(SECP256K1_ORDER)
            assert 0 <= val < SECP256K1_ORDER

    def test_generate_blinding_factor_within_range(self):
        drbg = DRBG(secrets.token_bytes(32))
        for _ in range(20):
            v = drbg.generate_blinding_factor()
            assert 0 <= v < SECP256K1_ORDER

    def test_small_modulus(self):
        drbg = DRBG(secrets.token_bytes(32))
        for _ in range(100):
            assert 0 <= drbg.generate(7) < 7

    def test_counter_increments(self):
        drbg = DRBG(secrets.token_bytes(32))
        assert drbg._counter == 0
        drbg.generate(100)
        assert drbg._counter == 1
        drbg.generate(100)
        assert drbg._counter == 2


# ---------------------------------------------------------------------------
# ThresholdECDSANode tests
# ---------------------------------------------------------------------------


class TestThresholdECDSANode:
    def test_invalid_key_share_zero(self):
        with pytest.raises(ValueError, match="Key share"):
            ThresholdECDSANode(0)

    def test_invalid_key_share_at_order(self):
        with pytest.raises(ValueError, match="Key share"):
            ThresholdECDSANode(SECP256K1_ORDER)

    def test_invalid_key_share_negative(self):
        with pytest.raises(ValueError, match="Key share"):
            ThresholdECDSANode(-1)

    def test_produce_masked_share(self):
        node = ThresholdECDSANode(42)
        share = node.produce_masked_share()
        assert 0 <= share.value < SECP256K1_ORDER
        assert 0 <= share.blinding_factor < SECP256K1_ORDER

    def test_masked_share_differs_from_key(self):
        key = 123456789
        node = ThresholdECDSANode(key)
        share = node.produce_masked_share()
        # With overwhelming probability the masked value differs from the key
        assert share.value != key

    def test_recovery_roundtrip(self):
        key = 987654321
        node = ThresholdECDSANode(key)
        share = node.produce_masked_share()
        recovered = ThresholdECDSANode.recover_key_share(
            share.value, share.blinding_factor
        )
        assert recovered == key

    def test_recovery_modular_wrap(self):
        """Key share close to curve order triggers modular wrap."""
        key = SECP256K1_ORDER - 1
        node = ThresholdECDSANode(key)
        share = node.produce_masked_share()
        recovered = ThresholdECDSANode.recover_key_share(
            share.value, share.blinding_factor
        )
        assert recovered == key

    def test_seed_is_accessible(self):
        seed = secrets.token_bytes(32)
        node = ThresholdECDSANode(42, seed=seed)
        assert node.seed == seed

    def test_auto_generated_seed_is_32_bytes(self):
        node = ThresholdECDSANode(42)
        assert len(node.seed) == 32


# ---------------------------------------------------------------------------
# Vulnerability reproduction: DRBG seed leakage → full key recovery
# ---------------------------------------------------------------------------


class TestDRBGLeakageAttack:
    def test_leaked_seed_allows_key_recovery(self):
        """Core exploit: attacker intercepts the seed, reconstructs blinding
        factors, and recovers the secret key share."""
        victim_key = 0xDEADBEEF
        seed = secrets.token_bytes(32)
        victim = ThresholdECDSANode(victim_key, seed=seed)

        masked = victim.produce_masked_share()

        # Attacker has the leaked seed
        attacker_drbg = DRBG(seed)
        reconstructed_v = attacker_drbg.generate_blinding_factor()

        recovered = ThresholdECDSANode.recover_key_share(
            masked.value, reconstructed_v
        )
        assert recovered == victim_key

    def test_wrong_seed_fails_recovery(self):
        victim_key = 0xCAFEBABE
        seed = secrets.token_bytes(32)
        victim = ThresholdECDSANode(victim_key, seed=seed)
        masked = victim.produce_masked_share()

        wrong_drbg = DRBG(secrets.token_bytes(32))
        wrong_v = wrong_drbg.generate_blinding_factor()
        recovered = ThresholdECDSANode.recover_key_share(masked.value, wrong_v)
        assert recovered != victim_key

    def test_multiple_rounds_all_recoverable(self):
        """Each masking round can be independently compromised."""
        victim_key = 42
        seed = secrets.token_bytes(32)
        victim = ThresholdECDSANode(victim_key, seed=seed)

        shares = [victim.produce_masked_share() for _ in range(5)]

        attacker_drbg = DRBG(seed)
        for share in shares:
            v = attacker_drbg.generate_blinding_factor()
            assert ThresholdECDSANode.recover_key_share(share.value, v) == victim_key


# ---------------------------------------------------------------------------
# TransportPayload helpers
# ---------------------------------------------------------------------------


class TestTransportPayload:
    def test_extract_seed_success(self):
        seed = secrets.token_bytes(32)
        payload = TransportPayload(sender_id=0, masked_share=0, raw_bytes=seed)
        assert extract_seed_from_payload(payload) == seed

    def test_extract_seed_with_extra_bytes(self):
        seed = secrets.token_bytes(32)
        raw = seed + b"\xff" * 64
        payload = TransportPayload(sender_id=1, masked_share=0, raw_bytes=raw)
        assert extract_seed_from_payload(payload) == seed

    def test_extract_seed_too_short(self):
        payload = TransportPayload(sender_id=2, masked_share=0, raw_bytes=b"\x00" * 31)
        assert extract_seed_from_payload(payload) is None

    def test_extract_seed_empty(self):
        payload = TransportPayload(sender_id=3, masked_share=0, raw_bytes=b"")
        assert extract_seed_from_payload(payload) is None
