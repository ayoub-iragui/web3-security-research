"""
Deterministic Random Bit Generator (DRBG) simulation for threshold ECDSA.

Models the vulnerability described in the DRBG State Leakage research:
when the DRBG root seed leaks over the transport layer, an attacker can
reconstruct blinding factors and recover the masked key share.

Reference: README.md — DRBG State Leakage in Threshold ECDSA
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field

# secp256k1 curve order
SECP256K1_ORDER = int(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
)


class DRBG:
    """HMAC-DRBG (simplified) keyed by a 32-byte seed."""

    def __init__(self, seed: bytes) -> None:
        if len(seed) != 32:
            raise ValueError("Seed must be exactly 32 bytes")
        self._key = seed
        self._counter = 0

    def generate(self, modulus: int) -> int:
        """Return the next deterministic integer in [0, modulus)."""
        data = self._key + self._counter.to_bytes(8, "big")
        digest = hmac.new(self._key, data, hashlib.sha256).digest()
        self._counter += 1
        return int.from_bytes(digest, "big") % modulus

    def generate_blinding_factor(self) -> int:
        """Return a blinding factor v in [0, secp256k1_order)."""
        return self.generate(SECP256K1_ORDER)


@dataclass
class MaskedShare:
    """A key share masked by a blinding factor: value ≡ (x_i + v_i) mod q."""

    value: int
    blinding_factor: int


class ThresholdECDSANode:
    """Simulates a single party in a t-of-n threshold ECDSA ceremony."""

    def __init__(self, key_share: int, seed: bytes | None = None) -> None:
        if not 0 < key_share < SECP256K1_ORDER:
            raise ValueError("Key share must be in (0, curve_order)")
        self._key_share = key_share
        self._seed = seed if seed is not None else secrets.token_bytes(32)
        self._drbg = DRBG(self._seed)

    @property
    def seed(self) -> bytes:
        return self._seed

    def produce_masked_share(self) -> MaskedShare:
        """Mask the key share with a DRBG-derived blinding factor."""
        v = self._drbg.generate_blinding_factor()
        masked = (self._key_share + v) % SECP256K1_ORDER
        return MaskedShare(value=masked, blinding_factor=v)

    @staticmethod
    def recover_key_share(
        masked_share: int,
        blinding_factor: int,
    ) -> int:
        """Recover the original key share given the mask and blinding factor."""
        return (masked_share - blinding_factor) % SECP256K1_ORDER


@dataclass
class TransportPayload:
    """Simulates a network payload that may inadvertently contain the seed."""

    sender_id: int
    masked_share: int
    raw_bytes: bytes = field(default_factory=bytes)


def extract_seed_from_payload(payload: TransportPayload) -> bytes | None:
    """Attempt to extract a 32-byte seed from a raw transport payload."""
    if len(payload.raw_bytes) >= 32:
        return payload.raw_bytes[:32]
    return None
