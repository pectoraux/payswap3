"""Pure-Python RFC 8032 Ed25519 public-key derivation and signing.

The Stellar testnet rail signs its transaction envelopes with
Ed25519. The repository is deliberately dependency-free, so this
module implements the RFC 8032 PureEdDSA algorithm directly on
Python integers (the reference implementation shape: affine twisted
Edwards arithmetic with modular inverses). Signing is fully
DETERMINISTIC (the RFC 8032 nonce is derived from the seed prefix and
the message — no entropy source, no clock reads), which the rail's
byte-deterministic envelopes require.

The implementation is pinned by the contract suite against the RFC
8032 §7.1 official test vectors, and the end-to-end envelope encoding
is pinned by golden bytes verified against the live testnet.

Security scope (honest and narrow): this signer is used ONLY for the
rail's deterministic TESTNET keypairs, whose 32-byte seeds are derived
from PUBLIC constants (documented in ``stellar.py``) — the seeds are
not secrets by construction. It is not a general-purpose hardened
signer: the affine reference arithmetic is not constant-time. No
secret material ever passes through this module in this repository.
"""

from __future__ import annotations

import hashlib

from src.core.errors import CoreValidationError

#: The Ed25519 prime (2**255 - 19).
_P = 2**255 - 19

#: The Ed25519 group order.
_L = 2**252 + 27742317777372353535851937790883648493

#: The twisted-Edwards curve parameter d, as an integer mod p.
_D = (-121665 * pow(121666, _P - 2, _P)) % _P

#: sqrt(-1) mod p, used in point decompression.
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _require_seed(seed: bytes) -> None:
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise CoreValidationError(
            "ed25519 seeds must be exactly 32 bytes (RFC 8032)"
        )


def _recover_x(y: int) -> int:
    """Recover the x coordinate of a curve point from y (compression)."""
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _SQRT_M1) % _P
    if (x * x - xx) % _P != 0:
        raise CoreValidationError("the point is not on the Ed25519 curve")
    if x % 2 != 0:
        x = _P - x
    return x


#: The Ed25519 base point (verified by construction: y = 4/5).
_BASE_POINT = (_recover_x((4 * pow(5, _P - 2, _P)) % _P), (4 * pow(5, _P - 2, _P)) % _P)


def _edwards_add(point: tuple[int, int], other: tuple[int, int]) -> tuple[int, int]:
    """Add two points on the twisted Edwards curve (affine, complete)."""
    x1, y1 = point
    x2, y2 = other
    x3 = (x1 * y2 + x2 * y1) * pow(1 + _D * x1 * x2 * y1 * y2, _P - 2, _P)
    y3 = (y1 * y2 + x1 * x2) * pow(1 - _D * x1 * x2 * y1 * y2, _P - 2, _P)
    return (x3 % _P, y3 % _P)


def _scalar_multiply(point: tuple[int, int], scalar: int) -> tuple[int, int]:
    """Double-and-add scalar multiplication (iterative)."""
    result = (0, 1)
    addend = point
    while scalar > 0:
        if scalar & 1:
            result = _edwards_add(result, addend)
        addend = _edwards_add(addend, addend)
        scalar >>= 1
    return result


def _encode_point(point: tuple[int, int]) -> bytes:
    """Encode a point: little-endian y with the x sign bit at bit 255."""
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _clamp_scalar(half: bytes) -> int:
    """Clamp the first half of the seed hash into the scalar (RFC 8032)."""
    value = bytearray(half)
    value[0] &= 248
    value[31] &= 127
    value[31] |= 64
    return int.from_bytes(bytes(value), "little")


def _expand_seed(seed: bytes) -> tuple[int, bytes]:
    digest = _sha512(bytes(seed))
    scalar = _clamp_scalar(digest[:32])
    return scalar, digest[32:]


def ed25519_public_key(seed: bytes) -> bytes:
    """Derive the 32-byte Ed25519 public key of a 32-byte seed."""
    _require_seed(seed)
    scalar, _prefix = _expand_seed(bytes(seed))
    return _encode_point(_scalar_multiply(_BASE_POINT, scalar))


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    """Sign a message deterministically (RFC 8032 PureEdDSA)."""
    _require_seed(seed)
    if not isinstance(message, (bytes, bytearray)):
        raise CoreValidationError("the ed25519 message must be bytes")
    scalar, prefix = _expand_seed(bytes(seed))
    public = _encode_point(_scalar_multiply(_BASE_POINT, scalar))
    nonce = int.from_bytes(_sha512(prefix + bytes(message)), "little") % _L
    point_r = _encode_point(_scalar_multiply(_BASE_POINT, nonce))
    challenge = int.from_bytes(
        _sha512(point_r + public + bytes(message)), "little"
    ) % _L
    signature_scalar = (nonce + challenge * scalar) % _L
    return point_r + signature_scalar.to_bytes(32, "little")


__all__ = [
    "ed25519_public_key",
    "ed25519_sign",
]
