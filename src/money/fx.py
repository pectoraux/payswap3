"""FX rate objects and exact, conservation-preserving conversion.

Semantics
---------
* ``FxRate`` is an exact positive rational ``numerator / denominator`` of
  *target major units per single source major unit*, always reduced to
  lowest terms deterministically. It quotes two distinct currencies.
* ``convert`` produces an ``FxConversion`` that is the unique deterministic
  rounded result of (source amount, rate, rounding mode) and satisfies the
  exact conservation identity::

      source.value * rate.numerator * 10 ** target.scale
          == target.value * residual_denominator + residual_numerator

  where ``residual_denominator == 10 ** source.scale * rate.denominator``
  and ``|residual_numerator| < residual_denominator``. The rounding
  residual is carried explicitly; nothing is silently dropped or created.
* ``FxQuote`` is the durable, envelope-backed record of a quoted rate. It
  consumes the canonical core ``ObjectEnvelope``: the envelope is sealed
  with ``with_integrity_hash()`` before the quote payload hash is
  computed, and deserialization verifies both seals, rejecting unsealed or
  tampered records. ``object_type`` is the internal (non-protocol-registry)
  identifier ``money/fx-quote/v1``.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from math import gcd
from typing import Any, Mapping

from ..core.envelope import ObjectEnvelope, Provenance
from ..core.errors import CoreValidationError
from ..core.serialization import canonical_json, canonical_sha256, loads_canonical
from .amount import Amount
from .currencies import Currency
from .rounding import RoundingMode, round_ratio

FX_QUOTE_OBJECT_TYPE = "money/fx-quote/v1"
FX_QUOTE_SCHEMA_VERSION = 1
FX_QUOTE_PROTOCOL_VERSION = "v0.1"

FX_RATE_FIELDS = frozenset(
    {
        "source_currency",
        "source_scale",
        "target_currency",
        "target_scale",
        "rate_numerator",
        "rate_denominator",
    }
)
FX_CONVERSION_FIELDS = frozenset(
    {
        "source",
        "rate",
        "rounding_mode",
        "target",
        "residual_numerator",
        "residual_denominator",
    }
)
FX_QUOTE_FIELDS = frozenset({"envelope", "rate", "quote_integrity_hash"})


class FxQuoteState(StrEnum):
    """Closed internal lifecycle vocabulary for durable FX quotes."""

    ACTIVE = "ACTIVE"
    SUPERSEDED = "SUPERSEDED"
    RETIRED = "RETIRED"


def _require_positive_int(name: str, value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise CoreValidationError(f"{name} must be an integer, got {type(value).__name__}")
    if value < 1:
        raise CoreValidationError(f"{name} must be a positive integer, got {value!r}")
    return value


@dataclass(frozen=True, slots=True)
class FxRate:
    """An exact quoted exchange rate between two distinct currencies."""

    source: Currency
    target: Currency
    numerator: int
    denominator: int

    def __post_init__(self) -> None:
        if not isinstance(self.source, Currency) or not isinstance(self.target, Currency):
            raise CoreValidationError("fx rate source and target must be Currencies")
        if self.source.code == self.target.code:
            raise CoreValidationError(
                f"fx rate requires distinct currency codes, got {self.source.code} on both sides"
            )
        _require_positive_int("fx rate numerator", self.numerator)
        _require_positive_int("fx rate denominator", self.denominator)
        divisor = gcd(self.numerator, self.denominator)
        if divisor > 1:
            # Canonical reduced form keeps serialized rates byte-stable.
            object.__setattr__(self, "numerator", self.numerator // divisor)
            object.__setattr__(self, "denominator", self.denominator // divisor)

    def inverted(self) -> "FxRate":
        """Exact reciprocal rate for the target -> source direction."""
        return FxRate(
            source=self.target,
            target=self.source,
            numerator=self.denominator,
            denominator=self.numerator,
        )

    def convert(self, amount: Amount, mode: RoundingMode) -> "FxConversion":
        return convert(self, amount, mode)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_currency": self.source.code,
            "source_scale": self.source.scale,
            "target_currency": self.target.code,
            "target_scale": self.target.scale,
            "rate_numerator": self.numerator,
            "rate_denominator": self.denominator,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "FxRate":
        if not isinstance(value, Mapping):
            raise CoreValidationError(f"fx rate must be an object, got {type(value).__name__}")
        if set(value) != FX_RATE_FIELDS:
            missing = sorted(FX_RATE_FIELDS - set(value))
            extra = sorted(set(value) - FX_RATE_FIELDS)
            raise CoreValidationError(
                f"non-canonical fx rate fields; missing={missing}, extra={extra}"
            )
        source_scale = value["source_scale"]
        target_scale = value["target_scale"]
        if not isinstance(source_scale, int) or isinstance(source_scale, bool):
            raise CoreValidationError("fx rate source scale must be an integer")
        if not isinstance(target_scale, int) or isinstance(target_scale, bool):
            raise CoreValidationError("fx rate target scale must be an integer")
        source = Currency(code=value["source_currency"], scale=source_scale)
        target = Currency(code=value["target_currency"], scale=target_scale)
        return cls(
            source=source,
            target=target,
            numerator=value["rate_numerator"],
            denominator=value["rate_denominator"],
        )

    @classmethod
    def from_json(cls, value: str) -> "FxRate":
        decoded = loads_canonical(value)
        if not isinstance(decoded, dict):
            raise CoreValidationError("fx rate JSON must decode to an object")
        return cls.from_dict(decoded)


@dataclass(frozen=True, slots=True)
class FxConversion:
    """One conservation-preserving conversion of an amount across currencies.

    Instances are always the exact deterministic result of
    ``(source, rate, rounding_mode)``; construction and deserialization
    both re-derive and reject any tampered or mode-inconsistent fields.
    """

    source: Amount
    rate: FxRate
    rounding_mode: RoundingMode
    target: Amount
    residual_numerator: int
    residual_denominator: int

    def __post_init__(self) -> None:
        if not isinstance(self.source, Amount):
            raise CoreValidationError("fx conversion source must be an Amount")
        if not isinstance(self.rate, FxRate):
            raise CoreValidationError("fx conversion rate must be an FxRate")
        if not isinstance(self.target, Amount):
            raise CoreValidationError("fx conversion target must be an Amount")
        if not isinstance(self.rounding_mode, RoundingMode):
            raise CoreValidationError(
                f"fx conversion rounding mode must use the closed vocabulary, got {self.rounding_mode!r}"
            )
        if self.source.currency != self.rate.source:
            raise CoreValidationError(
                f"fx conversion source currency must be {self.rate.source.code}, got {self.source.currency.code}"
            )
        if self.target.currency != self.rate.target:
            raise CoreValidationError(
                f"fx conversion target currency must be {self.rate.target.code}, got {self.target.currency.code}"
            )
        for name in ("residual_numerator", "residual_denominator"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool):
                raise CoreValidationError(f"fx conversion {name} must be an integer")
        if self.residual_denominator < 1:
            raise CoreValidationError(
                f"fx conversion residual denominator must be positive, got {self.residual_denominator!r}"
            )
        scaled_numerator = self.source.value * self.rate.numerator * 10 ** self.rate.target.scale
        scaled_denominator = 10 ** self.source.scale * self.rate.denominator
        expected_target_value = round_ratio(scaled_numerator, scaled_denominator, self.rounding_mode)
        if self.residual_denominator != scaled_denominator:
            raise CoreValidationError("fx conversion residual denominator is not canonical")
        if self.target.value != expected_target_value:
            raise CoreValidationError(
                "fx conversion target value is not the deterministic rounded result"
            )
        if self.residual_numerator != scaled_numerator - expected_target_value * scaled_denominator:
            raise CoreValidationError("fx conversion residual does not conserve exact value")
        if not -self.residual_denominator < self.residual_numerator < self.residual_denominator:
            raise CoreValidationError(
                "fx conversion residual magnitude must be smaller than its denominator"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source.to_dict(),
            "rate": self.rate.to_dict(),
            "rounding_mode": self.rounding_mode.value,
            "target": self.target.to_dict(),
            "residual_numerator": self.residual_numerator,
            "residual_denominator": self.residual_denominator,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "FxConversion":
        if not isinstance(value, Mapping):
            raise CoreValidationError(f"fx conversion must be an object, got {type(value).__name__}")
        if set(value) != FX_CONVERSION_FIELDS:
            missing = sorted(FX_CONVERSION_FIELDS - set(value))
            extra = sorted(set(value) - FX_CONVERSION_FIELDS)
            raise CoreValidationError(
                f"non-canonical fx conversion fields; missing={missing}, extra={extra}"
            )
        try:
            rounding_mode = RoundingMode(value["rounding_mode"])
        except ValueError as exc:
            raise CoreValidationError(
                f"fx conversion rounding mode must use the closed vocabulary, got {value['rounding_mode']!r}"
            ) from exc
        return cls(
            source=Amount.from_dict(value["source"]),
            rate=FxRate.from_dict(value["rate"]),
            rounding_mode=rounding_mode,
            target=Amount.from_dict(value["target"]),
            residual_numerator=value["residual_numerator"],
            residual_denominator=value["residual_denominator"],
        )

    @classmethod
    def from_json(cls, value: str) -> "FxConversion":
        decoded = loads_canonical(value)
        if not isinstance(decoded, dict):
            raise CoreValidationError("fx conversion JSON must decode to an object")
        return cls.from_dict(decoded)


def convert(rate: FxRate, amount: Amount, mode: RoundingMode) -> FxConversion:
    """Convert ``amount`` across currencies exactly, with an explicit mode.

    The conversion identity is::

        source.value * rate.numerator * 10 ** target.scale
            == target.value * (10 ** source.scale * rate.denominator)
               + residual_numerator

    so the exact converted value is ``target.value + residual_numerator /
    residual_denominator`` target minor units: value is conserved and the
    rounding residual is explicit.
    """
    if not isinstance(rate, FxRate):
        raise CoreValidationError(f"conversion requires an FxRate, got {type(rate).__name__}")
    if not isinstance(amount, Amount):
        raise CoreValidationError(f"conversion requires an Amount, got {type(amount).__name__}")
    if not isinstance(mode, RoundingMode):
        raise CoreValidationError(
            f"rounding mode must use the closed RoundingMode vocabulary, got {mode!r}"
        )
    if amount.currency != rate.source:
        raise CoreValidationError(
            f"conversion source amount must be {rate.source.code}, got {amount.currency.code}"
        )
    scaled_numerator = amount.value * rate.numerator * 10 ** rate.target.scale
    scaled_denominator = 10 ** amount.scale * rate.denominator
    target_value = round_ratio(scaled_numerator, scaled_denominator, mode)
    return FxConversion(
        source=amount,
        rate=rate,
        rounding_mode=mode,
        target=Amount(currency=rate.target, value=target_value, scale=rate.target.scale),
        residual_numerator=scaled_numerator - target_value * scaled_denominator,
        residual_denominator=scaled_denominator,
    )


@dataclass(frozen=True, slots=True)
class FxQuote:
    """Durable, integrity-sealed record of a quoted FX rate.

    The envelope must be sealed before the quote payload hash is computed;
    ``from_dict``/``from_json`` verify both the envelope seal and the quote
    payload seal and reject unsealed or tampered records. Versioning uses
    the canonical core ``next_version`` semantics: identity fields never
    change across versions and the version chain is controlled.
    """

    envelope: ObjectEnvelope
    rate: FxRate
    quote_integrity_hash: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError(
                f"fx quote envelope must be an ObjectEnvelope, got {type(self.envelope).__name__}"
            )
        if self.envelope.object_type != FX_QUOTE_OBJECT_TYPE:
            raise CoreValidationError(
                f"fx quote object_type must be {FX_QUOTE_OBJECT_TYPE!r}, "
                f"got {self.envelope.object_type!r}"
            )
        if self.envelope.schema_version != FX_QUOTE_SCHEMA_VERSION:
            raise CoreValidationError(
                f"fx quote schema_version must be {FX_QUOTE_SCHEMA_VERSION}, "
                f"got {self.envelope.schema_version!r}"
            )
        if self.envelope.protocol_version != FX_QUOTE_PROTOCOL_VERSION:
            raise CoreValidationError(
                f"fx quote rejects unknown protocol version {self.envelope.protocol_version!r}; "
                f"expected {FX_QUOTE_PROTOCOL_VERSION!r}"
            )
        try:
            FxQuoteState(self.envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"fx quote state must use the closed vocabulary, got {self.envelope.state!r}"
            ) from exc
        if not isinstance(self.rate, FxRate):
            raise CoreValidationError(
                f"fx quote rate must be an FxRate, got {type(self.rate).__name__}"
            )
        if self.quote_integrity_hash is not None and (
            not isinstance(self.quote_integrity_hash, str) or not self.quote_integrity_hash.strip()
        ):
            raise CoreValidationError("fx quote integrity hash must be a non-empty string or null")

    @classmethod
    def build(
        cls,
        *,
        rate: FxRate,
        object_id: str,
        environment_id: str,
        domain_id: str,
        state: str | FxQuoteState,
        provenance: Provenance,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> "FxQuote":
        try:
            state_value = FxQuoteState(state).value
        except ValueError as exc:
            raise CoreValidationError(
                f"fx quote state must use the closed vocabulary, got {state!r}"
            ) from exc
        envelope = ObjectEnvelope(
            object_id=object_id,
            object_type=FX_QUOTE_OBJECT_TYPE,
            object_version=1,
            environment_id=environment_id,
            domain_id=domain_id,
            schema_version=FX_QUOTE_SCHEMA_VERSION,
            protocol_version=FX_QUOTE_PROTOCOL_VERSION,
            state=state_value,
            provenance=provenance,
            causation_id=causation_id,
            correlation_id=correlation_id,
        ).with_integrity_hash()
        return cls(envelope=envelope, rate=rate).with_integrity_hash()

    def _payload_dict(self) -> dict[str, Any]:
        return {"envelope": self.envelope.to_dict(), "rate": self.rate.to_dict()}

    def with_integrity_hash(self) -> "FxQuote":
        """Seal the quote payload; requires an already-sealed envelope."""
        if self.envelope.integrity_hash is None:
            raise CoreValidationError(
                f"fx quote envelope must be sealed before the quote payload hash of {self.envelope.object_id}"
            )
        digest = canonical_sha256(self._payload_dict())
        return replace(self, quote_integrity_hash=digest)

    def verify_integrity(self) -> None:
        """Recompute and verify the quote payload hash on the trusted path."""
        if self.quote_integrity_hash is None:
            raise CoreValidationError(
                f"quote_integrity_hash is required for trusted deserialization of "
                f"{self.envelope.object_id}"
            )
        expected = canonical_sha256(self._payload_dict())
        if self.quote_integrity_hash != expected:
            raise CoreValidationError(
                f"quote integrity hash mismatch for object {self.envelope.object_id}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload_dict(), "quote_integrity_hash": self.quote_integrity_hash}

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "FxQuote":
        if not isinstance(value, Mapping):
            raise CoreValidationError(f"fx quote must be an object, got {type(value).__name__}")
        if set(value) != FX_QUOTE_FIELDS:
            missing = sorted(FX_QUOTE_FIELDS - set(value))
            extra = sorted(set(value) - FX_QUOTE_FIELDS)
            raise CoreValidationError(
                f"non-canonical fx quote fields; missing={missing}, extra={extra}"
            )
        envelope = ObjectEnvelope.from_dict(value["envelope"])
        rate = FxRate.from_dict(value["rate"])
        quote = cls(
            envelope=envelope,
            rate=rate,
            quote_integrity_hash=value["quote_integrity_hash"],
        )
        quote.verify_integrity()
        return quote

    @classmethod
    def from_json(cls, value: str) -> "FxQuote":
        decoded = loads_canonical(value)
        if not isinstance(decoded, dict):
            raise CoreValidationError("fx quote JSON must decode to an object")
        return cls.from_dict(decoded)

    def next_version(self, **changes: Any) -> "FxQuote":
        """Create the next envelope version; the rate payload is immutable."""
        envelope = self.envelope.next_version(**changes).with_integrity_hash()
        return FxQuote(envelope=envelope, rate=self.rate).with_integrity_hash()
