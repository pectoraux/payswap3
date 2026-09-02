"""Uncertainty: typed, exact representations of knowledge reliability.

An :class:`Uncertainty` record quantifies the reliability of a value with
an explicit typed representation — a closed vocabulary of ``INTERVAL``
(two-sided bounds), ``QUANTILES`` (strictly monotone quantile points in
basis points of probability) and ``BAND`` (a central value with a low and
high bound). Every value is an exact integer in minor units of the
declared scale and unit: no floating-point value is ever constructed, so
there is no float ambiguity anywhere in the representation.

Uncertainty has no lifecycle commands: the vocabulary is the single
``RECORDED`` state and the record is immutable (it is a representation
attached to evidence, not an observed fact).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError

from .contracts import (
    MAX_QUANTILE_BPS,
    MAX_SCALE,
    UNCERTAINTY_OBJECT_TYPE,
    UncertaintyForm,
)
from ._validation import (
    parse_enum,
    require_identifier,
    require_int,
    strict_fields,
)
from .seal import (
    build_domain_envelope,
    composite_to_json,
    decode_composite,
    decode_composite_json,
    seal_composite,
    verify_composite,
)

_UNCERTAINTY_SPEC_FIELDS = frozenset(
    {
        "subject_ref",
        "form",
        "scale",
        "unit",
        "lower_bound",
        "upper_bound",
        "points",
        "central_value",
        "band_low",
        "band_high",
    }
)

#: Minimum number of quantile points for a meaningful quantile function.
MIN_QUANTILE_POINTS = 2


class UncertaintyState(StrEnum):
    """Closed lifecycle vocabulary of an uncertainty record (immutable)."""

    RECORDED = "RECORDED"


@dataclass(frozen=True, slots=True)
class QuantilePoint:
    """One quantile of a quantile-function uncertainty representation.

    ``quantile_bps`` is the probability level in basis points (0..10000)
    and ``value`` the exact quantile value in the representation's scale.
    """

    quantile_bps: int
    value: int

    def __post_init__(self) -> None:
        require_int(
            "quantile point quantile_bps", self.quantile_bps,
            minimum=0, maximum=MAX_QUANTILE_BPS,
        )
        require_int("quantile point value", self.value)

    def to_dict(self) -> dict[str, Any]:
        return {"quantile_bps": self.quantile_bps, "value": self.value}

    @classmethod
    def from_dict(cls, value: object) -> "QuantilePoint":
        if not isinstance(value, Mapping) or set(value) != {"quantile_bps", "value"}:
            raise CoreValidationError(
                "quantile point fields are not canonical; expected "
                "{quantile_bps, value}"
            )
        return cls(quantile_bps=value["quantile_bps"], value=value["value"])


@dataclass(frozen=True, slots=True)
class UncertaintySpec:
    """Immutable typed uncertainty representation.

    Exactly one form is expressed, and only the fields of that form may
    be non-default — an ``INTERVAL`` carrying quantile points or band
    fields fails closed, so the representation is never ambiguous. All
    bounds validation is exact integer comparison.
    """

    subject_ref: str
    form: UncertaintyForm
    scale: int
    unit: str
    lower_bound: int | None = None
    upper_bound: int | None = None
    points: tuple[QuantilePoint, ...] = ()
    central_value: int | None = None
    band_low: int | None = None
    band_high: int | None = None

    def __post_init__(self) -> None:
        require_identifier("uncertainty.subject_ref", self.subject_ref)
        parse_enum("uncertainty form", UncertaintyForm, self.form)
        require_int("uncertainty.scale", self.scale, minimum=0, maximum=MAX_SCALE)
        if not isinstance(self.unit, str) or not self.unit.strip():
            raise CoreValidationError("uncertainty.unit must be a non-empty string")
        if not isinstance(self.points, tuple):
            raise CoreValidationError("uncertainty.points must be a tuple")
        for point in self.points:
            if not isinstance(point, QuantilePoint):
                raise CoreValidationError(
                    "uncertainty.points entries must be QuantilePoint instances"
                )
        if self.form is UncertaintyForm.INTERVAL:
            self._validate_interval()
        elif self.form is UncertaintyForm.QUANTILES:
            self._validate_quantiles()
        else:
            self._validate_band()

    def _validate_interval(self) -> None:
        if self.points or self.central_value is not None or self.band_low is not None or self.band_high is not None:
            raise CoreValidationError(
                "an INTERVAL uncertainty carries exactly lower_bound and upper_bound"
            )
        if self.lower_bound is None or self.upper_bound is None:
            raise CoreValidationError(
                "an INTERVAL uncertainty requires both lower_bound and upper_bound"
            )
        require_int("uncertainty.lower_bound", self.lower_bound)
        require_int("uncertainty.upper_bound", self.upper_bound)
        if self.lower_bound > self.upper_bound:
            raise CoreValidationError(
                "uncertainty lower_bound must not exceed upper_bound"
            )

    def _validate_quantiles(self) -> None:
        if self.lower_bound is not None or self.upper_bound is not None or self.central_value is not None or self.band_low is not None or self.band_high is not None:
            raise CoreValidationError(
                "a QUANTILES uncertainty carries exactly its quantile points"
            )
        if len(self.points) < MIN_QUANTILE_POINTS:
            raise CoreValidationError(
                f"a QUANTILES uncertainty requires at least {MIN_QUANTILE_POINTS} points"
            )
        previous_level: int | None = None
        previous_value: int | None = None
        for point in self.points:
            if previous_level is not None and point.quantile_bps <= previous_level:
                raise CoreValidationError(
                    "uncertainty quantile levels must be strictly increasing"
                )
            if previous_value is not None and point.value < previous_value:
                raise CoreValidationError(
                    "uncertainty quantile values must be non-decreasing"
                )
            previous_level = point.quantile_bps
            previous_value = point.value

    def _validate_band(self) -> None:
        if self.lower_bound is not None or self.upper_bound is not None or self.points:
            raise CoreValidationError(
                "a BAND uncertainty carries exactly central_value, band_low and band_high"
            )
        if (
            self.central_value is None
            or self.band_low is None
            or self.band_high is None
        ):
            raise CoreValidationError(
                "a BAND uncertainty requires central_value, band_low and band_high"
            )
        require_int("uncertainty.central_value", self.central_value)
        require_int("uncertainty.band_low", self.band_low)
        require_int("uncertainty.band_high", self.band_high)
        if not self.band_low <= self.central_value <= self.band_high:
            raise CoreValidationError(
                "uncertainty band bounds must satisfy band_low <= central_value <= band_high"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject_ref": self.subject_ref,
            "form": self.form.value,
            "scale": self.scale,
            "unit": self.unit,
            "lower_bound": self.lower_bound,
            "upper_bound": self.upper_bound,
            "points": [point.to_dict() for point in self.points],
            "central_value": self.central_value,
            "band_low": self.band_low,
            "band_high": self.band_high,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "UncertaintySpec":
        strict_fields("uncertainty", value, _UNCERTAINTY_SPEC_FIELDS)
        raw_points = value["points"]
        if not isinstance(raw_points, list):
            raise CoreValidationError("uncertainty.points must deserialize from a list")
        return cls(
            subject_ref=value["subject_ref"],
            form=parse_enum("uncertainty form", UncertaintyForm, value["form"]),
            scale=value["scale"],
            unit=value["unit"],
            lower_bound=value["lower_bound"],
            upper_bound=value["upper_bound"],
            points=tuple(QuantilePoint.from_dict(point) for point in raw_points),
            central_value=value["central_value"],
            band_low=value["band_low"],
            band_high=value["band_high"],
        )


@dataclass(frozen=True, slots=True)
class Uncertainty:
    """Durable uncertainty record (envelope + sealed payload)."""

    envelope: ObjectEnvelope
    spec: UncertaintySpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = UNCERTAINTY_OBJECT_TYPE
    STATE_TYPE = UncertaintyState

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("uncertainty envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, UncertaintySpec):
            raise CoreValidationError("uncertainty spec must be an UncertaintySpec")
        self.envelope.verify_integrity()
        if self.envelope.object_type != UNCERTAINTY_OBJECT_TYPE:
            raise CoreValidationError(
                f"uncertainty object_type must be {UNCERTAINTY_OBJECT_TYPE!r}"
            )
        try:
            UncertaintyState(self.envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"unknown uncertainty state: {self.envelope.state!r}"
            ) from exc
        verify_composite(self.envelope, self.spec, self.integrity_hash, self.envelope.object_id)

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> UncertaintyState:
        return UncertaintyState(self.envelope.state)

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "payload": self.spec.to_dict(),
            "integrity_hash": self.integrity_hash,
        }

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Uncertainty":
        envelope, payload = decode_composite(
            value,
            expected_object_type=UNCERTAINTY_OBJECT_TYPE,
            state_type=UncertaintyState,
        )
        spec = UncertaintySpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=value["integrity_hash"])

    @classmethod
    def from_json(cls, value: str) -> "Uncertainty":
        envelope, payload, integrity_hash = decode_composite_json(
            value,
            expected_object_type=UNCERTAINTY_OBJECT_TYPE,
            state_type=UncertaintyState,
        )
        spec = UncertaintySpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=integrity_hash)


def express_uncertainty(
    *,
    uncertainty_id: str,
    subject_ref: str,
    form: UncertaintyForm,
    scale: int,
    unit: str,
    lower_bound: int | None = None,
    upper_bound: int | None = None,
    points: tuple[QuantilePoint, ...] = (),
    central_value: int | None = None,
    band_low: int | None = None,
    band_high: int | None = None,
    environment_id: str,
    domain_id: str,
    provenance: Provenance,
    correlation_id: str | None = None,
) -> Uncertainty:
    """Express one typed uncertainty representation as a sealed record."""
    spec = UncertaintySpec(
        subject_ref=subject_ref,
        form=parse_enum("uncertainty form", UncertaintyForm, form),
        scale=scale,
        unit=unit,
        lower_bound=lower_bound,
        upper_bound=upper_bound,
        points=points,
        central_value=central_value,
        band_low=band_low,
        band_high=band_high,
    )
    envelope = build_domain_envelope(
        object_id=require_identifier("uncertainty.uncertainty_id", uncertainty_id),
        object_type=UNCERTAINTY_OBJECT_TYPE,
        state=UncertaintyState.RECORDED.value,
        environment_id=require_identifier("uncertainty.environment_id", environment_id),
        domain_id=require_identifier("uncertainty.domain_id", domain_id),
        provenance=provenance,
        correlation_id=correlation_id,
    )
    return Uncertainty(
        envelope=envelope, spec=spec, integrity_hash=seal_composite(envelope, spec)
    )


def _require_uncertainty(uncertainty: Uncertainty) -> Uncertainty:
    if not isinstance(uncertainty, Uncertainty):
        raise CoreValidationError("operation requires an Uncertainty")
    return uncertainty


def uncertainty_bounds(uncertainty: Uncertainty) -> tuple[int, int]:
    """Deterministic low/high bounds of the typed representation.

    ``INTERVAL`` yields ``(lower_bound, upper_bound)``; ``BAND`` yields
    ``(band_low, band_high)``; ``QUANTILES`` yields the value of the
    lowest and highest quantile points.
    """
    spec = _require_uncertainty(uncertainty).spec
    if spec.form is UncertaintyForm.INTERVAL:
        return (spec.lower_bound, spec.upper_bound)  # type: ignore[return-value]
    if spec.form is UncertaintyForm.BAND:
        return (spec.band_low, spec.band_high)  # type: ignore[return-value]
    return (spec.points[0].value, spec.points[-1].value)


def value_within_bounds(uncertainty: Uncertainty, value: int) -> bool:
    """Half-open membership test of a value inside the bounds."""
    require_int("value", value)
    low, high = uncertainty_bounds(uncertainty)
    return low <= value < high


def quantile_at(uncertainty: Uncertainty, quantile_bps: int) -> int:
    """Exact lower-step quantile lookup, deterministic and total.

    For a requested probability level, the value of the largest quantile
    point whose level does not exceed it is returned (the lowest point's
    value when no point qualifies). No interpolation is performed: the
    typed representation stays exact.
    """
    spec = _require_uncertainty(uncertainty).spec
    if spec.form is not UncertaintyForm.QUANTILES:
        raise CoreValidationError("quantile lookup requires a QUANTILES uncertainty")
    require_int("quantile_bps", quantile_bps, minimum=0, maximum=MAX_QUANTILE_BPS)
    result = spec.points[0].value
    for point in spec.points:
        if point.quantile_bps <= quantile_bps:
            result = point.value
        else:
            break
    return result
