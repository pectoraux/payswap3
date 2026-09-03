"""Clearing cycles: the recognition window record and its clearing statement.

A :class:`ClearingCycle` is the protocol-level, versioned record of one
clearing batch: a declared recognition window inside which obligations
are recognized from execution evidence. The frozen v0.1 ``Clearing``
command family ``Create/Validate/Finalize/Cancel`` drives it:

* ``Create`` opens the window (state ``OPEN``);
* ``Validate`` verifies every member obligation has passed validation
  (no ``RECOGNIZED`` stragglers, no open disputes);
* ``Finalize`` binds the clearing statement — the per pair and per
  asset gross exposure snapshot — and makes members netting-eligible;
* ``Cancel`` closes the batch without a statement; member obligations
  survive (immutable history) but are never cycle-cleared.

Accounting boundary: a clearing cycle RECOGNIZES obligations (the
ledger-posting model's ``Clearing → obligation recognition``); it never
moves funds, never posts, and never settles. The value domain
(WORK-005) remains the sole accounting authority; account and journal
references stay opaque identifiers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256

from ._validation import (
    require_identifier,
    require_int,
    require_text,
    require_utc_timestamp,
    require_utc_timestamp_order,
    strict_fields,
)
from .contracts import (
    CLEARING_CYCLE_OBJECT_TYPE,
    ClearingCycleState,
)
from .seal import (
    build_domain_envelope,
    composite_to_dict,
    composite_to_json,
    decode_composite,
    decode_composite_json,
    seal_composite,
    verify_composite,
)

_CYCLE_SPEC_FIELDS = frozenset(
    {
        "cycle_id",
        "window",
        "description",
        "member_ids",
        "statement",
    }
)

_WINDOW_FIELDS = frozenset({"opens_at", "closes_at"})

_STATEMENT_FIELDS = frozenset(
    {
        "finalized_at",
        "member_total",
        "gross_by_asset",
        "gross_by_pair",
    }
)

_GROSS_ASSET_FIELDS = frozenset({"asset", "scale", "gross"})
_GROSS_PAIR_FIELDS = frozenset({"obligor", "obligee", "asset", "scale", "gross"})


@dataclass(frozen=True, slots=True)
class RecognitionWindow:
    """The half-open UTC recognition window of one clearing cycle."""

    opens_at: str
    closes_at: str

    def __post_init__(self) -> None:
        require_utc_timestamp("cycle.window.opens_at", self.opens_at)
        require_utc_timestamp("cycle.window.closes_at", self.closes_at)
        require_utc_timestamp_order(
            "cycle.window.opens_at", self.opens_at, "cycle.window.closes_at", self.closes_at
        )

    def to_dict(self) -> dict[str, Any]:
        return {"opens_at": self.opens_at, "closes_at": self.closes_at}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RecognitionWindow":
        strict_fields("cycle.window", value, _WINDOW_FIELDS)
        return cls(opens_at=value["opens_at"], closes_at=value["closes_at"])


@dataclass(frozen=True, slots=True)
class AssetGross:
    """Gross recognized exposure in one asset (integer minor units)."""

    asset: str
    scale: int
    gross: int

    def __post_init__(self) -> None:
        require_identifier("statement gross_by_asset.asset", self.asset)
        require_int("statement gross_by_asset.scale", self.scale, minimum=0)
        require_int("statement gross_by_asset.gross", self.gross, minimum=0)

    def to_dict(self) -> dict[str, Any]:
        return {"asset": self.asset, "scale": self.scale, "gross": self.gross}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AssetGross":
        strict_fields("statement gross_by_asset", value, _GROSS_ASSET_FIELDS)
        return cls(asset=value["asset"], scale=value["scale"], gross=value["gross"])


@dataclass(frozen=True, slots=True)
class PairGross:
    """Gross recognized exposure one obligor owes one obligee in one asset."""

    obligor: str
    obligee: str
    asset: str
    scale: int
    gross: int

    def __post_init__(self) -> None:
        require_identifier("statement gross_by_pair.obligor", self.obligor)
        require_identifier("statement gross_by_pair.obligee", self.obligee)
        if self.obligor == self.obligee:
            raise CoreValidationError(
                "statement gross_by_pair obligor and obligee must be distinct participants"
            )
        require_identifier("statement gross_by_pair.asset", self.asset)
        require_int("statement gross_by_pair.scale", self.scale, minimum=0)
        require_int("statement gross_by_pair.gross", self.gross, minimum=0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "obligor": self.obligor,
            "obligee": self.obligee,
            "asset": self.asset,
            "scale": self.scale,
            "gross": self.gross,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PairGross":
        strict_fields("statement gross_by_pair", value, _GROSS_PAIR_FIELDS)
        return cls(
            obligor=value["obligor"],
            obligee=value["obligee"],
            asset=value["asset"],
            scale=value["scale"],
            gross=value["gross"],
        )


@dataclass(frozen=True, slots=True)
class ClearingStatement:
    """The binding gross-exposure snapshot produced by cycle finalization.

    The statement is the clearing domain's gross side of the
    gross-to-net computation: netting (WORK-015's netting cycle) consumes
    exactly this shape of fact. ``digest`` binds obligation resolutions
    and netting issuances to the exact statement content.
    """

    finalized_at: str
    member_total: int
    gross_by_asset: tuple[AssetGross, ...]
    gross_by_pair: tuple[PairGross, ...]

    def __post_init__(self) -> None:
        require_utc_timestamp("statement.finalized_at", self.finalized_at)
        require_int("statement.member_total", self.member_total, minimum=0)
        by_asset = tuple(self.gross_by_asset)
        by_pair = tuple(self.gross_by_pair)
        for entry in by_asset:
            if not isinstance(entry, AssetGross):
                raise CoreValidationError(
                    "statement.gross_by_asset entries must be AssetGross values"
                )
        for entry in by_pair:
            if not isinstance(entry, PairGross):
                raise CoreValidationError(
                    "statement.gross_by_pair entries must be PairGross values"
                )
        if len({(entry.asset, entry.scale) for entry in by_asset}) != len(by_asset):
            raise CoreValidationError("statement.gross_by_asset contains duplicate assets")
        if len(
            {(entry.obligor, entry.obligee, entry.asset, entry.scale) for entry in by_pair}
        ) != len(by_pair):
            raise CoreValidationError("statement.gross_by_pair contains duplicate pairs")

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "finalized_at": self.finalized_at,
            "member_total": self.member_total,
            "gross_by_asset": [entry.to_dict() for entry in self.gross_by_asset],
            "gross_by_pair": [entry.to_dict() for entry in self.gross_by_pair],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ClearingStatement":
        strict_fields("cycle.statement", value, _STATEMENT_FIELDS)
        return cls(
            finalized_at=value["finalized_at"],
            member_total=value["member_total"],
            gross_by_asset=tuple(AssetGross.from_dict(entry) for entry in value["gross_by_asset"]),
            gross_by_pair=tuple(PairGross.from_dict(entry) for entry in value["gross_by_pair"]),
        )


@dataclass(frozen=True, slots=True)
class ClearingCycleSpec:
    """Immutable clearing cycle payload.

    Identity fields (``cycle_id``, ``window``) are frozen for the
    object's whole life. ``member_ids`` mirrors the obligations
    recognized into this cycle (append-only, insertion ordered, written
    by ``obligation.create``); ``statement`` is written exactly once by
    ``cycle.finalize``.
    """

    cycle_id: str
    window: RecognitionWindow
    description: str = ""
    member_ids: tuple[str, ...] = ()
    statement: ClearingStatement | None = None

    def __post_init__(self) -> None:
        require_identifier("cycle.cycle_id", self.cycle_id)
        if not isinstance(self.window, RecognitionWindow):
            raise CoreValidationError(
                f"cycle.window must be a RecognitionWindow, got {type(self.window).__name__}"
            )
        if not isinstance(self.description, str):
            raise CoreValidationError("cycle.description must be a string")
        members = tuple(self.member_ids)
        for entry in members:
            require_identifier("cycle.member_ids entry", entry)
        if len(set(members)) != len(members):
            raise CoreValidationError("cycle.member_ids contains duplicate obligations")
        if self.statement is not None and not isinstance(self.statement, ClearingStatement):
            raise CoreValidationError(
                "cycle.statement must be a ClearingStatement"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "cycle_id": self.cycle_id,
            "window": self.window.to_dict(),
            "description": self.description,
            "member_ids": list(self.member_ids),
            "statement": self.statement.to_dict() if self.statement is not None else None,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ClearingCycleSpec":
        strict_fields("cycle payload", value, _CYCLE_SPEC_FIELDS)
        raw_statement = value["statement"]
        statement = (
            ClearingStatement.from_dict(raw_statement) if raw_statement is not None else None
        )
        return cls(
            cycle_id=value["cycle_id"],
            window=RecognitionWindow.from_dict(value["window"]),
            description=value["description"],
            member_ids=tuple(value["member_ids"]),
            statement=statement,
        )


@dataclass(frozen=True, slots=True)
class ClearingCycle:
    """Durable clearing cycle record (envelope + sealed payload)."""

    envelope: ObjectEnvelope
    spec: ClearingCycleSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = CLEARING_CYCLE_OBJECT_TYPE
    STATE_TYPE = ClearingCycleState

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("cycle envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, ClearingCycleSpec):
            raise CoreValidationError("cycle spec must be a ClearingCycleSpec")
        if self.envelope.object_type != CLEARING_CYCLE_OBJECT_TYPE:
            raise CoreValidationError(
                f"cycle object_type must be {CLEARING_CYCLE_OBJECT_TYPE!r}"
            )
        if self.envelope.object_id != self.spec.cycle_id:
            raise CoreValidationError("cycle object_id must equal spec.cycle_id")
        ClearingCycleState(self.envelope.state)
        verify_composite(
            self.envelope, self.spec, self.integrity_hash, self.envelope.object_id
        )

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> ClearingCycleState:
        return ClearingCycleState(self.envelope.state)

    def to_dict(self) -> dict[str, Any]:
        return composite_to_dict(self.envelope, self.spec, self.integrity_hash)

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ClearingCycle":
        envelope, payload = decode_composite(
            value, object_type=CLEARING_CYCLE_OBJECT_TYPE, state_type=ClearingCycleState
        )
        spec = ClearingCycleSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=value["integrity_hash"])

    @classmethod
    def from_json(cls, value: str) -> "ClearingCycle":
        envelope, payload, integrity_hash = decode_composite_json(
            value, object_type=CLEARING_CYCLE_OBJECT_TYPE, state_type=ClearingCycleState
        )
        spec = ClearingCycleSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=integrity_hash)


def make_cycle_record(
    *,
    spec: ClearingCycleSpec,
    environment_id: str,
    domain_id: str,
    provenance: Provenance,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> ClearingCycle:
    """Construct the version-1 sealed clearing cycle record."""
    envelope = build_domain_envelope(
        object_id=spec.cycle_id,
        object_type=CLEARING_CYCLE_OBJECT_TYPE,
        state=ClearingCycleState.OPEN.value,
        environment_id=environment_id,
        domain_id=domain_id,
        provenance=provenance,
        causation_id=causation_id,
        correlation_id=correlation_id,
    )
    return ClearingCycle(
        envelope=envelope, spec=spec, integrity_hash=seal_composite(envelope, spec)
    )


def compute_clearing_statement(
    *,
    members: Sequence[Any],
    finalized_at: str,
) -> ClearingStatement:
    """Compute the deterministic clearing statement over the member obligations.

    The clearing statement is the gross side of the gross-to-net
    computation: per asset and per pair gross recognized exposure over
    the cycle's members (canonical ordering: assets sorted, pairs sorted
    by obligor then obligee then asset). The netting cycle (WORK-015's
    netting family) consumes exactly this shape of fact.
    """
    require_utc_timestamp("statement.finalized_at", finalized_at)
    if not members:
        raise CoreValidationError("a clearing statement requires at least one member")
    gross_by_asset: dict[tuple[str, int], int] = {}
    gross_by_pair: dict[tuple[str, str, str, int], int] = {}
    for member in members:
        gross_by_asset[(member.spec.asset, member.spec.amount.scale)] = (
            gross_by_asset.get((member.spec.asset, member.spec.amount.scale), 0)
            + member.spec.amount.value
        )
        pair_key = (
            member.spec.obligor,
            member.spec.obligee,
            member.spec.asset,
            member.spec.amount.scale,
        )
        gross_by_pair[pair_key] = gross_by_pair.get(pair_key, 0) + member.spec.amount.value
    asset_entries = tuple(
        AssetGross(asset=asset, scale=scale, gross=gross)
        for (asset, scale), gross in sorted(gross_by_asset.items())
    )
    pair_entries = tuple(
        PairGross(obligor=obligor, obligee=obligee, asset=asset, scale=scale, gross=gross)
        for (obligor, obligee, asset, scale), gross in sorted(gross_by_pair.items())
    )
    return ClearingStatement(
        finalized_at=finalized_at,
        member_total=len(members),
        gross_by_asset=asset_entries,
        gross_by_pair=pair_entries,
    )
