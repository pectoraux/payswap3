"""Netting cycles: bilateral and multilateral gross-to-net computation.

A :class:`NettingCycle` is the protocol-level, versioned record of one
netting batch over a set of member obligations. The frozen v0.1
``Netting`` command family ``Create/Add/Remove/Calculate/Finalize/
Cancel`` drives it. ``Calculate`` binds the deterministic netting
statement; ``Finalize`` makes it binding: member obligations resolve
(kind ``NETTING``, statement digest bound) and — in ``BILATERAL`` mode —
one net obligation per unordered participant pair and asset is issued in
the dominant direction (ledger-posting model: ``Netting → obligation
offset``). In ``MULTILATERAL`` mode members are reclassified into per
participant net funding positions (``Netting → obligation
reclassification``); the sealed statement records the positions with
the conservation invariant ``Σ positions = 0`` per asset, and no new
obligations are issued — funding the net positions is settlement's
concern (WORK-016).

Gross-to-net arithmetic (the domain's core accounting fact):

* ``gross`` — the total amount that would move without netting
  (``Σ member amounts`` per asset);
* ``net`` — the total net funding requirement after netting:
  ``Σ |pair forward|`` (bilateral) or ``Σ positive participant
  positions`` (multilateral);
* ``reduction = gross − net >= 0`` — netting never increases the
  funding requirement: per pair ``|S_ab − S_ba| <= S_ab + S_ba``, and
  per participant ``Σ_{net>0} (payables − receivables) <= Σ payables``.

All per-asset arithmetic is exact integer arithmetic over the value
domain's :class:`src.value.Amount` minor units (same asset AND same
scale — cross-scale or cross-asset arithmetic fails closed exactly as
the value domain prescribes). The optional common-unit valuation of the
statement is computed through the money domain's exact FX authority
(WORK-006): declared :class:`src.money.FxRate` per asset currency, an
explicit :class:`src.money.RoundingMode`, conservation-preserving
conversion with explicit residuals. Per-asset numbers stay exact;
only the valuation is a conversion.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.money.amount import Amount as MoneyAmount
from src.money.currencies import get_currency
from src.money.fx import FxRate, convert
from src.money.rounding import RoundingMode
from src.value.amount import Amount

from ._validation import (
    parse_enum,
    require_identifier,
    require_int,
    require_text,
    strict_fields,
)
from .contracts import (
    NETTING_CYCLE_OBJECT_TYPE,
    NettingCycleState,
    NettingMode,
)
from .obligations import (
    DueWindow,
    Obligation,
    ObligationSpec,
    ObligationState,
    make_obligation_record,
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
from src.core.envelope import ObjectEnvelope, Provenance

_NETTING_SPEC_FIELDS = frozenset(
    {
        "netting_id",
        "mode",
        "due_window",
        "member_ids",
        "statement",
    }
)

_STATEMENT_FIELDS = frozenset(
    {
        "calculated_at",
        "mode",
        "member_total",
        "members",
        "groups",
        "gross_total",
        "net_total",
        "reduction",
        "valuation",
    }
)

_GROUP_FIELDS = frozenset({"asset", "scale", "gross", "net_total", "pairs", "positions"})
_PAIR_FIELDS = frozenset(
    {"obligor", "obligee", "forward", "resolved_count", "issued_obligation_id"}
)
_POSITION_FIELDS = frozenset({"participant", "net"})
_MEMBER_BINDING_FIELDS = frozenset(
    {"obligation_id", "object_version", "obligor", "obligee", "amount_value"}
)
_VALUATION_FIELDS = frozenset(
    {
        "base_currency",
        "rounding",
        "conversions",
        "gross_base",
        "net_base",
        "reduction_base",
    }
)
_CONVERSION_FIELDS = frozenset(
    {
        "asset",
        "currency",
        "rate",
        "rounding",
        "gross_source",
        "gross_target",
        "gross_residual_numerator",
        "gross_residual_denominator",
        "net_source",
        "net_target",
        "net_residual_numerator",
        "net_residual_denominator",
    }
)


# ---------------------------------------------------------------------------
# statement records
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MemberBinding:
    """One member obligation bound into the statement at calculation time.

    ``object_version`` pins the member's exact envelope version; the
    finalization gate re-verifies it, so any post-calculation mutation
    (amendment, dispute, resolution) fails closed as a stale statement.
    """

    obligation_id: str
    object_version: int
    obligor: str
    obligee: str
    amount_value: int

    def __post_init__(self) -> None:
        require_identifier("statement member.obligation_id", self.obligation_id)
        require_int("statement member.object_version", self.object_version, minimum=1)
        require_identifier("statement member.obligor", self.obligor)
        require_identifier("statement member.obligee", self.obligee)
        require_int("statement member.amount_value", self.amount_value, minimum=1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "obligation_id": self.obligation_id,
            "object_version": self.object_version,
            "obligor": self.obligor,
            "obligee": self.obligee,
            "amount_value": self.amount_value,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "MemberBinding":
        strict_fields("statement member", value, _MEMBER_BINDING_FIELDS)
        return cls(
            obligation_id=value["obligation_id"],
            object_version=value["object_version"],
            obligor=value["obligor"],
            obligee=value["obligee"],
            amount_value=value["amount_value"],
        )


@dataclass(frozen=True, slots=True)
class PairNet:
    """One bilateral net position of an unordered pair in one asset.

    ``forward`` is the net amount ``obligor → obligee`` (always
    positive; the direction records who net-owes whom). ``resolved_count``
    is the number of member obligations offset into this pair;
    ``issued_obligation_id`` names the net obligation that finalization
    issues (deterministic derived id), or ``None`` when the pair nets
    to exactly zero.
    """

    obligor: str
    obligee: str
    forward: int
    resolved_count: int
    issued_obligation_id: str | None

    def __post_init__(self) -> None:
        require_identifier("pair.obligor", self.obligor)
        require_identifier("pair.obligee", self.obligee)
        if self.obligor == self.obligee:
            raise CoreValidationError("pair obligor and obligee must be distinct")
        require_int("pair.forward", self.forward, minimum=0)
        require_int("pair.resolved_count", self.resolved_count, minimum=1)
        if self.forward == 0 and self.issued_obligation_id is not None:
            raise CoreValidationError(
                "a fully offset pair (forward == 0) must not name an issued obligation"
            )
        if self.forward > 0 and self.issued_obligation_id is None:
            raise CoreValidationError(
                "a pair with a positive net must name the obligation finalization issues"
            )
        if self.issued_obligation_id is not None:
            require_identifier("pair.issued_obligation_id", self.issued_obligation_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "obligor": self.obligor,
            "obligee": self.obligee,
            "forward": self.forward,
            "resolved_count": self.resolved_count,
            "issued_obligation_id": self.issued_obligation_id,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PairNet":
        strict_fields("statement pair", value, _PAIR_FIELDS)
        return cls(
            obligor=value["obligor"],
            obligee=value["obligee"],
            forward=value["forward"],
            resolved_count=value["resolved_count"],
            issued_obligation_id=value["issued_obligation_id"],
        )


@dataclass(frozen=True, slots=True)
class PositionNet:
    """One multilateral net position of a participant in one asset.

    ``net`` is signed: positive means net payable (the participant owes
    the group), negative means net receivable. Per asset group the
    positions conserve: ``Σ net == 0``.
    """

    participant: str
    net: int

    def __post_init__(self) -> None:
        require_identifier("position.participant", self.participant)
        require_int("position.net", self.net)
        if self.net == 0:
            raise CoreValidationError(
                "a multilateral position must be nonzero: zero-exposure "
                "participants are not carried"
            )

    def to_dict(self) -> dict[str, Any]:
        return {"participant": self.participant, "net": self.net}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PositionNet":
        strict_fields("statement position", value, _POSITION_FIELDS)
        return cls(participant=value["participant"], net=value["net"])


@dataclass(frozen=True, slots=True)
class AssetConversion:
    """One money-domain FX conversion of an asset group's gross and net.

    ``rate`` and ``rounding`` are the declared inputs (money domain
    authorities, consumed never redefined); the targets and explicit
    residuals are the exact deterministic conversion results.
    """

    asset: str
    currency: str
    rate: FxRate | None
    rounding: RoundingMode
    gross_source: int
    gross_target: int
    gross_residual_numerator: int
    gross_residual_denominator: int
    net_source: int
    net_target: int
    net_residual_numerator: int
    net_residual_denominator: int

    def __post_init__(self) -> None:
        require_identifier("conversion.asset", self.asset)
        require_text("conversion.currency", self.currency)
        if self.rate is None:
            # Identity leg: the group's currency IS the valuation base
            # currency (an FxRate requires distinct currencies, so the
            # base leg converts exactly 1:1 with zero residual).
            if self.gross_target != self.gross_source or self.net_target != self.net_source:
                raise CoreValidationError(
                    "an identity (base-currency) conversion must convert 1:1"
                )
            if (
                self.gross_residual_numerator != 0
                or self.net_residual_numerator != 0
                or self.gross_residual_denominator != 1
                or self.net_residual_denominator != 1
            ):
                raise CoreValidationError(
                    "an identity (base-currency) conversion carries no residual"
                )
        elif not isinstance(self.rate, FxRate):
            raise CoreValidationError("conversion.rate must be an FxRate or null")
        if not isinstance(self.rounding, RoundingMode):
            raise CoreValidationError("conversion.rounding must be a RoundingMode")
        for name in ("gross_source", "gross_target", "net_source", "net_target"):
            require_int(f"conversion.{name}", getattr(self, name))
        for name in (
            "gross_residual_numerator",
            "gross_residual_denominator",
            "net_residual_numerator",
            "net_residual_denominator",
        ):
            require_int(f"conversion.{name}", getattr(self, name))

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset": self.asset,
            "currency": self.currency,
            "rate": self.rate.to_dict() if self.rate is not None else None,
            "rounding": self.rounding.value,
            "gross_source": self.gross_source,
            "gross_target": self.gross_target,
            "gross_residual_numerator": self.gross_residual_numerator,
            "gross_residual_denominator": self.gross_residual_denominator,
            "net_source": self.net_source,
            "net_target": self.net_target,
            "net_residual_numerator": self.net_residual_numerator,
            "net_residual_denominator": self.net_residual_denominator,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AssetConversion":
        strict_fields("statement conversion", value, _CONVERSION_FIELDS)
        return cls(
            asset=value["asset"],
            currency=value["currency"],
            rate=(
                FxRate.from_dict(value["rate"]) if value["rate"] is not None else None
            ),
            rounding=parse_enum("conversion rounding", value["rounding"], RoundingMode),
            gross_source=value["gross_source"],
            gross_target=value["gross_target"],
            gross_residual_numerator=value["gross_residual_numerator"],
            gross_residual_denominator=value["gross_residual_denominator"],
            net_source=value["net_source"],
            net_target=value["net_target"],
            net_residual_numerator=value["net_residual_numerator"],
            net_residual_denominator=value["net_residual_denominator"],
        )


@dataclass(frozen=True, slots=True)
class NettingValuation:
    """The common-unit valuation of one netting statement.

    Every asset group is converted through the money domain's exact FX
    authority into the declared base currency with an explicit rounding
    mode. ``gross_base``/``net_base`` are the summed converted funding
    requirements; ``reduction_base`` is their difference.
    """

    base_currency: str
    rounding: RoundingMode
    conversions: tuple[AssetConversion, ...]
    gross_base: int
    net_base: int
    reduction_base: int

    def __post_init__(self) -> None:
        require_text("valuation.base_currency", self.base_currency)
        if not isinstance(self.rounding, RoundingMode):
            raise CoreValidationError("valuation.rounding must be a RoundingMode")
        entries = tuple(self.conversions)
        for entry in entries:
            if not isinstance(entry, AssetConversion):
                raise CoreValidationError(
                    "valuation.conversions entries must be AssetConversion values"
                )
        if len({entry.asset for entry in entries}) != len(entries):
            raise CoreValidationError("valuation.conversions contains duplicate assets")
        require_int("valuation.gross_base", self.gross_base)
        require_int("valuation.net_base", self.net_base)
        require_int("valuation.reduction_base", self.reduction_base)
        if self.reduction_base != self.gross_base - self.net_base:
            raise CoreValidationError(
                "valuation reduction_base must equal gross_base - net_base"
            )
        for entry in entries:
            if entry.rate is None:
                if entry.currency != self.base_currency:
                    raise CoreValidationError(
                        "a rateless (identity) conversion is legal only for the "
                        f"valuation base currency {self.base_currency}"
                    )
            elif entry.rate.target.code != self.base_currency:
                raise CoreValidationError(
                    f"conversion rate for asset {entry.asset} must target the "
                    f"valuation base currency {self.base_currency}"
                )
            if entry.rounding is not self.rounding:
                raise CoreValidationError(
                    "conversion rounding modes must match the valuation rounding mode"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "base_currency": self.base_currency,
            "rounding": self.rounding.value,
            "conversions": [entry.to_dict() for entry in self.conversions],
            "gross_base": self.gross_base,
            "net_base": self.net_base,
            "reduction_base": self.reduction_base,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "NettingValuation":
        strict_fields("statement valuation", value, _VALUATION_FIELDS)
        return cls(
            base_currency=value["base_currency"],
            rounding=parse_enum("valuation rounding", value["rounding"], RoundingMode),
            conversions=tuple(
                AssetConversion.from_dict(entry) for entry in value["conversions"]
            ),
            gross_base=value["gross_base"],
            net_base=value["net_base"],
            reduction_base=value["reduction_base"],
        )


@dataclass(frozen=True, slots=True)
class NettingGroup:
    """The netting computation of one (asset, scale) group of members."""

    asset: str
    scale: int
    gross: int
    net_total: int
    pairs: tuple[PairNet, ...] = ()
    positions: tuple[PositionNet, ...] = ()

    def __post_init__(self) -> None:
        require_identifier("group.asset", self.asset)
        require_int("group.scale", self.scale, minimum=0)
        require_int("group.gross", self.gross, minimum=0)
        require_int("group.net_total", self.net_total, minimum=0)
        if self.net_total > self.gross:
            raise CoreValidationError(
                "netting never increases the funding requirement: "
                f"net_total {self.net_total} exceeds gross {self.gross} for asset {self.asset}"
            )
        pair_entries = tuple(self.pairs)
        position_entries = tuple(self.positions)
        for entry in pair_entries:
            if not isinstance(entry, PairNet):
                raise CoreValidationError("group.pairs entries must be PairNet values")
        for entry in position_entries:
            if not isinstance(entry, PositionNet):
                raise CoreValidationError(
                    "group.positions entries must be PositionNet values"
                )
        if pair_entries and position_entries:
            raise CoreValidationError(
                "a netting group carries pairs (bilateral) or positions "
                "(multilateral), never both"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset": self.asset,
            "scale": self.scale,
            "gross": self.gross,
            "net_total": self.net_total,
            "pairs": [entry.to_dict() for entry in self.pairs],
            "positions": [entry.to_dict() for entry in self.positions],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "NettingGroup":
        strict_fields("statement group", value, _GROUP_FIELDS)
        return cls(
            asset=value["asset"],
            scale=value["scale"],
            gross=value["gross"],
            net_total=value["net_total"],
            pairs=tuple(PairNet.from_dict(entry) for entry in value["pairs"]),
            positions=tuple(PositionNet.from_dict(entry) for entry in value["positions"]),
        )


@dataclass(frozen=True, slots=True)
class NettingStatement:
    """The binding netting statement produced by ``Calculate``.

    ``digest`` binds every member resolution and net-obligation issuance
    to the exact statement content: finalization re-verifies the member
    bindings and re-derives the statement before committing anything.
    """

    calculated_at: str
    mode: str
    member_total: int
    members: tuple[MemberBinding, ...]
    groups: tuple[NettingGroup, ...]
    gross_total: int
    net_total: int
    reduction: int
    valuation: NettingValuation | None = None

    def __post_init__(self) -> None:
        require_text("statement.calculated_at", self.calculated_at)
        parse_enum("statement.mode", self.mode, NettingMode)
        require_int("statement.member_total", self.member_total, minimum=1)
        member_entries = tuple(self.members)
        group_entries = tuple(self.groups)
        for entry in member_entries:
            if not isinstance(entry, MemberBinding):
                raise CoreValidationError("statement.members entries must be MemberBinding values")
        if len({entry.obligation_id for entry in member_entries}) != len(member_entries):
            raise CoreValidationError("statement.members contains duplicate obligations")
        if len(member_entries) != self.member_total:
            raise CoreValidationError(
                "statement.member_total must equal the member binding count"
            )
        for entry in group_entries:
            if not isinstance(entry, NettingGroup):
                raise CoreValidationError("statement.groups entries must be NettingGroup values")
        if len({(entry.asset, entry.scale) for entry in group_entries}) != len(group_entries):
            raise CoreValidationError("statement.groups contains duplicate assets")
        require_int("statement.gross_total", self.gross_total, minimum=0)
        require_int("statement.net_total", self.net_total, minimum=0)
        require_int("statement.reduction", self.reduction, minimum=0)
        if self.reduction != self.gross_total - self.net_total:
            raise CoreValidationError(
                "statement reduction must equal gross_total - net_total"
            )
        if self.valuation is not None and not isinstance(self.valuation, NettingValuation):
            raise CoreValidationError("statement.valuation must be a NettingValuation")
        for group in group_entries:
            if self.mode == NettingMode.BILATERAL.value and group.positions:
                raise CoreValidationError(
                    "a bilateral statement carries pair nets, not participant positions"
                )
            if self.mode == NettingMode.MULTILATERAL.value and group.pairs:
                raise CoreValidationError(
                    "a multilateral statement carries participant positions, not pair nets"
                )
            if self.mode == NettingMode.MULTILATERAL.value and sum(
                position.net for position in group.positions
            ) != 0:
                raise CoreValidationError(
                    "multilateral positions must conserve: Σ positions = 0 per asset"
                )
        summed_gross = sum(group.gross for group in group_entries)
        if summed_gross != self.gross_total:
            raise CoreValidationError(
                "statement gross_total must equal the summed group gross"
            )
        summed_net = sum(group.net_total for group in group_entries)
        if summed_net != self.net_total:
            raise CoreValidationError(
                "statement net_total must equal the summed group net funding"
            )

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "calculated_at": self.calculated_at,
            "mode": self.mode,
            "member_total": self.member_total,
            "members": [entry.to_dict() for entry in self.members],
            "groups": [entry.to_dict() for entry in self.groups],
            "gross_total": self.gross_total,
            "net_total": self.net_total,
            "reduction": self.reduction,
            "valuation": self.valuation.to_dict() if self.valuation is not None else None,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "NettingStatement":
        strict_fields("netting.statement", value, _STATEMENT_FIELDS)
        raw_valuation = value["valuation"]
        valuation = (
            NettingValuation.from_dict(raw_valuation) if raw_valuation is not None else None
        )
        return cls(
            calculated_at=value["calculated_at"],
            mode=value["mode"],
            member_total=value["member_total"],
            members=tuple(MemberBinding.from_dict(entry) for entry in value["members"]),
            groups=tuple(NettingGroup.from_dict(entry) for entry in value["groups"]),
            gross_total=value["gross_total"],
            net_total=value["net_total"],
            reduction=value["reduction"],
            valuation=valuation,
        )


# ---------------------------------------------------------------------------
# the deterministic computation
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ValuationSpec:
    """Declared valuation inputs (money-domain authorities consumed).

    ``asset_currencies`` maps each netted asset to its canonical money
    currency code; ``rates`` carries one declared rate per distinct
    source currency targeting the base currency.
    """

    base_currency: str
    rounding: RoundingMode
    asset_currencies: tuple[tuple[str, str], ...]
    rates: tuple[FxRate, ...]

    def __post_init__(self) -> None:
        require_text("valuation spec.base_currency", self.base_currency)
        get_currency(self.base_currency)
        if not isinstance(self.rounding, RoundingMode):
            raise CoreValidationError("valuation spec.rounding must be a RoundingMode")
        mappings = tuple(self.asset_currencies)
        if not mappings:
            raise CoreValidationError(
                "valuation spec.asset_currencies must not be empty when a valuation is declared"
            )
        if len({asset for asset, _ in mappings}) != len(mappings):
            raise CoreValidationError(
                "valuation spec.asset_currencies contains duplicate assets"
            )
        for asset, code in mappings:
            require_identifier("valuation spec asset", asset)
            get_currency(code)
        rate_entries = tuple(self.rates)
        for rate in rate_entries:
            if not isinstance(rate, FxRate):
                raise CoreValidationError("valuation spec.rates entries must be FxRate values")
            if rate.target.code != self.base_currency:
                raise CoreValidationError(
                    f"valuation rate {rate.source.code}->{rate.target.code} must target "
                    f"the base currency {self.base_currency}"
                )
        if len({rate.source.code for rate in rate_entries}) != len(rate_entries):
            raise CoreValidationError(
                "valuation spec.rates contains duplicate source currencies"
            )

    def currency_for(self, asset: str) -> str:
        for mapped_asset, code in self.asset_currencies:
            if mapped_asset == asset:
                return code
        raise CoreValidationError(
            f"valuation has no currency mapping for asset {asset!r}"
        )

    def rate_for(self, currency: str) -> FxRate:
        for rate in self.rates:
            if rate.source.code == currency:
                return rate
        raise CoreValidationError(
            f"valuation has no declared rate for currency {currency!r} to base "
            f"{self.base_currency!r}"
        )


def _require_nettable(obligation: Obligation) -> None:
    """Require one obligation eligible for netting membership."""
    if obligation.state not in (
        ObligationState.VALIDATED,
        ObligationState.AMENDED,
        ObligationState.RESTRUCTURED,
        ObligationState.DUE,
    ):
        raise CoreValidationError(
            f"obligation {obligation.object_id} is {obligation.state.value}; netting "
            "members must have passed validation and carry no open dispute"
        )


def compute_netting_statement(
    *,
    netting_id: str,
    members: Sequence[Obligation],
    mode: NettingMode,
    calculated_at: str,
    valuation_spec: ValuationSpec | None = None,
) -> NettingStatement:
    """Compute the deterministic netting statement over the member obligations.

    The computation is pure: same members, same mode, same declared
    inputs → byte-identical statement. Groups are canonical (sorted by
    asset then scale); bilateral pairs are sorted within each group;
    multilateral positions are sorted by participant.
    """
    require_identifier("netting.netting_id", netting_id)
    require_text("statement calculated_at", calculated_at)
    parsed_mode = parse_enum("netting mode", mode, NettingMode)
    if not members:
        raise CoreValidationError("a netting statement requires at least one member")
    seen_ids: set[str] = set()
    for member in members:
        if not isinstance(member, Obligation):
            raise CoreValidationError(
                f"netting members must be Obligation records, got {type(member).__name__}"
            )
        _require_nettable(member)
        if member.object_id in seen_ids:
            raise CoreValidationError(
                f"netting member {member.object_id} appears more than once"
            )
        seen_ids.add(member.object_id)

    # -- group members by (asset, scale) --------------------------------
    grouped: dict[tuple[str, int], list[Obligation]] = {}
    for member in members:
        key = (member.spec.asset, member.spec.amount.scale)
        grouped.setdefault(key, []).append(member)

    member_bindings = tuple(
        MemberBinding(
            obligation_id=member.object_id,
            object_version=member.envelope.object_version,
            obligor=member.spec.obligor,
            obligee=member.spec.obligee,
            amount_value=member.spec.amount.value,
        )
        for member in members
    )

    groups: list[NettingGroup] = []
    issued_ordinal = 0
    for key in sorted(grouped):
        asset, scale = key
        group_members = grouped[key]
        gross = sum(member.spec.amount.value for member in group_members)
        if parsed_mode is NettingMode.BILATERAL:
            pairs: list[PairNet] = []
            forward_by_pair: dict[tuple[str, str], int] = {}
            count_by_pair: dict[tuple[str, str], int] = {}
            for member in group_members:
                forward_key = (member.spec.obligor, member.spec.obligee)
                forward_by_pair[forward_key] = (
                    forward_by_pair.get(forward_key, 0) + member.spec.amount.value
                )
                count_by_pair[forward_key] = count_by_pair.get(forward_key, 0) + 1
            canonical_pairs: dict[tuple[str, str], tuple[str, str, int]] = {}
            for (obligor, obligee), forward in forward_by_pair.items():
                reciprocal = (obligee, obligor)
                if reciprocal in canonical_pairs:
                    # The reverse direction was already canonicalized: offset.
                    net_obligor, net_obligee, running = canonical_pairs[reciprocal]
                    canonical_pairs[reciprocal] = (
                        net_obligor,
                        net_obligee,
                        running - forward,
                    )
                    count_by_pair[reciprocal] = count_by_pair[reciprocal] + count_by_pair[
                        (obligor, obligee)
                    ]
                    continue
                canonical_pairs[(obligor, obligee)] = (obligor, obligee, forward)
            for forward_key in sorted(canonical_pairs):
                obligor, obligee, net = canonical_pairs[forward_key]
                resolved_count = count_by_pair[forward_key]
                if net < 0:
                    # The reciprocal direction dominates: net flows obligee → obligor.
                    obligor, obligee, net = obligee, obligor, -net
                if net == 0:
                    pairs.append(
                        PairNet(
                            obligor=obligor,
                            obligee=obligee,
                            forward=0,
                            resolved_count=resolved_count,
                            issued_obligation_id=None,
                        )
                    )
                    continue
                issued_ordinal += 1
                pairs.append(
                    PairNet(
                        obligor=obligor,
                        obligee=obligee,
                        forward=net,
                        resolved_count=resolved_count,
                        issued_obligation_id=f"{netting_id}/obligation/{issued_ordinal}",
                    )
                )
            net_total = sum(entry.forward for entry in pairs)
            groups.append(
                NettingGroup(
                    asset=asset,
                    scale=scale,
                    gross=gross,
                    net_total=net_total,
                    pairs=tuple(pairs),
                )
            )
        else:
            positions: dict[str, int] = {}
            for member in group_members:
                positions[member.spec.obligor] = (
                    positions.get(member.spec.obligor, 0) + member.spec.amount.value
                )
                positions[member.spec.obligee] = (
                    positions.get(member.spec.obligee, 0) - member.spec.amount.value
                )
            carried = tuple(
                PositionNet(participant=participant, net=net)
                for participant, net in sorted(positions.items())
                if net != 0
            )
            if sum(position.net for position in carried) != 0:
                raise CoreValidationError(
                    "multilateral positions must conserve: Σ positions = 0 per asset"
                )
            net_total = sum(position.net for position in carried if position.net > 0)
            groups.append(
                NettingGroup(
                    asset=asset,
                    scale=scale,
                    gross=gross,
                    net_total=net_total,
                    positions=carried,
                )
            )

    gross_total = sum(group.gross for group in groups)
    net_total = sum(group.net_total for group in groups)

    valuation = None
    if valuation_spec is not None:
        valuation = _compute_valuation(groups, valuation_spec)

    return NettingStatement(
        calculated_at=calculated_at,
        mode=parsed_mode.value,
        member_total=len(members),
        members=member_bindings,
        groups=tuple(groups),
        gross_total=gross_total,
        net_total=net_total,
        reduction=gross_total - net_total,
        valuation=valuation,
    )


def _compute_valuation(
    groups: Sequence[NettingGroup], spec: ValuationSpec
) -> NettingValuation:
    """Value every asset group into the base currency through money FX."""
    conversions: list[AssetConversion] = []
    gross_base = 0
    net_base = 0
    for group in groups:
        currency = get_currency(spec.currency_for(group.asset))
        if group.scale != currency.scale:
            raise CoreValidationError(
                f"valuation of asset {group.asset} requires the money currency "
                f"{currency.code} canonical scale {currency.scale}; the netting group "
                f"scale is {group.scale} — per-asset arithmetic stays exact and "
                "cross-scale valuation fails closed"
            )
        if currency.code == spec.base_currency:
            # Identity leg: the group's currency is the base currency —
            # value passes through exactly (an FxRate requires distinct
            # currencies, so no rate exists or is needed).
            conversions.append(
                AssetConversion(
                    asset=group.asset,
                    currency=currency.code,
                    rate=None,
                    rounding=spec.rounding,
                    gross_source=group.gross,
                    gross_target=group.gross,
                    gross_residual_numerator=0,
                    gross_residual_denominator=1,
                    net_source=group.net_total,
                    net_target=group.net_total,
                    net_residual_numerator=0,
                    net_residual_denominator=1,
                )
            )
            gross_base += group.gross
            net_base += group.net_total
            continue
        rate = spec.rate_for(currency.code)
        gross_amount = MoneyAmount(currency=currency, value=group.gross, scale=group.scale)
        net_amount = MoneyAmount(
            currency=currency, value=group.net_total, scale=group.scale
        )
        gross_conversion = convert(rate, gross_amount, spec.rounding)
        net_conversion = convert(rate, net_amount, spec.rounding)
        conversions.append(
            AssetConversion(
                asset=group.asset,
                currency=currency.code,
                rate=rate,
                rounding=spec.rounding,
                gross_source=group.gross,
                gross_target=gross_conversion.target.value,
                gross_residual_numerator=gross_conversion.residual_numerator,
                gross_residual_denominator=gross_conversion.residual_denominator,
                net_source=group.net_total,
                net_target=net_conversion.target.value,
                net_residual_numerator=net_conversion.residual_numerator,
                net_residual_denominator=net_conversion.residual_denominator,
            )
        )
        gross_base += gross_conversion.target.value
        net_base += net_conversion.target.value
    return NettingValuation(
        base_currency=spec.base_currency,
        rounding=spec.rounding,
        conversions=tuple(conversions),
        gross_base=gross_base,
        net_base=net_base,
        reduction_base=gross_base - net_base,
    )


# ---------------------------------------------------------------------------
# netting cycle record
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class NettingCycleSpec:
    """Immutable netting cycle payload.

    Identity fields (``netting_id``, ``mode``, ``due_window``) are
    frozen for the object's whole life. ``member_ids`` is the
    append/removable membership (``Add``/``Remove``, only while OPEN);
    ``statement`` is written exactly once by ``Calculate``.
    """

    netting_id: str
    mode: str
    due_window: DueWindow
    member_ids: tuple[str, ...] = ()
    statement: NettingStatement | None = None

    def __post_init__(self) -> None:
        require_identifier("netting.netting_id", self.netting_id)
        parse_enum("netting.mode", self.mode, NettingMode)
        if not isinstance(self.due_window, DueWindow):
            raise CoreValidationError(
                f"netting.due_window must be a DueWindow, got {type(self.due_window).__name__}"
            )
        members = tuple(self.member_ids)
        for entry in members:
            require_identifier("netting.member_ids entry", entry)
        if len(set(members)) != len(members):
            raise CoreValidationError("netting.member_ids contains duplicate obligations")
        if self.statement is not None and not isinstance(self.statement, NettingStatement):
            raise CoreValidationError("netting.statement must be a NettingStatement")

    def to_dict(self) -> dict[str, Any]:
        return {
            "netting_id": self.netting_id,
            "mode": self.mode,
            "due_window": self.due_window.to_dict(),
            "member_ids": list(self.member_ids),
            "statement": self.statement.to_dict() if self.statement is not None else None,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "NettingCycleSpec":
        strict_fields("netting payload", value, _NETTING_SPEC_FIELDS)
        raw_statement = value["statement"]
        statement = (
            NettingStatement.from_dict(raw_statement) if raw_statement is not None else None
        )
        return cls(
            netting_id=value["netting_id"],
            mode=value["mode"],
            due_window=DueWindow.from_dict(value["due_window"]),
            member_ids=tuple(value["member_ids"]),
            statement=statement,
        )


@dataclass(frozen=True, slots=True)
class NettingCycle:
    """Durable netting cycle record (envelope + sealed payload)."""

    envelope: ObjectEnvelope
    spec: NettingCycleSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = NETTING_CYCLE_OBJECT_TYPE
    STATE_TYPE = NettingCycleState

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("netting envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, NettingCycleSpec):
            raise CoreValidationError("netting spec must be a NettingCycleSpec")
        if self.envelope.object_type != NETTING_CYCLE_OBJECT_TYPE:
            raise CoreValidationError(
                f"netting object_type must be {NETTING_CYCLE_OBJECT_TYPE!r}"
            )
        if self.envelope.object_id != self.spec.netting_id:
            raise CoreValidationError("netting object_id must equal spec.netting_id")
        NettingCycleState(self.envelope.state)
        _validate_state_facts(self.envelope.state, self.spec)
        verify_composite(
            self.envelope, self.spec, self.integrity_hash, self.envelope.object_id
        )

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> NettingCycleState:
        return NettingCycleState(self.envelope.state)

    def to_dict(self) -> dict[str, Any]:
        return composite_to_dict(self.envelope, self.spec, self.integrity_hash)

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "NettingCycle":
        envelope, payload = decode_composite(
            value, object_type=NETTING_CYCLE_OBJECT_TYPE, state_type=NettingCycleState
        )
        spec = NettingCycleSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=value["integrity_hash"])

    @classmethod
    def from_json(cls, value: str) -> "NettingCycle":
        envelope, payload, integrity_hash = decode_composite_json(
            value, object_type=NETTING_CYCLE_OBJECT_TYPE, state_type=NettingCycleState
        )
        spec = NettingCycleSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=integrity_hash)


def _validate_state_facts(state: str, spec: NettingCycleSpec) -> None:
    """Cross-check the envelope state against the spec's lifecycle facts."""
    has_statement = spec.statement is not None
    if state == NettingCycleState.OPEN.value and has_statement:
        raise CoreValidationError("an OPEN netting cycle cannot carry a statement")
    if state in (
        NettingCycleState.CALCULATED.value,
        NettingCycleState.FINALIZED.value,
    ) and not has_statement:
        raise CoreValidationError(
            f"a {state} netting cycle must carry its calculated statement"
        )
    if not spec.member_ids and state != NettingCycleState.OPEN.value:
        # A calculated/finalized cycle always has members; an open cycle may.
        if state != NettingCycleState.CANCELLED.value:
            raise CoreValidationError(
                f"a {state} netting cycle must carry its members"
            )


def make_netting_record(
    *,
    spec: NettingCycleSpec,
    environment_id: str,
    domain_id: str,
    provenance: Provenance,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> NettingCycle:
    """Construct the version-1 sealed netting cycle record (state OPEN)."""
    envelope = build_domain_envelope(
        object_id=spec.netting_id,
        object_type=NETTING_CYCLE_OBJECT_TYPE,
        state=NettingCycleState.OPEN.value,
        environment_id=environment_id,
        domain_id=domain_id,
        provenance=provenance,
        causation_id=causation_id,
        correlation_id=correlation_id,
    )
    return NettingCycle(
        envelope=envelope, spec=spec, integrity_hash=seal_composite(envelope, spec)
    )


def derive_issued_obligation(
    *,
    pair: PairNet,
    group: NettingGroup,
    netting_cycle: NettingCycle,
    statement_digest: str,
    environment_id: str,
    domain_id: str,
    provenance: Provenance,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> Obligation:
    """Build the net obligation record one finalized pair issues."""
    if pair.issued_obligation_id is None:
        raise CoreValidationError(
            "a fully offset pair (forward == 0) issues no net obligation"
        )
    obligation_spec = ObligationSpec(
        obligation_id=pair.issued_obligation_id,
        cycle_id=None,
        obligor=pair.obligor,
        obligee=pair.obligee,
        asset=group.asset,
        amount=Amount(value=pair.forward, scale=group.scale, asset=group.asset),
        source_kind="NETTING_ISSUANCE",
        source_ref=netting_cycle.object_id,
        source_digest=statement_digest,
        due_window=netting_cycle.spec.due_window,
    )
    return make_obligation_record(
        spec=obligation_spec,
        environment_id=environment_id,
        domain_id=domain_id,
        provenance=provenance,
        causation_id=causation_id,
        correlation_id=correlation_id,
    )


# ---------------------------------------------------------------------------
# command payload parsers (strict, fail-closed)
# ---------------------------------------------------------------------------

_CREATE_NETTING_FIELDS = frozenset({"netting_id", "mode", "due_window"})
_MEMBER_FIELDS = frozenset({"obligation_id"})
_CALCULATE_FIELDS = frozenset({"valuation"})
_CANCEL_FIELDS = frozenset({"reason"})

_VALUATION_SPEC_FIELDS = frozenset({"base_currency", "rounding", "asset_currencies", "rates"})


def parse_create_netting_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    strict_fields("netting.create payload", value, _CREATE_NETTING_FIELDS)
    require_identifier("netting.create netting_id", value["netting_id"])
    mode = parse_enum("netting.create mode", value["mode"], NettingMode)
    due_window = DueWindow.from_dict(value["due_window"])
    return {"netting_id": value["netting_id"], "mode": mode, "due_window": due_window}


def parse_member_payload(name: str, value: Mapping[str, Any]) -> str:
    strict_fields(name, value, _MEMBER_FIELDS)
    return require_identifier(f"{name} obligation_id", value["obligation_id"])


def parse_calculate_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    """Parse the ``netting.calculate`` payload (optional valuation spec)."""
    strict_fields("netting.calculate payload", value, _CALCULATE_FIELDS)
    raw = value["valuation"]
    if raw is None:
        return {"valuation": None}
    if not isinstance(raw, Mapping):
        raise CoreValidationError("netting.calculate valuation must be an object or null")
    strict_fields("netting.calculate valuation", raw, _VALUATION_SPEC_FIELDS)
    rounding = parse_enum("valuation rounding", raw["rounding"], RoundingMode)
    raw_mappings = raw["asset_currencies"]
    if isinstance(raw_mappings, (str, bytes)) or not isinstance(raw_mappings, (list, tuple)):
        raise CoreValidationError(
            "valuation asset_currencies must be a list of [asset, currency] pairs"
        )
    mappings: list[tuple[str, str]] = []
    for entry in raw_mappings:
        if isinstance(entry, (str, bytes)) or not isinstance(entry, (list, tuple)) or len(entry) != 2:
            raise CoreValidationError(
                "valuation asset_currencies entries must be [asset, currency] pairs"
            )
        asset, code = entry[0], entry[1]
        require_identifier("valuation asset", asset)
        get_currency(code)
        mappings.append((asset, code))
    if not mappings:
        raise CoreValidationError(
            "valuation asset_currencies must not be empty when a valuation is declared"
        )
    raw_rates = raw["rates"]
    if isinstance(raw_rates, (str, bytes)) or not isinstance(raw_rates, (list, tuple)):
        raise CoreValidationError("valuation rates must be a list of FxRate objects")
    rates = tuple(FxRate.from_dict(entry) for entry in raw_rates)
    spec = ValuationSpec(
        base_currency=raw["base_currency"],
        rounding=rounding,
        asset_currencies=mappings,
        rates=rates,
    )
    return {"valuation": spec}


def parse_reason_payload(name: str, value: Mapping[str, Any]) -> str:
    strict_fields(name, value, _CANCEL_FIELDS)
    return require_text(f"{name} reason", value["reason"])
