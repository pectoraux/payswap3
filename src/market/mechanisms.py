"""Pluggable auction mechanisms and deterministic allocation.

A :class:`MechanismEngine` turns one :class:`AllocationRequest` (a closed
market, its submissions, the referenced liquidity offers and the demand)
into one :class:`AllocationResult` — a pure deterministic function with
no I/O and no clock. Two frozen engines exist:

- :class:`RfqEngine` — the default direct-accept mechanism: it selects
  the single best admitted submission able to satisfy the demand
  minimum, fills it pay-as-bid at the submitted price, and emits the
  identifier of the firm quote the session then issues.

- :class:`BatchAuctionEngine` — the uniform-clearing batch mechanism:
  price-time priority (strict ``(price_bps, flat_fee, submitted_at,
  sequence)`` ordering, documented in ``ALLOCATION_CLASS``), partial
  fills, and every fill priced at the uniform clearing price — the
  price of the marginal (last-ranked) filled submission.

Engines re-validate every submission defensively (defense in depth)
through a shared fail-closed cascade: price band first, then admission,
offer lookup, offer coherence, environment and amount bounds. The batch
engine additionally applies the anti-gaming collusion cluster check over
the admitted batch.

Determinism and complexity: ranking is a single sort (O(n log n)) plus a
linear fill pass; no quadratic behavior, no clock, no hidden
nondeterminism.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Mapping

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_json, canonical_sha256, loads_canonical
from src.intent import Demand, DemandState

from .contracts import (
    ALLOCATION_CLASS,
    COLLUSION_CLUSTER_MIN,
    MAX_PRICE_BPS,
    MIN_PRICE_BPS,
    MechanismKind,
)
from ._validation import (
    parse_enum,
    parse_utc_timestamp,
    require_int,
    require_utc_timestamp,
    strict_fields,
)
from .markets import MarketMechanism, MarketState
from .offers import LiquidityOffer, LiquidityOfferState
from .pricing import fee_for_fill
from .submissions import (
    MarketSubmission,
    SubmissionRejectionReason,
    SubmissionState,
)

# ---------------------------------------------------------------------------
# Result vocabulary.
# ---------------------------------------------------------------------------


class AllocationStatus(StrEnum):
    """Closed vocabulary of allocation outcomes."""

    FILLED = "FILLED"
    PARTIALLY_FILLED = "PARTIALLY_FILLED"
    REJECTED = "REJECTED"


class AllocationRejectionReason(StrEnum):
    """Closed vocabulary of typed allocation-level rejection reasons."""

    DEMAND_MIN_NOT_MET = "DEMAND_MIN_NOT_MET"
    NO_ELIGIBLE_SUBMISSIONS = "NO_ELIGIBLE_SUBMISSIONS"


_FILL_FIELDS = frozenset(
    {
        "submission_id",
        "provider",
        "amount_value",
        "price_bps",
        "fee_value",
    }
)

_REJECTION_FIELDS = frozenset({"submission_id", "reason"})

_RESULT_FIELDS = frozenset(
    {
        "market_id",
        "demand_id",
        "mechanism_kind",
        "allocation_class",
        "status",
        "reason",
        "allocated_amount",
        "unfilled_amount",
        "clearing_price_bps",
        "total_fee_value",
        "fills",
        "rejections",
        "reservation_ids",
        "quote_id",
    }
)


@dataclass(frozen=True, slots=True)
class Fill:
    """One deterministic fill: exact amount, price and fee in minor units."""

    submission_id: str
    provider: str
    amount_value: int
    price_bps: int
    fee_value: int

    def __post_init__(self) -> None:
        if not isinstance(self.submission_id, str) or not self.submission_id:
            raise CoreValidationError("fill submission_id must be a non-empty string")
        if not isinstance(self.provider, str) or not self.provider:
            raise CoreValidationError("fill provider must be a non-empty string")
        require_int("fill amount_value", self.amount_value, minimum=1)
        require_int("fill price_bps", self.price_bps, minimum=MIN_PRICE_BPS, maximum=MAX_PRICE_BPS)
        require_int("fill fee_value", self.fee_value, minimum=0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "submission_id": self.submission_id,
            "provider": self.provider,
            "amount_value": self.amount_value,
            "price_bps": self.price_bps,
            "fee_value": self.fee_value,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Fill":
        strict_fields("fill", value, _FILL_FIELDS)
        return cls(
            submission_id=value["submission_id"],
            provider=value["provider"],
            amount_value=value["amount_value"],
            price_bps=value["price_bps"],
            fee_value=value["fee_value"],
        )


@dataclass(frozen=True, slots=True)
class AllocationRejection:
    """One typed per-submission rejection recorded by the engine."""

    submission_id: str
    reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.submission_id, str) or not self.submission_id:
            raise CoreValidationError("rejection submission_id must be a non-empty string")
        parse_enum(
            "rejection.reason", SubmissionRejectionReason, self.reason
        )

    def to_dict(self) -> dict[str, Any]:
        return {"submission_id": self.submission_id, "reason": self.reason}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AllocationRejection":
        strict_fields("allocation rejection", value, _REJECTION_FIELDS)
        return cls(
            submission_id=value["submission_id"], reason=value["reason"]
        )


@dataclass(frozen=True, slots=True)
class AllocationResult:
    """Immutable, deterministic allocation outcome.

    Value conservation is exact: the fills always sum to
    ``allocated_amount`` and the fill fees always sum to
    ``total_fee_value`` (asserted by construction).
    """

    market_id: str
    demand_id: str
    mechanism_kind: str
    allocation_class: str = ALLOCATION_CLASS
    status: AllocationStatus = AllocationStatus.REJECTED
    reason: str | None = None
    allocated_amount: int = 0
    unfilled_amount: int = 0
    clearing_price_bps: int | None = None
    total_fee_value: int = 0
    fills: tuple[Fill, ...] = ()
    rejections: tuple[AllocationRejection, ...] = ()
    reservation_ids: tuple[str, ...] = ()
    quote_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.market_id, str) or not self.market_id:
            raise CoreValidationError("allocation market_id must be a non-empty string")
        if not isinstance(self.demand_id, str) or not self.demand_id:
            raise CoreValidationError("allocation demand_id must be a non-empty string")
        parse_enum("allocation mechanism_kind", MechanismKind, self.mechanism_kind)
        if not isinstance(self.status, AllocationStatus):
            raise CoreValidationError("allocation status must use the closed vocabulary")
        if self.reason is not None:
            parse_enum("allocation reason", AllocationRejectionReason, self.reason)
        require_int("allocation allocated_amount", self.allocated_amount, minimum=0)
        require_int("allocation unfilled_amount", self.unfilled_amount, minimum=0)
        require_int("allocation total_fee_value", self.total_fee_value, minimum=0)
        if self.clearing_price_bps is not None:
            require_int(
                "allocation clearing_price_bps", self.clearing_price_bps,
                minimum=MIN_PRICE_BPS, maximum=MAX_PRICE_BPS,
            )
        if not isinstance(self.fills, tuple):
            raise CoreValidationError("allocation fills must be a tuple")
        if not isinstance(self.rejections, tuple):
            raise CoreValidationError("allocation rejections must be a tuple")
        if not isinstance(self.reservation_ids, tuple):
            raise CoreValidationError("allocation reservation_ids must be a tuple")
        if self.quote_id is not None and (
            not isinstance(self.quote_id, str) or not self.quote_id
        ):
            raise CoreValidationError("allocation quote_id must be a non-empty string")
        # Exact conservation guards (quote integrity invariant).
        if sum(fill.amount_value for fill in self.fills) != self.allocated_amount:
            raise CoreValidationError(
                "allocation fills must sum exactly to allocated_amount"
            )
        if sum(fill.fee_value for fill in self.fills) != self.total_fee_value:
            raise CoreValidationError(
                "allocation fill fees must sum exactly to total_fee_value"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "market_id": self.market_id,
            "demand_id": self.demand_id,
            "mechanism_kind": self.mechanism_kind,
            "allocation_class": self.allocation_class,
            "status": self.status.value,
            "reason": self.reason,
            "allocated_amount": self.allocated_amount,
            "unfilled_amount": self.unfilled_amount,
            "clearing_price_bps": self.clearing_price_bps,
            "total_fee_value": self.total_fee_value,
            "fills": [fill.to_dict() for fill in self.fills],
            "rejections": [rejection.to_dict() for rejection in self.rejections],
            "reservation_ids": list(self.reservation_ids),
            "quote_id": self.quote_id,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    def digest(self) -> str:
        """SHA-256 digest over the canonical allocation record."""
        return canonical_sha256(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AllocationResult":
        strict_fields("allocation result", value, _RESULT_FIELDS)
        fills = value["fills"]
        rejections = value["rejections"]
        reservation_ids = value["reservation_ids"]
        if not isinstance(fills, list):
            raise CoreValidationError("allocation fills must deserialize from a list")
        if not isinstance(rejections, list):
            raise CoreValidationError("allocation rejections must deserialize from a list")
        if not isinstance(reservation_ids, list):
            raise CoreValidationError(
                "allocation reservation_ids must deserialize from a list"
            )
        return cls(
            market_id=value["market_id"],
            demand_id=value["demand_id"],
            mechanism_kind=value["mechanism_kind"],
            allocation_class=value["allocation_class"],
            status=parse_enum("allocation status", AllocationStatus, value["status"]),
            reason=value["reason"],
            allocated_amount=value["allocated_amount"],
            unfilled_amount=value["unfilled_amount"],
            clearing_price_bps=value["clearing_price_bps"],
            total_fee_value=value["total_fee_value"],
            fills=tuple(Fill.from_dict(fill) for fill in fills),
            rejections=tuple(
                AllocationRejection.from_dict(rejection) for rejection in rejections
            ),
            reservation_ids=tuple(reservation_ids),
            quote_id=value["quote_id"],
        )

    @classmethod
    def from_json(cls, value: str) -> "AllocationResult":
        decoded = loads_canonical(value)
        if not isinstance(decoded, dict):
            raise CoreValidationError("allocation result JSON must decode to an object")
        return cls.from_dict(decoded)


# ---------------------------------------------------------------------------
# Requests and the engine abstraction.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AllocationRequest:
    """One closed market, its submissions, offers and demand, at an instant."""

    market: MarketMechanism
    submissions: tuple[MarketSubmission, ...]
    offers: Mapping[str, LiquidityOffer]
    demand: Demand
    as_of: str
    provenance: Any

    def __post_init__(self) -> None:
        if not isinstance(self.market, MarketMechanism):
            raise CoreValidationError("allocation request market must be a MarketMechanism")
        if not isinstance(self.submissions, tuple):
            raise CoreValidationError("allocation request submissions must be a tuple")
        for submission in self.submissions:
            if not isinstance(submission, MarketSubmission):
                raise CoreValidationError(
                    "allocation request submissions must be MarketSubmission records"
                )
        if not isinstance(self.offers, Mapping):
            raise CoreValidationError("allocation request offers must be a mapping")
        if not isinstance(self.demand, Demand):
            raise CoreValidationError("allocation request demand must be a Demand")
        require_utc_timestamp("allocation request as_of", self.as_of)


class MechanismEngine(ABC):
    """Base class of pluggable auction mechanisms.

    Engines are stateless deterministic functions of the request: the
    same request always yields the same result. Subclasses declare their
    frozen :class:`MechanismKind` and implement :meth:`allocate`.
    """

    kind: MechanismKind

    @abstractmethod
    def allocate(self, request: AllocationRequest) -> AllocationResult:
        """Compute the deterministic allocation of one request."""


# ---------------------------------------------------------------------------
# Shared defensive validation cascade (defense in depth).
# ---------------------------------------------------------------------------


def _submission_ref(submission: MarketSubmission) -> str:
    """Deterministic identifier of a submission, sealed or crafted."""
    if submission.envelope is not None:
        return submission.envelope.object_id
    return f"{submission.spec.market_id}/sub/unsealed/{submission.spec.sequence:06d}"


def _validate_submission(
    market: MarketMechanism, submission: MarketSubmission, offers: Mapping[str, LiquidityOffer]
) -> SubmissionRejectionReason | None:
    """Re-validate one submission; ``None`` when it is allocation-eligible.

    The cascade is ordered so that the market's price band is checked
    first (defense in depth: the engine never trusts that the session
    boundary already enforced it), then admission, then full offer
    coherence.
    """
    spec = submission.spec
    if not (
        MIN_PRICE_BPS <= spec.price_bps <= MAX_PRICE_BPS
        and market.spec.price_min_bps <= spec.price_bps <= market.spec.price_max_bps
    ):
        return SubmissionRejectionReason.PRICE_OUT_OF_BAND
    if submission.state != SubmissionState.ACCEPTED:
        return SubmissionRejectionReason.NOT_ADMITTED
    offer = offers.get(spec.offer_id)
    if offer is None:
        return SubmissionRejectionReason.OFFER_INACTIVE
    if not isinstance(offer, LiquidityOffer):
        return SubmissionRejectionReason.OFFER_INACTIVE
    if offer.spec.provider != spec.provider:
        return SubmissionRejectionReason.OFFER_MISMATCH
    if (
        offer.envelope.environment_id != market.envelope.environment_id
        or offer.envelope.domain_id != market.envelope.domain_id
    ):
        return SubmissionRejectionReason.ENVIRONMENT_MISMATCH
    if offer.state is not LiquidityOfferState.ACTIVE:
        return SubmissionRejectionReason.OFFER_INACTIVE
    if offer.spec.price_bps != spec.price_bps or offer.spec.flat_fee != spec.flat_fee:
        return SubmissionRejectionReason.OFFER_MISMATCH
    if not offer.spec.amount_min <= spec.amount <= offer.spec.amount_max:
        return SubmissionRejectionReason.AMOUNT_OUT_OF_OFFER_BOUNDS
    return None


def _validate_request(request: AllocationRequest) -> None:
    market = request.market
    if market.state is not MarketState.CLOSED:
        raise CoreValidationError(
            "allocation requires a CLOSED market; state is "
            f"{market.state.value}"
        )
    demand = request.demand
    if demand.state is not DemandState.OPEN:
        raise CoreValidationError(
            f"allocation requires an OPEN demand; state is {demand.state.value}"
        )
    if demand.envelope.environment_id != market.envelope.environment_id:
        raise CoreValidationError(
            "demand environment must match the market environment; got "
            f"{demand.envelope.environment_id} and {market.envelope.environment_id}"
        )
    if demand.envelope.domain_id != market.envelope.domain_id:
        raise CoreValidationError(
            "demand domain must match the market domain; got "
            f"{demand.envelope.domain_id} and {market.envelope.domain_id}"
        )
    if demand.spec.asset != market.spec.asset:
        raise CoreValidationError(
            "demand asset must match the market asset; got "
            f"{demand.spec.asset} and {market.spec.asset}"
        )
    if demand.spec.amount_scale != market.spec.scale:
        raise CoreValidationError(
            "demand amount scale must match the market scale; got "
            f"{demand.spec.amount_scale} and {market.spec.scale}"
        )
    if demand.spec.amount_max < market.spec.amount_min or demand.spec.amount_min > market.spec.amount_max:
        raise CoreValidationError(
            "demand amount window must intersect the market amount window"
        )


def _rank_key(submission: MarketSubmission) -> tuple[int, int, Any, int]:
    """Strict price-time priority: price, flat fee, instant, sequence."""
    spec = submission.spec
    return (
        spec.price_bps,
        spec.flat_fee,
        parse_utc_timestamp("submission.submitted_at", spec.submitted_at),
        spec.sequence,
    )


def _eligible_submissions(
    request: AllocationRequest,
) -> tuple[list[MarketSubmission], list[AllocationRejection]]:
    """Run the defensive cascade over all submissions of the request."""
    rejections: list[AllocationRejection] = []
    eligible: list[MarketSubmission] = []
    for submission in request.submissions:
        reason = _validate_submission(request.market, submission, request.offers)
        if reason is None:
            eligible.append(submission)
        else:
            rejections.append(
                AllocationRejection(
                    submission_id=_submission_ref(submission), reason=reason.value
                )
            )
    return eligible, rejections


# ---------------------------------------------------------------------------
# RFQ engine: the default direct-accept mechanism.
# ---------------------------------------------------------------------------


def rfq_quote_id(market_id: str) -> str:
    """Deterministic identifier of the firm quote emitted by an RFQ market."""
    return f"{market_id}/quote"


class RfqEngine(MechanismEngine):
    """Direct-accept mechanism: one best submission, pay-as-bid.

    The engine selects the single best admitted submission (strict
    price-time priority) whose submitted amount can satisfy the demand
    minimum on its own, fills it for ``min(demand_max, amount)`` at the
    submitted price, and reports the quote identifier the session uses
    to issue the firm quote for the taker to accept and commit.
    """

    kind = MechanismKind.RFQ

    def allocate(self, request: AllocationRequest) -> AllocationResult:
        _validate_request(request)
        eligible, rejections = _eligible_submissions(request)
        candidates = [
            submission
            for submission in eligible
            if submission.spec.amount >= request.demand.spec.amount_min
        ]
        if not candidates:
            return AllocationResult(
                market_id=request.market.envelope.object_id,
                demand_id=request.demand.envelope.object_id,
                mechanism_kind=self.kind.value,
                status=AllocationStatus.REJECTED,
                reason=AllocationRejectionReason.NO_ELIGIBLE_SUBMISSIONS.value,
                unfilled_amount=request.demand.spec.amount_max,
                rejections=tuple(rejections),
            )
        best = min(candidates, key=_rank_key)
        fill_amount = min(request.demand.spec.amount_max, best.spec.amount)
        fill = Fill(
            submission_id=_submission_ref(best),
            provider=best.spec.provider,
            amount_value=fill_amount,
            price_bps=best.spec.price_bps,
            fee_value=fee_for_fill(fill_amount, best.spec.price_bps, best.spec.flat_fee),
        )
        status = (
            AllocationStatus.FILLED
            if fill_amount == request.demand.spec.amount_max
            else AllocationStatus.PARTIALLY_FILLED
        )
        return AllocationResult(
            market_id=request.market.envelope.object_id,
            demand_id=request.demand.envelope.object_id,
            mechanism_kind=self.kind.value,
            status=status,
            allocated_amount=fill_amount,
            unfilled_amount=request.demand.spec.amount_max - fill_amount,
            clearing_price_bps=None,
            total_fee_value=fill.fee_value,
            fills=(fill,),
            rejections=tuple(rejections),
            quote_id=rfq_quote_id(request.market.envelope.object_id),
        )


# ---------------------------------------------------------------------------
# Batch auction engine: uniform clearing price.
# ---------------------------------------------------------------------------


class BatchAuctionEngine(MechanismEngine):
    """Uniform-price batch auction with documented price-time priority.

    Rule (``ALLOCATION_CLASS``): admitted, validated submissions are
    ranked by strict ``(price_bps, flat_fee, submitted_at, sequence)``
    ordering and filled greedily toward the demand maximum. Every fill is
    priced at the uniform clearing price — the price of the marginal
    (last filled) submission — while each fill keeps its own submission's
    flat fee. The demand's ``max_payment_count`` bounds the number of
    fills once the demand minimum is secured; when the minimum cannot be
    met within that bound (and the demand allows splits), the engine
    keeps filling until the minimum is met, because meeting the economic
    ask outranks the payment-count preference. A non-splittable demand
    never fills more than one submission. If the minimum cannot be met
    at all, the whole allocation is rejected with ``DEMAND_MIN_NOT_MET``.

    Anti-gaming: before ranking, the engine flags mirrored-quote
    clusters — at least ``COLLUSION_CLUSTER_MIN`` distinct providers
    quoting the identical ``(price, flat fee, amount)`` triple while the
    batch shows genuine price dispersion — and excludes them as
    ``COLLUSION_SUSPECTED`` (fail closed).

    Complexity: one sort (O(n log n)) plus linear validation and fill
    passes; the hook ``_fill_price`` lets a subclass replace the fill
    pricing rule without touching the deterministic plan.
    """

    kind = MechanismKind.BATCH_AUCTION

    def __init__(self) -> None:
        # Hook context: the uniform clearing price of the current plan.
        # Set and consumed inside one allocate call only.
        self._clearing_price_bps: int | None = None

    def _fill_price(self, submission: MarketSubmission) -> int:
        """Price of one planned fill; default: the uniform clearing price.

        Subclasses override this hook to change the pricing rule (for
        example pay-as-bid). The uniform clearing price of the current
        plan is available as engine state during :meth:`allocate`.
        """
        if self._clearing_price_bps is None:
            raise CoreValidationError(
                "fill pricing requires a non-empty allocation plan"
            )
        return self._clearing_price_bps

    def _collusion_rejections(
        self, eligible: list[MarketSubmission]
    ) -> list[MarketSubmission]:
        """Fail-closed mirrored-quote cluster check (anti-gaming hook)."""
        if len(eligible) < COLLUSION_CLUSTER_MIN:
            return []
        prices = {submission.spec.price_bps for submission in eligible}
        if len(prices) < 2:
            # No price dispersion: identical pricing is indistinguishable
            # from a thin market and is not flagged.
            return []
        clusters: dict[tuple[int, int, int], list[MarketSubmission]] = {}
        for submission in eligible:
            spec = submission.spec
            key = (spec.price_bps, spec.flat_fee, spec.amount)
            clusters.setdefault(key, []).append(submission)
        flagged: list[MarketSubmission] = []
        for members in clusters.values():
            providers = {member.spec.provider for member in members}
            if len(members) >= COLLUSION_CLUSTER_MIN and len(providers) >= COLLUSION_CLUSTER_MIN:
                flagged.extend(members)
        return flagged

    def allocate(self, request: AllocationRequest) -> AllocationResult:
        _validate_request(request)
        eligible, rejections = _eligible_submissions(request)

        # Anti-gaming: collusion cluster over the admitted batch.
        flagged = self._collusion_rejections(eligible)
        if flagged:
            flagged_refs = {id(submission) for submission in flagged}
            for submission in flagged:
                rejections.append(
                    AllocationRejection(
                        submission_id=_submission_ref(submission),
                        reason=SubmissionRejectionReason.COLLUSION_SUSPECTED.value,
                    )
                )
            eligible = [
                submission
                for submission in eligible
                if id(submission) not in flagged_refs
            ]

        demand = request.demand
        ranked = sorted(eligible, key=_rank_key)
        target = demand.spec.amount_max
        minimum = demand.spec.amount_min
        cap = 1 if not demand.spec.allow_split else demand.spec.max_payment_count

        plan: list[tuple[MarketSubmission, int]] = []
        total = 0
        for submission in ranked:
            if total >= target:
                break
            if len(plan) >= cap and total >= minimum:
                break
            take = min(target - total, submission.spec.amount)
            if take <= 0:
                continue
            plan.append((submission, take))
            total += take

        if not eligible or (total < minimum):
            reason = (
                AllocationRejectionReason.NO_ELIGIBLE_SUBMISSIONS
                if not eligible
                else AllocationRejectionReason.DEMAND_MIN_NOT_MET
            )
            return AllocationResult(
                market_id=request.market.envelope.object_id,
                demand_id=request.demand.envelope.object_id,
                mechanism_kind=self.kind.value,
                status=AllocationStatus.REJECTED,
                reason=reason.value,
                unfilled_amount=target,
                rejections=tuple(rejections),
            )

        self._clearing_price_bps = plan[-1][0].spec.price_bps
        fills = tuple(
            Fill(
                submission_id=_submission_ref(submission),
                provider=submission.spec.provider,
                amount_value=amount,
                price_bps=self._fill_price(submission),
                fee_value=fee_for_fill(
                    amount, self._fill_price(submission), submission.spec.flat_fee
                ),
            )
            for submission, amount in plan
        )
        clearing_price_bps = self._clearing_price_bps
        self._clearing_price_bps = None

        status = (
            AllocationStatus.FILLED if total == target else AllocationStatus.PARTIALLY_FILLED
        )
        return AllocationResult(
            market_id=request.market.envelope.object_id,
            demand_id=request.demand.envelope.object_id,
            mechanism_kind=self.kind.value,
            status=status,
            allocated_amount=total,
            unfilled_amount=target - total,
            clearing_price_bps=clearing_price_bps,
            total_fee_value=sum(fill.fee_value for fill in fills),
            fills=fills,
            rejections=tuple(rejections),
        )


#: Frozen registry of the shipped mechanism engines.
MECHANISM_ENGINES: Mapping[MechanismKind, MechanismEngine] = MappingProxyType(
    {
        MechanismKind.RFQ: RfqEngine(),
        MechanismKind.BATCH_AUCTION: BatchAuctionEngine(),
    }
)


def resolve_engine(engine: Any, market: MarketMechanism) -> MechanismEngine:
    """Resolve and validate the engine of one allocation command."""
    if not isinstance(engine, MechanismEngine):
        raise CoreValidationError(
            f"mechanism engines must be MechanismEngine instances, got {type(engine).__name__}"
        )
    if engine.kind.value != market.spec.mechanism_kind:
        raise CoreValidationError(
            f"engine mechanism {engine.kind.value} does not match market mechanism "
            f"{market.spec.mechanism_kind}"
        )
    return engine
