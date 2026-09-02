"""Market sessions: the command processor for one market instance.

A :class:`MarketSession` drives one :class:`MarketMechanism` through the
frozen ``Market`` command family — ``Open/Submit/Withdraw/Accept/Reject/
Close/Allocate/Cancel`` — keeping the current immutable market record,
the submission records, the reservations created by a batch allocation
and the firm quote emitted by an RFQ allocation. Every step is a
deterministic transition over explicit instants with typed, explicit
failure outcomes; the session performs no I/O, touches no accounting
state and produces no external effect (accounting and execution belong
to later sibling Work Orders).

Submission-time anti-gaming guards (typed rejection reasons, ordered):
``MARKET_NOT_OPEN``, ``WINDOW_CLOSED``, ``SELF_DEALING``,
``ENVIRONMENT_MISMATCH``, ``OFFER_MISMATCH``, ``OFFER_INACTIVE``,
``PRICE_OUT_OF_BAND``, ``AMOUNT_OUT_OF_OFFER_BOUNDS``,
``DUPLICATE_SUBMISSION``, ``MARKET_AT_CAPACITY``. Withdrawal is locked
after close (``SUBMISSION_LOCKED``) and after allocation
(``ALLOCATION_FINAL``).
"""

from __future__ import annotations

from dataclasses import replace

from src.core.envelope import Provenance
from src.core.errors import CoreValidationError
from src.intent import Demand

from .contracts import (
    DEFAULT_QUOTE_VALIDITY_SECONDS,
    DEFAULT_RESERVATION_HOLD_SECONDS,
    MAX_PRICE_BPS,
    MIN_PRICE_BPS,
    MechanismKind,
)
from ._validation import (
    offset_utc_timestamp,
    require_identifier,
    require_utc_timestamp,
    utc_timestamp_within,
)
from .markets import (
    MarketMechanism,
    MarketState,
    cancel_market,
    close_market,
    open_market,
)
from .mechanisms import (
    MECHANISM_ENGINES,
    AllocationRequest,
    AllocationResult,
    MechanismEngine,
    rfq_quote_id,
    resolve_engine,
)
from .offers import LiquidityOffer, LiquidityOfferState
from .quotes import (
    Quote,
    QuoteReasonCode,
    QuoteState,
    create_quote,
    invalidate_quote,
)
from .reservations import (
    Reservation,
    commit_reservation,
    create_reservation,
    release_reservation,
)
from .submissions import (
    MarketSubmission,
    SubmissionRejectionReason,
    SubmissionResult,
    SubmissionState,
    build_submission,
    parse_rejection_reason,
)

_ACTIVE_SUBMISSION_STATES = (SubmissionState.SUBMITTED, SubmissionState.ACCEPTED)


class MarketSession:
    """Deterministic command processor for one market.

    The session is mutable state over immutable records: each command
    validates preconditions fail-closed, produces the next sealed record
    versions and returns them. It never rewrites history.
    """

    def __init__(self, market: MarketMechanism) -> None:
        if not isinstance(market, MarketMechanism):
            raise CoreValidationError("MarketSession requires a MarketMechanism")
        self._market = market
        self._submissions: list[MarketSubmission] = []
        self._reservations: tuple[Reservation, ...] = ()
        self._quote: Quote | None = None
        self._sequence = 0

    # -- projections -------------------------------------------------------

    @property
    def market(self) -> MarketMechanism:
        return self._market

    @property
    def submissions(self) -> tuple[MarketSubmission, ...]:
        return tuple(self._submissions)

    @property
    def reservations(self) -> tuple[Reservation, ...]:
        return self._reservations

    @property
    def quote(self) -> Quote | None:
        return self._quote

    # -- market phase commands ----------------------------------------------

    def open(self, as_of: str = "", *, provenance: Provenance) -> MarketMechanism:
        """Open the market (the ``Open`` command)."""
        if not as_of:
            raise CoreValidationError("session open requires an explicit as_of instant")
        self._market = open_market(self._market, as_of, provenance=provenance)
        return self._market

    def close(self, as_of: str = "", *, provenance: Provenance) -> MarketMechanism:
        """Close the market once its trading window elapsed (``Close``)."""
        if not as_of:
            raise CoreValidationError("session close requires an explicit as_of instant")
        self._market = close_market(self._market, as_of, provenance=provenance)
        return self._market

    def cancel(self, as_of: str = "", *, provenance: Provenance) -> MarketMechanism:
        """Cancel the market before allocation (``Cancel``)."""
        if not as_of:
            raise CoreValidationError("session cancel requires an explicit as_of instant")
        self._market = cancel_market(self._market, as_of, provenance=provenance)
        return self._market

    # -- submission commands -------------------------------------------------

    def submit(
        self,
        *,
        provider: str,
        offer: LiquidityOffer,
        amount: int,
        submitted_at: str,
        provenance: Provenance,
    ) -> SubmissionResult:
        """Submit one provider's offer into the market (``Submit``).

        Anti-gaming guards are typed and ordered; a rejected submission
        is an observable outcome, not an exception.
        """
        if not isinstance(offer, LiquidityOffer):
            raise CoreValidationError("submit requires a LiquidityOffer")
        require_identifier("submit.provider", provider)
        require_utc_timestamp("submit.submitted_at", submitted_at)
        if not isinstance(amount, int) or isinstance(amount, bool) or amount < 1:
            raise CoreValidationError(f"submit amount must be a positive integer, got {amount!r}")
        market = self._market
        spec = market.spec

        if market.state is not MarketState.OPEN:
            return SubmissionResult(SubmissionRejectionReason.MARKET_NOT_OPEN, None)
        if not utc_timestamp_within(spec.opens_at, submitted_at, spec.closes_at):
            return SubmissionResult(SubmissionRejectionReason.WINDOW_CLOSED, None)
        if provider == spec.taker:
            return SubmissionResult(SubmissionRejectionReason.SELF_DEALING, None)
        if (
            offer.envelope.environment_id != market.envelope.environment_id
            or offer.envelope.domain_id != market.envelope.domain_id
        ):
            return SubmissionResult(SubmissionRejectionReason.ENVIRONMENT_MISMATCH, None)
        if offer.spec.provider != provider:
            return SubmissionResult(SubmissionRejectionReason.OFFER_MISMATCH, None)
        if offer.state is not LiquidityOfferState.ACTIVE:
            return SubmissionResult(SubmissionRejectionReason.OFFER_INACTIVE, None)
        if not (
            MIN_PRICE_BPS <= offer.spec.price_bps <= MAX_PRICE_BPS
            and spec.price_min_bps <= offer.spec.price_bps <= spec.price_max_bps
        ):
            return SubmissionResult(SubmissionRejectionReason.PRICE_OUT_OF_BAND, None)
        if not offer.spec.amount_min <= amount <= offer.spec.amount_max:
            return SubmissionResult(SubmissionRejectionReason.AMOUNT_OUT_OF_OFFER_BOUNDS, None)
        if any(
            submission.spec.provider == provider and submission.state in _ACTIVE_SUBMISSION_STATES
            for submission in self._submissions
        ):
            return SubmissionResult(SubmissionRejectionReason.DUPLICATE_SUBMISSION, None)
        if (
            sum(
                1
                for submission in self._submissions
                if submission.state in _ACTIVE_SUBMISSION_STATES
            )
            >= spec.max_submissions
        ):
            return SubmissionResult(SubmissionRejectionReason.MARKET_AT_CAPACITY, None)

        self._sequence += 1
        submission = build_submission(
            market_id=market.envelope.object_id,
            provider=provider,
            offer_id=offer.envelope.object_id,
            amount=amount,
            price_bps=offer.spec.price_bps,
            flat_fee=offer.spec.flat_fee,
            submitted_at=submitted_at,
            sequence=self._sequence,
            environment_id=market.envelope.environment_id,
            domain_id=market.envelope.domain_id,
            provenance=provenance,
            correlation_id=market.envelope.correlation_id,
        )
        self._submissions.append(submission)
        return SubmissionResult(None, submission)

    def withdraw(
        self, submission_id: str, *, as_of: str, provenance: Provenance
    ) -> SubmissionResult:
        """Withdraw a submission (``Withdraw``); locked after close/allocation."""
        require_identifier("withdraw.submission_id", submission_id)
        require_utc_timestamp("withdraw.as_of", as_of)
        state = self._market.state
        if state is MarketState.OPEN:
            pass
        elif state in (MarketState.CLOSED, MarketState.CANCELLED, MarketState.CREATED):
            return SubmissionResult(SubmissionRejectionReason.SUBMISSION_LOCKED, None)
        else:
            return SubmissionResult(SubmissionRejectionReason.ALLOCATION_FINAL, None)
        submission = self._find_submission(submission_id)
        if submission.state not in _ACTIVE_SUBMISSION_STATES:
            raise CoreValidationError(
                "only a SUBMITTED or ACCEPTED submission can be withdrawn; state is "
                f"{submission.state.value if submission.state else None}"
            )
        withdrawn = submission._advance(
            SubmissionState.WITHDRAWN, provenance=provenance
        )
        self._replace_submission(withdrawn)
        return SubmissionResult(None, withdrawn)

    def admit(self, submission_id: str, *, as_of: str, provenance: Provenance) -> MarketSubmission:
        """Adjudicate a submission as admitted (the ``Accept`` command)."""
        require_identifier("admit.submission_id", submission_id)
        require_utc_timestamp("admit.as_of", as_of)
        if self._market.state is not MarketState.OPEN:
            raise CoreValidationError(
                "submission admission requires an OPEN market; state is "
                f"{self._market.state.value}"
            )
        submission = self._find_submission(submission_id)
        if submission.state is not SubmissionState.SUBMITTED:
            raise CoreValidationError(
                "only a SUBMITTED submission can be admitted; state is "
                f"{submission.state.value if submission.state else None}"
            )
        admitted = submission._advance(SubmissionState.ACCEPTED, provenance=provenance)
        self._replace_submission(admitted)
        return admitted

    def reject_submission(
        self,
        submission_id: str,
        *,
        reason: SubmissionRejectionReason,
        as_of: str,
        provenance: Provenance,
    ) -> MarketSubmission:
        """Reject a submission for an operator policy reason (``Reject``)."""
        require_identifier("reject.submission_id", submission_id)
        reason = parse_rejection_reason("reject.reason", reason)
        require_utc_timestamp("reject.as_of", as_of)
        if self._market.state is not MarketState.OPEN:
            raise CoreValidationError(
                "submission rejection requires an OPEN market; state is "
                f"{self._market.state.value}"
            )
        submission = self._find_submission(submission_id)
        if submission.state not in _ACTIVE_SUBMISSION_STATES:
            raise CoreValidationError(
                "only a SUBMITTED or ACCEPTED submission can be rejected; state is "
                f"{submission.state.value if submission.state else None}"
            )
        rejected = submission._advance(
            SubmissionState.REJECTED, provenance=provenance, reason=reason.value
        )
        self._replace_submission(rejected)
        return rejected

    # -- allocation and adjudication ------------------------------------------

    def allocate(
        self,
        *,
        demand: Demand,
        offers: dict[str, LiquidityOffer],
        as_of: str,
        provenance: Provenance,
        engine: MechanismEngine | None = None,
    ) -> AllocationResult:
        """Run the market's mechanism engine (the ``Allocate`` command).

        The engine is resolved from the frozen registry unless one is
        injected; an injected engine must be a :class:`MechanismEngine`
        of the market's declared mechanism kind. After a successful
        allocation the market is ALLOCATED; a batch allocation creates
        the reservations of the fills, an RFQ allocation emits the firm
        quote for the taker.
        """
        if not isinstance(demand, Demand):
            raise CoreValidationError("allocate requires a Demand")
        if not isinstance(offers, dict):
            raise CoreValidationError("allocate requires a mapping of offers")
        require_utc_timestamp("allocate.as_of", as_of)
        if self._market.state is not MarketState.CLOSED:
            raise CoreValidationError(
                "allocation requires a CLOSED market; state is "
                f"{self._market.state.value}"
            )
        resolved = resolve_engine(
            engine if engine is not None else MECHANISM_ENGINES[
                MechanismKind(self._market.spec.mechanism_kind)
            ],
            self._market,
        )
        request = AllocationRequest(
            market=self._market,
            submissions=tuple(self._submissions),
            offers=offers,
            demand=demand,
            as_of=as_of,
            provenance=provenance,
        )
        # The Allocate command is final once accepted: the market passes
        # into ALLOCATED before the engine runs, so a failed (raising)
        # attempt cannot be silently retried — recovery requires an
        # explicit reject/cancel of the allocation.
        self._market = self._market._advance(MarketState.ALLOCATED, provenance=provenance)
        outcome = resolved.allocate(request)

        if resolved.kind is MechanismKind.RFQ:
            outcome = self._apply_rfq_outcome(outcome, demand, offers, as_of, provenance)
        else:
            outcome = self._apply_batch_outcome(outcome, as_of, provenance)

        return outcome

    def accept(
        self, *, as_of: str, provenance: Provenance, quote: Quote | None = None
    ) -> MarketMechanism:
        """Accept the allocation (the market-level ``Accept`` command).

        Batch markets commit their reservations; RFQ markets require the
        committed quote (produced by the taker accepting and committing
        the emitted firm quote) to be supplied.
        """
        require_utc_timestamp("accept.as_of", as_of)
        if self._market.state is not MarketState.ALLOCATED:
            raise CoreValidationError(
                "only an ALLOCATED market can be accepted; state is "
                f"{self._market.state.value}"
            )
        kind = MechanismKind(self._market.spec.mechanism_kind)
        if kind is MechanismKind.RFQ:
            if quote is None:
                raise CoreValidationError(
                    "an RFQ market can only be accepted together with its committed quote"
                )
            if not isinstance(quote, Quote):
                raise CoreValidationError("accept requires a Quote")
            if quote.state is not QuoteState.COMMITTED:
                raise CoreValidationError(
                    f"the RFQ market quote must be COMMITTED; state is {quote.state.value}"
                )
            if self._quote is not None and quote.envelope.object_id != self._quote.envelope.object_id:
                raise CoreValidationError(
                    "the supplied quote is not the quote emitted by this market"
                )
            self._quote = quote
        else:
            if quote is not None:
                raise CoreValidationError(
                    "a batch auction market is accepted without a quote"
                )
            self._reservations = tuple(
                commit_reservation(reservation, as_of=as_of, provenance=provenance)
                for reservation in self._reservations
            )
        self._market = self._market._advance(MarketState.ACCEPTED, provenance=provenance)
        return self._market

    def reject_allocation(self, *, as_of: str, provenance: Provenance) -> MarketMechanism:
        """Reject the allocation (the market-level ``Reject`` command).

        Batch markets release their reservations; RFQ markets invalidate
        the uncommitted emitted quote.
        """
        require_utc_timestamp("reject_allocation.as_of", as_of)
        if self._market.state is not MarketState.ALLOCATED:
            raise CoreValidationError(
                "only an ALLOCATED market can reject its allocation; state is "
                f"{self._market.state.value}"
            )
        kind = MechanismKind(self._market.spec.mechanism_kind)
        if kind is MechanismKind.RFQ:
            if self._quote is not None and self._quote.state in (
                QuoteState.FIRM,
                QuoteState.ACCEPTED,
            ):
                self._quote = invalidate_quote(
                    self._quote, reason=QuoteReasonCode.TAKER_DECLINED, provenance=provenance
                )
        else:
            self._reservations = tuple(
                release_reservation(reservation, provenance=provenance)
                for reservation in self._reservations
            )
        self._market = self._market._advance(MarketState.REJECTED, provenance=provenance)
        return self._market

    # -- internals -----------------------------------------------------------

    def _find_submission(self, submission_id: str) -> MarketSubmission:
        for submission in self._submissions:
            if submission.envelope.object_id == submission_id:
                return submission
        raise CoreValidationError(f"unknown submission {submission_id!r} in this session")

    def _replace_submission(self, updated: MarketSubmission) -> None:
        object_id = updated.envelope.object_id
        for index, submission in enumerate(self._submissions):
            if submission.envelope.object_id == object_id:
                self._submissions[index] = updated
                return
        raise CoreValidationError(f"unknown submission {object_id!r} in this session")

    def _apply_batch_outcome(
        self, outcome: AllocationResult, as_of: str, provenance: Provenance
    ) -> AllocationResult:
        """Apply fill/unfill states and create the fill reservations."""
        fill_by_id = {fill.submission_id: fill for fill in outcome.fills}
        reservations: list[Reservation] = []
        for submission in self._submissions:
            submission_id = submission.envelope.object_id
            if submission_id in fill_by_id:
                fill = fill_by_id[submission_id]
                new_state = (
                    SubmissionState.ALLOCATED_FULL
                    if fill.amount_value == submission.spec.amount
                    else SubmissionState.ALLOCATED_PARTIAL
                )
                self._replace_submission(
                    submission._advance(new_state, provenance=provenance)
                )
                reservations.append(
                    create_reservation(
                        reservation_id=f"{self._market.envelope.object_id}/res/{len(reservations) + 1:06d}",
                        provider=submission.spec.provider,
                        beneficiary=self._market.spec.taker,
                        asset=self._market.spec.asset,
                        scale=self._market.spec.scale,
                        amount_value=fill.amount_value,
                        source_quote_id=submission_id,
                        reserved_from=as_of,
                        reserved_until=offset_utc_timestamp(
                            "reservation as_of", as_of, DEFAULT_RESERVATION_HOLD_SECONDS
                        ),
                        environment_id=self._market.envelope.environment_id,
                        domain_id=self._market.envelope.domain_id,
                        provenance=provenance,
                        correlation_id=self._market.envelope.correlation_id,
                    )
                )
            elif submission.state is SubmissionState.ACCEPTED:
                self._replace_submission(
                    submission._advance(SubmissionState.UNALLOCATED, provenance=provenance)
                )
        self._reservations = tuple(reservations)
        if reservations:
            outcome = replace(
                outcome, reservation_ids=tuple(
                    reservation.envelope.object_id for reservation in reservations
                )
            )
        return outcome

    def _apply_rfq_outcome(
        self,
        outcome: AllocationResult,
        demand: Demand,
        offers: dict[str, LiquidityOffer],
        as_of: str,
        provenance: Provenance,
    ) -> AllocationResult:
        """Advance submission states and emit the RFQ firm quote."""
        fill_by_id = {fill.submission_id: fill for fill in outcome.fills}
        for submission in self._submissions:
            submission_id = submission.envelope.object_id
            if submission_id in fill_by_id:
                fill = fill_by_id[submission_id]
                new_state = (
                    SubmissionState.ALLOCATED_FULL
                    if fill.amount_value == submission.spec.amount
                    else SubmissionState.ALLOCATED_PARTIAL
                )
                self._replace_submission(
                    submission._advance(new_state, provenance=provenance)
                )
            elif submission.state is SubmissionState.ACCEPTED:
                self._replace_submission(
                    submission._advance(SubmissionState.UNALLOCATED, provenance=provenance)
                )
        if not outcome.fills:
            return outcome
        fill = outcome.fills[0]
        submission = self._find_submission(fill.submission_id)
        offer = offers.get(submission.spec.offer_id)
        if offer is None:
            raise CoreValidationError(
                f"RFQ quote emission requires the winning offer {submission.spec.offer_id!r}"
            )
        market = self._market
        quote = create_quote(
            quote_id=rfq_quote_id(market.envelope.object_id),
            demand_id=demand.envelope.object_id,
            maker=fill.provider,
            asset=market.spec.asset,
            scale=market.spec.scale,
            amount_min=max(demand.spec.amount_min, offer.spec.amount_min),
            amount_max=min(demand.spec.amount_max, fill.amount_value),
            price_bps=fill.price_bps,
            flat_fee=submission.spec.flat_fee,
            valid_from=as_of,
            valid_until=offset_utc_timestamp(
                "rfq as_of", as_of, DEFAULT_QUOTE_VALIDITY_SECONDS
            ),
            offer=offer,
            environment_id=market.envelope.environment_id,
            domain_id=market.envelope.domain_id,
            provenance=provenance,
            correlation_id=market.envelope.correlation_id,
        )
        self._quote = quote
        return outcome
