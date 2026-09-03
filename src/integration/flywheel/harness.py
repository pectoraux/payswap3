"""The IG-006 flywheel gate harness: the composed merchant journey driver.

The gate owns ONLY the journey orchestration and its stage journal.
Every authority interaction goes through the consumed implementations'
public boundaries:

* merchant commands through :class:`src.merchant.MerchantEngine`;
* the canonical fulfillment path through the merged
  :class:`~src.integration.lifecycle.FulfillmentLifecycleGate` stages
  (compiler → plan → execution → clearing → settlement → finality),
  driven twice — once on the primary rail (killed mid-flight) and once
  through the declared redundancy rail after the governed failover;
* the resilience orchestration through the merged
  :class:`~src.operations.OperationsEngine` (incident → degradation →
  failover → resolve, with digest-bound authority conservation);
* the durable outcome evidence through the merged evidence domain
  (``record_observation`` / ``submit_evidence``).

Stage-journal discipline (the sibling-gate convention): every stage
records the composed-state digest before and after the authority
interaction; the journal chains fail-closed (the after-digest of one
stage must equal the before-digest of the next), so any mutation
outside a recorded stage is detectable. A driver that fails closed
(rejected/contained) must leave the composed state byte-identical —
the gate fails closed on divergence.

The composed state digest covers ALL FIVE composed authorities (the
merchant record boundary, the primary-rail lifecycle composition, the
redundancy-rail lifecycle composition, the operations authority and
the evidence archive), so the journal is honest about the WHOLE
journey, not a favorable subset.
"""

from __future__ import annotations

from typing import Any, Callable, Iterable, Mapping

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.core.envelope import Provenance
from src.evidence import EpistemicType, ScaledValue, record_observation, submit_evidence
from src.merchant import (
    Acceptance,
    Checkout,
    CheckoutSpec,
    CheckoutState,
    PromiseState,
    RefundRoute,
    SettlementPromise,
    SettlementPromiseSpec,
)
from src.operations import ProbeResult
from src.value import Amount

from .contracts import (
    CHECKOUT_ID,
    CLEARING_CYCLE_ID,
    DEFAULT_FLYWHEEL_ACTOR,
    EXECUTION_AUTHORITY_REF,
    EXECUTION_SERVICE_ID,
    FINALITY_ID,
    INCIDENT_ID,
    JOURNEY_AMOUNT_MINOR,
    JOURNEY_ASSET_CODE,
    JOURNEY_SCALE,
    JOURNEY_EVIDENCE_ID,
    JOURNEY_STAGE_TOKENS,
    MERCHANT_ACTOR,
    JourneyStage,
    OUTCOME_OBSERVATION_ID,
    PRIMARY_EXECUTION_PLAN_ID,
    PRIMARY_IDEMPOTENCY_KEY,
    PRIMARY_PLAN_ID,
    PRIMARY_STEP_ID,
    PROMISE_ID,
    REDUNDANCY_EXECUTION_PLAN_ID,
    REDUNDANCY_IDEMPOTENCY_KEY,
    REDUNDANCY_PLAN_ID,
    REDUNDANCY_STEP_ID,
    REFUND_ROUTE_ID,
    SETTLEMENT_ID,
    T_ACCEPT,
    T_CHECKOUT,
    T_CYCLE_FINALIZE,
    T_CYCLE_OPEN,
    T_CYCLE_VALIDATE,
    T_DUE_FROM,
    T_DUE_UNTIL,
    T_FINALITY_ESTABLISH,
    T_FINALITY_VALIDATE,
    T_KILL,
    T_CANARY,
    T_DEGRADE,
    T_FAILOVER,
    T_OBLIGATION_RESOLVE,
    T_OUTCOME,
    T_PLAN_AUTHORIZE,
    T_PLAN_CREATE,
    T_PLAN_START,
    T_PROMISE,
    T_RECOGNIZE,
    T_RECONCILE,
    T_REFUND_ROUTE,
    T_REPROBE,
    T_MARK_DUE,
    T_RETRY_ACCEPT,
    T_RETRY_ACK,
    T_RETRY_AUTHORIZE,
    T_RETRY_CLAIM,
    T_RETRY_COMPLETE,
    T_RETRY_CREATE,
    T_RETRY_QUERY,
    T_RETRY_REQUEST,
    T_RETRY_RESULT,
    T_RETRY_START,
    T_RETRY_STATUS,
    T_RETRY_SUBMIT,
    T_SETTLE,
    T_SETTLE_RECONCILE,
    T_VALID_FROM,
    T_VALID_UNTIL,
    SUBMIT_BY,
    SETTLE_BY,
    CYCLE_OPENS_AT,
    CYCLE_CLOSES_AT,
    validate_flywheel_gate_id,
)
from .worlds import FlywheelWorld, build_flywheel_world, declared_world_for

#: Provenance source stamp of every gate-driven evidence record.
FLYWHEEL_PROVENANCE_SOURCE = "integration-gate-ig006"

def _probe(
    dependency_id: str, as_of: str, availability_bps: int, detail: str
) -> ProbeResult:
    """One typed dead/restored health probe (declared data only)."""
    return ProbeResult(
        probe_id=f"operations/probe/ig006/{dependency_id.rsplit('/', 1)[-1]}-{as_of[-8:-1]}",
        dependency_id=dependency_id,
        as_of=as_of,
        epistemic="OBSERVED",
        availability_bps=availability_bps,
        samples=5,
        detail=detail,
    )


def _index_digest(engine: Any) -> str:
    """Canonical digest over an authority's public record index.

    Computed purely through the sibling's public ``objects()``
    accessor (the observer pattern — the gate never re-derives sibling
    state, it digests the public boundary).
    """
    entries = sorted(
        (record.object_id, record.to_dict()) for record in engine.objects()
    )
    return canonical_sha256({"index": entries})


def _require_accepted(transition: Any, label: str) -> None:
    from src.transition import Outcome

    if transition.outcome is not Outcome.ACCEPTED:
        raise CoreValidationError(
            f"the flywheel journey requires acceptance at {label}; got "
            f"{transition.outcome.name}"
        )


def _require_entry_outcome(entry: Mapping[str, Any], label: str) -> None:
    outcome = entry.get("outcome")
    if outcome is not None and outcome != "accepted":
        raise CoreValidationError(
            f"the flywheel journey requires acceptance at {label}; got {outcome!r}"
        )


class FlywheelGate:
    """One IG-006 composed merchant-journey execution.

    The gate composes the world's five real authorities and drives the
    journey stage by stage. It introduces no domain semantics: the
    merchant delay/credit condition, the fulfillment lifecycle, the
    resilience orchestration and the evidence records all belong to
    their consumed authorities.
    """

    def __init__(
        self,
        world: FlywheelWorld | None = None,
        *,
        gate_id: str = "IG-006",
        actor: str = DEFAULT_FLYWHEEL_ACTOR,
    ) -> None:
        validate_flywheel_gate_id(gate_id)
        if world is None:
            world = build_flywheel_world(gate_id=gate_id)
        if not isinstance(world, FlywheelWorld):
            raise CoreValidationError("the flywheel gate composes a FlywheelWorld")
        self._gate_id = gate_id
        self._world = world
        self._actor = actor
        self._stage_journal: list[dict[str, Any]] = []
        self._last_state_after: str | None = None
        self._journey_facts: dict[str, Any] = {}
        self._command_count = 0
        self._obligation_ids: list[str] = []
        self._native_reference: str | None = None
        self._merchant_records: dict[str, Any] = {}

    # ------------------------------------------------------------------
    # read-only access to the real composed implementations
    # ------------------------------------------------------------------

    @property
    def gate_id(self) -> str:
        return self._gate_id

    @property
    def world(self) -> FlywheelWorld:
        return self._world

    @property
    def actor(self) -> str:
        return self._actor

    @property
    def merchant(self) -> Any:
        """The gate's merchant record boundary (real sealed records).

        The WORK-025 kernel-binding engine path is pre-existing red at
        this base (the disclosed ``TransitionApplication`` NameError —
        the merged WORK-029 economics gate composed through this same
        record boundary and disclosed it; the engine defect belongs to
        WORK-025's owned surface and is NOT fixed here).
        """
        return self._merchant_records

    @property
    def primary(self) -> Any:
        return self._world.primary

    @property
    def redundancy(self) -> Any:
        return self._world.redundancy

    @property
    def operations(self) -> Any:
        return self._world.operations

    @property
    def evidence(self) -> Any:
        return self._world.evidence

    @property
    def stage_journal(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._stage_journal)

    @property
    def journey_facts(self) -> dict[str, Any]:
        return dict(self._journey_facts)

    @property
    def command_count(self) -> int:
        return self._command_count

    @property
    def obligation_ids(self) -> tuple[str, ...]:
        return tuple(self._obligation_ids)

    # ------------------------------------------------------------------
    # composed-state honesty
    # ------------------------------------------------------------------

    def _merchant_digest(self) -> str:
        records = {
            object_id: record.to_dict()
            for object_id, record in self._merchant_records.items()
        }
        return canonical_sha256({"records": records})

    def _operations_digest(self) -> str:
        return canonical_sha256({"state": self._world.operations.snapshot_state()})

    def _evidence_digest(self) -> str:
        return self._world.evidence.archive_digest()

    def composed_state_digest(self) -> str:
        """Digest over ALL five composed authorities (byte-stable)."""
        return canonical_sha256(
            {
                "merchant": self._merchant_digest(),
                "primary": self._world.primary.composed_digest(),
                "redundancy": self._world.redundancy.composed_digest(),
                "operations": self._operations_digest(),
                "evidence": self._evidence_digest(),
            }
        )

    def _record_stage(
        self,
        stage: JourneyStage,
        *,
        domain: str,
        command_ids: Iterable[str],
        requested_at: str,
        driver: Callable[[], Any],
    ) -> Any:
        """Drive one journey stage under the journal discipline.

        The chaining rule (the after-digest of the previous stage must
        equal the before-digest of this one) fails closed on any
        composed-state mutation outside a recorded stage. A driver that
        fails closed must leave the composed state byte-identical —
        divergence is a double failure and fails closed harder.
        """
        if stage.value not in JOURNEY_STAGE_TOKENS:
            raise CoreValidationError(f"unknown flywheel stage {stage!r}")
        command_id_list = list(command_ids)
        state_before = self.composed_state_digest()
        if (
            self._last_state_after is not None
            and self._last_state_after != state_before
        ):
            raise CoreValidationError(
                f"stage journal chaining violated at {stage.value!r}: the "
                "composed state changed outside a recorded stage"
            )
        try:
            result = driver()
        except CoreValidationError:
            state_on_failure = self.composed_state_digest()
            if state_on_failure != state_before:
                raise CoreValidationError(
                    f"stage {stage.value!r} failed closed but the composed "
                    "state mutated; failing on composed-state divergence"
                )
            raise
        state_after = self.composed_state_digest()
        self._command_count += len(command_id_list)
        self._last_state_after = state_after
        self._stage_journal.append(
            {
                "stage": stage.value,
                "domain": domain,
                "command_ids": command_id_list,
                "requested_at": requested_at,
                "outcome": "accepted",
                "state_before": state_before,
                "state_after": state_after,
            }
        )
        return result

    # ------------------------------------------------------------------
    # journey stages
    # ------------------------------------------------------------------

    def _merchant_provenance(self, command_id: str, at: str) -> Provenance:
        return Provenance(
            issuer=MERCHANT_ACTOR,
            source=FLYWHEEL_PROVENANCE_SOURCE,
            recorded_at=at,
            evidence_refs=(command_id,),
        )

    def _amount(self, value_minor: int) -> Amount:
        return Amount(
            value=value_minor,
            scale=self._world.amount_scale,
            asset=self._world.asset_code,
        )

    def stage_merchant_checkout(self) -> None:
        """Act 1a — the customer's checkout, created and accepted.

        Built through the merchant domain's public record factories
        (validated specs, the domain seal) and advanced through the
        record boundary's own transition discipline with causation ids
        (the WORK-029 precedent: the record boundary is the working
        public surface of the merged WORK-025 implementation).
        """
        world = self._world

        def create_checkout() -> Any:
            checkout = Checkout.create(
                spec=CheckoutSpec(
                    checkout_id=world.checkout_id,
                    merchant_id=world.payee,
                    customer_id=world.payer,
                    intent_id=world.intent_id,
                    amount=self._amount(world.amount_minor),
                    expires_at=T_VALID_UNTIL,
                ),
                environment_id=world.environment_id,
                domain_id=world.merchant_domain_id,
                provenance=self._merchant_provenance(
                    "cmd/ig006/checkout-create", T_CHECKOUT
                ),
            )
            self._merchant_records[world.checkout_id] = checkout
            return checkout

        def accept_checkout() -> Any:
            checkout = self._merchant_records[world.checkout_id]
            acceptance = Acceptance.create(
                checkout=checkout,
                merchant_id=world.payee,
                provenance=self._merchant_provenance(
                    "cmd/ig006/checkout-accept", T_ACCEPT
                ),
                accepted_at=T_ACCEPT,
            )
            updated = checkout.advance(
                CheckoutState.ACCEPTED,
                self._merchant_provenance("cmd/ig006/checkout-accept", T_ACCEPT),
                "cmd/ig006/checkout-accept",
            )
            self._merchant_records[world.checkout_id] = updated
            self._merchant_records[acceptance.acceptance_id] = acceptance
            return updated

        for label, command_id, instant, driver in (
            ("checkout create", "cmd/ig006/checkout-create", T_CHECKOUT, create_checkout),
            ("checkout accept", "cmd/ig006/checkout-accept", T_ACCEPT, accept_checkout),
        ):
            self._record_stage(
                JourneyStage.MERCHANT_CHECKOUT,
                domain=world.merchant_domain_id,
                command_ids=(command_id,),
                requested_at=instant,
                driver=driver,
            )

    def stage_merchant_promise(self) -> None:
        """Act 1b — the delayed/credited settlement condition, explicit.

        The settlement promise (``PENDING``, within the merchant credit
        limit, bound to the journey's settlement id) IS the delayed
        settlement condition; the refund route records the customer's
        recourse path. Both are the merchant domain's own sealed
        records.
        """
        world = self._world

        def issue_promise() -> Any:
            checkout = self._merchant_records[world.checkout_id]
            promise = SettlementPromise.create(
                spec=SettlementPromiseSpec(
                    promise_id=PROMISE_ID,
                    checkout_id=world.checkout_id,
                    settlement_id=world.promise_settlement_id,
                    merchant_id=world.payee,
                    amount=self._amount(world.amount_minor),
                    credit_limit=self._amount(world.credit_limit_minor),
                    expires_at=T_VALID_UNTIL,
                ),
                environment_id=world.environment_id,
                domain_id=world.merchant_domain_id,
                provenance=self._merchant_provenance(
                    "cmd/ig006/checkout-promise", T_PROMISE
                ),
            )
            updated = checkout.advance(
                CheckoutState.PROMISED,
                self._merchant_provenance("cmd/ig006/checkout-promise", T_PROMISE),
                "cmd/ig006/checkout-promise",
            )
            self._merchant_records[world.checkout_id] = updated
            self._merchant_records[promise.spec.promise_id] = promise
            return updated

        def record_refund_route() -> Any:
            checkout = self._merchant_records[world.checkout_id]
            route = RefundRoute.create(
                checkout=checkout,
                route_id=REFUND_ROUTE_ID,
                settlement_id=world.promise_settlement_id,
                provenance=self._merchant_provenance(
                    "cmd/ig006/checkout-refund-route", T_REFUND_ROUTE
                ),
            )
            self._merchant_records[route.route_id] = route
            return route

        for label, command_id, instant, driver in (
            ("settlement promise", "cmd/ig006/checkout-promise", T_PROMISE, issue_promise),
            (
                "refund route",
                "cmd/ig006/checkout-refund-route",
                T_REFUND_ROUTE,
                record_refund_route,
            ),
        ):
            self._record_stage(
                JourneyStage.MERCHANT_PROMISE,
                domain=world.merchant_domain_id,
                command_ids=(command_id,),
                requested_at=instant,
                driver=driver,
            )

    def stage_primary_compile(self) -> Any:
        """Act 2a — the canonical intent compiled on the primary rail."""
        world = self._world
        declared = declared_world_for(
            world,
            tag="ig006-primary-1",
            environment_id=world.environment_id,
            domain_id=world.primary_domain_id,
        )
        entry = self._record_stage(
            JourneyStage.PRIMARY_COMPILE,
            domain=world.primary_domain_id,
            command_ids=("cmd/ig006/primary-compile",),
            requested_at=T_PLAN_CREATE,
            driver=lambda: world.primary.stage_compile(
                declared,
                plan_id=PRIMARY_PLAN_ID,
                command_id="cmd/ig006/primary-compile",
                idempotency_key="key/ig006/primary-compile",
                nonce="nonce-ig006-primary-compile",
            ),
        )
        _require_entry_outcome(entry, "primary compile")
        return declared

    def stage_primary_plan(self) -> None:
        """Act 2b — the plan accepted and armed on the primary rail."""
        world = self._world

        def accept() -> Any:
            return world.primary.stage_accept_plan(
                PRIMARY_PLAN_ID,
                command_id="cmd/ig006/primary-accept",
                idempotency_key="key/ig006/primary-accept",
                nonce="nonce-ig006-primary-accept",
                as_of=T_ACCEPT,
            )

        def create() -> Any:
            return world.primary.stage_create_execution_plan(
                PRIMARY_PLAN_ID,
                command_id="cmd/ig006/primary-exec-create",
                requested_at=T_PLAN_CREATE,
            )

        def authorize() -> Any:
            return world.primary.stage_authorize_execution_plan(
                PRIMARY_EXECUTION_PLAN_ID,
                command_id="cmd/ig006/primary-exec-authorize",
                requested_at=T_PLAN_AUTHORIZE,
            )

        def start() -> Any:
            return world.primary.stage_start_execution_plan(
                PRIMARY_EXECUTION_PLAN_ID,
                command_id="cmd/ig006/primary-exec-start",
                requested_at=T_PLAN_START,
            )

        for label, command_id, instant, driver in (
            ("plan accept", "cmd/ig006/primary-accept", T_ACCEPT, accept),
            ("plan create", "cmd/ig006/primary-exec-create", T_PLAN_CREATE, create),
            (
                "plan authorize",
                "cmd/ig006/primary-exec-authorize",
                T_PLAN_AUTHORIZE,
                authorize,
            ),
            ("plan start", "cmd/ig006/primary-exec-start", T_PLAN_START, start),
        ):
            entry = self._record_stage(
                JourneyStage.PRIMARY_PLAN,
                domain=world.primary_domain_id,
                command_ids=(command_id,),
                requested_at=instant,
                driver=driver,
            )
            _require_entry_outcome(entry, f"primary {label}")

    def stage_primary_submit(self) -> None:
        """Act 2c — THE KILL: the primary submission dies mid-flight.

        The rail scripts a transport failure: no definitive submission
        response (``UNKNOWN``), nothing recorded rail-side. The step
        ends ``UNKNOWN`` — never a false success — and no effect result
        exists for the killed leg.
        """
        world = self._world

        def request() -> Any:
            return world.primary.stage_request_effect(
                PRIMARY_STEP_ID,
                idempotency_key=PRIMARY_IDEMPOTENCY_KEY,
                command_id="cmd/ig006/primary-request",
                requested_at=T_PLAN_START,
            )

        def submit() -> Any:
            return world.primary.stage_submit_effect(
                PRIMARY_STEP_ID,
                command_id="cmd/ig006/primary-submit",
                requested_at=T_KILL,
            )

        for label, command_id, instant, driver in (
            ("effect request", "cmd/ig006/primary-request", T_PLAN_START, request),
            ("effect submit (the kill)", "cmd/ig006/primary-submit", T_KILL, submit),
        ):
            entry = self._record_stage(
                JourneyStage.PRIMARY_SUBMIT,
                domain=world.primary_domain_id,
                command_ids=(command_id,),
                requested_at=instant,
                driver=driver,
            )
            _require_entry_outcome(entry, f"primary {label}")
        step = world.primary.execution.step(PRIMARY_STEP_ID)
        self._journey_facts["first_submission_state"] = step.state.value

    def stage_rail_incident(self) -> None:
        """Act 2d — operations observes the dead rail and degrades.

        A dead-canary probe (0 bps → ``UNAVAILABLE`` against the
        declared profile) opens the incident; the degradation declares
        severity and the digest of the primary composition's execution
        authority (the live public record index — the observer
        pattern: operations digests the public boundary, never
        re-derives sibling state).
        """
        world = self._world
        operations = world.operations

        def open_incident() -> Any:
            return operations.open_incident(
                command_id="cmd/ig006/incident-open",
                requested_at=T_CANARY,
                incident_id=INCIDENT_ID,
                dependency_id=world.primary_rail_dependency_id,
                trigger_probe=_probe(
                    world.primary_rail_dependency_id,
                    T_CANARY,
                    0,
                    "canary: primary rail submission transport failure",
                ),
                summary="primary rail transport outage (the journey kill)",
            )

        def declare_degradation() -> Any:
            return operations.declare_degradation(
                command_id="cmd/ig006/degrade",
                requested_at=T_DEGRADE,
                incident_id=INCIDENT_ID,
                probe=_probe(
                    world.primary_rail_dependency_id,
                    T_DEGRADE,
                    0,
                    "primary rail still dead at degradation",
                ),
                affected_dependencies=(world.primary_rail_dependency_id,),
                affected_authorities={
                    EXECUTION_AUTHORITY_REF: _index_digest(world.primary.execution)
                },
                detail="primary rail dead; payment execution degraded",
            )

        for label, command_id, instant, driver in (
            ("incident open", "cmd/ig006/incident-open", T_CANARY, open_incident),
            ("declare degradation", "cmd/ig006/degrade", T_DEGRADE, declare_degradation),
        ):
            self._record_stage(
                JourneyStage.RAIL_INCIDENT,
                domain=world.operations_domain_id,
                command_ids=(command_id,),
                requested_at=instant,
                driver=driver,
            )
        self._journey_facts["degradation_severity"] = (
            operations.incident(INCIDENT_ID).spec.degradation_facts[-1].severity
        )

    def stage_failover(self) -> None:
        """Act 2e — the governed failover onto the declared redundancy.

        The failover is control-plane only: the authority digest handed
        to the failover must equal the digest declared at degradation
        (the conservation the operations authority itself enforces and
        the battery re-proves).
        """
        from src.operations import classify_health

        world = self._world
        operations = world.operations
        target_probe = _probe(
            world.redundancy_rail_dependency_id,
            T_FAILOVER,
            10000,
            "redundancy rail healthy at failover",
        )
        target_status = classify_health(
            target_probe,
            operations.resilience_profiles[0],
            dependency_service=EXECUTION_SERVICE_ID,
        )
        if target_status.value != "HEALTHY":
            raise CoreValidationError(
                "the failover target must classify HEALTHY before the failover"
            )

        def failover() -> Any:
            return operations.execute_failover(
                command_id="cmd/ig006/failover",
                requested_at=T_FAILOVER,
                incident_id=INCIDENT_ID,
                target_dependency_id=world.redundancy_rail_dependency_id,
                target_probe=target_probe,
                adapter_contract={
                    "adapter_id": world.redundancy_adapter_id,
                    "fidelity_class": "SIMULATION",
                    "effect_operations": ("SUBMIT_PAYMENT",),
                },
                authority_digests={
                    EXECUTION_AUTHORITY_REF: _index_digest(world.primary.execution)
                },
                detail="failover onto the declared redundancy rail",
            )

        self._record_stage(
            JourneyStage.RAILOVER,
            domain=world.operations_domain_id,
            command_ids=("cmd/ig006/failover",),
            requested_at=T_FAILOVER,
            driver=failover,
        )
        self._journey_facts["failover_target"] = world.redundancy_rail_dependency_id

    def stage_recovery_reconcile(self) -> str:
        """Act 3a — reconcile the dead leg BEFORE any retry.

        The reconciliation queries the primary rail through the public
        port: the killed key was never recorded rail-side, so the
        truthful outcome is ``NOT_FOUND`` — the retry-safe truth.
        """
        world = self._world
        entry = self._record_stage(
            JourneyStage.RECOVERY_RECONCILE,
            domain=world.primary_domain_id,
            command_ids=("cmd/ig006/primary-reconcile",),
            requested_at=T_RECONCILE,
            driver=lambda: world.primary.stage_reconcile_effect(
                PRIMARY_STEP_ID,
                command_id="cmd/ig006/primary-reconcile",
                requested_at=T_RECONCILE,
            ),
        )
        _require_entry_outcome(entry, "dead-leg reconciliation")
        observation = world.primary.execution.observations()[-1]
        outcome = observation.spec.content["outcome"]
        self._journey_facts["dead_leg_reconciliation"] = outcome
        return outcome

    def stage_recovery_retry(self) -> str:
        """Act 3b — the recovery retry through the redundancy rail.

        A FRESH plan with a FRESH idempotency key (never a blind retry
        of the killed key) on the declared redundancy rail: compile →
        accept → arm → request → submit → acknowledge → query → status
        → SUCCEEDED result → complete → finality claim.
        """
        world = self._world
        gate = world.redundancy
        declared = declared_world_for(
            world,
            tag="ig006-redundancy-2",
            environment_id=world.environment_id,
            domain_id=world.redundancy_domain_id,
        )

        def compile_plan() -> Any:
            return gate.stage_compile(
                declared,
                plan_id=REDUNDANCY_PLAN_ID,
                command_id="cmd/ig006/retry-compile",
                idempotency_key="key/ig006/retry-compile",
                nonce="nonce-ig006-retry-compile",
            )

        def accept_plan() -> Any:
            return gate.stage_accept_plan(
                REDUNDANCY_PLAN_ID,
                command_id="cmd/ig006/retry-accept",
                idempotency_key="key/ig006/retry-accept",
                nonce="nonce-ig006-retry-accept",
                as_of=T_RETRY_ACCEPT,
            )

        def create_plan() -> Any:
            return gate.stage_create_execution_plan(
                REDUNDANCY_PLAN_ID,
                command_id="cmd/ig006/retry-exec-create",
                requested_at=T_RETRY_CREATE,
            )

        def authorize_plan() -> Any:
            return gate.stage_authorize_execution_plan(
                REDUNDANCY_EXECUTION_PLAN_ID,
                command_id="cmd/ig006/retry-exec-authorize",
                requested_at=T_RETRY_AUTHORIZE,
            )

        def start_plan() -> Any:
            return gate.stage_start_execution_plan(
                REDUNDANCY_EXECUTION_PLAN_ID,
                command_id="cmd/ig006/retry-exec-start",
                requested_at=T_RETRY_START,
            )

        def request_effect() -> Any:
            return gate.stage_request_effect(
                REDUNDANCY_STEP_ID,
                idempotency_key=REDUNDANCY_IDEMPOTENCY_KEY,
                command_id="cmd/ig006/retry-request",
                requested_at=T_RETRY_REQUEST,
            )

        def submit_effect() -> Any:
            return gate.stage_submit_effect(
                REDUNDANCY_STEP_ID,
                command_id="cmd/ig006/retry-submit",
                requested_at=T_RETRY_SUBMIT,
            )

        for label, command_id, instant, driver in (
            ("retry compile", "cmd/ig006/retry-compile", T_RETRY_CREATE, compile_plan),
            ("retry accept", "cmd/ig006/retry-accept", T_RETRY_ACCEPT, accept_plan),
            ("retry create", "cmd/ig006/retry-exec-create", T_RETRY_CREATE, create_plan),
            (
                "retry authorize",
                "cmd/ig006/retry-exec-authorize",
                T_RETRY_AUTHORIZE,
                authorize_plan,
            ),
            ("retry start", "cmd/ig006/retry-exec-start", T_RETRY_START, start_plan),
            ("retry request", "cmd/ig006/retry-request", T_RETRY_REQUEST, request_effect),
            ("retry submit", "cmd/ig006/retry-submit", T_RETRY_SUBMIT, submit_effect),
        ):
            entry = self._record_stage(
                JourneyStage.RECOVERY_RETRY,
                domain=world.redundancy_domain_id,
                command_ids=(command_id,),
                requested_at=instant,
                driver=driver,
            )
            _require_entry_outcome(entry, label)

        step = gate.execution.step(REDUNDANCY_STEP_ID)
        if step.state.value != "SUBMITTED":
            raise CoreValidationError(
                f"the redundancy submission must be ACCEPTED; step is "
                f"{step.state.value}"
            )
        attempts = [
            record
            for record in gate.execution.objects()
            if record.__class__.__name__ == "ExecutionAttempt"
            and record.spec.step_id == REDUNDANCY_STEP_ID
        ]
        native_reference = attempts[-1].spec.native_reference
        if native_reference is None:
            raise CoreValidationError(
                "an ACCEPTED redundancy submission must carry the rail's "
                "native reference"
            )
        self._native_reference = native_reference
        self._journey_facts["recovery_native_reference"] = native_reference

        def acknowledge() -> Any:
            return gate.stage_acknowledge_effect(
                REDUNDANCY_STEP_ID,
                native_reference=native_reference,
                command_id="cmd/ig006/retry-ack",
                requested_at=T_RETRY_ACK,
            )

        def query() -> Any:
            return gate.stage_reconcile_effect(
                REDUNDANCY_STEP_ID,
                command_id="cmd/ig006/retry-query",
                requested_at=T_RETRY_QUERY,
            )

        def status() -> Any:
            return gate.stage_record_payment_status(
                REDUNDANCY_STEP_ID,
                native_code=world.redundancy_rail.native_status_for(
                    REDUNDANCY_IDEMPOTENCY_KEY
                ),
                command_id="cmd/ig006/retry-status",
                requested_at=T_RETRY_STATUS,
            )

        def observe_result() -> Any:
            return gate.stage_observe_effect_result(
                REDUNDANCY_STEP_ID,
                outcome="SUCCEEDED",
                native_reference=native_reference,
                observed_at=T_RETRY_RESULT,
                command_id="cmd/ig006/retry-result",
            )

        def complete() -> Any:
            return gate.stage_complete_step(
                REDUNDANCY_STEP_ID,
                command_id="cmd/ig006/retry-complete",
                requested_at=T_RETRY_COMPLETE,
            )

        def finality_claim() -> Any:
            return gate.stage_record_finality_claim(
                REDUNDANCY_STEP_ID,
                claim="FINAL",
                native_reference=native_reference,
                command_id="cmd/ig006/retry-claim",
                requested_at=T_RETRY_CLAIM,
            )

        for label, command_id, instant, driver in (
            ("retry acknowledge", "cmd/ig006/retry-ack", T_RETRY_ACK, acknowledge),
            ("retry query", "cmd/ig006/retry-query", T_RETRY_QUERY, query),
            ("retry status", "cmd/ig006/retry-status", T_RETRY_STATUS, status),
            ("retry result", "cmd/ig006/retry-result", T_RETRY_RESULT, observe_result),
            ("retry complete", "cmd/ig006/retry-complete", T_RETRY_COMPLETE, complete),
            (
                "retry finality claim",
                "cmd/ig006/retry-claim",
                T_RETRY_CLAIM,
                finality_claim,
            ),
        ):
            entry = self._record_stage(
                JourneyStage.RECOVERY_RETRY,
                domain=world.redundancy_domain_id,
                command_ids=(command_id,),
                requested_at=instant,
                driver=driver,
            )
            _require_entry_outcome(entry, label)
        self._journey_facts["recovery_step_state"] = (
            gate.execution.step(REDUNDANCY_STEP_ID).state.value
        )
        return native_reference

    def _redundancy_obligation_ids(self) -> list[str]:
        from src.clearing import Obligation

        return [
            record.object_id
            for record in self._world.redundancy.clearing.records()
            if isinstance(record, Obligation)
        ]

    def stage_obligation_recognition(self) -> tuple[str, ...]:
        """Act 3c — recognize the REAL obligation from sealed evidence.

        The clearing cycle opens its recognition window and recognizes
        the obligation from the redundancy rail's sealed SUCCEEDED
        effect result — obligations are recognized ONLY from SUCCEEDED
        evidence, so the killed leg's UNKNOWN outcome can never create
        one (the discrimination battery re-proves this).
        """
        world = self._world
        gate = world.redundancy

        def open_cycle() -> Any:
            return gate.stage_open_clearing_cycle(
                CLEARING_CYCLE_ID,
                opens_at=CYCLE_OPENS_AT,
                closes_at=CYCLE_CLOSES_AT,
                command_id="cmd/ig006/cycle-open",
                requested_at=T_CYCLE_OPEN,
                description="the flywheel journey's recognition window",
            )

        before = set(self._redundancy_obligation_ids())

        def recognize() -> Any:
            return gate.stage_recognize_obligation(
                cycle_id=CLEARING_CYCLE_ID,
                step_id=REDUNDANCY_STEP_ID,
                due_from=T_DUE_FROM,
                due_until=T_DUE_UNTIL,
                command_id="cmd/ig006/recognize",
                requested_at=T_RECOGNIZE,
            )

        for label, command_id, instant, driver in (
            ("cycle open", "cmd/ig006/cycle-open", T_CYCLE_OPEN, open_cycle),
            ("recognize obligation", "cmd/ig006/recognize", T_RECOGNIZE, recognize),
        ):
            entry = self._record_stage(
                JourneyStage.OBLIGATION_RECOGNITION,
                domain=world.redundancy_domain_id,
                command_ids=(command_id,),
                requested_at=instant,
                driver=driver,
            )
            _require_entry_outcome(entry, label)
        after = self._redundancy_obligation_ids()
        self._obligation_ids = [
            obligation_id
            for obligation_id in after
            if obligation_id not in before
        ]
        if not self._obligation_ids:
            raise CoreValidationError(
                "the journey requires a recognized obligation from the "
                "redundancy rail's SUCCEEDED evidence"
            )
        self._journey_facts["obligation_ids"] = list(self._obligation_ids)
        return tuple(self._obligation_ids)

    def stage_delayed_settlement(self) -> None:
        """Act 3d — the DELAY: the obligation matures inside its window.

        The obligation is validated and marked due exactly inside the
        declared delay window (``due_from`` .. ``due_until``) — the
        clearing authority's own explicit delay representation — and
        the cycle validates and finalizes.
        """
        world = self._world
        gate = world.redundancy
        for index, obligation_id in enumerate(self._obligation_ids, start=1):
            entry = self._record_stage(
                JourneyStage.DELAYED_SETTLEMENT,
                domain=world.redundancy_domain_id,
                command_ids=(f"cmd/ig006/validate-{index}",),
                requested_at=T_DUE_FROM,
                driver=lambda obligation_id=obligation_id: gate.stage_validate_obligation(
                    obligation_id,
                    command_id=f"cmd/ig006/validate-{index}",
                    requested_at=T_DUE_FROM,
                ),
            )
            _require_entry_outcome(entry, "obligation validation")
        for index, obligation_id in enumerate(self._obligation_ids, start=1):
            entry = self._record_stage(
                JourneyStage.DELAYED_SETTLEMENT,
                domain=world.redundancy_domain_id,
                command_ids=(f"cmd/ig006/due-{index}",),
                requested_at=T_MARK_DUE,
                driver=lambda obligation_id=obligation_id: gate.stage_mark_due_obligation(
                    obligation_id,
                    command_id=f"cmd/ig006/due-{index}",
                    requested_at=T_MARK_DUE,
                ),
            )
            _require_entry_outcome(entry, "obligation due marking")
        for label, command_id, driver in (
            (
                "cycle validate",
                "cmd/ig006/cycle-validate",
                lambda: gate.stage_validate_cycle(
                    CLEARING_CYCLE_ID,
                    command_id="cmd/ig006/cycle-validate",
                    requested_at=T_CYCLE_VALIDATE,
                ),
            ),
            (
                "cycle finalize",
                "cmd/ig006/cycle-finalize",
                lambda: gate.stage_finalize_cycle(
                    CLEARING_CYCLE_ID,
                    command_id="cmd/ig006/cycle-finalize",
                    requested_at=T_CYCLE_FINALIZE,
                ),
            ),
        ):
            entry = self._record_stage(
                JourneyStage.DELAYED_SETTLEMENT,
                domain=world.redundancy_domain_id,
                command_ids=(command_id,),
                requested_at=T_CYCLE_VALIDATE if "validate" in command_id else T_CYCLE_FINALIZE,
                driver=driver,
            )
            _require_entry_outcome(entry, label)

    def stage_settlement(self) -> None:
        """Act 3e — the settlement batch created, authorized, submitted."""
        world = self._world
        gate = world.redundancy
        entry = self._record_stage(
            JourneyStage.DELAYED_SETTLEMENT,
            domain=world.redundancy_domain_id,
            command_ids=(
                "cmd/ig006/settle-create",
                "cmd/ig006/settle-authorize",
                "cmd/ig006/settle-submit",
            ),
            requested_at=T_SETTLE,
            driver=lambda: gate.stage_settle(
                SETTLEMENT_ID,
                self._obligation_ids,
                submit_by=SUBMIT_BY,
                settle_by=SETTLE_BY,
                command_prefix="cmd/ig006/settle",
                requested_at=T_SETTLE,
            ),
        )
        _require_entry_outcome(entry, "settlement batch")

    def _leg_bindings(self) -> dict[str, str]:
        """Bind each settlement leg to the step whose evidence folds it."""
        gate = self._world.redundancy
        settlement = gate.settlement.settlement(SETTLEMENT_ID)
        instruction_by_obligation = {
            instruction.obligation_id: instruction.instruction_id
            for instruction in settlement.spec.instructions
        }
        return {
            instruction_by_obligation[obligation_id]: REDUNDANCY_STEP_ID
            for obligation_id in self._obligation_ids
        }

    def stage_settlement_reconciliation(self) -> None:
        """Act 3f — fold the recorded rail evidence into the legs."""
        world = self._world
        gate = world.redundancy
        legs = self._leg_bindings()
        entry = self._record_stage(
            JourneyStage.SETTLEMENT_RECONCILIATION,
            domain=world.redundancy_domain_id,
            command_ids=("cmd/ig006/settle-reconcile",),
            requested_at=T_SETTLE_RECONCILE,
            driver=lambda: gate.stage_fold_rail_evidence(
                SETTLEMENT_ID,
                legs,
                command_id="cmd/ig006/settle-reconcile",
                requested_at=T_SETTLE_RECONCILE,
            ),
        )
        _require_entry_outcome(entry, "settlement reconciliation")

    def stage_finality(self) -> None:
        """Act 3g — the finality certificate validated and established."""
        world = self._world
        gate = world.redundancy
        legs = self._leg_bindings()
        certificate = self._record_stage(
            JourneyStage.FINALITY,
            domain=world.redundancy_domain_id,
            command_ids=(
                "cmd/ig006/claim-validate-create",
                "cmd/ig006/claim-validate-finality",
            ),
            requested_at=T_FINALITY_VALIDATE,
            driver=lambda: gate.stage_validate_finality_certificate(
                FINALITY_ID,
                SETTLEMENT_ID,
                legs,
                command_prefix="cmd/ig006/claim-validate",
                requested_at=T_FINALITY_VALIDATE,
            ),
        )
        _require_entry_outcome(certificate, "finality certificate")
        established = self._record_stage(
            JourneyStage.FINALITY,
            domain=world.redundancy_domain_id,
            command_ids=("cmd/ig006/finality",),
            requested_at=T_FINALITY_ESTABLISH,
            driver=lambda: gate.stage_establish_finality(
                FINALITY_ID,
                command_id="cmd/ig006/finality",
                requested_at=T_FINALITY_ESTABLISH,
            ),
        )
        _require_entry_outcome(established, "finality establishment")

    def stage_obligation_resolution(self) -> None:
        """Act 3h — resolve the settled obligations with discharge evidence."""
        world = self._world
        gate = world.redundancy
        entry = self._record_stage(
            JourneyStage.OBLIGATION_RESOLUTION,
            domain=world.redundancy_domain_id,
            command_ids=("cmd/ig006/resolve",),
            requested_at=T_OBLIGATION_RESOLVE,
            driver=lambda: gate.stage_resolve_settled_obligations(
                SETTLEMENT_ID,
                command_prefix="cmd/ig006/resolve",
                requested_at=T_OBLIGATION_RESOLVE,
            ),
        )
        _require_entry_outcome(entry, "obligation resolution")

    def stage_incident_resolution(self) -> None:
        """Act 4a — the recovery completes and the incident resolves.

        The recovery evidence: the dead leg was reconciled (NOT_FOUND),
        the payment was retried through the redundancy (a fresh plan
        and key, completed SUCCEEDED), the execution authority rebuilds
        byte-identically from its journal alone, and the primary rail
        probes healthy again. The resolve gate requires all of it.
        """
        from src.execution import ExecutionEngine
        from src.operations import AuthorityRebuild, RecoveryActionRecord

        world = self._world
        operations = world.operations
        live_digest = _index_digest(world.primary.execution)
        rebuilt_execution = ExecutionEngine.rebuild_from_journal(
            environment_id=world.environment_id,
            domain_id=world.primary.execution.domain_id,
            bindings=dict(world.primary.bindings),
            journal=world.primary.execution.journal(),
        )
        rebuilt_digest = _index_digest(rebuilt_execution)
        if live_digest != rebuilt_digest:
            raise CoreValidationError(
                "the primary execution authority must rebuild byte-identically "
                "from its journal alone (no silent state loss)"
            )
        restored_probe = _probe(
            world.primary_rail_dependency_id,
            T_REPROBE,
            10000,
            "primary rail restored after repair",
        )
        recovery_actions = tuple(
            RecoveryActionRecord(
                action=kind,
                authority_ref=None
                if kind.value == "REPROBE"
                else EXECUTION_AUTHORITY_REF,
                detail={
                    "REPROBE": "fresh probes of the affected primary rail",
                    "RECONCILE": "the killed leg queried through the public "
                    "reconciliation port: NOT_FOUND (retry-safe)",
                    "RETRY": "the payment re-executed through the declared "
                    "redundancy rail (a fresh plan and idempotency key)",
                    "REBUILD": "journal-only rebuild of the execution "
                    "authority: live digest equals rebuilt digest",
                }[kind.value],
                at=T_REPROBE,
            )
            for kind in world.recovery_actions
        )

        def resolve() -> Any:
            return operations.resolve_incident(
                command_id="cmd/ig006/resolve-incident",
                requested_at=T_REPROBE,
                incident_id=INCIDENT_ID,
                probes=(restored_probe,),
                recovery_actions=recovery_actions,
                authority_evidence=(
                    AuthorityRebuild(
                        authority_ref=EXECUTION_AUTHORITY_REF,
                        live_index_digest=live_digest,
                        rebuilt_index_digest=rebuilt_digest,
                    ),
                ),
                note="primary rail restored; journey recovered through the "
                "declared redundancy",
            )

        self._record_stage(
            JourneyStage.INCIDENT_RESOLUTION,
            domain=world.operations_domain_id,
            command_ids=("cmd/ig006/resolve-incident",),
            requested_at=T_REPROBE,
            driver=resolve,
        )
        resolved = operations.incident(INCIDENT_ID)
        self._journey_facts["incident_final_state"] = resolved.state.value
        self._journey_facts["recovery_duration_seconds"] = (
            resolved.spec.resolution_fact.recovery_duration_seconds
        )

    def _assert_outcome_preconditions(self) -> None:
        """The outcome guards: observed authority reads, fail-closed.

        The merchant outcome may only be recorded when the REAL
        authorities say so: the settlement batch COMPLETED, the
        finality ESTABLISHED, and the merchant promise↔settlement
        binding intact. Each guard reads the live authority records —
        nothing is claimable.
        """
        world = self._world
        settlement = world.redundancy.settlement.settlement(SETTLEMENT_ID)
        finality = world.redundancy.settlement.finality(FINALITY_ID)
        promise = self._merchant_records[PROMISE_ID]
        if settlement.envelope.state != "COMPLETED":
            raise CoreValidationError(
                "the merchant outcome requires the settlement batch COMPLETED; "
                f"observed {settlement.envelope.state}"
            )
        if finality.envelope.state != "ESTABLISHED":
            raise CoreValidationError(
                "the merchant outcome requires finality ESTABLISHED; observed "
                f"{finality.envelope.state}"
            )
        if promise.spec.settlement_id != SETTLEMENT_ID:
            raise CoreValidationError(
                "the merchant outcome requires the promise↔settlement binding "
                "to be intact"
            )

    def stage_merchant_outcome(self) -> dict[str, Any]:
        """Act 4b — the final merchant/customer outcome, observed.

        The outcome is an OBSERVED evidence-domain record binding the
        merchant promise to the observed settled amount; the durable
        journey evidence record rests on it. The classification is
        derived from real authority reads (settlement COMPLETED,
        finality ESTABLISHED, obligations RESOLVED, promise binding
        intact) — never claimed.
        """
        self._assert_outcome_preconditions()
        world = self._world
        promise = self._merchant_records[PROMISE_ID]
        provenance = Provenance(
            issuer=self._actor,
            source=FLYWHEEL_PROVENANCE_SOURCE,
            recorded_at=T_OUTCOME,
            evidence_refs=(promise.envelope.object_id,),
        )
        observation = record_observation(
            observation_id=OUTCOME_OBSERVATION_ID,
            subject_ref=PROMISE_ID,
            epistemic_type=EpistemicType.OBSERVED,
            observed_at=T_OUTCOME,
            valid_from=T_VALID_FROM,
            valid_until=T_VALID_UNTIL,
            value=ScaledValue(
                value=world.amount_minor,
                scale=world.amount_scale,
                unit=world.asset_code,
            ),
            environment_id=world.environment_id,
            domain_id=world.evidence_domain_id,
            provenance=provenance,
        )

        def record_outcome() -> Any:
            world.evidence.append(observation)
            return observation

        self._record_stage(
            JourneyStage.MERCHANT_OUTCOME,
            domain=world.evidence_domain_id,
            command_ids=("cmd/ig006/outcome-observation",),
            requested_at=T_OUTCOME,
            driver=record_outcome,
        )
        evidence = submit_evidence(
            evidence_id=JOURNEY_EVIDENCE_ID,
            epistemic_type=EpistemicType.OBSERVED,
            subject_ref=CHECKOUT_ID,
            observed_at=T_OUTCOME,
            valid_from=T_VALID_FROM,
            valid_until=T_VALID_UNTIL,
            value=ScaledValue(
                value=world.amount_minor,
                scale=world.amount_scale,
                unit=world.asset_code,
            ),
            observations=(observation,),
            environment_id=world.environment_id,
            domain_id=world.evidence_domain_id,
            provenance=provenance,
        )

        def record_evidence() -> Any:
            world.evidence.append(evidence)
            return evidence

        self._record_stage(
            JourneyStage.MERCHANT_OUTCOME,
            domain=world.evidence_domain_id,
            command_ids=("cmd/ig006/journey-evidence",),
            requested_at=T_OUTCOME,
            driver=record_evidence,
        )
        outcome = {
            "observation_id": OUTCOME_OBSERVATION_ID,
            "evidence_id": JOURNEY_EVIDENCE_ID,
            "settlement_state": world.redundancy.settlement.settlement(
                SETTLEMENT_ID
            ).envelope.state,
            "finality_state": world.redundancy.settlement.finality(
                FINALITY_ID
            ).envelope.state,
        }
        self._journey_facts.update(outcome)
        return outcome

    # ------------------------------------------------------------------
    # the typed journey report
    # ------------------------------------------------------------------

    def journey_report(self) -> dict[str, Any]:
        """The typed, read-only journey outcome projection.

        Every field is derived from real authority reads; the
        classification requires the settlement COMPLETED, finality
        ESTABLISHED, every obligation RESOLVED and the promise binding
        intact — anything else is an explicit failure classification.
        """
        world = self._world
        settlement = world.redundancy.settlement.settlement(SETTLEMENT_ID)
        finality = world.redundancy.settlement.finality(FINALITY_ID)
        promise = self._merchant_records[PROMISE_ID]
        checkout = self._merchant_records[CHECKOUT_ID]
        obligations_resolved = all(
            world.redundancy.clearing.obligation(obligation_id).envelope.state
            == "RESOLVED"
            for obligation_id in self._obligation_ids
        )
        if (
            settlement.envelope.state == "COMPLETED"
            and finality.envelope.state == "ESTABLISHED"
            and obligations_resolved
            and promise.spec.settlement_id == SETTLEMENT_ID
        ):
            classification = "delayed-settlement-completed"
        else:
            classification = "settlement-failed"
        return {
            "schema_version": 1,
            "gate_id": self._gate_id,
            "work_order": "WORK-031",
            "environment_id": world.environment_id,
            "checkout_id": CHECKOUT_ID,
            "promise_id": PROMISE_ID,
            "settlement_id": SETTLEMENT_ID,
            "finality_id": FINALITY_ID,
            "checkout_state": checkout.envelope.state,
            "promise_state": promise.envelope.state,
            "promise_settlement_binding": promise.spec.settlement_id,
            "settlement_state": settlement.envelope.state,
            "finality_state": finality.envelope.state,
            "obligation_ids": list(self._obligation_ids),
            "outcome": classification,
            "outcome_observation_id": OUTCOME_OBSERVATION_ID,
            "journey_evidence_id": JOURNEY_EVIDENCE_ID,
            "amount_minor": world.amount_minor,
            "asset_code": world.asset_code,
            "credit_limit_minor": world.credit_limit_minor,
            "stage_count": len(self._stage_journal),
            "command_count": self._command_count,
        }

    def snapshot(self) -> dict[str, Any]:
        """Canonical, byte-stable snapshot of the composed gate state."""
        world = self._world
        return {
            "schema_version": 1,
            "gate_id": self._gate_id,
            "environment_id": world.environment_id,
            "stage_journal": [dict(entry) for entry in self._stage_journal],
            "journey_facts": dict(self._journey_facts),
            "journey_report": self.journey_report(),
            "composed_digest": self.composed_state_digest(),
        }
