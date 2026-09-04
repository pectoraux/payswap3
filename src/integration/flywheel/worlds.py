"""The composed merchant-journey world of the IG-006 flywheel gate.

One world is ONE environment of the SAME composed protocol machine
(``env/sandbox-ig006-flywheel``, sandbox class — the merged IG-003
parity vocabulary's simulation role; the production protocol path
running where no production financial state is reachable):

* the REAL merchant record boundary (WORK-025): the public record
  factories (``Checkout``/``Acceptance``/``SettlementPromise``/
  ``RefundRoute`` over validated specs with the domain seal) own the
  checkout, the acceptance, the settlement promise (the
  delayed/credited condition) and the refund route. The module's
  kernel-binding engine path is pre-existing red at this base (the
  disclosed WORK-025 ``TransitionApplication`` NameError in
  ``src/merchant/engine.py`` — the same disclosed defect the merged
  WORK-029 economics gate worked around through this exact record
  boundary; it is NOT fixed here: it is WORK-025's owned surface);
* TWO REAL fulfillment lifecycle compositions (the merged WORK-027
  IG-002 harness): the primary-rail composition and the
  declared-redundancy-rail composition — each a full
  compiler/execution/clearing/settlement engine tree behind exactly
  ONE typed adapter binding (the lifecycle harness's frozen
  single-binding rule), bound to a
  :class:`~src.integration.rails.LocalDeterministicRail` imported
  from the merged WORK-030 IG-005 public boundary (the sandbox-rail
  discipline: scripted submissions, rail-side idempotency,
  truth-telling reconciliation);
* the REAL operations authority (WORK-024): the dependency graph over
  the two rails as provider adapters of the payment-execution service
  and the declared resilience profile whose redundancy target IS the
  redundancy rail — the incident/degradation/failover/recovery
  orchestration of the journey's rail kill;
* the REAL evidence domain (WORK-018): the ``EvidenceArchive`` that
  persists the durable merchant-outcome observation and journey
  evidence records.

Determinism discipline: every instant is declared ``as_of`` data; the
rails resolve declared scripts only; two constructions from the same
declared inputs build byte-identical worlds. No wall-clock reads and
no entropy anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.evidence import EvidenceArchive
from src.execution.adapters import AdapterBinding
from src.integration.lifecycle import (
    FulfillmentLifecycleGate,
    build_declared_world,
)
from src.integration.parity import WorldRole
from src.integration.rails import LocalDeterministicRail
from src.interoperability import (
    AdapterStatusMap,
    CanonicalPaymentStatus,
    EFFECT_CAPABLE_FIDELITY_CLASSES,
    EffectInterface,
    IdentifierScheme,
    ObservationInterface,
    StatusMapEntry,
    WorldAdapter,
)
from src.merchant import (
    Acceptance,
    Checkout,
    CheckoutSpec,
    RefundRoute,
    SettlementPromise,
    SettlementPromiseSpec,
)
from src.operations import (
    DependencyGraph,
    OperationsEngine,
    RecoveryActionKind,
    make_dependency_record,
    make_profile_record,
)
from src.simulation.contracts import EnvironmentMode, mode_epistemic_type

from .contracts import (
    AVAILABILITY_TARGET_BPS,
    CHECKOUT_ID,
    CREDIT_LIMIT_MINOR,
    CUSTOMER_ACTOR,
    DEGRADED_BELOW_BPS,
    DEFAULT_FLYWHEEL_ACTOR,
    EVIDENCE_DOMAIN_ID,
    EXECUTION_SERVICE_ID,
    FLYWHEEL_ENVIRONMENT_ID,
    FLYWHEEL_ENVIRONMENT_ROLE,
    INTENT_ID,
    JOURNEY_AMOUNT_MINOR,
    JOURNEY_ASSET_CODE,
    JOURNEY_SCALE,
    MERCHANT_ACTOR,
    MERCHANT_DOMAIN_ID,
    OPERATIONS_DOMAIN_ID,
    PRIMARY_ADAPTER_ID,
    PRIMARY_DOMAIN_ID,
    PRIMARY_IDEMPOTENCY_KEY,
    PRIMARY_RAIL_DEPENDENCY_ID,
    RECOVERY_POINT_OBJECTIVE_SECONDS,
    RECOVERY_TIME_OBJECTIVE_SECONDS,
    REDUNDANCY_ADAPTER_ID,
    REDUNDANCY_DOMAIN_ID,
    REDUNDANCY_IDEMPOTENCY_KEY,
    REDUNDANCY_RAIL_DEPENDENCY_ID,
    SETTLEMENT_ID,
    UNAVAILABLE_BELOW_BPS,
    validate_flywheel_gate_id,
)

#: The journey's recovery-action plan (the declared profile actions).
RECOVERY_ACTIONS = (
    RecoveryActionKind.REPROBE,
    RecoveryActionKind.RECONCILE,
    RecoveryActionKind.RETRY,
    RecoveryActionKind.REBUILD,
)

#: The declared adapter contract of the redundancy rail (the public
#: world-adapter contract consumed exactly as declared; the failover
#: evidence re-declares it).
REDUNDANCY_ADAPTER_CONTRACT = {
    "adapter_id": REDUNDANCY_ADAPTER_ID,
    "fidelity_class": "SIMULATION",
    "effect_operations": ("SUBMIT_PAYMENT",),
}


#: The local deterministic rail's declared native status vocabulary
#: (the rail's own words, mapped into the canonical payment lifecycle
#: exactly as the merged IG-002/IG-005 bindings declare it).
SANDBOX_STATUS_MAP = (
    StatusMapEntry("ACSD", CanonicalPaymentStatus.ACKNOWLEDGED),
    StatusMapEntry("PDNG", CanonicalPaymentStatus.PROCESSING),
    StatusMapEntry("UKWN", CanonicalPaymentStatus.UNKNOWN),
    StatusMapEntry("RJCT", CanonicalPaymentStatus.FAILED),
    StatusMapEntry("STLD", CanonicalPaymentStatus.SETTLED),
    StatusMapEntry("FINL", CanonicalPaymentStatus.FINAL),
)


def _binding(adapter_id: str, rail: LocalDeterministicRail) -> AdapterBinding:
    """Bind one sandbox rail through the PUBLIC typed adapter path."""
    world_adapter = WorldAdapter(
        adapter_id=adapter_id,
        capability_id=f"capability/{adapter_id.rsplit('/', 1)[-1]}",
        observation_interface=ObservationInterface(
            operations=("RESOLVE_ENDPOINT", "PAYMENT_STATUS", "FINALITY")
        ),
        effect_interface=EffectInterface(
            operations=("SUBMIT_PAYMENT",),
            destination_schemes=(IdentifierScheme.ALIAS,),
        ),
        fidelity_class="SIMULATION",
    )
    if world_adapter.fidelity_class not in EFFECT_CAPABLE_FIDELITY_CLASSES:
        raise CoreValidationError(
            "the flywheel rails must declare effect-capable fidelity"
        )
    return AdapterBinding(
        adapter_id=adapter_id,
        submission_port=rail,
        reconciliation_port=rail,
        world_adapter=world_adapter,
        status_map=AdapterStatusMap(
            adapter_id=adapter_id, entries=SANDBOX_STATUS_MAP
        ),
    )


def _operations_engine() -> OperationsEngine:
    """The journey's declared dependency graph and resilience profile."""
    graph = DependencyGraph.build(
        (
            make_dependency_record(
                dependency_id=PRIMARY_RAIL_DEPENDENCY_ID,
                kind="PROVIDER_ADAPTER",
                service_id=EXECUTION_SERVICE_ID,
                depends_on=(),
                critical=True,
                note="the journey's primary payment rail",
                environment_id=FLYWHEEL_ENVIRONMENT_ID,
                domain_id=OPERATIONS_DOMAIN_ID,
            ),
            make_dependency_record(
                dependency_id=REDUNDANCY_RAIL_DEPENDENCY_ID,
                kind="PROVIDER_ADAPTER",
                service_id=EXECUTION_SERVICE_ID,
                depends_on=(),
                critical=True,
                note="the declared redundancy rail (the failover target)",
                environment_id=FLYWHEEL_ENVIRONMENT_ID,
                domain_id=OPERATIONS_DOMAIN_ID,
            ),
        )
    )
    profile = make_profile_record(
        service_id=EXECUTION_SERVICE_ID,
        availability_target_bps=AVAILABILITY_TARGET_BPS,
        degraded_below_bps=DEGRADED_BELOW_BPS,
        unavailable_below_bps=UNAVAILABLE_BELOW_BPS,
        redundancy=(REDUNDANCY_RAIL_DEPENDENCY_ID,),
        recovery_actions=RECOVERY_ACTIONS,
        recovery_time_objective_seconds=RECOVERY_TIME_OBJECTIVE_SECONDS,
        recovery_point_objective_seconds=RECOVERY_POINT_OBJECTIVE_SECONDS,
        note="the flywheel journey's payment-execution resilience profile",
        environment_id=FLYWHEEL_ENVIRONMENT_ID,
        domain_id=OPERATIONS_DOMAIN_ID,
    )
    return OperationsEngine(
        environment_id=FLYWHEEL_ENVIRONMENT_ID,
        domain_id=OPERATIONS_DOMAIN_ID,
        dependency_graph=graph,
        resilience_profiles={EXECUTION_SERVICE_ID: profile},
        actor=DEFAULT_FLYWHEEL_ACTOR,
        authorized_actors=(MERCHANT_ACTOR,),
    )


@dataclass(frozen=True, slots=True)
class FlywheelWorld:
    """One fully-wired merchant-journey world (deterministic).

    All engines are the REAL merged implementations, wired through
    their public boundaries only. The two sandbox rails are scripted
    at construction: the primary rail kills the journey's first
    submission (a transport failure with no definitive response —
    nothing recorded rail-side, so reconciliation truthfully reports
    NOT_FOUND), and the redundancy rail accepts the recovery retry.
    """

    gate_id: str
    environment_id: str
    environment_role: WorldRole
    environment_mode: EnvironmentMode
    merchant_domain_id: str
    primary: FulfillmentLifecycleGate
    primary_rail: LocalDeterministicRail
    primary_domain_id: str
    redundancy: FulfillmentLifecycleGate
    redundancy_rail: LocalDeterministicRail
    redundancy_domain_id: str
    operations: OperationsEngine
    operations_domain_id: str
    evidence: EvidenceArchive
    evidence_domain_id: str
    checkout_id: str
    intent_id: str
    promise_settlement_id: str
    amount_minor: int
    asset_code: str
    amount_scale: int
    credit_limit_minor: int
    payer: str
    payee: str
    primary_key: str
    redundancy_key: str

    def __post_init__(self) -> None:
        validate_flywheel_gate_id(self.gate_id)
        # The environment binding follows the merged IG-003 parity
        # discipline: the declared role drives the environment mode,
        # and the mode's frozen epistemic binding is load-bearing.
        if self.environment_mode is EnvironmentMode.SIMULATION:
            if self.environment_role is not WorldRole.SIMULATION:
                raise CoreValidationError(
                    "the sandbox flywheel environment must bind the parity "
                    "vocabulary's simulation role"
                )
            if mode_epistemic_type(self.environment_mode).value != "SIMULATED":
                raise CoreValidationError("mode/epistemic binding drift")

    @property
    def actor(self) -> str:
        return DEFAULT_FLYWHEEL_ACTOR

    @property
    def primary_rail_dependency_id(self) -> str:
        return PRIMARY_RAIL_DEPENDENCY_ID

    @property
    def redundancy_rail_dependency_id(self) -> str:
        return REDUNDANCY_RAIL_DEPENDENCY_ID

    @property
    def redundancy_adapter_id(self) -> str:
        return REDUNDANCY_ADAPTER_ID

    @property
    def recovery_actions(self) -> tuple:
        return RECOVERY_ACTIONS

    def world_digest(self) -> str:
        """Canonical digest of the declared (pre-execution) world data."""
        return canonical_sha256(
            {
                "environment_id": self.environment_id,
                "environment_role": self.environment_role.value,
                "merchant_domain": self.merchant_domain_id,
                "primary_domain": self.primary_domain_id,
                "redundancy_domain": self.redundancy_domain_id,
                "operations_domain": self.operations_domain_id,
                "evidence_domain": self.evidence_domain_id,
                "checkout_id": self.checkout_id,
                "intent_id": self.intent_id,
                "promise_settlement_id": self.promise_settlement_id,
                "amount_minor": self.amount_minor,
                "asset_code": self.asset_code,
                "amount_scale": self.amount_scale,
                "credit_limit_minor": self.credit_limit_minor,
                "payer": self.payer,
                "payee": self.payee,
            }
        )


def build_flywheel_world(
    *, gate_id: str = "IG-006"
) -> FlywheelWorld:
    """Build one deterministic composed merchant-journey world.

    Two constructions from the same declared inputs are byte-identical
    (same identifiers, same scripted rails, same sealed dependency and
    profile records).
    """
    validate_flywheel_gate_id(gate_id)

    # The two sandbox rails, imported from the merged WORK-030 public
    # boundary. The primary rail scripts THE KILL: the journey's first
    # submission is a transport failure (never a false success), and
    # reconciliation of that key truthfully reports NOT_FOUND.
    primary_rail = LocalDeterministicRail(
        submissions={PRIMARY_IDEMPOTENCY_KEY: ("unknown",)},
        queries={PRIMARY_IDEMPOTENCY_KEY: ("not-found",)},
    )
    redundancy_rail = LocalDeterministicRail()

    primary_gate = FulfillmentLifecycleGate(
        environment_id=FLYWHEEL_ENVIRONMENT_ID,
        domain_id=PRIMARY_DOMAIN_ID,
        bindings={PRIMARY_ADAPTER_ID: _binding(PRIMARY_ADAPTER_ID, primary_rail)},
        gate_id="IG-002",
        actor=DEFAULT_FLYWHEEL_ACTOR,
        authorized_actors=(MERCHANT_ACTOR, CUSTOMER_ACTOR),
    )
    redundancy_gate = FulfillmentLifecycleGate(
        environment_id=FLYWHEEL_ENVIRONMENT_ID,
        domain_id=REDUNDANCY_DOMAIN_ID,
        bindings={
            REDUNDANCY_ADAPTER_ID: _binding(REDUNDANCY_ADAPTER_ID, redundancy_rail)
        },
        gate_id="IG-002",
        actor=DEFAULT_FLYWHEEL_ACTOR,
        authorized_actors=(MERCHANT_ACTOR, CUSTOMER_ACTOR),
    )

    return FlywheelWorld(
        gate_id=gate_id,
        environment_id=FLYWHEEL_ENVIRONMENT_ID,
        environment_role=WorldRole.SIMULATION,
        environment_mode=EnvironmentMode.SIMULATION,
        merchant_domain_id=MERCHANT_DOMAIN_ID,
        primary=primary_gate,
        primary_rail=primary_rail,
        primary_domain_id=PRIMARY_DOMAIN_ID,
        redundancy=redundancy_gate,
        redundancy_rail=redundancy_rail,
        redundancy_domain_id=REDUNDANCY_DOMAIN_ID,
        operations=_operations_engine(),
        operations_domain_id=OPERATIONS_DOMAIN_ID,
        evidence=EvidenceArchive(),
        evidence_domain_id=EVIDENCE_DOMAIN_ID,
        checkout_id=CHECKOUT_ID,
        intent_id=INTENT_ID,
        promise_settlement_id=SETTLEMENT_ID,
        amount_minor=JOURNEY_AMOUNT_MINOR,
        asset_code=JOURNEY_ASSET_CODE,
        amount_scale=JOURNEY_SCALE,
        credit_limit_minor=CREDIT_LIMIT_MINOR,
        payer=CUSTOMER_ACTOR,
        payee=MERCHANT_ACTOR,
        primary_key=PRIMARY_IDEMPOTENCY_KEY,
        redundancy_key=REDUNDANCY_IDEMPOTENCY_KEY,
    )


def declared_world_for(
    world: FlywheelWorld,
    *,
    tag: str,
    environment_id: str,
    domain_id: str,
) -> Any:
    """Build one deterministic declared fulfillment world.

    The SAME declared parameters always build a byte-identical world:
    the journey's payer (the customer), payee (the merchant), amount
    and asset — differing only in the tag (the primary journey vs the
    recovery journey).
    """
    return build_declared_world(
        environment_id=environment_id,
        domain_id=domain_id,
        tag=tag,
        payer=world.payer,
        payee=world.payee,
        amount_minor=world.amount_minor,
        currency=world.asset_code,
    )
