"""The two composed economic worlds of the IG-004 gate.

Each world is ONE environment of the SAME composed protocol machine:

* the REAL merchant checkout record (the demand source) built through
  ``src.merchant``'s public record boundary;
* the REAL extension runtime + capability marketplace (WORK-020):
  a concrete in-repo deterministic route-advisor extension is
  registered, sandbox-certified, reviewed, published, installed and
  activated per world, then invoked on the merchant demand signal;
* the REAL agents surface (WORK-021): deployed models, a bounded
  proposal mandate, a hypothetical-only agent context, kernel-recorded
  route proposals and the simulation-first mediation engine;
* the mediation world adapter (the merged WORK-019 ``ScriptedWorld``)
  whose SIMULATED route observations for the economy family are
  DERIVED from the extension's output artifact (the composition
  binding) and whose premium family observations are the declared
  no-extension default.

The worlds differ ONLY in their environment binding: the environment
identity, the extension runtime's environment mode (SIMULATION vs
PRODUCTION — the manifest declares support for both and the same code
runs in each) and the mode-required epistemic class of the world
observations consumed by the mediation substrate. Everything economic
— amounts, savings, contributions, proposals, decisions — is identical
declared data.

Determinism discipline: every instant is declared ``as_of`` data; the
code repository resolves declared code hashes only; two constructions
from the same declared inputs build byte-identical worlds.
"""

from __future__ import annotations

from collections import namedtuple
from dataclasses import dataclass, field
from typing import Any, Mapping

from src.agents import (
    MEDIATION_REQUIRED_MODE,
    PROPOSAL_AUTHORITY_CLASS,
    AgentContext,
    AgentsEngine,
    MediationEngine,
    MediationPolicy,
    ModelOutput,
    RouteProposal,
    build_agent_context,
)
from src.agents.mediation import MediationDecision
from src.core.envelope import Provenance
from src.core.errors import CoreValidationError
from src.evidence.contracts import EpistemicType
from src.extensions import (
    CodeRepository,
    ExtensionArtifact,
    ExtensionArtifactKind,
    ExtensionCapability,
    ExtensionContribution,
    ExtensionManifest,
    ExtensionPermission,
    ExtensionRuntime,
    MonitoringLevel,
    PricingModel,
    PricingSpec,
    ResourceRequirements,
    RiskControls,
    VerificationEvidence,
)
from src.extensions.contracts import EXTENSION_COMMAND_TYPES
from src.merchant import Checkout, CheckoutSpec
from src.simulation import (
    EnvironmentMode,
    ScriptedWorld,
    WorldObservation,
    mode_epistemic_type,
)
from src.transition import (
    AuthorizationDecision,
    Command,
    ExpectedVersion,
    Outcome,
)
from src.value import Amount

from src.integration.economics.contracts import (
    AGENT_PRINCIPAL,
    AGENTS_DOMAIN_ID,
    CONTEXT_ID,
    DEFAULT_AUTHORIZED_ACTORS,
    DEFAULT_ECONOMICS_ACTOR,
    DEMAND_ARTIFACT_ID,
    DEMAND_ASSET,
    DEMAND_SCALE,
    DEMAND_VOLUME_MINOR,
    ECONOMY_FAMILY,
    ECONOMY_LATENCY_MS,
    ECONOMY_RELIABILITY_BPS,
    ESCALATOR_PRINCIPAL,
    EXTENSIONS_DOMAIN_ID,
    EXTENSION_CODE_HASH,
    EXTENSION_ID,
    EconomicRole,
    GOVERNANCE_AUTHORITY_CLASS,
    GRANT_ID,
    INSTANCE_ID,
    MANDATE_ID,
    MEDIATION_ACTOR,
    MEDIATION_ID,
    MERCHANT_ACTOR,
    MERCHANT_CHECKOUT_ID,
    MERCHANT_DOMAIN_ID,
    MODEL_APPROVER,
    MODEL_COST_ID,
    MODEL_DEVELOPER,
    MODEL_RELIABILITY_ID,
    POLICY_COST_WEIGHT_BPS,
    POLICY_ID,
    POLICY_LATENCY_WEIGHT_BPS,
    POLICY_RELIABILITY_WEIGHT_BPS,
    PREMIUM_COST_MINOR,
    PREMIUM_FAMILY,
    PREMIUM_LATENCY_MS,
    PREMIUM_RELIABILITY_BPS,
    PRICING_ASSET,
    PRODUCTION_COMPATIBLE_ENVIRONMENT_ID,
    PROPOSAL_ALPHA_ID,
    PROPOSAL_BRAVO_ID,
    REVENUE_SHARE_BPS,
    SIMULATION_ENVIRONMENT_ID,
    T_EXPIRY,
    T_INSTALL,
    T_MANDATE,
    T_MEDIATE,
    T_MODELS,
    T_OUTPUT,
    T_PROPOSE,
    T_REGISTER,
    T_SANDBOX,
    T_TREATMENT,
)

#: The payer/customer/intent of the merchant demand scenario.
DEMAND_PAYER = "principal/ig004-payer"
DEMAND_CUSTOMER = "principal/customer-ig004-1"
DEMAND_INTENT = "intent/ig004-demand-1"

#: The deterministic pair of the two composed worlds (fixed order).
EconomicPair = namedtuple("EconomicPair", ["simulation", "production"])


def _authority_table() -> Any:
    """Deterministic fixture authorization (actor -> registry class)."""

    table = {
        DEFAULT_ECONOMICS_ACTOR: "A1",
        MEDIATION_ACTOR: GOVERNANCE_AUTHORITY_CLASS,
        MODEL_DEVELOPER: "A1",
        MODEL_APPROVER: "A1",
        AGENT_PRINCIPAL: PROPOSAL_AUTHORITY_CLASS,
        ESCALATOR_PRINCIPAL: "R4",
    }

    def hook(command: Command, view) -> AuthorizationDecision:
        granted = table.get(command.actor)
        if granted is None:
            return AuthorizationDecision(
                granted=False,
                authority=None,
                reason=(
                    f"actor {command.actor} holds no authority in this "
                    "environment"
                ),
            )
        return AuthorizationDecision(granted=True, authority=granted, reason=None)

    return hook


def route_advisor_handler(context: Any) -> tuple[ExtensionArtifact, ...]:
    """The REAL extension: a deterministic route-advisor provider.

    Reads one declared demand signal and proposes the economy route
    whose cost is exactly the declared default cost minus one percent
    of the corridor volume (pure integer arithmetic). The handler is a
    pure function of the closed sandbox context: it receives no store,
    engine, view, ledger or kernel handle, and it cannot branch on
    anything but the declared inputs — which is exactly why the SAME
    code produces byte-identical economics in both environments.
    """
    demand = context.inputs[0]
    payload = demand.payload_value()
    volume = payload["volume_minor"]
    savings = volume // 100
    cost = PREMIUM_COST_MINOR - savings
    return (
        ExtensionArtifact(
            artifact_id=f"extension-artifact/{context.invocation_id}/route",
            kind=ExtensionArtifactKind.ROUTE_PROPOSAL,
            schema_version=1,
            producer=context.extension_id,
            payload=(
                ("corridor", payload["corridor"]),
                ("route_family", ECONOMY_FAMILY),
                ("cost_minor", cost),
                ("cost_savings_minor", savings),
                ("latency_ms", ECONOMY_LATENCY_MS),
                ("reliability_bps", ECONOMY_RELIABILITY_BPS),
                ("quality_bps", 9000),
            ),
            provenance=Provenance(
                issuer=MERCHANT_ACTOR,
                source="economics/route-advisor",
                recorded_at=context.as_of,
                evidence_refs=(demand.artifact_id,),
            ),
            expires_at=T_EXPIRY,
            confidence_bps=8500,
            dependencies=(demand.artifact_id,),
            risk_band="LOW",
        ),
    )


def merchant_checkout_spec() -> CheckoutSpec:
    """The declared merchant demand (the scenario's economic source)."""
    return CheckoutSpec(
        checkout_id=MERCHANT_CHECKOUT_ID,
        merchant_id=MERCHANT_ACTOR,
        customer_id=DEMAND_CUSTOMER,
        intent_id=DEMAND_INTENT,
        amount=Amount(
            value=DEMAND_VOLUME_MINOR, scale=DEMAND_SCALE, asset=DEMAND_ASSET
        ),
        expires_at=T_EXPIRY,
    )


def build_merchant_checkout(environment_id: str) -> Checkout:
    """Build the sealed merchant checkout record (public record boundary).

    Composed through ``src.merchant``'s actual public record factory
    (``Checkout.create`` over a validated ``CheckoutSpec`` with the
    domain seal). The module's kernel-binding engine path is
    pre-existing red at this base (the disclosed WORK-025
    ``TransitionApplication`` NameError in ``src/merchant/engine.py``,
    6/9 pytest failures); the record factory is the working public
    boundary and no silent workaround is performed — the pre-existing
    engine failure is disclosed in the PR, never fixed here.
    """
    return Checkout.create(
        spec=merchant_checkout_spec(),
        environment_id=environment_id,
        domain_id=MERCHANT_DOMAIN_ID,
        provenance=Provenance(
            issuer=MERCHANT_ACTOR,
            source="economics/merchant-demand",
            recorded_at=T_REGISTER,
        ),
    )


def demand_artifact(checkout: Checkout) -> ExtensionArtifact:
    """The demand signal artifact derived from the sealed checkout.

    The binding is exact: the artifact's volume IS the checkout amount
    value and the artifact id references the checkout record.
    """
    return ExtensionArtifact(
        artifact_id=DEMAND_ARTIFACT_ID,
        kind=ExtensionArtifactKind.DEMAND_SIGNAL,
        schema_version=1,
        producer=MERCHANT_ACTOR,
        payload=(
            ("corridor", "US->GH"),
            ("volume_minor", checkout.spec.amount.value),
            ("currency", checkout.spec.amount.asset),
            ("scale", checkout.spec.amount.scale),
            ("checkout_id", checkout.spec.checkout_id),
        ),
        provenance=Provenance(
            issuer=MERCHANT_ACTOR,
            source="economics/merchant-demand",
            recorded_at=T_REGISTER,
        ),
        expires_at=checkout.spec.expires_at,
        confidence_bps=9000,
        dependencies=(checkout.spec.checkout_id,),
        risk_band="LOW",
    )


def extension_manifest() -> ExtensionManifest:
    """The declared marketplace manifest of the real extension."""
    return ExtensionManifest(
        extension_id=EXTENSION_ID,
        developer="principal/ig004-developer",
        version="1.0.0",
        code_hash=EXTENSION_CODE_HASH,
        capabilities_provided=(ExtensionCapability.ROUTE_PROPOSAL,),
        capabilities_required=(),
        permissions=(ExtensionPermission.READ_MARKET_DATA,),
        dependencies=(),
        inputs=(ExtensionArtifactKind.DEMAND_SIGNAL,),
        outputs=(ExtensionArtifactKind.ROUTE_PROPOSAL,),
        pricing=PricingSpec(
            model=PricingModel.REVENUE_SHARE,
            amount_minor=0,
            asset=PRICING_ASSET,
            share_bps=REVENUE_SHARE_BPS,
        ),
        resource_requirements=ResourceRequirements(10, 1_048_576),
        authority_class="R2",
        risk_class="MEDIUM",
        jurisdictions=("US",),
        protocol_versions=("v0.1",),
        schema_versions=(1,),
        simulation_support=True,
        production_support=True,
        verification=VerificationEvidence(
            method="third-party-audit",
            evidence_refs=("evidence/ig004-audit",),
            review_digest="c" * 64,
        ),
        risk_controls=RiskControls(
            monitoring_level=MonitoringLevel.STANDARD,
            collateral=None,
            risk_limits=None,
        ),
    )


def capability_grant_fixture() -> dict[str, Any]:
    """The declared covering grant for the installed instance."""
    return {
        "grant_id": GRANT_ID,
        "capability": "route_proposal",
        "granted_by": DEFAULT_ECONOMICS_ACTOR,
        "valid_from": T_REGISTER,
        "valid_until": T_EXPIRY,
        "jurisdictions": ("US",),
        "budget": {
            "max_invocations": 5,
            "window_start": T_REGISTER,
            "window_end": T_EXPIRY,
        },
    }


def _model_output(output_id: str, model_id: str, value: Any) -> ModelOutput:
    return ModelOutput(
        output_id=output_id,
        model_id=model_id,
        epistemic_type=EpistemicType.SIMULATED,
        confidence_bps=8000,
        value=value,
        declared_limitations=("corridor observations only",),
        produced_at=T_OUTPUT,
        valid_from=T_OUTPUT,
        valid_until=T_EXPIRY,
        provenance=Provenance(
            issuer=model_id,
            source="economics/model-output",
            recorded_at=T_OUTPUT,
            evidence_refs=(f"evidence/ig004-{output_id}",),
        ),
    )


def model_outputs_for_route(
    route_family: str, cost_minor: int
) -> tuple[ModelOutput, ...]:
    """The model outputs backing one route proposal (declared fixtures)."""
    return (
        _model_output(
            f"model-output/ig004-{route_family}-cost",
            MODEL_COST_ID,
            {"cost_minor": cost_minor},
        ),
        _model_output(
            f"model-output/ig004-{route_family}-reliability",
            MODEL_RELIABILITY_ID,
            {"reliability_bps": ECONOMY_RELIABILITY_BPS},
        ),
    )


def premium_declared_route_metrics() -> dict[str, int]:
    """The declared no-extension default route metrics (premium family)."""
    return {
        "cost-minor": PREMIUM_COST_MINOR,
        "latency-ms": PREMIUM_LATENCY_MS,
        "reliability-bps": PREMIUM_RELIABILITY_BPS,
    }


def economy_route_metrics_from_artifact(
    artifact: ExtensionArtifact,
) -> dict[str, int]:
    """The economy route metrics DERIVED from the extension's artifact.

    This is the load-bearing composition binding: the mediation world's
    economy-family observations are exactly the extension's measured
    route economics (cost, latency, reliability), and the extension's
    cost embeds its declared savings against the premium default.
    """
    payload = artifact.payload_value()
    return {
        "cost-minor": payload["cost_minor"],
        "latency-ms": payload["latency_ms"],
        "reliability-bps": payload["reliability_bps"],
    }


def build_mediation_world(
    route_metrics: Mapping[str, Mapping[str, int]],
) -> ScriptedWorld:
    """Build the deterministic mediation world from the route metrics.

    The observations carry the frozen ``SIMULATED`` epistemic class
    required by the frozen ``SIMULATION`` mediation mode, keyed exactly
    as the merged mediation handler reads them
    (``route/<family>/<metric-key>``), at the declared mediation
    instant.
    """
    observations = []
    for family in sorted(route_metrics):
        for metric_key in sorted(route_metrics[family]):
            observations.append(
                WorldObservation(
                    observation_key=f"route/{family}/{metric_key}",
                    epistemic_type=EpistemicType.SIMULATED,
                    as_of=T_MEDIATE,
                    value=route_metrics[family][metric_key],
                    source="world/ig004-mediation",
                )
            )
    return ScriptedWorld(
        observations=tuple(observations),
        epistemic_type=EpistemicType.SIMULATED,
    )


def mediation_policy() -> MediationPolicy:
    """The declared deterministic mediation policy (explicit weights)."""
    return MediationPolicy(
        policy_id=POLICY_ID,
        policy_version=1,
        cost_weight_bps=POLICY_COST_WEIGHT_BPS,
        latency_weight_bps=POLICY_LATENCY_WEIGHT_BPS,
        reliability_weight_bps=POLICY_RELIABILITY_WEIGHT_BPS,
    )


@dataclass
class EconomicWorld:
    """One composed environment of the IG-004 economic integration gate.

    Holds the LIVE merged engines (extension runtime, agents engine,
    mediation engine) plus the per-world composed records read back
    through the engines' public trusted paths. The world never caches
    authoritative state: ``checkout``, ``demand_artifact``,
    ``proposals``, ``decision`` and ``contribution`` are the artifacts
    the gate produced through the real public boundaries, retained for
    projection and audit only.
    """

    role: EconomicRole
    environment_id: str
    environment_mode: EnvironmentMode
    epistemic_class: EpistemicType
    extensions_domain_id: str
    agents_domain_id: str
    merchant_domain_id: str
    runtime: ExtensionRuntime
    agents: AgentsEngine
    mediator: MediationEngine
    checkout: Checkout | None = None
    demand_artifact: ExtensionArtifact | None = None
    world_source: ScriptedWorld | None = None
    route_metrics: dict[str, dict[str, int]] = field(default_factory=dict)
    treatment_invocation_ids: list[str] = field(default_factory=list)
    context: AgentContext | None = None
    proposals: dict[str, RouteProposal] = field(default_factory=dict)
    decision: MediationDecision | None = None
    contribution: ExtensionContribution | None = None
    #: Back-reference to the owning gate (set by the gate constructor;
    #: the projection reads the gate's stage journal through it).
    gate: Any = None

    def __post_init__(self) -> None:
        if not isinstance(self.role, EconomicRole):
            raise CoreValidationError("an economic world requires an EconomicRole")
        if not isinstance(self.environment_mode, EnvironmentMode):
            raise CoreValidationError(
                "an economic world requires an EnvironmentMode"
            )
        if not isinstance(self.epistemic_class, EpistemicType):
            raise CoreValidationError(
                "an economic world requires an EpistemicType"
            )
        # The frozen mode→epistemic binding is load-bearing: the world's
        # declared epistemic class must be exactly what its environment
        # mode requires (SIMULATION → SIMULATED, PRODUCTION → OBSERVED).
        required = mode_epistemic_type(self.environment_mode)
        if self.epistemic_class is not required:
            raise CoreValidationError(
                f"economic world role {self.role.value} binds mode "
                f"{self.environment_mode.value} which requires {required.value} "
                f"world observations, but the world declares "
                f"{self.epistemic_class.value} (mode/epistemic confusion fails "
                "closed)"
            )
        if self.runtime.environment_id != self.environment_id:
            raise CoreValidationError(
                "the extension runtime must bind the world's environment"
            )
        if self.agents.environment_id != self.environment_id:
            raise CoreValidationError(
                "the agents engine must bind the world's environment"
            )


def build_economic_world(role: EconomicRole) -> EconomicWorld:
    """Build one composed economic world from the declared fixture data.

    Everything is deterministic declared data: the code repository
    resolves exactly the declared code hash, the authorization table is
    the fixture class table, and the engines bind the world's
    environment. Two calls build byte-identical worlds. The world
    fixture carries the sealed merchant demand checkout with its
    derived demand signal artifact and the pre-registered marketplace
    manifest of the real route-advisor extension (driven through the
    public ``extension/register`` command, so the fixture records are
    live kernel state, never seeded projections). The gate then owns
    the lifecycle advancement and the whole composed scenario.
    """
    role = EconomicRole.parse(role)
    if role is EconomicRole.SIMULATION:
        environment_id = SIMULATION_ENVIRONMENT_ID
        environment_mode = EnvironmentMode.SIMULATION
    else:
        environment_id = PRODUCTION_COMPATIBLE_ENVIRONMENT_ID
        environment_mode = EnvironmentMode.PRODUCTION
    epistemic_class = mode_epistemic_type(environment_mode)

    repository = CodeRepository()
    repository.register(EXTENSION_CODE_HASH, route_advisor_handler)
    runtime = ExtensionRuntime(
        environment_id=environment_id,
        domain_id=EXTENSIONS_DOMAIN_ID,
        environment_mode=environment_mode,
        authorized_actors=DEFAULT_AUTHORIZED_ACTORS,
        code_repository=repository,
    )
    agents = AgentsEngine(
        environment_id,
        AGENTS_DOMAIN_ID,
        authorization=_authority_table(),
        emit_rejection_events=True,
        rejection_authority=GOVERNANCE_AUTHORITY_CLASS,
    )
    mediator = MediationEngine(engine=agents, policy=mediation_policy())
    world = EconomicWorld(
        role=role,
        environment_id=environment_id,
        environment_mode=environment_mode,
        epistemic_class=epistemic_class,
        extensions_domain_id=EXTENSIONS_DOMAIN_ID,
        agents_domain_id=AGENTS_DOMAIN_ID,
        merchant_domain_id=MERCHANT_DOMAIN_ID,
        runtime=runtime,
        agents=agents,
        mediator=mediator,
    )
    # The declared fixture records: the sealed merchant checkout, its
    # demand signal artifact and the registered extension manifest.
    world.checkout = build_merchant_checkout(environment_id)
    world.demand_artifact = demand_artifact(world.checkout)
    result = runtime.submit(
        extension_command(
            world,
            command_id="fixture/ig004-register",
            command_type="extension/register",
            target_refs=(EXTENSION_ID,),
            payload={"manifest": extension_manifest().to_record_dict()},
            expected_versions=((EXTENSION_ID, 0),),
            requested_at=T_REGISTER,
        )
    )
    if result.outcome is not Outcome.ACCEPTED:
        raise CoreValidationError(
            "the fixture extension manifest registration was not accepted"
        )
    return world


def build_economic_pair() -> EconomicPair:
    """Build the two compared worlds (deterministic order)."""
    return EconomicPair(
        simulation=build_economic_world(EconomicRole.SIMULATION),
        production=build_economic_world(EconomicRole.PRODUCTION_COMPATIBLE),
    )


def extension_command(
    world: EconomicWorld,
    *,
    command_id: str,
    command_type: str,
    target_refs: tuple[str, ...],
    payload: Any,
    requested_at: str,
    expected_versions: tuple[tuple[str, int], ...] = (),
) -> Command:
    """Build one extension-domain command bound to the world's environment."""
    if command_type not in EXTENSION_COMMAND_TYPES:
        raise CoreValidationError(f"unknown extension command type {command_type!r}")
    return Command.build(
        command_id=command_id,
        command_type=command_type,
        actor=DEFAULT_ECONOMICS_ACTOR,
        authority_refs=("authority/ig004-ops",),
        target_refs=target_refs,
        payload=payload,
        environment_id=world.environment_id,
        domain_id=world.extensions_domain_id,
        idempotency_key=f"key/{command_id}",
        nonce="1",
        requested_at=requested_at,
        expected_versions=tuple(
            ExpectedVersion(object_ref=ref, object_version=version)
            for ref, version in expected_versions
        ),
    )


def agents_command(
    world: "EconomicWorld | AgentsEngine",
    *,
    command_id: str,
    command_type: str,
    actor: str,
    target: str,
    payload: Any,
    requested_at: str,
    expected_version: int = 0,
) -> Command:
    """Build one agents-domain command bound to the world's environment.

    Accepts either a composed :class:`EconomicWorld` or a bare
    :class:`AgentsEngine` (the containment probes drive throwaway
    engines with the same fixture authorization).
    """
    if isinstance(world, EconomicWorld):
        environment_id = world.environment_id
        domain_id = world.agents_domain_id
    else:
        environment_id = world.environment_id
        domain_id = world.domain_id
    return Command.build(
        command_id=f"cmd/{command_id}",
        command_type=command_type,
        actor=actor,
        authority_refs=(f"authority/{command_id}",),
        target_refs=(target,),
        payload=payload,
        environment_id=environment_id,
        domain_id=domain_id,
        expected_versions=(
            ExpectedVersion(object_ref=target, object_version=expected_version),
        ),
        idempotency_key=f"key/{command_id}",
        nonce="1",
        requested_at=requested_at,
    )


def current_extension_version(world: EconomicWorld, object_ref: str) -> int:
    """The live kernel-store version of one extension-domain object."""
    envelope = world.runtime.store.get(object_ref)
    return 0 if envelope is None else envelope.object_version


def register_model_commands(world: "EconomicWorld | AgentsEngine") -> None:
    """Drive the model lifecycle (register→validate→approve→deploy ×2)."""
    from src.integration.economics.contracts import T_MODELS as _T_MODELS

    engine = world.agents if isinstance(world, EconomicWorld) else world
    for model_id in (MODEL_COST_ID, MODEL_RELIABILITY_ID):
        engine.process(
            agents_command(
                world,
                command_id=f"register-{model_id}",
                command_type="model/register",
                actor=MODEL_DEVELOPER,
                target=model_id,
                payload={
                    "model_id": model_id,
                    "developer": MODEL_DEVELOPER,
                    "task": "predict route economics in exact minor units",
                    "risk_class": "LOW",
                    "declared_limitations": (
                        "trained on corridor observations only",
                        "no counterparty default modeling",
                    ),
                    "code_hash": EXTENSION_CODE_HASH,
                },
                requested_at=_T_MODELS,
            )
        )
        engine.process(
            agents_command(
                world,
                command_id=f"validate-{model_id}",
                command_type="model/validate",
                actor=MODEL_DEVELOPER,
                target=model_id,
                payload={"model_id": model_id, "validation_notes": "backtests pass"},
                requested_at=_T_MODELS,
                expected_version=1,
            )
        )
        engine.process(
            agents_command(
                world,
                command_id=f"approve-{model_id}",
                command_type="model/approve",
                actor=MODEL_APPROVER,
                target=model_id,
                payload={"model_id": model_id, "approver": MODEL_APPROVER},
                requested_at=_T_MODELS,
                expected_version=2,
            )
        )
        engine.process(
            agents_command(
                world,
                command_id=f"deploy-{model_id}",
                command_type="model/deploy",
                actor=MEDIATION_ACTOR,
                target=model_id,
                payload={"model_id": model_id},
                requested_at=_T_MODELS,
                expected_version=3,
            )
        )


def authorize_mandate(world: "EconomicWorld | AgentsEngine") -> None:
    """Authorize the bounded proposal mandate (governance actor)."""
    from src.integration.economics.contracts import T_MANDATE as _T_MANDATE

    engine = world.agents if isinstance(world, EconomicWorld) else world
    engine.process(
        agents_command(
            world,
            command_id="mandate-ig004",
            command_type="agent/authorize-mandate",
            actor=MEDIATION_ACTOR,
            target=MANDATE_ID,
            payload={
                "mandate_id": MANDATE_ID,
                "agent_principal": AGENT_PRINCIPAL,
                "proposal_kinds": ["ROUTE"],
                "route_families": [PREMIUM_FAMILY, ECONOMY_FAMILY],
                "max_proposals": 3,
                "not_before": _T_MANDATE,
                "not_after": T_EXPIRY,
                "authority_class": PROPOSAL_AUTHORITY_CLASS,
            },
            requested_at=_T_MANDATE,
        )
    )


def build_context(world: EconomicWorld) -> AgentContext:
    """Build the hypothetical-only agent context over the deployed models."""
    from src.integration.economics.contracts import T_MANDATE as _T_MANDATE

    return build_agent_context(
        registry=world.agents.registry,
        mandates=world.agents.mandates,
        context_id=CONTEXT_ID,
        agent_principal=AGENT_PRINCIPAL,
        mandate_id=MANDATE_ID,
        model_ids=(MODEL_COST_ID, MODEL_RELIABILITY_ID),
        allowed_modes=(MEDIATION_REQUIRED_MODE,),
        as_of=_T_MANDATE,
    )


def route_proposal(
    world: EconomicWorld,
    *,
    proposal_id: str,
    route_family: str,
    declared_cost_minor: int,
    declared_latency_ms: int,
    declared_reliability_bps: int,
) -> RouteProposal:
    """Build one sealed route proposal record for the agent."""
    context = world.context
    if context is None:
        raise CoreValidationError(
            "the agent context must exist before proposals are built"
        )
    return RouteProposal.build(
        proposal_id=proposal_id,
        agent_principal=AGENT_PRINCIPAL,
        mandate_id=MANDATE_ID,
        route_family=route_family,
        rail=f"rail/ig004-{route_family}",
        declared_cost_minor=declared_cost_minor,
        declared_cost_scale=DEMAND_SCALE,
        declared_cost_asset=f"asset/{DEMAND_ASSET.lower()}",
        declared_latency_ms=declared_latency_ms,
        declared_reliability_bps=declared_reliability_bps,
        context=context,
        model_outputs=model_outputs_for_route(route_family, declared_cost_minor),
        as_of=T_PROPOSE,
    )


def record_proposal(world: EconomicWorld, proposal: RouteProposal) -> Any:
    """Record one agent proposal through the real kernel."""
    return world.agents.process(
        agents_command(
            world,
            command_id=f"propose-{proposal.proposal_id}",
            command_type="agent/propose",
            actor=AGENT_PRINCIPAL,
            target=proposal.proposal_id,
            payload={"proposal": proposal.to_dict()},
            requested_at=T_PROPOSE,
        )
    )
