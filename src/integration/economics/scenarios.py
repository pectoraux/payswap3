"""The IG-004 deterministic scenario drivers.

* :func:`run_economic_scenario` — the canonical composed economic chain
  (merchant demand → extension lifecycle + treatment invocation → agent
  models/mandate/context/proposals → simulation-first mediation →
  contribution measurement) executed in BOTH worlds in lockstep, with
  the sealed parity verdict failing closed on any divergence.
* :func:`run_containment_battery` — the frozen authority-containment
  probe set (extensions cannot acquire undeclared authority, agents
  cannot escalate, contexts stay hypothetical, model outputs cannot
  masquerade as observations, activity volume is not contribution,
  commands stay in their domains). Every probe must be CONTAINED with
  the composed domain state byte-unchanged (the books of both engines;
  agent-side rejection audit events are append-only journal records,
  never book mutations).
* :func:`run_contribution_integrity_scenario` — the economic
  contribution integrity report: unverified treatments never earn,
  shadow activity adds no earnings, and the cross-currency attribution
  conserves value through the merged money FX authority (exact
  residuals, closed rounding mode).

Every driver is a pure function of the declared fixture data: two runs
produce byte-identical results.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from src.agents import ModelOutput, build_agent_context
from src.core.errors import CoreValidationError
from src.extensions import ExtensionManifest, MonitoringLevel
from src.money import Amount as MoneyAmount
from src.money import FxRate, RoundingMode, convert, get_currency
from src.simulation import EnvironmentMode
from src.transition import Command, ExpectedVersion, Outcome, RejectionReason

from src.integration.economics.contracts import (
    AGENT_PRINCIPAL,
    CONTAINMENT_PROBES,
    CONTRIBUTION_ID,
    DECISION_ID,
    DEMAND_VOLUME_MINOR,
    ESCALATOR_PRINCIPAL,
    EXTENSION_ID,
    FX_USD_GHS_DENOMINATOR,
    FX_USD_GHS_NUMERATOR,
    INSTANCE_ID,
    MANDATE_ID,
    MEDIATION_ACTOR,
    MEDIATION_ID,
    PREMIUM_COST_MINOR,
    PROPOSAL_ALPHA_ID,
    SHADOW_INVOCATION_ID,
    SHADOW_REMEASURE_ID,
    T_INSTALL,
    T_MEASURE,
    T_SHADOW,
    UNVERIFIED_CONTRIBUTION_ID,
)
from src.integration.economics.harness import EconomicIntegrationGate, assert_economic_parity
from src.integration.economics.worlds import (
    EXTENSION_CODE_HASH,
    agents_command,
    extension_command,
    current_extension_version,
    extension_manifest,
    route_proposal,
)


def run_economic_scenario(
    *, scenario_id: str = "ig004/canonical"
) -> tuple[EconomicIntegrationGate, Any]:
    """Drive the canonical scenario in both worlds; fail closed on divergence."""
    gate = EconomicIntegrationGate()
    verdict = gate.run_canonical_scenario()
    assert_economic_parity(verdict)
    return gate, verdict


@dataclass(frozen=True)
class ContainmentProbeResult:
    """One authority-containment probe outcome (fail-closed evidence)."""

    probe_id: str
    contained: bool
    detail: str
    state_unchanged: bool

    def __post_init__(self) -> None:
        if self.probe_id not in CONTAINMENT_PROBES:
            raise CoreValidationError(
                f"unknown containment probe {self.probe_id!r}"
            )
        if not isinstance(self.detail, str) or not self.detail.strip():
            raise CoreValidationError(
                "a containment probe requires its fail-closed detail"
            )


def _probe(
    world: Any,
    gate: EconomicIntegrationGate,
    probe_id: str,
    action,
) -> ContainmentProbeResult:
    """Run one probe with the state-unchanged fail-closed wrapper."""
    before = gate.composed_state_digest(world)
    try:
        detail = action()
    except CoreValidationError as exc:
        return ContainmentProbeResult(
            probe_id=probe_id,
            contained=True,
            detail=str(exc),
            state_unchanged=True,
        )
    after = gate.composed_state_digest(world)
    state_unchanged = before == after
    contained = state_unchanged and detail is None
    if detail is not None and not isinstance(detail, str):
        raise CoreValidationError(
            f"probe {probe_id!r} produced an unexpected probe artifact"
        )
    return ContainmentProbeResult(
        probe_id=probe_id,
        contained=contained,
        detail=detail or "the probe was NOT contained",
        state_unchanged=state_unchanged,
    )


def _reject_detail(result: Any) -> str | None:
    """A kernel rejection result is a CONTAINED probe (the None path)."""
    if result.outcome is Outcome.REJECTED:
        reason = result.reason.value if result.reason is not None else "rejected"
        return None if reason == "REJECTED" else None
    if result.outcome is Outcome.DUPLICATE:
        return "the probe command was a DUPLICATE, not a rejection"
    return "the probe command was ACCEPTED"


def run_containment_battery() -> tuple[ContainmentProbeResult, ...]:
    """Run the frozen containment probe set on the composed state."""
    gate, _verdict = run_economic_scenario()
    world = gate.simulation_world
    results: list[ContainmentProbeResult] = []

    # 1. tier escalation: an R5 authority claim without the required
    #    financial collateral fails closed at manifest construction (the
    #    frozen tier schedule — the monitoring requirement is satisfied
    #    so the rejection exercises exactly the collateral boundary).
    def _tier_escalation() -> str | None:
        base = extension_manifest()
        escalated = replace(
            base,
            authority_class="R5",
            risk_controls=replace(
                base.risk_controls,
                monitoring_level=MonitoringLevel.INTENSIVE,
                # Collateral stays undeclared: the R5 schedule minimum
                # (25,000,000 minor units) is the binding constraint.
            ),
        )
        return f"R5 manifest accepted: {escalated.extension_id}"

    results.append(_probe(world, gate, "tier-escalation-r5", _tier_escalation))

    # 2. forbidden permission: a manifest claiming a forbidden power
    #    fails closed (not a member of the closed permission vocabulary).
    def _forbidden_permission_action() -> str | None:
        replace(extension_manifest(), permissions=("ledger_write",))
        return "forbidden manifest accepted"

    results.append(
        _probe(world, gate, "forbidden-permission", _forbidden_permission_action)
    )

    # 3. undeclared resource: the sandbox refuses resources the manifest
    #    does not declare (extensions cannot access undeclared resources).
    def _undeclared_resource() -> str | None:
        result = world.runtime.submit(
            extension_command(
                world,
                command_id="cmd/ig004-probe-undeclared-resource",
                command_type="extension/invoke",
                target_refs=("extension-invocation/ig004-probe-resource",),
                payload={
                    "invocation_id": "extension-invocation/ig004-probe-resource",
                    "capability": "route_proposal",
                    "inputs": [world.demand_artifact.to_dict()],
                    "resources": {"observe_protocol_state": {"view": "full"}},
                    "as_of": T_MEASURE,
                    "jurisdiction": "US",
                },
                expected_versions=(
                    ("extension-invocation/ig004-probe-resource", 0),
                    (INSTANCE_ID, current_extension_version(world, INSTANCE_ID)),
                ),
                requested_at=T_MEASURE,
            )
        )
        return _reject_detail(result)

    results.append(_probe(world, gate, "undeclared-resource", _undeclared_resource))

    # 4. undeclared capability: the manifest provides only route_proposal.
    def _undeclared_capability() -> str | None:
        result = world.runtime.submit(
            extension_command(
                world,
                command_id="cmd/ig004-probe-undeclared-capability",
                command_type="extension/invoke",
                target_refs=("extension-invocation/ig004-probe-capability",),
                payload={
                    "invocation_id": "extension-invocation/ig004-probe-capability",
                    "capability": "quote_provision",
                    "inputs": [world.demand_artifact.to_dict()],
                    "resources": {"read_market_data": {"spread_bps": 12}},
                    "as_of": T_MEASURE,
                    "jurisdiction": "US",
                },
                expected_versions=(
                    ("extension-invocation/ig004-probe-capability", 0),
                    (INSTANCE_ID, current_extension_version(world, INSTANCE_ID)),
                ),
                requested_at=T_MEASURE,
            )
        )
        return _reject_detail(result)

    results.append(
        _probe(world, gate, "undeclared-capability", _undeclared_capability)
    )

    # 5. execute-tier proposal: an R4 EXECUTE principal tries to act as
    #    an agent; the kernel denies it at the authorization stage.
    def _execute_tier() -> str | None:
        result = world.agents.process(
            agents_command(
                world,
                command_id="probe-escalation",
                command_type="agent/propose",
                actor=ESCALATOR_PRINCIPAL,
                target=PROPOSAL_ALPHA_ID,
                payload={"proposal": world.proposals[PROPOSAL_ALPHA_ID].to_dict()},
                requested_at=T_MEASURE,
            )
        )
        return _reject_detail(result)

    results.append(_probe(world, gate, "execute-tier-proposal", _execute_tier))

    # 6. out-of-scope family: the agent proposes a route family outside
    #    its mandate scope; the policy gate rejects it.
    def _out_of_scope() -> str | None:
        proposal = route_proposal(
            world,
            proposal_id="agent-proposal/ig004-offledger-bypass",
            route_family="offledger-direct",
            declared_cost_minor=PREMIUM_COST_MINOR,
            declared_latency_ms=120,
            declared_reliability_bps=9980,
        )
        result = world.agents.process(
            agents_command(
                world,
                command_id="probe-scope-bypass",
                command_type="agent/propose",
                actor=AGENT_PRINCIPAL,
                target=proposal.proposal_id,
                payload={"proposal": proposal.to_dict()},
                requested_at=T_MEASURE,
            )
        )
        return _reject_detail(result)

    results.append(_probe(world, gate, "out-of-scope-family", _out_of_scope))

    # 7. production agent context: agents never receive live-observation
    #    authority (contexts are hypothetical-world-only).
    def _production_context() -> str | None:
        build_agent_context(
            registry=world.agents.registry,
            mandates=world.agents.mandates,
            context_id="agent/ig004-probe-production",
            agent_principal=AGENT_PRINCIPAL,
            mandate_id=MANDATE_ID,
            model_ids=("model/ig004-cost-model",),
            allowed_modes=(EnvironmentMode.PRODUCTION,),
            as_of=T_MEASURE,
        )
        return "PRODUCTION-mode agent context was accepted"

    results.append(
        _probe(world, gate, "production-agent-context", _production_context)
    )

    # 8. observed model output: a model output can never masquerade as
    #    an observation (the frozen epistemic restriction).
    def _observed_output() -> str | None:
        from src.evidence.contracts import EpistemicType
        from src.core.envelope import Provenance
        from src.integration.economics.contracts import T_OUTPUT, T_EXPIRY

        ModelOutput(
            output_id="model-output/ig004-probe-observed",
            model_id="model/ig004-cost-model",
            epistemic_type=EpistemicType.OBSERVED,
            confidence_bps=8000,
            value={"cost_minor": 1},
            declared_limitations=("probe",),
            produced_at=T_OUTPUT,
            valid_from=T_OUTPUT,
            valid_until=T_EXPIRY,
            provenance=Provenance(
                issuer="model/ig004-cost-model",
                source="economics/probe",
                recorded_at=T_OUTPUT,
            ),
        )
        return "OBSERVED model output was accepted"

    results.append(
        _probe(world, gate, "observed-model-output", _observed_output)
    )

    # 9. volume metric: activity volume is not a contribution measure
    #    (the closed metric vocabulary rejects it).
    def _volume_metric() -> str | None:
        result = world.runtime.submit(
            extension_command(
                world,
                command_id="cmd/ig004-probe-volume-metric",
                command_type="extension/measure",
                target_refs=("extension-contribution/ig004-probe-volume",),
                payload={
                    "contribution_id": "extension-contribution/ig004-probe-volume",
                    "baseline": {
                        "extension_id": EXTENSION_ID,
                        "metric": "invocation_count",
                        "value": 0,
                        "as_of": T_MEASURE,
                        "epistemic_type": "COUNTERFACTUAL",
                        "evidence_refs": ["counterfactual/ig004-default-route"],
                    },
                    "treatment": {
                        "extension_id": EXTENSION_ID,
                        "metric": "invocation_count",
                        "value": 5,
                        "as_of": T_MEASURE,
                        "epistemic_type": "SIMULATED",
                        "evidence_refs": ["extension-invocation/ig004-treatment-1"],
                    },
                },
                expected_versions=(
                    ("extension-contribution/ig004-probe-volume", 0),
                ),
                requested_at=T_MEASURE,
            )
        )
        return _reject_detail(result)

    results.append(_probe(world, gate, "volume-metric", _volume_metric))

    # 10. suspended model: only DEPLOYED models may back contexts.
    def _suspended_model() -> str | None:
        engine = _fresh_agents_engine(world)
        from src.integration.economics.worlds import register_model_commands, authorize_mandate

        register_model_commands(engine)
        engine.process(
            agents_command(
                engine,
                command_id="probe-suspend-model",
                command_type="model/suspend",
                actor=MEDIATION_ACTOR,
                target="model/ig004-cost-model",
                payload={
                    "model_id": "model/ig004-cost-model",
                    "reason": "drift detected in corridor backtests",
                },
                requested_at=T_MEASURE,
                expected_version=4,
            )
        )
        authorize_mandate(engine)
        build_agent_context(
            registry=engine.registry,
            mandates=engine.mandates,
            context_id="agent/ig004-probe-suspended",
            agent_principal=AGENT_PRINCIPAL,
            mandate_id=MANDATE_ID,
            model_ids=("model/ig004-cost-model", "model/ig004-reliability-model"),
            allowed_modes=(EnvironmentMode.SIMULATION,),
            as_of=T_MEASURE,
        )
        return "a suspended model backed an agent context"

    results.append(_probe(world, gate, "suspended-model", _suspended_model))

    # 11. mandate authority class: the mandate must freeze exactly the
    #     R2 PROPOSE tier (never a higher class).
    def _mandate_authority() -> str | None:
        result = world.agents.process(
            agents_command(
                world,
                command_id="probe-mandate-class",
                command_type="agent/authorize-mandate",
                actor=MEDIATION_ACTOR,
                target="agent-mandate/ig004-escalated",
                payload={
                    "mandate_id": "agent-mandate/ig004-escalated",
                    "agent_principal": ESCALATOR_PRINCIPAL,
                    "proposal_kinds": ["ROUTE"],
                    "route_families": ["premium", "economy"],
                    "max_proposals": 3,
                    "not_before": T_MEASURE,
                    "not_after": "2026-09-05T00:00:00Z",
                    "authority_class": "R4",
                },
                requested_at=T_MEASURE,
            )
        )
        return _reject_detail(result)

    results.append(
        _probe(world, gate, "mandate-authority-class", _mandate_authority)
    )

    # 12. agent self-mediation: the proposing agent cannot mediate its
    #     own proposals (mediation requires a governance authority).
    def _self_mediation() -> str | None:
        try:
            world.mediator.mediate(
                context=world.context,
                proposals=tuple(
                    world.proposals[proposal_id]
                    for proposal_id in sorted(world.proposals)
                ),
                world=world.world_source,
                mediation_id="mediation/ig004-self",
                decision_id="mediation-decision/ig004-self",
                as_of=T_MEASURE,
                actor=AGENT_PRINCIPAL,
            )
        except CoreValidationError:
            raise
        return "the agent mediated its own proposals"

    results.append(_probe(world, gate, "agent-self-mediation", _self_mediation))

    # 13. foreign-domain command: an extension command aimed at another
    #     domain is rejected by the kernel's domain binding.
    def _foreign_domain() -> str | None:
        command = Command.build(
            command_id="cmd/ig004-probe-foreign-domain",
            command_type="extension/publish",
            actor="principal/ig004-marketplace-operator",
            authority_refs=("authority/ig004-ops",),
            target_refs=(EXTENSION_ID,),
            payload={},
            environment_id=world.environment_id,
            domain_id="domain/foreign-economics",
            idempotency_key="key/ig004-probe-foreign-domain",
            nonce="1",
            requested_at=T_MEASURE,
            expected_versions=(
                ExpectedVersion(
                    object_ref=EXTENSION_ID,
                    object_version=current_extension_version(world, EXTENSION_ID),
                ),
            ),
        )
        result = world.runtime.submit(command)
        if result.outcome is Outcome.REJECTED and (
            result.reason is RejectionReason.DOMAIN_MISMATCH
        ):
            return None
        return _reject_detail(result)

    results.append(_probe(world, gate, "foreign-domain-command", _foreign_domain))

    unexpected = {probe.probe_id for probe in results} ^ set(CONTAINMENT_PROBES)
    if unexpected:
        raise CoreValidationError(
            f"the containment battery must cover exactly the frozen probe set; "
            f"unexpected {sorted(unexpected)}"
        )
    return tuple(results)


def _fresh_agents_engine(world: Any) -> Any:
    """A throwaway agents engine with the same fixture authorization."""
    from src.integration.economics.worlds import _authority_table
    from src.integration.economics.contracts import GOVERNANCE_AUTHORITY_CLASS, AGENTS_DOMAIN_ID

    from src.agents import AgentsEngine

    return AgentsEngine(
        world.environment_id,
        AGENTS_DOMAIN_ID,
        authorization=_authority_table(),
        emit_rejection_events=True,
        rejection_authority=GOVERNANCE_AUTHORITY_CLASS,
    )


def run_contribution_integrity_scenario() -> dict[str, Any]:
    """The contribution integrity report (conservation and no-free-earnings)."""
    gate, verdict = run_economic_scenario()
    world = gate.simulation_world
    contribution = world.contribution
    if contribution is None:
        raise CoreValidationError("the canonical contribution is missing")

    # 1. An UNBACKED treatment (no evidence references) measures zero
    #    earnings: activity volume and unverified claims never earn.
    unverified_savings = contribution.treatment.value
    world.runtime.submit(
        extension_command(
            world,
            command_id="cmd/ig004-measure-unverified",
            command_type="extension/measure",
            target_refs=(UNVERIFIED_CONTRIBUTION_ID,),
            payload={
                "contribution_id": UNVERIFIED_CONTRIBUTION_ID,
                "baseline": {
                    "extension_id": EXTENSION_ID,
                    "metric": "cost_savings_minor",
                    "value": 0,
                    "as_of": T_MEASURE,
                    "epistemic_type": "COUNTERFACTUAL",
                    "evidence_refs": ["counterfactual/ig004-default-route"],
                },
                "treatment": {
                    "extension_id": EXTENSION_ID,
                    "metric": "cost_savings_minor",
                    "value": unverified_savings,
                    "as_of": T_MEASURE,
                    "epistemic_type": "SIMULATED",
                    "evidence_refs": [],
                },
            },
            expected_versions=((UNVERIFIED_CONTRIBUTION_ID, 0),),
            requested_at=T_MEASURE,
        )
    )
    unverified = world.runtime.contribution(UNVERIFIED_CONTRIBUTION_ID)

    # 2. SHADOW activity adds no earnings and no applied invocations:
    #    the remeasurement's treatment evidence now ALSO references the
    #    shadowed invocation, but a shadowed observation is inert by the
    #    runtime's frozen derivation — it is never counted as an applied
    #    invocation, never adds resource credits, and the declared
    #    treatment value stays the RECORDED invocation's savings (only
    #    RECORDED evidence can carry measured value).
    world.runtime.submit(
        extension_command(
            world,
            command_id="cmd/ig004-shadow-on",
            command_type="extension/shadow",
            target_refs=(INSTANCE_ID,),
            payload={"shadow": True},
            expected_versions=(
                (INSTANCE_ID, current_extension_version(world, INSTANCE_ID)),
            ),
            requested_at=T_SHADOW,
        )
    )
    world.runtime.submit(
        extension_command(
            world,
            command_id=f"cmd/{SHADOW_INVOCATION_ID}",
            command_type="extension/invoke",
            target_refs=(SHADOW_INVOCATION_ID,),
            payload={
                "invocation_id": SHADOW_INVOCATION_ID,
                "capability": "route_proposal",
                "inputs": [world.demand_artifact.to_dict()],
                "resources": {"read_market_data": {"spread_bps": 12}},
                "as_of": T_SHADOW,
                "jurisdiction": "US",
            },
            expected_versions=(
                (SHADOW_INVOCATION_ID, 0),
                (INSTANCE_ID, current_extension_version(world, INSTANCE_ID)),
            ),
            requested_at=T_SHADOW,
        )
    )
    shadow_savings = world.runtime.invocation(
        SHADOW_INVOCATION_ID
    ).output_artifacts[0].payload_value()["cost_savings_minor"]
    if shadow_savings <= 0:
        raise CoreValidationError(
            "the shadow invocation produced no measurable output; the probe "
            "requires real shadowed activity"
        )
    world.runtime.submit(
        extension_command(
            world,
            command_id="cmd/ig004-measure-shadow",
            command_type="extension/measure",
            target_refs=(SHADOW_REMEASURE_ID,),
            payload={
                "contribution_id": SHADOW_REMEASURE_ID,
                "baseline": {
                    "extension_id": EXTENSION_ID,
                    "metric": "cost_savings_minor",
                    "value": 0,
                    "as_of": T_MEASURE,
                    "epistemic_type": "COUNTERFACTUAL",
                    "evidence_refs": ["counterfactual/ig004-default-route"],
                },
                "treatment": {
                    "extension_id": EXTENSION_ID,
                    "metric": "cost_savings_minor",
                    "value": contribution.treatment.value,
                    "as_of": T_MEASURE,
                    "epistemic_type": "SIMULATED",
                    "evidence_refs": [
                        "extension-invocation/ig004-treatment-1",
                        SHADOW_INVOCATION_ID,
                    ],
                },
            },
            expected_versions=((SHADOW_REMEASURE_ID, 0),),
            requested_at=T_MEASURE,
        )
    )
    shadow_remeasure = world.runtime.contribution(SHADOW_REMEASURE_ID)

    # 3. Cross-currency conservation through the merged money FX
    #    authority: the earned USD attribution converts to GHS with an
    #    exact residual identity (value is never created or destroyed).
    usd = get_currency("USD")
    ghs = get_currency("GHS")
    earnings = MoneyAmount(
        currency=usd, value=contribution.earnings.amount_minor, scale=usd.scale
    )
    rate = FxRate(
        source=usd,
        target=ghs,
        numerator=FX_USD_GHS_NUMERATOR,
        denominator=FX_USD_GHS_DENOMINATOR,
    )
    conversion = convert(rate, earnings, RoundingMode.FLOOR)
    scaled_numerator = (
        conversion.source.value
        * conversion.rate.numerator
        * 10 ** conversion.rate.target.scale
    )
    scaled_denominator = (
        10 ** conversion.source.scale * conversion.rate.denominator
    )
    fx_conservation = (
        scaled_numerator
        == conversion.target.value * scaled_denominator
        + conversion.residual_numerator
        and conversion.residual_denominator == scaled_denominator
    )
    if not fx_conservation:
        raise CoreValidationError(
            "the FX conversion does not conserve value through the money "
            "authority's exact residual identity"
        )

    return {
        "scenario_id": "ig004/contribution-integrity",
        "parity_verdict": verdict.verdict,
        "incremental_minor": contribution.incremental,
        "earnings_minor": contribution.earnings.amount_minor,
        "unverified_contribution_id": UNVERIFIED_CONTRIBUTION_ID,
        "unverified_verified": unverified.verified,
        "unverified_earnings_minor": unverified.earnings.amount_minor,
        "shadow_contribution_id": SHADOW_REMEASURE_ID,
        "shadow_savings_minor": shadow_savings,
        "shadow_earnings_delta_minor": (
            shadow_remeasure.earnings.amount_minor
            - contribution.earnings.amount_minor
        ),
        "shadow_applied_delta": (
            shadow_remeasure.applied_invocations - contribution.applied_invocations
        ),
        "fx_rate": rate.to_dict(),
        "fx_source_minor": earnings.value,
        "fx_target_minor": conversion.target.value,
        "fx_residual_numerator": conversion.residual_numerator,
        "fx_residual_denominator": conversion.residual_denominator,
        "fx_conservation": fx_conservation,
        "fx_conversion": conversion.to_dict(),
    }
