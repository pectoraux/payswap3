"""DOGFOOD-020: install a real extension in simulation, measure its
contribution against a counterfactual baseline, then shadow it.

The Work Order mandates this conformance experiment. It exercises the
PUBLIC contracts end to end through the real transition kernel:

1. **install** — a concrete in-repo route-proposal extension (a real
   deterministic handler implementing the typed artifact interfaces) is
   registered, sandbox-certified, reviewed, published, installed and
   activated in a ``SIMULATION`` environment;
2. **contribution** — three live invocations run against real demand
   artifacts; the treatment outcome is derived from the invocation
   outputs and measured against a ``COUNTERFACTUAL`` baseline (the
   default routing without the extension) through the kernel ``measure``
   command — verified incremental contribution, exact integer earnings;
3. **shadow** — the instance is switched into shadow mode (live
   observation, non-production effects); two further invocations are
   recorded with ``SHADOWED`` effect mode; re-measuring with the shadow
   invocations included in the treatment evidence changes NOTHING:
   shadow activity adds no earnings and no applied invocations.

Every instant is declared ``as_of`` data; the transcript is a pure
function of the declared inputs, so two clean processes produce
byte-identical output.
"""

from __future__ import annotations

from typing import Any

from src.core.envelope import Provenance
from src.core.serialization import canonical_sha256
from src.simulation import EnvironmentMode
from src.transition import Command, ExpectedVersion, Outcome

from .artifacts import ExtensionArtifact
from .contracts import (
    ExtensionArtifactKind,
    ExtensionCapability,
    ExtensionPermission,
    ExtensionLifecycleState,
    InvocationEffectMode,
    MonitoringLevel,
    PricingModel,
)
from .grants import CapabilityGrant
from .manifest import (
    ExtensionManifest,
    PricingSpec,
    ResourceRequirements,
    RiskControls,
    VerificationEvidence,
)
from .runtime import CodeRepository, SandboxContext
from .engine import ExtensionRuntime

# -- deterministic declared data ------------------------------------------

DOGFOOD_ENVIRONMENT = "env/dogfood-020-simulation"
DOGFOOD_DOMAIN = "domain/extensions-dogfood"
DOGFOOD_ACTOR = "principal/marketplace-operator"
DOGFOOD_CODE_HASH = "a" * 64

T0 = "2026-09-02T00:00:00Z"
T1 = "2026-09-02T00:01:00Z"
T2 = "2026-09-02T00:30:00Z"
T2B = "2026-09-02T00:31:00Z"
T3 = "2026-09-02T01:00:00Z"
T4 = "2026-09-02T06:00:00Z"
T_EXPIRY = "2026-09-03T00:00:00Z"

#: The REAL extension: a deterministic route-proposal provider. It reads
#: one declared demand signal and proposes a route whose cost savings are
#: exactly one twentieth of the corridor volume (integer arithmetic).
CORRIDOR_DEMANDS = (
    ("US->GH", 5_000_000),
    ("EU->KE", 4_000_000),
    ("US->NG", 6_000_000),
)


def _provenance() -> Provenance:
    return Provenance(
        issuer=DOGFOOD_ACTOR,
        source="extensions/dogfooding",
        recorded_at=T1,
    )


def route_proposal_handler(context: SandboxContext):
    """The in-repo route-proposal extension (the dogfooded artifact)."""
    demand = context.inputs[0]
    payload = demand.payload_value()
    savings = payload["volume_minor"] // 20
    return (
        ExtensionArtifact(
            artifact_id=f"extension-artifact/{context.invocation_id}/proposal",
            kind=ExtensionArtifactKind.ROUTE_PROPOSAL,
            schema_version=1,
            producer=context.extension_id,
            payload=(
                ("corridor", payload["corridor"]),
                ("cost_savings_minor", savings),
                ("quality_bps", 9000),
            ),
            provenance=_provenance(),
            expires_at=T_EXPIRY,
            confidence_bps=8500,
            dependencies=(demand.artifact_id,),
            risk_band="LOW",
        ),
    )


def _demand_artifact(index: int, corridor: str, volume_minor: int) -> ExtensionArtifact:
    return ExtensionArtifact(
        artifact_id=f"extension-artifact/dogfood-demand-{index}",
        kind=ExtensionArtifactKind.DEMAND_SIGNAL,
        schema_version=1,
        producer="extension/dogfood-demand-source",
        payload=(("corridor", corridor), ("volume_minor", volume_minor)),
        provenance=_provenance(),
        expires_at=T_EXPIRY,
        confidence_bps=9000,
        dependencies=(),
        risk_band="LOW",
    )


def _manifest() -> ExtensionManifest:
    return ExtensionManifest(
        extension_id="extension/dogfood-route",
        developer="principal/dogfood-developer",
        version="1.0.0",
        code_hash=DOGFOOD_CODE_HASH,
        capabilities_provided=(ExtensionCapability.ROUTE_PROPOSAL,),
        capabilities_required=(),
        permissions=(ExtensionPermission.READ_MARKET_DATA,),
        dependencies=(),
        inputs=(ExtensionArtifactKind.DEMAND_SIGNAL,),
        outputs=(ExtensionArtifactKind.ROUTE_PROPOSAL,),
        pricing=PricingSpec(
            model=PricingModel.REVENUE_SHARE,
            amount_minor=0,
            asset="USD",
            share_bps=1000,
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
            evidence_refs=("evidence/dogfood-audit",),
            review_digest="c" * 64,
        ),
        risk_controls=RiskControls(
            monitoring_level=MonitoringLevel.STANDARD,
            collateral=None,
            risk_limits=None,
        ),
    )


def _command(
    command_id: str,
    command_type: str,
    target_refs: tuple[str, ...],
    payload: dict[str, Any],
    *,
    expected_versions: tuple[tuple[str, int], ...] = (),
    requested_at: str = T2,
) -> Command:
    return Command.build(
        command_id=command_id,
        command_type=command_type,
        actor=DOGFOOD_ACTOR,
        authority_refs=("authority/ops",),
        target_refs=target_refs,
        payload=payload,
        environment_id=DOGFOOD_ENVIRONMENT,
        domain_id=DOGFOOD_DOMAIN,
        idempotency_key=f"key/{command_id}",
        nonce="1",
        requested_at=requested_at,
        expected_versions=tuple(
            ExpectedVersion(object_ref=ref, object_version=version)
            for ref, version in expected_versions
        ),
    )


def _current_version(runtime: ExtensionRuntime, object_ref: str) -> int:
    envelope = runtime.store.get(object_ref)
    return 0 if envelope is None else envelope.object_version


def _invoke(
    runtime: ExtensionRuntime,
    invocation_id: str,
    demand: ExtensionArtifact,
    *,
    requested_at: str = T2,
) -> Any:
    payload = {
        "invocation_id": invocation_id,
        "capability": "route_proposal",
        "inputs": [demand.to_dict()],
        "resources": {"read_market_data": {"spread_bps": 12}},
        "as_of": requested_at,
        "jurisdiction": "US",
    }
    target = (
        "extension-instance/dogfood-route@sim"
        if runtime.store.get("extension-instance/dogfood-route@sim") is not None
        and runtime.instance("extension-instance/dogfood-route@sim").state
        is ExtensionLifecycleState.ACTIVE
        else "extension/dogfood-route"
    )
    return runtime.submit(
        _command(
            f"cmd/{invocation_id}",
            "extension/invoke",
            (invocation_id,),
            payload,
            expected_versions=(
                (invocation_id, 0),
                (target, _current_version(runtime, target)),
            ),
            requested_at=requested_at,
        )
    )


def _measurement(extension_id: str, value: int, refs: tuple[str, ...]) -> dict[str, Any]:
    return {
        "extension_id": extension_id,
        "metric": "cost_savings_minor",
        "value": value,
        "as_of": T3,
        "epistemic_type": "SIMULATED",
        "evidence_refs": list(refs),
    }


def _baseline_measurement(extension_id: str) -> dict[str, Any]:
    return {
        "extension_id": extension_id,
        "metric": "cost_savings_minor",
        "value": 0,
        "as_of": T3,
        "epistemic_type": "COUNTERFACTUAL",
        "evidence_refs": ["counterfactual/default-route"],
    }


def build_transcript() -> tuple[str, str]:
    """Run the DOGFOOD-020 experiment; return (transcript, digest)."""
    repository = CodeRepository()
    repository.register(DOGFOOD_CODE_HASH, route_proposal_handler)
    runtime = ExtensionRuntime(
        environment_id=DOGFOOD_ENVIRONMENT,
        domain_id=DOGFOOD_DOMAIN,
        environment_mode=EnvironmentMode.SIMULATION,
        authorized_actors=frozenset({DOGFOOD_ACTOR}),
        code_repository=repository,
    )
    manifest = _manifest()
    checks: list[tuple[str, bool]] = []
    lines: list[str] = []
    lines.append(
        "DOGFOOD-020: install a real extension in simulation, measure "
        "contribution, then shadow it"
    )
    lines.append(
        f"environment: {DOGFOOD_ENVIRONMENT} mode={EnvironmentMode.SIMULATION.value} "
        f"protocol=v0.1"
    )

    # -- 1. register, sandbox-certify, review and publish -------------------
    submit_1 = runtime.submit(
        _command(
            "cmd/dogfood-register",
            "extension/register",
            (manifest.extension_id,),
            {"manifest": manifest.to_record_dict()},
            expected_versions=((manifest.extension_id, 0),),
            requested_at=T1,
        )
    )
    runtime.submit(
        _command(
            "cmd/dogfood-submit-1",
            "extension/submit",
            ("extension/dogfood-route",),
            {},
            expected_versions=(
                ("extension/dogfood-route", _current_version(runtime, "extension/dogfood-route")),
            ),
        )
    )
    sandbox_result = _invoke(
        runtime, "extension-invocation/dogfood-sandbox-1", _demand_artifact(1, *CORRIDOR_DEMANDS[0])
    )
    runtime.submit(
        _command(
            "cmd/dogfood-certify",
            "extension/certify",
            ("extension/dogfood-route",),
            {},
            expected_versions=(
                ("extension/dogfood-route", _current_version(runtime, "extension/dogfood-route")),
            ),
        )
    )
    runtime.submit(
        _command(
            "cmd/dogfood-submit-2",
            "extension/submit",
            ("extension/dogfood-route",),
            {},
            expected_versions=(
                ("extension/dogfood-route", _current_version(runtime, "extension/dogfood-route")),
            ),
        )
    )
    for suffix in ("approve-1", "approve-2"):
        runtime.submit(
            _command(
                f"cmd/dogfood-{suffix}",
                "extension/approve",
                ("extension/dogfood-route",),
                {},
                expected_versions=(
                    (
                        "extension/dogfood-route",
                        _current_version(runtime, "extension/dogfood-route"),
                    ),
                ),
            )
        )
    runtime.submit(
        _command(
            "cmd/dogfood-publish",
            "extension/publish",
            ("extension/dogfood-route",),
            {},
            expected_versions=(
                ("extension/dogfood-route", _current_version(runtime, "extension/dogfood-route")),
            ),
        )
    )
    checks.append(
        (
            "register accepted",
            submit_1.outcome is Outcome.ACCEPTED,
        )
    )
    checks.append(
        (
            "manifest published after sandbox certification",
            runtime.store.get("extension/dogfood-route").state == "PUBLISHED",
        )
    )
    checks.append(
        (
            "sandbox invocation completed",
            sandbox_result.outcome is Outcome.ACCEPTED
            and runtime.invocation(
                "extension-invocation/dogfood-sandbox-1"
            ).status
            == "COMPLETED",
        )
    )

    # -- 2. install and activate -------------------------------------------
    grant = {
        "grant_id": "extension-grant/dogfood-route",
        "capability": "route_proposal",
        "granted_by": DOGFOOD_ACTOR,
        "valid_from": T0,
        "valid_until": T4,
        "jurisdictions": ("US",),
        "budget": {
            "max_invocations": 5,
            "window_start": T0,
            "window_end": T4,
        },
    }
    instance_id = "extension-instance/dogfood-route@sim"
    install_result = runtime.submit(
        _command(
            "cmd/dogfood-install",
            "extension/install",
            (instance_id, grant["grant_id"]),
            {
                "instance_id": instance_id,
                "manifest_id": "extension/dogfood-route",
                "version": "1.0.0",
                "jurisdictions": ("US",),
                "grants": [grant],
            },
            expected_versions=((instance_id, 0), (grant["grant_id"], 0)),
        )
    )
    runtime.submit(
        _command(
            "cmd/dogfood-activate",
            "extension/activate",
            (instance_id,),
            {},
            expected_versions=((instance_id, _current_version(runtime, instance_id)),),
        )
    )
    checks.append(("install accepted", install_result.outcome is Outcome.ACCEPTED))
    checks.append(
        (
            "instance ACTIVE",
            runtime.instance(instance_id).state is ExtensionLifecycleState.ACTIVE,
        )
    )
    bound_grant: CapabilityGrant = runtime.grant("extension-grant/dogfood-route")
    checks.append(
        (
            "grant covers the route_proposal capability",
            bound_grant.capability is ExtensionCapability.ROUTE_PROPOSAL
            and bound_grant.budget.max_invocations == 5,
        )
    )
    lines.append(
        f"install: instance {instance_id} INSTALLED->ACTIVE grants=1 "
        f"capability={bound_grant.capability.value} "
        f"budget={bound_grant.budget.max_invocations}"
    )

    # -- 3. live treatment invocations --------------------------------------
    live_ids: list[str] = []
    live_savings = 0
    for index, (corridor, volume) in enumerate(CORRIDOR_DEMANDS, start=1):
        invocation_id = f"extension-invocation/dogfood-live-{index}"
        result = _invoke(
            runtime, invocation_id, _demand_artifact(index, corridor, volume)
        )
        checks.append(
            (
                f"live invocation {index} accepted",
                result.outcome is Outcome.ACCEPTED,
            )
        )
        invocation = runtime.invocation(invocation_id)
        checks.append(
            (
                f"live invocation {index} recorded (not shadowed)",
                invocation.effect_mode is InvocationEffectMode.RECORDED,
            )
        )
        savings = invocation.output_artifacts[0].payload_value()["cost_savings_minor"]
        live_savings += savings
        live_ids.append(invocation_id)
    lines.append(
        f"invocations: {len(live_ids)} recorded route-proposal invocations "
        f"cost_savings_minor={live_savings}"
    )

    # -- 4. measure contribution against the counterfactual baseline --------
    first_contribution_id = "extension-contribution/dogfood-live"
    measure_1 = runtime.submit(
        _command(
            "cmd/dogfood-measure-1",
            "extension/measure",
            (first_contribution_id,),
            {
                "contribution_id": first_contribution_id,
                "baseline": _baseline_measurement("extension/dogfood-route"),
                "treatment": _measurement(
                    "extension/dogfood-route", live_savings, tuple(live_ids)
                ),
            },
            expected_versions=((first_contribution_id, 0),),
            requested_at=T3,
        )
    )
    contribution = runtime.contribution(first_contribution_id)
    expected_earnings = (1000 * live_savings) // 10_000
    checks.append(("measure accepted", measure_1.outcome is Outcome.ACCEPTED))
    checks.append(
        (
            "contribution verified against the counterfactual baseline",
            contribution.verified and contribution.incremental == live_savings,
        )
    )
    checks.append(
        (
            "earnings use exact integer revenue share",
            contribution.earnings.amount_minor == expected_earnings,
        )
    )
    checks.append(
        (
            "applied invocations derive from recorded evidence",
            contribution.applied_invocations == 3,
        )
    )
    lines.append(
        f"contribution: {first_contribution_id} "
        f"incremental_minor={contribution.incremental} "
        f"verified={contribution.verified} "
        f"earnings_minor={contribution.earnings.amount_minor} "
        f"applied_invocations={contribution.applied_invocations} "
        f"resource_credits={contribution.resource_credits.credits}"
    )

    # -- 5. shadow the instance ----------------------------------------------
    runtime.submit(
        _command(
            "cmd/dogfood-shadow-on",
            "extension/shadow",
            (instance_id,),
            {"shadow": True},
            expected_versions=((instance_id, _current_version(runtime, instance_id)),),
            requested_at=T2B,
        )
    )
    checks.append(
        (
            "instance shadowed",
            runtime.instance(instance_id).shadow,
        )
    )
    lines.append(f"shadow: instance {instance_id} shadowed=True")
    shadow_ids: list[str] = []
    for index, (corridor, volume) in enumerate(CORRIDOR_DEMANDS[:2], start=1):
        invocation_id = f"extension-invocation/dogfood-shadow-{index}"
        result = _invoke(
            runtime,
            invocation_id,
            _demand_artifact(index + 10, corridor, volume),
            requested_at=T2B,
        )
        checks.append(
            (
                f"shadow invocation {index} accepted",
                result.outcome is Outcome.ACCEPTED,
            )
        )
        invocation = runtime.invocation(invocation_id)
        checks.append(
            (
                f"shadow invocation {index} is SHADOWED (non-production effects)",
                invocation.effect_mode is InvocationEffectMode.SHADOWED,
            )
        )
        shadow_ids.append(invocation_id)
    lines.append(
        f"shadow.invocations: {len(shadow_ids)} invocations recorded with "
        f"effect_mode={InvocationEffectMode.SHADOWED.value}"
    )

    # -- 6. re-measure with the shadow invocations included ------------------
    second_contribution_id = "extension-contribution/dogfood-shadow"
    measure_2 = runtime.submit(
        _command(
            "cmd/dogfood-measure-2",
            "extension/measure",
            (second_contribution_id,),
            {
                "contribution_id": second_contribution_id,
                "baseline": _baseline_measurement("extension/dogfood-route"),
                "treatment": _measurement(
                    "extension/dogfood-route",
                    live_savings,
                    tuple(live_ids) + tuple(shadow_ids),
                ),
            },
            expected_versions=((second_contribution_id, 0),),
            requested_at=T3,
        )
    )
    shadow_contribution = runtime.contribution(second_contribution_id)
    earnings_delta = (
        shadow_contribution.earnings.amount_minor - contribution.earnings.amount_minor
    )
    applied_delta = (
        shadow_contribution.applied_invocations - contribution.applied_invocations
    )
    checks.append(("shadow re-measure accepted", measure_2.outcome is Outcome.ACCEPTED))
    checks.append(
        (
            "shadow activity adds no earnings",
            earnings_delta == 0
            and shadow_contribution.earnings.amount_minor == expected_earnings,
        )
    )
    checks.append(
        (
            "shadow activity adds no applied invocations",
            applied_delta == 0 and shadow_contribution.applied_invocations == 3,
        )
    )
    lines.append(
        f"shadow.remeasure: {second_contribution_id} "
        f"incremental_minor={shadow_contribution.incremental} "
        f"verified={shadow_contribution.verified} "
        f"earnings_minor={shadow_contribution.earnings.amount_minor} "
        f"applied_invocations={shadow_contribution.applied_invocations}"
    )
    lines.append(f"shadow.earnings_delta_minor={earnings_delta}")
    lines.append(f"shadow.applied_invocations_delta={applied_delta}")

    # -- 7. journal reproducibility -------------------------------------------
    live_digest = runtime.domain_state_digest()
    rebuilt_digest = runtime.rebuild_from_journal()
    checks.append(
        (
            "domain projection rebuilds byte-identically from the journal",
            rebuilt_digest == live_digest,
        )
    )
    lines.append(f"journal: entries={len(runtime.engine.journal)}")
    lines.append(f"rebuild_digest={rebuilt_digest}")

    failed = [name for name, ok in checks if not ok]
    for name, ok in checks:
        lines.append(f"check: {'PASS' if ok else 'FAIL'} {name}")
    lines.append(f"checks: {len(checks) - len(failed)}/{len(checks)} PASS")
    lines.append(
        "DOGFOOD-020: "
        + ("PASS" if not failed else "FAIL " + ", ".join(failed))
    )
    transcript = "\n".join(lines) + "\n"
    return transcript, canonical_sha256(transcript)
