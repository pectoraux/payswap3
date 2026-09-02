"""DOGFOOD-019: one machine, many worlds — parity across environments.

Run in a clean process:

    python3 -m src.simulation.dogfooding

The dogfooding/conformance contract of WORK-019: run the SAME protocol
scenario (one intent create, one intent route consuming two rail world
observations, carrying one settlement effect intent) through the SAME
protocol binding in three environments — SIMULATION (simulated world),
SHADOW (live-style observations, no production effects) and a
PRODUCTION-compatible harness (live observations plus an explicit typed
effect authorization) — then:

* compare the canonical transitions: the parity projection and its
  digest must be byte-identical across the three environments, and the
  raw canonical journals must differ ONLY in the environment identity
  fields (proven with the canonical journal diff);
* prove only the effect policy differs: the same effect intent is
  RECORDED in simulation, SHADOWED in shadow and AUTHORIZED in
  production — same effect id, same payload digest — while the protocol
  state (object versions and states) stays identical;
* prove the production-compatible harness emits authorized typed
  records only: real execution lives outside this package, behind the
  authorization boundary (there is no execution path in this domain);
* prove the comparison is load-bearing with a control environment: the
  same scenario in a simulation whose world carries a different rail
  observation value must produce a DIFFERENT parity digest (business
  semantics respond to the world; parity is not vacuous).

Everything is explicit and deterministic: declared ``as_of`` instants,
scripted world observations, no wall-clock reads, no entropy sources.
"""

from __future__ import annotations

if __package__ in (None, ""):  # pragma: no cover - direct script execution
    import sys
    from pathlib import Path

    _REPOSITORY_ROOT = str(Path(__file__).resolve().parents[2])
    if _REPOSITORY_ROOT not in sys.path:
        sys.path.insert(0, _REPOSITORY_ROOT)
    __package__ = "src.simulation"  # noqa: A001

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.serialization import canonical_json, canonical_sha256
from src.transition import (
    AuthorizationDecision,
    Command,
    ExpectedVersion,
    TransitionApplication,
    payload_to_json_value,
)

from . import (
    MODE_EPISTEMIC_TYPES,
    EffectAuthorization,
    EffectIntent,
    EffectPolicy,
    EnvironmentMode,
    EnvironmentRuntime,
    EnvironmentSpec,
    EpistemicType,
    ScriptedWorld,
    StateNamespace,
    WorldObservation,
    canonical_journal_diff,
    parity_digest,
    parity_projection,
)
from .runtime import CommandRegistration, ProtocolBinding

ENV_SIMULATION = "env/dogfood-019-simulation"
ENV_SHADOW = "env/dogfood-019-shadow"
ENV_PRODUCTION = "env/dogfood-019-production"
ENV_CONTROL = "env/dogfood-019-control"
DOMAIN = "domain/payments-demo"

T0 = "2026-09-02T00:00:00Z"
T1 = "2026-09-02T00:01:00Z"
T2 = "2026-09-02T01:00:00Z"

INTENT_ID = "intent/dogfood-pay-1"
RAIL_UP_KEY = "rail/alpha-up"
RAIL_LATENCY_KEY = "rail/alpha-latency-ms"

CREATE_COMMAND_TYPE = "intent/create"
ROUTE_COMMAND_TYPE = "intent/route"
CREATE_EVENT_TYPE = "intent/created"
ROUTE_EVENT_TYPE = "intent/routed"

EFFECT_TYPE = "settlement/submit"
EFFECT_ID = "effect/submit-1"
EFFECT_IDEMPOTENCY_KEY = "effect-key-1"

AUTHORITY_CLASS = "A2"

#: The environment identity paths at which the raw journals are allowed
#: to differ — anything else is a business-semantics divergence.
EXPECTED_IDENTITY_DIFF = (
    "entry[0].event.environment_id",
    "entry[1].event.environment_id",
)


def _allow(command: Command, view) -> AuthorizationDecision:
    return AuthorizationDecision(granted=True, authority=AUTHORITY_CLASS, reason=None)


def _create_handler(command: Command, view, world) -> TransitionApplication:
    envelope = ObjectEnvelope(
        object_id=command.target_refs[0],
        object_type="payswap/intent/v1",
        object_version=1,
        environment_id=command.environment_id,
        domain_id=command.domain_id,
        schema_version=1,
        protocol_version="v0.1",
        state="CREATED",
        provenance=Provenance(
            issuer=command.actor,
            source="simulation/dogfood",
            recorded_at=command.requested_at,
        ),
        causation_id=command.command_id,
        correlation_id=command.correlation_id,
    ).with_integrity_hash()
    return TransitionApplication(
        resulting_envelopes=(envelope,),
        payload={"object_id": command.target_refs[0], "created": True},
    )


def _route_handler(command: Command, view, world) -> TransitionApplication:
    up = world.observe(RAIL_UP_KEY, command.requested_at)
    latency = world.observe(RAIL_LATENCY_KEY, command.requested_at)
    target = command.target_refs[0]
    current = view.get(target)
    if up.value is True and latency.value <= 200:
        rail = "alpha"
    else:
        rail = "beta"
    resulting = (current.next_version(state="ROUTED").with_integrity_hash(),)
    return TransitionApplication(
        resulting_envelopes=resulting,
        payload={"rail": rail, "latency_ms": latency.value, "rail_up": up.value},
    )


def make_binding() -> ProtocolBinding:
    return ProtocolBinding(
        binding_id="binding/dogfood-payments",
        protocol_version="v0.1",
        registrations=(
            CommandRegistration(
                command_type=CREATE_COMMAND_TYPE,
                event_type=CREATE_EVENT_TYPE,
                handler=_create_handler,
            ),
            CommandRegistration(
                command_type=ROUTE_COMMAND_TYPE,
                event_type=ROUTE_EVENT_TYPE,
                handler=_route_handler,
            ),
        ),
        authorization=_allow,
    )


def make_world(epistemic_type: EpistemicType, *, rail_up: bool) -> ScriptedWorld:
    return ScriptedWorld(
        observations=(
            WorldObservation(
                observation_key=RAIL_UP_KEY,
                epistemic_type=epistemic_type,
                as_of=T1,
                value=rail_up,
                source="world/dogfood",
            ),
            WorldObservation(
                observation_key=RAIL_LATENCY_KEY,
                epistemic_type=epistemic_type,
                as_of=T1,
                value=150,
                source="world/dogfood",
            ),
        ),
        epistemic_type=epistemic_type,
    )


def make_create_command(environment_id: str) -> Command:
    return Command.build(
        command_id="cmd/create-1",
        command_type=CREATE_COMMAND_TYPE,
        actor="principal/merchant",
        authority_refs=("authority/ops",),
        target_refs=(INTENT_ID,),
        payload={"origin": "dogfood-019"},
        environment_id=environment_id,
        domain_id=DOMAIN,
        expected_versions=(ExpectedVersion(object_ref=INTENT_ID, object_version=0),),
        idempotency_key="key/create-1",
        nonce="1",
        requested_at=T0,
        correlation_id="corr/dogfood-019",
    )


def make_route_command(environment_id: str) -> Command:
    return Command.build(
        command_id="cmd/route-1",
        command_type=ROUTE_COMMAND_TYPE,
        actor="principal/merchant",
        authority_refs=("authority/ops",),
        target_refs=(INTENT_ID,),
        payload={"route": True},
        environment_id=environment_id,
        domain_id=DOMAIN,
        expected_versions=(ExpectedVersion(object_ref=INTENT_ID, object_version=1),),
        idempotency_key="key/route-1",
        nonce="1",
        requested_at=T1,
        correlation_id="corr/dogfood-019",
    )


def make_effect_intent() -> EffectIntent:
    return EffectIntent(
        effect_id=EFFECT_ID,
        effect_type=EFFECT_TYPE,
        payload={"rail": "alpha"},
        idempotency_key=EFFECT_IDEMPOTENCY_KEY,
        requested_at=T1,
    )


def make_authorization() -> EffectAuthorization:
    return EffectAuthorization(
        authorizer="principal/ops",
        authority_class=AUTHORITY_CLASS,
        authorized_types=frozenset({EFFECT_TYPE}),
        valid_from=T0,
        valid_until=T2,
    )


def run_scenario(
    *,
    environment_id: str,
    mode: EnvironmentMode,
    rail_up: bool,
    effect_policy: EffectPolicy | None = None,
) -> EnvironmentRuntime:
    """Drive the same protocol scenario through one environment."""
    runtime = EnvironmentRuntime(
        spec=EnvironmentSpec(
            environment_id=environment_id,
            mode=mode,
            domain_id=DOMAIN,
            as_of=T0,
        ),
        binding=make_binding(),
        world=make_world(mode_epistemic(mode), rail_up=rail_up),
        effect_policy=effect_policy,
    )
    runtime.submit(make_create_command(environment_id))
    runtime.submit(
        make_route_command(environment_id),
        effect_intents=(make_effect_intent(),),
    )
    return runtime


def mode_epistemic(mode: EnvironmentMode) -> EpistemicType:
    return MODE_EPISTEMIC_TYPES[mode]


def build_transcript() -> tuple[str, str]:
    """Build the deterministic DOGFOOD-019 transcript and its digest."""
    simulation = run_scenario(
        environment_id=ENV_SIMULATION, mode=EnvironmentMode.SIMULATION, rail_up=True
    )
    shadow = run_scenario(
        environment_id=ENV_SHADOW, mode=EnvironmentMode.SHADOW, rail_up=True
    )
    production = run_scenario(
        environment_id=ENV_PRODUCTION,
        mode=EnvironmentMode.PRODUCTION,
        rail_up=True,
        effect_policy=EffectPolicy(
            mode=EnvironmentMode.PRODUCTION, authorization=make_authorization()
        ),
    )
    control = run_scenario(
        environment_id=ENV_CONTROL, mode=EnvironmentMode.SIMULATION, rail_up=False
    )

    # Canonical transition comparison: identical parity projections across
    # the three environments; the raw journals differ only in identity.
    simulation_parity = parity_digest(simulation.journal)
    shadow_parity = parity_digest(shadow.journal)
    production_parity = parity_digest(production.journal)
    parity_equal = (
        simulation_parity == shadow_parity == production_parity
        and parity_projection(simulation.journal)
        == parity_projection(shadow.journal)
        == parity_projection(production.journal)
    )
    diff_shadow = canonical_journal_diff(simulation.journal, shadow.journal)
    diff_production = canonical_journal_diff(simulation.journal, production.journal)
    only_identity = (
        diff_shadow == EXPECTED_IDENTITY_DIFF
        and diff_production == EXPECTED_IDENTITY_DIFF
    )

    # Protocol state is identical across environments (modulo identity).
    def protocol_view(runtime: EnvironmentRuntime) -> list[dict]:
        return [
            {
                "object_id": envelope.object_id,
                "object_version": envelope.object_version,
                "state": envelope.state,
            }
            for envelope in runtime.namespace_state(StateNamespace.PROTOCOL)
        ]

    states_identical = (
        protocol_view(simulation) == protocol_view(shadow) == protocol_view(production)
    )

    # Only the effect policy differs.
    simulation_decision = simulation.effects[0].decision.value
    shadow_decision = shadow.effects[0].decision.value
    production_decision = production.effects[0].decision.value
    effect_ids_identical = (
        [record.effect_id for record in simulation.effects]
        == [record.effect_id for record in shadow.effects]
        == [record.effect_id for record in production.effects]
    )
    production_record = production.effects[0]
    authorized_record_only = (
        production_decision == "authorized"
        and production_record.authorization_digest is not None
        and len(production.effects) == 1
    )
    decisions_as_expected = (
        simulation_decision == "recorded"
        and shadow_decision == "shadowed"
        and production_decision == "authorized"
    )

    # The comparison is load-bearing: a different world value must change
    # the canonical transitions (business semantics respond to the world).
    control_parity = parity_digest(control.journal)
    control_diverges = control_parity != simulation_parity
    control_rail = payload_to_json_value(control.journal[1].payload)["rail"]

    def route_payload(runtime: EnvironmentRuntime) -> str:
        return canonical_json(payload_to_json_value(runtime.journal[1].payload))

    lines = [
        "DOGFOOD-019: one machine, many worlds — parity across simulation, "
        "shadow and production",
        "binding=binding/dogfood-payments protocol=v0.1",
        "scenario=intent create + intent route (2 rail world observations) "
        "carrying one settlement/submit effect intent",
        f"world.values=rail_up=true latency_ms=150 as_of={T1}",
        "modes=simulation:SIMULATED shadow:OBSERVED production:OBSERVED",
        f"parity.simulation={simulation_parity}",
        f"parity.shadow={shadow_parity}",
        f"parity.production={production_parity}",
        f"parity.equal_across_environments={parity_equal}",
        "diff.simulation_vs_shadow=" + ",".join(diff_shadow),
        "diff.simulation_vs_production=" + ",".join(diff_production),
        f"diff.only_environment_identity={only_identity}",
        f"states.protocol_view.identical={states_identical}",
        f"transitions.count={len(simulation.transitions)}",
        f"route.payload={route_payload(simulation)}",
        "route.payload.identical_across_environments="
        f"{route_payload(simulation) == route_payload(shadow) == route_payload(production)}",
        f"effects.simulation.decision={simulation_decision}",
        f"effects.shadow.decision={shadow_decision}",
        f"effects.production.decision={production_decision}",
        f"effects.ids={simulation.effects[0].effect_id}",
        f"effects.ids.identical={effect_ids_identical}",
        f"effects.production.authorization_digest_present="
        f"{production_record.authorization_digest is not None}",
        "effects.production.authorized_record_only="
        f"{authorized_record_only and decisions_as_expected}",
        "production.execution_path_in_package=False",
        f"control.world.rail_up=false control.route={control_rail}",
        f"control.parity={control_parity}",
        f"control.diverges={control_diverges}",
    ]
    passed = (
        parity_equal
        and only_identity
        and states_identical
        and decisions_as_expected
        and effect_ids_identical
        and authorized_record_only
        and control_diverges
        and control_rail == "beta"
    )
    lines.append(f"DOGFOOD-019: {'PASS' if passed else 'FAIL'}")
    transcript = "\n".join(lines)
    digest = canonical_sha256({"transcript": transcript})
    return transcript, digest


def main() -> str:
    """Run DOGFOOD-019, print the transcript and return its digest."""
    transcript, digest = build_transcript()
    print(transcript)
    print(f"digest={digest}")
    return digest


if __name__ == "__main__":  # pragma: no cover - manual conformance run
    main()
