"""WORK-019 contract and discrimination suite (red-first).

This suite was authored BEFORE the implementation and captures the frozen
contract of the simulation environment runtime domain:

- the frozen v0.1 ``simulation.md`` environment modes
  ``SIMULATION/REPLAY/FORECAST/COUNTERFACTUAL/SHADOW/PRODUCTION`` as one
  runtime abstraction over the REAL transition kernel
  (:class:`src.transition.TransitionEngine` — never a second state
  machine), with the parity invariant: identical protocol transitions
  across environments given the same protocol version, policy, initial
  state, inputs and world observations;
- separate state namespaces for protocol, value, trust, economic and
  dependency state with fail-closed classification, provisioning
  contamination checks and per-namespace digests;
- the deterministic world adapter boundary: explicit ``as_of``/clock
  values, no wall-clock reads, no entropy, epistemic typing reused from
  the frozen ``src.evidence`` vocabulary (``OBSERVED``/``ESTIMATED``/
  ``PREDICTED``/``SIMULATED``/``COUNTERFACTUAL``), and mode/epistemic
  confusion failing closed;
- the effect policy as the ONLY difference between environments:
  simulated/shadow environments record effects, production requires an
  explicit typed authorization and still only emits authorized effect
  records — no out-of-environment execution path exists in this package;
- snapshots and sealed checkpoints with content digests, checkpoint
  chains, deterministic restore (cross-environment, cross-mode, binding
  mismatch and tamper all fail closed) and replay with per-entry
  divergence detection;
- forecast/counterfactual state branching from snapshots (branching into
  production is refused — simulation state is never copied into
  production financial state) and the promotion chain
  simulation → evidence → production decision → fresh validation →
  production authorization with no state-copy path;
- the import boundary: domain modules import only the stdlib, the
  canonical core and the declared dependency domains actually consumed
  (``src.transition``, ``src.evidence``) — never unmerged siblings.
"""

from __future__ import annotations

import ast
import json
import sys
import unittest
from pathlib import Path

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256

from src.transition import (
    AuthorizationDecision,
    Command,
    ExpectedVersion,
    Outcome,
    PROTOCOL_VERSION,
    TransitionApplication,
    TransitionResult,
    payload_to_json_value,
)

from src.evidence.contracts import EpistemicType as EvidenceEpistemicType

from src.simulation import (
    SIMULATION_API_VERSION,
    SIMULATION_CHECKPOINT_OBJECT_TYPE,
    SIMULATION_COMMANDS,
    SIMULATION_EVENT_NAMESPACE,
    SIMULATION_OBJECT_TYPE,
    SIMULATION_PROTOCOL_VERSION,
    SIMULATION_RESULT_OBJECT_TYPE,
    SIMULATION_RUN_STATES,
    SIMULATION_SCHEMA_VERSION,
    SIMULATION_TERMINAL_STATES,
    DEFAULT_NAMESPACE_RULES,
    MODE_EPISTEMIC_TYPES,
    CommandRegistration,
    EffectAuthorization,
    EffectDecision,
    EffectIntent,
    EffectPolicy,
    EffectRecord,
    EnvironmentMode,
    EnvironmentRuntime,
    EnvironmentSnapshot,
    EnvironmentSpec,
    EnvironmentTransition,
    FaultKind,
    ForecastError,
    FreshValidation,
    NamespaceRule,
    NamespaceRules,
    PromotionAuthorization,
    PromotionRequest,
    PromotionVerdict,
    ReplayJournal,
    ReplayReport,
    ScriptedWorld,
    SimulationCheckpoint,
    SimulationResult,
    SimulationRunState,
    StateNamespace,
    ValidationVerdict,
    WorldAdapter,
    WorldObservation,
    branch,
    branch_from,
    canonical_journal_diff,
    decide_promotion_authorization,
    forecast_errors,
    parity_digest,
    parity_projection,
    perform_fresh_validation,
    replay,
    request_promotion,
    CoreValidationError as SimulationCoreError,
    EpistemicType,
)

ENV_SIM = "env/parity-simulation"
ENV_SHADOW = "env/parity-shadow"
ENV_PROD = "env/parity-production"
ENV_REPLAY = "env/parity-replay"
ENV_CF = "env/counterfactual-branch"
ENV_FORECAST = "env/forecast-branch"
ENV_OTHER = "env/somewhere-else"
DOMAIN = "domain/payments"

CREATE_AT = "2026-09-02T00:00:00Z"
ROUTE_AT = "2026-09-02T00:01:00Z"
STEP3_AT = "2026-09-02T00:02:00Z"
LATER_AT = "2026-09-02T00:10:00Z"
MUCH_LATER_AT = "2026-09-02T01:00:00Z"

INTENT_ID = "intent/pay-1"
HOLD_ID = "value/hold-1"

CREATE_COMMAND_TYPE = "intent/create"
ROUTE_COMMAND_TYPE = "intent/route"
HOLD_COMMAND_TYPE = "value/hold"
CREATE_EVENT_TYPE = "intent/created"
ROUTE_EVENT_TYPE = "intent/routed"
HOLD_EVENT_TYPE = "reservation/held"

RAIL_UP_KEY = "rail/alpha-up"
RAIL_LATENCY_KEY = "rail/alpha-latency-ms"

EFFECT_TYPE = "settlement/submit"
AUTHORITY_CLASS = "A2"

DOMAIN_PACKAGE = Path(__file__).parent
DOMAIN_SOURCES = sorted(
    source
    for source in DOMAIN_PACKAGE.glob("*.py")
    if source.name != "test_simulation.py"
)
ALLOWED_SRC_DOMAINS = frozenset({"core", "transition", "evidence"})
FORBIDDEN_SRC_DOMAINS = frozenset(
    {
        "market",
        "intent",
        "money",
        "trust",
        "interoperability",
        "liquidity",
        "safety",
        "reservation",
        "value",
        "capability",
    }
)
STDLIB_ROOTS = frozenset(sys.stdlib_module_names)


# ---------------------------------------------------------------------------
# Fixtures: one real protocol scenario driven through the real kernel.
# ---------------------------------------------------------------------------


def prov(source: str = "simulation/test") -> Provenance:
    return Provenance(
        issuer="principal/simulation-operator",
        source=source,
        recorded_at=CREATE_AT,
        evidence_refs=("evidence/work-019",),
    )


def make_envelope(
    object_id: str,
    state: str,
    environment_id: str,
    *,
    version: int = 1,
    previous_version: int | None = None,
    object_type: str = "payswap/intent/v1",
) -> ObjectEnvelope:
    return ObjectEnvelope(
        object_id=object_id,
        object_type=object_type,
        object_version=version,
        environment_id=environment_id,
        domain_id=DOMAIN,
        schema_version=1,
        protocol_version=PROTOCOL_VERSION,
        state=state,
        provenance=prov(),
        causation_id=None,
        correlation_id=None,
        previous_version=previous_version,
    ).with_integrity_hash()


def _allow(command: Command, view) -> AuthorizationDecision:
    return AuthorizationDecision(granted=True, authority=AUTHORITY_CLASS, reason=None)


def _deny(command: Command, view) -> AuthorizationDecision:
    return AuthorizationDecision(
        granted=False, authority=None, reason="authorization denied by fixture policy"
    )


def _create_handler(command: Command, view, world) -> TransitionApplication:
    target = command.target_refs[0]
    envelope = ObjectEnvelope(
        object_id=target,
        object_type="payswap/intent/v1",
        object_version=1,
        environment_id=command.environment_id,
        domain_id=command.domain_id,
        schema_version=1,
        protocol_version=PROTOCOL_VERSION,
        state="CREATED",
        provenance=Provenance(
            issuer=command.actor,
            source="simulation/test",
            recorded_at=command.requested_at,
        ),
        causation_id=command.command_id,
        correlation_id=command.correlation_id,
    ).with_integrity_hash()
    return TransitionApplication(
        resulting_envelopes=(envelope,),
        payload={"object_id": target, "created": True},
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
    resulting = (
        current.next_version(state="ROUTED").with_integrity_hash(),
    )
    return TransitionApplication(
        resulting_envelopes=resulting,
        payload={"rail": rail, "latency_ms": latency.value, "rail_up": up.value},
    )


def _settle_handler(command: Command, view, world) -> TransitionApplication:
    target = command.target_refs[0]
    current = view.get(target)
    resulting = (
        current.next_version(state="SETTLED").with_integrity_hash(),
    )
    return TransitionApplication(
        resulting_envelopes=resulting,
        payload={"object_id": target, "settled": True},
    )


def _hold_handler(command: Command, view, world) -> TransitionApplication:
    target = command.target_refs[0]
    current = view.get(target)
    resulting = (
        current.next_version(state="HELD").with_integrity_hash(),
    )
    return TransitionApplication(
        resulting_envelopes=resulting,
        payload={"object_id": target, "held": True},
    )


def make_binding(
    *,
    authorization=_allow,
    binding_id: str = "binding/payments-demo",
) -> object:
    from src.simulation import ProtocolBinding

    return ProtocolBinding(
        binding_id=binding_id,
        protocol_version=PROTOCOL_VERSION,
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
            CommandRegistration(
                command_type="intent/settle",
                event_type="intent/settled",
                handler=_settle_handler,
            ),
            CommandRegistration(
                command_type=HOLD_COMMAND_TYPE,
                event_type=HOLD_EVENT_TYPE,
                handler=_hold_handler,
            ),
        ),
        authorization=authorization,
    )


def make_world(
    epistemic_type: EpistemicType,
    *,
    rail_up: bool = True,
    latency: int = 150,
    at: str = ROUTE_AT,
) -> ScriptedWorld:
    return ScriptedWorld(
        observations=(
            WorldObservation(
                observation_key=RAIL_UP_KEY,
                epistemic_type=epistemic_type,
                as_of=at,
                value=rail_up,
                source="world/scripted",
            ),
            WorldObservation(
                observation_key=RAIL_LATENCY_KEY,
                epistemic_type=epistemic_type,
                as_of=at,
                value=latency,
                source="world/scripted",
            ),
        ),
        epistemic_type=epistemic_type,
    )


def make_spec(
    environment_id: str = ENV_SIM,
    mode: EnvironmentMode = EnvironmentMode.SIMULATION,
) -> EnvironmentSpec:
    return EnvironmentSpec(
        environment_id=environment_id,
        mode=mode,
        domain_id=DOMAIN,
        as_of=CREATE_AT,
    )


def make_create_command(
    environment_id: str = ENV_SIM,
    *,
    command_id: str = "cmd/create-1",
    at: str = CREATE_AT,
) -> Command:
    return Command.build(
        command_id=command_id,
        command_type=CREATE_COMMAND_TYPE,
        actor="principal/merchant",
        authority_refs=("authority/ops",),
        target_refs=(INTENT_ID,),
        payload={"origin": "work-019-test"},
        environment_id=environment_id,
        domain_id=DOMAIN,
        expected_versions=(ExpectedVersion(object_ref=INTENT_ID, object_version=0),),
        idempotency_key="key/create-1",
        nonce="1",
        requested_at=at,
        correlation_id="corr/work-019",
    )


def make_route_command(
    environment_id: str = ENV_SIM,
    *,
    command_id: str = "cmd/route-1",
    at: str = ROUTE_AT,
    expected_version: int = 1,
    target: str = INTENT_ID,
    idempotency_key: str = "key/route-1",
) -> Command:
    return Command.build(
        command_id=command_id,
        command_type=ROUTE_COMMAND_TYPE,
        actor="principal/merchant",
        authority_refs=("authority/ops",),
        target_refs=(target,),
        payload={"route": True},
        environment_id=environment_id,
        domain_id=DOMAIN,
        expected_versions=(
            ExpectedVersion(object_ref=target, object_version=expected_version),
        ),
        idempotency_key=idempotency_key,
        nonce="1",
        requested_at=at,
        correlation_id="corr/work-019",
    )


def make_settle_command(
    environment_id: str = ENV_SIM,
    *,
    command_id: str = "cmd/settle-1",
    at: str = STEP3_AT,
    expected_version: int = 2,
) -> Command:
    return Command.build(
        command_id=command_id,
        command_type="intent/settle",
        actor="principal/merchant",
        authority_refs=("authority/ops",),
        target_refs=(INTENT_ID,),
        payload={"settle": True},
        environment_id=environment_id,
        domain_id=DOMAIN,
        expected_versions=(
            ExpectedVersion(object_ref=INTENT_ID, object_version=expected_version),
        ),
        idempotency_key="key/settle-1",
        nonce="1",
        requested_at=at,
        correlation_id="corr/work-019",
    )


def make_hold_command(
    environment_id: str = ENV_SIM,
    *,
    command_id: str = "cmd/hold-1",
    at: str = ROUTE_AT,
    expected_version: int = 1,
) -> Command:
    return Command.build(
        command_id=command_id,
        command_type=HOLD_COMMAND_TYPE,
        actor="principal/treasury",
        authority_refs=("authority/ops",),
        target_refs=(HOLD_ID,),
        payload={"hold": True},
        environment_id=environment_id,
        domain_id=DOMAIN,
        expected_versions=(
            ExpectedVersion(object_ref=HOLD_ID, object_version=expected_version),
        ),
        idempotency_key="key/hold-1",
        nonce="1",
        requested_at=at,
        correlation_id="corr/work-019",
    )


def make_effect_intent(
    *,
    effect_id: str = "effect/submit-1",
    effect_type: str = EFFECT_TYPE,
    requested_at: str = ROUTE_AT,
    payload: dict | None = None,
    idempotency_key: str = "effect-key-1",
) -> EffectIntent:
    return EffectIntent(
        effect_id=effect_id,
        effect_type=effect_type,
        payload=payload if payload is not None else {"rail": "alpha"},
        idempotency_key=idempotency_key,
        requested_at=requested_at,
    )


def make_runtime(
    *,
    environment_id: str = ENV_SIM,
    mode: EnvironmentMode = EnvironmentMode.SIMULATION,
    world: ScriptedWorld | None = None,
    binding=None,
    initial_state: dict | None = None,
    effect_policy: EffectPolicy | None = None,
) -> EnvironmentRuntime:
    if world is None:
        world = make_world(MODE_EPISTEMIC_TYPES[mode])
    return EnvironmentRuntime(
        spec=make_spec(environment_id, mode),
        binding=binding if binding is not None else make_binding(),
        world=world,
        initial_state=initial_state if initial_state is not None else {},
        effect_policy=effect_policy,
    )


def run_parity_scenario(
    *,
    mode: EnvironmentMode,
    environment_id: str,
    effect_policy: EffectPolicy | None = None,
    authorization: EffectAuthorization | None = None,
) -> EnvironmentRuntime:
    world = make_world(MODE_EPISTEMIC_TYPES[mode])
    policy = effect_policy
    if policy is None and authorization is not None:
        policy = EffectPolicy(mode=mode, authorization=authorization)
    runtime = make_runtime(
        environment_id=environment_id,
        mode=mode,
        world=world,
        effect_policy=policy,
    )
    runtime.submit(make_create_command(environment_id))
    runtime.submit(
        make_route_command(environment_id),
        effect_intents=(make_effect_intent(),),
    )
    return runtime


def make_authorization(
    *,
    authorized_types: frozenset[str] = frozenset({EFFECT_TYPE}),
    valid_from: str = CREATE_AT,
    valid_until: str = MUCH_LATER_AT,
) -> EffectAuthorization:
    return EffectAuthorization(
        authorizer="principal/ops",
        authority_class=AUTHORITY_CLASS,
        authorized_types=authorized_types,
        valid_from=valid_from,
        valid_until=valid_until,
    )


# ---------------------------------------------------------------------------
# 1. Static boundary contracts and the import boundary.
# ---------------------------------------------------------------------------


class BoundaryContractTests(unittest.TestCase):
    """Typed, versioned public boundary and frozen vocabularies."""

    def test_api_versions_are_exposed(self) -> None:
        self.assertEqual(SIMULATION_API_VERSION, "v0.1")
        self.assertEqual(SIMULATION_PROTOCOL_VERSION, PROTOCOL_VERSION)
        self.assertEqual(SIMULATION_PROTOCOL_VERSION, "v0.1")
        self.assertEqual(SIMULATION_SCHEMA_VERSION, 1)

    def test_object_types_match_the_frozen_registry(self) -> None:
        registry = json.loads(
            (Path(__file__).parents[2] / "spec" / "registry" / "protocol-registry.json")
            .read_text(encoding="utf-8")
        )
        object_types = registry["registry"]["objectTypes"]
        namespaces = registry["registry"]["eventNamespaces"]
        self.assertIn(SIMULATION_OBJECT_TYPE, object_types)
        self.assertEqual(SIMULATION_OBJECT_TYPE, "payswap/simulation/v1")
        self.assertIn(SIMULATION_EVENT_NAMESPACE, namespaces)
        self.assertEqual(SIMULATION_EVENT_NAMESPACE, "simulation")
        self.assertEqual(SIMULATION_CHECKPOINT_OBJECT_TYPE, "simulation/checkpoint/v1")
        self.assertEqual(SIMULATION_RESULT_OBJECT_TYPE, "simulation/result/v1")

    def test_mode_vocabulary_is_the_frozen_six(self) -> None:
        self.assertEqual(
            {mode.value for mode in EnvironmentMode},
            {
                "simulation",
                "replay",
                "forecast",
                "counterfactual",
                "shadow",
                "production",
            },
        )

    def test_unknown_mode_fails_closed(self) -> None:
        with self.assertRaises(CoreValidationError):
            EnvironmentMode.parse("staging")
        with self.assertRaises(CoreValidationError):
            EnvironmentSpec(
                environment_id=ENV_SIM,
                mode="simulation",
                domain_id=DOMAIN,
                as_of=CREATE_AT,
            )

    def test_namespace_vocabulary_is_the_frozen_five(self) -> None:
        self.assertEqual(
            {namespace.value for namespace in StateNamespace},
            {"protocol", "value", "trust", "economic", "dependency"},
        )

    def test_simulation_commands_match_the_frozen_family(self) -> None:
        self.assertEqual(
            SIMULATION_COMMANDS,
            frozenset(
                {
                    "simulation/create",
                    "simulation/initialize",
                    "simulation/run",
                    "simulation/pause",
                    "simulation/resume",
                    "simulation/checkpoint",
                    "simulation/step",
                    "simulation/inject-fault",
                    "simulation/branch",
                    "simulation/complete",
                    "simulation/fail",
                    "simulation/cancel",
                    "simulation/replay",
                }
            ),
        )

    def test_run_state_vocabulary(self) -> None:
        self.assertEqual(
            SIMULATION_RUN_STATES,
            {"RUNNING", "PAUSED", "COMPLETED", "FAILED", "CANCELLED"},
        )
        self.assertEqual(
            SIMULATION_TERMINAL_STATES, {"COMPLETED", "FAILED", "CANCELLED"}
        )
        self.assertEqual(SimulationRunState.RUNNING.value, "RUNNING")

    def test_mode_epistemic_binding_is_frozen(self) -> None:
        self.assertEqual(set(MODE_EPISTEMIC_TYPES), set(EnvironmentMode))
        self.assertIs(
            MODE_EPISTEMIC_TYPES[EnvironmentMode.SIMULATION], EpistemicType.SIMULATED
        )
        self.assertIs(MODE_EPISTEMIC_TYPES[EnvironmentMode.REPLAY], EpistemicType.OBSERVED)
        self.assertIs(
            MODE_EPISTEMIC_TYPES[EnvironmentMode.FORECAST], EpistemicType.PREDICTED
        )
        self.assertIs(
            MODE_EPISTEMIC_TYPES[EnvironmentMode.COUNTERFACTUAL],
            EpistemicType.COUNTERFACTUAL,
        )
        self.assertIs(MODE_EPISTEMIC_TYPES[EnvironmentMode.SHADOW], EpistemicType.OBSERVED)
        self.assertIs(
            MODE_EPISTEMIC_TYPES[EnvironmentMode.PRODUCTION], EpistemicType.OBSERVED
        )

    def test_epistemic_vocabulary_is_reused_from_evidence(self) -> None:
        self.assertIs(EpistemicType, EvidenceEpistemicType)
        self.assertIs(SimulationCoreError, CoreValidationError)

    def test_domain_modules_import_only_allowed_domains(self) -> None:
        for source in DOMAIN_SOURCES:
            tree = ast.parse(source.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                modules: list[str] = []
                if isinstance(node, ast.Import):
                    modules = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    if node.level == 0 and node.module:
                        modules = [node.module]
                    elif node.level > 0 and node.module:
                        prefix = ("src", "simulation")[: 2 - (node.level - 1)]
                        modules = [".".join((*prefix, *node.module.split(".")))]
                for module in modules:
                    if module == "src" or module.startswith("src."):
                        domain = module.split(".")[1] if module != "src" else "src"
                        self.assertIn(
                            domain,
                            ALLOWED_SRC_DOMAINS | {"simulation", "src"},
                            f"{source.name} imports forbidden module {module!r}",
                        )
                        self.assertNotIn(
                            domain,
                            FORBIDDEN_SRC_DOMAINS,
                            f"{source.name} imports unmerged/undeclared sibling {module!r}",
                        )
                    else:
                        root = module.split(".")[0]
                        self.assertIn(
                            root,
                            STDLIB_ROOTS | {"__future__"},
                            f"{source.name} imports non-stdlib module {module!r}",
                        )

    def test_declared_dependency_domains_are_actually_consumed(self) -> None:
        consumed: set[str] = set()
        for source in DOMAIN_SOURCES:
            tree = ast.parse(source.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    if node.level == 0 and node.module and node.module.startswith("src."):
                        consumed.add(node.module.split(".")[1])
                    elif node.level > 1 and node.module:
                        consumed.add(node.module.split(".")[0])
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.startswith("src."):
                            consumed.add(alias.name.split(".")[1])
        self.assertEqual(consumed, ALLOWED_SRC_DOMAINS)

    def test_domain_code_has_no_wall_clock_or_entropy(self) -> None:
        for source in DOMAIN_SOURCES:
            text = source.read_text(encoding="utf-8")
            for forbidden in (
                "time.time",
                "time.monotonic",
                "datetime.now",
                "utcnow",
                "random",
                "uuid",
                "secrets",
                "time.sleep",
            ):
                self.assertNotIn(
                    forbidden, text, f"{source.name} references {forbidden}"
                )

    def test_error_authority_is_core(self) -> None:
        with self.assertRaises(CoreValidationError):
            EnvironmentMode.parse("nope")


# ---------------------------------------------------------------------------
# 2. State namespaces.
# ---------------------------------------------------------------------------


class NamespaceRuleTests(unittest.TestCase):
    """Namespace classification rules and fail-closed behavior."""

    def test_default_rules_cover_all_five_namespaces(self) -> None:
        covered = {rule.namespace for rule in DEFAULT_NAMESPACE_RULES.rules}
        self.assertEqual(covered, set(StateNamespace))

    def test_default_rules_classify_representative_ids(self) -> None:
        self.assertEqual(
            DEFAULT_NAMESPACE_RULES.classify("intent/pay-1"),
            StateNamespace.PROTOCOL,
        )
        self.assertEqual(
            DEFAULT_NAMESPACE_RULES.classify("value/hold-1"), StateNamespace.VALUE
        )
        self.assertEqual(
            DEFAULT_NAMESPACE_RULES.classify("trust/principal-1"), StateNamespace.TRUST
        )
        self.assertEqual(
            DEFAULT_NAMESPACE_RULES.classify("economic/fee-1"),
            StateNamespace.ECONOMIC,
        )
        self.assertEqual(
            DEFAULT_NAMESPACE_RULES.classify("dependency/extension-1"),
            StateNamespace.DEPENDENCY,
        )

    def test_unclassified_object_id_fails_closed(self) -> None:
        with self.assertRaises(CoreValidationError):
            DEFAULT_NAMESPACE_RULES.classify("mystery/object-1")

    def test_rules_require_all_five_namespaces(self) -> None:
        with self.assertRaises(CoreValidationError):
            NamespaceRules(
                (
                    NamespaceRule("intent/", StateNamespace.PROTOCOL),
                    NamespaceRule("value/", StateNamespace.VALUE),
                    NamespaceRule("trust/", StateNamespace.TRUST),
                    NamespaceRule("economic/", StateNamespace.ECONOMIC),
                )
            )

    def test_rules_reject_ambiguous_prefixes(self) -> None:
        with self.assertRaises(CoreValidationError):
            NamespaceRules(
                (
                    NamespaceRule("intent/", StateNamespace.PROTOCOL),
                    NamespaceRule("intent/urgent/", StateNamespace.VALUE),
                    NamespaceRule("value/", StateNamespace.VALUE),
                    NamespaceRule("trust/", StateNamespace.TRUST),
                    NamespaceRule("economic/", StateNamespace.ECONOMIC),
                    NamespaceRule("dependency/", StateNamespace.DEPENDENCY),
                )
            )

    def test_rules_reject_duplicate_prefixes(self) -> None:
        with self.assertRaises(CoreValidationError):
            NamespaceRules(
                (
                    NamespaceRule("intent/", StateNamespace.PROTOCOL),
                    NamespaceRule("intent/", StateNamespace.PROTOCOL),
                    NamespaceRule("value/", StateNamespace.VALUE),
                    NamespaceRule("trust/", StateNamespace.TRUST),
                    NamespaceRule("economic/", StateNamespace.ECONOMIC),
                    NamespaceRule("dependency/", StateNamespace.DEPENDENCY),
                )
            )

    def test_rules_reject_malformed_prefixes(self) -> None:
        with self.assertRaises(CoreValidationError):
            NamespaceRule("intent", StateNamespace.PROTOCOL)
        with self.assertRaises(CoreValidationError):
            NamespaceRule("", StateNamespace.PROTOCOL)

    def test_rules_digest_is_deterministic(self) -> None:
        rules = NamespaceRules(
            (
                NamespaceRule("intent/", StateNamespace.PROTOCOL),
                NamespaceRule("value/", StateNamespace.VALUE),
                NamespaceRule("trust/", StateNamespace.TRUST),
                NamespaceRule("economic/", StateNamespace.ECONOMIC),
                NamespaceRule("dependency/", StateNamespace.DEPENDENCY),
            )
        )
        again = NamespaceRules(
            (
                NamespaceRule("value/", StateNamespace.VALUE),
                NamespaceRule("intent/", StateNamespace.PROTOCOL),
                NamespaceRule("trust/", StateNamespace.TRUST),
                NamespaceRule("economic/", StateNamespace.ECONOMIC),
                NamespaceRule("dependency/", StateNamespace.DEPENDENCY),
            )
        )
        self.assertEqual(rules.digest, again.digest)


# ---------------------------------------------------------------------------
# 3. The deterministic world adapter boundary.
# ---------------------------------------------------------------------------


class WorldTests(unittest.TestCase):
    """World observations, scripted adapters and epistemic gating."""

    def test_world_observation_round_trip(self) -> None:
        observation = WorldObservation(
            observation_key=RAIL_UP_KEY,
            epistemic_type=EpistemicType.SIMULATED,
            as_of=ROUTE_AT,
            value=True,
            source="world/scripted",
        )
        decoded = WorldObservation.from_dict(observation.to_dict())
        self.assertEqual(decoded, observation)
        self.assertEqual(observation.digest, decoded.digest)

    def test_world_observation_rejects_unknown_epistemic_type(self) -> None:
        with self.assertRaises(CoreValidationError):
            WorldObservation(
                observation_key=RAIL_UP_KEY,
                epistemic_type="GUESSED",
                as_of=ROUTE_AT,
                value=True,
                source="world/scripted",
            )

    def test_world_observation_rejects_float_values(self) -> None:
        with self.assertRaises(CoreValidationError):
            WorldObservation(
                observation_key=RAIL_LATENCY_KEY,
                epistemic_type=EpistemicType.SIMULATED,
                as_of=ROUTE_AT,
                value=150.5,
                source="world/scripted",
            )

    def test_world_observation_rejects_malformed_timestamps(self) -> None:
        with self.assertRaises(CoreValidationError):
            WorldObservation(
                observation_key=RAIL_UP_KEY,
                epistemic_type=EpistemicType.SIMULATED,
                as_of="2026-09-02 00:00:00",
                value=True,
                source="world/scripted",
            )

    def test_scripted_world_serves_scripted_values(self) -> None:
        world = make_world(EpistemicType.SIMULATED)
        up = world.observe(RAIL_UP_KEY, ROUTE_AT)
        latency = world.observe(RAIL_LATENCY_KEY, ROUTE_AT)
        self.assertIs(up.value, True)
        self.assertEqual(latency.value, 150)
        self.assertIs(up.epistemic_type, EpistemicType.SIMULATED)

    def test_scripted_world_unknown_key_fails_closed(self) -> None:
        world = make_world(EpistemicType.SIMULATED)
        with self.assertRaises(CoreValidationError):
            world.observe("rail/unknown", ROUTE_AT)

    def test_scripted_world_unknown_as_of_fails_closed(self) -> None:
        world = make_world(EpistemicType.SIMULATED)
        with self.assertRaises(CoreValidationError):
            world.observe(RAIL_UP_KEY, LATER_AT)

    def test_scripted_world_conflicting_duplicates_fail_closed(self) -> None:
        with self.assertRaises(CoreValidationError):
            ScriptedWorld(
                observations=(
                    WorldObservation(
                        observation_key=RAIL_UP_KEY,
                        epistemic_type=EpistemicType.SIMULATED,
                        as_of=ROUTE_AT,
                        value=True,
                        source="world/scripted",
                    ),
                    WorldObservation(
                        observation_key=RAIL_UP_KEY,
                        epistemic_type=EpistemicType.SIMULATED,
                        as_of=ROUTE_AT,
                        value=False,
                        source="world/scripted",
                    ),
                ),
                epistemic_type=EpistemicType.SIMULATED,
            )

    def test_scripted_world_exact_duplicates_are_tolerated(self) -> None:
        observation = WorldObservation(
            observation_key=RAIL_UP_KEY,
            epistemic_type=EpistemicType.SIMULATED,
            as_of=ROUTE_AT,
            value=True,
            source="world/scripted",
        )
        world = ScriptedWorld(
            observations=(observation, observation),
            epistemic_type=EpistemicType.SIMULATED,
        )
        self.assertIs(world.observe(RAIL_UP_KEY, ROUTE_AT).value, True)

    def test_scripted_world_rejects_mixed_epistemic_types(self) -> None:
        with self.assertRaises(CoreValidationError):
            ScriptedWorld(
                observations=(
                    WorldObservation(
                        observation_key=RAIL_UP_KEY,
                        epistemic_type=EpistemicType.SIMULATED,
                        as_of=ROUTE_AT,
                        value=True,
                        source="world/scripted",
                    ),
                    WorldObservation(
                        observation_key=RAIL_LATENCY_KEY,
                        epistemic_type=EpistemicType.OBSERVED,
                        as_of=ROUTE_AT,
                        value=150,
                        source="world/scripted",
                    ),
                ),
                epistemic_type=EpistemicType.SIMULATED,
            )

    def test_world_adapter_abc_requires_observe(self) -> None:
        class Incomplete(WorldAdapter):
            pass

        with self.assertRaises(TypeError):
            Incomplete()

    def test_world_view_records_consumed_observations(self) -> None:
        runtime = make_runtime()
        runtime.submit(make_create_command())
        transition = runtime.submit(make_route_command())
        self.assertEqual(len(transition.observations), 2)
        self.assertEqual(len(runtime.observations), 2)
        self.assertEqual(runtime.observations[0].observation_key, RAIL_UP_KEY)

    def test_world_observation_epistemic_confusion_fails_closed_at_observe(self) -> None:
        class LyingWorld(WorldAdapter):
            @property
            def epistemic_type(self):
                return EpistemicType.SIMULATED

            def observe(self, observation_key, as_of):
                return WorldObservation(
                    observation_key=observation_key,
                    epistemic_type=EpistemicType.OBSERVED,
                    as_of=as_of,
                    value=True,
                    source="world/lying",
                )

        runtime = make_runtime(world=LyingWorld())
        runtime.submit(make_create_command())
        with self.assertRaises(CoreValidationError):
            runtime.submit(make_route_command())
        self.assertEqual(len(runtime.journal), 1)
        protocol_state = runtime.namespace_state(StateNamespace.PROTOCOL)
        self.assertEqual(len(protocol_state), 1)
        self.assertEqual(protocol_state[0].object_version, 1)
        self.assertEqual(runtime.observations, ())


# ---------------------------------------------------------------------------
# 4. The effect policy and the authorization boundary.
# ---------------------------------------------------------------------------


class EffectTests(unittest.TestCase):
    """Effects: typed intents, policy decisions and gateable records."""

    def test_effect_intent_round_trip_and_digest(self) -> None:
        intent = make_effect_intent()
        decoded = EffectIntent.from_dict(intent.to_dict())
        self.assertEqual(decoded, intent)
        self.assertEqual(intent.digest, decoded.digest)

    def test_effect_intent_rejects_malformed_effect_types(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_effect_intent(effect_type="settlement submit")
        with self.assertRaises(CoreValidationError):
            make_effect_intent(effect_type="settlementsubmit")
        with self.assertRaises(CoreValidationError):
            EffectIntent(
                effect_id="",
                effect_type=EFFECT_TYPE,
                payload={},
                idempotency_key="k",
                requested_at=ROUTE_AT,
            )

    def test_effect_intent_rejects_float_payloads(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_effect_intent(payload={"amount": 1.5})

    def test_authorization_covers_type_and_half_open_window(self) -> None:
        authorization = make_authorization()
        self.assertTrue(authorization.covers(EFFECT_TYPE, ROUTE_AT))
        self.assertFalse(authorization.covers(EFFECT_TYPE, CREATE_AT))
        self.assertFalse(authorization.covers("settlement/other", ROUTE_AT))
        self.assertFalse(authorization.covers(EFFECT_TYPE, MUCH_LATER_AT))

    def test_authorization_rejects_unknown_authority_class(self) -> None:
        with self.assertRaises(CoreValidationError):
            EffectAuthorization(
                authorizer="principal/ops",
                authority_class="A9",
                authorized_types=frozenset({EFFECT_TYPE}),
                valid_from=CREATE_AT,
                valid_until=MUCH_LATER_AT,
            )

    def test_authorization_rejects_inverted_windows(self) -> None:
        with self.assertRaises(CoreValidationError):
            EffectAuthorization(
                authorizer="principal/ops",
                authority_class=AUTHORITY_CLASS,
                authorized_types=frozenset({EFFECT_TYPE}),
                valid_from=MUCH_LATER_AT,
                valid_until=CREATE_AT,
            )

    def test_authorization_rejects_empty_type_sets(self) -> None:
        with self.assertRaises(CoreValidationError):
            EffectAuthorization(
                authorizer="principal/ops",
                authority_class=AUTHORITY_CLASS,
                authorized_types=frozenset(),
                valid_from=CREATE_AT,
                valid_until=MUCH_LATER_AT,
            )

    def test_simulation_policy_records_instead_of_authorizing(self) -> None:
        policy = EffectPolicy.for_mode(EnvironmentMode.SIMULATION)
        decision, reason, authorization_digest = policy.decide(make_effect_intent())
        self.assertIs(decision, EffectDecision.RECORDED)
        self.assertIsNone(authorization_digest)
        self.assertTrue(reason)

    def test_shadow_policy_shadows(self) -> None:
        policy = EffectPolicy.for_mode(EnvironmentMode.SHADOW)
        decision, _, _ = policy.decide(make_effect_intent())
        self.assertIs(decision, EffectDecision.SHADOWED)

    def test_production_policy_fails_closed_without_authorization(self) -> None:
        policy = EffectPolicy.for_mode(EnvironmentMode.PRODUCTION)
        with self.assertRaises(CoreValidationError):
            policy.decide(make_effect_intent())

    def test_production_policy_fails_closed_when_not_covered(self) -> None:
        authorization = make_authorization(
            authorized_types=frozenset({"settlement/other"})
        )
        policy = EffectPolicy(
            mode=EnvironmentMode.PRODUCTION, authorization=authorization
        )
        with self.assertRaises(CoreValidationError):
            policy.decide(make_effect_intent())

    def test_production_policy_authorizes_covered_intents(self) -> None:
        authorization = make_authorization()
        policy = EffectPolicy(
            mode=EnvironmentMode.PRODUCTION, authorization=authorization
        )
        decision, reason, authorization_digest = policy.decide(make_effect_intent())
        self.assertIs(decision, EffectDecision.AUTHORIZED)
        self.assertEqual(authorization_digest, authorization.digest)
        self.assertTrue(reason)

    def test_authorization_is_production_only(self) -> None:
        with self.assertRaises(CoreValidationError):
            EffectPolicy(
                mode=EnvironmentMode.SIMULATION,
                authorization=make_authorization(),
            )

    def test_effect_record_round_trip_is_sealed(self) -> None:
        record = EffectRecord(
            effect_id="effect/submit-1",
            effect_type=EFFECT_TYPE,
            decision=EffectDecision.RECORDED,
            environment_id=ENV_SIM,
            mode=EnvironmentMode.SIMULATION,
            command_id="cmd/route-1",
            idempotency_key="effect-key-1",
            requested_at=ROUTE_AT,
            reason="environment records effects",
            authorization_digest=None,
            fault_reason=None,
            payload_digest=make_effect_intent().digest,
        )
        decoded = EffectRecord.from_dict(record.to_dict())
        self.assertEqual(decoded, record)

    def test_effect_record_tamper_fails_closed(self) -> None:
        runtime = run_parity_scenario(
            mode=EnvironmentMode.SIMULATION, environment_id=ENV_SIM
        )
        record = runtime.effects[0]
        payload = record.to_dict()
        payload["effect_type"] = "settlement/other"
        with self.assertRaises(CoreValidationError):
            EffectRecord.from_dict(payload)

    def test_runtime_rejects_mismatched_effect_policy_mode(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_runtime(
                mode=EnvironmentMode.SIMULATION,
                effect_policy=EffectPolicy.for_mode(EnvironmentMode.SHADOW),
            )

    def test_runtime_rejects_non_effect_intent_inputs(self) -> None:
        runtime = make_runtime()
        runtime.submit(make_create_command())
        with self.assertRaises(CoreValidationError):
            runtime.submit(
                make_route_command(),
                effect_intents=({"effect_id": "not-typed"},),
            )

    def test_effects_on_rejected_transition_fail_closed(self) -> None:
        runtime = make_runtime()
        runtime.submit(make_create_command())
        conflicting = Command.build(
            command_id="cmd/route-conflict",
            command_type=ROUTE_COMMAND_TYPE,
            actor="principal/merchant",
            authority_refs=("authority/ops",),
            target_refs=(INTENT_ID,),
            payload={"route": True},
            environment_id=ENV_SIM,
            domain_id=DOMAIN,
            expected_versions=(
                ExpectedVersion(object_ref=INTENT_ID, object_version=7),
            ),
            idempotency_key="key/route-conflict",
            nonce="1",
            requested_at=ROUTE_AT,
        )
        with self.assertRaises(CoreValidationError):
            runtime.submit(conflicting, effect_intents=(make_effect_intent(),))
        self.assertEqual(runtime.effects, ())

    def test_simulation_effects_never_touch_protocol_state(self) -> None:
        runtime = make_runtime()
        runtime.submit(make_create_command())
        before = runtime.state_digest
        namespace_before = {
            namespace: runtime.namespace_digest(namespace)
            for namespace in StateNamespace
        }
        runtime.submit(make_route_command(), effect_intents=(make_effect_intent(),))
        self.assertEqual(len(runtime.effects), 1)
        self.assertIs(runtime.effects[0].decision, EffectDecision.RECORDED)
        self.assertNotEqual(runtime.state_digest, before)
        self.assertEqual(
            runtime.namespace_digest(StateNamespace.VALUE),
            namespace_before[StateNamespace.VALUE],
        )

    def test_production_runtime_effects_require_authorization(self) -> None:
        runtime = make_runtime(
            environment_id=ENV_PROD,
            mode=EnvironmentMode.PRODUCTION,
            effect_policy=EffectPolicy.for_mode(EnvironmentMode.PRODUCTION),
        )
        runtime.submit(make_create_command(ENV_PROD))
        with self.assertRaises(CoreValidationError):
            runtime.submit(
                make_route_command(ENV_PROD),
                effect_intents=(make_effect_intent(),),
            )

    def test_production_runtime_authorized_effect_records(self) -> None:
        runtime = make_runtime(
            environment_id=ENV_PROD,
            mode=EnvironmentMode.PRODUCTION,
            effect_policy=EffectPolicy(
                mode=EnvironmentMode.PRODUCTION,
                authorization=make_authorization(),
            ),
        )
        runtime.submit(make_create_command(ENV_PROD))
        runtime.submit(
            make_route_command(ENV_PROD),
            effect_intents=(make_effect_intent(),),
        )
        self.assertEqual(len(runtime.effects), 1)
        record = runtime.effects[0]
        self.assertIs(record.decision, EffectDecision.AUTHORIZED)
        self.assertIsNotNone(record.authorization_digest)

    def test_shadow_runtime_effects_are_shadowed(self) -> None:
        runtime = make_runtime(
            environment_id=ENV_SHADOW, mode=EnvironmentMode.SHADOW
        )
        runtime.submit(make_create_command(ENV_SHADOW))
        runtime.submit(
            make_route_command(ENV_SHADOW),
            effect_intents=(make_effect_intent(),),
        )
        self.assertIs(runtime.effects[0].decision, EffectDecision.SHADOWED)


# ---------------------------------------------------------------------------
# 5. The environment runtime over the real kernel.
# ---------------------------------------------------------------------------


class RuntimeTests(unittest.TestCase):
    """Environment runtime construction, submission and lifecycle."""

    def test_construction_epistemic_confusion_fails_closed(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_runtime(
                mode=EnvironmentMode.SIMULATION,
                world=make_world(EpistemicType.OBSERVED),
            )

    def test_spec_validation_fails_closed(self) -> None:
        with self.assertRaises(CoreValidationError):
            EnvironmentSpec(
                environment_id="",
                mode=EnvironmentMode.SIMULATION,
                domain_id=DOMAIN,
                as_of=CREATE_AT,
            )
        with self.assertRaises(CoreValidationError):
            EnvironmentSpec(
                environment_id=ENV_SIM,
                mode=EnvironmentMode.SIMULATION,
                domain_id=DOMAIN,
                as_of="2026-09-02 00:00:00",
            )

    def test_submit_processes_through_the_real_kernel(self) -> None:
        runtime = make_runtime()
        transition = runtime.submit(make_create_command())
        self.assertIsInstance(transition, EnvironmentTransition)
        self.assertIs(transition.outcome, Outcome.ACCEPTED)
        self.assertIsInstance(transition.result, TransitionResult)
        self.assertEqual(len(runtime.journal), 1)
        envelopes = runtime.namespace_state(StateNamespace.PROTOCOL)
        self.assertEqual(envelopes[0].object_version, 1)

    def test_binding_requires_the_kernel_protocol_version(self) -> None:
        from src.simulation import ProtocolBinding

        with self.assertRaises(CoreValidationError):
            ProtocolBinding(
                binding_id="binding/bad",
                protocol_version="v0.2",
                registrations=(
                    CommandRegistration(
                        command_type=CREATE_COMMAND_TYPE,
                        event_type=CREATE_EVENT_TYPE,
                        handler=_create_handler,
                    ),
                ),
                authorization=_allow,
            )

    def test_binding_rejects_non_registry_event_types(self) -> None:
        from src.simulation import ProtocolBinding

        with self.assertRaises(CoreValidationError):
            ProtocolBinding(
                binding_id="binding/bad",
                protocol_version=PROTOCOL_VERSION,
                registrations=(
                    CommandRegistration(
                        command_type=CREATE_COMMAND_TYPE,
                        event_type="bogus/created",
                        handler=_create_handler,
                    ),
                ),
                authorization=_allow,
            )

    def test_binding_rejects_duplicate_command_types(self) -> None:
        from src.simulation import ProtocolBinding

        with self.assertRaises(CoreValidationError):
            ProtocolBinding(
                binding_id="binding/bad",
                protocol_version=PROTOCOL_VERSION,
                registrations=(
                    CommandRegistration(
                        command_type=CREATE_COMMAND_TYPE,
                        event_type=CREATE_EVENT_TYPE,
                        handler=_create_handler,
                    ),
                    CommandRegistration(
                        command_type=CREATE_COMMAND_TYPE,
                        event_type=CREATE_EVENT_TYPE,
                        handler=_create_handler,
                    ),
                ),
                authorization=_allow,
            )

    def test_binding_fingerprint_is_deterministic(self) -> None:
        first = make_binding()
        second = make_binding()
        self.assertEqual(first.fingerprint, second.fingerprint)
        other = make_binding(binding_id="binding/other")
        self.assertNotEqual(first.fingerprint, other.fingerprint)

    def test_cross_environment_command_is_a_typed_rejection(self) -> None:
        runtime = make_runtime()
        before = runtime.state_digest
        transition = runtime.submit(make_create_command(ENV_OTHER))
        self.assertIs(transition.outcome, Outcome.REJECTED)
        self.assertEqual(transition.reason.value, "environment_mismatch")
        self.assertEqual(runtime.journal, ())
        self.assertEqual(runtime.state_digest, before)

    def test_unknown_command_type_is_a_typed_rejection(self) -> None:
        runtime = make_runtime()
        command = Command.build(
            command_id="cmd/unknown-1",
            command_type="intent/mystery",
            actor="principal/merchant",
            authority_refs=("authority/ops",),
            target_refs=(INTENT_ID,),
            payload={},
            environment_id=ENV_SIM,
            domain_id=DOMAIN,
            expected_versions=(ExpectedVersion(object_ref=INTENT_ID, object_version=0),),
            idempotency_key="key/unknown-1",
            nonce="1",
            requested_at=CREATE_AT,
        )
        transition = runtime.submit(command)
        self.assertIs(transition.outcome, Outcome.REJECTED)
        self.assertEqual(transition.reason.value, "unknown_command_type")

    def test_unauthorized_command_is_a_typed_rejection(self) -> None:
        runtime = make_runtime(binding=make_binding(authorization=_deny))
        transition = runtime.submit(make_create_command())
        self.assertIs(transition.outcome, Outcome.REJECTED)
        self.assertEqual(transition.reason.value, "unauthorized")

    def test_unclassified_command_reference_fails_closed(self) -> None:
        runtime = make_runtime()
        command = Command.build(
            command_id="cmd/mystery-1",
            command_type=CREATE_COMMAND_TYPE,
            actor="principal/merchant",
            authority_refs=("authority/ops",),
            target_refs=("mystery/object-1",),
            payload={},
            environment_id=ENV_SIM,
            domain_id=DOMAIN,
            expected_versions=(
                ExpectedVersion(object_ref="mystery/object-1", object_version=0),
            ),
            idempotency_key="key/mystery-1",
            nonce="1",
            requested_at=CREATE_AT,
        )
        before = runtime.state_digest
        with self.assertRaises(CoreValidationError):
            runtime.submit(command)
        self.assertEqual(runtime.state_digest, before)
        self.assertEqual(runtime.journal, ())

    def test_namespaced_store_rejects_unclassified_access(self) -> None:
        from src.simulation import NamespacedStateStore
        from src.transition import MemoryStateStore

        store = NamespacedStateStore(DEFAULT_NAMESPACE_RULES, MemoryStateStore())
        with self.assertRaises(CoreValidationError):
            store.get("mystery/object-1")
        with self.assertRaises(CoreValidationError):
            store.commit((make_envelope("mystery/object-1", "CREATED", ENV_SIM),))

    def test_provisioning_contamination_fails_closed(self) -> None:
        hold = make_envelope(HOLD_ID, "ACTIVE", ENV_SIM, object_type="value/hold/v1")
        with self.assertRaises(CoreValidationError):
            make_runtime(
                initial_state={StateNamespace.TRUST: (hold,)},
            )

    def test_provisioning_duplicate_object_ids_fail_closed(self) -> None:
        intent = make_envelope(INTENT_ID, "CREATED", ENV_SIM)
        with self.assertRaises(CoreValidationError):
            make_runtime(
                initial_state={
                    StateNamespace.PROTOCOL: (intent,),
                    StateNamespace.VALUE: (intent,),
                }
            )

    def test_namespaced_provisioning_serves_state(self) -> None:
        hold = make_envelope(HOLD_ID, "ACTIVE", ENV_SIM, object_type="value/hold/v1")
        runtime = make_runtime(
            initial_state={StateNamespace.VALUE: (hold,)}
        )
        self.assertEqual(
            [envelope.object_id for envelope in runtime.namespace_state(
                StateNamespace.VALUE
            )],
            [HOLD_ID],
        )
        self.assertEqual(runtime.namespace_state(StateNamespace.PROTOCOL), ())

    def test_namespace_views_are_disjoint(self) -> None:
        hold = make_envelope(HOLD_ID, "ACTIVE", ENV_SIM, object_type="value/hold/v1")
        runtime = make_runtime(
            initial_state={StateNamespace.VALUE: (hold,)}
        )
        runtime.submit(make_create_command())
        seen: set[str] = set()
        for namespace in StateNamespace:
            ids = {
                envelope.object_id
                for envelope in runtime.namespace_state(namespace)
            }
            self.assertFalse(seen & ids)
            seen |= ids
        self.assertEqual(seen, {INTENT_ID, HOLD_ID})

    def test_value_namespace_update_leaves_other_digests_unchanged(self) -> None:
        hold = make_envelope(HOLD_ID, "ACTIVE", ENV_SIM, object_type="value/hold/v1")
        runtime = make_runtime(
            initial_state={StateNamespace.VALUE: (hold,)}
        )
        runtime.submit(make_create_command())
        digests = {
            namespace: runtime.namespace_digest(namespace)
            for namespace in StateNamespace
        }
        runtime.submit(make_hold_command())
        self.assertNotEqual(
            runtime.namespace_digest(StateNamespace.VALUE), digests[StateNamespace.VALUE]
        )
        for namespace in (
            StateNamespace.PROTOCOL,
            StateNamespace.TRUST,
            StateNamespace.ECONOMIC,
            StateNamespace.DEPENDENCY,
        ):
            self.assertEqual(
                runtime.namespace_digest(namespace), digests[namespace]
            )

    def test_duplicate_command_converges_without_new_effects(self) -> None:
        runtime = make_runtime()
        command = make_create_command()
        first = runtime.submit(command)
        second = runtime.submit(command)
        self.assertIs(first.outcome, Outcome.ACCEPTED)
        self.assertIs(second.outcome, Outcome.DUPLICATE)
        self.assertEqual(len(runtime.journal), 1)
        self.assertEqual(len(runtime.transitions), 2)

    def test_duplicate_command_with_conflicting_intents_fails_closed(self) -> None:
        runtime = make_runtime(
            environment_id=ENV_PROD,
            mode=EnvironmentMode.PRODUCTION,
            effect_policy=EffectPolicy(
                mode=EnvironmentMode.PRODUCTION,
                authorization=make_authorization(),
            ),
        )
        command = make_route_command(ENV_PROD)
        runtime.submit(make_create_command(ENV_PROD))
        runtime.submit(command, effect_intents=(make_effect_intent(),))
        with self.assertRaises(CoreValidationError):
            runtime.submit(
                command,
                effect_intents=(
                    make_effect_intent(
                        effect_id="effect/submit-2", idempotency_key="effect-key-2"
                    ),
                ),
            )
        self.assertEqual(len(runtime.effects), 1)

    def test_duplicate_command_reuses_recorded_effects(self) -> None:
        runtime = make_runtime(
            environment_id=ENV_PROD,
            mode=EnvironmentMode.PRODUCTION,
            effect_policy=EffectPolicy(
                mode=EnvironmentMode.PRODUCTION,
                authorization=make_authorization(),
            ),
        )
        command = make_route_command(ENV_PROD)
        runtime.submit(make_create_command(ENV_PROD))
        runtime.submit(command, effect_intents=(make_effect_intent(),))
        runtime.submit(command, effect_intents=(make_effect_intent(),))
        self.assertEqual(len(runtime.effects), 1)

    def test_step_and_run_are_submission_paths(self) -> None:
        runtime = make_runtime()
        runtime.step(make_create_command())
        self.assertEqual(len(runtime.transitions), 1)
        other = make_runtime()
        results = other.run((make_create_command(), make_route_command()))
        self.assertEqual(len(results), 2)
        self.assertEqual(len(other.journal), 2)

    def test_pause_resume_gate_submissions(self) -> None:
        runtime = make_runtime()
        runtime.pause(LATER_AT)
        self.assertIs(runtime.run_state, SimulationRunState.PAUSED)
        with self.assertRaises(CoreValidationError):
            runtime.submit(make_create_command())
        runtime.resume(LATER_AT)
        self.assertIs(runtime.run_state, SimulationRunState.RUNNING)
        transition = runtime.submit(make_create_command())
        self.assertIs(transition.outcome, Outcome.ACCEPTED)

    def test_operations_journal_records_lifecycle(self) -> None:
        runtime = make_runtime()
        self.assertEqual(runtime.operations[0].operation, "simulation/create")
        runtime.submit(make_create_command())
        self.assertEqual(runtime.operations[-1].operation, "simulation/step")
        runtime.pause(LATER_AT)
        self.assertEqual(runtime.operations[-1].operation, "simulation/pause")
        runtime.resume(LATER_AT)
        self.assertEqual(runtime.operations[-1].operation, "simulation/resume")

    def test_simulation_envelope_identity(self) -> None:
        runtime = make_runtime()
        envelope = runtime.simulation_envelope
        self.assertEqual(envelope.object_type, SIMULATION_OBJECT_TYPE)
        self.assertEqual(envelope.state, "RUNNING")
        self.assertEqual(envelope.protocol_version, PROTOCOL_VERSION)

    def test_complete_seals_terminal_run(self) -> None:
        runtime = make_runtime()
        runtime.submit(make_create_command())
        runtime.submit(make_route_command())
        result = runtime.complete(MUCH_LATER_AT, note="run finished")
        self.assertIs(runtime.run_state, SimulationRunState.COMPLETED)
        self.assertEqual(result.envelope.object_type, SIMULATION_RESULT_OBJECT_TYPE)
        self.assertEqual(result.envelope.state, "COMPLETED")
        self.assertEqual(runtime.simulation_envelope.object_version, 2)
        with self.assertRaises(CoreValidationError):
            runtime.submit(make_create_command(command_id="cmd/after-complete"))
        with self.assertRaises(CoreValidationError):
            runtime.checkpoint(label="late", at=MUCH_LATER_AT)

    def test_fail_and_cancel_are_terminal(self) -> None:
        failed = make_runtime()
        result = failed.fail(MUCH_LATER_AT, reason="route exploded")
        self.assertIs(failed.run_state, SimulationRunState.FAILED)
        self.assertEqual(result.envelope.state, "FAILED")
        cancelled = make_runtime()
        result = cancelled.cancel(MUCH_LATER_AT, reason="operator abort")
        self.assertIs(cancelled.run_state, SimulationRunState.CANCELLED)
        self.assertEqual(result.envelope.state, "CANCELLED")

    def test_simulation_result_round_trip(self) -> None:
        runtime = make_runtime()
        runtime.submit(make_create_command())
        result = runtime.complete(MUCH_LATER_AT)
        decoded = SimulationResult.from_dict(result.to_dict())
        self.assertEqual(decoded, result)

    def test_simulation_result_tamper_fails_closed(self) -> None:
        runtime = make_runtime()
        runtime.submit(make_create_command())
        result = runtime.complete(MUCH_LATER_AT)
        payload = result.to_dict()
        payload["payload"]["transition_count"] = 99
        with self.assertRaises(CoreValidationError):
            SimulationResult.from_dict(payload)

    def test_fault_injection_blocks_world_observations(self) -> None:
        runtime = make_runtime()
        runtime.submit(make_create_command())
        runtime.inject_fault(
            kind=FaultKind.WORLD_OBSERVATION_UNAVAILABLE,
            observation_key=RAIL_UP_KEY,
            reason="rail alpha is down",
            at=LATER_AT,
        )
        with self.assertRaises(CoreValidationError):
            runtime.submit(make_route_command())
        self.assertEqual(len(runtime.journal), 1)
        runtime.clear_fault(
            kind=FaultKind.WORLD_OBSERVATION_UNAVAILABLE,
            target=RAIL_UP_KEY,
            at=LATER_AT,
        )
        transition = runtime.submit(make_route_command())
        self.assertIs(transition.outcome, Outcome.ACCEPTED)

    def test_fault_injection_marks_effect_failures(self) -> None:
        runtime = make_runtime(
            environment_id=ENV_PROD,
            mode=EnvironmentMode.PRODUCTION,
            effect_policy=EffectPolicy(
                mode=EnvironmentMode.PRODUCTION,
                authorization=make_authorization(),
            ),
        )
        runtime.submit(make_create_command(ENV_PROD))
        runtime.inject_fault(
            kind=FaultKind.EFFECT_FAILURE,
            effect_type=EFFECT_TYPE,
            reason="rail returned an error",
            at=LATER_AT,
        )
        runtime.submit(
            make_route_command(ENV_PROD), effect_intents=(make_effect_intent(),)
        )
        record = runtime.effects[0]
        self.assertEqual(record.fault_reason, "rail returned an error")

    def test_fault_injection_requires_a_target(self) -> None:
        runtime = make_runtime()
        with self.assertRaises(CoreValidationError):
            runtime.inject_fault(
                kind=FaultKind.WORLD_OBSERVATION_UNAVAILABLE,
                reason="no key",
                at=LATER_AT,
            )
        with self.assertRaises(CoreValidationError):
            runtime.inject_fault(
                kind=FaultKind.EFFECT_FAILURE,
                observation_key=RAIL_UP_KEY,
                reason="wrong target kind",
                at=LATER_AT,
            )


# ---------------------------------------------------------------------------
# 6. The parity invariant — the heart of the Work Order.
# ---------------------------------------------------------------------------


class ParityTests(unittest.TestCase):
    """Protocol transitions are identical across environments."""

    def test_parity_across_simulation_shadow_and_production(self) -> None:
        simulation = run_parity_scenario(
            mode=EnvironmentMode.SIMULATION, environment_id=ENV_SIM
        )
        shadow = run_parity_scenario(
            mode=EnvironmentMode.SHADOW, environment_id=ENV_SHADOW
        )
        production = run_parity_scenario(
            mode=EnvironmentMode.PRODUCTION,
            environment_id=ENV_PROD,
            authorization=make_authorization(),
        )
        self.assertEqual(
            parity_digest(simulation.journal), parity_digest(shadow.journal)
        )
        self.assertEqual(
            parity_digest(simulation.journal), parity_digest(production.journal)
        )

    def test_raw_journals_differ_only_in_environment_identity(self) -> None:
        simulation = run_parity_scenario(
            mode=EnvironmentMode.SIMULATION, environment_id=ENV_SIM
        )
        shadow = run_parity_scenario(
            mode=EnvironmentMode.SHADOW, environment_id=ENV_SHADOW
        )
        production = run_parity_scenario(
            mode=EnvironmentMode.PRODUCTION,
            environment_id=ENV_PROD,
            authorization=make_authorization(),
        )
        expected_diff = (
            "entry[0].event.environment_id",
            "entry[1].event.environment_id",
        )
        self.assertEqual(
            canonical_journal_diff(simulation.journal, shadow.journal), expected_diff
        )
        self.assertEqual(
            canonical_journal_diff(simulation.journal, production.journal), expected_diff
        )

    def test_parity_projection_strips_environment_identity(self) -> None:
        simulation = run_parity_scenario(
            mode=EnvironmentMode.SIMULATION, environment_id=ENV_SIM
        )
        production = run_parity_scenario(
            mode=EnvironmentMode.PRODUCTION,
            environment_id=ENV_PROD,
            authorization=make_authorization(),
        )
        left = parity_projection(simulation.journal)
        right = parity_projection(production.journal)
        self.assertEqual(left, right)
        for entry in left:
            self.assertIn('"environment_id":null', entry)

    def test_effect_policy_outcomes_differ_by_environment(self) -> None:
        simulation = run_parity_scenario(
            mode=EnvironmentMode.SIMULATION, environment_id=ENV_SIM
        )
        shadow = run_parity_scenario(
            mode=EnvironmentMode.SHADOW, environment_id=ENV_SHADOW
        )
        production = run_parity_scenario(
            mode=EnvironmentMode.PRODUCTION,
            environment_id=ENV_PROD,
            authorization=make_authorization(),
        )
        self.assertIs(simulation.effects[0].decision, EffectDecision.RECORDED)
        self.assertIs(shadow.effects[0].decision, EffectDecision.SHADOWED)
        self.assertIs(production.effects[0].decision, EffectDecision.AUTHORIZED)
        self.assertEqual(
            [record.effect_id for record in simulation.effects],
            [record.effect_id for record in production.effects],
        )

    def test_different_world_values_change_transitions(self) -> None:
        first = run_parity_scenario(
            mode=EnvironmentMode.SIMULATION, environment_id=ENV_SIM
        )
        runtime = EnvironmentRuntime(
            spec=make_spec(ENV_OTHER),
            binding=make_binding(binding_id="binding/other-env"),
            world=make_world(EpistemicType.SIMULATED, rail_up=False),
        )
        runtime.submit(make_create_command(ENV_OTHER))
        runtime.submit(
            make_route_command(ENV_OTHER), effect_intents=(make_effect_intent(),)
        )
        self.assertNotEqual(parity_digest(first.journal), parity_digest(runtime.journal))

    def test_state_is_identical_across_environments_modulo_identity(self) -> None:
        simulation = run_parity_scenario(
            mode=EnvironmentMode.SIMULATION, environment_id=ENV_SIM
        )
        shadow = run_parity_scenario(
            mode=EnvironmentMode.SHADOW, environment_id=ENV_SHADOW
        )
        sim_state = [
            envelope.to_dict()
            for envelope in simulation.namespace_state(StateNamespace.PROTOCOL)
        ]
        shadow_state = [
            envelope.to_dict()
            for envelope in shadow.namespace_state(StateNamespace.PROTOCOL)
        ]
        for left, right in zip(sim_state, shadow_state):
            self.assertEqual(left["object_version"], right["object_version"])
            self.assertEqual(left["state"], right["state"])
            self.assertNotEqual(left["environment_id"], right["environment_id"])


# ---------------------------------------------------------------------------
# 7. Snapshots, checkpoints and restore.
# ---------------------------------------------------------------------------


class SnapshotTests(unittest.TestCase):
    """Snapshots, sealed checkpoints and fail-closed restore."""

    def _two_step_runtime(self) -> EnvironmentRuntime:
        runtime = make_runtime()
        runtime.submit(make_create_command())
        runtime.submit(make_route_command())
        return runtime

    def test_checkpoint_creates_a_sealed_durable_object(self) -> None:
        runtime = self._two_step_runtime()
        checkpoint = runtime.checkpoint(label="cp-1", at=LATER_AT)
        self.assertIsInstance(checkpoint, SimulationCheckpoint)
        self.assertEqual(checkpoint.envelope.object_type, SIMULATION_CHECKPOINT_OBJECT_TYPE)
        self.assertEqual(checkpoint.envelope.state, "SEALED")
        self.assertEqual(checkpoint.sequence, 1)
        self.assertIsNone(checkpoint.parent_checkpoint_digest)
        decoded = SimulationCheckpoint.from_dict(checkpoint.to_dict())
        self.assertEqual(decoded, checkpoint)

    def test_checkpoint_chain_records_parents(self) -> None:
        runtime = self._two_step_runtime()
        first = runtime.checkpoint(label="cp-1", at=LATER_AT)
        runtime.submit(make_settle_command(expected_version=2, at=STEP3_AT))
        second = runtime.checkpoint(label="cp-2", at=MUCH_LATER_AT)
        self.assertEqual(second.sequence, 2)
        self.assertEqual(second.parent_checkpoint_digest, first.checkpoint_digest)

    def test_environment_snapshot_round_trip(self) -> None:
        runtime = self._two_step_runtime()
        snapshot = runtime.snapshot(label="snap", at=LATER_AT)
        decoded = EnvironmentSnapshot.from_dict(snapshot.to_dict())
        self.assertEqual(decoded, snapshot)
        self.assertEqual(snapshot.environment_id, ENV_SIM)
        self.assertEqual(snapshot.mode, EnvironmentMode.SIMULATION)
        self.assertEqual(snapshot.label, "snap")

    def test_environment_snapshot_tamper_fails_closed(self) -> None:
        runtime = self._two_step_runtime()
        snapshot = runtime.snapshot(label="snap", at=LATER_AT)
        payload = snapshot.to_dict()
        payload["clock"] = 99
        with self.assertRaises(CoreValidationError):
            EnvironmentSnapshot.from_dict(payload)

    def test_restore_continues_the_run_identically(self) -> None:
        source = self._two_step_runtime()
        checkpoint = source.checkpoint(label="cp-1", at=LATER_AT)
        restored = make_runtime()
        restored.restore(checkpoint)
        self.assertEqual(
            [entry.event.to_json() for entry in restored.journal],
            [entry.event.to_json() for entry in source.journal],
        )
        self.assertEqual(restored.state_digest, source.state_digest)
        step_three = make_settle_command(expected_version=2, at=STEP3_AT)
        restored_transition = restored.submit(step_three)
        uninterrupted = self._two_step_runtime()
        uninterrupted_transition = uninterrupted.submit(step_three)
        self.assertEqual(
            restored_transition.transition_digest,
            uninterrupted_transition.transition_digest,
        )

    def test_restore_into_wrong_environment_fails_closed(self) -> None:
        source = self._two_step_runtime()
        checkpoint = source.checkpoint(label="cp-1", at=LATER_AT)
        other = make_runtime(environment_id=ENV_OTHER)
        with self.assertRaises(CoreValidationError):
            other.restore(checkpoint)

    def test_restore_across_modes_fails_closed(self) -> None:
        source = self._two_step_runtime()
        checkpoint = source.checkpoint(label="cp-1", at=LATER_AT)
        production = make_runtime(
            environment_id=ENV_SIM, mode=EnvironmentMode.PRODUCTION
        )
        with self.assertRaises(CoreValidationError):
            production.restore(checkpoint)

    def test_restore_with_mismatched_binding_fails_closed(self) -> None:
        source = self._two_step_runtime()
        checkpoint = source.checkpoint(label="cp-1", at=LATER_AT)
        other_binding = make_runtime(binding=make_binding(binding_id="binding/other"))
        with self.assertRaises(CoreValidationError):
            other_binding.restore(checkpoint)

    def test_restore_into_terminal_run_fails_closed(self) -> None:
        source = self._two_step_runtime()
        checkpoint = source.checkpoint(label="cp-1", at=LATER_AT)
        terminal = make_runtime()
        terminal.complete(MUCH_LATER_AT)
        with self.assertRaises(CoreValidationError):
            terminal.restore(checkpoint)

    def test_checkpoint_tamper_fails_closed_on_restore(self) -> None:
        source = self._two_step_runtime()
        checkpoint = source.checkpoint(label="cp-1", at=LATER_AT)
        payload = checkpoint.to_dict()
        payload["payload"]["snapshot"]["clock"] = 99
        with self.assertRaises(CoreValidationError):
            SimulationCheckpoint.from_dict(payload)


# ---------------------------------------------------------------------------
# 8. Deterministic replay.
# ---------------------------------------------------------------------------


class ReplayTests(unittest.TestCase):
    """Journal recording, deterministic replay and divergence detection."""

    def _two_step_runtime(self) -> EnvironmentRuntime:
        runtime = make_runtime(
            environment_id=ENV_REPLAY, mode=EnvironmentMode.SIMULATION
        )
        runtime.submit(make_create_command(ENV_REPLAY))
        runtime.submit(
            make_route_command(ENV_REPLAY), effect_intents=(make_effect_intent(),)
        )
        return runtime

    def test_replay_journal_round_trip(self) -> None:
        runtime = self._two_step_runtime()
        journal = ReplayJournal.from_runtime(runtime, label="journal-1")
        decoded = ReplayJournal.from_dict(journal.to_dict())
        self.assertEqual(decoded, journal)
        self.assertEqual(len(journal.entries), 2)
        self.assertEqual(journal.environment_id, ENV_REPLAY)
        self.assertEqual(journal.mode, EnvironmentMode.SIMULATION)

    def test_replay_reproduces_state_and_journal(self) -> None:
        runtime = self._two_step_runtime()
        journal = ReplayJournal.from_runtime(runtime, label="journal-1")
        report = replay(journal, binding=runtime.binding)
        self.assertIsInstance(report, ReplayReport)
        self.assertEqual(report.entries_replayed, 2)
        self.assertEqual(report.journal_digest, journal.final_journal_digest)
        self.assertEqual(report.state_digest, journal.final_state_digest)
        self.assertEqual(report.environment_id, ENV_REPLAY)
        self.assertEqual(
            dict(report.namespace_digests),
            dict(journal.namespace_digests),
        )

    def test_replay_divergence_fails_closed(self) -> None:
        runtime = self._two_step_runtime()
        journal = ReplayJournal.from_runtime(runtime, label="journal-1")
        payload = journal.to_dict()
        payload["content"]["entries"][1]["transition_digest"] = "0" * 64
        payload["integrity_hash"] = canonical_sha256(payload["content"])
        doctored = ReplayJournal.from_dict(payload)
        with self.assertRaises(CoreValidationError):
            replay(doctored, binding=runtime.binding)

    def test_replay_with_missing_world_observation_fails_closed(self) -> None:
        runtime = self._two_step_runtime()
        journal = ReplayJournal.from_runtime(runtime, label="journal-1")
        payload = journal.to_dict()
        observations = payload["content"]["observations"]
        payload["content"]["observations"] = [observations[0]]
        payload["integrity_hash"] = canonical_sha256(payload["content"])
        doctored = ReplayJournal.from_dict(payload)
        with self.assertRaises(CoreValidationError):
            replay(doctored, binding=runtime.binding)

    def test_replay_with_mismatched_binding_fails_closed(self) -> None:
        runtime = self._two_step_runtime()
        journal = ReplayJournal.from_runtime(runtime, label="journal-1")
        with self.assertRaises(CoreValidationError):
            replay(journal, binding=make_binding(binding_id="binding/other"))

    def test_replay_of_production_run_requires_authorization(self) -> None:
        runtime = make_runtime(
            environment_id=ENV_PROD,
            mode=EnvironmentMode.PRODUCTION,
            effect_policy=EffectPolicy(
                mode=EnvironmentMode.PRODUCTION,
                authorization=make_authorization(),
            ),
        )
        runtime.submit(make_create_command(ENV_PROD))
        runtime.submit(
            make_route_command(ENV_PROD), effect_intents=(make_effect_intent(),)
        )
        journal = ReplayJournal.from_runtime(runtime, label="prod-journal")
        with self.assertRaises(CoreValidationError):
            replay(journal, binding=runtime.binding)
        report = replay(
            journal,
            binding=runtime.binding,
            effect_policy=EffectPolicy(
                mode=EnvironmentMode.PRODUCTION,
                authorization=make_authorization(),
            ),
        )
        self.assertEqual(report.entries_replayed, 2)

    def test_replay_run_is_epistemically_gated(self) -> None:
        runtime = self._two_step_runtime()
        journal = ReplayJournal.from_runtime(runtime, label="journal-1")
        report = replay(journal, binding=runtime.binding)
        replayed = report.runtime
        self.assertEqual(
            [observation.digest for observation in replayed.observations],
            [observation.digest for observation in runtime.observations],
        )
        self.assertEqual(
            [record.effect_id for record in replayed.effects],
            [record.effect_id for record in runtime.effects],
        )

    def test_replay_operations_journal_marks_replay(self) -> None:
        runtime = self._two_step_runtime()
        journal = ReplayJournal.from_runtime(runtime, label="journal-1")
        report = replay(journal, binding=runtime.binding)
        self.assertEqual(report.runtime.operations[0].operation, "simulation/replay")


# ---------------------------------------------------------------------------
# 9. Forecast and counterfactual branching.
# ---------------------------------------------------------------------------


class BranchingTests(unittest.TestCase):
    """State branching from snapshots and forecast error feedback."""

    def _parent(self) -> EnvironmentRuntime:
        runtime = make_runtime()
        runtime.submit(make_create_command())
        runtime.submit(make_route_command())
        return runtime

    def test_counterfactual_branch_diverges_on_changed_assumptions(self) -> None:
        parent = self._parent()
        parent_journal = [entry.event.to_json() for entry in parent.journal]
        parent_digests = {
            namespace: parent.namespace_digest(namespace)
            for namespace in StateNamespace
        }
        branch_runtime = branch_from(
            parent,
            at=LATER_AT,
            environment_id=ENV_CF,
            mode=EnvironmentMode.COUNTERFACTUAL,
            world=make_world(
                EpistemicType.COUNTERFACTUAL, rail_up=False
            ),
            label="cf-rail-down",
        )
        self.assertIs(branch_runtime.mode, EnvironmentMode.COUNTERFACTUAL)
        self.assertEqual(
            [entry.event.to_json() for entry in parent.journal], parent_journal
        )
        self.assertEqual(
            {namespace: parent.namespace_digest(namespace) for namespace in StateNamespace},
            parent_digests,
        )
        route_again = make_route_command(
            ENV_CF,
            command_id="cmd/route-cf",
            expected_version=2,
            idempotency_key="key/route-cf",
        )
        transition = branch_runtime.submit(route_again)
        self.assertEqual(payload_to_json_value(transition.payload)["rail"], "beta")

    def test_forecast_branch_with_same_values_repeats_semantics(self) -> None:
        parent = self._parent()
        branch_runtime = branch_from(
            parent,
            at=LATER_AT,
            environment_id=ENV_FORECAST,
            mode=EnvironmentMode.FORECAST,
            world=make_world(EpistemicType.PREDICTED),
            label="forecast-same",
        )
        route_again = make_route_command(
            ENV_FORECAST,
            command_id="cmd/route-f",
            expected_version=2,
            idempotency_key="key/route-f",
        )
        transition = branch_runtime.submit(route_again)
        parent_route = make_route_command(
            ENV_SIM,
            command_id="cmd/route-p",
            expected_version=2,
            idempotency_key="key/route-p",
        )
        parent_transition = parent.submit(parent_route)
        self.assertEqual(
            parity_projection(branch_runtime.journal)[-1],
            parity_projection(parent.journal)[-1],
        )
        self.assertEqual(
            payload_to_json_value(transition.payload)["rail"],
            payload_to_json_value(parent_transition.payload)["rail"],
        )

    def test_branch_from_checkpoint_object(self) -> None:
        parent = self._parent()
        checkpoint = parent.checkpoint(label="cp-branch", at=LATER_AT)
        branch_runtime = branch(
            checkpoint,
            binding=parent.binding,
            environment_id=ENV_CF,
            mode=EnvironmentMode.COUNTERFACTUAL,
            world=make_world(EpistemicType.COUNTERFACTUAL),
        )
        self.assertEqual(branch_runtime.environment_id, ENV_CF)

    def test_branch_into_production_fails_closed(self) -> None:
        parent = self._parent()
        with self.assertRaises(CoreValidationError):
            branch_from(
                parent,
                at=LATER_AT,
                environment_id=ENV_PROD,
                mode=EnvironmentMode.PRODUCTION,
                world=make_world(EpistemicType.OBSERVED),
            )

    def test_branch_requires_a_new_environment_id(self) -> None:
        parent = self._parent()
        with self.assertRaises(CoreValidationError):
            branch_from(
                parent,
                at=LATER_AT,
                environment_id=ENV_SIM,
                mode=EnvironmentMode.COUNTERFACTUAL,
                world=make_world(EpistemicType.COUNTERFACTUAL),
            )

    def test_branch_simulation_provenance_references_parent(self) -> None:
        parent = self._parent()
        checkpoint = parent.checkpoint(label="cp-branch", at=LATER_AT)
        branch_runtime = branch(
            checkpoint,
            binding=parent.binding,
            environment_id=ENV_CF,
            mode=EnvironmentMode.COUNTERFACTUAL,
            world=make_world(EpistemicType.COUNTERFACTUAL),
        )
        self.assertEqual(
            branch_runtime.simulation_envelope.causation_id,
            checkpoint.checkpoint_digest,
        )
        self.assertEqual(
            branch_runtime.operations[0].operation, "simulation/branch"
        )

    def test_branch_inherits_protocol_history(self) -> None:
        parent = self._parent()
        parent_route = make_route_command(ENV_SIM)
        branch_runtime = branch_from(
            parent,
            at=LATER_AT,
            environment_id=ENV_CF,
            mode=EnvironmentMode.COUNTERFACTUAL,
            world=make_world(EpistemicType.COUNTERFACTUAL),
        )
        self.assertEqual(len(branch_runtime.journal), len(parent.journal))
        duplicate_result = branch_runtime.submit(parent_route)
        self.assertIs(duplicate_result.outcome, Outcome.DUPLICATE)
        self.assertEqual(len(branch_runtime.journal), len(parent.journal))

    def test_branch_epistemic_confusion_fails_closed(self) -> None:
        parent = self._parent()
        with self.assertRaises(CoreValidationError):
            branch_from(
                parent,
                at=LATER_AT,
                environment_id=ENV_CF,
                mode=EnvironmentMode.COUNTERFACTUAL,
                world=make_world(EpistemicType.SIMULATED),
            )

    def test_forecast_errors_are_exact_integer_arithmetic(self) -> None:
        predicted = WorldObservation(
            observation_key="settlement/latency-ms",
            epistemic_type=EpistemicType.PREDICTED,
            as_of=ROUTE_AT,
            value=100,
            source="world/forecast",
        )
        observed = WorldObservation(
            observation_key="settlement/latency-ms",
            epistemic_type=EpistemicType.OBSERVED,
            as_of=ROUTE_AT,
            value=130,
            source="world/live",
        )
        errors = forecast_errors((predicted,), (observed,))
        self.assertEqual(len(errors), 1)
        error = errors[0]
        self.assertIsInstance(error, ForecastError)
        self.assertEqual(error.signed_error, 30)
        self.assertEqual(error.absolute_error, 30)
        decoded = ForecastError.from_dict(error.to_dict())
        self.assertEqual(decoded, error)

    def test_forecast_errors_fail_closed_on_confusion_and_gaps(self) -> None:
        wrong_type = WorldObservation(
            observation_key="settlement/latency-ms",
            epistemic_type=EpistemicType.OBSERVED,
            as_of=ROUTE_AT,
            value=100,
            source="world/live",
        )
        observed = WorldObservation(
            observation_key="settlement/latency-ms",
            epistemic_type=EpistemicType.OBSERVED,
            as_of=ROUTE_AT,
            value=130,
            source="world/live",
        )
        with self.assertRaises(CoreValidationError):
            forecast_errors((wrong_type,), (observed,))
        predicted = WorldObservation(
            observation_key="settlement/latency-ms",
            epistemic_type=EpistemicType.PREDICTED,
            as_of=ROUTE_AT,
            value=100,
            source="world/forecast",
        )
        with self.assertRaises(CoreValidationError):
            forecast_errors((predicted,), ())

    def test_forecast_errors_reject_non_integer_values(self) -> None:
        predicted = WorldObservation(
            observation_key="settlement/latency-ms",
            epistemic_type=EpistemicType.PREDICTED,
            as_of=ROUTE_AT,
            value=100,
            source="world/forecast",
        )
        observed = WorldObservation(
            observation_key="settlement/latency-ms",
            epistemic_type=EpistemicType.OBSERVED,
            as_of=ROUTE_AT,
            value="slow",
            source="world/live",
        )
        with self.assertRaises(CoreValidationError):
            forecast_errors((predicted,), (observed,))


# ---------------------------------------------------------------------------
# 10. The promotion boundary.
# ---------------------------------------------------------------------------


class PromotionTests(unittest.TestCase):
    """Promotion chain: request, fresh validation, authorization."""

    def _checkpoint(self) -> SimulationCheckpoint:
        runtime = make_runtime()
        runtime.submit(make_create_command())
        runtime.submit(make_route_command())
        return runtime.checkpoint(label="promotion-source", at=LATER_AT)

    def test_promotion_request_requires_evidence(self) -> None:
        checkpoint = self._checkpoint()
        request = request_promotion(
            checkpoint,
            requested_by="principal/ops",
            requested_at=LATER_AT,
            evidence_refs=("evidence/sim-run-1",),
            valid_until=MUCH_LATER_AT,
        )
        self.assertIsInstance(request, PromotionRequest)
        self.assertEqual(request.source_checkpoint_digest, checkpoint.checkpoint_digest)
        self.assertIs(request.source_mode, EnvironmentMode.SIMULATION)
        with self.assertRaises(CoreValidationError):
            request_promotion(
                checkpoint,
                requested_by="principal/ops",
                requested_at=LATER_AT,
                evidence_refs=(),
                valid_until=MUCH_LATER_AT,
            )

    def test_promotion_request_rejects_production_sources(self) -> None:
        runtime = make_runtime(
            environment_id=ENV_PROD, mode=EnvironmentMode.PRODUCTION
        )
        runtime.submit(make_create_command(ENV_PROD))
        checkpoint = runtime.checkpoint(label="prod-source", at=LATER_AT)
        with self.assertRaises(CoreValidationError):
            request_promotion(
                checkpoint,
                requested_by="principal/ops",
                requested_at=LATER_AT,
                evidence_refs=("evidence/run",),
                valid_until=MUCH_LATER_AT,
            )

    def test_fresh_validation_must_target_the_requested_state(self) -> None:
        checkpoint = self._checkpoint()
        request = request_promotion(
            checkpoint,
            requested_by="principal/ops",
            requested_at=LATER_AT,
            evidence_refs=("evidence/sim-run-1",),
            valid_until=MUCH_LATER_AT,
        )
        other_runtime = make_runtime(environment_id=ENV_OTHER)
        other_runtime.submit(make_create_command(ENV_OTHER))
        other_checkpoint = other_runtime.checkpoint(label="other", at=LATER_AT)
        with self.assertRaises(CoreValidationError):
            perform_fresh_validation(
                request,
                other_checkpoint,
                validator="principal/validator",
                validated_at=LATER_AT,
                result=ValidationVerdict.PASS,
            )

    def test_fresh_validation_window_is_enforced(self) -> None:
        checkpoint = self._checkpoint()
        request = request_promotion(
            checkpoint,
            requested_by="principal/ops",
            requested_at=LATER_AT,
            evidence_refs=("evidence/sim-run-1",),
            valid_until=MUCH_LATER_AT,
        )
        with self.assertRaises(CoreValidationError):
            perform_fresh_validation(
                request,
                checkpoint,
                validator="principal/validator",
                validated_at="2026-09-03T00:00:00Z",
                result=ValidationVerdict.PASS,
            )

    def test_fresh_validation_round_trip(self) -> None:
        checkpoint = self._checkpoint()
        request = request_promotion(
            checkpoint,
            requested_by="principal/ops",
            requested_at=LATER_AT,
            evidence_refs=("evidence/sim-run-1",),
            valid_until=MUCH_LATER_AT,
        )
        validation = perform_fresh_validation(
            request,
            checkpoint,
            validator="principal/validator",
            validated_at=LATER_AT,
            result=ValidationVerdict.PASS,
            findings="state matches the evidence digest",
        )
        self.assertIsInstance(validation, FreshValidation)
        self.assertIs(validation.result, ValidationVerdict.PASS)
        decoded = FreshValidation.from_dict(validation.to_dict())
        self.assertEqual(decoded, validation)

    def test_authorization_requires_passing_fresh_validation(self) -> None:
        checkpoint = self._checkpoint()
        request = request_promotion(
            checkpoint,
            requested_by="principal/ops",
            requested_at=LATER_AT,
            evidence_refs=("evidence/sim-run-1",),
            valid_until=MUCH_LATER_AT,
        )
        failed = perform_fresh_validation(
            request,
            checkpoint,
            validator="principal/validator",
            validated_at=LATER_AT,
            result=ValidationVerdict.FAIL,
            findings="state diverged",
        )
        with self.assertRaises(CoreValidationError):
            decide_promotion_authorization(
                failed,
                authorized_by="principal/release-manager",
                authority_class="A3",
                decided_at=LATER_AT,
                decision=PromotionVerdict.APPROVED,
            )

    def test_authorization_without_any_validation_has_no_path(self) -> None:
        checkpoint = self._checkpoint()
        request = request_promotion(
            checkpoint,
            requested_by="principal/ops",
            requested_at=LATER_AT,
            evidence_refs=("evidence/sim-run-1",),
            valid_until=MUCH_LATER_AT,
        )
        validation = perform_fresh_validation(
            request,
            checkpoint,
            validator="principal/validator",
            validated_at=LATER_AT,
            result=ValidationVerdict.PASS,
        )
        authorization = decide_promotion_authorization(
            validation,
            authorized_by="principal/release-manager",
            authority_class="A3",
            decided_at=LATER_AT,
            decision=PromotionVerdict.APPROVED,
        )
        self.assertIsInstance(authorization, PromotionAuthorization)
        decoded = PromotionAuthorization.from_dict(authorization.to_dict())
        self.assertEqual(decoded, authorization)

    def test_authorized_promotion_never_carries_state(self) -> None:
        checkpoint = self._checkpoint()
        request = request_promotion(
            checkpoint,
            requested_by="principal/ops",
            requested_at=LATER_AT,
            evidence_refs=("evidence/sim-run-1",),
            valid_until=MUCH_LATER_AT,
        )
        validation = perform_fresh_validation(
            request,
            checkpoint,
            validator="principal/validator",
            validated_at=LATER_AT,
            result=ValidationVerdict.PASS,
        )
        authorization = decide_promotion_authorization(
            validation,
            authorized_by="principal/release-manager",
            authority_class="A3",
            decided_at=LATER_AT,
            decision=PromotionVerdict.APPROVED,
        )
        payload = authorization.to_dict()
        self.assertIn("authorization_id", payload)
        for key, value in payload.items():
            self.assertNotIsInstance(value, list)
        with self.assertRaises(CoreValidationError):
            PromotionAuthorization.from_dict(
                {**payload, "authorization_id": "promotion/other"}
            )

    def test_authorization_rejects_unknown_authority_class(self) -> None:
        checkpoint = self._checkpoint()
        request = request_promotion(
            checkpoint,
            requested_by="principal/ops",
            requested_at=LATER_AT,
            evidence_refs=("evidence/sim-run-1",),
            valid_until=MUCH_LATER_AT,
        )
        validation = perform_fresh_validation(
            request,
            checkpoint,
            validator="principal/validator",
            validated_at=LATER_AT,
            result=ValidationVerdict.PASS,
        )
        with self.assertRaises(CoreValidationError):
            decide_promotion_authorization(
                validation,
                authorized_by="principal/release-manager",
                authority_class="Z9",
                decided_at=LATER_AT,
                decision=PromotionVerdict.APPROVED,
            )


# ---------------------------------------------------------------------------
# 11. Deterministic scale (quality-attribute support).
# ---------------------------------------------------------------------------


class ScaleTests(unittest.TestCase):
    """Deterministic multi-step scenarios (no timing assertions here)."""

    def test_large_scenario_is_deterministic(self) -> None:
        def run_scenario() -> tuple[str, str]:
            runtime = make_runtime(environment_id=ENV_REPLAY)
            runtime.submit(make_create_command(ENV_REPLAY))
            for step in range(120):
                runtime.submit(
                    make_route_command(
                        ENV_REPLAY,
                        command_id=f"cmd/route-{step}",
                        expected_version=step + 1,
                    )
                )
            return runtime.state_digest, parity_digest(runtime.journal)

        first = run_scenario()
        second = run_scenario()
        self.assertEqual(first, second)
        self.assertEqual(len(first), 2)


if __name__ == "__main__":
    unittest.main()
