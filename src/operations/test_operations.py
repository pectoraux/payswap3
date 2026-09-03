"""Contract suite for the operations domain (WORK-024) — authored red-first.

WORK-024 — resilience, observability and recovery — owns ``src/operations/``:
the declared dependency graph, resilience profiles, health/economic metrics,
the frozen v0.1 ``Operations`` command family
``DeclareDegradation/Failover/Incident/Emergency/Resolve`` bound to the REAL
transition kernel, and recovery orchestration evidence. This suite was
authored BEFORE the implementation existed and was persisted RED at
``/home/z/red-w024.txt`` (missing ``src.operations`` public names).
"""

from __future__ import annotations

import ast
import subprocess
import sys
import unittest
from pathlib import Path

from src.core.errors import CoreValidationError
from src.evidence.contracts import EpistemicType
from src.transition.registry import PROTOCOL_VERSION

from src.operations import (
    AuthorityRebuild,
    COMMAND_EVENT_TYPES,
    DEGRADATION_SEVERITY_ORDER,
    DEPENDENCY_OBJECT_TYPE,
    INCIDENT_OBJECT_TYPE,
    INCIDENT_TERMINAL_STATES,
    OBJECT_TYPES,
    OPERATIONS_API_VERSION,
    OPERATIONS_COMMANDS,
    OPERATIONS_EVENT_NAMESPACE,
    OPERATIONS_PROTOCOL_VERSION,
    OPERATIONS_SCHEMA_VERSION,
    OPERATIONS_TRANSITIONS,
    RESILIENCE_PROFILE_OBJECT_TYPE,
    SYSTEMIC_RISK_OBJECT_TYPE,
    DegradationFact,
    DegradationSeverity,
    Dependency,
    DependencyKind,
    EmergencyFact,
    FailoverFact,
    HealthSnapshot,
    HealthStatus,
    Incident,
    IncidentSpec,
    IncidentState,
    OperationsEngine,
    OperationsTransition,
    ProbeResult,
    RecoveryActionKind,
    ResilienceProfile,
    ResolutionFact,
    SystemicRiskAssessment,
    assess_systemic_risk,
    classify_health,
    economic_exposure,
    health_snapshot,
    make_dependency_record,
    make_incident_record,
    make_profile_record,
    probe_digest,
    validate_command,
    DEFAULT_COMMAND_AUTHORITY_CLASS,
    DEFAULT_ENGINE_ACTOR,
    advance_envelope,
    build_domain_envelope,
    composite_to_dict,
    composite_to_json,
    decode_composite,
    decode_composite_json,
    seal_composite,
    verify_composite,
)

from src.operations.metrics import EconomicExposure
from src.operations.dogfooding import build_transcript as dogfood_transcript


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

T0 = "2026-09-10T00:00:00Z"
T1 = "2026-09-10T00:05:00Z"
T2 = "2026-09-10T00:07:00Z"
T3 = "2026-09-10T00:09:00Z"
T4 = "2026-09-10T00:12:00Z"
T5 = "2026-09-10T00:20:00Z"
LATE = "2026-09-10T09:00:00Z"

ENV = "env/test-operations-024"
DOMAIN = "domain/operations"

RAIL_A = "operations/dependency/provider-a"
RAIL_B = "operations/dependency/provider-b"
PEER_DOMAIN = "operations/dependency/federation-peer"
CLEARING_DEP = "operations/dependency/clearing-execution"
EXECUTION_SERVICE = "operations/service/payment-execution"
FEDERATION_SERVICE = "operations/service/federation-peer"
CLEARING_SERVICE = "operations/service/clearing"

ADAPTER_B_CONTRACT = {
    "adapter_id": "interoperability/adapter/provider-b",
    "fidelity_class": "SIMULATION",
    "effect_operations": ("SUBMIT_PAYMENT",),
}


def probe(
    dependency_id: str,
    *,
    as_of: str = T1,
    availability_bps: int = 10000,
    probe_id: str | None = None,
    detail: str = "probe ok",
    samples: int = 1,
    epistemic: EpistemicType = EpistemicType.OBSERVED,
) -> ProbeResult:
    return ProbeResult(
        probe_id=probe_id if probe_id is not None else f"operations/probe/{dependency_id.rsplit('/', 1)[-1]}",
        dependency_id=dependency_id,
        as_of=as_of,
        epistemic=epistemic,
        availability_bps=availability_bps,
        samples=samples,
        detail=detail,
    )


def dependency(
    dependency_id: str,
    *,
    kind: DependencyKind = DependencyKind.PROVIDER_ADAPTER,
    service_id: str = EXECUTION_SERVICE,
    depends_on: tuple[str, ...] = (),
    critical: bool = True,
    note: str = "declared dependency",
) -> Dependency:
    return make_dependency_record(
        dependency_id=dependency_id,
        kind=kind,
        service_id=service_id,
        depends_on=depends_on,
        critical=critical,
        note=note,
        environment_id=ENV,
        domain_id=DOMAIN,
    )


def profile(
    service_id: str = EXECUTION_SERVICE,
    *,
    redundancy: tuple[str, ...] = (RAIL_B,),
    degraded_below_bps: int = 9500,
    unavailable_below_bps: int = 5000,
    recovery_actions: tuple[RecoveryActionKind, ...] | None = None,
    recovery_time_objective_seconds: int = 3600,
) -> ResilienceProfile:
    return make_profile_record(
        service_id=service_id,
        availability_target_bps=9990,
        degraded_below_bps=degraded_below_bps,
        unavailable_below_bps=unavailable_below_bps,
        redundancy=redundancy,
        recovery_actions=recovery_actions
        if recovery_actions is not None
        else (
            RecoveryActionKind.REPROBE,
            RecoveryActionKind.RECONCILE,
            RecoveryActionKind.RETRY,
            RecoveryActionKind.REBUILD,
        ),
        recovery_time_objective_seconds=recovery_time_objective_seconds,
        recovery_point_objective_seconds=60,
        note="declared resilience profile",
        environment_id=ENV,
        domain_id=DOMAIN,
    )


def graph() -> "DependencyGraphFixture":
    from src.operations import DependencyGraph

    return DependencyGraph.build(
        (
            dependency(RAIL_A, service_id=EXECUTION_SERVICE),
            dependency(RAIL_B, service_id=EXECUTION_SERVICE),
            dependency(
                PEER_DOMAIN,
                kind=DependencyKind.NETWORK_DOMAIN,
                service_id=FEDERATION_SERVICE,
            ),
            dependency(
                CLEARING_DEP,
                kind=DependencyKind.PROTOCOL_SERVICE,
                service_id=CLEARING_SERVICE,
                depends_on=(RAIL_A,),
                critical=True,
                note="clearing depends on payment execution",
            ),
        )
    )


def profiles() -> dict[str, ResilienceProfile]:
    return {
        EXECUTION_SERVICE: profile(EXECUTION_SERVICE),
        FEDERATION_SERVICE: profile(
            FEDERATION_SERVICE,
            redundancy=(PEER_DOMAIN,),
            recovery_actions=(RecoveryActionKind.REPROBE,),
            recovery_time_objective_seconds=7200,
        ),
        CLEARING_SERVICE: profile(CLEARING_SERVICE, redundancy=(RAIL_B,)),
    }


def engine() -> OperationsEngine:
    return OperationsEngine(
        environment_id=ENV,
        domain_id=DOMAIN,
        dependency_graph=graph(),
        resilience_profiles=profiles(),
    )


def dead_rail_a_probe(as_of: str = T1) -> ProbeResult:
    return probe(
        RAIL_A,
        as_of=as_of,
        availability_bps=0,
        detail="canary submission transport failure",
    )


def open_incident(target: OperationsEngine | None = None) -> OperationsEngine:
    target = target if target is not None else engine()
    target.open_incident(
        command_id="cmd-open-1",
        requested_at=T1,
        incident_id="operations/incident/inc-1",
        dependency_id=RAIL_A,
        trigger_probe=dead_rail_a_probe(),
        summary="provider A transport outage",
    )
    return target


def degraded_incident(target: OperationsEngine) -> OperationsEngine:
    target.declare_degradation(
        command_id="cmd-degrade-1",
        requested_at=T2,
        incident_id="operations/incident/inc-1",
        probe=dead_rail_a_probe(as_of=T2),
        affected_dependencies=(RAIL_A, PEER_DOMAIN),
        affected_authorities={"authority/execution": "a" * 64},
        detail="provider A dead, peer domain stale",
    )
    return target


def full_recovery_actions(at: str = T4) -> tuple:
    from src.operations import RecoveryActionRecord

    return tuple(
        RecoveryActionRecord(
            action=kind,
            authority_ref=None
            if kind is RecoveryActionKind.REPROBE
            else "authority/execution",
            detail="action executed",
            at=at,
        )
        for kind in (
            RecoveryActionKind.REPROBE,
            RecoveryActionKind.RECONCILE,
            RecoveryActionKind.RETRY,
            RecoveryActionKind.REBUILD,
        )
    )


# ---------------------------------------------------------------------------
# static boundary
# ---------------------------------------------------------------------------


class StaticBoundaryTests(unittest.TestCase):
    """The typed, versioned public boundary is frozen and deterministic."""

    def test_import_closure_is_pure_in_isolated_process(self) -> None:
        code = (
            "import sys; sys.path.insert(0, '.'); "
            "import src.operations; "
            "print([m for m in sys.modules if m.startswith('src.')])"
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            cwd=Path(__file__).resolve().parents[2],
            timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        modules = eval(result.stdout)
        banned = ("src.intent", "src.market", "src.liquidity", "src.safety", "src.trust")
        for module in banned:
            self.assertNotIn(module, modules, f"unexpected import of {module}")

    def test_all_is_sorted_and_unique(self) -> None:
        import src.operations as package

        exported = package.__all__
        self.assertEqual(exported, sorted(exported))
        self.assertEqual(len(exported), len(set(exported)))
        for name in exported:
            self.assertTrue(hasattr(package, name), name)

    def test_versions_are_frozen(self) -> None:
        self.assertEqual(OPERATIONS_API_VERSION, "v0.1")
        self.assertEqual(OPERATIONS_PROTOCOL_VERSION, PROTOCOL_VERSION)
        self.assertEqual(OPERATIONS_SCHEMA_VERSION, 1)

    def test_object_types_are_internal_operations_formats(self) -> None:
        for object_type in OBJECT_TYPES:
            self.assertTrue(object_type.startswith("operations/"))
            self.assertTrue(object_type.endswith("/v1"))
        self.assertEqual(
            set(OBJECT_TYPES),
            {
                DEPENDENCY_OBJECT_TYPE,
                RESILIENCE_PROFILE_OBJECT_TYPE,
                INCIDENT_OBJECT_TYPE,
                SYSTEMIC_RISK_OBJECT_TYPE,
            },
        )

    def test_event_namespace_is_registered_governance(self) -> None:
        # No operations namespace exists in the frozen registry; the
        # governance namespace (the federation/agents precedent; the
        # governance.md emergency-authority scope) is used exactly as
        # registered — never invented.
        self.assertEqual(OPERATIONS_EVENT_NAMESPACE, "governance")
        for event_type in COMMAND_EVENT_TYPES.values():
            self.assertTrue(event_type.startswith("governance/"))

    def test_frozen_command_family(self) -> None:
        self.assertEqual(
            OPERATIONS_COMMANDS,
            frozenset(
                {
                    "operations/incident",
                    "operations/declare-degradation",
                    "operations/failover",
                    "operations/emergency",
                    "operations/resolve",
                }
            ),
        )
        self.assertEqual(set(COMMAND_EVENT_TYPES), set(OPERATIONS_COMMANDS))
        self.assertEqual(len(COMMAND_EVENT_TYPES), 5)

    def test_no_wall_clock_or_entropy_in_domain_modules(self) -> None:
        package_root = Path(__file__).resolve().parent
        banned_calls = {"now", "today", "utcnow", "monotonic", "random", "randint", "urandom", "uuid4", "uuid1"}
        banned_imports = ("random", "uuid", "time")
        for module_path in sorted(package_root.glob("*.py")):
            tree = ast.parse(module_path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    function = node.func
                    name = (
                        function.attr
                        if isinstance(function, ast.Attribute)
                        else function.id
                        if isinstance(function, ast.Name)
                        else ""
                    )
                    self.assertNotIn(
                        name,
                        banned_calls,
                        f"{module_path.name}:{node.lineno} calls {name}",
                    )
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertNotIn(
                            alias.name.split(".")[0],
                            banned_imports,
                            f"{module_path.name} imports {alias.name}",
                        )
                if isinstance(node, ast.ImportFrom):
                    if node.module and node.module.split(".")[0] in banned_imports:
                        self.fail(f"{module_path.name} imports {node.module}")

    def test_default_engine_identity(self) -> None:
        self.assertEqual(DEFAULT_ENGINE_ACTOR, "principal/operations-service")
        self.assertEqual(DEFAULT_COMMAND_AUTHORITY_CLASS, "A3")


# ---------------------------------------------------------------------------
# contracts
# ---------------------------------------------------------------------------


class ContractTests(unittest.TestCase):
    def test_validate_command_accepts_frozen_family(self) -> None:
        for command in OPERATIONS_COMMANDS:
            self.assertEqual(validate_command(command), command)

    def test_validate_command_rejects_unknown(self) -> None:
        from src.operations import validate_command

        for bad in ("", "operations/cancel", "clearing/cycle.create", "operations/resolve ", 5):
            with self.assertRaises(CoreValidationError):
                validate_command(bad)

    def test_incident_lifecycle_is_closed(self) -> None:
        self.assertEqual(
            {state.value for state in IncidentState},
            {"OPEN", "DEGRADED", "FAILED_OVER", "ESCALATED", "RESOLVED"},
        )
        self.assertEqual(INCIDENT_TERMINAL_STATES, frozenset({IncidentState.RESOLVED}))

    def test_transition_table_is_frozen(self) -> None:
        self.assertEqual(OPERATIONS_TRANSITIONS["operations/incident"], frozenset())
        self.assertEqual(
            OPERATIONS_TRANSITIONS["operations/declare-degradation"],
            frozenset({IncidentState.OPEN, IncidentState.DEGRADED}),
        )
        self.assertEqual(
            OPERATIONS_TRANSITIONS["operations/failover"],
            frozenset({IncidentState.DEGRADED}),
        )
        self.assertEqual(
            OPERATIONS_TRANSITIONS["operations/emergency"],
            frozenset(
                {
                    IncidentState.OPEN,
                    IncidentState.DEGRADED,
                    IncidentState.FAILED_OVER,
                }
            ),
        )
        self.assertEqual(
            OPERATIONS_TRANSITIONS["operations/resolve"],
            frozenset(
                {
                    IncidentState.OPEN,
                    IncidentState.DEGRADED,
                    IncidentState.FAILED_OVER,
                    IncidentState.ESCALATED,
                }
            ),
        )
        self.assertEqual(set(OPERATIONS_TRANSITIONS), set(OPERATIONS_COMMANDS))

    def test_severity_order_is_frozen(self) -> None:
        self.assertEqual(
            DEGRADATION_SEVERITY_ORDER,
            {DegradationSeverity.DEGRADED: 1, DegradationSeverity.UNAVAILABLE: 2},
        )

    def test_dependency_kind_vocabulary(self) -> None:
        self.assertEqual(
            {kind.value for kind in DependencyKind},
            {"PROVIDER_ADAPTER", "NETWORK_DOMAIN", "PROTOCOL_SERVICE"},
        )

    def test_recovery_action_vocabulary(self) -> None:
        self.assertEqual(
            {action.value for action in RecoveryActionKind},
            {"REPROBE", "RECONCILE", "RETRY", "REBUILD"},
        )

    def test_health_status_vocabulary(self) -> None:
        self.assertEqual(
            {status.value for status in HealthStatus},
            {"HEALTHY", "DEGRADED", "UNAVAILABLE"},
        )


# ---------------------------------------------------------------------------
# domain sealing
# ---------------------------------------------------------------------------


class SealTests(unittest.TestCase):
    def _envelope(self, state: str = "DECLARED"):
        from src.core.envelope import Provenance

        return build_domain_envelope(
            object_id="operations/dependency/x",
            object_type=DEPENDENCY_OBJECT_TYPE,
            state=state,
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=Provenance(issuer="principal/test", source="test", recorded_at=T0),
        )

    def test_build_and_verify_round_trip(self) -> None:
        envelope = self._envelope()
        payload = {"dependency_id": "operations/dependency/x"}
        digest = seal_composite(envelope, payload)
        verify_composite(envelope, payload, digest, "operations/dependency/x")

    def test_tampered_payload_fails_closed(self) -> None:
        envelope = self._envelope()
        digest = seal_composite(envelope, {"dependency_id": "operations/dependency/x"})
        with self.assertRaises(CoreValidationError):
            verify_composite(
                envelope, {"dependency_id": "operations/dependency/y"}, digest, "x"
            )

    def test_missing_digest_fails_closed(self) -> None:
        envelope = self._envelope()
        with self.assertRaises(CoreValidationError):
            verify_composite(envelope, {}, None, "x")

    def test_advance_envelope_bumps_version(self) -> None:
        from src.core.envelope import Provenance

        envelope = self._envelope()
        advanced = advance_envelope(
            envelope,
            state="DEGRADED",
            provenance=Provenance(issuer="principal/test", source="test", recorded_at=T1),
        )
        self.assertEqual(advanced.object_version, envelope.object_version + 1)
        self.assertEqual(advanced.state, "DEGRADED")

    def test_decode_rejects_registry_claim(self) -> None:
        envelope = self._envelope()
        payload = {"dependency_id": "operations/dependency/x"}
        digest = seal_composite(envelope, payload)
        composite = composite_to_dict(envelope, payload, digest)
        composite["envelope"]["object_type"] = "payswap/obligation/v1"
        with self.assertRaises(CoreValidationError):
            decode_composite(
                composite, object_type=DEPENDENCY_OBJECT_TYPE, state_type=IncidentState
            )

    def test_decode_rejects_wrong_state_vocabulary(self) -> None:
        envelope = self._envelope(state="NOT_A_STATE")
        payload = {"dependency_id": "operations/dependency/x"}
        digest = seal_composite(envelope, payload)
        composite = composite_to_dict(envelope, payload, digest)
        with self.assertRaises(CoreValidationError):
            decode_composite(
                composite, object_type=DEPENDENCY_OBJECT_TYPE, state_type=IncidentState
            )

    def test_decode_rejects_unknown_protocol_version(self) -> None:
        envelope = self._envelope()
        payload = {"dependency_id": "operations/dependency/x"}
        digest = seal_composite(envelope, payload)
        composite = composite_to_dict(envelope, payload, digest)
        composite["envelope"]["protocol_version"] = "v9.9"
        with self.assertRaises(CoreValidationError):
            decode_composite(
                composite, object_type=DEPENDENCY_OBJECT_TYPE, state_type=IncidentState
            )

    def test_decode_rejects_unknown_object_type(self) -> None:
        envelope = self._envelope()
        payload = {"dependency_id": "operations/dependency/x"}
        digest = seal_composite(envelope, payload)
        composite = composite_to_dict(envelope, payload, digest)
        with self.assertRaises(CoreValidationError):
            decode_composite(
                composite, object_type="operations/ghost/v1", state_type=IncidentState
            )

    def test_decode_json_round_trip(self) -> None:
        from src.operations import DependencyRecordState

        envelope = self._envelope()
        payload = {"dependency_id": "operations/dependency/x"}
        digest = seal_composite(envelope, payload)
        decoded = decode_composite_json(
            composite_to_json(envelope, payload, digest),
            object_type=DEPENDENCY_OBJECT_TYPE,
            state_type=DependencyRecordState,
        )
        self.assertEqual(decoded[2], digest)


# ---------------------------------------------------------------------------
# dependency graph
# ---------------------------------------------------------------------------


class GraphTests(unittest.TestCase):
    def test_build_valid_graph(self) -> None:
        from src.operations import DependencyGraph

        built = graph()
        self.assertEqual(len(built.dependencies()), 4)
        self.assertEqual(built.service_of(RAIL_A), EXECUTION_SERVICE)

    def test_duplicate_dependency_rejected(self) -> None:
        from src.operations import DependencyGraph

        with self.assertRaises(CoreValidationError):
            DependencyGraph.build(
                (dependency(RAIL_A), dependency(RAIL_A, note="duplicate"))
            )

    def test_unknown_depends_on_reference_rejected(self) -> None:
        from src.operations import DependencyGraph

        with self.assertRaises(CoreValidationError):
            DependencyGraph.build(
                (dependency(RAIL_A, depends_on=("operations/dependency/ghost",)),)
            )

    def test_dependency_cycle_rejected(self) -> None:
        from src.operations import DependencyGraph

        with self.assertRaises(CoreValidationError):
            DependencyGraph.build(
                (
                    dependency(RAIL_A, depends_on=(RAIL_B,)),
                    dependency(RAIL_B, depends_on=(RAIL_A,)),
                )
            )

    def test_self_dependency_rejected(self) -> None:
        from src.operations import DependencyGraph

        with self.assertRaises(CoreValidationError):
            DependencyGraph.build((dependency(RAIL_A, depends_on=(RAIL_A,)),))

    def test_unknown_dependency_lookup_fails_closed(self) -> None:
        with self.assertRaises(CoreValidationError):
            graph().dependency("operations/dependency/ghost")

    def test_dependents_of_is_transitive(self) -> None:
        from src.operations import DependencyGraph

        built = DependencyGraph.build(
            (
                dependency(RAIL_A),
                dependency(
                    "operations/dependency/execution-service",
                    kind=DependencyKind.PROTOCOL_SERVICE,
                    service_id=EXECUTION_SERVICE,
                    depends_on=(RAIL_A,),
                ),
                dependency(
                    "operations/dependency/clearing",
                    kind=DependencyKind.PROTOCOL_SERVICE,
                    service_id=CLEARING_SERVICE,
                    depends_on=("operations/dependency/execution-service",),
                ),
            )
        )
        dependents = built.dependents_of(RAIL_A)
        self.assertIn("operations/dependency/execution-service", dependents)
        self.assertIn("operations/dependency/clearing", dependents)
        self.assertNotIn(RAIL_A, dependents)

    def test_graph_digest_is_deterministic(self) -> None:
        self.assertEqual(graph().digest, graph().digest)

    def test_dependency_record_is_sealed_composite(self) -> None:
        record = dependency(RAIL_A)
        self.assertEqual(record.object_id, RAIL_A)
        self.assertEqual(record.envelope.object_type, DEPENDENCY_OBJECT_TYPE)
        with self.assertRaises(CoreValidationError):
            Dependency.from_dict(
                {
                    "envelope": record.envelope.to_dict(),
                    "spec": dict(record.spec.to_dict(), service_id="operations/service/other"),
                    "integrity_hash": record.integrity_hash,
                }
            )

    def test_dependency_spec_validation(self) -> None:
        with self.assertRaises(CoreValidationError):
            dependency("")
        with self.assertRaises(CoreValidationError):
            dependency(RAIL_A, service_id="")
        with self.assertRaises(CoreValidationError):
            dependency(RAIL_A, depends_on=("",))


# ---------------------------------------------------------------------------
# resilience profiles
# ---------------------------------------------------------------------------


class ProfileTests(unittest.TestCase):
    def test_profile_record_round_trip(self) -> None:
        record = profile()
        self.assertEqual(record.object_id, f"operations/profile/{EXECUTION_SERVICE}")
        decoded = ResilienceProfile.from_dict(record.to_dict())
        self.assertEqual(decoded, record)

    def test_threshold_ordering_gates(self) -> None:
        with self.assertRaises(CoreValidationError):
            profile(degraded_below_bps=5000, unavailable_below_bps=9500)
        with self.assertRaises(CoreValidationError):
            profile(degraded_below_bps=10001)
        with self.assertRaises(CoreValidationError):
            profile(unavailable_below_bps=-1)
        with self.assertRaises(CoreValidationError):
            profile(degraded_below_bps=9500, unavailable_below_bps=9500)

    def test_engine_rejects_undeclared_redundancy_targets(self) -> None:
        from src.operations import DependencyGraph

        ghost_profile = make_profile_record(
            service_id=EXECUTION_SERVICE,
            availability_target_bps=9990,
            degraded_below_bps=9500,
            unavailable_below_bps=5000,
            redundancy=("operations/dependency/ghost",),
            recovery_actions=(RecoveryActionKind.REPROBE,),
            recovery_time_objective_seconds=3600,
            recovery_point_objective_seconds=60,
            note="redundancy target is not declared in the graph",
            environment_id=ENV,
            domain_id=DOMAIN,
        )
        with self.assertRaises(CoreValidationError):
            OperationsEngine(
                environment_id=ENV,
                domain_id=DOMAIN,
                dependency_graph=DependencyGraph.build(
                    (dependency(RAIL_A), dependency(RAIL_B))
                ),
                resilience_profiles={EXECUTION_SERVICE: ghost_profile},
            )

    def test_recovery_actions_must_be_non_empty(self) -> None:
        with self.assertRaises(CoreValidationError):
            profile(recovery_actions=())

    def test_recovery_time_objective_must_be_positive(self) -> None:
        with self.assertRaises(CoreValidationError):
            profile(recovery_time_objective_seconds=0)
        with self.assertRaises(CoreValidationError):
            profile(recovery_time_objective_seconds=-5)

    def test_classify_health_thresholds_are_load_bearing(self) -> None:
        service_profile = profile()
        healthy = probe(RAIL_A, availability_bps=9500)
        degraded = probe(RAIL_A, availability_bps=9499)
        middle = probe(RAIL_A, availability_bps=5000)
        worst = probe(RAIL_A, availability_bps=4999)
        bottom = probe(RAIL_A, availability_bps=0)
        self.assertIs(classify_health(healthy, service_profile), HealthStatus.HEALTHY)
        self.assertIs(classify_health(degraded, service_profile), HealthStatus.DEGRADED)
        self.assertIs(classify_health(middle, service_profile), HealthStatus.DEGRADED)
        self.assertIs(classify_health(worst, service_profile), HealthStatus.UNAVAILABLE)
        self.assertIs(classify_health(bottom, service_profile), HealthStatus.UNAVAILABLE)

    def test_classify_health_requires_matching_profile_service(self) -> None:
        # the profile's service must match the dependency's owning service
        with self.assertRaises(CoreValidationError):
            classify_health(
                probe(PEER_DOMAIN),
                profile(EXECUTION_SERVICE),
                dependency_service=FEDERATION_SERVICE,
            )


# ---------------------------------------------------------------------------
# metrics: probes, health snapshots, exposure, systemic risk
# ---------------------------------------------------------------------------


class MetricsTests(unittest.TestCase):
    def test_probe_result_validation(self) -> None:
        with self.assertRaises(CoreValidationError):
            probe(RAIL_A, availability_bps=10001)
        with self.assertRaises(CoreValidationError):
            probe(RAIL_A, availability_bps=-1)
        with self.assertRaises(CoreValidationError):
            probe(RAIL_A, samples=0)
        with self.assertRaises(CoreValidationError):
            probe(RAIL_A, as_of="2026-09-10T00:00:00+00:00")
        with self.assertRaises(CoreValidationError):
            probe(RAIL_A, detail="")
        with self.assertRaises(CoreValidationError):
            probe(RAIL_A, probe_id="")

    def test_probe_epistemic_must_be_observed(self) -> None:
        with self.assertRaises(CoreValidationError):
            probe(RAIL_A, epistemic=EpistemicType.SIMULATED)
        with self.assertRaises(CoreValidationError):
            probe(RAIL_A, epistemic=EpistemicType.PREDICTED)

    def test_probe_round_trip(self) -> None:
        result = probe(RAIL_A)
        decoded = ProbeResult.from_dict(result.to_dict())
        self.assertEqual(decoded, result)

    def test_probe_from_dict_rejects_non_canonical_fields(self) -> None:
        canonical = probe(RAIL_A).to_dict()
        with self.assertRaises(CoreValidationError):
            ProbeResult.from_dict({**canonical, "extra": "undeclared field"})
        missing = {key: value for key, value in canonical.items() if key != "detail"}
        with self.assertRaises(CoreValidationError):
            ProbeResult.from_dict(missing)

    def test_probe_digest_is_deterministic_and_binding(self) -> None:
        first = probe(RAIL_A)
        second = probe(RAIL_B)
        self.assertEqual(probe_digest(first), probe_digest(first))
        self.assertNotEqual(probe_digest(first), probe_digest(second))
        self.assertNotEqual(probe_digest(first), probe_digest(probe(RAIL_A, as_of=T2)))

    def test_health_snapshot_classification(self) -> None:
        snapshot = health_snapshot(
            (
                probe(RAIL_A, availability_bps=0),
                probe(RAIL_B, availability_bps=10000),
                probe(PEER_DOMAIN, availability_bps=7000),
            ),
            graph(),
            profiles(),
        )
        self.assertIsInstance(snapshot, HealthSnapshot)
        statuses = dict(snapshot.statuses)
        self.assertIs(statuses[RAIL_A], HealthStatus.UNAVAILABLE)
        self.assertIs(statuses[RAIL_B], HealthStatus.HEALTHY)
        self.assertIs(statuses[PEER_DOMAIN], HealthStatus.DEGRADED)
        self.assertEqual(snapshot.as_of, T1)

    def test_health_snapshot_requires_same_instant(self) -> None:
        with self.assertRaises(CoreValidationError):
            health_snapshot(
                (probe(RAIL_A, as_of=T1), probe(RAIL_B, as_of=T2)),
                graph(),
                profiles(),
            )

    def test_health_snapshot_rejects_unknown_dependency(self) -> None:
        with self.assertRaises(CoreValidationError):
            health_snapshot((probe("operations/dependency/ghost"),), graph(), profiles())

    def test_health_snapshot_rejects_missing_profile(self) -> None:
        built = graph()
        with self.assertRaises(CoreValidationError):
            health_snapshot((probe(RAIL_A),), built, {})

    def test_health_snapshot_rejects_duplicate_dependency(self) -> None:
        with self.assertRaises(CoreValidationError):
            health_snapshot(
                (probe(RAIL_A), probe(RAIL_A, as_of=T1)), graph(), profiles()
            )

    def test_health_snapshot_digest_is_deterministic(self) -> None:
        probes = (probe(RAIL_A, availability_bps=0), probe(RAIL_B))
        self.assertEqual(
            health_snapshot(probes, graph(), profiles()).digest,
            health_snapshot(probes, graph(), profiles()).digest,
        )
        self.assertNotEqual(
            health_snapshot(probes, graph(), profiles()).digest,
            health_snapshot(
                (probe(RAIL_A, availability_bps=10000), probe(RAIL_B)),
                graph(),
                profiles(),
            ).digest,
        )

    def test_economic_exposure_from_real_clearing_obligations(self) -> None:
        from src.clearing import ClearingEngine
        from src.clearing.dogfooding import ACCRA, NYC, USD, _effect_result_for

        clearing = ClearingEngine(environment_id=ENV, domain_id="domain/clearing")
        clearing.create_cycle(
            command_id="cmd-cycle",
            requested_at=T0,
            cycle_id="clearing/cycle/ops-1",
            opens_at=T0,
            closes_at=T1,
        )
        clearing.recognize_obligation(
            command_id="cmd-rec-1",
            requested_at=T0,
            cycle_id="clearing/cycle/ops-1",
            effect_result=_effect_result_for("ops", 1, ACCRA, NYC, USD, 10_000),
            due_from=T1,
            due_until=LATE,
        )
        clearing.recognize_obligation(
            command_id="cmd-rec-2",
            requested_at=T0,
            cycle_id="clearing/cycle/ops-1",
            effect_result=_effect_result_for("ops", 2, NYC, ACCRA, USD, 4_000),
            due_from=T1,
            due_until=LATE,
        )
        obligations = [
            record
            for record in clearing.records()
            if record.envelope.object_type == "payswap/obligation/v1"
        ]
        self.assertEqual(len(obligations), 2)
        exposure = economic_exposure(obligations)
        self.assertIsInstance(exposure, EconomicExposure)
        self.assertEqual(exposure.obligation_count, 2)
        self.assertEqual(exposure.outstanding_count, 2)
        self.assertEqual(exposure.asset_totals, ((USD, 14_000, 2),))

    def test_economic_exposure_excludes_terminal_obligations(self) -> None:
        from src.clearing import ClearingEngine
        from src.clearing.dogfooding import ACCRA, NYC, USD, _effect_result_for

        clearing = ClearingEngine(environment_id=ENV, domain_id="domain/clearing")
        clearing.create_cycle(
            command_id="cmd-cycle",
            requested_at=T0,
            cycle_id="clearing/cycle/ops-1",
            opens_at=T0,
            closes_at=T1,
        )
        clearing.recognize_obligation(
            command_id="cmd-rec-1",
            requested_at=T0,
            cycle_id="clearing/cycle/ops-1",
            effect_result=_effect_result_for("ops", 1, ACCRA, NYC, USD, 10_000),
            due_from=T1,
            due_until=LATE,
        )
        obligation_id = "plan/dogfood-015-ops-1/request/1/result/obligation"
        clearing.validate_obligation(
            command_id="cmd-val-1", requested_at=T0, obligation_id=obligation_id
        )
        clearing.mark_due_obligation(
            command_id="cmd-due-1", requested_at=T1, obligation_id=obligation_id
        )
        clearing.resolve_obligation(
            command_id="cmd-res-1",
            requested_at=T2,
            obligation_id=obligation_id,
            evidence_ref="evidence/observation/ops-1",
            evidence_digest="a" * 64,
            reason="discharge recorded",
        )
        obligations = [
            record
            for record in clearing.records()
            if record.envelope.object_type == "payswap/obligation/v1"
        ]
        exposure = economic_exposure(obligations)
        self.assertEqual(exposure.obligation_count, 1)
        self.assertEqual(exposure.outstanding_count, 0)
        self.assertEqual(exposure.asset_totals, ())

    def test_economic_exposure_rejects_non_obligations(self) -> None:
        with self.assertRaises(CoreValidationError):
            economic_exposure(({"not": "an obligation"},))

    def test_economic_exposure_digest_is_deterministic(self) -> None:
        from src.clearing import ClearingEngine
        from src.clearing.dogfooding import ACCRA, NYC, USD, _effect_result_for

        clearing = ClearingEngine(environment_id=ENV, domain_id="domain/clearing")
        clearing.create_cycle(
            command_id="cmd-cycle",
            requested_at=T0,
            cycle_id="clearing/cycle/ops-1",
            opens_at=T0,
            closes_at=T1,
        )
        clearing.recognize_obligation(
            command_id="cmd-rec-1",
            requested_at=T0,
            cycle_id="clearing/cycle/ops-1",
            effect_result=_effect_result_for("ops", 1, ACCRA, NYC, USD, 10_000),
            due_from=T1,
            due_until=LATE,
        )
        obligations = [
            record
            for record in clearing.records()
            if record.envelope.object_type == "payswap/obligation/v1"
        ]
        self.assertEqual(
            economic_exposure(obligations).digest,
            economic_exposure(obligations).digest,
        )

    def test_systemic_risk_propagation_is_transitive(self) -> None:
        snapshot = health_snapshot(
            (
                probe(RAIL_A, availability_bps=0),
                probe(RAIL_B, availability_bps=10000),
                probe(PEER_DOMAIN, availability_bps=0),
            ),
            graph(),
            profiles(),
        )
        assessment = assess_systemic_risk(graph(), snapshot)
        self.assertIsInstance(assessment, SystemicRiskAssessment)
        self.assertIn(RAIL_A, assessment.failed_dependencies)
        self.assertIn(PEER_DOMAIN, assessment.failed_dependencies)
        self.assertIn(CLEARING_DEP, assessment.affected_dependencies)
        self.assertIn(RAIL_A, assessment.affected_dependencies)
        self.assertIn(PEER_DOMAIN, assessment.affected_dependencies)
        self.assertIn(EXECUTION_SERVICE, assessment.affected_services)
        self.assertIn(FEDERATION_SERVICE, assessment.affected_services)
        self.assertIn(CLEARING_SERVICE, assessment.affected_services)
        self.assertNotIn(RAIL_B, assessment.affected_dependencies)

    def test_systemic_risk_healthy_snapshot_has_no_failures(self) -> None:
        snapshot = health_snapshot(
            (probe(RAIL_A), probe(RAIL_B), probe(PEER_DOMAIN)),
            graph(),
            profiles(),
        )
        assessment = assess_systemic_risk(graph(), snapshot)
        self.assertEqual(assessment.failed_dependencies, ())
        self.assertEqual(assessment.affected_dependencies, ())
        self.assertEqual(assessment.affected_services, ())

    def test_systemic_risk_digest_is_deterministic(self) -> None:
        snapshot = health_snapshot(
            (probe(RAIL_A, availability_bps=0), probe(RAIL_B)), graph(), profiles()
        )
        self.assertEqual(
            assess_systemic_risk(graph(), snapshot).digest,
            assess_systemic_risk(graph(), snapshot).digest,
        )

    def test_systemic_risk_counts_degraded_band_as_failed(self) -> None:
        # 7000 bps sits strictly inside the DEGRADED band (5000 <= 7000 <
        # 9500): a degraded dependency is a failure for stress propagation,
        # not only an unavailable one — its dependents are affected too.
        snapshot = health_snapshot(
            (
                probe(RAIL_A, availability_bps=7000),
                probe(RAIL_B, availability_bps=10000),
                probe(PEER_DOMAIN, availability_bps=10000),
            ),
            graph(),
            profiles(),
        )
        assessment = assess_systemic_risk(graph(), snapshot)
        self.assertEqual(assessment.failed_dependencies, (RAIL_A,))
        self.assertIn(RAIL_A, assessment.affected_dependencies)
        self.assertIn(CLEARING_DEP, assessment.affected_dependencies)
        self.assertIn(EXECUTION_SERVICE, assessment.affected_services)
        self.assertIn(CLEARING_SERVICE, assessment.affected_services)
        self.assertNotIn(RAIL_B, assessment.affected_dependencies)
        self.assertNotIn(PEER_DOMAIN, assessment.affected_dependencies)


# ---------------------------------------------------------------------------
# incident records and facts
# ---------------------------------------------------------------------------


class IncidentRecordTests(unittest.TestCase):
    def _spec(self, **overrides) -> IncidentSpec:
        base = dict(
            incident_id="operations/incident/inc-1",
            dependency_id=RAIL_A,
            summary="s",
            trigger_probe_digest="a" * 64,
            trigger_as_of=T1,
            opened_at=T1,
            severity=DegradationSeverity.UNAVAILABLE,
            degradation_facts=(),
            failover_fact=None,
            emergency_fact=None,
            resolution_fact=None,
        )
        base.update(overrides)
        return IncidentSpec(**base)

    def test_incident_spec_validation(self) -> None:
        with self.assertRaises(CoreValidationError):
            self._spec(incident_id="")
        with self.assertRaises(CoreValidationError):
            self._spec(trigger_probe_digest="not-a-digest")

    def test_degradation_fact_validation(self) -> None:
        with self.assertRaises(CoreValidationError):
            DegradationFact(
                severity=DegradationSeverity.DEGRADED,
                probe_digest="not-a-digest",
                probe_as_of=T2,
                affected_dependencies=(RAIL_A,),
                affected_authorities=(("authority/execution", "a" * 64),),
                observed_at=T2,
                detail="d",
            )
        with self.assertRaises(CoreValidationError):
            DegradationFact(
                severity=DegradationSeverity.DEGRADED,
                probe_digest="a" * 64,
                probe_as_of=T2,
                affected_dependencies=(),
                affected_authorities=(("authority/execution", "a" * 64),),
                observed_at=T2,
                detail="d",
            )

    def test_recovery_action_record_validation(self) -> None:
        with self.assertRaises(CoreValidationError):
            from src.operations import RecoveryActionRecord

            RecoveryActionRecord(
                action=RecoveryActionKind.RECONCILE,
                authority_ref=None,
                detail="",
                at=T3,
            )
        with self.assertRaises(CoreValidationError):
            from src.operations import RecoveryActionRecord

            RecoveryActionRecord(
                action=RecoveryActionKind.RECONCILE,
                authority_ref="",
                detail="d",
                at=T3,
            )

    def test_authority_rebuild_validation(self) -> None:
        with self.assertRaises(CoreValidationError):
            AuthorityRebuild(
                authority_ref="authority/execution",
                live_index_digest="a" * 64,
                rebuilt_index_digest="b" * 64,
            )
        valid = AuthorityRebuild(
            authority_ref="authority/execution",
            live_index_digest="a" * 64,
            rebuilt_index_digest="a" * 64,
        )
        self.assertEqual(valid.live_index_digest, valid.rebuilt_index_digest)
        with self.assertRaises(CoreValidationError):
            AuthorityRebuild(
                authority_ref="",
                live_index_digest="a" * 64,
                rebuilt_index_digest="a" * 64,
            )

    def test_incident_record_seal_tamper_rejected(self) -> None:
        target = degraded_incident(open_incident())
        record = target.incident("operations/incident/inc-1")
        composite = record.to_dict()
        composite["spec"]["severity"] = "DEGRADED"
        with self.assertRaises(CoreValidationError):
            Incident.from_dict(composite)

    def test_failover_fact_validation(self) -> None:
        with self.assertRaises(CoreValidationError):
            FailoverFact(
                from_dependency=RAIL_A,
                target_dependency=RAIL_B,
                target_probe_digest="c" * 64,
                target_probe_as_of=T3,
                adapter_contract={
                    "adapter_id": "interoperability/adapter/provider-b",
                    "fidelity_class": "SHADOW",
                    "effect_operations": ("SUBMIT_PAYMENT",),
                },
                authority_digests=(("authority/execution", "a" * 64),),
                executed_at=T3,
                detail="d",
            )

    def test_emergency_fact_validation(self) -> None:
        with self.assertRaises(CoreValidationError):
            EmergencyFact(
                window_from=T3,
                window_until=T2,  # inverted window
                mandate="m",
                scope=(RAIL_A,),
                declared_at=T3,
            )
        with self.assertRaises(CoreValidationError):
            EmergencyFact(
                window_from=T3,
                window_until=T5,
                mandate="",
                scope=(RAIL_A,),
                declared_at=T3,
            )

    def test_make_incident_record_requires_degradation_severity(self) -> None:
        from src.core.envelope import Provenance

        with self.assertRaises(CoreValidationError):
            make_incident_record(
                incident_id="operations/incident/inc-x",
                dependency_id=RAIL_A,
                summary="s",
                trigger_probe_digest="a" * 64,
                trigger_as_of=T1,
                opened_at=T1,
                severity="HEALTHY",  # not a degradation severity
                environment_id=ENV,
                domain_id=DOMAIN,
                provenance=Provenance(
                    issuer="principal/test", source="test", recorded_at=T1
                ),
            )


# ---------------------------------------------------------------------------
# engine: the frozen command family through the real kernel
# ---------------------------------------------------------------------------


class EngineLifecycleTests(unittest.TestCase):
    def test_open_incident_requires_unhealthy_trigger(self) -> None:
        target = engine()
        with self.assertRaises(CoreValidationError):
            target.open_incident(
                command_id="cmd-open",
                requested_at=T1,
                incident_id="operations/incident/inc-1",
                dependency_id=RAIL_A,
                trigger_probe=probe(RAIL_A, as_of=T1, availability_bps=10000),
            )

    def test_open_incident_requires_declared_dependency(self) -> None:
        target = engine()
        with self.assertRaises(CoreValidationError):
            target.open_incident(
                command_id="cmd-open",
                requested_at=T1,
                incident_id="operations/incident/inc-1",
                dependency_id="operations/dependency/ghost",
                trigger_probe=probe(
                    "operations/dependency/ghost", availability_bps=0
                ),
            )

    def test_open_incident_requires_profile_for_service(self) -> None:
        from src.operations import DependencyGraph

        built = DependencyGraph.build((dependency(RAIL_A),))
        target = OperationsEngine(
            environment_id=ENV,
            domain_id=DOMAIN,
            dependency_graph=built,
            resilience_profiles={},
        )
        with self.assertRaises(CoreValidationError):
            target.open_incident(
                command_id="cmd-open",
                requested_at=T1,
                incident_id="operations/incident/inc-1",
                dependency_id=RAIL_A,
                trigger_probe=dead_rail_a_probe(),
            )

    def test_open_incident_probe_must_target_the_dependency(self) -> None:
        target = engine()
        with self.assertRaises(CoreValidationError):
            target.open_incident(
                command_id="cmd-open",
                requested_at=T1,
                incident_id="operations/incident/inc-1",
                dependency_id=RAIL_A,
                trigger_probe=probe(RAIL_B, as_of=T1, availability_bps=0),
            )

    def test_full_lifecycle_through_kernel(self) -> None:
        target = degraded_incident(open_incident())
        record = target.incident("operations/incident/inc-1")
        self.assertIs(record.state, IncidentState.DEGRADED)
        self.assertEqual(record.spec.severity, DegradationSeverity.UNAVAILABLE)
        self.assertEqual(len(record.spec.degradation_facts), 1)
        self.assertEqual(
            record.spec.degradation_facts[0].affected_authorities,
            (("authority/execution", "a" * 64),),
        )

        target.execute_failover(
            command_id="cmd-failover-1",
            requested_at=T3,
            incident_id="operations/incident/inc-1",
            target_dependency_id=RAIL_B,
            target_probe=probe(RAIL_B, as_of=T3, availability_bps=10000),
            adapter_contract=ADAPTER_B_CONTRACT,
            authority_digests={"authority/execution": "a" * 64},
            detail="failed over to provider B",
        )
        record = target.incident("operations/incident/inc-1")
        self.assertIs(record.state, IncidentState.FAILED_OVER)
        self.assertIsNotNone(record.spec.failover_fact)

        target.resolve_incident(
            command_id="cmd-resolve-1",
            requested_at=T5,
            incident_id="operations/incident/inc-1",
            probes=(
                probe(RAIL_A, as_of=T5, availability_bps=10000),
                probe(PEER_DOMAIN, as_of=T5, availability_bps=10000),
            ),
            recovery_actions=full_recovery_actions(),
            authority_evidence={"authority/execution": ("a" * 64, "a" * 64)},
            note="provider restored, redundant path used, state rebuilt",
        )
        resolved = target.incident("operations/incident/inc-1")
        self.assertIs(resolved.state, IncidentState.RESOLVED)
        self.assertIn(resolved.state, INCIDENT_TERMINAL_STATES)
        self.assertIsNotNone(resolved.spec.resolution_fact)
        self.assertEqual(
            resolved.spec.resolution_fact.recovery_duration_seconds,
            780,  # T2 (degraded) -> T5 (resolved)
        )

    def test_emergency_lifecycle(self) -> None:
        target = open_incident()
        target.declare_emergency(
            command_id="cmd-emergency-1",
            requested_at=T2,
            incident_id="operations/incident/inc-1",
            window_from=T2,
            window_until=T5,
            mandate="time-bounded operational emergency, no history rewrite",
            scope=(RAIL_A,),
        )
        record = target.incident("operations/incident/inc-1")
        self.assertIs(record.state, IncidentState.ESCALATED)
        self.assertIsNotNone(record.spec.emergency_fact)
        self.assertEqual(record.spec.emergency_fact.mandate[:12], "time-bounded")

    def test_resolve_from_open_false_alarm(self) -> None:
        target = open_incident()
        target.resolve_incident(
            command_id="cmd-resolve-1",
            requested_at=T5,
            incident_id="operations/incident/inc-1",
            probes=(probe(RAIL_A, as_of=T5, availability_bps=10000),),
            recovery_actions=(),
            authority_evidence={},
            note="false alarm: dependency healthy again",
        )
        record = target.incident("operations/incident/inc-1")
        self.assertIs(record.state, IncidentState.RESOLVED)

    def test_transition_outcome_records_mirror_kernel(self) -> None:
        target = open_incident()
        transition = target.transitions()[-1]
        self.assertIsInstance(transition, OperationsTransition)
        self.assertEqual(transition.command_type, "operations/incident")
        self.assertIs(transition.outcome.value, "accepted")


class EngineGateTests(unittest.TestCase):
    def test_unauthorized_actor_rejected(self) -> None:
        target = engine()
        command = target.build_raw_command(
            command_id="cmd-raw-1",
            command_type="operations/incident",
            requested_at=T1,
            target_refs=("operations/incident/inc-1",),
            payload={},
            actor="principal/attacker",
        )
        transition = target.submit(command)
        self.assertNotEqual(transition.outcome.value, "accepted")

    def test_unknown_command_rejected_by_contract(self) -> None:
        target = engine()
        with self.assertRaises(CoreValidationError):
            target.build_raw_command(
                command_id="cmd-raw-2",
                command_type="operations/cancel",
                requested_at=T1,
                target_refs=("operations/incident/inc-1",),
                payload={},
            )

    def test_duplicate_incident_rejected(self) -> None:
        target = open_incident()
        with self.assertRaises(CoreValidationError):
            target.open_incident(
                command_id="cmd-open-2",
                requested_at=T2,
                incident_id="operations/incident/inc-1",
                dependency_id=RAIL_A,
                trigger_probe=dead_rail_a_probe(as_of=T2),
            )

    def test_declare_degradation_rejects_improving_severity(self) -> None:
        target = degraded_incident(open_incident())
        # incident severity is UNAVAILABLE; a DEGRADED probe is an improvement
        with self.assertRaises(CoreValidationError):
            target.declare_degradation(
                command_id="cmd-degrade-2",
                requested_at=T3,
                incident_id="operations/incident/inc-1",
                probe=probe(
                    RAIL_A, as_of=T3, availability_bps=7000, detail="partial recovery"
                ),
                affected_dependencies=(RAIL_A,),
                affected_authorities={"authority/execution": "a" * 64},
            )

    def test_declare_degradation_accepts_worsening_severity(self) -> None:
        target = open_incident()
        target.declare_degradation(
            command_id="cmd-degrade-1",
            requested_at=T2,
            incident_id="operations/incident/inc-1",
            probe=probe(RAIL_A, as_of=T2, availability_bps=7000, detail="degraded"),
            affected_dependencies=(RAIL_A,),
            affected_authorities={"authority/execution": "a" * 64},
        )
        target.declare_degradation(
            command_id="cmd-degrade-2",
            requested_at=T3,
            incident_id="operations/incident/inc-1",
            probe=dead_rail_a_probe(as_of=T3),
            affected_dependencies=(RAIL_A,),
            affected_authorities={"authority/execution": "a" * 64},
        )
        record = target.incident("operations/incident/inc-1")
        self.assertEqual(len(record.spec.degradation_facts), 2)
        self.assertEqual(record.spec.severity, DegradationSeverity.UNAVAILABLE)

    def test_declare_degradation_rejects_healthy_probe(self) -> None:
        target = open_incident()
        with self.assertRaises(CoreValidationError):
            target.declare_degradation(
                command_id="cmd-degrade-3",
                requested_at=T2,
                incident_id="operations/incident/inc-1",
                probe=probe(RAIL_A, as_of=T2, availability_bps=10000),
                affected_dependencies=(RAIL_A,),
                affected_authorities={"authority/execution": "a" * 64},
            )

    def test_declare_degradation_rejects_foreign_probe(self) -> None:
        target = open_incident()
        with self.assertRaises(CoreValidationError):
            target.declare_degradation(
                command_id="cmd-degrade-4",
                requested_at=T2,
                incident_id="operations/incident/inc-1",
                probe=probe(RAIL_B, as_of=T2, availability_bps=0),
                affected_dependencies=(RAIL_A,),
                affected_authorities={"authority/execution": "a" * 64},
            )

    def test_declare_degradation_rejects_unknown_affected_dependency(self) -> None:
        target = open_incident()
        with self.assertRaises(CoreValidationError):
            target.declare_degradation(
                command_id="cmd-degrade-5",
                requested_at=T2,
                incident_id="operations/incident/inc-1",
                probe=dead_rail_a_probe(as_of=T2),
                affected_dependencies=(RAIL_A, "operations/dependency/ghost"),
                affected_authorities={"authority/execution": "a" * 64},
            )

    def test_declare_degradation_rejects_missing_incident_dependency(self) -> None:
        target = open_incident()
        with self.assertRaises(CoreValidationError):
            target.declare_degradation(
                command_id="cmd-degrade-6",
                requested_at=T2,
                incident_id="operations/incident/inc-1",
                probe=dead_rail_a_probe(as_of=T2),
                affected_dependencies=(PEER_DOMAIN,),
                affected_authorities={"authority/execution": "a" * 64},
            )

    def test_failover_requires_declared_redundancy(self) -> None:
        target = degraded_incident(open_incident())
        with self.assertRaises(CoreValidationError):
            target.execute_failover(
                command_id="cmd-failover-2",
                requested_at=T3,
                incident_id="operations/incident/inc-1",
                target_dependency_id=PEER_DOMAIN,  # not in the redundancy list
                target_probe=probe(PEER_DOMAIN, as_of=T3, availability_bps=10000),
                adapter_contract={
                    "adapter_id": "interoperability/adapter/peer",
                    "fidelity_class": "SIMULATION",
                    "effect_operations": ("SUBMIT_PAYMENT",),
                },
                authority_digests={"authority/execution": "a" * 64},
            )

    def test_failover_requires_healthy_target_probe(self) -> None:
        target = degraded_incident(open_incident())
        with self.assertRaises(CoreValidationError):
            target.execute_failover(
                command_id="cmd-failover-3",
                requested_at=T3,
                incident_id="operations/incident/inc-1",
                target_dependency_id=RAIL_B,
                target_probe=probe(RAIL_B, as_of=T3, availability_bps=0),
                adapter_contract=ADAPTER_B_CONTRACT,
                authority_digests={"authority/execution": "a" * 64},
            )

    def test_failover_requires_effect_capable_adapter_contract(self) -> None:
        target = degraded_incident(open_incident())
        with self.assertRaises(CoreValidationError):
            target.execute_failover(
                command_id="cmd-failover-4",
                requested_at=T3,
                incident_id="operations/incident/inc-1",
                target_dependency_id=RAIL_B,
                target_probe=probe(RAIL_B, as_of=T3, availability_bps=10000),
                adapter_contract={
                    "adapter_id": "interoperability/adapter/provider-b",
                    "fidelity_class": "SHADOW",  # not effect-capable
                    "effect_operations": ("SUBMIT_PAYMENT",),
                },
                authority_digests={"authority/execution": "a" * 64},
            )

    def test_failover_requires_conserved_authority_digests(self) -> None:
        target = degraded_incident(open_incident())
        with self.assertRaises(CoreValidationError):
            target.execute_failover(
                command_id="cmd-failover-5",
                requested_at=T3,
                incident_id="operations/incident/inc-1",
                target_dependency_id=RAIL_B,
                target_probe=probe(RAIL_B, as_of=T3, availability_bps=10000),
                adapter_contract=ADAPTER_B_CONTRACT,
                authority_digests={
                    "authority/execution": "b" * 64  # diverged from the recorded digest
                },
            )

    def test_failover_target_probe_must_target_target(self) -> None:
        target = degraded_incident(open_incident())
        with self.assertRaises(CoreValidationError):
            target.execute_failover(
                command_id="cmd-failover-6",
                requested_at=T3,
                incident_id="operations/incident/inc-1",
                target_dependency_id=RAIL_B,
                target_probe=probe(RAIL_A, as_of=T3, availability_bps=10000),
                adapter_contract=ADAPTER_B_CONTRACT,
                authority_digests={"authority/execution": "a" * 64},
            )

    def test_emergency_requires_forward_window(self) -> None:
        target = degraded_incident(open_incident())
        with self.assertRaises(CoreValidationError):
            target.declare_emergency(
                command_id="cmd-emergency-2",
                requested_at=T3,
                incident_id="operations/incident/inc-1",
                window_from=T4,
                window_until=T2,
                mandate="m",
                scope=(RAIL_A,),
            )

    def test_emergency_scope_must_include_incident_dependency(self) -> None:
        target = degraded_incident(open_incident())
        with self.assertRaises(CoreValidationError):
            target.declare_emergency(
                command_id="cmd-emergency-3",
                requested_at=T3,
                incident_id="operations/incident/inc-1",
                window_from=T3,
                window_until=T5,
                mandate="m",
                scope=(RAIL_B,),
            )

    def test_emergency_rejects_unknown_scope_dependency(self) -> None:
        target = degraded_incident(open_incident())
        with self.assertRaises(CoreValidationError):
            target.declare_emergency(
                command_id="cmd-emergency-4",
                requested_at=T3,
                incident_id="operations/incident/inc-1",
                window_from=T3,
                window_until=T5,
                mandate="m",
                scope=(RAIL_A, "operations/dependency/ghost"),
            )

    def test_resolve_requires_healthy_probes_for_every_affected_dependency(self) -> None:
        target = degraded_incident(open_incident())
        with self.assertRaises(CoreValidationError):
            target.resolve_incident(
                command_id="cmd-resolve-2",
                requested_at=T5,
                incident_id="operations/incident/inc-1",
                probes=(probe(RAIL_A, as_of=T5, availability_bps=10000),),  # PEER_DOMAIN missing
                recovery_actions=full_recovery_actions(),
                authority_evidence={"authority/execution": ("a" * 64, "a" * 64)},
            )

    def test_resolve_requires_degraded_probe_dependency(self) -> None:
        # a healthy probe for a dependency that never degraded is rejected
        target = degraded_incident(open_incident())
        with self.assertRaises(CoreValidationError):
            target.resolve_incident(
                command_id="cmd-resolve-2b",
                requested_at=T5,
                incident_id="operations/incident/inc-1",
                probes=(
                    probe(RAIL_A, as_of=T5, availability_bps=10000),
                    probe(RAIL_B, as_of=T5, availability_bps=10000),
                ),
                recovery_actions=full_recovery_actions(),
                authority_evidence={"authority/execution": ("a" * 64, "a" * 64)},
            )

    def test_resolve_requires_full_recovery_coverage(self) -> None:
        target = degraded_incident(open_incident())
        partial = (
            full_recovery_actions()[0],
        )
        with self.assertRaises(CoreValidationError):
            target.resolve_incident(
                command_id="cmd-resolve-3",
                requested_at=T5,
                incident_id="operations/incident/inc-1",
                probes=(
                    probe(RAIL_A, as_of=T5, availability_bps=10000),
                    probe(PEER_DOMAIN, as_of=T5, availability_bps=10000),
                ),
                recovery_actions=partial,
                authority_evidence={"authority/execution": ("a" * 64, "a" * 64)},
            )

    def test_resolve_rejects_divergent_rebuild_digest(self) -> None:
        target = degraded_incident(open_incident())
        with self.assertRaises(CoreValidationError):
            target.resolve_incident(
                command_id="cmd-resolve-5",
                requested_at=T5,
                incident_id="operations/incident/inc-1",
                probes=(
                    probe(RAIL_A, as_of=T5, availability_bps=10000),
                    probe(PEER_DOMAIN, as_of=T5, availability_bps=10000),
                ),
                recovery_actions=full_recovery_actions(),
                authority_evidence={
                    "authority/execution": ("a" * 64, "b" * 64)  # rebuild diverged
                },
            )

    def test_resolve_rejects_rto_violation(self) -> None:
        target = degraded_incident(open_incident())
        with self.assertRaises(CoreValidationError):
            target.resolve_incident(
                command_id="cmd-resolve-6",
                requested_at=LATE,  # 8+ hours after degradation; RTO is 3600s
                incident_id="operations/incident/inc-1",
                probes=(
                    probe(RAIL_A, as_of=LATE, availability_bps=10000),
                    probe(PEER_DOMAIN, as_of=LATE, availability_bps=10000),
                ),
                recovery_actions=full_recovery_actions(at=LATE),
                authority_evidence={"authority/execution": ("a" * 64, "a" * 64)},
            )

    def test_resolved_incident_is_terminal(self) -> None:
        target = degraded_incident(open_incident())
        target.resolve_incident(
            command_id="cmd-resolve-7",
            requested_at=T5,
            incident_id="operations/incident/inc-1",
            probes=(
                probe(RAIL_A, as_of=T5, availability_bps=10000),
                probe(PEER_DOMAIN, as_of=T5, availability_bps=10000),
            ),
            recovery_actions=full_recovery_actions(),
            authority_evidence={"authority/execution": ("a" * 64, "a" * 64)},
        )
        with self.assertRaises(CoreValidationError):
            target.declare_degradation(
                command_id="cmd-degrade-late",
                requested_at=LATE,
                incident_id="operations/incident/inc-1",
                probe=dead_rail_a_probe(as_of=LATE),
                affected_dependencies=(RAIL_A,),
                affected_authorities={"authority/execution": "a" * 64},
            )

    def test_kernel_rejects_transition_from_wrong_state(self) -> None:
        # failover requires DEGRADED; an OPEN incident cannot fail over
        target = open_incident()
        command = target.build_raw_command(
            command_id="cmd-raw-3",
            command_type="operations/failover",
            requested_at=T2,
            target_refs=("operations/incident/inc-1",),
            payload={
                "incident_id": "operations/incident/inc-1",
                "target_dependency_id": RAIL_B,
                "target_probe": probe(
                    RAIL_B, as_of=T2, availability_bps=10000
                ).to_dict(),
                "adapter_contract": ADAPTER_B_CONTRACT,
                "authority_digests": (("authority/execution", "a" * 64),),
                "detail": "raw",
            },
        )
        transition = target.submit(command)
        self.assertNotEqual(transition.outcome.value, "accepted")


class EngineStateTests(unittest.TestCase):
    def _resolved_engine(self) -> OperationsEngine:
        target = degraded_incident(open_incident())
        target.execute_failover(
            command_id="cmd-failover-1",
            requested_at=T3,
            incident_id="operations/incident/inc-1",
            target_dependency_id=RAIL_B,
            target_probe=probe(RAIL_B, as_of=T3, availability_bps=10000),
            adapter_contract=ADAPTER_B_CONTRACT,
            authority_digests={"authority/execution": "a" * 64},
        )
        target.declare_emergency(
            command_id="cmd-emergency-1",
            requested_at=T4,
            incident_id="operations/incident/inc-1",
            window_from=T3,
            window_until=T5,
            mandate="time-bounded recovery emergency, no history rewrite",
            scope=(RAIL_A,),
        )
        target.resolve_incident(
            command_id="cmd-resolve-1",
            requested_at=T5,
            incident_id="operations/incident/inc-1",
            probes=(
                probe(RAIL_A, as_of=T5, availability_bps=10000),
                probe(PEER_DOMAIN, as_of=T5, availability_bps=10000),
            ),
            recovery_actions=full_recovery_actions(),
            authority_evidence={"authority/execution": ("a" * 64, "a" * 64)},
        )
        return target

    def test_snapshot_restore_round_trip(self) -> None:
        target = self._resolved_engine()
        snapshot = target.snapshot_state()
        fresh = engine()
        fresh.restore_state(snapshot)
        self.assertEqual(
            fresh.incident("operations/incident/inc-1").to_dict(),
            target.incident("operations/incident/inc-1").to_dict(),
        )
        self.assertEqual(
            fresh.snapshot_state()["engine"], target.snapshot_state()["engine"]
        )

    def test_restore_rejects_environment_mismatch(self) -> None:
        target = self._resolved_engine()
        snapshot = target.snapshot_state()
        other = OperationsEngine(
            environment_id="env/other",
            domain_id=DOMAIN,
            dependency_graph=graph(),
            resilience_profiles=profiles(),
        )
        with self.assertRaises(CoreValidationError):
            other.restore_state(snapshot)

    def test_rebuild_from_journal_is_byte_identical(self) -> None:
        target = self._resolved_engine()
        rebuilt = OperationsEngine.rebuild_from_journal(
            environment_id=ENV,
            domain_id=DOMAIN,
            dependency_graph=graph(),
            resilience_profiles=profiles(),
            journal=target.journal,
        )
        self.assertEqual(
            rebuilt.incident("operations/incident/inc-1").to_dict(),
            target.incident("operations/incident/inc-1").to_dict(),
        )
        self.assertEqual(rebuilt.records(), target.records())
        # The journal is the rebuild's sole input, so it must reproduce the
        # store envelopes exactly; the kernel's command-id dedup records
        # restart after a journal-only rebuild (command envelopes are not
        # journaled — by design), so the domain state — not the kernel's
        # idempotency index — is what must be byte-identical.
        self.assertEqual(tuple(rebuilt.journal), tuple(target.journal))
        self.assertEqual(
            rebuilt.snapshot_state()["store"], target.snapshot_state()["store"]
        )
        self.assertEqual(
            rebuilt.snapshot_state()["index"], target.snapshot_state()["index"]
        )

    def test_rebuild_on_empty_journal(self) -> None:
        rebuilt = OperationsEngine.rebuild_from_journal(
            environment_id=ENV,
            domain_id=DOMAIN,
            dependency_graph=graph(),
            resilience_profiles=profiles(),
            journal=(),
        )
        self.assertEqual(rebuilt.records(), ())

    def test_journal_is_append_only_and_events_use_governance_namespace(self) -> None:
        target = self._resolved_engine()
        event_types = tuple(entry.event.event_type for entry in target.journal)
        self.assertEqual(len(event_types), 5)
        for event_type in event_types:
            self.assertTrue(event_type.startswith("governance/"))
        self.assertEqual(
            event_types[0],
            COMMAND_EVENT_TYPES["operations/incident"],
        )

    def test_incident_record_from_dict_round_trip(self) -> None:
        target = self._resolved_engine()
        record = target.incident("operations/incident/inc-1")
        decoded = Incident.from_dict(record.to_dict())
        self.assertEqual(decoded.to_dict(), record.to_dict())


# ---------------------------------------------------------------------------
# dogfooding conformance
# ---------------------------------------------------------------------------


class DogfoodingTests(unittest.TestCase):
    def test_dogfood_transcript_passes_all_checks(self) -> None:
        transcript = dogfood_transcript()
        self.assertIn("checks", transcript)
        checks = transcript["checks"]
        self.assertGreaterEqual(len(checks), 18)
        failed = [check for check in checks if not check["ok"]]
        self.assertEqual(failed, [], failed)

    def test_dogfood_transcript_is_deterministic(self) -> None:
        first = dogfood_transcript()
        second = dogfood_transcript()
        self.assertEqual(first, second)

    def test_dogfood_reports_no_false_success_during_outage(self) -> None:
        transcript = dogfood_transcript()
        facts = transcript["facts"]
        self.assertEqual(facts["inflight_step_state"], "UNKNOWN")
        self.assertFalse(facts["inflight_step_succeeded"])
        self.assertTrue(facts["clearing_refused_unknown_evidence"])

    def test_dogfood_reports_authority_conservation(self) -> None:
        transcript = dogfood_transcript()
        facts = transcript["facts"]
        self.assertTrue(facts["failover_conserved_authority_digest"])
        self.assertEqual(facts["incident_final_state"], "RESOLVED")
        self.assertTrue(facts["recovery_completed_step_succeeded"])


if __name__ == "__main__":
    unittest.main()
