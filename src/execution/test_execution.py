"""WORK-014 execution domain test suite (red-first authored).

Covers the frozen v0.1 contracts this Work Order owns:

* the typed, versioned public boundary (versions, registry discipline,
  frozen command families ``Execution`` and ``External``);
* the execution plan/step/attempt lifecycles with explicit failure
  paths for every illegal transition;
* effect requests/results and their integrity binding to the exact
  request content they resolve;
* the typed adapter ports (submission + reconciliation) and the
  binding discipline against the canonical world adapter contract;
* idempotent submission (idempotency keys + duplicate detection) and
  rail-side dedupe;
* the unknown-result recovery discipline (never blind retry: reconcile
  first — constitution invariants 9 and 12, implementation principle 8);
* authority-before-financial-effect (plan authorization, safety gates,
  held reservations, covering effect authorization);
* external observations recorded as evidence (query, status, finality
  claim) with NO clearing/finality authority in this package;
* kernel binding through the real transition engine, determinism and
  scope isolation.

The suite never requires a real rail: the local deterministic sandbox
rail is a test-side artifact living in ``dogfooding.py`` and is used
through the public adapter path only.
"""

from __future__ import annotations

import ast
import json
import sys
import unittest
from pathlib import Path

from src.core.errors import CoreValidationError

from src.execution import EXECUTION_API_VERSION  # red-first marker

DOMAIN_PACKAGE = Path(__file__).parent
REPOSITORY_ROOT = DOMAIN_PACKAGE.parents[1]
REGISTRY_PATH = REPOSITORY_ROOT / "spec" / "registry" / "protocol-registry.json"

ENV = "env/test-execution"
DOMAIN = "domain/payments"
AUTHORITY_CLASS = "A2"

T0 = "2026-09-02T00:00:00Z"
T1 = "2026-09-02T00:01:00Z"
T2 = "2026-09-02T00:02:00Z"
T3 = "2026-09-02T00:03:00Z"
T4 = "2026-09-02T00:04:00Z"
T5 = "2026-09-02T00:05:00Z"
T9 = "2026-09-02T00:09:00Z"
T_DEADLINE = "2026-09-02T00:02:30Z"

PLAN_ID = "execution/plan/pay-1"
STEP_IDS = ("execution/plan/pay-1/step/1", "execution/plan/pay-1/step/2")
# The sandbox adapter id follows the internal adapter identifier format
# owned by the merged interoperability contract
# ("interoperability/adapter/<local_id>").
ADAPTER_ID = "interoperability/adapter/sandbox-rail"
EFFECT_TYPES = ("payment/submit", "payment/fee")
RESERVATION_ID = "reservation/hold-1"

FRAUD_GATE = {
    "decision_id": "safety/fraud-decision-1",
    "verdict": "ALLOW",
    "object_version": 3,
}
COMPLIANCE_GATE = {
    "assessment_id": "safety/compliance-1",
    "verdict": "SATISFIED",
    "object_version": 2,
}
HOLD_GATE = {
    "reservation_id": RESERVATION_ID,
    "state": "HELD",
    "object_version": 4,
}

DOMAIN_SOURCES = sorted(
    source
    for source in DOMAIN_PACKAGE.glob("*.py")
    if source.name != "test_execution.py"
)

ALLOWED_SRC_DOMAINS = frozenset(
    {"core", "transition", "interoperability", "reservation", "safety", "evidence", "simulation"}
)
FORBIDDEN_SRC_DOMAINS = frozenset(
    {
        "market",
        "intent",
        "money",
        "trust",
        "liquidity",
        "value",
        "capability",
        "integration",
        "compiler",
        "extensions",
        "agents",
        "data",
    }
)
STDLIB_ROOTS = frozenset(sys.stdlib_module_names)


# ---------------------------------------------------------------------------
# shared fixtures
# ---------------------------------------------------------------------------


def _steps_payload() -> list[dict]:
    return [
        {
            "step_id": STEP_IDS[0],
            "adapter_id": ADAPTER_ID,
            "effect_type": EFFECT_TYPES[0],
            "payload": {"currency": "USD", "amount_value": 900000, "amount_scale": 2},
            "reservation_ref": RESERVATION_ID,
            "max_attempts": 2,
        },
        {
            "step_id": STEP_IDS[1],
            "adapter_id": ADAPTER_ID,
            "effect_type": EFFECT_TYPES[1],
            "payload": {"currency": "USD", "amount_value": 25000, "amount_scale": 2},
            "reservation_ref": RESERVATION_ID,
            "max_attempts": 2,
        },
    ]


def _fraud(verdict: str = "ALLOW") -> dict:
    return {
        "decision_id": "safety/fraud-decision-1",
        "verdict": verdict,
        "object_version": 3,
    }


def _compliance(verdict: str = "SATISFIED") -> dict:
    return {
        "assessment_id": "safety/compliance-1",
        "verdict": verdict,
        "object_version": 2,
    }


def _hold(state: str = "HELD") -> dict:
    return {
        "reservation_id": RESERVATION_ID,
        "state": state,
        "object_version": 4,
    }


class SandboxFixture:
    """Deterministic sandbox rail + adapter binding (test-side artifact)."""

    def __init__(self, *, submissions: dict | None = None, queries: dict | None = None):
        from src.execution.dogfooding import SandboxRail, make_sandbox_binding

        self.rail = SandboxRail(
            submissions=submissions if submissions is not None else {},
            queries=queries if queries is not None else {},
        )
        self.binding = make_sandbox_binding(self.rail)


def make_engine(*, submissions: dict | None = None, queries: dict | None = None) -> "SandboxFixture":
    """Build an ExecutionEngine wired to a scripted sandbox rail."""
    from src.execution import ExecutionEngine, EffectAuthorization

    fixture = SandboxFixture(submissions=submissions, queries=queries)
    authorization = EffectAuthorization(
        authorizer="principal/ops",
        authority_class=AUTHORITY_CLASS,
        authorized_types=frozenset(EFFECT_TYPES),
        valid_from=T0,
        valid_until=T9,
    )
    engine = ExecutionEngine(
        environment_id=ENV,
        domain_id=DOMAIN,
        bindings={ADAPTER_ID: fixture.binding},
    )
    fixture.engine = engine
    fixture.authorization = authorization
    return fixture


def make_running_plan(fixture) -> None:
    """Drive a fresh two-step plan through create → authorize → start."""
    engine = fixture.engine
    engine.create_plan(
        command_id="cmd/create-1",
        requested_at=T0,
        plan_id=PLAN_ID,
        steps=_steps_payload(),
        source_ref="intent/pay-1",
        summary="two-leg sandbox payment",
    )
    engine.authorize_plan(
        command_id="cmd/authorize-1",
        requested_at=T1,
        plan_id=PLAN_ID,
        authority_class=AUTHORITY_CLASS,
        fraud_decision=FRAUD_GATE,
        compliance_assessment=COMPLIANCE_GATE,
    )
    engine.start_plan(command_id="cmd/start-1", requested_at=T2, plan_id=PLAN_ID)


def _engine_of(fixture):
    return fixture.engine


# ---------------------------------------------------------------------------
# 1. static boundary
# ---------------------------------------------------------------------------


class StaticBoundaryTests(unittest.TestCase):
    """The public boundary is typed, versioned and registry-disciplined."""

    def test_public_api_all_is_frozen(self) -> None:
        from src.execution import __all__

        self.assertEqual(sorted(__all__), sorted(EXPECTED_PUBLIC_API))

    def test_versions_are_typed_and_versioned(self) -> None:
        from src.execution import (
            EXECUTION_API_VERSION,
            EXECUTION_PROTOCOL_VERSION,
            EXECUTION_SCHEMA_VERSION,
        )

        self.assertEqual(EXECUTION_API_VERSION, "v0.1")
        self.assertEqual(EXECUTION_PROTOCOL_VERSION, "v0.1")
        self.assertEqual(EXECUTION_SCHEMA_VERSION, 1)

    def test_plan_object_type_is_registry_listed(self) -> None:
        from src.execution import EXECUTION_EVENT_NAMESPACE, EXECUTION_PLAN_OBJECT_TYPE

        registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        self.assertIn(EXECUTION_PLAN_OBJECT_TYPE, registry["registry"]["objectTypes"])
        self.assertIn(EXECUTION_EVENT_NAMESPACE, registry["registry"]["eventNamespaces"])

    def test_internal_object_types_do_not_claim_registry_names(self) -> None:
        from src.execution import (
            EFFECT_REQUEST_OBJECT_TYPE,
            EFFECT_RESULT_OBJECT_TYPE,
            EXECUTION_ATTEMPT_OBJECT_TYPE,
            EXECUTION_OBSERVATION_OBJECT_TYPE,
            EXECUTION_RECEIPT_OBJECT_TYPE,
            EXECUTION_STEP_OBJECT_TYPE,
        )

        for object_type in (
            EXECUTION_STEP_OBJECT_TYPE,
            EXECUTION_ATTEMPT_OBJECT_TYPE,
            EFFECT_REQUEST_OBJECT_TYPE,
            EFFECT_RESULT_OBJECT_TYPE,
            EXECUTION_RECEIPT_OBJECT_TYPE,
            EXECUTION_OBSERVATION_OBJECT_TYPE,
        ):
            self.assertTrue(str(object_type).startswith("execution/"))
            self.assertFalse(str(object_type).startswith("payswap/"))

    def test_command_families_exactly_cover_the_frozen_model(self) -> None:
        from src.execution import EXECUTION_COMMANDS, EXTERNAL_COMMANDS

        self.assertEqual(
            set(EXECUTION_COMMANDS),
            {
                "execution/plan.create",
                "execution/plan.authorize",
                "execution/plan.start",
                "execution/step.submit",
                "execution/step.acknowledge",
                "execution/step.complete",
                "execution/step.fail",
                "execution/step.timeout",
                "execution/step.retry",
                "execution/plan.cancel",
            },
        )
        self.assertEqual(
            set(EXTERNAL_COMMANDS),
            {
                "external/request-effect",
                "external/record-observation",
                "external/record-effect-result",
                "external/record-status",
                "external/record-finality",
            },
        )

    def test_every_command_emits_a_registered_namespace_event(self) -> None:
        from src.execution import COMMAND_EVENT_TYPES, EXECUTION_ALL_COMMANDS

        self.assertEqual(set(COMMAND_EVENT_TYPES), set(EXECUTION_ALL_COMMANDS))
        for command, event in COMMAND_EVENT_TYPES.items():
            self.assertTrue(event.startswith("execution/"), event)
            self.assertNotIn("_", event.rsplit("/", 1)[-1][:1])

    def test_no_settlement_or_finality_object_types_or_commands(self) -> None:
        from src.execution import EXECUTION_ALL_COMMANDS, OBJECT_TYPES

        for object_type in OBJECT_TYPES:
            self.assertNotIn("settlement", str(object_type))
            self.assertNotIn("finality", str(object_type))
        for command in EXECUTION_ALL_COMMANDS:
            self.assertNotIn("clearing", command)
            self.assertNotIn("settle", command)
            self.assertNotIn("establish", command)

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
        from src.execution import EffectRequest

        with self.assertRaises(CoreValidationError):
            EffectRequest.from_dict(
                {
                    "request_id": "execution/plan/pay-1/step/1/request/1",
                    "plan_id": PLAN_ID,
                    "step_id": STEP_IDS[0],
                    "attempt_number": 1,
                    "effect_type": "not a type",
                    "adapter_id": ADAPTER_ID,
                    "idempotency_key": "",
                    "payload": {},
                    "requested_at": T1,
                    "authorization_digest": "0" * 64,
                }
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

    def test_domain_sources_do_not_import_unmerged_or_forbidden_siblings(self) -> None:
        for source in DOMAIN_SOURCES:
            tree = ast.parse(source.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    if node.level == 0 and node.module and node.module.startswith("src."):
                        domain = node.module.split(".")[1]
                        self.assertNotIn(
                            domain,
                            FORBIDDEN_SRC_DOMAINS,
                            f"{source.name} imports forbidden sibling src.{domain}",
                        )
                    elif node.level == 0 and node.module:
                        root = node.module.split(".")[0]
                        self.assertIn(
                            root,
                            STDLIB_ROOTS | {"__future__"},
                            f"{source.name} imports non-stdlib module {node.module!r}",
                        )
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.startswith("src."):
                            domain = alias.name.split(".")[1]
                            self.assertNotIn(domain, FORBIDDEN_SRC_DOMAINS)
                        else:
                            root = alias.name.split(".")[0]
                            self.assertIn(root, STDLIB_ROOTS)


# The exact frozen public API surface (pinned; changes require an ACR).
EXPECTED_PUBLIC_API = [
    "ADAPTER_PORT_API_VERSION",
    "AdapterBinding",
    "AdapterQueryResult",
    "AdapterSubmission",
    "COMMAND_EVENT_TYPES",
    "EFFECT_REQUEST_OBJECT_TYPE",
    "EFFECT_RESULT_OBJECT_TYPE",
    "EffectOutcome",
    "EffectReconciliationPort",
    "EffectRequest",
    "EffectRequestSpec",
    "EffectRequestState",
    "EffectResult",
    "EffectResultSpec",
    "EffectSubmissionLedger",
    "EffectSubmissionPort",
    "EXECUTION_ALL_COMMANDS",
    "EXECUTION_API_VERSION",
    "EXECUTION_ATTEMPT_OBJECT_TYPE",
    "EXECUTION_COMMANDS",
    "EXECUTION_EVENT_NAMESPACE",
    "EXECUTION_OBSERVATION_OBJECT_TYPE",
    "EXECUTION_PLAN_OBJECT_TYPE",
    "EXECUTION_PLAN_TERMINAL_STATES",
    "EXECUTION_PROTOCOL_VERSION",
    "EXECUTION_RECEIPT_OBJECT_TYPE",
    "EXECUTION_SCHEMA_VERSION",
    "EXECUTION_STEP_OBJECT_TYPE",
    "EXECUTION_STEP_TERMINAL_STATES",
    "EXECUTION_TRANSITIONS",
    "ExecutionAttempt",
    "ExecutionAttemptSpec",
    "ExecutionAttemptState",
    "ExecutionEngine",
    "ExecutionPlan",
    "ExecutionPlanSpec",
    "ExecutionPlanState",
    "ExecutionStep",
    "ExecutionStepSpec",
    "ExecutionStepState",
    "ExecutionTransition",
    "EXTERNAL_COMMANDS",
    "ExternalObservation",
    "ExternalObservationSpec",
    "FINALITY_CLAIMS",
    "FinalityClaim",
    "ObservationKind",
    "QueryOutcome",
    "Receipt",
    "ReceiptSpec",
    "SubmissionStatus",
    "CoreValidationError",
    "OBJECT_TYPES",
]


# ---------------------------------------------------------------------------
# 2. validation strictness of the durable records
# ---------------------------------------------------------------------------


class RecordValidationTests(unittest.TestCase):
    """Every durable record fails closed on malformed content."""

    def _step_spec_dict(self) -> dict:
        return {
            "step_id": STEP_IDS[0],
            "plan_id": PLAN_ID,
            "position": 1,
            "adapter_id": ADAPTER_ID,
            "effect_type": EFFECT_TYPES[0],
            "payload": {"currency": "USD", "amount_value": 900000, "amount_scale": 2},
            "reservation_ref": RESERVATION_ID,
            "max_attempts": 2,
        }

    def _request_spec_dict(self) -> dict:
        return {
            "request_id": "execution/plan/pay-1/step/1/request/1",
            "plan_id": PLAN_ID,
            "step_id": STEP_IDS[0],
            "attempt_number": 1,
            "effect_type": EFFECT_TYPES[0],
            "adapter_id": ADAPTER_ID,
            "idempotency_key": "effect-key-1",
            "payload": {"currency": "USD"},
            "requested_at": T1,
            "authorization_digest": "a" * 64,
        }

    def _result_spec_dict(self) -> dict:
        return {
            "result_id": "execution/plan/pay-1/step/1/request/1/result",
            "request_id": "execution/plan/pay-1/step/1/request/1",
            "step_id": STEP_IDS[0],
            "effect_type": EFFECT_TYPES[0],
            "outcome": "SUCCEEDED",
            "native_reference": "sandbox/effect-key-1",
            "error_code": None,
            "observed_at": T3,
            "request_digest": "b" * 64,
            "detail": {},
        }

    def _receipt_spec_dict(self) -> dict:
        return {
            "receipt_id": "execution/plan/pay-1/step/1/request/1/receipt",
            "request_id": "execution/plan/pay-1/step/1/request/1",
            "step_id": STEP_IDS[0],
            "adapter_id": ADAPTER_ID,
            "native_reference": "sandbox/effect-key-1",
            "acknowledged_at": T2,
            "request_digest": "b" * 64,
        }

    def _observation_spec_dict(self) -> dict:
        return {
            "observation_id": "execution/observation/cmd/query-1",
            "kind": "QUERY",
            "subject_ref": "execution/plan/pay-1/step/1/request/1",
            "adapter_id": ADAPTER_ID,
            "epistemic": "OBSERVED",
            "observed_at": T3,
            "content": {"outcome": "NOT_FOUND", "native_reference": None},
            "subject_request_digest": "b" * 64,
        }

    def test_step_spec_round_trip_is_byte_stable(self) -> None:
        from src.execution import ExecutionStepSpec
        from src.core.serialization import canonical_json

        spec = ExecutionStepSpec.from_dict(self._step_spec_dict())
        again = ExecutionStepSpec.from_dict(
            json.loads(canonical_json(spec.to_dict()))
        )
        self.assertEqual(canonical_json(spec.to_dict()), canonical_json(again.to_dict()))

    def test_step_spec_rejects_non_canonical_fields(self) -> None:
        from src.execution import ExecutionStepSpec

        value = self._step_spec_dict()
        value["extra"] = "nope"
        with self.assertRaises(CoreValidationError):
            ExecutionStepSpec.from_dict(value)

    def test_step_spec_rejects_zero_max_attempts(self) -> None:
        from src.execution import ExecutionStepSpec

        value = self._step_spec_dict()
        value["max_attempts"] = 0
        with self.assertRaises(CoreValidationError):
            ExecutionStepSpec.from_dict(value)

    def test_step_spec_rejects_bad_effect_type(self) -> None:
        from src.execution import ExecutionStepSpec

        value = self._step_spec_dict()
        value["effect_type"] = "Not A Type"
        with self.assertRaises(CoreValidationError):
            ExecutionStepSpec.from_dict(value)

    def test_request_spec_requires_idempotency_key(self) -> None:
        from src.execution import EffectRequestSpec

        value = self._request_spec_dict()
        value["idempotency_key"] = ""
        with self.assertRaises(CoreValidationError):
            EffectRequestSpec.from_dict(value)

    def test_request_spec_rejects_float_payloads(self) -> None:
        from src.execution import EffectRequestSpec

        value = self._request_spec_dict()
        value["payload"] = {"amount": 1.5}
        with self.assertRaises(CoreValidationError):
            EffectRequestSpec.from_dict(value)

    def test_request_spec_requires_canonical_digest(self) -> None:
        from src.execution import EffectRequestSpec

        value = self._request_spec_dict()
        value["authorization_digest"] = "not-a-digest"
        with self.assertRaises(CoreValidationError):
            EffectRequestSpec.from_dict(value)

    def test_result_spec_outcome_is_closed(self) -> None:
        from src.execution import EffectResultSpec

        value = self._result_spec_dict()
        value["outcome"] = "MAYBE"
        with self.assertRaises(CoreValidationError):
            EffectResultSpec.from_dict(value)

    def test_receipt_requires_native_reference(self) -> None:
        from src.execution import ReceiptSpec

        value = self._receipt_spec_dict()
        value["native_reference"] = ""
        with self.assertRaises(CoreValidationError):
            ReceiptSpec.from_dict(value)

    def test_observation_spec_requires_observed_epistemic_type(self) -> None:
        from src.execution import ExternalObservationSpec

        value = self._observation_spec_dict()
        value["epistemic"] = "SIMULATED"
        with self.assertRaises(CoreValidationError):
            ExternalObservationSpec.from_dict(value)

    def test_observation_kind_is_closed(self) -> None:
        from src.execution import ExternalObservationSpec

        value = self._observation_spec_dict()
        value["kind"] = "TELEPATHY"
        with self.assertRaises(CoreValidationError):
            ExternalObservationSpec.from_dict(value)

    def test_query_observation_content_requires_adapter_outcome(self) -> None:
        from src.execution import ExternalObservationSpec

        value = self._observation_spec_dict()
        value["content"] = {"outcome": "PERHAPS", "native_reference": None}
        with self.assertRaises(CoreValidationError):
            ExternalObservationSpec.from_dict(value)

    def test_status_observation_content_requires_canonical_status(self) -> None:
        from src.execution import ExternalObservationSpec

        value = self._observation_spec_dict()
        value["kind"] = "STATUS"
        value["content"] = {"native_code": "ACSD", "canonical_status": "SOMEDAY"}
        with self.assertRaises(CoreValidationError):
            ExternalObservationSpec.from_dict(value)

    def test_finality_observation_content_requires_claim_vocabulary(self) -> None:
        from src.execution import ExternalObservationSpec

        value = self._observation_spec_dict()
        value["kind"] = "FINALITY"
        value["content"] = {"claim": "TOTALLY_FINAL", "native_reference": "x"}
        with self.assertRaises(CoreValidationError):
            ExternalObservationSpec.from_dict(value)

    def test_finality_claims_are_closed(self) -> None:
        from src.execution import FINALITY_CLAIMS

        self.assertEqual(
            sorted(claim.value for claim in FINALITY_CLAIMS), ["FINAL", "REVOKED", "SETTLED"]
        )

    def test_observation_timestamps_must_be_explicit_utc(self) -> None:
        from src.execution import ExternalObservationSpec

        value = self._observation_spec_dict()
        value["observed_at"] = "2026-09-02T00:03:00+02:00"
        with self.assertRaises(CoreValidationError):
            ExternalObservationSpec.from_dict(value)


# ---------------------------------------------------------------------------
# 3. plan lifecycle
# ---------------------------------------------------------------------------


class PlanLifecycleTests(unittest.TestCase):
    """The Execution command family as an explicit state machine."""

    def test_create_plan_happy_path(self) -> None:
        fixture = make_engine()
        engine = fixture.engine
        transition = engine.create_plan(
            command_id="cmd/create-1",
            requested_at=T0,
            plan_id=PLAN_ID,
            steps=_steps_payload(),
            source_ref="intent/pay-1",
            summary="two-leg sandbox payment",
        )
        self.assertEqual(transition.outcome, "accepted")
        plan = engine.plan(PLAN_ID)
        self.assertEqual(plan.state.value, "DRAFT")
        steps = engine.steps(PLAN_ID)
        self.assertEqual([step.state.value for step in steps], ["PENDING", "PENDING"])
        self.assertEqual(plan.spec.source_ref, "intent/pay-1")
        self.assertEqual(steps[0].spec.position, 1)
        self.assertEqual(steps[1].spec.position, 2)

    def test_create_plan_requires_at_least_one_step(self) -> None:
        fixture = make_engine()
        with self.assertRaises(CoreValidationError):
            fixture.engine.create_plan(
                command_id="cmd/create-1",
                requested_at=T0,
                plan_id=PLAN_ID,
                steps=[],
                source_ref="intent/pay-1",
            )

    def test_create_plan_rejects_duplicate_step_ids(self) -> None:
        fixture = make_engine()
        steps = _steps_payload()
        steps[1]["step_id"] = steps[0]["step_id"]
        with self.assertRaises(CoreValidationError):
            fixture.engine.create_plan(
                command_id="cmd/create-1",
                requested_at=T0,
                plan_id=PLAN_ID,
                steps=steps,
                source_ref="intent/pay-1",
            )

    def test_create_plan_rejects_unknown_adapter(self) -> None:
        fixture = make_engine()
        steps = _steps_payload()
        steps[0]["adapter_id"] = "adapter/nowhere"
        with self.assertRaises(CoreValidationError):
            fixture.engine.create_plan(
                command_id="cmd/create-1",
                requested_at=T0,
                plan_id=PLAN_ID,
                steps=steps,
                source_ref="intent/pay-1",
            )

    def test_create_plan_rejects_zero_max_attempts(self) -> None:
        fixture = make_engine()
        steps = _steps_payload()
        steps[0]["max_attempts"] = 0
        with self.assertRaises(CoreValidationError):
            fixture.engine.create_plan(
                command_id="cmd/create-1",
                requested_at=T0,
                plan_id=PLAN_ID,
                steps=steps,
                source_ref="intent/pay-1",
            )

    def test_create_plan_duplicate_command_converges(self) -> None:
        fixture = make_engine()
        engine = fixture.engine
        engine.create_plan(
            command_id="cmd/create-1",
            requested_at=T0,
            plan_id=PLAN_ID,
            steps=_steps_payload(),
            source_ref="intent/pay-1",
        )
        journal_len = len(engine.journal())
        transition = engine.create_plan(
            command_id="cmd/create-1",
            requested_at=T0,
            plan_id=PLAN_ID,
            steps=_steps_payload(),
            source_ref="intent/pay-1",
        )
        self.assertEqual(transition.outcome, "duplicate")
        self.assertEqual(len(engine.journal()), journal_len)

    def test_authorize_happy_path_pins_gates(self) -> None:
        fixture = make_engine()
        engine = fixture.engine
        engine.create_plan(
            command_id="cmd/create-1",
            requested_at=T0,
            plan_id=PLAN_ID,
            steps=_steps_payload(),
            source_ref="intent/pay-1",
        )
        transition = engine.authorize_plan(
            command_id="cmd/authorize-1",
            requested_at=T1,
            plan_id=PLAN_ID,
            authority_class=AUTHORITY_CLASS,
            fraud_decision=FRAUD_GATE,
            compliance_assessment=COMPLIANCE_GATE,
        )
        self.assertEqual(transition.outcome, "accepted")
        plan = engine.plan(PLAN_ID)
        self.assertEqual(plan.state.value, "AUTHORIZED")
        self.assertEqual(plan.spec.authority_class, AUTHORITY_CLASS)
        self.assertEqual(plan.spec.fraud_decision["verdict"], "ALLOW")
        self.assertEqual(plan.spec.compliance_assessment["verdict"], "SATISFIED")

    def test_authorize_requires_safety_gates(self) -> None:
        fixture = make_engine()
        engine = fixture.engine
        engine.create_plan(
            command_id="cmd/create-1",
            requested_at=T0,
            plan_id=PLAN_ID,
            steps=_steps_payload(),
            source_ref="intent/pay-1",
        )
        with self.assertRaises(CoreValidationError):
            engine.authorize_plan(
                command_id="cmd/authorize-1",
                requested_at=T1,
                plan_id=PLAN_ID,
                authority_class=AUTHORITY_CLASS,
                fraud_decision=None,
                compliance_assessment=COMPLIANCE_GATE,
            )

    def test_authorize_rejects_fraud_block(self) -> None:
        fixture = make_engine()
        engine = fixture.engine
        engine.create_plan(
            command_id="cmd/create-1",
            requested_at=T0,
            plan_id=PLAN_ID,
            steps=_steps_payload(),
            source_ref="intent/pay-1",
        )
        with self.assertRaises(CoreValidationError):
            engine.authorize_plan(
                command_id="cmd/authorize-1",
                requested_at=T1,
                plan_id=PLAN_ID,
                authority_class=AUTHORITY_CLASS,
                fraud_decision=_fraud("BLOCKED"),
                compliance_assessment=COMPLIANCE_GATE,
            )

    def test_authorize_rejects_fraud_step_up(self) -> None:
        fixture = make_engine()
        engine = fixture.engine
        engine.create_plan(
            command_id="cmd/create-1",
            requested_at=T0,
            plan_id=PLAN_ID,
            steps=_steps_payload(),
            source_ref="intent/pay-1",
        )
        with self.assertRaises(CoreValidationError):
            engine.authorize_plan(
                command_id="cmd/authorize-1",
                requested_at=T1,
                plan_id=PLAN_ID,
                authority_class=AUTHORITY_CLASS,
                fraud_decision=_fraud("STEP_UP"),
                compliance_assessment=COMPLIANCE_GATE,
            )

    def test_authorize_rejects_compliance_blocked(self) -> None:
        fixture = make_engine()
        engine = fixture.engine
        engine.create_plan(
            command_id="cmd/create-1",
            requested_at=T0,
            plan_id=PLAN_ID,
            steps=_steps_payload(),
            source_ref="intent/pay-1",
        )
        with self.assertRaises(CoreValidationError):
            engine.authorize_plan(
                command_id="cmd/authorize-1",
                requested_at=T1,
                plan_id=PLAN_ID,
                authority_class=AUTHORITY_CLASS,
                fraud_decision=FRAUD_GATE,
                compliance_assessment=_compliance("BLOCKED"),
            )

    def test_authorize_rejects_unknown_authority_class(self) -> None:
        fixture = make_engine()
        engine = fixture.engine
        engine.create_plan(
            command_id="cmd/create-1",
            requested_at=T0,
            plan_id=PLAN_ID,
            steps=_steps_payload(),
            source_ref="intent/pay-1",
        )
        with self.assertRaises(CoreValidationError):
            engine.authorize_plan(
                command_id="cmd/authorize-1",
                requested_at=T1,
                plan_id=PLAN_ID,
                authority_class="Z9",
                fraud_decision=FRAUD_GATE,
                compliance_assessment=COMPLIANCE_GATE,
            )

    def test_authorize_rejects_unknown_verdicts(self) -> None:
        fixture = make_engine()
        engine = fixture.engine
        engine.create_plan(
            command_id="cmd/create-1",
            requested_at=T0,
            plan_id=PLAN_ID,
            steps=_steps_payload(),
            source_ref="intent/pay-1",
        )
        with self.assertRaises(CoreValidationError):
            engine.authorize_plan(
                command_id="cmd/authorize-1",
                requested_at=T1,
                plan_id=PLAN_ID,
                authority_class=AUTHORITY_CLASS,
                fraud_decision=_fraud("PROBABLY"),
                compliance_assessment=COMPLIANCE_GATE,
            )

    def test_start_requires_authorized_plan(self) -> None:
        fixture = make_engine()
        engine = fixture.engine
        engine.create_plan(
            command_id="cmd/create-1",
            requested_at=T0,
            plan_id=PLAN_ID,
            steps=_steps_payload(),
            source_ref="intent/pay-1",
        )
        with self.assertRaises(CoreValidationError):
            engine.start_plan(command_id="cmd/start-1", requested_at=T1, plan_id=PLAN_ID)

    def test_authorize_twice_fails_closed(self) -> None:
        fixture = make_engine()
        make_running_plan(fixture)
        with self.assertRaises(CoreValidationError):
            fixture.engine.authorize_plan(
                command_id="cmd/authorize-2",
                requested_at=T3,
                plan_id=PLAN_ID,
                authority_class=AUTHORITY_CLASS,
                fraud_decision=FRAUD_GATE,
                compliance_assessment=COMPLIANCE_GATE,
            )

    def test_cancel_from_draft(self) -> None:
        fixture = make_engine()
        engine = fixture.engine
        engine.create_plan(
            command_id="cmd/create-1",
            requested_at=T0,
            plan_id=PLAN_ID,
            steps=_steps_payload(),
            source_ref="intent/pay-1",
        )
        engine.cancel_plan(
            command_id="cmd/cancel-1", requested_at=T1, plan_id=PLAN_ID, reason="abandoned"
        )
        self.assertEqual(engine.plan(PLAN_ID).state.value, "CANCELLED")
        self.assertEqual(
            [step.state.value for step in engine.steps(PLAN_ID)],
            ["CANCELLED", "CANCELLED"],
        )

    def test_cancel_running_with_pending_steps_cancels_them(self) -> None:
        fixture = make_engine()
        make_running_plan(fixture)
        fixture.engine.cancel_plan(
            command_id="cmd/cancel-1", requested_at=T3, plan_id=PLAN_ID, reason="operator"
        )
        self.assertEqual(fixture.engine.plan(PLAN_ID).state.value, "CANCELLED")
        self.assertEqual(
            [step.state.value for step in fixture.engine.steps(PLAN_ID)],
            ["CANCELLED", "CANCELLED"],
        )

    def test_cancel_running_with_inflight_step_fails_closed(self) -> None:
        fixture = make_engine(
            submissions={"effect-key-1": ("accept",)}
        )
        make_running_plan(fixture)
        _declare_and_submit(fixture, key="effect-key-1", at=T3)
        with self.assertRaises(CoreValidationError):
            fixture.engine.cancel_plan(
                command_id="cmd/cancel-1",
                requested_at=T4,
                plan_id=PLAN_ID,
                reason="operator",
            )

    def test_cancel_completed_plan_fails_closed(self) -> None:
        fixture = make_engine(submissions={"effect-key-1": ("accept",)})
        make_running_plan(fixture)
        _complete_first_step(fixture, key="effect-key-1")
        fixture.engine.cancel_plan(
            command_id="cmd/cancel-1", requested_at=T5, plan_id=PLAN_ID, reason="late"
        )
        # plan was not terminal yet (step 2 still pending) — cancelling is fine;
        # completing the plan first then cancelling must fail instead.
        self.assertEqual(fixture.engine.plan(PLAN_ID).state.value, "CANCELLED")
        fixture2 = make_engine(submissions={"k1": ("accept",), "k2": ("accept",)})
        make_running_plan(fixture2)
        _complete_first_step(fixture2, key="k1")
        _complete_second_step(fixture2, key="k2")
        with self.assertRaises(CoreValidationError):
            fixture2.engine.cancel_plan(
                command_id="cmd/cancel-2", requested_at=T5, plan_id=PLAN_ID, reason="late"
            )


# ---------------------------------------------------------------------------
# 4. submission authority (authority before financial effect)
# ---------------------------------------------------------------------------


class SubmissionAuthorityTests(unittest.TestCase):
    """No effect leaves without prior recorded authority and gates."""

    def test_request_effect_requires_running_plan(self) -> None:
        fixture = make_engine()
        engine = fixture.engine
        engine.create_plan(
            command_id="cmd/create-1",
            requested_at=T0,
            plan_id=PLAN_ID,
            steps=_steps_payload(),
            source_ref="intent/pay-1",
        )
        engine.authorize_plan(
            command_id="cmd/authorize-1",
            requested_at=T1,
            plan_id=PLAN_ID,
            authority_class=AUTHORITY_CLASS,
            fraud_decision=FRAUD_GATE,
            compliance_assessment=COMPLIANCE_GATE,
        )
        with self.assertRaises(CoreValidationError):
            engine.request_effect(
                command_id="cmd/req-1",
                requested_at=T2,
                step_id=STEP_IDS[0],
                idempotency_key="effect-key-1",
                authorization=fixture.authorization,
                hold=HOLD_GATE,
            )

    def test_request_effect_requires_pending_step(self) -> None:
        fixture = make_engine(submissions={"effect-key-1": ("accept",)})
        make_running_plan(fixture)
        _declare_and_submit(fixture, key="effect-key-1", at=T3)
        with self.assertRaises(CoreValidationError):
            fixture.engine.request_effect(
                command_id="cmd/req-2",
                requested_at=T4,
                step_id=STEP_IDS[0],
                idempotency_key="effect-key-2",
                authorization=fixture.authorization,
                hold=HOLD_GATE,
            )

    def test_request_effect_requires_held_reservation(self) -> None:
        fixture = make_engine()
        make_running_plan(fixture)
        with self.assertRaises(CoreValidationError):
            fixture.engine.request_effect(
                command_id="cmd/req-1",
                requested_at=T3,
                step_id=STEP_IDS[0],
                idempotency_key="effect-key-1",
                authorization=fixture.authorization,
                hold=_hold("RESERVED"),
            )

    def test_request_effect_requires_reservation_state_vocabulary(self) -> None:
        fixture = make_engine()
        make_running_plan(fixture)
        with self.assertRaises(CoreValidationError):
            fixture.engine.request_effect(
                command_id="cmd/req-1",
                requested_at=T3,
                step_id=STEP_IDS[0],
                idempotency_key="effect-key-1",
                authorization=fixture.authorization,
                hold=_hold("MAYBE"),
            )

    def test_request_effect_requires_covering_authorization_type(self) -> None:
        from src.execution import EffectAuthorization

        fixture = make_engine()
        make_running_plan(fixture)
        authorization = EffectAuthorization(
            authorizer="principal/ops",
            authority_class=AUTHORITY_CLASS,
            authorized_types=frozenset({"treasury/sweep"}),
            valid_from=T0,
            valid_until=T9,
        )
        with self.assertRaises(CoreValidationError):
            fixture.engine.request_effect(
                command_id="cmd/req-1",
                requested_at=T3,
                step_id=STEP_IDS[0],
                idempotency_key="effect-key-1",
                authorization=authorization,
                hold=HOLD_GATE,
            )

    def test_request_effect_requires_unexpired_authorization_window(self) -> None:
        from src.execution import EffectAuthorization

        fixture = make_engine()
        make_running_plan(fixture)
        authorization = EffectAuthorization(
            authorizer="principal/ops",
            authority_class=AUTHORITY_CLASS,
            authorized_types=frozenset(EFFECT_TYPES),
            valid_from=T0,
            valid_until=T2,
        )
        with self.assertRaises(CoreValidationError):
            fixture.engine.request_effect(
                command_id="cmd/req-1",
                requested_at=T3,
                step_id=STEP_IDS[0],
                idempotency_key="effect-key-1",
                authorization=authorization,
                hold=HOLD_GATE,
            )

    def test_request_effect_pins_authorization_digest(self) -> None:
        fixture = make_engine()
        make_running_plan(fixture)
        fixture.engine.request_effect(
            command_id="cmd/req-1",
            requested_at=T3,
            step_id=STEP_IDS[0],
            idempotency_key="effect-key-1",
            authorization=fixture.authorization,
            hold=HOLD_GATE,
        )
        request = fixture.engine.effect_request(
            "execution/plan/pay-1/step/1/request/1"
        )
        self.assertEqual(request.spec.authorization_digest, fixture.authorization.digest)
        self.assertEqual(request.state.value, "REQUESTED")

    def test_submit_happy_path_accepted(self) -> None:
        fixture = make_engine(submissions={"effect-key-1": ("accept",)})
        make_running_plan(fixture)
        transition = _declare_and_submit(fixture, key="effect-key-1", at=T3)
        self.assertEqual(transition.outcome, "accepted")
        engine = fixture.engine
        self.assertEqual(engine.step(STEP_IDS[0]).state.value, "SUBMITTED")
        self.assertEqual(
            engine.effect_request("execution/plan/pay-1/step/1/request/1").state.value,
            "SUBMITTED",
        )
        attempt = engine.attempt("execution/plan/pay-1/step/1/attempt/1")
        self.assertEqual(attempt.state.value, "IN_FLIGHT")
        self.assertEqual(attempt.spec.idempotency_key, "effect-key-1")
        self.assertEqual(fixture.rail.submit_call_count, 1)

    def test_submit_synchronous_rejection_fails_step(self) -> None:
        fixture = make_engine(submissions={"effect-key-1": ("reject",)})
        make_running_plan(fixture)
        _declare_and_submit(fixture, key="effect-key-1", at=T3)
        engine = fixture.engine
        self.assertEqual(engine.step(STEP_IDS[0]).state.value, "FAILED")
        attempt = engine.attempt("execution/plan/pay-1/step/1/attempt/1")
        self.assertEqual(attempt.state.value, "FAILED")
        self.assertIsNotNone(attempt.spec.reason)

    def test_submit_unknown_transport_lands_step_unknown(self) -> None:
        fixture = make_engine(submissions={"effect-key-1": ("unknown",)})
        make_running_plan(fixture)
        _declare_and_submit(fixture, key="effect-key-1", at=T3)
        engine = fixture.engine
        self.assertEqual(engine.step(STEP_IDS[0]).state.value, "UNKNOWN")
        self.assertEqual(
            engine.attempt("execution/plan/pay-1/step/1/attempt/1").state.value,
            "UNKNOWN",
        )


# ---------------------------------------------------------------------------
# 5. idempotent submission
# ---------------------------------------------------------------------------


class IdempotencyTests(unittest.TestCase):
    """Idempotency keys + duplicate detection; no second external effect."""

    def test_duplicate_submission_converges_without_second_port_call(self) -> None:
        fixture = make_engine(submissions={"effect-key-1": ("accept",)})
        make_running_plan(fixture)
        _declare_and_submit(fixture, key="effect-key-1", at=T3)
        engine = fixture.engine
        # A brand-new command (new command id, new command idempotency key)
        # resubmitting the SAME effect request (same effect idempotency key
        # and identical request content) must converge without a second rail
        # submission: the ledger echoes the recorded submission.
        transition = engine.submit_step(
            command_id="cmd/submit-again",
            requested_at=T4,
            step_id=STEP_IDS[0],
        )
        self.assertEqual(transition.outcome, "duplicate")
        self.assertEqual(fixture.rail.submit_call_count, 1)
        self.assertEqual(engine.step(STEP_IDS[0]).state.value, "SUBMITTED")

    def test_duplicate_request_declaration_converges(self) -> None:
        fixture = make_engine()
        make_running_plan(fixture)
        engine = fixture.engine
        engine.request_effect(
            command_id="cmd/req-1",
            requested_at=T3,
            step_id=STEP_IDS[0],
            idempotency_key="effect-key-1",
            authorization=fixture.authorization,
            hold=HOLD_GATE,
        )
        transition = engine.request_effect(
            command_id="cmd/req-again",
            requested_at=T3,
            step_id=STEP_IDS[0],
            idempotency_key="effect-key-1",
            authorization=fixture.authorization,
            hold=HOLD_GATE,
        )
        self.assertEqual(transition.outcome, "duplicate")

    def test_same_key_different_content_fails_closed(self) -> None:
        fixture = make_engine()
        make_running_plan(fixture)
        engine = fixture.engine
        engine.request_effect(
            command_id="cmd/req-1",
            requested_at=T3,
            step_id=STEP_IDS[0],
            idempotency_key="effect-key-1",
            authorization=fixture.authorization,
            hold=HOLD_GATE,
        )
        # Same key, different hold evidence version → different request
        # digest under one key: an idempotency conflict, never a silent
        # overwrite.
        with self.assertRaises(CoreValidationError):
            engine.request_effect(
                command_id="cmd/req-2",
                requested_at=T4,
                step_id=STEP_IDS[0],
                idempotency_key="effect-key-1",
                authorization=fixture.authorization,
                hold=_hold_with_version(5),
            )

    def test_retry_attempt_must_use_a_new_idempotency_key(self) -> None:
        fixture = make_engine(submissions={"effect-key-1": ("reject",)})
        make_running_plan(fixture)
        _declare_and_submit(fixture, key="effect-key-1", at=T3)
        engine = fixture.engine
        engine.retry_step(
            command_id="cmd/retry-1", requested_at=T4, step_id=STEP_IDS[0], reason="rail rejected"
        )
        with self.assertRaises(CoreValidationError):
            engine.request_effect(
                command_id="cmd/req-2",
                requested_at=T5,
                step_id=STEP_IDS[0],
                idempotency_key="effect-key-1",
                authorization=fixture.authorization,
                hold=HOLD_GATE,
            )

    def test_ledger_round_trip_is_byte_stable(self) -> None:
        from src.execution import EffectSubmissionLedger
        from src.core.serialization import canonical_json

        ledger = EffectSubmissionLedger()
        ledger.declare(
            key="effect-key-1",
            request_id="execution/plan/pay-1/step/1/request/1",
            request_digest="b" * 64,
        )
        ledger.record_submission(
            key="effect-key-1",
            submission={
                "status": "ACCEPTED",
                "native_reference": "sandbox/effect-key-1",
                "reason": None,
                "submitted_at": T3,
                "command_id": "cmd/submit-1",
            },
        )
        again = EffectSubmissionLedger.from_dict(ledger.to_dict())
        self.assertEqual(canonical_json(ledger.to_dict()), canonical_json(again.to_dict()))

    def test_sandbox_rail_dedupes_on_idempotency_key(self) -> None:
        from src.execution.dogfooding import SandboxRail

        rail = SandboxRail(submissions={"effect-key-1": ("accept",)}, queries={})
        request = _request_record(
            {
                "request_id": "execution/plan/pay-1/step/1/request/1",
                "plan_id": PLAN_ID,
                "step_id": STEP_IDS[0],
                "attempt_number": 1,
                "effect_type": EFFECT_TYPES[0],
                "adapter_id": ADAPTER_ID,
                "idempotency_key": "effect-key-1",
                "payload": {"currency": "USD"},
                "requested_at": T1,
                "authorization_digest": "a" * 64,
            }
        )
        first = rail.submit_effect(request)
        second = rail.submit_effect(request)
        self.assertEqual(first, second)
        self.assertEqual(rail.submit_call_count, 2)
        self.assertEqual(rail.processed_key_count, 1)

    def test_kernel_command_id_replay_converges(self) -> None:
        fixture = make_engine(submissions={"effect-key-1": ("accept",)})
        make_running_plan(fixture)
        engine = fixture.engine
        engine.request_effect(
            command_id="cmd/req-1",
            requested_at=T3,
            step_id=STEP_IDS[0],
            idempotency_key="effect-key-1",
            authorization=fixture.authorization,
            hold=HOLD_GATE,
        )
        first = engine.submit_step(
            command_id="cmd/submit-1", requested_at=T3, step_id=STEP_IDS[0]
        )
        second = engine.submit_step(
            command_id="cmd/submit-1", requested_at=T3, step_id=STEP_IDS[0]
        )
        self.assertEqual(first.outcome, "accepted")
        self.assertEqual(second.outcome, "duplicate")
        self.assertEqual(fixture.rail.submit_call_count, 1)


# ---------------------------------------------------------------------------
# 6. acknowledge / result recording / complete / fail
# ---------------------------------------------------------------------------


class AcknowledgeCompleteTests(unittest.TestCase):
    def test_acknowledge_records_receipt(self) -> None:
        fixture = make_engine(submissions={"effect-key-1": ("accept",)})
        make_running_plan(fixture)
        engine = fixture.engine
        _declare_and_submit(fixture, key="effect-key-1", at=T3)
        engine.acknowledge_step(
            command_id="cmd/ack-1",
            requested_at=T4,
            step_id=STEP_IDS[0],
            native_reference="sandbox/effect-key-1",
        )
        self.assertEqual(engine.step(STEP_IDS[0]).state.value, "ACKNOWLEDGED")
        receipt = engine.receipt("execution/plan/pay-1/step/1/request/1/receipt")
        self.assertEqual(receipt.spec.native_reference, "sandbox/effect-key-1")
        self.assertEqual(receipt.state.value, "ISSUED")

    def test_acknowledge_requires_submitted_step(self) -> None:
        fixture = make_engine()
        make_running_plan(fixture)
        with self.assertRaises(CoreValidationError):
            fixture.engine.acknowledge_step(
                command_id="cmd/ack-1",
                requested_at=T4,
                step_id=STEP_IDS[0],
                native_reference="sandbox/effect-key-1",
            )

    def test_record_result_then_complete_first_step(self) -> None:
        fixture = make_engine(submissions={"effect-key-1": ("accept",)})
        make_running_plan(fixture)
        engine = fixture.engine
        _declare_and_submit(fixture, key="effect-key-1", at=T3)
        engine.acknowledge_step(
            command_id="cmd/ack-1",
            requested_at=T4,
            step_id=STEP_IDS[0],
            native_reference="sandbox/effect-key-1",
        )
        engine.record_effect_result(
            command_id="cmd/result-1",
            requested_at=T5,
            step_id=STEP_IDS[0],
            outcome="SUCCEEDED",
            native_reference="sandbox/effect-key-1",
            observed_at=T5,
        )
        result = engine.effect_result(
            "execution/plan/pay-1/step/1/request/1/result"
        )
        self.assertEqual(result.state.value, "RECORDED")
        self.assertEqual(result.spec.outcome.value, "SUCCEEDED")
        engine.complete_step(
            command_id="cmd/complete-1", requested_at=T5, step_id=STEP_IDS[0]
        )
        self.assertEqual(engine.step(STEP_IDS[0]).state.value, "SUCCEEDED")
        # Step 2 still pending: the plan keeps running.
        self.assertEqual(engine.plan(PLAN_ID).state.value, "RUNNING")

    def test_complete_requires_recorded_success_result(self) -> None:
        fixture = make_engine(submissions={"effect-key-1": ("accept",)})
        make_running_plan(fixture)
        engine = fixture.engine
        _declare_and_submit(fixture, key="effect-key-1", at=T3)
        with self.assertRaises(CoreValidationError):
            engine.complete_step(
                command_id="cmd/complete-1", requested_at=T5, step_id=STEP_IDS[0]
            )

    def test_complete_rejects_failed_result(self) -> None:
        fixture = make_engine(submissions={"effect-key-1": ("accept",)})
        make_running_plan(fixture)
        engine = fixture.engine
        _declare_and_submit(fixture, key="effect-key-1", at=T3)
        engine.record_effect_result(
            command_id="cmd/result-1",
            requested_at=T5,
            step_id=STEP_IDS[0],
            outcome="FAILED",
            native_reference="sandbox/effect-key-1",
            observed_at=T5,
        )
        with self.assertRaises(CoreValidationError):
            engine.complete_step(
                command_id="cmd/complete-1", requested_at=T5, step_id=STEP_IDS[0]
            )

    def test_last_step_completion_completes_plan(self) -> None:
        fixture = make_engine(
            submissions={"k1": ("accept",), "k2": ("accept",)}
        )
        make_running_plan(fixture)
        _complete_first_step(fixture, key="k1")
        _complete_second_step(fixture, key="k2")
        self.assertEqual(fixture.engine.plan(PLAN_ID).state.value, "COMPLETED")
        self.assertEqual(
            fixture.engine.step(STEP_IDS[1]).state.value, "SUCCEEDED"
        )

    def test_fail_consumes_recorded_failure(self) -> None:
        fixture = make_engine(submissions={"k1": ("accept",)})
        make_running_plan(fixture)
        engine = fixture.engine
        _declare_and_submit(fixture, key="k1", at=T3)
        engine.record_effect_result(
            command_id="cmd/result-1",
            requested_at=T5,
            step_id=STEP_IDS[0],
            outcome="FAILED",
            native_reference="sandbox/k1",
            error_code="RAIL_NACK",
            observed_at=T5,
        )
        engine.fail_step(
            command_id="cmd/fail-1", requested_at=T5, step_id=STEP_IDS[0], reason="rail nack"
        )
        self.assertEqual(engine.step(STEP_IDS[0]).state.value, "FAILED")

    def test_fail_with_pending_sibling_leaves_plan_running(self) -> None:
        fixture = make_engine(submissions={"k1": ("accept",)})
        make_running_plan(fixture)
        engine = fixture.engine
        _declare_and_submit(fixture, key="k1", at=T3)
        engine.record_effect_result(
            command_id="cmd/result-1",
            requested_at=T5,
            step_id=STEP_IDS[0],
            outcome="FAILED",
            native_reference="sandbox/k1",
            observed_at=T5,
        )
        engine.fail_step(
            command_id="cmd/fail-1", requested_at=T5, step_id=STEP_IDS[0], reason="rail nack"
        )
        self.assertEqual(engine.plan(PLAN_ID).state.value, "RUNNING")

    def test_last_step_failure_fails_plan(self) -> None:
        fixture = make_engine(submissions={"k1": ("accept",), "k2": ("accept",)})
        make_running_plan(fixture)
        _complete_first_step(fixture, key="k1")
        engine = fixture.engine
        _declare_and_submit_second(fixture, key="k2", at=T4)
        engine.record_effect_result(
            command_id="cmd/result-2",
            requested_at=T5,
            step_id=STEP_IDS[1],
            outcome="FAILED",
            native_reference="sandbox/k2",
            observed_at=T5,
        )
        engine.fail_step(
            command_id="cmd/fail-2", requested_at=T5, step_id=STEP_IDS[1], reason="rail nack"
        )
        self.assertEqual(engine.plan(PLAN_ID).state.value, "FAILED")

    def test_record_effect_result_unknown_marks_attempt_not_step_terminal(self) -> None:
        fixture = make_engine(submissions={"k1": ("accept",)})
        make_running_plan(fixture)
        engine = fixture.engine
        _declare_and_submit(fixture, key="k1", at=T3)
        engine.record_effect_result(
            command_id="cmd/result-1",
            requested_at=T5,
            step_id=STEP_IDS[0],
            outcome="UNKNOWN",
            native_reference=None,
            observed_at=T5,
        )
        self.assertEqual(
            engine.attempt("execution/plan/pay-1/step/1/attempt/1").state.value,
            "UNKNOWN",
        )
        self.assertEqual(engine.step(STEP_IDS[0]).state.value, "SUBMITTED")

    def test_record_effect_result_on_terminal_step_fails(self) -> None:
        fixture = make_engine(submissions={"k1": ("accept",)})
        make_running_plan(fixture)
        _complete_first_step(fixture, key="k1")
        with self.assertRaises(CoreValidationError):
            fixture.engine.record_effect_result(
                command_id="cmd/result-2",
                requested_at=T5,
                step_id=STEP_IDS[0],
                outcome="SUCCEEDED",
                native_reference="sandbox/k1",
                observed_at=T5,
            )

    def test_record_effect_result_binds_to_the_current_request(self) -> None:
        fixture = make_engine(submissions={"k1": ("accept",)})
        make_running_plan(fixture)
        engine = fixture.engine
        _declare_and_submit(fixture, key="k1", at=T3)
        raw = engine.build_raw_command(
            command_id="cmd/result-forged",
            command_type="external/record-effect-result",
            requested_at=T5,
            target_refs=(STEP_IDS[0], "execution/plan/pay-1/step/1/request/2"),
            payload={
                "request_id": "execution/plan/pay-1/step/1/request/2",
                "outcome": "SUCCEEDED",
                "native_reference": "sandbox/k1",
                "error_code": None,
                "observed_at": T5,
                "detail": {},
            },
        )
        with self.assertRaises(CoreValidationError):
            engine.submit(raw)

    def test_result_digest_binds_to_request_content(self) -> None:
        fixture = make_engine(submissions={"k1": ("accept",)})
        make_running_plan(fixture)
        engine = fixture.engine
        _declare_and_submit(fixture, key="k1", at=T3)
        engine.record_effect_result(
            command_id="cmd/result-1",
            requested_at=T5,
            step_id=STEP_IDS[0],
            outcome="SUCCEEDED",
            native_reference="sandbox/k1",
            observed_at=T5,
        )
        result = engine.effect_result("execution/plan/pay-1/step/1/request/1/result")
        request = engine.effect_request("execution/plan/pay-1/step/1/request/1")
        self.assertEqual(result.spec.request_digest, request.spec.digest)


# ---------------------------------------------------------------------------
# 7. unknown-result recovery (never blind retry)
# ---------------------------------------------------------------------------


class UnknownResultRecoveryTests(unittest.TestCase):
    """Constitution invariants 9 + 12: reconcile before any unsafe retry."""

    def test_timeout_moves_submitted_step_to_unknown(self) -> None:
        fixture = make_engine(submissions={"k1": ("accept",)})
        make_running_plan(fixture)
        engine = fixture.engine
        _declare_and_submit(fixture, key="k1", at=T3)
        engine.timeout_step(
            command_id="cmd/timeout-1",
            requested_at=T4,
            step_id=STEP_IDS[0],
            deadline=T_DEADLINE,
            reason="no acknowledgment within window",
        )
        self.assertEqual(engine.step(STEP_IDS[0]).state.value, "UNKNOWN")
        self.assertEqual(
            engine.attempt("execution/plan/pay-1/step/1/attempt/1").state.value,
            "UNKNOWN",
        )

    def test_timeout_rejects_declaration_before_the_deadline(self) -> None:
        fixture = make_engine(submissions={"k1": ("accept",)})
        make_running_plan(fixture)
        engine = fixture.engine
        _declare_and_submit(fixture, key="k1", at=T3)
        with self.assertRaises(CoreValidationError):
            engine.timeout_step(
                command_id="cmd/timeout-early",
                requested_at=T3,
                step_id=STEP_IDS[0],
                deadline=T4,
                reason="too early",
            )

    def test_blind_retry_after_unknown_submission_fails_closed(self) -> None:
        fixture = make_engine(submissions={"k1": ("unknown",)})
        make_running_plan(fixture)
        _declare_and_submit(fixture, key="k1", at=T3)
        with self.assertRaises(CoreValidationError):
            fixture.engine.retry_step(
                command_id="cmd/retry-blind",
                requested_at=T4,
                step_id=STEP_IDS[0],
                reason="blind",
            )

    def test_blind_retry_after_timeout_fails_closed(self) -> None:
        fixture = make_engine(submissions={"k1": ("accept",)})
        make_running_plan(fixture)
        engine = fixture.engine
        _declare_and_submit(fixture, key="k1", at=T3)
        engine.timeout_step(
            command_id="cmd/timeout-1",
            requested_at=T4,
            step_id=STEP_IDS[0],
            deadline=T_DEADLINE,
            reason="no acknowledgment within window",
        )
        with self.assertRaises(CoreValidationError):
            engine.retry_step(
                command_id="cmd/retry-blind",
                requested_at=T5,
                step_id=STEP_IDS[0],
                reason="blind",
            )

    def test_retry_after_not_found_observation_succeeds(self) -> None:
        fixture = make_engine(
            submissions={"k1": ("unknown", "accept")},
            queries={"k1": ("not-found",)},
        )
        make_running_plan(fixture)
        engine = fixture.engine
        _declare_and_submit(fixture, key="k1", at=T3)
        engine.timeout_step(
            command_id="cmd/timeout-1",
            requested_at=T4,
            step_id=STEP_IDS[0],
            deadline=T_DEADLINE,
            reason="no acknowledgment within window",
        )
        transition = engine.reconcile_step(
            command_id="cmd/reconcile-1", requested_at=T5, step_id=STEP_IDS[0]
        )
        self.assertEqual(transition.outcome, "accepted")
        observation = engine.observations()[-1]
        self.assertEqual(observation.spec.kind.value, "QUERY")
        self.assertEqual(observation.spec.query_outcome, "NOT_FOUND")
        engine.retry_step(
            command_id="cmd/retry-1", requested_at=T5, step_id=STEP_IDS[0], reason="not found"
        )
        self.assertEqual(engine.step(STEP_IDS[0]).state.value, "PENDING")
        # The retried submission must use a NEW idempotency key.
        engine.request_effect(
            command_id="cmd/req-2",
            requested_at=T5,
            step_id=STEP_IDS[0],
            idempotency_key="k1-retry",
            authorization=fixture.authorization,
            hold=HOLD_GATE,
        )
        engine.submit_step(
            command_id="cmd/submit-2", requested_at=T5, step_id=STEP_IDS[0]
        )
        self.assertEqual(engine.step(STEP_IDS[0]).state.value, "SUBMITTED")
        self.assertEqual(
            engine.attempt("execution/plan/pay-1/step/1/attempt/2").state.value,
            "IN_FLIGHT",
        )

    def test_retry_after_still_unknown_query_fails_closed(self) -> None:
        fixture = make_engine(
            submissions={"k1": ("unknown",)},
            queries={"k1": ("unknown",)},
        )
        make_running_plan(fixture)
        engine = fixture.engine
        _declare_and_submit(fixture, key="k1", at=T3)
        engine.timeout_step(
            command_id="cmd/timeout-1",
            requested_at=T4,
            step_id=STEP_IDS[0],
            deadline=T_DEADLINE,
            reason="no acknowledgment within window",
        )
        engine.reconcile_step(
            command_id="cmd/reconcile-1", requested_at=T5, step_id=STEP_IDS[0]
        )
        with self.assertRaises(CoreValidationError):
            engine.retry_step(
                command_id="cmd/retry-1",
                requested_at=T5,
                step_id=STEP_IDS[0],
                reason="still unknown",
            )

    def test_retry_after_status_unknown_observation_fails_closed(self) -> None:
        fixture = make_engine(submissions={"k1": ("accept",)})
        make_running_plan(fixture)
        engine = fixture.engine
        _declare_and_submit(fixture, key="k1", at=T3)
        engine.record_status(
            command_id="cmd/status-1",
            requested_at=T4,
            step_id=STEP_IDS[0],
            native_code="UKWN",
        )
        self.assertEqual(engine.step(STEP_IDS[0]).state.value, "UNKNOWN")
        with self.assertRaises(CoreValidationError):
            engine.retry_step(
                command_id="cmd/retry-1",
                requested_at=T5,
                step_id=STEP_IDS[0],
                reason="status still unknown",
            )

    def test_retry_safe_status_observation_permits_retry(self) -> None:
        fixture = make_engine(
            submissions={"k1": ("accept",), "k2": ("accept",)}
        )
        make_running_plan(fixture)
        engine = fixture.engine
        _declare_and_submit(fixture, key="k1", at=T3)
        engine.timeout_step(
            command_id="cmd/timeout-1",
            requested_at=T4,
            step_id=STEP_IDS[0],
            deadline=T_DEADLINE,
            reason="no acknowledgment within window",
        )
        engine.record_status(
            command_id="cmd/status-1",
            requested_at=T5,
            step_id=STEP_IDS[0],
            native_code="RJCT",
        )
        engine.retry_step(
            command_id="cmd/retry-1", requested_at=T5, step_id=STEP_IDS[0], reason="rejected at rail"
        )
        self.assertEqual(engine.step(STEP_IDS[0]).state.value, "PENDING")

    def test_retry_after_failed_result_allowed_without_observation(self) -> None:
        fixture = make_engine(submissions={"k1": ("accept",)})
        make_running_plan(fixture)
        engine = fixture.engine
        _declare_and_submit(fixture, key="k1", at=T3)
        engine.record_effect_result(
            command_id="cmd/result-1",
            requested_at=T5,
            step_id=STEP_IDS[0],
            outcome="FAILED",
            native_reference="sandbox/k1",
            observed_at=T5,
        )
        engine.retry_step(
            command_id="cmd/retry-1", requested_at=T5, step_id=STEP_IDS[0], reason="definitive"
        )
        self.assertEqual(engine.step(STEP_IDS[0]).state.value, "PENDING")

    def test_retry_beyond_max_attempts_fails_closed(self) -> None:
        fixture = make_engine(
            submissions={"k1": ("reject",), "k1r": ("reject",)}
        )
        steps = _steps_payload()
        steps[0]["max_attempts"] = 1
        engine = fixture.engine
        engine.create_plan(
            command_id="cmd/create-1",
            requested_at=T0,
            plan_id=PLAN_ID,
            steps=steps,
            source_ref="intent/pay-1",
        )
        engine.authorize_plan(
            command_id="cmd/authorize-1",
            requested_at=T1,
            plan_id=PLAN_ID,
            authority_class=AUTHORITY_CLASS,
            fraud_decision=FRAUD_GATE,
            compliance_assessment=COMPLIANCE_GATE,
        )
        engine.start_plan(command_id="cmd/start-1", requested_at=T2, plan_id=PLAN_ID)
        _declare_and_submit(fixture, key="k1", at=T3)
        with self.assertRaises(CoreValidationError):
            engine.retry_step(
                command_id="cmd/retry-1",
                requested_at=T4,
                step_id=STEP_IDS[0],
                reason="budget exhausted",
            )

    def test_retry_requires_retryable_state(self) -> None:
        fixture = make_engine(submissions={"k1": ("accept",)})
        make_running_plan(fixture)
        with self.assertRaises(CoreValidationError):
            fixture.engine.retry_step(
                command_id="cmd/retry-1",
                requested_at=T4,
                step_id=STEP_IDS[0],
                reason="pending is not retryable",
            )

    def test_unknown_submission_recovers_via_query_succeeded(self) -> None:
        fixture = make_engine(
            submissions={"k1": ("unknown",)},
            queries={"k1": ("succeeded",)},
        )
        make_running_plan(fixture)
        engine = fixture.engine
        _declare_and_submit(fixture, key="k1", at=T3)
        engine.reconcile_step(
            command_id="cmd/reconcile-1", requested_at=T5, step_id=STEP_IDS[0]
        )
        engine.record_effect_result(
            command_id="cmd/result-1",
            requested_at=T5,
            step_id=STEP_IDS[0],
            outcome="SUCCEEDED",
            native_reference="sandbox/k1",
            observed_at=T5,
        )
        engine.complete_step(
            command_id="cmd/complete-1", requested_at=T5, step_id=STEP_IDS[0]
        )
        self.assertEqual(engine.step(STEP_IDS[0]).state.value, "SUCCEEDED")


# ---------------------------------------------------------------------------
# 8. external observations (evidence, never authority)
# ---------------------------------------------------------------------------


class ExternalObservationTests(unittest.TestCase):
    def test_record_status_maps_native_code_canonically(self) -> None:
        fixture = make_engine(submissions={"k1": ("accept",)})
        make_running_plan(fixture)
        engine = fixture.engine
        _declare_and_submit(fixture, key="k1", at=T3)
        engine.record_status(
            command_id="cmd/status-1",
            requested_at=T4,
            step_id=STEP_IDS[0],
            native_code="ACSD",
        )
        observation = engine.observations()[-1]
        self.assertEqual(observation.spec.kind.value, "STATUS")
        self.assertEqual(observation.spec.canonical_status, "ACKNOWLEDGED")

    def test_record_status_rejects_undeclared_native_code(self) -> None:
        fixture = make_engine(submissions={"k1": ("accept",)})
        make_running_plan(fixture)
        engine = fixture.engine
        _declare_and_submit(fixture, key="k1", at=T3)
        with self.assertRaises(CoreValidationError):
            engine.record_status(
                command_id="cmd/status-1",
                requested_at=T4,
                step_id=STEP_IDS[0],
                native_code="NOT-A-CODE",
            )

    def test_status_observation_unknown_drives_step_unknown(self) -> None:
        fixture = make_engine(submissions={"k1": ("accept",)})
        make_running_plan(fixture)
        engine = fixture.engine
        _declare_and_submit(fixture, key="k1", at=T3)
        engine.record_status(
            command_id="cmd/status-1",
            requested_at=T4,
            step_id=STEP_IDS[0],
            native_code="UKWN",
        )
        self.assertEqual(engine.step(STEP_IDS[0]).state.value, "UNKNOWN")

    def test_status_observation_success_is_evidence_only(self) -> None:
        fixture = make_engine(submissions={"k1": ("accept",)})
        make_running_plan(fixture)
        engine = fixture.engine
        _declare_and_submit(fixture, key="k1", at=T3)
        engine.record_status(
            command_id="cmd/status-1",
            requested_at=T4,
            step_id=STEP_IDS[0],
            native_code="PDNG",
        )
        self.assertEqual(engine.step(STEP_IDS[0]).state.value, "SUBMITTED")

    def test_finality_observation_records_evidence_only(self) -> None:
        fixture = make_engine(submissions={"k1": ("accept",)})
        make_running_plan(fixture)
        engine = fixture.engine
        _declare_and_submit(fixture, key="k1", at=T3)
        before = {record.object_id: record.to_dict() for record in engine.objects()}
        engine.record_finality(
            command_id="cmd/finality-1",
            requested_at=T5,
            step_id=STEP_IDS[0],
            claim="FINAL",
            native_reference="sandbox/k1",
        )
        after = {record.object_id: record.to_dict() for record in engine.objects()}
        # Exactly one new object appears: the observation. No plan/step/
        # attempt/request envelope mutates — finality is recorded, never
        # established here.
        self.assertEqual(len(after), len(before) + 1)
        mutated = {
            object_id for object_id in before if after.get(object_id) != before[object_id]
        }
        self.assertEqual(mutated, set())
        observation = engine.observations()[-1]
        self.assertEqual(observation.spec.kind.value, "FINALITY")
        self.assertEqual(observation.spec.finality_claim, "FINAL")

    def test_finality_observation_requires_claim_vocabulary(self) -> None:
        fixture = make_engine(submissions={"k1": ("accept",)})
        make_running_plan(fixture)
        engine = fixture.engine
        _declare_and_submit(fixture, key="k1", at=T3)
        with self.assertRaises(CoreValidationError):
            engine.record_finality(
                command_id="cmd/finality-1",
                requested_at=T5,
                step_id=STEP_IDS[0],
                claim="TOTALLY_FINAL",
                native_reference="sandbox/k1",
            )

    def test_query_observation_requires_subject_binding(self) -> None:
        fixture = make_engine(submissions={"k1": ("accept",)})
        make_running_plan(fixture)
        engine = fixture.engine
        _declare_and_submit(fixture, key="k1", at=T3)
        raw = engine.build_raw_command(
            command_id="cmd/obs-forged",
            command_type="external/record-observation",
            requested_at=T5,
            target_refs=(STEP_IDS[0],),
            payload={
                "query": {
                    "outcome": "NOT_FOUND",
                    "native_reference": None,
                },
                "subject_ref": "execution/plan/pay-1/step/1/request/2",
            },
        )
        with self.assertRaises(CoreValidationError):
            engine.submit(raw)

    def test_observations_are_immutable_and_append_only(self) -> None:
        fixture = make_engine(submissions={"k1": ("accept",)})
        make_running_plan(fixture)
        engine = fixture.engine
        _declare_and_submit(fixture, key="k1", at=T3)
        engine.reconcile_step(
            command_id="cmd/reconcile-1", requested_at=T4, step_id=STEP_IDS[0]
        )
        engine.reconcile_step(
            command_id="cmd/reconcile-2", requested_at=T5, step_id=STEP_IDS[0]
        )
        self.assertEqual(len(engine.observations()), 2)
        ids = [observation.object_id for observation in engine.observations()]
        self.assertEqual(len(set(ids)), len(ids))


# ---------------------------------------------------------------------------
# 9. adapter ports
# ---------------------------------------------------------------------------


class AdapterPortTests(unittest.TestCase):
    def test_adapter_binding_requires_matching_ids(self) -> None:
        from src.execution import AdapterBinding
        from src.execution.dogfooding import (
            SandboxRail,
            make_sandbox_world_adapter,
        )

        rail = SandboxRail(submissions={}, queries={})
        with self.assertRaises(CoreValidationError):
            AdapterBinding(
                adapter_id="adapter/other-rail",
                submission_port=rail,
                reconciliation_port=rail,
                world_adapter=make_sandbox_world_adapter(),
            )

    def test_adapter_binding_rejects_pure_observation_contract(self) -> None:
        from src.execution import AdapterBinding
        from src.execution.dogfooding import SandboxRail, make_sandbox_world_adapter
        from src.interoperability import (
            EffectInterface,
            ObservationInterface,
            WorldAdapter,
        )

        rail = SandboxRail(submissions={}, queries={})
        contract = WorldAdapter(
            adapter_id=ADAPTER_ID,
            capability_id="capability/sandbox-rail",
            observation_interface=ObservationInterface(
                operations=("RESOLVE_ENDPOINT", "PAYMENT_STATUS")
            ),
            effect_interface=EffectInterface(),
            fidelity_class="SIMULATION",
        )
        with self.assertRaises(CoreValidationError):
            AdapterBinding(
                adapter_id=ADAPTER_ID,
                submission_port=rail,
                reconciliation_port=rail,
                world_adapter=contract,
            )

    def test_adapter_submission_requires_native_reference_when_accepted(self) -> None:
        from src.execution import AdapterSubmission

        with self.assertRaises(CoreValidationError):
            AdapterSubmission(status="ACCEPTED", native_reference=None, reason=None)

    def test_adapter_submission_requires_reason_when_rejected(self) -> None:
        from src.execution import AdapterSubmission

        with self.assertRaises(CoreValidationError):
            AdapterSubmission(status="REJECTED", native_reference=None, reason=None)

    def test_adapter_submission_requires_reason_when_unknown(self) -> None:
        from src.execution import AdapterSubmission

        with self.assertRaises(CoreValidationError):
            AdapterSubmission(status="UNKNOWN", native_reference=None, reason=None)

    def test_adapter_query_result_requires_reference_when_succeeded(self) -> None:
        from src.execution import AdapterQueryResult

        with self.assertRaises(CoreValidationError):
            AdapterQueryResult(outcome="SUCCEEDED", native_reference=None, detail=None)

    def test_adapter_query_result_outcome_is_closed(self) -> None:
        from src.execution import AdapterQueryResult

        with self.assertRaises(CoreValidationError):
            AdapterQueryResult(outcome="MAYBE", native_reference=None, detail=None)

    def test_engine_requires_at_least_one_binding(self) -> None:
        from src.execution import ExecutionEngine

        with self.assertRaises(CoreValidationError):
            ExecutionEngine(environment_id=ENV, domain_id=DOMAIN, bindings={})

    def test_port_api_version_is_pinned(self) -> None:
        from src.execution import ADAPTER_PORT_API_VERSION

        self.assertEqual(ADAPTER_PORT_API_VERSION, "v0.1")


# ---------------------------------------------------------------------------
# 10. kernel binding
# ---------------------------------------------------------------------------


class KernelBindingTests(unittest.TestCase):
    def test_events_use_execution_namespace(self) -> None:
        from src.execution import COMMAND_EVENT_TYPES

        fixture = make_engine(submissions={"k1": ("accept",)})
        make_running_plan(fixture)
        engine = fixture.engine
        _declare_and_submit(fixture, key="k1", at=T3)
        engine.acknowledge_step(
            command_id="cmd/ack-1",
            requested_at=T4,
            step_id=STEP_IDS[0],
            native_reference="sandbox/k1",
        )
        observed = {entry.event.event_type for entry in engine.journal()}
        for transition in engine.transitions():
            if transition.outcome != "accepted":
                continue
            self.assertIsNotNone(transition.result.event)
            self.assertEqual(
                transition.result.event.event_type,
                COMMAND_EVENT_TYPES[transition.command_type],
            )
        self.assertIn("execution/plan-created", observed)
        self.assertIn("execution/step-submitted", observed)
        self.assertIn("execution/step-acknowledged", observed)
        self.assertIn("execution/effect-requested", observed)

    def test_unknown_command_type_rejected(self) -> None:
        fixture = make_engine()
        engine = fixture.engine
        raw = engine.build_raw_command(
            command_id="cmd/whatever",
            command_type="execution/teleport",
            requested_at=T1,
            target_refs=(PLAN_ID,),
            payload={},
        )
        transition = engine.submit(raw)
        self.assertEqual(transition.outcome, "rejected")
        self.assertEqual(transition.reason.value, "unknown_command_type")

    def test_environment_mismatch_rejected(self) -> None:
        fixture = make_engine()
        engine = fixture.engine
        raw = engine.build_raw_command(
            command_id="cmd/elsewhere",
            command_type="execution/plan.create",
            requested_at=T1,
            target_refs=(PLAN_ID,),
            payload={},
            environment_id="env/elsewhere",
        )
        transition = engine.submit(raw)
        self.assertEqual(transition.outcome, "rejected")
        self.assertEqual(transition.reason.value, "environment_mismatch")

    def test_stale_expected_version_rejected(self) -> None:
        fixture = make_engine()
        make_running_plan(fixture)
        engine = fixture.engine
        raw = engine.build_raw_command(
            command_id="cmd/stale-start",
            command_type="execution/plan.start",
            requested_at=T3,
            target_refs=(PLAN_ID,),
            payload={},
            expected_versions={PLAN_ID: 1},
        )
        transition = engine.submit(raw)
        self.assertEqual(transition.outcome, "rejected")
        self.assertEqual(transition.reason.value, "version_conflict")

    def test_handler_validation_failure_leaves_state_byte_identical(self) -> None:
        fixture = make_engine()
        make_running_plan(fixture)
        engine = fixture.engine
        before = [envelope.to_dict() for envelope in engine.objects()]
        journal_before = len(engine.journal())
        raw = engine.build_raw_command(
            command_id="cmd/bad-authorize",
            command_type="execution/plan.authorize",
            requested_at=T3,
            target_refs=(PLAN_ID,),
            payload={"authority_class": AUTHORITY_CLASS},
        )
        with self.assertRaises(CoreValidationError):
            engine.submit(raw)
        self.assertEqual([envelope.to_dict() for envelope in engine.objects()], before)
        self.assertEqual(len(engine.journal()), journal_before)

    def test_journal_is_append_only(self) -> None:
        fixture = make_engine(submissions={"k1": ("accept",)})
        make_running_plan(fixture)
        engine = fixture.engine
        _declare_and_submit(fixture, key="k1", at=T3)
        event_ids = [entry.event.event_id for entry in engine.journal()]
        self.assertEqual(len(set(event_ids)), len(event_ids))


# ---------------------------------------------------------------------------
# 11. rebuild / transformation completeness
# ---------------------------------------------------------------------------


class RebuildTests(unittest.TestCase):
    def test_rebuild_from_journal_reproduces_index_and_ledger(self) -> None:
        fixture = make_engine(
            submissions={"k1": ("unknown", "accept")},
            queries={"k1": ("not-found",)},
        )
        make_running_plan(fixture)
        engine = fixture.engine
        _declare_and_submit(fixture, key="k1", at=T3)
        engine.timeout_step(
            command_id="cmd/timeout-1",
            requested_at=T4,
            step_id=STEP_IDS[0],
            deadline=T_DEADLINE,
            reason="no acknowledgment within window",
        )
        engine.reconcile_step(
            command_id="cmd/reconcile-1", requested_at=T5, step_id=STEP_IDS[0]
        )
        engine.retry_step(
            command_id="cmd/retry-1", requested_at=T5, step_id=STEP_IDS[0], reason="not found"
        )
        snapshot = engine.snapshot_state()
        fixture2 = make_engine(
            submissions={"k1": ("unknown", "accept")},
            queries={"k1": ("not-found",)},
        )
        fixture2.engine.restore_state(snapshot)
        restored = fixture2.engine
        self.assertEqual(
            [record.to_dict() for record in restored.observations()],
            [record.to_dict() for record in engine.observations()],
        )
        self.assertEqual(restored.plan(PLAN_ID).to_dict(), engine.plan(PLAN_ID).to_dict())
        self.assertEqual(
            restored.step(STEP_IDS[0]).to_dict(), engine.step(STEP_IDS[0]).to_dict()
        )
        self.assertEqual(
            restored.effect_request("execution/plan/pay-1/step/1/request/1").to_dict(),
            engine.effect_request("execution/plan/pay-1/step/1/request/1").to_dict(),
        )
        self.assertEqual(
            fixture2.engine.submission_ledger().to_dict(),
            engine.submission_ledger().to_dict(),
        )

    def test_snapshot_round_trip_is_byte_stable(self) -> None:
        from src.core.serialization import canonical_json

        fixture = make_engine(submissions={"k1": ("accept",)})
        make_running_plan(fixture)
        engine = fixture.engine
        _declare_and_submit(fixture, key="k1", at=T3)
        snapshot = engine.snapshot_state()
        self.assertEqual(
            canonical_json(snapshot), canonical_json(engine.snapshot_state())
        )

    def test_restore_rejects_a_tampered_snapshot(self) -> None:
        fixture = make_engine(submissions={"k1": ("accept",)})
        make_running_plan(fixture)
        engine = fixture.engine
        _declare_and_submit(fixture, key="k1", at=T3)
        snapshot = engine.snapshot_state()
        plan_record = snapshot["index"][PLAN_ID]
        plan_record["payload"]["source_ref"] = "intent/tampered"
        fixture2 = make_engine(submissions={"k1": ("accept",)})
        with self.assertRaises(CoreValidationError):
            fixture2.engine.restore_state(snapshot)

    def test_records_verify_on_trusted_path_after_rebuild(self) -> None:
        fixture = make_engine(submissions={"k1": ("accept",)})
        make_running_plan(fixture)
        engine = fixture.engine
        _declare_and_submit(fixture, key="k1", at=T3)
        engine.acknowledge_step(
            command_id="cmd/ack-1",
            requested_at=T4,
            step_id=STEP_IDS[0],
            native_reference="sandbox/k1",
        )
        snapshot = engine.snapshot_state()
        fixture2 = make_engine(submissions={"k1": ("accept",)})
        fixture2.engine.restore_state(snapshot)
        plan = fixture2.engine.plan(PLAN_ID)
        plan.to_json()  # trusted-path decode of a sealed composite
        self.assertEqual(plan.state.value, "RUNNING")


# ---------------------------------------------------------------------------
# 12. dogfooding conformance (sandbox rail through the public ports)
# ---------------------------------------------------------------------------


class DogfoodingConformanceTests(unittest.TestCase):
    def test_experiment_transcript_is_deterministic(self) -> None:
        from src.execution.dogfooding import build_transcript

        first, digest_first = build_transcript()
        second, digest_second = build_transcript()
        self.assertEqual(first, second)
        self.assertEqual(digest_first, digest_second)

    def test_experiment_classifies_pass(self) -> None:
        from src.execution.dogfooding import build_transcript

        transcript, _ = build_transcript()
        self.assertIn("DOGFOOD-014: PASS", transcript.splitlines()[-1])

    def test_experiment_exercises_the_public_adapter_path(self) -> None:
        from src.execution.dogfooding import build_transcript

        transcript, _ = build_transcript()
        self.assertIn("adapter=interoperability/adapter/sandbox-rail", transcript)
        self.assertIn("submit_calls=3", transcript)
        self.assertIn("unknown_result_recovered=True", transcript)

    def test_sandbox_rail_is_deterministic(self) -> None:
        from src.execution.dogfooding import SandboxRail

        request = _request_record(
            {
                "request_id": "execution/plan/pay-1/step/1/request/1",
                "plan_id": PLAN_ID,
                "step_id": STEP_IDS[0],
                "attempt_number": 1,
                "effect_type": EFFECT_TYPES[0],
                "adapter_id": ADAPTER_ID,
                "idempotency_key": "k1",
                "payload": {"currency": "USD"},
                "requested_at": T1,
                "authorization_digest": "a" * 64,
            }
        )
        outcomes = []
        for _ in range(2):
            rail = SandboxRail(
                submissions={"k1": ("unknown", "accept")}, queries={"k1": ("not-found",)}
            )
            outcomes.append(rail.submit_effect(request).to_dict())
            outcomes.append(rail.query_effect(request).to_dict())
        self.assertEqual(outcomes[0], outcomes[2])
        self.assertEqual(outcomes[1], outcomes[3])


# ---------------------------------------------------------------------------
# shared helpers used by the lifecycle fixtures
# ---------------------------------------------------------------------------


def _hold_with_version(version: int) -> dict:
    return {
        "reservation_id": RESERVATION_ID,
        "state": "HELD",
        "object_version": version,
    }


def _envelope_for(spec) -> "object":
    from src.core.envelope import ObjectEnvelope, Provenance
    from src.execution import EFFECT_REQUEST_OBJECT_TYPE

    return ObjectEnvelope(
        object_id=spec.request_id,
        object_type=EFFECT_REQUEST_OBJECT_TYPE,
        object_version=1,
        environment_id=ENV,
        domain_id=DOMAIN,
        schema_version=1,
        protocol_version="v0.1",
        state="REQUESTED",
        provenance=Provenance(
            issuer="principal/test",
            source="execution/test",
            recorded_at=spec.requested_at,
        ),
        causation_id=None,
        correlation_id=None,
    ).with_integrity_hash()


def _request_record(spec_dict: dict) -> "object":
    """A standalone sealed EffectRequest built from a canonical spec dict."""
    from src.execution import EffectRequest, EffectRequestSpec
    from src.execution.seal import seal_composite

    spec = EffectRequestSpec.from_dict(spec_dict)
    envelope = _envelope_for(spec)
    return EffectRequest(
        envelope=envelope, spec=spec, integrity_hash=seal_composite(envelope, spec)
    )


def _declare_and_submit(fixture, *, key: str, at: str):
    engine = fixture.engine
    engine.request_effect(
        command_id=f"cmd/req-{key}",
        requested_at=at,
        step_id=STEP_IDS[0],
        idempotency_key=key,
        authorization=fixture.authorization,
        hold=HOLD_GATE,
    )
    return engine.submit_step(
        command_id=f"cmd/submit-{key}", requested_at=at, step_id=STEP_IDS[0]
    )


def _declare_and_submit_second(fixture, *, key: str, at: str):
    engine = fixture.engine
    engine.request_effect(
        command_id=f"cmd/req-{key}",
        requested_at=at,
        step_id=STEP_IDS[1],
        idempotency_key=key,
        authorization=fixture.authorization,
        hold=HOLD_GATE,
    )
    return engine.submit_step(
        command_id=f"cmd/submit-{key}", requested_at=at, step_id=STEP_IDS[1]
    )


def _complete_first_step(fixture, *, key: str) -> None:
    engine = fixture.engine
    _declare_and_submit(fixture, key=key, at=T3)
    engine.acknowledge_step(
        command_id="cmd/ack-1",
        requested_at=T4,
        step_id=STEP_IDS[0],
        native_reference=f"sandbox/{key}",
    )
    engine.record_effect_result(
        command_id="cmd/result-1",
        requested_at=T5,
        step_id=STEP_IDS[0],
        outcome="SUCCEEDED",
        native_reference=f"sandbox/{key}",
        observed_at=T5,
    )
    engine.complete_step(
        command_id="cmd/complete-1", requested_at=T5, step_id=STEP_IDS[0]
    )


def _complete_second_step(fixture, *, key: str) -> None:
    engine = fixture.engine
    _declare_and_submit_second(fixture, key=key, at=T4)
    engine.acknowledge_step(
        command_id="cmd/ack-2",
        requested_at=T4,
        step_id=STEP_IDS[1],
        native_reference=f"sandbox/{key}",
    )
    engine.record_effect_result(
        command_id="cmd/result-2",
        requested_at=T5,
        step_id=STEP_IDS[1],
        outcome="SUCCEEDED",
        native_reference=f"sandbox/{key}",
        observed_at=T5,
    )
    engine.complete_step(
        command_id="cmd/complete-2", requested_at=T5, step_id=STEP_IDS[1]
    )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
