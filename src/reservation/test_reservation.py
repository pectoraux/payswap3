"""WORK-012 contract and discrimination suite (red-first).

This suite was authored BEFORE the implementation and captures the frozen
contract of the protocol-level reservation domain:

- the frozen v0.1 ``Reservation`` command family
  ``Create/Hold/Commit/Amend/Release/Expire/Default/Consume`` with a closed
  state vocabulary, versioned transitions and terminal states;
- conditional commit: window validity at ``as_of`` + explicit condition-set
  satisfaction + expected-version preconditions, failing closed otherwise;
- explicit expiry/release/default/consume paths, each a distinct transition
  with its own state and provenance;
- keyed concurrency: per-resource-key serialization with deterministic
  precedence (earliest ``requested_at``, then command id, then actor),
  cross-key progress, and no global mutex;
- the versioned reservation store: expected-version preconditions, atomic
  validate-all-then-apply batches with multi-object rollback, and live-key
  exclusivity (a resource key admits at most one non-terminal reservation);
- sealed durable objects on the canonical core envelope with domain seals
  and fail-closed tamper rejection;
- the import boundary: domain modules import only the stdlib, the canonical
  core and the three declared dependency domains actually consumed
  (src/transition, src/value, src/capability) — never unmerged siblings.

The market-local ``Reservation`` of WORK-010 is a bounded mechanism-local
claim artifact (``Create/Commit/Release/Expire`` only); this suite pins the
protocol-level superset owned by WORK-012.
"""

from __future__ import annotations

import ast
import sys
import threading
import time
import unittest
from pathlib import Path

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256

from src.reservation import (
    Amount,
    CommitEvidence,
    ConditionEvaluation,
    ConditionKind,
    ConditionSpec,
    CoreValidationError as ReservationCoreError,
    DefaultReason,
    ExpectedVersion,
    KeyedLockManager,
    OperatingWindow,
    Provenance as ReservationProvenance,
    RESERVATION_API_VERSION,
    RESERVATION_COMMANDS,
    RESERVATION_OBJECT_TYPE,
    RESERVATION_PROTOCOL_VERSION,
    RESERVATION_SCHEMA_VERSION,
    RESERVATION_TERMINAL_STATES,
    RESERVATION_TRANSITIONS,
    Reservation,
    ReservationCommand,
    ReservationSpec,
    ReservationState,
    ReservationStore,
    WriterClaim,
    amend_reservation,
    commit_reservation,
    consume_reservation,
    create_reservation,
    default_reservation,
    evaluate_condition_satisfaction,
    expire_reservation,
    hold_reservation,
    release_reservation,
    resolve_precedence,
)

ENV = "env/test"
DOMAIN = "domain/demo"
STAMP = "2026-09-02T00:00:00Z"
ASSET = "asset/USD"
OTHER_ASSET = "asset/EUR"

OPENS_AT = "2026-09-03T00:00:00Z"
CLOSES_AT = "2026-09-03T01:00:00Z"
LATER_CLOSES_AT = "2026-09-03T02:00:00Z"
BEFORE_WINDOW = "2026-09-02T23:59:59Z"
IN_WINDOW = "2026-09-03T00:30:00Z"
IN_WINDOW_LATER = "2026-09-03T00:45:00Z"
AT_CLOSE = "2026-09-03T01:00:00Z"
AFTER_CLOSE = "2026-09-03T02:00:00Z"

RESOURCE_KEY = "resource/provider-alpha/asset-USD/slot-7"
OTHER_RESOURCE_KEY = "resource/provider-beta/asset-USD/slot-8"
RESERVATION_ID = "reservation/r-1"
HOLD_REF = "value/hold/h-1"
OTHER_HOLD_REF = "value/hold/h-2"
FUNDING_REF = "value/funding-source/wallet-7"

CLAIM_A = WriterClaim(
    actor="actor/alpha",
    requested_at="2026-09-03T00:00:01Z",
    command_id="command/w-012-alpha",
)
CLAIM_B = WriterClaim(
    actor="actor/beta",
    requested_at="2026-09-03T00:00:02Z",
    command_id="command/w-012-beta",
)
CLAIM_C = WriterClaim(
    actor="actor/gamma",
    requested_at="2026-09-03T00:00:02Z",
    command_id="command/w-012-gamma",
)
CLAIM_LATE = WriterClaim(
    actor="actor/late",
    requested_at="2026-09-03T00:00:09Z",
    command_id="command/w-012-late",
)

DOMAIN_PACKAGE = Path(__file__).parent
DOMAIN_SOURCES = sorted(
    source
    for source in DOMAIN_PACKAGE.glob("*.py")
    if source.name != "test_reservation.py"
)
ALLOWED_SRC_DOMAINS = frozenset({"core", "transition", "value", "capability"})
FORBIDDEN_SRC_DOMAINS = frozenset(
    {
        "market",
        "intent",
        "money",
        "trust",
        "interoperability",
        "liquidity",
        "safety",
        "evidence",
    }
)
STDLIB_ROOTS = frozenset(sys.stdlib_module_names)


def prov(source: str = "reservation/test") -> Provenance:
    return Provenance(
        issuer="principal/reservation-operator",
        source=source,
        recorded_at=STAMP,
        evidence_refs=("evidence/work-012",),
    )


def amount(value: int = 25000, asset: str = ASSET) -> Amount:
    return Amount(value=value, scale=2, asset=asset)


def window(
    opens_at: str = OPENS_AT, closes_at: str = CLOSES_AT
) -> OperatingWindow:
    return OperatingWindow(opens_at=opens_at, closes_at=closes_at)


def conditions() -> tuple[ConditionSpec, ...]:
    return (
        ConditionSpec(
            condition_key="cond/encumbrance",
            kind=ConditionKind.ENCUMBRANCE,
            ref=HOLD_REF,
        ),
        ConditionSpec(
            condition_key="cond/funding",
            kind=ConditionKind.FUNDING,
            ref=FUNDING_REF,
        ),
    )


def reservation(**overrides) -> Reservation:
    kwargs = dict(
        reservation_id=RESERVATION_ID,
        resource_key=RESOURCE_KEY,
        provider="provider/alpha",
        beneficiary="principal/merchant-42",
        asset=ASSET,
        amount=Amount(value=25000, scale=2, asset=ASSET),
        window=OperatingWindow(opens_at=OPENS_AT, closes_at=CLOSES_AT),
        conditions=(),
        funding_refs=(FUNDING_REF,),
        source_ref="market/quote/q-1",
        environment_id=ENV,
        domain_id=DOMAIN,
        provenance=prov("reservation/create"),
        correlation_id="corr/w-012",
    )
    kwargs.update(overrides)
    return create_reservation(**kwargs)


def apply_one(
    store: ReservationStore,
    record: Reservation,
    writer: WriterClaim,
    expected_version: int,
) -> None:
    store.apply(
        (record,),
        expected_versions=(
            ExpectedVersion(record.envelope.object_id, expected_version),
        ),
        writer=writer,
    )


def _wait_until(predicate, timeout: float = 10.0) -> None:
    """Bounded test synchronization (never a domain decision input)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.001)
    raise AssertionError("test synchronization timed out")


def _reseal_envelope(envelope_dict: dict, **changes) -> dict:
    """Rebuild a tampered envelope dict with a freshly sealed core hash.

    Test-only forger: ``ObjectEnvelope.from_dict`` verifies integrity, so a
    tampered dict must be resealed before the domain-level checks are
    reachable at all.
    """
    base = dict(envelope_dict)
    envelope = ObjectEnvelope(
        object_id=base["object_id"],
        object_type=changes.pop("object_type", base["object_type"]),
        object_version=base["object_version"],
        environment_id=base["environment_id"],
        domain_id=base["domain_id"],
        schema_version=changes.pop("schema_version", base["schema_version"]),
        protocol_version=changes.pop("protocol_version", base["protocol_version"]),
        state=changes.pop("state", base["state"]),
        provenance=Provenance.from_dict(base["provenance"]),
        causation_id=base["causation_id"],
        correlation_id=base["correlation_id"],
        previous_version=base["previous_version"],
    ).with_integrity_hash()
    assert not changes, changes
    return envelope.to_dict()


def _reseal_composite(decoded: dict) -> dict:
    """Recompute the domain seal over a tampered payload (test-only forger)."""
    decoded["integrity_hash"] = canonical_sha256(
        {"envelope": decoded["envelope"], "payload": decoded["payload"]}
    )
    return decoded


# ---------------------------------------------------------------------------
# 1. Static contracts and the import boundary.
# ---------------------------------------------------------------------------


class StaticContractTests(unittest.TestCase):
    """The typed, versioned public boundary of the reservation domain."""

    def test_api_protocol_and_schema_versions_are_frozen(self) -> None:
        self.assertEqual(RESERVATION_API_VERSION, 1)
        self.assertEqual(RESERVATION_PROTOCOL_VERSION, "v0.1")
        self.assertEqual(RESERVATION_SCHEMA_VERSION, 1)

    def test_object_type_is_internal_non_registry_format(self) -> None:
        # The frozen registry lists no reservation object type, so — per the
        # sibling convention — the domain uses an internal non-registry
        # "reservation/..." format and never invents a "payswap/..." name.
        self.assertEqual(RESERVATION_OBJECT_TYPE, "reservation/resource-reservation/v1")
        self.assertTrue(RESERVATION_OBJECT_TYPE.startswith("reservation/"))
        self.assertFalse(RESERVATION_OBJECT_TYPE.startswith("payswap/"))

    def test_command_family_is_the_frozen_reservation_vocabulary(self) -> None:
        self.assertEqual(
            RESERVATION_COMMANDS,
            ("Create", "Hold", "Commit", "Amend", "Release", "Expire", "Default", "Consume"),
        )
        self.assertEqual(
            {command.value for command in ReservationCommand},
            {"Create", "Hold", "Commit", "Amend", "Release", "Expire", "Default", "Consume"},
        )
        # The protocol-level family is a strict superset of the bounded
        # market-local subset (Create/Commit/Release/Expire) of WORK-010.
        self.assertGreater(
            set(RESERVATION_COMMANDS),
            {"Create", "Commit", "Release", "Expire"},
        )

    def test_state_vocabulary_is_closed(self) -> None:
        self.assertEqual(
            {state.value for state in ReservationState},
            {
                "RESERVED",
                "HELD",
                "COMMITTED",
                "RELEASED",
                "EXPIRED",
                "DEFAULTED",
                "CONSUMED",
            },
        )
        with self.assertRaises(ValueError):
            ReservationState("PENDING")

    def test_terminal_states_are_declared_and_closed(self) -> None:
        self.assertEqual(
            {state.value for state in RESERVATION_TERMINAL_STATES},
            {"RELEASED", "EXPIRED", "DEFAULTED", "CONSUMED"},
        )

    def test_transition_table_matches_the_frozen_family(self) -> None:
        self.assertEqual(set(RESERVATION_TRANSITIONS), set(ReservationCommand))
        self.assertEqual(
            RESERVATION_TRANSITIONS[ReservationCommand.CREATE],
            frozenset(),
        )
        self.assertEqual(
            RESERVATION_TRANSITIONS[ReservationCommand.HOLD],
            frozenset({ReservationState.RESERVED}),
        )
        self.assertEqual(
            RESERVATION_TRANSITIONS[ReservationCommand.AMEND],
            frozenset({ReservationState.RESERVED, ReservationState.HELD}),
        )
        self.assertEqual(
            RESERVATION_TRANSITIONS[ReservationCommand.COMMIT],
            frozenset({ReservationState.RESERVED, ReservationState.HELD}),
        )
        self.assertEqual(
            RESERVATION_TRANSITIONS[ReservationCommand.RELEASE],
            frozenset({ReservationState.RESERVED, ReservationState.HELD}),
        )
        self.assertEqual(
            RESERVATION_TRANSITIONS[ReservationCommand.EXPIRE],
            frozenset({ReservationState.RESERVED, ReservationState.HELD}),
        )
        self.assertEqual(
            RESERVATION_TRANSITIONS[ReservationCommand.DEFAULT],
            frozenset({ReservationState.HELD, ReservationState.COMMITTED}),
        )
        self.assertEqual(
            RESERVATION_TRANSITIONS[ReservationCommand.CONSUME],
            frozenset({ReservationState.COMMITTED}),
        )
        # No terminal state is a valid transition source; every live state is.
        for sources in RESERVATION_TRANSITIONS.values():
            self.assertFalse(sources & set(RESERVATION_TERMINAL_STATES))
        live = set(ReservationState) - set(RESERVATION_TERMINAL_STATES)
        reachable: set[ReservationState] = set()
        for sources in RESERVATION_TRANSITIONS.values():
            reachable |= sources
        self.assertEqual(reachable, live)

    def test_default_reasons_are_a_closed_vocabulary(self) -> None:
        self.assertEqual(
            {reason.value for reason in DefaultReason},
            {
                "PROVIDER_FAILURE",
                "RESOURCE_UNAVAILABLE",
                "CONDITION_BREACH",
                "COUNTERPARTY_DEFAULT",
            },
        )
        with self.assertRaises(ValueError):
            DefaultReason("WHO_KNOWS")

    def test_condition_kinds_are_a_closed_vocabulary(self) -> None:
        self.assertEqual(
            {kind.value for kind in ConditionKind},
            {"ENCUMBRANCE", "FUNDING", "CAPABILITY", "QUOTE", "EVIDENCE"},
        )
        with self.assertRaises(ValueError):
            ConditionKind("MYSTERY")

    def test_reexported_authorities_are_the_owning_modules(self) -> None:
        # Consumed, never reimplemented: the expected-version precondition
        # type is the transition kernel's, the amount is the value domain's,
        # the window is the capability domain's, and the error/provenance
        # authorities are the canonical core's.
        from src.transition.command import ExpectedVersion as KernelExpectedVersion
        from src.value.amount import Amount as ValueAmount
        from src.capability.windows import OperatingWindow as CapabilityWindow
        from src.core.errors import CoreValidationError as CoreError
        from src.core.envelope import Provenance as CoreProvenance

        self.assertIs(ExpectedVersion, KernelExpectedVersion)
        self.assertIs(Amount, ValueAmount)
        self.assertIs(OperatingWindow, CapabilityWindow)
        self.assertIs(ReservationCoreError, CoreError)
        self.assertIs(ReservationProvenance, CoreProvenance)

    def test_domain_modules_import_only_allowed_domains(self) -> None:
        for source in DOMAIN_SOURCES:
            if source.name == "dogfooding.py":
                # The dogfooding harness is the one sanctioned home of the
                # real-PostgreSQL dependencies (pgserver, psycopg2); the
                # harness boundary itself is pinned by
                # test_pgserver_and_psycopg2_live_only_in_the_dogfooding_harness.
                continue
            tree = ast.parse(source.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                modules: list[str] = []
                if isinstance(node, ast.Import):
                    modules = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    if node.level == 0 and node.module:
                        modules = [node.module]
                    elif node.level > 0 and node.module:
                        # Resolve relative imports against this package.
                        prefix = ("src", "reservation")[: 2 - (node.level - 1)]
                        modules = [".".join((*prefix, *node.module.split(".")))]
                for module in modules:
                    if module == "src" or module.startswith("src."):
                        domain = module.split(".")[1] if module != "src" else "src"
                        self.assertIn(
                            domain,
                            ALLOWED_SRC_DOMAINS | {"reservation", "src"},
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

    def test_domain_code_has_no_wall_clock_randomness_or_uuids(self) -> None:
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

    def test_pgserver_and_psycopg2_live_only_in_the_dogfooding_harness(self) -> None:
        for source in DOMAIN_SOURCES:
            text = source.read_text(encoding="utf-8")
            if source.name == "dogfooding.py":
                self.assertIn("pgserver", text)
                self.assertIn("psycopg2", text)
            else:
                self.assertNotIn("pgserver", text, f"{source.name} references pgserver")
                self.assertNotIn("psycopg2", text, f"{source.name} references psycopg2")

    def test_store_is_constructible_with_seed_records(self) -> None:
        store = ReservationStore([reservation()])
        self.assertIsNotNone(store.get(RESERVATION_ID))
        self.assertIsNone(store.get("reservation/missing"))
        self.assertEqual(
            [record.object_id for record in store.snapshot()],
            [RESERVATION_ID],
        )


# ---------------------------------------------------------------------------
# 2. Conditional-commit condition vocabulary.
# ---------------------------------------------------------------------------


class ConditionTests(unittest.TestCase):
    """Condition specs and explicit satisfaction evaluation."""

    def test_condition_spec_round_trip(self) -> None:
        spec = ConditionSpec(
            condition_key="cond/encumbrance",
            kind=ConditionKind.ENCUMBRANCE,
            ref=HOLD_REF,
        )
        self.assertEqual(ConditionSpec.from_dict(spec.to_dict()), spec)

    def test_condition_spec_rejects_unknown_fields(self) -> None:
        spec = ConditionSpec(
            condition_key="cond/encumbrance",
            kind=ConditionKind.ENCUMBRANCE,
            ref=HOLD_REF,
        )
        payload = spec.to_dict()
        payload["extra"] = "nope"
        with self.assertRaises(CoreValidationError):
            ConditionSpec.from_dict(payload)

    def test_condition_spec_rejects_unknown_kind(self) -> None:
        with self.assertRaises(CoreValidationError):
            ConditionSpec.from_dict(
                {
                    "condition_key": "cond/encumbrance",
                    "kind": "MYSTERY",
                    "ref": HOLD_REF,
                }
            )

    def test_evaluation_accepts_a_fully_satisfied_set(self) -> None:
        evaluation = evaluate_condition_satisfaction(
            conditions(), satisfied=("cond/encumbrance", "cond/funding")
        )
        self.assertIsInstance(evaluation, ConditionEvaluation)
        self.assertTrue(evaluation.all_satisfied)
        self.assertEqual(evaluation.missing, ())
        self.assertEqual(evaluation.unknown, ())

    def test_evaluation_fails_closed_on_missing_conditions(self) -> None:
        evaluation = evaluate_condition_satisfaction(
            conditions(), satisfied=("cond/encumbrance",)
        )
        self.assertFalse(evaluation.all_satisfied)
        self.assertEqual(evaluation.missing, ("cond/funding",))
        self.assertEqual(evaluation.unknown, ())

    def test_evaluation_fails_closed_on_unknown_satisfied_keys(self) -> None:
        evaluation = evaluate_condition_satisfaction(
            conditions(),
            satisfied=("cond/encumbrance", "cond/funding", "cond/ghost"),
        )
        self.assertFalse(evaluation.all_satisfied)
        self.assertEqual(evaluation.missing, ())
        self.assertEqual(evaluation.unknown, ("cond/ghost",))

    def test_evaluation_fails_closed_on_both(self) -> None:
        evaluation = evaluate_condition_satisfaction(
            conditions(), satisfied=("cond/ghost",)
        )
        self.assertFalse(evaluation.all_satisfied)
        self.assertEqual(evaluation.missing, ("cond/encumbrance", "cond/funding"))
        self.assertEqual(evaluation.unknown, ("cond/ghost",))

    def test_empty_declared_set_is_trivially_satisfied(self) -> None:
        evaluation = evaluate_condition_satisfaction((), satisfied=())
        self.assertTrue(evaluation.all_satisfied)
        evaluation = evaluate_condition_satisfaction((), satisfied=("cond/ghost",))
        self.assertFalse(evaluation.all_satisfied)
        self.assertEqual(evaluation.unknown, ("cond/ghost",))

    def test_evaluation_rejects_duplicate_satisfied_keys(self) -> None:
        with self.assertRaises(CoreValidationError):
            evaluate_condition_satisfaction(
                conditions(),
                satisfied=("cond/encumbrance", "cond/encumbrance"),
            )

    def test_commit_evidence_validation(self) -> None:
        evidence = CommitEvidence(
            satisfied_keys=("cond/encumbrance",),
            evidence_refs=("evidence/work-012",),
            decided_at=IN_WINDOW,
        )
        self.assertEqual(evidence.satisfied_keys, ("cond/encumbrance",))
        with self.assertRaises(CoreValidationError):
            CommitEvidence(
                satisfied_keys=("a", "a"),
                evidence_refs=(),
                decided_at=IN_WINDOW,
            )
        with self.assertRaises(CoreValidationError):
            CommitEvidence(
                satisfied_keys=("a",),
                evidence_refs=(),
                decided_at="not-a-timestamp",
            )


# ---------------------------------------------------------------------------
# 3. Reservation lifecycle: the frozen 8-command state machine.
# ---------------------------------------------------------------------------


class LifecycleTests(unittest.TestCase):
    """All eight commands, version chains, provenance and fail-closed guards."""

    def test_create_builds_a_sealed_version_one_reserved_record(self) -> None:
        record = reservation()
        self.assertEqual(record.envelope.object_type, RESERVATION_OBJECT_TYPE)
        self.assertEqual(record.envelope.object_version, 1)
        self.assertEqual(record.state, ReservationState.RESERVED)
        self.assertEqual(record.resource_key, RESOURCE_KEY)
        self.assertEqual(record.spec.provider, "provider/alpha")
        self.assertEqual(record.spec.beneficiary, "principal/merchant-42")
        self.assertEqual(record.spec.asset, ASSET)
        self.assertEqual(record.spec.amount, Amount(value=25000, scale=2, asset=ASSET))
        self.assertEqual(record.spec.window.opens_at, OPENS_AT)
        self.assertEqual(record.spec.window.closes_at, CLOSES_AT)
        self.assertEqual(record.spec.source_ref, "market/quote/q-1")
        self.assertIsNone(record.spec.hold_ref)
        self.assertFalse(record.is_terminal())
        record.envelope.verify_integrity()

    def test_create_fails_closed_on_nonpositive_amount(self) -> None:
        for bad in (0, -1):
            with self.assertRaises(CoreValidationError):
                reservation(amount=Amount(value=bad, scale=2, asset=ASSET))

    def test_create_fails_closed_on_asset_mismatch(self) -> None:
        with self.assertRaises(CoreValidationError):
            reservation(
                asset=ASSET, amount=Amount(value=25000, scale=2, asset=OTHER_ASSET)
            )

    def test_create_fails_closed_on_malformed_identifiers(self) -> None:
        for field, value in (
            ("reservation_id", ""),
            ("resource_key", "bad key with spaces"),
            ("provider", ""),
            ("beneficiary", "not!!an!!identifier"),
        ):
            with self.assertRaises(CoreValidationError):
                reservation(**{field: value})

    def test_create_fails_closed_on_duplicate_condition_keys(self) -> None:
        duplicate = (
            ConditionSpec("cond/dup", ConditionKind.FUNDING, FUNDING_REF),
            ConditionSpec("cond/dup", ConditionKind.CAPABILITY, "capability/c/1"),
        )
        with self.assertRaises(CoreValidationError):
            reservation(conditions=duplicate)

    def test_create_fails_closed_on_duplicate_funding_refs(self) -> None:
        with self.assertRaises(CoreValidationError):
            reservation(funding_refs=(FUNDING_REF, FUNDING_REF))

    def test_create_fails_closed_on_bad_window(self) -> None:
        with self.assertRaises(CoreValidationError):
            reservation(window=OperatingWindow(CLOSES_AT, OPENS_AT))

    def test_hold_attaches_the_encumbrance_and_moves_to_held(self) -> None:
        held = hold_reservation(
            reservation(), as_of=IN_WINDOW, hold_ref=HOLD_REF, provenance=prov()
        )
        self.assertEqual(held.state, ReservationState.HELD)
        self.assertEqual(held.spec.hold_ref, HOLD_REF)
        self.assertEqual(held.envelope.object_version, 2)
        self.assertEqual(held.envelope.previous_version, 1)
        self.assertEqual(held.spec.resource_key, RESOURCE_KEY)
        self.assertFalse(held.is_terminal())

    def test_hold_fails_closed_outside_the_window(self) -> None:
        for as_of in (BEFORE_WINDOW, AT_CLOSE, AFTER_CLOSE):
            with self.assertRaises(CoreValidationError):
                hold_reservation(
                    reservation(), as_of=as_of, hold_ref=HOLD_REF, provenance=prov()
                )

    def test_hold_fails_closed_from_held(self) -> None:
        held = hold_reservation(
            reservation(), as_of=IN_WINDOW, hold_ref=HOLD_REF, provenance=prov()
        )
        with self.assertRaises(CoreValidationError):
            hold_reservation(
                held, as_of=IN_WINDOW, hold_ref=OTHER_HOLD_REF, provenance=prov()
            )

    def test_hold_fails_closed_on_bad_hold_ref(self) -> None:
        for bad in ("", "value/hold/with spaces"):
            with self.assertRaises(CoreValidationError):
                hold_reservation(
                    reservation(), as_of=IN_WINDOW, hold_ref=bad, provenance=prov()
                )

    def test_amend_extends_window_and_amount_within_state(self) -> None:
        record = reservation()
        amended = amend_reservation(
            record,
            as_of=IN_WINDOW,
            amount=Amount(value=30000, scale=2, asset=ASSET),
            window=OperatingWindow(OPENS_AT, LATER_CLOSES_AT),
            provenance=prov(),
        )
        self.assertEqual(amended.state, ReservationState.RESERVED)
        self.assertEqual(amended.envelope.object_version, 2)
        self.assertEqual(amended.spec.amount.value, 30000)
        self.assertEqual(amended.spec.window.closes_at, LATER_CLOSES_AT)

    def test_amend_from_held_keeps_held_state_and_updates_hold_ref(self) -> None:
        held = hold_reservation(
            reservation(), as_of=IN_WINDOW, hold_ref=HOLD_REF, provenance=prov()
        )
        amended = amend_reservation(
            held, as_of=IN_WINDOW_LATER, hold_ref=OTHER_HOLD_REF, provenance=prov()
        )
        self.assertEqual(amended.state, ReservationState.HELD)
        self.assertEqual(amended.spec.hold_ref, OTHER_HOLD_REF)

    def test_amend_omitted_fields_are_unchanged(self) -> None:
        record = reservation(conditions=conditions())
        amended = amend_reservation(record, as_of=IN_WINDOW, provenance=prov())
        self.assertEqual(amended.spec.amount, record.spec.amount)
        self.assertEqual(amended.spec.window, record.spec.window)
        self.assertEqual(amended.spec.conditions, record.spec.conditions)
        self.assertEqual(amended.spec.conditions, conditions())

    def test_amend_can_replace_and_clear_conditions(self) -> None:
        record = reservation(conditions=conditions())
        replaced = amend_reservation(
            record,
            as_of=IN_WINDOW,
            conditions=(
                ConditionSpec("cond/capability", ConditionKind.CAPABILITY, "capability/c/9"),
            ),
            provenance=prov(),
        )
        self.assertEqual(len(replaced.spec.conditions), 1)
        cleared = amend_reservation(
            replaced, as_of=IN_WINDOW_LATER, conditions=(), provenance=prov()
        )
        self.assertEqual(cleared.spec.conditions, ())

    def test_amend_fails_closed_outside_the_current_window(self) -> None:
        with self.assertRaises(CoreValidationError):
            amend_reservation(
                reservation(), as_of=AFTER_CLOSE, provenance=prov()
            )

    def test_amend_fails_closed_on_terminal_states(self) -> None:
        released = release_reservation(reservation(), as_of=IN_WINDOW, provenance=prov())
        with self.assertRaises(CoreValidationError):
            amend_reservation(released, as_of=IN_WINDOW, provenance=prov())

    def test_amend_cannot_attach_a_hold_ref_from_reserved(self) -> None:
        with self.assertRaises(CoreValidationError):
            amend_reservation(
                reservation(), as_of=IN_WINDOW, hold_ref=HOLD_REF, provenance=prov()
            )

    def test_amend_fails_closed_on_identity_fields(self) -> None:
        record = reservation()
        with self.assertRaises(CoreValidationError):
            amend_reservation(
                record,
                as_of=IN_WINDOW,
                amount=Amount(value=30000, scale=2, asset=OTHER_ASSET),
                provenance=prov(),
            )

    def test_commit_accepts_a_condition_free_reservation_in_window(self) -> None:
        committed = commit_reservation(
            reservation(), as_of=IN_WINDOW, provenance=prov()
        )
        self.assertEqual(committed.state, ReservationState.COMMITTED)
        self.assertEqual(committed.envelope.object_version, 2)
        self.assertEqual(committed.spec.committed_at, IN_WINDOW)
        self.assertIsNotNone(committed.spec.commit_evidence)
        self.assertFalse(committed.is_terminal())

    def test_commit_accepts_a_fully_satisfied_condition_set(self) -> None:
        record = reservation(conditions=conditions())
        committed = commit_reservation(
            record,
            as_of=IN_WINDOW,
            satisfied_conditions=("cond/encumbrance", "cond/funding"),
            evidence_refs=("evidence/work-012",),
            provenance=prov(),
        )
        self.assertEqual(committed.state, ReservationState.COMMITTED)
        self.assertEqual(
            committed.spec.commit_evidence.satisfied_keys,
            ("cond/encumbrance", "cond/funding"),
        )
        self.assertEqual(committed.spec.commit_evidence.decided_at, IN_WINDOW)

    def test_commit_denied_before_the_window_opens(self) -> None:
        with self.assertRaises(CoreValidationError) as ctx:
            commit_reservation(reservation(), as_of=BEFORE_WINDOW, provenance=prov())
        self.assertIn("window", str(ctx.exception))

    def test_commit_denied_at_and_after_the_window_closes(self) -> None:
        for as_of in (AT_CLOSE, AFTER_CLOSE):
            with self.assertRaises(CoreValidationError) as ctx:
                commit_reservation(reservation(), as_of=as_of, provenance=prov())
            self.assertIn("window", str(ctx.exception))

    def test_commit_denied_when_a_condition_is_missing(self) -> None:
        record = reservation(conditions=conditions())
        with self.assertRaises(CoreValidationError) as ctx:
            commit_reservation(
                record,
                as_of=IN_WINDOW,
                satisfied_conditions=("cond/encumbrance",),
                provenance=prov(),
            )
        self.assertIn("cond/funding", str(ctx.exception))

    def test_commit_denied_when_a_satisfied_key_is_unknown(self) -> None:
        record = reservation(conditions=conditions())
        with self.assertRaises(CoreValidationError) as ctx:
            commit_reservation(
                record,
                as_of=IN_WINDOW,
                satisfied_conditions=("cond/encumbrance", "cond/funding", "cond/ghost"),
                provenance=prov(),
            )
        self.assertIn("cond/ghost", str(ctx.exception))

    def test_commit_denied_on_terminal_states(self) -> None:
        released = release_reservation(reservation(), as_of=IN_WINDOW, provenance=prov())
        with self.assertRaises(CoreValidationError):
            commit_reservation(released, as_of=IN_WINDOW, provenance=prov())

    def test_commit_from_held_carries_the_hold_reference(self) -> None:
        held = hold_reservation(
            reservation(), as_of=IN_WINDOW, hold_ref=HOLD_REF, provenance=prov()
        )
        committed = commit_reservation(held, as_of=IN_WINDOW_LATER, provenance=prov())
        self.assertEqual(committed.state, ReservationState.COMMITTED)
        self.assertEqual(committed.spec.hold_ref, HOLD_REF)
        self.assertEqual(committed.spec.committed_at, IN_WINDOW_LATER)

    def test_release_moves_reserved_to_released_terminal(self) -> None:
        released = release_reservation(
            reservation(), as_of=IN_WINDOW, provenance=prov()
        )
        self.assertEqual(released.state, ReservationState.RELEASED)
        self.assertTrue(released.is_terminal())
        self.assertEqual(released.envelope.object_version, 2)

    def test_release_from_held(self) -> None:
        held = hold_reservation(
            reservation(), as_of=IN_WINDOW, hold_ref=HOLD_REF, provenance=prov()
        )
        released = release_reservation(held, as_of=IN_WINDOW_LATER, provenance=prov())
        self.assertEqual(released.state, ReservationState.RELEASED)
        self.assertEqual(released.spec.hold_ref, HOLD_REF)

    def test_release_fails_closed_at_or_after_the_window_end(self) -> None:
        for as_of in (AT_CLOSE, AFTER_CLOSE):
            with self.assertRaises(CoreValidationError) as ctx:
                release_reservation(reservation(), as_of=as_of, provenance=prov())
            self.assertIn("expire", str(ctx.exception))

    def test_release_fails_closed_from_committed(self) -> None:
        committed = commit_reservation(
            reservation(), as_of=IN_WINDOW, provenance=prov()
        )
        with self.assertRaises(CoreValidationError):
            release_reservation(committed, as_of=IN_WINDOW_LATER, provenance=prov())

    def test_expire_moves_reserved_to_expired_once_elapsed(self) -> None:
        expired = expire_reservation(
            reservation(), as_of=AT_CLOSE, provenance=prov()
        )
        self.assertEqual(expired.state, ReservationState.EXPIRED)
        self.assertTrue(expired.is_terminal())

    def test_expire_fails_closed_before_the_window_end(self) -> None:
        for as_of in (BEFORE_WINDOW, IN_WINDOW):
            with self.assertRaises(CoreValidationError):
                expire_reservation(reservation(), as_of=as_of, provenance=prov())

    def test_expire_fails_closed_from_committed(self) -> None:
        committed = commit_reservation(
            reservation(), as_of=IN_WINDOW, provenance=prov()
        )
        with self.assertRaises(CoreValidationError):
            expire_reservation(committed, as_of=AFTER_CLOSE, provenance=prov())

    def test_default_records_reason_from_held_and_committed(self) -> None:
        held = hold_reservation(
            reservation(), as_of=IN_WINDOW, hold_ref=HOLD_REF, provenance=prov()
        )
        defaulted = default_reservation(
            held,
            as_of=IN_WINDOW_LATER,
            reason=DefaultReason.PROVIDER_FAILURE,
            provenance=prov(),
        )
        self.assertEqual(defaulted.state, ReservationState.DEFAULTED)
        self.assertTrue(defaulted.is_terminal())
        self.assertEqual(defaulted.spec.defaulted_reason, DefaultReason.PROVIDER_FAILURE)
        self.assertEqual(defaulted.spec.defaulted_at, IN_WINDOW_LATER)

        committed = commit_reservation(
            reservation(), as_of=IN_WINDOW, provenance=prov()
        )
        defaulted_committed = default_reservation(
            committed,
            as_of=IN_WINDOW_LATER,
            reason=DefaultReason.COUNTERPARTY_DEFAULT,
            provenance=prov(),
        )
        self.assertEqual(defaulted_committed.state, ReservationState.DEFAULTED)
        self.assertEqual(
            defaulted_committed.spec.defaulted_reason, DefaultReason.COUNTERPARTY_DEFAULT
        )
        # Defaulting a committed reservation preserves the commit history.
        self.assertEqual(defaulted_committed.spec.committed_at, IN_WINDOW)

    def test_default_fails_closed_from_reserved(self) -> None:
        with self.assertRaises(CoreValidationError):
            default_reservation(
                reservation(),
                as_of=IN_WINDOW,
                reason=DefaultReason.PROVIDER_FAILURE,
                provenance=prov(),
            )

    def test_default_fails_closed_before_the_commit_instant(self) -> None:
        committed = commit_reservation(
            reservation(), as_of=IN_WINDOW_LATER, provenance=prov()
        )
        with self.assertRaises(CoreValidationError):
            default_reservation(
                committed,
                as_of=IN_WINDOW,
                reason=DefaultReason.PROVIDER_FAILURE,
                provenance=prov(),
            )

    def test_default_rejects_unknown_reasons(self) -> None:
        with self.assertRaises(CoreValidationError):
            default_reservation(
                reservation(),
                as_of=IN_WINDOW,
                reason="WHO_KNOWS",
                provenance=prov(),
            )

    def test_consume_completes_a_committed_reservation(self) -> None:
        committed = commit_reservation(
            reservation(), as_of=IN_WINDOW, provenance=prov()
        )
        consumed = consume_reservation(
            committed, as_of=IN_WINDOW_LATER, provenance=prov()
        )
        self.assertEqual(consumed.state, ReservationState.CONSUMED)
        self.assertTrue(consumed.is_terminal())
        self.assertEqual(consumed.spec.consumed_at, IN_WINDOW_LATER)
        self.assertEqual(consumed.spec.committed_at, IN_WINDOW)

    def test_consume_fails_closed_from_uncommitted_states(self) -> None:
        for record in (
            reservation(),
            hold_reservation(
                reservation(), as_of=IN_WINDOW, hold_ref=HOLD_REF, provenance=prov()
            ),
        ):
            with self.assertRaises(CoreValidationError):
                consume_reservation(record, as_of=IN_WINDOW_LATER, provenance=prov())

    def test_consume_fails_closed_before_the_commit_instant(self) -> None:
        committed = commit_reservation(
            reservation(), as_of=IN_WINDOW_LATER, provenance=prov()
        )
        with self.assertRaises(CoreValidationError):
            consume_reservation(committed, as_of=IN_WINDOW, provenance=prov())

    def test_terminal_records_refuse_every_command(self) -> None:
        terminals = (
            release_reservation(reservation(), as_of=IN_WINDOW, provenance=prov()),
            expire_reservation(reservation(), as_of=AT_CLOSE, provenance=prov()),
            default_reservation(
                hold_reservation(
                    reservation(), as_of=IN_WINDOW, hold_ref=HOLD_REF, provenance=prov()
                ),
                as_of=IN_WINDOW_LATER,
                reason=DefaultReason.PROVIDER_FAILURE,
                provenance=prov(),
            ),
            consume_reservation(
                commit_reservation(reservation(), as_of=IN_WINDOW, provenance=prov()),
                as_of=IN_WINDOW_LATER,
                provenance=prov(),
            ),
        )
        for terminal in terminals:
            for operation in (
                lambda r: hold_reservation(
                    r, as_of=IN_WINDOW, hold_ref=OTHER_HOLD_REF, provenance=prov()
                ),
                lambda r: amend_reservation(r, as_of=IN_WINDOW, provenance=prov()),
                lambda r: commit_reservation(r, as_of=IN_WINDOW, provenance=prov()),
                lambda r: release_reservation(r, as_of=IN_WINDOW, provenance=prov()),
                lambda r: expire_reservation(r, as_of=AFTER_CLOSE, provenance=prov()),
                lambda r: default_reservation(
                    r,
                    as_of=AFTER_CLOSE,
                    reason=DefaultReason.PROVIDER_FAILURE,
                    provenance=prov(),
                ),
                lambda r: consume_reservation(r, as_of=AFTER_CLOSE, provenance=prov()),
            ):
                with self.assertRaises(CoreValidationError):
                    operation(terminal)

    def test_transitions_chain_versions_and_provenance(self) -> None:
        record = reservation()
        held = hold_reservation(
            record, as_of=IN_WINDOW, hold_ref=HOLD_REF, provenance=prov()
        )
        committed = commit_reservation(
            held, as_of=IN_WINDOW_LATER, provenance=prov()
        )
        consumed = consume_reservation(
            committed, as_of=AT_CLOSE, provenance=prov()
        )
        self.assertEqual(
            [r.envelope.object_version for r in (record, held, committed, consumed)],
            [1, 2, 3, 4],
        )
        self.assertEqual(
            [r.envelope.previous_version for r in (record, held, committed, consumed)],
            [None, 1, 2, 3],
        )
        self.assertEqual(consumed.envelope.object_id, RESERVATION_ID)
        self.assertEqual(consumed.envelope.correlation_id, "corr/w-012")
        for transition in (held, committed, consumed):
            self.assertNotEqual(
                transition.envelope.integrity_hash,
                record.envelope.integrity_hash,
            )
            transition.envelope.verify_integrity()

    def test_every_command_accepts_causation_and_correlation_ids(self) -> None:
        released = release_reservation(
            reservation(),
            as_of=IN_WINDOW,
            provenance=prov(),
            causation_id="command/release-1",
            correlation_id="corr/release-1",
        )
        self.assertEqual(released.envelope.causation_id, "command/release-1")
        self.assertEqual(released.envelope.correlation_id, "corr/release-1")

    def test_create_records_the_source_reference_as_causation(self) -> None:
        record = reservation()
        self.assertEqual(record.envelope.causation_id, "market/quote/q-1")
        record2 = reservation(source_ref=None)
        self.assertIsNone(record2.envelope.causation_id)


# ---------------------------------------------------------------------------
# 4. Deterministic conflict precedence.
# ---------------------------------------------------------------------------


class PrecedenceTests(unittest.TestCase):
    """Writer claims resolve by explicit precedence, never by timing."""

    def test_writer_claim_validation(self) -> None:
        with self.assertRaises(CoreValidationError):
            WriterClaim(actor="", requested_at="2026-09-03T00:00:01Z", command_id="c/1")
        with self.assertRaises(CoreValidationError):
            WriterClaim(actor="a/1", requested_at="2026-09-03 00:00:01", command_id="c/1")
        with self.assertRaises(CoreValidationError):
            WriterClaim(actor="a/1", requested_at="2026-09-03T00:00:01Z", command_id="")
        claim = WriterClaim(
            actor="a/1",
            requested_at="2026-09-03T00:00:01Z",
            command_id="c/1",
        )
        self.assertEqual(
            claim.precedence_key(),
            ("2026-09-03T00:00:01Z", "c/1", "a/1"),
        )

    def test_resolve_precedence_ranks_earliest_requested_at_first(self) -> None:
        self.assertEqual(
            resolve_precedence((CLAIM_B, CLAIM_A, CLAIM_LATE)),
            (CLAIM_A, CLAIM_B, CLAIM_LATE),
        )

    def test_resolve_precedence_tie_breaks_on_command_id_then_actor(self) -> None:
        # CLAIM_B and CLAIM_C share requested_at; command id decides.
        self.assertEqual(
            resolve_precedence((CLAIM_C, CLAIM_B)),
            (CLAIM_B, CLAIM_C),
        )
        same_command = WriterClaim(
            actor="actor/aaa",
            requested_at="2026-09-03T00:00:02Z",
            command_id="command/w-012-gamma",
        )
        self.assertEqual(
            resolve_precedence((CLAIM_C, same_command)),
            (same_command, CLAIM_C),
        )

    def test_resolve_precedence_is_order_independent(self) -> None:
        claims = (CLAIM_A, CLAIM_B, CLAIM_C, CLAIM_LATE)
        expected = (CLAIM_A, CLAIM_B, CLAIM_C, CLAIM_LATE)
        self.assertEqual(resolve_precedence(claims), expected)
        self.assertEqual(resolve_precedence(tuple(reversed(claims))), expected)
        self.assertEqual(
            resolve_precedence((CLAIM_LATE, CLAIM_B, CLAIM_A, CLAIM_C)), expected
        )

    def test_resolve_precedence_rejects_duplicate_claims(self) -> None:
        with self.assertRaises(CoreValidationError):
            resolve_precedence((CLAIM_A, CLAIM_A))

    def test_resolve_precedence_empty_input_is_empty(self) -> None:
        self.assertEqual(resolve_precedence(()), ())


# ---------------------------------------------------------------------------
# 5. Keyed concurrency (threads, barriers and events).
# ---------------------------------------------------------------------------


class KeyedConcurrencyTests(unittest.TestCase):
    """Per-key serialization with deterministic precedence, cross-key progress."""

    def test_independent_keys_progress_while_one_key_is_held(self) -> None:
        manager = KeyedLockManager()
        a_holds = threading.Event()
        b_done = threading.Event()
        order: list[str] = []
        failures: list[Exception] = []

        def actor_a() -> None:
            try:
                with manager.locked(RESOURCE_KEY, claim=CLAIM_A):
                    a_holds.set()
                    if not b_done.wait(timeout=30):
                        failures.append(AssertionError("B never finished on key two"))
                    order.append("A_released")
            except Exception as exc:  # pragma: no cover - surfaced below
                failures.append(exc)

        def actor_b() -> None:
            try:
                if not a_holds.wait(timeout=30):
                    failures.append(AssertionError("A never acquired key one"))
                with manager.locked(OTHER_RESOURCE_KEY, claim=CLAIM_B):
                    order.append("B_acquired")
                b_done.set()
            except Exception as exc:  # pragma: no cover - surfaced below
                failures.append(exc)

        threads = (threading.Thread(target=actor_a), threading.Thread(target=actor_b))
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        self.assertEqual(failures, [])
        self.assertFalse(any(thread.is_alive() for thread in threads))
        # B acquired and completed on its own key while A still held key one:
        # no global mutex serializes independent keys.
        self.assertEqual(order, ["B_acquired", "A_released"])
        self.assertIsNone(manager.holder(RESOURCE_KEY))
        self.assertIsNone(manager.holder(OTHER_RESOURCE_KEY))

    def test_same_key_writers_serialize_with_deterministic_queued_grants(self) -> None:
        manager = KeyedLockManager()
        key = RESOURCE_KEY
        grant_order: list[str] = []
        holder_ready = threading.Event()
        release_holder = threading.Event()
        failures: list[Exception] = []

        def holder() -> None:
            try:
                with manager.locked(key, claim=CLAIM_LATE):
                    holder_ready.set()
                    if not release_holder.wait(timeout=30):
                        failures.append(AssertionError("holder never released"))
            except Exception as exc:  # pragma: no cover - surfaced below
                failures.append(exc)

        def waiter(claim: WriterClaim, label: str) -> None:
            try:
                with manager.locked(key, claim=claim):
                    grant_order.append(label)
            except Exception as exc:  # pragma: no cover - surfaced below
                failures.append(exc)

        holder_thread = threading.Thread(target=holder)
        holder_thread.start()
        self.assertTrue(holder_ready.wait(timeout=30))
        self.assertEqual(manager.holder(key), CLAIM_LATE)

        # Queue the early claim first, then the late one: both block while
        # the holder owns the key, so the gate MUST grant by precedence.
        b_thread = threading.Thread(target=waiter, args=(CLAIM_B, "B"))
        b_thread.start()
        _wait_until(lambda: manager.waiting(key) == (CLAIM_B,))
        c_thread = threading.Thread(target=waiter, args=(CLAIM_C, "C"))
        c_thread.start()
        _wait_until(lambda: manager.waiting(key) == (CLAIM_B, CLAIM_C))
        release_holder.set()
        for thread in (holder_thread, b_thread, c_thread):
            thread.join(timeout=30)
        self.assertEqual(failures, [])
        self.assertFalse(
            any(thread.is_alive() for thread in (holder_thread, b_thread, c_thread))
        )
        # CLAIM_B precedes CLAIM_C (earlier requested_at), regardless of
        # registration order or scheduler timing.
        self.assertEqual(grant_order, ["B", "C"])

    def test_waiting_order_reports_precedence_not_arrival(self) -> None:
        manager = KeyedLockManager()
        with manager.locked(RESOURCE_KEY, claim=CLAIM_LATE):
            manager.acquire(OTHER_RESOURCE_KEY, claim=CLAIM_B)
            try:
                self.assertEqual(manager.waiting(RESOURCE_KEY), ())
            finally:
                manager.release(OTHER_RESOURCE_KEY, claim=CLAIM_B)

    def test_locked_all_acquires_keys_in_sorted_order(self) -> None:
        manager = KeyedLockManager()
        acquired: list[str] = []
        with manager.locked_all(
            (OTHER_RESOURCE_KEY, RESOURCE_KEY), claim=CLAIM_A
        ):
            acquired.append("outer")
            # Nested acquisition of the same key set in sorted order from a
            # different claim is impossible while held: assert exclusivity.
            self.assertIsNotNone(manager.holder(OTHER_RESOURCE_KEY))
            self.assertIsNotNone(manager.holder(RESOURCE_KEY))
        self.assertEqual(acquired, ["outer"])
        self.assertIsNone(manager.holder(OTHER_RESOURCE_KEY))
        self.assertIsNone(manager.holder(RESOURCE_KEY))

    def test_reentrant_key_acquisition_fails_closed(self) -> None:
        manager = KeyedLockManager()
        with manager.locked(RESOURCE_KEY, claim=CLAIM_A):
            with self.assertRaises(CoreValidationError):
                manager.acquire(RESOURCE_KEY, claim=CLAIM_A)

    def test_release_of_an_unheld_key_fails_closed(self) -> None:
        manager = KeyedLockManager()
        with self.assertRaises(CoreValidationError):
            manager.release(RESOURCE_KEY, claim=CLAIM_A)

    def test_two_writers_on_one_key_via_the_store_leave_one_winner(self) -> None:
        base = reservation()
        store = ReservationStore([base])
        winner_record = commit_reservation(base, as_of=IN_WINDOW, provenance=prov())
        loser_record = release_reservation(base, as_of=IN_WINDOW, provenance=prov())
        results: dict[str, str] = {}
        done = threading.Event()
        failures: list[Exception] = []

        def run(claim: WriterClaim, record: Reservation) -> None:
            try:
                apply_one(store, record, claim, 1)
                results[claim.actor] = "ok"
            except CoreValidationError as exc:
                results[claim.actor] = f"conflict: {exc}"
            except Exception as exc:  # pragma: no cover - surfaced below
                failures.append(exc)

        # The deterministic schedule grants the precedence winner first:
        # resolve_precedence ranks CLAIM_A before CLAIM_B.
        first, second = resolve_precedence((CLAIM_A, CLAIM_B))
        winner_thread = threading.Thread(target=run, args=(first, winner_record))
        loser_thread: list[threading.Thread] = []

        def scheduled_loser() -> None:
            if not done.wait(timeout=30):
                failures.append(AssertionError("winner never applied"))
            run(second, loser_record)

        loser = threading.Thread(target=scheduled_loser)
        winner_thread.start()
        loser.start()

        def wait_winner() -> None:
            winner_thread.join(timeout=30)
            done.set()

        waiter = threading.Thread(target=wait_winner)
        waiter.start()
        for thread in (winner_thread, loser, waiter):
            thread.join(timeout=30)
        self.assertEqual(failures, [])
        self.assertEqual(results[CLAIM_A.actor], "ok")
        self.assertIn("expected-version conflict", results[CLAIM_B.actor])
        # Exactly one winner: the store advanced exactly one version with
        # exactly one terminal outcome, and the loser changed nothing.
        final = store.get(RESERVATION_ID)
        self.assertEqual(final.envelope.object_version, 2)
        self.assertEqual(final.state, ReservationState.COMMITTED)

    def test_simultaneous_same_key_writers_produce_exactly_one_winner(self) -> None:
        base = reservation()
        store = ReservationStore([base])
        records = (
            commit_reservation(base, as_of=IN_WINDOW, provenance=prov()),
            release_reservation(base, as_of=IN_WINDOW, provenance=prov()),
            expire_reservation(base, as_of=AT_CLOSE, provenance=prov()),
        )
        claims = (CLAIM_A, CLAIM_B, CLAIM_C)
        barrier = threading.Barrier(len(claims))
        outcomes: dict[str, str] = {}
        failures: list[Exception] = []

        def run(claim: WriterClaim, record: Reservation) -> None:
            try:
                barrier.wait(timeout=30)
                apply_one(store, record, claim, 1)
                outcomes[claim.actor] = "ok"
            except CoreValidationError as exc:
                outcomes[claim.actor] = f"conflict: {exc}"
            except Exception as exc:  # pragma: no cover - surfaced below
                failures.append(exc)

        threads = [
            threading.Thread(target=run, args=(claim, record))
            for claim, record in zip(claims, records)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        self.assertEqual(failures, [])
        ok_actors = [actor for actor, result in outcomes.items() if result == "ok"]
        conflict_actors = [actor for actor, result in outcomes.items() if result != "ok"]
        self.assertEqual(len(ok_actors), 1, outcomes)
        self.assertEqual(len(conflict_actors), 2, outcomes)
        for actor in conflict_actors:
            self.assertIn("expected-version conflict", outcomes[actor])
        final = store.get(RESERVATION_ID)
        self.assertEqual(final.envelope.object_version, 2)

    def test_cross_key_store_applies_progress_concurrently(self) -> None:
        base_a = reservation()
        base_b = reservation(
            reservation_id="reservation/r-2",
            resource_key=OTHER_RESOURCE_KEY,
            provider="provider/beta",
        )
        store = ReservationStore([base_a, base_b])
        a_locked = threading.Event()
        b_done = threading.Event()
        order: list[str] = []
        failures: list[Exception] = []

        def actor_a() -> None:
            try:
                with store.locks().locked(RESOURCE_KEY, claim=CLAIM_A):
                    a_locked.set()
                    if not b_done.wait(timeout=30):
                        failures.append(AssertionError("B never applied on key two"))
                    order.append("A_applied")
            except Exception as exc:  # pragma: no cover - surfaced below
                failures.append(exc)

        def actor_b() -> None:
            try:
                if not a_locked.wait(timeout=30):
                    failures.append(AssertionError("A never locked key one"))
                apply_one(
                    store,
                    commit_reservation(base_b, as_of=IN_WINDOW, provenance=prov()),
                    CLAIM_B,
                    1,
                )
                order.append("B_applied")
                b_done.set()
            except Exception as exc:  # pragma: no cover - surfaced below
                failures.append(exc)

        threads = (threading.Thread(target=actor_a), threading.Thread(target=actor_b))
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        self.assertEqual(failures, [])
        self.assertEqual(order, ["B_applied", "A_applied"])
        self.assertEqual(store.get("reservation/r-2").state, ReservationState.COMMITTED)
        self.assertEqual(store.get(RESERVATION_ID).state, ReservationState.RESERVED)


# ---------------------------------------------------------------------------
# 6. The versioned reservation store.
# ---------------------------------------------------------------------------


class StoreTests(unittest.TestCase):
    """Expected-version preconditions, atomic batches, live-key exclusivity."""

    def store_with_reservation(self) -> ReservationStore:
        return ReservationStore([reservation()])

    def test_apply_creates_at_version_one_with_expected_version_zero(self) -> None:
        store = ReservationStore()
        record = reservation()
        apply_one(store, record, CLAIM_A, 0)
        self.assertEqual(store.get(RESERVATION_ID), record)

    def test_apply_creation_rejects_nonzero_expected_version(self) -> None:
        store = ReservationStore()
        with self.assertRaises(CoreValidationError) as ctx:
            apply_one(store, reservation(), CLAIM_A, 1)
        self.assertIn("expected-version conflict", str(ctx.exception))
        self.assertIsNone(store.get(RESERVATION_ID))

    def test_apply_rejects_creation_when_the_reservation_exists(self) -> None:
        store = self.store_with_reservation()
        with self.assertRaises(CoreValidationError) as ctx:
            apply_one(
                store,
                reservation(reservation_id="reservation/r-2"),
                CLAIM_A,
                0,
            )
        # The existing reservation occupies the same resource key.
        self.assertIn("resource key", str(ctx.exception))

    def test_apply_advances_with_the_matching_expected_version(self) -> None:
        store = self.store_with_reservation()
        held = hold_reservation(
            store.get(RESERVATION_ID), as_of=IN_WINDOW, hold_ref=HOLD_REF, provenance=prov()
        )
        apply_one(store, held, CLAIM_B, 1)
        self.assertEqual(store.get(RESERVATION_ID), held)

    def test_apply_rejects_a_stale_expected_version(self) -> None:
        store = self.store_with_reservation()
        held = hold_reservation(
            store.get(RESERVATION_ID), as_of=IN_WINDOW, hold_ref=HOLD_REF, provenance=prov()
        )
        apply_one(store, held, CLAIM_B, 1)
        committed = commit_reservation(held, as_of=IN_WINDOW_LATER, provenance=prov())
        with self.assertRaises(CoreValidationError) as ctx:
            apply_one(store, committed, CLAIM_A, 1)
        message = str(ctx.exception)
        self.assertIn("expected-version conflict", message)
        self.assertIn("expected version 1", message)
        self.assertIn("store holds version 2", message)
        self.assertEqual(store.get(RESERVATION_ID).envelope.object_version, 2)

    def test_apply_rejects_expected_version_for_a_missing_reservation(self) -> None:
        store = ReservationStore()
        with self.assertRaises(CoreValidationError) as ctx:
            apply_one(store, reservation(), CLAIM_A, 4)
        self.assertIn("store holds no reservation", str(ctx.exception))

    def test_apply_rejects_version_jumps(self) -> None:
        store = self.store_with_reservation()
        committed = commit_reservation(
            store.get(RESERVATION_ID), as_of=IN_WINDOW, provenance=prov()
        )
        consumed = consume_reservation(
            committed, as_of=IN_WINDOW_LATER, provenance=prov()
        )
        with self.assertRaises(CoreValidationError) as ctx:
            apply_one(store, consumed, CLAIM_A, 1)
        self.assertIn("exactly one version at a time", str(ctx.exception))

    def test_apply_rejects_chain_breaks(self) -> None:
        store = self.store_with_reservation()
        forged = hold_reservation(
            store.get(RESERVATION_ID), as_of=IN_WINDOW, hold_ref=HOLD_REF, provenance=prov()
        )
        broken_envelope = ObjectEnvelope(
            object_id=RESERVATION_ID,
            object_type=RESERVATION_OBJECT_TYPE,
            object_version=2,
            environment_id=ENV,
            domain_id=DOMAIN,
            schema_version=RESERVATION_SCHEMA_VERSION,
            protocol_version=RESERVATION_PROTOCOL_VERSION,
            state=ReservationState.HELD.value,
            provenance=prov(),
            previous_version=None,
        ).with_integrity_hash()
        broken = Reservation(
            envelope=broken_envelope,
            spec=forged.spec,
            integrity_hash=canonical_sha256(
                {
                    "envelope": broken_envelope.to_dict(),
                    "payload": forged.spec.to_dict(),
                }
            ),
        )
        with self.assertRaises(CoreValidationError) as ctx:
            apply_one(store, broken, CLAIM_A, 1)
        self.assertIn("immutable version chain", str(ctx.exception))

    def test_apply_rejects_identity_changes(self) -> None:
        store = self.store_with_reservation()
        moved_base = reservation(
            resource_key=OTHER_RESOURCE_KEY,
            reservation_id=RESERVATION_ID,
        )
        moved = amend_reservation(moved_base, as_of=IN_WINDOW, provenance=prov())
        with self.assertRaises(CoreValidationError) as ctx:
            apply_one(store, moved, CLAIM_A, 1)
        self.assertIn("payload identity", str(ctx.exception))

    def test_apply_rejects_amount_scale_changes(self) -> None:
        store = self.store_with_reservation()
        amended = amend_reservation(
            store.get(RESERVATION_ID),
            as_of=IN_WINDOW,
            amount=Amount(value=25000, scale=3, asset=ASSET),
            provenance=prov(),
        )
        with self.assertRaises(CoreValidationError):
            apply_one(store, amended, CLAIM_A, 1)

    def test_apply_rejects_noncanonical_batches(self) -> None:
        store = self.store_with_reservation()
        with self.assertRaises(CoreValidationError):
            store.apply((), expected_versions=(), writer=CLAIM_A)
        with self.assertRaises(CoreValidationError):
            store.apply(
                [reservation()], expected_versions=(), writer=CLAIM_A
            )

    def test_apply_rejects_incomplete_expected_version_coverage(self) -> None:
        store = ReservationStore()
        first = reservation()
        second = reservation(
            reservation_id="reservation/r-2",
            resource_key=OTHER_RESOURCE_KEY,
            provider="provider/beta",
        )
        with self.assertRaises(CoreValidationError) as ctx:
            store.apply(
                (first, second),
                expected_versions=(ExpectedVersion(RESERVATION_ID, 0),),
                writer=CLAIM_A,
            )
        self.assertIn("coverage", str(ctx.exception))
        with self.assertRaises(CoreValidationError) as ctx:
            store.apply(
                (first,),
                expected_versions=(
                    ExpectedVersion(RESERVATION_ID, 0),
                    ExpectedVersion("reservation/r-2", 0),
                ),
                writer=CLAIM_A,
            )
        self.assertIn("coverage", str(ctx.exception))

    def test_apply_rejects_duplicate_object_ids_in_a_batch(self) -> None:
        store = ReservationStore()
        record = reservation()
        with self.assertRaises(CoreValidationError):
            store.apply(
                (record, record),
                expected_versions=(
                    ExpectedVersion(RESERVATION_ID, 0),
                    ExpectedVersion(RESERVATION_ID, 0),
                ),
                writer=CLAIM_A,
            )
        self.assertIsNone(store.get(RESERVATION_ID))

    def test_atomic_batch_rolls_back_when_a_later_object_is_invalid(self) -> None:
        store = self.store_with_reservation()
        other = reservation(
            reservation_id="reservation/r-2",
            resource_key=OTHER_RESOURCE_KEY,
            provider="provider/beta",
        )
        apply_one(store, other, CLAIM_A, 0)
        before_snapshot = store.snapshot()
        before_digest = store.snapshot_digest()
        valid_a = hold_reservation(
            store.get(RESERVATION_ID),
            as_of=IN_WINDOW,
            hold_ref=HOLD_REF,
            provenance=prov(),
        )
        valid_b = commit_reservation(
            store.get("reservation/r-2"), as_of=IN_WINDOW, provenance=prov()
        )
        # A third object that violates its creation precondition.
        invalid_c = reservation(
            reservation_id="reservation/r-3",
            resource_key="resource/provider-gamma/asset-USD/slot-9",
            provider="provider/gamma",
        )
        with self.assertRaises(CoreValidationError):
            store.apply(
                (valid_a, valid_b, invalid_c),
                expected_versions=(
                    ExpectedVersion(RESERVATION_ID, 1),
                    ExpectedVersion("reservation/r-2", 1),
                    ExpectedVersion("reservation/r-3", 1),
                ),
                writer=CLAIM_A,
            )
        self.assertEqual(store.snapshot(), before_snapshot)
        self.assertEqual(store.snapshot_digest(), before_digest)
        self.assertEqual(store.get(RESERVATION_ID).state, ReservationState.RESERVED)
        self.assertEqual(
            store.get("reservation/r-2").state, ReservationState.RESERVED
        )
        self.assertIsNone(store.get("reservation/r-3"))

    def test_atomic_batch_rolls_back_a_valid_creation(self) -> None:
        store = self.store_with_reservation()
        before_snapshot = store.snapshot()
        before_digest = store.snapshot_digest()
        valid_creation = reservation(
            reservation_id="reservation/r-2",
            resource_key=OTHER_RESOURCE_KEY,
            provider="provider/beta",
        )
        stale_advance = commit_reservation(
            store.get(RESERVATION_ID), as_of=IN_WINDOW, provenance=prov()
        )
        with self.assertRaises(CoreValidationError):
            store.apply(
                (valid_creation, stale_advance),
                expected_versions=(
                    ExpectedVersion("reservation/r-2", 0),
                    ExpectedVersion(RESERVATION_ID, 2),
                ),
                writer=CLAIM_A,
            )
        self.assertEqual(store.snapshot(), before_snapshot)
        self.assertEqual(store.snapshot_digest(), before_digest)
        self.assertIsNone(store.get("reservation/r-2"))

    def test_valid_multi_object_batch_applies_every_record(self) -> None:
        store = self.store_with_reservation()
        creation = reservation(
            reservation_id="reservation/r-2",
            resource_key=OTHER_RESOURCE_KEY,
            provider="provider/beta",
        )
        advance = hold_reservation(
            store.get(RESERVATION_ID),
            as_of=IN_WINDOW,
            hold_ref=HOLD_REF,
            provenance=prov(),
        )
        store.apply(
            (creation, advance),
            expected_versions=(
                ExpectedVersion("reservation/r-2", 0),
                ExpectedVersion(RESERVATION_ID, 1),
            ),
            writer=CLAIM_A,
        )
        self.assertEqual(store.get("reservation/r-2"), creation)
        self.assertEqual(store.get(RESERVATION_ID), advance)

    def test_live_key_exclusivity_rejects_a_second_live_reservation(self) -> None:
        store = self.store_with_reservation()
        rival = reservation(
            reservation_id="reservation/r-rival",
            resource_key=RESOURCE_KEY,
            provider="provider/alpha",
        )
        with self.assertRaises(CoreValidationError) as ctx:
            apply_one(store, rival, CLAIM_B, 0)
        message = str(ctx.exception)
        self.assertIn("resource key", message)
        self.assertIn("reservation/r-1", message)
        self.assertIsNone(store.get("reservation/r-rival"))

    def test_terminal_state_frees_the_resource_key(self) -> None:
        store = self.store_with_reservation()
        released = release_reservation(
            store.get(RESERVATION_ID), as_of=IN_WINDOW, provenance=prov()
        )
        apply_one(store, released, CLAIM_A, 1)
        successor = reservation(
            reservation_id="reservation/r-successor",
            resource_key=RESOURCE_KEY,
            provider="provider/alpha",
        )
        apply_one(store, successor, CLAIM_B, 0)
        self.assertEqual(store.get("reservation/r-successor"), successor)

    def test_batch_releasing_and_re_reserving_one_key_is_atomic(self) -> None:
        store = self.store_with_reservation()
        released = release_reservation(
            store.get(RESERVATION_ID), as_of=IN_WINDOW, provenance=prov()
        )
        successor = reservation(
            reservation_id="reservation/r-successor",
            resource_key=RESOURCE_KEY,
            provider="provider/alpha",
        )
        store.apply(
            (released, successor),
            expected_versions=(
                ExpectedVersion(RESERVATION_ID, 1),
                ExpectedVersion("reservation/r-successor", 0),
            ),
            writer=CLAIM_A,
        )
        self.assertEqual(store.get(RESERVATION_ID).state, ReservationState.RELEASED)
        self.assertEqual(store.get("reservation/r-successor"), successor)

    def test_snapshot_is_sorted_and_digest_is_deterministic(self) -> None:
        records = (
            reservation(),
            reservation(
                reservation_id="reservation/r-0",
                resource_key="resource/provider-zeta/asset-USD/slot-1",
                provider="provider/zeta",
            ),
            reservation(
                reservation_id="reservation/r-2",
                resource_key=OTHER_RESOURCE_KEY,
                provider="provider/beta",
            ),
        )
        store = ReservationStore(records)
        self.assertEqual(
            [record.object_id for record in store.snapshot()],
            ["reservation/r-0", "reservation/r-1", "reservation/r-2"],
        )
        twin = ReservationStore(
            (
                records[1],
                records[0],
                records[2],
            )
        )
        self.assertEqual(store.snapshot_digest(), twin.snapshot_digest())

    def test_store_exposes_its_keyed_lock_manager(self) -> None:
        manager = KeyedLockManager()
        store = ReservationStore([], locks=manager)
        self.assertIs(store.locks(), manager)

    def test_store_seed_rejects_duplicate_ids(self) -> None:
        with self.assertRaises(CoreValidationError):
            ReservationStore([reservation(), reservation()])

    def test_store_seed_rejects_live_key_collisions(self) -> None:
        with self.assertRaises(CoreValidationError) as ctx:
            ReservationStore(
                [
                    reservation(),
                    reservation(
                        reservation_id="reservation/r-rival",
                        resource_key=RESOURCE_KEY,
                        provider="provider/alpha",
                    ),
                ]
            )
        self.assertIn("resource key", str(ctx.exception))


# ---------------------------------------------------------------------------
# 7. Sealing, tamper rejection and round trips.
# ---------------------------------------------------------------------------


class SealTamperTests(unittest.TestCase):
    """Domain seals over the core envelope fail closed on every splice."""

    def test_round_trip_is_lossless_and_byte_stable(self) -> None:
        record = reservation(conditions=conditions())
        for transition in (
            record,
            hold_reservation(
                record, as_of=IN_WINDOW, hold_ref=HOLD_REF, provenance=prov()
            ),
            commit_reservation(
                record,
                as_of=IN_WINDOW,
                satisfied_conditions=("cond/encumbrance", "cond/funding"),
                provenance=prov(),
            ),
            release_reservation(record, as_of=IN_WINDOW, provenance=prov()),
            expire_reservation(record, as_of=AT_CLOSE, provenance=prov()),
            default_reservation(
                hold_reservation(
                    record, as_of=IN_WINDOW, hold_ref=HOLD_REF, provenance=prov()
                ),
                as_of=IN_WINDOW_LATER,
                reason=DefaultReason.PROVIDER_FAILURE,
                provenance=prov(),
            ),
            consume_reservation(
                commit_reservation(
                    record,
                    as_of=IN_WINDOW,
                    satisfied_conditions=("cond/encumbrance", "cond/funding"),
                    provenance=prov(),
                ),
                as_of=IN_WINDOW_LATER,
                provenance=prov(),
            ),
        ):
            encoded = transition.to_json()
            decoded = Reservation.from_json(encoded)
            self.assertEqual(decoded, transition)
            self.assertEqual(decoded.to_json(), encoded)
            rebuilt = Reservation.from_dict(transition.to_dict())
            self.assertEqual(rebuilt, transition)

    def test_rebuilds_from_identical_inputs_are_byte_identical(self) -> None:
        first = reservation(conditions=conditions())
        second = reservation(conditions=conditions())
        self.assertEqual(first.to_json(), second.to_json())
        self.assertEqual(first.integrity_hash, second.integrity_hash)

    def test_tampered_payload_is_rejected(self) -> None:
        record = reservation()
        decoded = record.to_dict()
        decoded["payload"]["amount"]["value"] = 999999
        with self.assertRaises(CoreValidationError):
            Reservation.from_dict(decoded)

    def test_tampered_envelope_state_is_rejected(self) -> None:
        record = reservation()
        decoded = record.to_dict()
        decoded["envelope"]["state"] = "COMMITTED"
        with self.assertRaises(CoreValidationError):
            Reservation.from_dict(decoded)

    def test_resealed_envelope_with_stale_domain_seal_is_rejected(self) -> None:
        record = reservation()
        decoded = record.to_dict()
        decoded["envelope"] = _reseal_envelope(decoded["envelope"], state="COMMITTED")
        with self.assertRaises(CoreValidationError):
            Reservation.from_dict(decoded)

    def test_spliced_payload_from_another_reservation_is_rejected(self) -> None:
        record = reservation()
        other = reservation(
            reservation_id="reservation/r-2",
            resource_key=OTHER_RESOURCE_KEY,
            provider="provider/beta",
        )
        spliced = record.to_dict()
        spliced["payload"] = other.to_dict()["payload"]
        with self.assertRaises(CoreValidationError):
            Reservation.from_dict(spliced)

    def test_missing_domain_seal_is_rejected(self) -> None:
        record = reservation()
        decoded = record.to_dict()
        decoded.pop("integrity_hash")
        with self.assertRaises(CoreValidationError):
            Reservation.from_dict(decoded)

    def test_unknown_state_vocabulary_is_rejected(self) -> None:
        record = hold_reservation(
            reservation(), as_of=IN_WINDOW, hold_ref=HOLD_REF, provenance=prov()
        )
        decoded = record.to_dict()
        decoded["envelope"] = _reseal_envelope(decoded["envelope"], state="PENDING")
        decoded = _reseal_composite(decoded)
        with self.assertRaises(CoreValidationError):
            Reservation.from_dict(decoded)

    def test_registry_claiming_object_types_are_rejected(self) -> None:
        record = reservation()
        decoded = record.to_dict()
        decoded["envelope"] = _reseal_envelope(
            decoded["envelope"], object_type="payswap/reservation/v1"
        )
        decoded = _reseal_composite(decoded)
        with self.assertRaises(CoreValidationError) as ctx:
            Reservation.from_dict(decoded)
        self.assertIn("protocol-visible", str(ctx.exception))

    def test_wrong_schema_and_protocol_versions_are_rejected(self) -> None:
        for changes in ({"schema_version": 2}, {"protocol_version": "v0.2"}):
            record = reservation()
            decoded = record.to_dict()
            decoded["envelope"] = _reseal_envelope(decoded["envelope"], **changes)
            decoded = _reseal_composite(decoded)
            with self.assertRaises(CoreValidationError):
                Reservation.from_dict(decoded)

    def test_state_field_coherence_is_enforced_on_decode(self) -> None:
        record = reservation()
        # HELD without an encumbrance reference (resealed so only the
        # coherence guard can fire).
        held = hold_reservation(
            record, as_of=IN_WINDOW, hold_ref=HOLD_REF, provenance=prov()
        ).to_dict()
        held["payload"]["hold_ref"] = None
        with self.assertRaises(CoreValidationError):
            Reservation.from_dict(_reseal_composite(held))
        # COMMITTED without a commit instant.
        committed = commit_reservation(
            record, as_of=IN_WINDOW, provenance=prov()
        ).to_dict()
        committed["payload"]["committed_at"] = None
        with self.assertRaises(CoreValidationError):
            Reservation.from_dict(_reseal_composite(committed))
        # DEFAULTED without a reason.
        defaulted = default_reservation(
            hold_reservation(
                record, as_of=IN_WINDOW, hold_ref=HOLD_REF, provenance=prov()
            ),
            as_of=IN_WINDOW_LATER,
            reason=DefaultReason.PROVIDER_FAILURE,
            provenance=prov(),
        ).to_dict()
        defaulted["payload"]["defaulted_reason"] = None
        with self.assertRaises(CoreValidationError):
            Reservation.from_dict(_reseal_composite(defaulted))
        # CONSUMED without a preceding commit.
        consumed = consume_reservation(
            commit_reservation(record, as_of=IN_WINDOW, provenance=prov()),
            as_of=IN_WINDOW_LATER,
            provenance=prov(),
        ).to_dict()
        consumed["payload"]["committed_at"] = None
        consumed["payload"]["commit_evidence"] = None
        with self.assertRaises(CoreValidationError):
            Reservation.from_dict(_reseal_composite(consumed))

    def test_noncanonical_payload_fields_are_rejected(self) -> None:
        record = reservation()
        decoded = record.to_dict()
        decoded["payload"]["surprise"] = True
        with self.assertRaises(CoreValidationError):
            Reservation.from_dict(decoded)

    def test_noncanonical_json_duplicates_are_rejected(self) -> None:
        import json as _json

        record = reservation()
        decoded = _json.loads(record.to_json())
        envelope_pairs = ",".join(
            f"{_json.dumps(key)}:{_json.dumps(value)}"
            for key, value in decoded["envelope"].items()
        )
        duplicated_key = _json.dumps(decoded["envelope"]["object_id"])
        duplicated = (
            '{"envelope":{'
            + envelope_pairs
            + f',"object_id":{duplicated_key}'
            + '},"payload":'
            + _json.dumps(decoded["payload"])
            + ',"integrity_hash":'
            + _json.dumps(decoded["integrity_hash"])
            + "}"
        )
        with self.assertRaises(CoreValidationError):
            Reservation.from_json(duplicated)


# ---------------------------------------------------------------------------
# 8. DOGFOOD-012 conformance (guarded real-PostgreSQL two-actor race).
# ---------------------------------------------------------------------------


class DogfoodingTests(unittest.TestCase):
    """The dogfooding harness is deterministic and byte-stable.

    The suite itself stays runnable without PostgreSQL: the harness module
    imports pgserver/psycopg2 (they live nowhere else), so these tests skip
    cleanly when the real-PostgreSQL stack is unavailable and run the full
    two-actor race when it is. That guard is the documented choice — the
    domain suite never requires a database.
    """

    def _harness(self):
        try:
            from src.reservation import dogfooding
        except Exception as exc:  # pragma: no cover - environment guard
            self.skipTest(f"real-PostgreSQL stack unavailable: {exc}")
        return dogfooding

    def test_harness_keeps_postgresql_data_outside_the_worktree(self) -> None:
        harness = self._harness()
        self.assertEqual(harness.TABLE, "reservation_race_w012")
        self.assertFalse(
            Path(harness.DATADIR).is_relative_to(Path(__file__).parent),
            "the PostgreSQL datadir must live outside the package/worktree",
        )

    def test_transcript_is_deterministic_with_a_stable_digest(self) -> None:
        harness = self._harness()
        transcript_a, digest_a = harness.build_transcript()
        transcript_b, digest_b = harness.build_transcript()
        self.assertEqual(transcript_a, transcript_b)
        self.assertEqual(digest_a, digest_b)
        self.assertEqual(len(digest_a), 64)
        self.assertIn("schedule=domain precedence rule", transcript_a)

    def test_same_key_create_race_leaves_exactly_one_winner_with_loser_provenance(
        self,
    ) -> None:
        harness = self._harness()
        transcript, _ = harness.build_transcript()
        self.assertIn("exp=A same-key create race (unique constraint)", transcript)
        self.assertIn("b.error=UniqueViolation", transcript)
        self.assertIn("pg.live_rows_on_key=1", transcript)
        self.assertIn("winner=actor/alpha reservation/dogfood-a", transcript)
        self.assertIn("loser=actor/beta reservation/dogfood-b", transcript)
        self.assertIn(
            "loser.reason=resource key admits at most one live reservation", transcript
        )
        self.assertIn("loser.provenance=precedence requested_at", transcript)
        self.assertIn("domain.loser_denied_by=live_key_exclusivity", transcript)

    def test_same_key_hold_race_is_decided_by_row_locks_and_versions(self) -> None:
        harness = self._harness()
        transcript, _ = harness.build_transcript()
        self.assertIn("exp=A same-key hold race (row-level locking)", transcript)
        self.assertIn(
            "b.nowait=LockNotAvailable (row lock held by actor/alpha)", transcript
        )
        self.assertIn("b.rows_updated=0", transcript)
        self.assertIn(
            "b.reason=expected-version conflict (writer expected 1, store holds 2)",
            transcript,
        )
        self.assertIn("domain.hold_loser_denied_by=expected_version", transcript)
        self.assertIn("pg.hold_state=HELD v2", transcript)
        self.assertIn("domain.hold_state=HELD v2", transcript)

    def test_keyed_not_global_concurrency_interleaves_real_commits(self) -> None:
        harness = self._harness()
        transcript, _ = harness.build_transcript()
        self.assertIn("exp=B keyed-not-global concurrency", transcript)
        self.assertIn(
            "b.nowait=LockNotAvailable (key one row lock still held)", transcript
        )
        self.assertIn(
            "b.commit=ok (key two committed while key one lock held)", transcript
        )
        self.assertIn(
            "interleaved=beta committed before alpha (no global serialization)",
            transcript,
        )
        self.assertIn(
            "pg.row resource/provider-alpha/asset-USD/slot-7"
            " reservation/dogfood-a COMMITTED v3",
            transcript,
        )
        self.assertIn(
            "pg.row resource/provider-beta/asset-USD/slot-8"
            " reservation/dogfood-b2 COMMITTED v2",
            transcript,
        )
        self.assertIn("pg.live_per_key=1", transcript)
        self.assertIn(
            "domain.b_cross_key_apply=ok (key two committed while key one gate held)",
            transcript,
        )


if __name__ == "__main__":
    unittest.main()
