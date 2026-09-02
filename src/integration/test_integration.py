"""Contract suite for the IG-001 kernel/value integration gate (WORK-026).

Authored RED-FIRST against the declared public boundary of
``src.integration``: the whole suite was written and run before any
implementation module existed, and it must fail with import errors at that
stage (evidence persisted outside the repository).

The gate composes real merged implementations ONLY (read-only consumed):

* ``src.transition`` — the deterministic command/event transition kernel;
* ``src.value``      — the authoritative ledger, postings, holds;
* ``src.money``      — exact fixed-point amounts, FX, allocation;
* ``src.core``       — canonical envelopes and the single error authority.

The suite covers:

- static boundary contracts (typed versioned boundary, AST import audit,
  loaded-module audit, no floats, no wall-clock/entropy);
- the full payment lifecycle through the REAL kernel driving the REAL
  ledger and REAL money arithmetic (balanced double-entry legs, holds,
  FX conversion with an explicit residual, weighted residual allocation,
  reconciliation);
- kernel discipline (idempotency, duplicate convergence, expected-version
  conflicts, environment isolation, authorization, unknown command types);
- explicit failure paths (fail closed, zero value-state change);
- the cross-layer invariant battery and its discrimination regressions;
- deterministic journal-driven replay and snapshot transformation
  completeness;
- a scaled quality-attribute fixture and the DOGFOOD-026 conformance.
"""

from __future__ import annotations

import ast
import pathlib
import sys
import time
import unittest

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.serialization import canonical_json, canonical_sha256
from src.money import (
    Amount as MoneyAmount,
    FxRate,
    RoundingMode,
    allocate_weighted,
    convert,
    get_currency,
)
from src.transition import (
    Command,
    ExpectedVersion,
    MemoryStateStore,
    Outcome,
    RejectionReason,
)
from src.value import (
    AccountState,
    AssetState,
    BalanceView,
    EntrySide,
    HoldState,
    JournalState,
    PostingClass,
    PostingLeg,
    ReconciliationState,
)

from src.integration import (
    CONSUMED_SURFACES,
    CoreValidationError,
    INTEGRATION_API_VERSION,
    INTEGRATION_GATE_ID,
    INTEGRATION_SCHEMA_VERSION,
    INTENT_AUTHORIZE_COMMAND,
    INTENT_CREATE_COMMAND,
    INTENT_CREATED_EVENT,
    INTENT_AUTHORIZED_EVENT,
    INTENT_OBJECT_TYPE,
    KNOWN_INTEGRATION_GATES,
    SETTLEMENT_OBJECT_TYPE,
    SETTLEMENT_RECONCILE_COMMAND,
    SETTLEMENT_RECONCILED_EVENT,
    SETTLEMENT_SUBMIT_COMMAND,
    SETTLEMENT_SUBMITTED_EVENT,
    IntegrationGate,
    assert_replay_equivalence,
    replay_from_journal,
    validate_gate_id,
    verify_invariants,
)
from src.integration import invariants
from src.integration.dogfooding import build_transcript, main
from src.integration.scenarios import (
    DEFAULT_ALLOCATION_WEIGHTS,
    DEFAULT_FEE_MINOR,
    DEFAULT_INITIAL_DEPOSIT_MINOR,
    DEFAULT_RATE_DENOMINATOR,
    DEFAULT_RATE_NUMERATOR,
    DEFAULT_SOURCE_MINOR,
    payment_scenario_commands,
    run_payment_scenario,
    run_scaled_scenario,
)

ENV = "env/ig001-test"
DOMAIN = "domain/ig001-test"
PAYER = "value/account/payer-ig1"
PAYEE = "value/account/payee-ig1"
SAVINGS = "value/account/payee-savings-ig1"
HOUSE_USD = "value/account/house-usd-ig1"
HOUSE_EUR = "value/account/house-eur-ig1"
VAULT = "value/account/vault-ig1"
FEE_INCOME = "value/account/fee-income-ig1"
JOURNAL = "value/journal/ig1"

# Exact deterministic money facts of the canonical scenario.
EXPECTED_TARGET_MINOR = 1137546
EXPECTED_RESIDUAL_NUMERATOR = -5000
EXPECTED_RESIDUAL_DENOMINATOR = 10000
EXPECTED_ALLOCATION_PARTS = (758364, 379182)


def standard_gate() -> IntegrationGate:
    gate = IntegrationGate(environment_id=ENV, domain_id=DOMAIN)
    gate.provision()
    return gate


def settled_gate() -> IntegrationGate:
    """A gate whose canonical payment scenario ran to reconciliation."""
    gate = standard_gate()
    run_payment_scenario(gate, tag="ig1")
    return gate


# ---------------------------------------------------------------------------
# 1. Static boundary contracts.
# ---------------------------------------------------------------------------


class StaticBoundaryTests(unittest.TestCase):
    """The typed, versioned public boundary and the import containment."""

    def test_gate_identity_constants(self) -> None:
        self.assertEqual(INTEGRATION_GATE_ID, "IG-001")
        self.assertEqual(INTEGRATION_API_VERSION, "v0.1")
        self.assertEqual(INTEGRATION_SCHEMA_VERSION, 1)
        self.assertEqual(KNOWN_INTEGRATION_GATES, frozenset({"IG-001"}))
        self.assertEqual(
            CONSUMED_SURFACES,
            ("src.core", "src.transition", "src.value", "src.money"),
        )

    def test_public_boundary_all_is_explicit_and_frozen(self) -> None:
        import src.integration

        self.assertEqual(
            set(src.integration.__all__),
            {
                "CONSUMED_SURFACES",
                "CoreValidationError",
                "INTEGRATION_API_VERSION",
                "INTEGRATION_GATE_ID",
                "INTEGRATION_SCHEMA_VERSION",
                "INTENT_AUTHORIZE_COMMAND",
                "INTENT_CREATE_COMMAND",
                "INTENT_CREATED_EVENT",
                "INTENT_AUTHORIZED_EVENT",
                "INTENT_OBJECT_TYPE",
                "KNOWN_INTEGRATION_GATES",
                "SETTLEMENT_OBJECT_TYPE",
                "SETTLEMENT_RECONCILE_COMMAND",
                "SETTLEMENT_RECONCILED_EVENT",
                "SETTLEMENT_SUBMIT_COMMAND",
                "SETTLEMENT_SUBMITTED_EVENT",
                "IntegrationGate",
                "assert_replay_equivalence",
                "replay_from_journal",
                "validate_gate_id",
                "verify_invariants",
            },
        )

    def test_composed_object_types_come_from_the_frozen_registry(self) -> None:
        # payswap/intent/v1 and payswap/settlement/v1 are registry-listed
        # protocol-visible object types; the gate invents none.
        import json

        registry = json.loads(
            (pathlib.Path(__file__).resolve().parents[2] / "spec/registry/protocol-registry.json")
            .read_text(encoding="utf-8")
        )
        listed = set(registry["registry"]["objectTypes"])
        self.assertIn(INTENT_OBJECT_TYPE, listed)
        self.assertIn(SETTLEMENT_OBJECT_TYPE, listed)

    def test_command_types_use_the_internal_gate_prefix(self) -> None:
        for command_type in (
            INTENT_CREATE_COMMAND,
            INTENT_AUTHORIZE_COMMAND,
            SETTLEMENT_SUBMIT_COMMAND,
            SETTLEMENT_RECONCILE_COMMAND,
        ):
            self.assertTrue(command_type.startswith("integration/"))
            self.assertIn(".", command_type.split("/", 1)[1])

    def test_event_types_use_frozen_registry_namespaces(self) -> None:
        from src.transition import EVENT_NAMESPACES

        for event_type in (
            INTENT_CREATED_EVENT,
            INTENT_AUTHORIZED_EVENT,
            SETTLEMENT_SUBMITTED_EVENT,
            SETTLEMENT_RECONCILED_EVENT,
        ):
            namespace = event_type.split("/", 1)[0]
            self.assertIn(namespace, EVENT_NAMESPACES)

    def test_gate_modules_import_only_composed_roots(self) -> None:
        # AST import audit: stdlib plus src.core/src.transition/src.value/
        # src.money only; relative imports inside this package are allowed.
        allowed_roots = set(CONSUMED_SURFACES)
        package = pathlib.Path(__file__).parent
        for source in sorted(package.glob("*.py")):
            if source.name == "test_integration.py":
                continue
            tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        root = alias.name.split(".", 1)[0]
                        if root == "src":
                            prefix = ".".join(alias.name.split(".")[:2])
                            self.assertIn(prefix, allowed_roots, f"{source.name} imports {alias.name}")
                        else:
                            self.assertIn(
                                root, sys.stdlib_module_names, f"{source.name} imports {alias.name}"
                            )
                elif isinstance(node, ast.ImportFrom):
                    if node.level >= 1:
                        continue
                    module = node.module or ""
                    root = module.split(".", 1)[0]
                    if root == "__future__":
                        continue
                    if root == "src":
                        prefix = ".".join(module.split(".")[:2])
                        self.assertIn(prefix, allowed_roots, f"{source.name} imports from {module}")
                    else:
                        self.assertIn(
                            root, sys.stdlib_module_names, f"{source.name} imports from {module}"
                        )

    def test_gate_sources_never_reference_forbidden_siblings(self) -> None:
        package = pathlib.Path(__file__).parent
        for source in sorted(package.glob("*.py")):
            if source.name == "test_integration.py":
                continue
            text = source.read_text(encoding="utf-8")
            for forbidden in (
                "src.intent",
                "src.market",
                "src.reservation",
                "src.liquidity",
                "src.safety",
                "src.evidence",
                "src.capability",
                "src.interoperability",
                "src.trust",
                "src.simulation",
            ):
                self.assertNotIn(forbidden, text, f"{source.name} references {forbidden}")

    def test_gate_sources_contain_no_float_literals(self) -> None:
        package = pathlib.Path(__file__).parent
        sources = sorted(
            path for path in package.glob("*.py") if not path.name.startswith("test")
        )
        self.assertTrue(sources)
        for path in sources:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, float):
                    self.fail(f"float literal found in {path.name} at line {node.lineno}")

    def test_gate_code_has_no_wall_clock_entropy_or_uuids(self) -> None:
        package = pathlib.Path(__file__).parent
        for source in sorted(package.glob("*.py")):
            if source.name in ("test_integration.py", "dogfooding.py"):
                continue
            text = source.read_text(encoding="utf-8")
            for forbidden in (
                "time.time",
                "datetime.now",
                "utcnow",
                "random",
                "uuid",
                "time.monotonic",
                "time.process_time",
            ):
                self.assertNotIn(forbidden, text, f"{source.name} references {forbidden}")

    def test_loaded_modules_never_include_forbidden_siblings(self) -> None:
        import src.integration  # noqa: F401  (boundary import under audit)

        allowed = set(CONSUMED_SURFACES)
        for name in list(sys.modules):
            if name.startswith("src.") and name.count(".") >= 1:
                prefix = ".".join(name.split(".")[:2])
                self.assertIn(
                    prefix,
                    allowed | {"src.integration"},
                    f"importing src.integration loaded {name}",
                )


# ---------------------------------------------------------------------------
# 2. Gate identity.
# ---------------------------------------------------------------------------


class GateIdentityTests(unittest.TestCase):
    def test_validate_gate_id_accepts_the_known_gate(self) -> None:
        self.assertEqual(validate_gate_id("IG-001"), "IG-001")

    def test_validate_gate_id_fails_closed_on_unknown_gate(self) -> None:
        for unknown in ("IG-002", "ig-001", "", "IG-1", None, 1):
            with self.assertRaises(CoreValidationError) as raised:
                validate_gate_id(unknown)
            self.assertIn("unknown integration gate", str(raised.exception))

    def test_gate_constructor_rejects_unknown_gate_ids(self) -> None:
        with self.assertRaises(CoreValidationError):
            IntegrationGate(environment_id=ENV, domain_id=DOMAIN, gate_id="IG-999")
        with self.assertRaises(CoreValidationError):
            IntegrationGate(environment_id=ENV, domain_id=DOMAIN, gate_id="")

    def test_gate_constructor_binds_one_environment_and_domain(self) -> None:
        gate = IntegrationGate(environment_id=ENV, domain_id=DOMAIN)
        self.assertEqual(gate.environment_id, ENV)
        self.assertEqual(gate.domain_id, DOMAIN)
        self.assertEqual(gate.engine.environment_id, ENV)
        ledger_state = gate.ledger_state()
        self.assertEqual(ledger_state["environment_id"], ENV)
        self.assertEqual(ledger_state["domain_id"], DOMAIN)

    def test_gate_exposes_the_real_composed_implementations(self) -> None:
        from src.money import Amount as MoneyAmountAlias
        from src.transition import TransitionEngine
        from src.value import ValueLedger

        gate = IntegrationGate(environment_id=ENV, domain_id=DOMAIN)
        self.assertIsInstance(gate.engine, TransitionEngine)
        self.assertIsInstance(gate.ledger, ValueLedger)
        self.assertIsInstance(gate.store, MemoryStateStore)
        self.assertEqual(len(gate.store.snapshot()), 0)
        # money arithmetic is exercised through the real conversion API
        usd = get_currency("USD")
        eur = get_currency("EUR")
        rate = FxRate(source=usd, target=eur, numerator=91, denominator=100)
        conversion = convert(
            rate, MoneyAmountAlias(currency=usd, value=10, scale=2), RoundingMode.HALF_EVEN
        )
        self.assertEqual(conversion.rate.numerator, 91)


# ---------------------------------------------------------------------------
# 3. Environment provisioning.
# ---------------------------------------------------------------------------


class ProvisioningTests(unittest.TestCase):
    def test_provision_builds_a_deterministic_funded_environment(self) -> None:
        gate = IntegrationGate(environment_id=ENV, domain_id=DOMAIN)
        gate.provision()
        state = gate.ledger_state()
        self.assertEqual(len(state["assets"]), 2)
        self.assertEqual(len(state["accounts"]), 7)
        self.assertEqual(len(state["journals"]), 1)
        self.assertEqual(len(state["postings"]), 1)
        balances = gate.ledger.derive_balances(account_id=PAYER)
        self.assertEqual(balances.available, DEFAULT_INITIAL_DEPOSIT_MINOR)
        self.assertEqual(balances.total, DEFAULT_INITIAL_DEPOSIT_MINOR)
        vault = gate.ledger.derive_balances(account_id=VAULT)
        self.assertEqual(vault.available, DEFAULT_INITIAL_DEPOSIT_MINOR)

    def test_provision_is_deterministic(self) -> None:
        first = IntegrationGate(environment_id=ENV, domain_id=DOMAIN)
        first.provision()
        second = IntegrationGate(environment_id=ENV, domain_id=DOMAIN)
        second.provision()
        self.assertEqual(first.ledger_digest(), second.ledger_digest())

    def test_provision_registers_assets_with_canonical_money_scales(self) -> None:
        gate = standard_gate()
        usd = gate.ledger.get_asset("USD")
        eur = gate.ledger.get_asset("EUR")
        self.assertEqual(usd.payload.scale, get_currency("USD").scale)
        self.assertEqual(eur.payload.scale, get_currency("EUR").scale)
        self.assertEqual(usd.envelope.state, AssetState.ACTIVE.value)
        self.assertEqual(eur.envelope.state, AssetState.ACTIVE.value)
        for account_id in (PAYER, PAYEE, SAVINGS, HOUSE_USD, HOUSE_EUR, VAULT, FEE_INCOME):
            self.assertEqual(
                gate.ledger.get_account(account_id).envelope.state,
                AccountState.ACTIVE.value,
            )
        self.assertEqual(
            gate.ledger.get_journal(JOURNAL).envelope.state, JournalState.ACTIVE.value
        )

    def test_provision_twice_fails_closed(self) -> None:
        gate = standard_gate()
        with self.assertRaises(CoreValidationError):
            gate.provision()


# ---------------------------------------------------------------------------
# 4. Scenario lifecycle through the real kernel.
# ---------------------------------------------------------------------------


class ScenarioLifecycleTests(unittest.TestCase):
    def test_commands_declare_kernel_envelope_discipline(self) -> None:
        commands = payment_scenario_commands(tag="ig1")
        self.assertEqual(len(commands), 4)
        self.assertEqual(commands[0].command_type, INTENT_CREATE_COMMAND)
        self.assertEqual(commands[1].command_type, INTENT_AUTHORIZE_COMMAND)
        self.assertEqual(commands[2].command_type, SETTLEMENT_SUBMIT_COMMAND)
        self.assertEqual(commands[3].command_type, SETTLEMENT_RECONCILE_COMMAND)
        command_ids = {command.command_id for command in commands}
        keys = {command.idempotency_key for command in commands}
        self.assertEqual(len(command_ids), 4)
        self.assertEqual(len(keys), 4)
        self.assertEqual(
            commands[0].expected_versions,
            (ExpectedVersion(object_ref="intent/ig1", object_version=0),),
        )
        self.assertEqual(
            commands[1].expected_versions,
            (ExpectedVersion(object_ref="intent/ig1", object_version=1),),
        )
        self.assertEqual(
            commands[2].expected_versions,
            (
                ExpectedVersion(object_ref="intent/ig1", object_version=2),
                ExpectedVersion(object_ref="settlement/ig1", object_version=0),
            ),
        )
        self.assertEqual(
            commands[3].expected_versions,
            (ExpectedVersion(object_ref="settlement/ig1", object_version=1),),
        )

    def test_full_scenario_is_accepted_step_by_step(self) -> None:
        gate = standard_gate()
        results = run_payment_scenario(gate, tag="ig1")
        self.assertEqual(len(results), 4)
        for result in results:
            self.assertEqual(result.outcome, Outcome.ACCEPTED)
            self.assertIsNotNone(result.event)
        self.assertEqual(
            [result.event.event_type for result in results],
            [
                INTENT_CREATED_EVENT,
                INTENT_AUTHORIZED_EVENT,
                SETTLEMENT_SUBMITTED_EVENT,
                SETTLEMENT_RECONCILED_EVENT,
            ],
        )
        self.assertEqual(len(gate.engine.journal), 4)

    def test_intent_lifecycle_advances_the_registry_intent_object(self) -> None:
        gate = standard_gate()
        results = run_payment_scenario(gate, tag="ig1")
        create, authorize, settle, _ = results
        intent_v1 = create.resulting_envelopes[0]
        self.assertEqual(intent_v1.object_id, "intent/ig1")
        self.assertEqual(intent_v1.object_type, INTENT_OBJECT_TYPE)
        self.assertEqual(intent_v1.state, "CREATED")
        self.assertEqual(intent_v1.object_version, 1)
        intent_v2 = authorize.resulting_envelopes[0]
        self.assertEqual(intent_v2.state, "AUTHORIZED")
        self.assertEqual(intent_v2.object_version, 2)
        self.assertEqual(intent_v2.previous_version, 1)
        by_id = {envelope.object_id: envelope for envelope in settle.resulting_envelopes}
        self.assertEqual(by_id["intent/ig1"].state, "SETTLED")
        self.assertEqual(by_id["intent/ig1"].object_version, 3)
        settlement = by_id["settlement/ig1"]
        self.assertEqual(settlement.object_type, SETTLEMENT_OBJECT_TYPE)
        self.assertEqual(settlement.state, "SUBMITTED")
        self.assertEqual(settlement.object_version, 1)
        reconciled = results[3].resulting_envelopes[0]
        self.assertEqual(reconciled.object_id, "settlement/ig1")
        self.assertEqual(reconciled.state, "RECONCILED")
        self.assertEqual(reconciled.object_version, 2)

    def test_kernel_envelopes_are_sealed_and_integrity_verified(self) -> None:
        gate = settled_gate()
        for envelope in gate.store.snapshot():
            envelope.verify_integrity()
            self.assertIsNotNone(envelope.integrity_hash)
        self.assertEqual(gate.current_version("intent/ig1"), 3)
        self.assertEqual(gate.current_version("settlement/ig1"), 2)

    def test_authorization_records_a_real_hold_with_an_encumbrance_posting(self) -> None:
        gate = settled_gate()
        state = gate.ledger_state()
        self.assertEqual(len(state["holds"]), 1)
        hold = state["holds"][0]
        self.assertEqual(hold["envelope"]["object_id"], "value/hold/ig1")
        # the settle step released it; the ACTIVE intermediate state and the
        # exact held amount live in the journal-recorded effect outputs
        entry = gate.snapshot()["engine"]["journal"][1]
        hold_effect = entry["payload"]["effects"][0]
        self.assertEqual(hold_effect["kind"], "hold_create")
        self.assertEqual(
            hold_effect["outputs"]["hold"]["envelope"]["state"], HoldState.ACTIVE.value
        )
        self.assertEqual(
            hold_effect["outputs"]["hold"]["payload"]["amount"]["value"], DEFAULT_SOURCE_MINOR
        )
        # a fully settled hold is RELEASED and holds nothing
        self.assertEqual(hold["envelope"]["state"], HoldState.RELEASED.value)
        self.assertEqual(hold["payload"]["amount"]["value"], 0)

    def test_settlement_posts_balanced_fx_and_fee_postings(self) -> None:
        gate = settled_gate()
        state = gate.ledger_state()
        self.assertEqual(len(state["postings"]), 6)
        classes = [posting["payload"]["posting_class"] for posting in state["postings"]]
        self.assertEqual(classes, ["EXECUTION", "HOLD", "HOLD", "FX", "FEE", "FX"])
        for posting in state["postings"]:
            legs = posting["payload"]["legs"]
            self.assertGreaterEqual(len(legs), 2)
            debits: dict[str, int] = {}
            credits: dict[str, int] = {}
            for leg in legs:
                bucket = debits if leg["side"] == "DEBIT" else credits
                bucket[leg["amount"]["asset"]] = (
                    bucket.get(leg["amount"]["asset"], 0) + leg["amount"]["value"]
                )
            self.assertEqual(
                debits, credits, f"unbalanced posting {posting['envelope']['object_id']}"
            )

    def test_settlement_moves_value_between_accounts_exactly(self) -> None:
        gate = settled_gate()
        payer = gate.ledger.derive_balances(account_id=PAYER)
        payee = gate.ledger.derive_balances(account_id=PAYEE)
        savings = gate.ledger.derive_balances(account_id=SAVINGS)
        house_usd = gate.ledger.derive_balances(account_id=HOUSE_USD)
        house_eur = gate.ledger.derive_balances(account_id=HOUSE_EUR)
        vault = gate.ledger.derive_balances(account_id=VAULT)
        fee_income = gate.ledger.derive_balances(account_id=FEE_INCOME)
        self.assertEqual(
            payer.available,
            DEFAULT_INITIAL_DEPOSIT_MINOR - DEFAULT_SOURCE_MINOR - DEFAULT_FEE_MINOR,
        )
        self.assertEqual(payer.total, payer.available)
        self.assertEqual(payee.available, EXPECTED_ALLOCATION_PARTS[0])
        self.assertEqual(savings.available, EXPECTED_ALLOCATION_PARTS[1])
        self.assertEqual(house_usd.available, -DEFAULT_SOURCE_MINOR)
        self.assertEqual(house_eur.available, EXPECTED_TARGET_MINOR)
        self.assertEqual(vault.available, DEFAULT_INITIAL_DEPOSIT_MINOR)
        self.assertEqual(fee_income.available, DEFAULT_FEE_MINOR)

    def test_reconciliation_certifies_balance_and_seals_the_journal(self) -> None:
        gate = settled_gate()
        state = gate.ledger_state()
        self.assertEqual(len(state["reconciliations"]), 1)
        reconciliation = state["reconciliations"][0]
        self.assertEqual(
            reconciliation["envelope"]["state"], ReconciliationState.BALANCED.value
        )
        self.assertEqual(reconciliation["payload"]["discrepancies"], [])
        self.assertEqual(
            gate.ledger.get_journal(JOURNAL).envelope.state, JournalState.RECONCILED.value
        )

    def test_scaled_scenario_produces_a_deterministic_state(self) -> None:
        gate = IntegrationGate(environment_id=ENV, domain_id=DOMAIN)
        gate.provision(initial_deposit_minor=2 * (DEFAULT_SOURCE_MINOR + DEFAULT_FEE_MINOR))
        summary = run_scaled_scenario(gate, count=2)
        self.assertEqual(summary["intents"], 2)
        self.assertEqual(summary["commands"], 7)
        self.assertEqual(summary["journal_entries"], 7)
        self.assertEqual(summary["postings"], 11)
        again = IntegrationGate(environment_id=ENV, domain_id=DOMAIN)
        again.provision(initial_deposit_minor=2 * (DEFAULT_SOURCE_MINOR + DEFAULT_FEE_MINOR))
        second = run_scaled_scenario(again, count=2)
        self.assertEqual(summary["composed_digest"], second["composed_digest"])


# ---------------------------------------------------------------------------
# 5. Money composition (FX, allocation, scale authority).
# ---------------------------------------------------------------------------


class MoneyCompositionTests(unittest.TestCase):
    def settled_entries(self) -> tuple[IntegrationGate, list[dict]]:
        gate = settled_gate()
        entries = gate.snapshot()["engine"]["journal"]
        return gate, entries

    def test_conversion_effect_records_the_exact_fx_identity(self) -> None:
        gate, entries = self.settled_entries()
        effects = entries[2]["payload"]["effects"]
        convert_effect = effects[0]
        self.assertEqual(convert_effect["kind"], "convert")
        outputs = convert_effect["outputs"]["conversion"]
        self.assertEqual(outputs["source"]["value"], DEFAULT_SOURCE_MINOR)
        self.assertEqual(outputs["source"]["currency"], "USD")
        self.assertEqual(outputs["target"]["value"], EXPECTED_TARGET_MINOR)
        self.assertEqual(outputs["target"]["currency"], "EUR")
        self.assertEqual(outputs["residual_numerator"], EXPECTED_RESIDUAL_NUMERATOR)
        self.assertEqual(outputs["residual_denominator"], EXPECTED_RESIDUAL_DENOMINATOR)
        self.assertLess(abs(outputs["residual_numerator"]), outputs["residual_denominator"])
        # exact conservation identity: source * num * 10^target_scale ==
        # target * denominator + residual
        numerator = outputs["source"]["value"] * 91 * 10**2
        self.assertEqual(
            numerator,
            outputs["target"]["value"] * outputs["residual_denominator"]
            + outputs["residual_numerator"],
        )
        del gate

    def test_conversion_effect_matches_the_real_money_domain_result(self) -> None:
        usd = get_currency("USD")
        eur = get_currency("EUR")
        rate = FxRate(
            source=usd,
            target=eur,
            numerator=DEFAULT_RATE_NUMERATOR,
            denominator=DEFAULT_RATE_DENOMINATOR,
        )
        conversion = convert(
            rate,
            MoneyAmount(currency=usd, value=DEFAULT_SOURCE_MINOR, scale=2),
            RoundingMode.HALF_EVEN,
        )
        self.assertEqual(conversion.target.value, EXPECTED_TARGET_MINOR)
        self.assertEqual(conversion.residual_numerator, EXPECTED_RESIDUAL_NUMERATOR)
        self.assertEqual(conversion.residual_denominator, EXPECTED_RESIDUAL_DENOMINATOR)

    def test_allocation_effect_sums_exactly_to_the_converted_amount(self) -> None:
        _, entries = self.settled_entries()
        effects = entries[2]["payload"]["effects"]
        allocate_effect = effects[1]
        self.assertEqual(allocate_effect["kind"], "allocate")
        self.assertEqual(allocate_effect["inputs"]["weights"], list(DEFAULT_ALLOCATION_WEIGHTS))
        parts = allocate_effect["outputs"]["parts"]
        self.assertEqual([part["value"] for part in parts], list(EXPECTED_ALLOCATION_PARTS))
        self.assertEqual(sum(part["value"] for part in parts), EXPECTED_TARGET_MINOR)
        for part in parts:
            self.assertEqual(part["currency"], "EUR")
            self.assertEqual(part["scale"], 2)

    def test_ledger_amounts_use_canonical_currency_scales(self) -> None:
        gate, _ = self.settled_entries()
        for posting in gate.ledger_state()["postings"]:
            for leg in posting["payload"]["legs"]:
                currency = get_currency(leg["amount"]["asset"])
                self.assertEqual(leg["amount"]["scale"], currency.scale)

    def test_fx_legs_carry_the_exact_conversion_amounts(self) -> None:
        gate, _ = self.settled_entries()
        postings = gate.ledger_state()["postings"]
        fx_source = postings[3]
        fx_target = postings[5]
        self.assertEqual(fx_source["payload"]["legs"][0]["amount"]["value"], DEFAULT_SOURCE_MINOR)
        self.assertEqual(fx_source["payload"]["legs"][0]["amount"]["asset"], "USD")
        eur_credits = [
            leg["amount"]["value"]
            for leg in fx_target["payload"]["legs"]
            if leg["side"] == "CREDIT"
        ]
        self.assertEqual(eur_credits, list(EXPECTED_ALLOCATION_PARTS))
        eur_debits = [
            leg["amount"]["value"]
            for leg in fx_target["payload"]["legs"]
            if leg["side"] == "DEBIT"
        ]
        self.assertEqual(eur_debits, [EXPECTED_TARGET_MINOR])


# ---------------------------------------------------------------------------
# 6. Kernel discipline through the gate.
# ---------------------------------------------------------------------------


class KernelDisciplineTests(unittest.TestCase):
    def test_duplicate_commands_converge_without_new_events_or_state(self) -> None:
        gate = standard_gate()
        commands = payment_scenario_commands(tag="ig1", environment_id=ENV, domain_id=DOMAIN)
        first = gate.submit(commands[0])
        digest_before = gate.composed_digest()
        duplicate = gate.submit(commands[0])
        self.assertEqual(duplicate.outcome, Outcome.DUPLICATE)
        self.assertEqual(duplicate.event, first.event)
        self.assertEqual(len(gate.engine.journal), 1)
        self.assertEqual(gate.composed_digest(), digest_before)

    def test_command_id_reuse_for_different_content_fails_closed(self) -> None:
        gate = standard_gate()
        create = payment_scenario_commands(
            tag="ig1", environment_id=ENV, domain_id=DOMAIN
        )[0]
        gate.submit(create)
        tampered = Command.build(
            command_id=create.command_id,
            command_type=create.command_type,
            actor=create.actor,
            target_refs=create.target_refs,
            payload={"originator": "principal/customer-7", "malicious": True},
            environment_id=create.environment_id,
            domain_id=create.domain_id,
            idempotency_key=create.idempotency_key + "/other",
            nonce=create.nonce,
            requested_at=create.requested_at,
        )
        result = gate.submit(tampered)
        self.assertEqual(result.outcome, Outcome.REJECTED)
        self.assertEqual(result.reason, RejectionReason.COMMAND_ID_REUSED)

    def test_idempotency_key_conflict_fails_closed(self) -> None:
        gate = standard_gate()
        create = payment_scenario_commands(
            tag="ig1", environment_id=ENV, domain_id=DOMAIN
        )[0]
        gate.submit(create)
        conflicting = Command.build(
            command_id="cmd/ig1/create-conflict",
            command_type=create.command_type,
            actor=create.actor,
            target_refs=create.target_refs,
            payload={"originator": "principal/customer-7", "conflict": True},
            environment_id=create.environment_id,
            domain_id=create.domain_id,
            idempotency_key=create.idempotency_key,
            nonce=create.nonce + "-2",
            requested_at=create.requested_at,
        )
        result = gate.submit(conflicting)
        self.assertEqual(result.outcome, Outcome.REJECTED)
        self.assertEqual(result.reason, RejectionReason.IDEMPOTENCY_CONFLICT)

    def test_stale_expected_version_is_rejected_without_value_mutation(self) -> None:
        gate = standard_gate()
        commands = payment_scenario_commands(tag="ig1", environment_id=ENV, domain_id=DOMAIN)
        gate.submit(commands[0])
        digest_before = gate.composed_digest()
        stale = Command.build(
            command_id="cmd/ig1/stale",
            command_type=INTENT_AUTHORIZE_COMMAND,
            actor="principal/customer-7",
            target_refs=("intent/ig1",),
            payload={
                "source_asset": "USD",
                "source_amount": DEFAULT_SOURCE_MINOR,
                "account_id": PAYER,
            },
            environment_id=ENV,
            domain_id=DOMAIN,
            expected_versions=(ExpectedVersion(object_ref="intent/ig1", object_version=0),),
            idempotency_key="key/ig1/stale",
            nonce="n",
            requested_at="2026-09-02T00:05:00Z",
        )
        result = gate.submit(stale)
        self.assertEqual(result.outcome, Outcome.REJECTED)
        self.assertEqual(result.reason, RejectionReason.VERSION_CONFLICT)
        self.assertEqual(gate.composed_digest(), digest_before)

    def test_unknown_command_type_is_rejected_without_value_mutation(self) -> None:
        gate = standard_gate()
        digest_before = gate.composed_digest()
        rogue = Command.build(
            command_id="cmd/ig1/rogue",
            command_type="integration/intent.rogue",
            actor="principal/customer-7",
            target_refs=("intent/ig1",),
            payload={},
            environment_id=ENV,
            domain_id=DOMAIN,
            idempotency_key="key/ig1/rogue",
            nonce="n",
            requested_at="2026-09-02T00:05:00Z",
        )
        result = gate.submit(rogue)
        self.assertEqual(result.outcome, Outcome.REJECTED)
        self.assertEqual(result.reason, RejectionReason.UNKNOWN_COMMAND_TYPE)
        self.assertEqual(gate.composed_digest(), digest_before)

    def test_foreign_environment_commands_are_isolated(self) -> None:
        gate = standard_gate()
        digest_before = gate.composed_digest()
        foreign = Command.build(
            command_id="cmd/ig1/foreign",
            command_type=INTENT_CREATE_COMMAND,
            actor="principal/customer-7",
            target_refs=("intent/foreign",),
            payload={"originator": "principal/customer-7"},
            environment_id="env/production",
            domain_id=DOMAIN,
            idempotency_key="key/ig1/foreign",
            nonce="n",
            requested_at="2026-09-02T00:05:00Z",
        )
        result = gate.submit(foreign)
        self.assertEqual(result.outcome, Outcome.REJECTED)
        self.assertEqual(result.reason, RejectionReason.ENVIRONMENT_MISMATCH)
        self.assertEqual(gate.composed_digest(), digest_before)

    def test_unauthorized_actors_are_rejected_without_value_mutation(self) -> None:
        gate = standard_gate()
        digest_before = gate.composed_digest()
        attacker = Command.build(
            command_id="cmd/ig1/attack",
            command_type=INTENT_CREATE_COMMAND,
            actor="principal/attacker",
            target_refs=("intent/attack",),
            payload={"originator": "principal/attacker"},
            environment_id=ENV,
            domain_id=DOMAIN,
            idempotency_key="key/ig1/attack",
            nonce="n",
            requested_at="2026-09-02T00:05:00Z",
        )
        result = gate.submit(attacker)
        self.assertEqual(result.outcome, Outcome.REJECTED)
        self.assertEqual(result.reason, RejectionReason.UNAUTHORIZED)
        self.assertEqual(gate.composed_digest(), digest_before)

    def test_gate_accepts_declared_actors_with_a_registry_authority_class(self) -> None:
        gate = standard_gate()
        commands = payment_scenario_commands(tag="ig1", environment_id=ENV, domain_id=DOMAIN)
        result = gate.submit(commands[0])
        self.assertEqual(result.outcome, Outcome.ACCEPTED)
        self.assertIn(result.event.authority, ("A0", "A1", "A2", "A3"))

    def test_replay_of_the_whole_scenario_converges_as_duplicates(self) -> None:
        gate = settled_gate()
        digest_before = gate.composed_digest()
        commands = payment_scenario_commands(tag="ig1", environment_id=ENV, domain_id=DOMAIN)
        outcomes = [gate.submit(command).outcome for command in commands]
        self.assertEqual(outcomes, [Outcome.DUPLICATE] * 4)
        self.assertEqual(len(gate.engine.journal), 4)
        self.assertEqual(gate.composed_digest(), digest_before)


# ---------------------------------------------------------------------------
# 7. Explicit failure paths (fail closed, zero value-state change).
# ---------------------------------------------------------------------------


class FailurePathTests(unittest.TestCase):
    def settle_payload(self, **overrides: object) -> dict:
        payload: dict = {
            "hold_id": "value/hold/ig1",
            "fx_rate": {"numerator": 91, "denominator": 100},
            "rounding_mode": "HALF_EVEN",
            "fee_minor": DEFAULT_FEE_MINOR,
            "allocation_weights": [2, 1],
            "target_asset": "EUR",
            "payout_accounts": [PAYEE, SAVINGS],
        }
        payload.update(overrides)
        return payload

    def authorized_gate(self) -> tuple[IntegrationGate, tuple[Command, ...]]:
        gate = standard_gate()
        commands = payment_scenario_commands(tag="ig1", environment_id=ENV, domain_id=DOMAIN)
        gate.submit(commands[0])
        gate.submit(commands[1])
        return gate, commands

    def test_settlement_rejects_a_divergent_quoted_target_without_state_change(self) -> None:
        gate, _ = self.authorized_gate()
        digest_before = gate.composed_digest()
        divergent = Command.build(
            command_id="cmd/ig1/settle-divergent",
            command_type=SETTLEMENT_SUBMIT_COMMAND,
            actor="principal/customer-7",
            target_refs=("intent/ig1", "settlement/ig1"),
            payload=self.settle_payload(quoted_target_minor=EXPECTED_TARGET_MINOR + 7),
            environment_id=ENV,
            domain_id=DOMAIN,
            expected_versions=(
                ExpectedVersion(object_ref="intent/ig1", object_version=2),
                ExpectedVersion(object_ref="settlement/ig1", object_version=0),
            ),
            idempotency_key="key/ig1/settle-divergent",
            nonce="n",
            requested_at="2026-09-02T00:20:00Z",
        )
        with self.assertRaises(CoreValidationError) as raised:
            gate.submit(divergent)
        self.assertIn("quoted", str(raised.exception))
        self.assertEqual(gate.composed_digest(), digest_before)

    def test_settlement_rejects_zero_fee_without_state_change(self) -> None:
        # A zero fee would build non-positive legs: the pre-flight leg
        # validation must reject it BEFORE any ledger mutation (the hold
        # release must not have happened).
        gate, _ = self.authorized_gate()
        digest_before = gate.composed_digest()
        zero_fee = Command.build(
            command_id="cmd/ig1/settle-zero-fee",
            command_type=SETTLEMENT_SUBMIT_COMMAND,
            actor="principal/customer-7",
            target_refs=("intent/ig1", "settlement/ig1"),
            payload=self.settle_payload(fee_minor=0),
            environment_id=ENV,
            domain_id=DOMAIN,
            expected_versions=(
                ExpectedVersion(object_ref="intent/ig1", object_version=2),
                ExpectedVersion(object_ref="settlement/ig1", object_version=0),
            ),
            idempotency_key="key/ig1/settle-zero-fee",
            nonce="n",
            requested_at="2026-09-02T00:20:00Z",
        )
        with self.assertRaises(CoreValidationError):
            gate.submit(zero_fee)
        self.assertEqual(gate.composed_digest(), digest_before)
        # the hold must still be active: no partial settlement happened
        state = gate.ledger_state()
        self.assertEqual(state["holds"][0]["envelope"]["state"], HoldState.ACTIVE.value)
        self.assertEqual(
            gate.ledger.derive_balances(account_id=PAYER).encumbered, DEFAULT_SOURCE_MINOR
        )

    def test_authorization_beyond_available_funds_is_rejected(self) -> None:
        gate = standard_gate()
        commands = payment_scenario_commands(
            tag="ig1",
            source_minor=DEFAULT_INITIAL_DEPOSIT_MINOR + 1,
            environment_id=ENV,
            domain_id=DOMAIN,
        )
        gate.submit(commands[0])
        digest_before = gate.composed_digest()
        with self.assertRaises(CoreValidationError) as raised:
            gate.submit(commands[1])
        self.assertIn("reservation safety", str(raised.exception))
        self.assertEqual(gate.composed_digest(), digest_before)

    def test_settlement_without_a_prior_authorization_fails_closed(self) -> None:
        gate = standard_gate()
        commands = payment_scenario_commands(tag="ig1", environment_id=ENV, domain_id=DOMAIN)
        gate.submit(commands[0])
        digest_before = gate.composed_digest()
        unbacked_settlement = Command.build(
            command_id="cmd/ig1/settle-unbacked",
            command_type=SETTLEMENT_SUBMIT_COMMAND,
            actor="principal/customer-7",
            target_refs=("intent/ig1", "settlement/ig1"),
            payload=self.settle_payload(),
            environment_id=ENV,
            domain_id=DOMAIN,
            expected_versions=(
                ExpectedVersion(object_ref="intent/ig1", object_version=1),
                ExpectedVersion(object_ref="settlement/ig1", object_version=0),
            ),
            idempotency_key="key/ig1/settle-unbacked",
            nonce="n",
            requested_at="2026-09-02T00:20:00Z",
        )
        with self.assertRaises(CoreValidationError) as raised:
            gate.submit(unbacked_settlement)
        self.assertIn("unknown hold", str(raised.exception))
        self.assertEqual(gate.composed_digest(), digest_before)

    def test_second_settlement_object_is_rejected_by_version_discipline(self) -> None:
        gate = settled_gate()
        digest_before = gate.composed_digest()
        second = Command.build(
            command_id="cmd/ig1/settle-again",
            command_type=SETTLEMENT_SUBMIT_COMMAND,
            actor="principal/customer-7",
            target_refs=("intent/ig1", "settlement/ig1"),
            payload=self.settle_payload(),
            environment_id=ENV,
            domain_id=DOMAIN,
            expected_versions=(
                ExpectedVersion(object_ref="intent/ig1", object_version=2),
                ExpectedVersion(object_ref="settlement/ig1", object_version=0),
            ),
            idempotency_key="key/ig1/settle-again",
            nonce="n",
            requested_at="2026-09-02T00:40:00Z",
        )
        result = gate.submit(second)
        self.assertEqual(result.outcome, Outcome.REJECTED)
        self.assertEqual(result.reason, RejectionReason.VERSION_CONFLICT)
        self.assertEqual(gate.composed_digest(), digest_before)

    def test_reconciled_journal_rejects_further_postings(self) -> None:
        gate = IntegrationGate(environment_id=ENV, domain_id=DOMAIN)
        gate.provision(initial_deposit_minor=2 * DEFAULT_INITIAL_DEPOSIT_MINOR)
        run_payment_scenario(gate, tag="ig1")
        commands = payment_scenario_commands(tag="ig2", environment_id=ENV, domain_id=DOMAIN)
        accepted = gate.submit(commands[0])
        self.assertEqual(accepted.outcome, Outcome.ACCEPTED)
        with self.assertRaises(CoreValidationError) as raised:
            gate.submit(commands[1])
        self.assertIn("journal", str(raised.exception).lower())
        # the failed authorization left no partial value state behind: the
        # second intent's hold was never published and no new postings were
        # recorded on the sealed journal
        state = gate.ledger_state()
        self.assertEqual(len(state["postings"]), 6)
        self.assertEqual(len(state["holds"]), 1)
        self.assertEqual(state["holds"][0]["envelope"]["state"], HoldState.RELEASED.value)

    def test_settlement_rejects_unknown_target_assets(self) -> None:
        gate, _ = self.authorized_gate()
        digest_before = gate.composed_digest()
        bad_asset = Command.build(
            command_id="cmd/ig1/settle-bad-asset",
            command_type=SETTLEMENT_SUBMIT_COMMAND,
            actor="principal/customer-7",
            target_refs=("intent/ig1", "settlement/ig1"),
            payload=self.settle_payload(target_asset="CHF"),
            environment_id=ENV,
            domain_id=DOMAIN,
            expected_versions=(
                ExpectedVersion(object_ref="intent/ig1", object_version=2),
                ExpectedVersion(object_ref="settlement/ig1", object_version=0),
            ),
            idempotency_key="key/ig1/settle-bad-asset",
            nonce="n",
            requested_at="2026-09-02T00:20:00Z",
        )
        with self.assertRaises(CoreValidationError):
            gate.submit(bad_asset)
        self.assertEqual(gate.composed_digest(), digest_before)


# ---------------------------------------------------------------------------
# 8. The cross-layer invariant battery.
# ---------------------------------------------------------------------------


class InvariantBatteryTests(unittest.TestCase):
    def test_verify_runs_every_declared_check_on_a_settled_gate(self) -> None:
        gate = settled_gate()
        checks = verify_invariants(gate)
        self.assertEqual(
            set(checks),
            {
                "postings-balance-per-asset",
                "journal-trial-balance",
                "balances-match-posting-history",
                "hold-view-reconciliation",
                "asset-sheets-balance",
                "money-conservation",
                "envelope-integrity",
                "journal-payload-integrity",
                "journal-digest-reproducible",
                "scale-authority",
                "trace-consistency",
            },
        )

    def test_verify_after_each_step_passes_on_the_canonical_scenario(self) -> None:
        # submit() runs the battery after every accepted command; the
        # scenario completing without raising is itself the assertion.
        gate = standard_gate()
        run_payment_scenario(gate, tag="ig1")
        verify_invariants(gate)

    def test_postings_balance_rejects_a_tampered_unbalanced_posting(self) -> None:
        gate = settled_gate()
        state = gate.ledger_state()
        state["postings"][3]["payload"]["legs"][0]["amount"]["value"] += 1
        with self.assertRaises(CoreValidationError) as raised:
            invariants.assert_postings_balance(state)
        self.assertIn("debits", str(raised.exception))

    def test_balances_consistency_rejects_divergent_derived_balances(self) -> None:
        gate = settled_gate()
        state = gate.ledger_state()
        derived = {
            account["envelope"]["object_id"]: gate.ledger.derive_balances(
                account_id=account["envelope"]["object_id"]
            ).to_dict()
            for account in state["accounts"]
        }
        invariants.assert_balances_consistent(state, derived)
        derived[PAYER]["available"] += 1
        with self.assertRaises(CoreValidationError) as raised:
            invariants.assert_balances_consistent(state, derived)
        self.assertIn(PAYER, str(raised.exception))

    def test_hold_view_reconciliation_rejects_divergence(self) -> None:
        gate = standard_gate()
        commands = payment_scenario_commands(tag="ig1", environment_id=ENV, domain_id=DOMAIN)
        gate.submit(commands[0])
        gate.submit(commands[1])
        state = gate.ledger_state()
        invariants.assert_hold_view_reconciliation(state)
        state["holds"][0]["payload"]["amount"]["value"] += 1
        with self.assertRaises(CoreValidationError):
            invariants.assert_hold_view_reconciliation(state)

    def test_asset_sheets_reject_a_tampered_position(self) -> None:
        gate = settled_gate()
        state = gate.ledger_state()
        invariants.assert_asset_sheets(state)
        state["postings"][3]["payload"]["legs"][0]["amount"]["value"] += 1
        with self.assertRaises(CoreValidationError) as raised:
            invariants.assert_asset_sheets(state)
        self.assertIn("USD", str(raised.exception))

    def test_money_conservation_rejects_a_non_conserving_conversion(self) -> None:
        gate = settled_gate()
        entries = gate.snapshot()["engine"]["journal"]
        invariants.assert_money_conservation(entries)
        tampered = [dict(entry) for entry in entries]
        payload = dict(tampered[2]["payload"])
        effects = list(payload["effects"])
        effect = dict(effects[0])
        outputs = dict(effect["outputs"])
        conversion = dict(outputs["conversion"])
        conversion["target"] = dict(conversion["target"])
        conversion["target"]["value"] = conversion["target"]["value"] + 1
        outputs["conversion"] = conversion
        effect["outputs"] = outputs
        effects[0] = effect
        payload["effects"] = effects
        tampered[2]["payload"] = payload
        with self.assertRaises(CoreValidationError) as raised:
            invariants.assert_money_conservation(tampered)
        self.assertIn("conversion", str(raised.exception))

    def test_money_conservation_rejects_a_non_conserving_allocation(self) -> None:
        gate = settled_gate()
        entries = gate.snapshot()["engine"]["journal"]
        tampered = [dict(entry) for entry in entries]
        payload = dict(tampered[2]["payload"])
        effects = list(payload["effects"])
        effect = dict(effects[1])
        outputs = dict(effect["outputs"])
        parts = [dict(part) for part in outputs["parts"]]
        parts[0]["value"] = parts[0]["value"] + 1
        outputs["parts"] = parts
        effect["outputs"] = outputs
        effects[1] = effect
        payload["effects"] = effects
        tampered[2]["payload"] = payload
        with self.assertRaises(CoreValidationError) as raised:
            invariants.assert_money_conservation(tampered)
        self.assertIn("allocation", str(raised.exception))

    def test_state_integrity_rejects_a_tampered_ledger_record(self) -> None:
        import json

        gate = settled_gate()
        state = gate.ledger_state()
        invariants.assert_state_integrity(state)
        encoded = canonical_json(state["postings"][3])
        tampered = encoded.replace('"value":1250050', '"value":1250051')
        if encoded == tampered:
            self.fail("tamper target not present in the fixture posting")
        state["postings"][3] = json.loads(tampered)
        with self.assertRaises(CoreValidationError):
            invariants.assert_state_integrity(state)

    def test_journal_payload_integrity_rejects_a_tampered_entry(self) -> None:
        gate = settled_gate()
        engine_state = gate.snapshot()["engine"]
        invariants.assert_journal_integrity(engine_state)
        tampered = dict(engine_state)
        journal = [dict(entry) for entry in engine_state["journal"]]
        payload = dict(journal[2]["payload"])
        payload["summary"] = {"forged": True}
        journal[2]["payload"] = payload
        tampered["journal"] = journal
        with self.assertRaises(CoreValidationError) as raised:
            invariants.assert_journal_integrity(tampered)
        self.assertIn("payload hash", str(raised.exception))

    def test_journal_digest_is_reproducible_across_the_round_trip(self) -> None:
        gate = settled_gate()
        digest = gate.journal_digest()
        self.assertEqual(gate.journal_digest(), digest)
        rebuilt = replay_from_journal(gate.snapshot())
        self.assertEqual(rebuilt.journal_digest(), digest)

    def test_scale_authority_rejects_a_non_canonical_scale(self) -> None:
        gate = settled_gate()
        state = gate.ledger_state()
        invariants.assert_scale_authority(state)
        state["assets"][0]["payload"]["scale"] = 3
        with self.assertRaises(CoreValidationError):
            invariants.assert_scale_authority(state)

    def test_trace_consistency_rejects_amount_divergence(self) -> None:
        gate = settled_gate()
        entries = gate.snapshot()["engine"]["journal"]
        invariants.assert_trace_consistency(entries)
        tampered = [dict(entry) for entry in entries]
        payload = dict(tampered[1]["payload"])
        terms = dict(payload["terms"])
        terms["source_amount"] = DEFAULT_SOURCE_MINOR + 1
        payload["terms"] = terms
        tampered[1]["payload"] = payload
        with self.assertRaises(CoreValidationError) as raised:
            invariants.assert_trace_consistency(tampered)
        self.assertIn("source_amount", str(raised.exception))


# ---------------------------------------------------------------------------
# 9. Deterministic replay and transformation completeness.
# ---------------------------------------------------------------------------


class ReplayTransformationTests(unittest.TestCase):
    def test_snapshot_is_a_canonical_byte_stable_projection(self) -> None:
        gate = settled_gate()
        first = canonical_json(gate.snapshot())
        second = canonical_json(gate.snapshot())
        self.assertEqual(first, second)
        self.assertEqual(
            set(gate.snapshot()),
            {
                "schema_version",
                "gate_id",
                "environment_id",
                "domain_id",
                "authorized_actors",
                "provisioning",
                "engine",
                "store",
                "ledger",
            },
        )

    def test_journal_driven_replay_rebuilds_the_composed_state_identically(self) -> None:
        gate = settled_gate()
        rebuilt = replay_from_journal(gate.snapshot())
        assert_replay_equivalence(gate, rebuilt)

    def test_replay_preserves_every_ledger_digest_exactly(self) -> None:
        gate = settled_gate()
        rebuilt = replay_from_journal(gate.snapshot())
        self.assertEqual(rebuilt.ledger_digest(), gate.ledger_digest())
        self.assertEqual(rebuilt.kernel_digest(), gate.kernel_digest())
        self.assertEqual(rebuilt.composed_digest(), gate.composed_digest())
        original_state = gate.ledger_state()
        rebuilt_state = rebuilt.ledger_state()
        self.assertEqual(set(original_state), set(rebuilt_state))
        for key in original_state:
            self.assertEqual(
                canonical_json(original_state[key]), canonical_json(rebuilt_state[key]), key
            )

    def test_replay_kernel_store_is_rebuilt_from_journal_records(self) -> None:
        gate = settled_gate()
        rebuilt = replay_from_journal(gate.snapshot())
        self.assertEqual(
            [envelope.to_dict() for envelope in rebuilt.store.snapshot()],
            [envelope.to_dict() for envelope in gate.store.snapshot()],
        )
        self.assertEqual(rebuilt.current_version("intent/ig1"), 3)
        self.assertEqual(rebuilt.current_version("settlement/ig1"), 2)

    def test_rebuilt_gate_keeps_deduplicating_replayed_commands(self) -> None:
        gate = settled_gate()
        rebuilt = replay_from_journal(gate.snapshot())
        commands = payment_scenario_commands(tag="ig1", environment_id=ENV, domain_id=DOMAIN)
        outcomes = [rebuilt.submit(command).outcome for command in commands]
        self.assertEqual(outcomes, [Outcome.DUPLICATE] * 4)
        self.assertEqual(len(rebuilt.engine.journal), 4)
        self.assertEqual(rebuilt.composed_digest(), gate.composed_digest())

    def test_rebuilt_gate_invariants_pass(self) -> None:
        gate = settled_gate()
        rebuilt = replay_from_journal(gate.snapshot())
        self.assertEqual(verify_invariants(rebuilt), verify_invariants(gate))

    def test_replay_fails_closed_on_a_tampered_journal_payload(self) -> None:
        gate = settled_gate()
        snapshot = gate.snapshot()
        engine_state = dict(snapshot["engine"])
        journal = [dict(entry) for entry in engine_state["journal"]]
        payload = dict(journal[2]["payload"])
        effects = list(payload["effects"])
        effect = dict(effects[3])
        inputs = dict(effect["inputs"])
        inputs["description"] = "forged fx source description"
        effect["inputs"] = inputs
        effects[3] = effect
        payload["effects"] = effects
        journal[2]["payload"] = payload
        engine_state["journal"] = journal
        snapshot = dict(snapshot)
        snapshot["engine"] = engine_state
        with self.assertRaises(CoreValidationError) as raised:
            replay_from_journal(snapshot)
        self.assertIn("divergence", str(raised.exception))

    def test_replay_fails_closed_on_a_tampered_recorded_output(self) -> None:
        gate = settled_gate()
        snapshot = gate.snapshot()
        engine_state = dict(snapshot["engine"])
        journal = [dict(entry) for entry in engine_state["journal"]]
        payload = dict(journal[2]["payload"])
        effects = list(payload["effects"])
        effect = dict(effects[3])
        outputs = dict(effect["outputs"])
        posting = dict(outputs["posting"])
        posting["object_id"] = "value/journal/ig1/p999999"
        outputs["posting"] = posting
        effect["outputs"] = outputs
        effects[3] = effect
        payload["effects"] = effects
        journal[2]["payload"] = payload
        engine_state["journal"] = journal
        snapshot = dict(snapshot)
        snapshot["engine"] = engine_state
        with self.assertRaises(CoreValidationError):
            replay_from_journal(snapshot)

    def test_snapshot_round_trip_through_json_is_lossless(self) -> None:
        import json

        gate = settled_gate()
        snapshot = gate.snapshot()
        encoded = canonical_json(snapshot)
        decoded = json.loads(encoded)
        self.assertEqual(canonical_json(decoded), encoded)
        rebuilt = replay_from_journal(decoded)
        assert_replay_equivalence(gate, rebuilt)

    def test_replay_of_a_scaled_scenario_is_identical(self) -> None:
        gate = IntegrationGate(environment_id=ENV, domain_id=DOMAIN)
        gate.provision(initial_deposit_minor=3 * (DEFAULT_SOURCE_MINOR + DEFAULT_FEE_MINOR))
        run_scaled_scenario(gate, count=3)
        rebuilt = replay_from_journal(gate.snapshot())
        assert_replay_equivalence(gate, rebuilt)


# ---------------------------------------------------------------------------
# 10. Quality attribute (measured, honest).
# ---------------------------------------------------------------------------


class QualityAttributeTests(unittest.TestCase):
    SCALED_INTENTS = 40

    def test_scaled_scenario_replay_and_snapshot_cost_is_measured_and_bounded(self) -> None:
        deposit = self.SCALED_INTENTS * (DEFAULT_SOURCE_MINOR + DEFAULT_FEE_MINOR)
        start = time.process_time()
        gate = IntegrationGate(environment_id=ENV, domain_id=DOMAIN)
        gate.provision(initial_deposit_minor=deposit)
        summary = run_scaled_scenario(gate, count=self.SCALED_INTENTS)
        scenario_cpu = time.process_time() - start
        start = time.process_time()
        rebuilt = replay_from_journal(gate.snapshot())
        replay_cpu = time.process_time() - start
        start = time.process_time()
        snapshot_json = canonical_json(gate.snapshot())
        snapshot_cpu = time.process_time() - start
        # Determinism is asserted by digest equality (timing is reported,
        # not asserted, beyond a generous regression tripwire).
        assert_replay_equivalence(gate, rebuilt)
        self.assertEqual(summary["intents"], self.SCALED_INTENTS)
        self.assertEqual(summary["journal_entries"], 3 * self.SCALED_INTENTS + 1)
        self.assertGreater(len(snapshot_json), 1000)
        self.assertLess(scenario_cpu, 120.0)
        self.assertLess(replay_cpu, 120.0)
        self.assertLess(snapshot_cpu, 60.0)

    def test_digest_verification_overhead_is_measured_and_bounded(self) -> None:
        gate = settled_gate()
        start = time.process_time()
        for _ in range(20):
            verify_invariants(gate)
        verification_cpu = time.process_time() - start
        self.assertLess(verification_cpu, 60.0)
        self.assertGreater(verification_cpu, 0.0)


# ---------------------------------------------------------------------------
# 11. DOGFOOD-026 conformance.
# ---------------------------------------------------------------------------


class DogfoodingTests(unittest.TestCase):
    def test_transcript_is_deterministic_with_a_stable_digest(self) -> None:
        transcript_a, digest_a = build_transcript()
        transcript_b, digest_b = build_transcript()
        self.assertEqual(transcript_a, transcript_b)
        self.assertEqual(digest_a, digest_b)
        self.assertEqual(digest_a, canonical_sha256({"transcript": transcript_a}))

    def test_transcript_covers_the_full_lifecycle_and_replay(self) -> None:
        transcript, _ = build_transcript()
        self.assertIn("work order: WORK-026", transcript)
        self.assertIn("gate: IG-001", transcript)
        self.assertIn("intent.create", transcript)
        self.assertIn("intent.authorize", transcript)
        self.assertIn("settlement.submit", transcript)
        self.assertIn("settlement.reconcile", transcript)
        self.assertIn("residual=-5000/10000", transcript)
        self.assertIn("classification: DOGFOOD-026: PASS", transcript)
        self.assertTrue(transcript.endswith("classification: DOGFOOD-026: PASS\n"))
        self.assertIn("ledger_digest_rebuilt", transcript)
        self.assertIn("identical", transcript)

    def test_transcript_reports_every_invariant_check(self) -> None:
        transcript, _ = build_transcript()
        for check in (
            "postings-balance-per-asset",
            "balances-match-posting-history",
            "money-conservation",
            "envelope-integrity",
            "journal-payload-integrity",
            "journal-digest-reproducible",
            "trace-consistency",
        ):
            self.assertIn(check, transcript)

    def test_main_prints_the_transcript(self) -> None:
        import contextlib
        import io

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            main()
        transcript, _ = build_transcript()
        self.assertEqual(buffer.getvalue(), transcript)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
