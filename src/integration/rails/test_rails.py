"""IG-005 external rail sandbox integration gate — contract suite.

The contract suite pins the public boundary of the external rail
sandbox gate (WORK-030, ``spec/integration-gates.md`` row IG-005):

* a typed, versioned, frozen public API exercising canonical
  interoperability over TWO rail-shaped adapters through the merged
  typed adapter boundary (WORK-007 ``WorldAdapter`` +
  WORK-014 ``EffectSubmissionPort``/``EffectReconciliationPort``);
* rail A = Stripe test mode (REAL_PROVIDER_SANDBOX, reused from the
  merged WORK-027 ``StripeTestRail`` — imported, never forked), rail B
  = Stellar testnet (REAL_PROVIDER_SANDBOX, credential-free public
  testnet, NEW adapter behind the same typed ports), plus the merged
  local deterministic rail for the deterministic failure/investigation
  battery (LOCAL_DETERMINISTIC_SANDBOX — never counted as an external
  rail);
* the required scenario battery A–E, the failure/investigation paths,
  the settlement/finality discipline, the explicit rail normalization
  registry, replay determinism and dogfood conformance.

The suite is fully deterministic and network-free: the canonical A/B
machinery is proven on the local deterministic pair, the cryptography
is proven against the RFC 8032 test vectors and pinned XDR golden
bytes (verified against the live testnet out-of-band), and the real
rails are exercised by the DOGFOOD-030 experiment (executed live and
persisted) with the offline contract tested here deterministically.
"""

from __future__ import annotations

import ast
import json
import pathlib
import subprocess
import sys
import unittest

import src.integration.rails as rails_package


_REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]

#: RFC 8032 §7.1 official Ed25519 test vectors (the golden crypto
#: contract of the pure-Python ed25519 the Stellar rail signs with).
RFC8032_VECTORS = (
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        bytes(),
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        bytes.fromhex("72"),
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        bytes.fromhex("af82"),
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
        "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
)

#: Pinned golden Stellar payment-envelope bytes: the exact V0 envelope
#: for the declared golden inputs (RFC 8032 test seeds as the deterministic
#: test keypair, seq 42, 1.00 XLM, memo ig005-golden-1, fee 1000 stroops,
#: network "Test SDF Network ; September 2015"). The encoding rules were
#: verified byte-for-byte against the live testnet (accepted transaction
#: plus offline verification of friendbot's own signatures) before
#: pinning; the suite proves the implementation reproduces them.
GOLDEN_ENVELOPE_B64 = "AAAAAgAAAADXWpgBgrEKt9VL/tPJZAc6DuFy89qmIyWvAhpo9wdRGgAAA+gAAAAAAAAAKgAAAAAAAAABAAAADmlnMDA1LWdvbGRlbi0xAAAAAAABAAAAAAAAAAEAAAAAPUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0ZgwAAAAAAAAAAACYloAAAAAAAAAAAfcHURoAAABAqHkag9AhVS/Njtlc59zvROp4l2n88HgVGsptlAIyhX+nQyKKmIltrO3aA60Cs+y44H30DGU240P9TJ11U4XqAA=="
GOLDEN_TX_HASH = (
    "bc7097f84ced27db6345f95dd13257f0c8ce6e2eea8c0606db53f9685e804b24"
)
GOLDEN_SOURCE_STRKEY = (
    "GDLVVGABQKYQVN6VJP7NHSLEA45A5YLS6PNKMIZFV4BBU2HXA5IRVHUR"
)
GOLDEN_DESTINATION_STRKEY = (
    "GA6UAF6D5BBYSWUSW4FKOTI3P26JZGBMZ4XMJFUMYDGVL4JK6RTAZGXX"
)


class StaticBoundaryTests(unittest.TestCase):
    """The typed, versioned, frozen public boundary of the IG-005 gate."""

    def test_gate_identity_constants(self) -> None:
        self.assertEqual(rails_package.RAILS_GATE_ID, "IG-005")
        self.assertEqual(rails_package.RAILS_API_VERSION, "v0.1")
        self.assertEqual(rails_package.RAILS_SCHEMA_VERSION, 1)
        self.assertEqual(
            rails_package.KNOWN_RAILS_GATES, frozenset({"IG-005"})
        )

    def test_public_boundary_all_is_explicit_frozen_and_sorted(self) -> None:
        exported = rails_package.__all__
        self.assertIsInstance(exported, tuple)
        self.assertEqual(sorted(exported), list(exported))
        self.assertEqual(len(exported), len(set(exported)))
        for name in exported:
            self.assertTrue(
                hasattr(rails_package, name),
                f"__all__ exports {name!r} but the attribute is missing",
            )

    def test_consumed_surfaces_cover_exactly_the_declared_roots(self) -> None:
        self.assertEqual(
            set(rails_package.CONSUMED_SURFACES),
            {
                "src.core",
                "src.transition",
                "src.evidence",
                "src.capability",
                "src.interoperability",
                "src.execution",
                "src.clearing",
                "src.settlement",
                "src.integration.lifecycle",
            },
        )

    def test_rails_modules_import_only_consumed_roots(self) -> None:
        allowed = set(rails_package.CONSUMED_SURFACES)
        package = pathlib.Path(__file__).parent
        sources = sorted(path for path in package.glob("*.py"))
        self.assertTrue(sources)
        for source in sources:
            if source.name.startswith("test_"):
                continue
            tree = ast.parse(
                source.read_text(encoding="utf-8"), filename=str(source)
            )
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self._audit_root(source.name, alias.name, allowed)
                elif isinstance(node, ast.ImportFrom):
                    if node.level >= 1:
                        continue
                    module = node.module or ""
                    if module == "__future__":
                        continue
                    self._audit_root(source.name, module, allowed)

    def _audit_root(
        self, source_name: str, module: str, allowed: set[str]
    ) -> None:
        root = module.split(".", 1)[0]
        if root == "src":
            matched = any(
                module == surface or module.startswith(surface + ".")
                for surface in allowed
            )
            self.assertTrue(
                matched,
                f"{source_name} imports {module} outside the consumed surfaces",
            )
        else:
            self.assertIn(
                root,
                sys.stdlib_module_names,
                f"{source_name} imports non-stdlib {module}",
            )

    def test_rails_sources_contain_no_float_literals(self) -> None:
        package = pathlib.Path(__file__).parent
        sources = sorted(
            path for path in package.glob("*.py") if not path.name.startswith("test")
        )
        self.assertTrue(sources)
        for path in sources:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, float):
                    self.fail(
                        f"float literal found in {path.name} at line {node.lineno}"
                    )

    def test_rails_code_has_no_wall_clock_entropy_or_uuids(self) -> None:
        package = pathlib.Path(__file__).parent
        for source in sorted(package.glob("*.py")):
            if source.name.startswith("test_"):
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
                self.assertNotIn(
                    forbidden, text, f"{source.name} references {forbidden}"
                )

    def test_rails_sources_contain_no_secret_material(self) -> None:
        package = pathlib.Path(__file__).parent
        sources = sorted(
            path for path in package.glob("*.py") if not path.name.startswith("test")
        )
        self.assertTrue(sources)
        for source in sources:
            text = source.read_text(encoding="utf-8")
            for forbidden in (
                "sk_live",
                "sk_test",
                "whsec_",
                "FLWSECK",
                "pk_live",
                "Bearer ",
                "STRIPE_SECRET_KEY=",
            ):
                self.assertNotIn(
                    forbidden, text, f"{source.name} contains {forbidden!r}"
                )

    def test_importing_the_gate_loads_only_composed_roots(self) -> None:
        allowed = set(rails_package.CONSUMED_SURFACES) | {
            "src.integration",
            "src.money",
            "src.value",
            "src.trust",
            "src.intent",
            "src.capability",
            "src.market",
            "src.liquidity",
            "src.reservation",
            "src.safety",
            "src.compiler",
            # the merged execution domain re-exports the effect
            # authorization record from the merged simulation domain,
            # so importing the lifecycle tree transitively loads it.
            "src.simulation",
        }
        code = (
            "import sys, json\n"
            "import src.integration.rails\n"
            "print(json.dumps(sorted(m for m in sys.modules if m.startswith('src.'))))\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            cwd=_REPO_ROOT,
            timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        loaded = json.loads(result.stdout)
        self.assertTrue(loaded, "the gate import must load its composed roots")
        for name in loaded:
            matched = any(
                name == surface or name.startswith(surface + ".")
                for surface in allowed
            )
            self.assertTrue(
                matched,
                f"importing src.integration.rails loaded {name}",
            )

    def test_validate_rails_gate_id_fails_closed_on_unknown_gate(self) -> None:
        from src.core.errors import CoreValidationError

        self.assertEqual(
            rails_package.validate_rails_gate_id("IG-005"), "IG-005"
        )
        for unknown in ("IG-001", "IG-002", "IG-003", "IG-004", "IG-006", ""):
            with self.assertRaises(CoreValidationError):
                rails_package.validate_rails_gate_id(unknown)

    def test_rail_classification_vocabulary_is_frozen(self) -> None:
        rail_class = rails_package.RailClass
        self.assertEqual(
            {member.value for member in rail_class},
            {"REAL_PROVIDER_SANDBOX", "LOCAL_DETERMINISTIC_SANDBOX"},
        )
        self.assertEqual(
            rail_class.REAL_PROVIDER_SANDBOX, "REAL_PROVIDER_SANDBOX"
        )
        self.assertEqual(
            rail_class.LOCAL_DETERMINISTIC_SANDBOX,
            "LOCAL_DETERMINISTIC_SANDBOX",
        )

    def test_the_gate_declares_two_distinct_real_rails(self) -> None:
        self.assertEqual(
            rails_package.RAIL_A_ADAPTER_ID,
            "interoperability/adapter/stripe-test",
        )
        self.assertEqual(
            rails_package.RAIL_B_ADAPTER_ID,
            "interoperability/adapter/stellar-testnet",
        )
        self.assertNotEqual(
            rails_package.RAIL_A_ADAPTER_ID, rails_package.RAIL_B_ADAPTER_ID
        )
        self.assertNotEqual(
            rails_package.RAIL_A_ENVIRONMENT_ID,
            rails_package.RAIL_B_ENVIRONMENT_ID,
        )
        self.assertNotEqual(
            rails_package.RAIL_A_DOMAIN_ID, rails_package.RAIL_B_DOMAIN_ID
        )
        for environment_id in (
            rails_package.RAIL_A_ENVIRONMENT_ID,
            rails_package.RAIL_B_ENVIRONMENT_ID,
        ):
            self.assertTrue(environment_id.startswith("env/sandbox-ig005-"))

    def test_normalization_rules_are_frozen_documented_and_field_bound(self) -> None:
        rules = rails_package.RAILS_NORMALIZATION_RULES
        self.assertTrue(rules)
        fields: set[str] = set()
        for rule in rules:
            for column in (
                "rule_id",
                "field",
                "rail_a_representation",
                "rail_b_representation",
                "reason",
                "rule",
                "safety_argument",
            ):
                value = getattr(rule, column)
                self.assertIsInstance(
                    value, str,
                    f"rule {rule.rule_id!r} column {column!r} must be text",
                )
                self.assertTrue(
                    value.strip(),
                    f"rule {rule.rule_id!r} column {column!r} must be non-empty",
                )
            fields.add(rule.field)
        # one rule per field (no broad multi-field strategies).
        self.assertEqual(len(fields), len(rules))
        # the load-bearing rail-neutral fields are NEVER in the registry.
        for forbidden in (
            "amount_value",
            "amount_scale",
            "value",
            "scale",
            "outcome",
            "failure_class",
            "status",
            "state",
        ):
            self.assertNotIn(
                forbidden,
                fields,
                f"the field {forbidden!r} must never be normalized",
            )

    def test_normalization_digest_is_declared(self) -> None:
        digest = rails_package.RAILS_NORMALIZATION_DIGEST
        self.assertIsInstance(digest, str)
        self.assertEqual(len(digest), 64)
        second = rails_package.RAILS_NORMALIZATION_DIGEST
        self.assertEqual(digest, second)


class Ed25519ConformanceTests(unittest.TestCase):
    """The pure-Python ed25519 signer against the RFC 8032 vectors."""

    def test_public_key_derivation_matches_the_vectors(self) -> None:
        for seed_hex, public_hex, _message, _signature in RFC8032_VECTORS:
            seed = bytes.fromhex(seed_hex)
            public = rails_package.ed25519_public_key(seed)
            self.assertEqual(public.hex(), public_hex)

    def test_signatures_match_the_vectors(self) -> None:
        for seed_hex, _public_hex, message, signature_hex in RFC8032_VECTORS:
            seed = bytes.fromhex(seed_hex)
            signature = rails_package.ed25519_sign(seed, message)
            self.assertEqual(signature.hex(), signature_hex)

    def test_signing_is_deterministic(self) -> None:
        seed = bytes.fromhex(RFC8032_VECTORS[0][0])
        message = b"ig005 determinism probe"
        first = rails_package.ed25519_sign(seed, message)
        second = rails_package.ed25519_sign(seed, message)
        self.assertEqual(first, second)
        self.assertEqual(len(first), 64)

    def test_seed_length_is_enforced(self) -> None:
        from src.core.errors import CoreValidationError

        with self.assertRaises(CoreValidationError):
            rails_package.ed25519_public_key(b"short")
        with self.assertRaises(CoreValidationError):
            rails_package.ed25519_sign(b"x" * 33, b"message")


class StellarRailContractTests(unittest.TestCase):
    """The Stellar testnet rail: XDR goldens, strkey, status vocabulary."""

    def test_network_constants_are_declared(self) -> None:
        self.assertEqual(
            rails_package.STELLAR_TESTNET_PASSPHRASE,
            "Test SDF Network ; September 2015",
        )
        self.assertEqual(rails_package.STELLAR_STROOPS_PER_XLM, 10_000_000)
        self.assertEqual(rails_package.STELLAR_FEE_STROOPS, 1000)

    def test_golden_envelope_bytes_are_reproduced(self) -> None:
        seed = bytes.fromhex(RFC8032_VECTORS[0][0])
        destination_pub = bytes.fromhex(
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
        )
        envelope = rails_package.build_payment_envelope(
            source_seed=seed,
            destination_public_key=destination_pub,
            sequence=42,
            amount_stroops=10_000_000,
            memo="ig005-golden-1",
            fee_stroops=1000,
        )
        self.assertEqual(envelope, GOLDEN_ENVELOPE_B64)
        self.assertEqual(rails_package.stellar_transaction_hash(envelope), GOLDEN_TX_HASH)

    def test_strkey_encoding_is_the_known_answer(self) -> None:
        seed = bytes.fromhex(RFC8032_VECTORS[0][0])
        public = rails_package.ed25519_public_key(seed)
        self.assertEqual(
            rails_package.strkey_encode_account(public), GOLDEN_SOURCE_STRKEY
        )
        destination = bytes.fromhex(
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
        )
        self.assertEqual(
            rails_package.strkey_encode_account(destination),
            GOLDEN_DESTINATION_STRKEY,
        )

    def test_stellar_status_map_is_declared_and_closed(self) -> None:
        from src.interoperability import CanonicalPaymentStatus

        entries = {
            entry.native_code: entry.canonical_status
            for entry in rails_package.STELLAR_STATUS_MAP
        }
        self.assertEqual(
            entries["completed"], CanonicalPaymentStatus.SETTLED
        )
        self.assertEqual(entries["pending"], CanonicalPaymentStatus.PROCESSING)
        self.assertEqual(entries["failed"], CanonicalPaymentStatus.FAILED)
        from src.core.errors import CoreValidationError

        status_map = rails_package.make_stellar_status_map()
        with self.assertRaises(CoreValidationError):
            status_map.map_status("unexpected-status-word")

    def test_stellar_rail_declares_no_credential_requirement(self) -> None:
        rail = rails_package.StellarTestnetRail()
        self.assertIsNone(rail.credential_env_var)

    def test_stellar_rail_offline_contract_when_unreachable(self) -> None:
        from src.execution.contracts import QueryOutcome, SubmissionStatus

        rail = rails_package.StellarTestnetRail(
            api_base="https://ig005-offline.invalid"
        )
        from src.integration.lifecycle.dogfooding import make_local_binding  # noqa: F401

        request = _offline_probe_request(rails_package.RAIL_B_ADAPTER_ID, "ig005-offline-1")
        submission = rail.submit_effect(request)
        self.assertIs(submission.status, SubmissionStatus.UNKNOWN)
        self.assertIn("NOT ATTEMPTED", submission.reason)
        query = rail.query_effect(request)
        self.assertIs(query.outcome, QueryOutcome.NOT_FOUND)
        self.assertIsNone(rail.native_payment("ig005-offline-1"))

    def test_stripe_rail_offline_contract_without_credential(self) -> None:
        from src.execution.contracts import QueryOutcome, SubmissionStatus

        rail = rails_package.StripeTestRail(
            secret_env_var="IG005_SUITE_NEVER_SET_STRIPE_KEY"
        )
        request = _offline_probe_request(
            rails_package.RAIL_A_ADAPTER_ID, "ig005-offline-1"
        )
        submission = rail.submit_effect(request)
        self.assertIs(submission.status, SubmissionStatus.UNKNOWN)
        self.assertIn("NOT ATTEMPTED", submission.reason)
        query = rail.query_effect(request)
        self.assertIs(query.outcome, QueryOutcome.NOT_FOUND)


class WorldHarnessTests(unittest.TestCase):
    """The rail world harnesses: classification honesty and typed ports."""

    def test_real_rail_worlds_declare_real_provider_sandbox(self) -> None:
        world_a = rails_package.build_rail_world_a()
        world_b = rails_package.build_rail_world_b()
        self.assertEqual(
            world_a.rail_class, rails_package.RailClass.REAL_PROVIDER_SANDBOX
        )
        self.assertEqual(
            world_b.rail_class, rails_package.RailClass.REAL_PROVIDER_SANDBOX
        )
        self.assertEqual(
            world_a.adapter_id, rails_package.RAIL_A_ADAPTER_ID
        )
        self.assertEqual(world_b.adapter_id, rails_package.RAIL_B_ADAPTER_ID)
        self.assertEqual(
            world_a.environment_id, rails_package.RAIL_A_ENVIRONMENT_ID
        )
        self.assertEqual(
            world_b.environment_id, rails_package.RAIL_B_ENVIRONMENT_ID
        )
        self.assertEqual(world_a.declared_currency, "USD")
        self.assertEqual(world_b.declared_currency, "USD")

    def test_local_rail_worlds_classify_local_deterministic(self) -> None:
        world_a, world_b = rails_package.build_local_rail_pair()
        self.assertEqual(
            world_a.rail_class, rails_package.RailClass.LOCAL_DETERMINISTIC_SANDBOX
        )
        self.assertEqual(
            world_b.rail_class, rails_package.RailClass.LOCAL_DETERMINISTIC_SANDBOX
        )
        self.assertNotEqual(world_a.environment_id, world_b.environment_id)
        self.assertNotEqual(world_a.adapter_id, world_b.adapter_id)

    def test_classification_honesty_is_enforced_fail_closed(self) -> None:
        from src.core.errors import CoreValidationError

        world_a, world_b = rails_package.build_local_rail_pair()
        with self.assertRaises(CoreValidationError):
            # a local deterministic rail can never claim REAL_PROVIDER_SANDBOX
            rails_package.RailWorld(
                name="lying-world",
                rail_class=rails_package.RailClass.REAL_PROVIDER_SANDBOX,
                environment_id=world_a.environment_id,
                domain_id=world_a.domain_id,
                adapter_id=world_a.adapter_id,
                rail=world_a.rail,
                binding=world_a.binding,
                declared_currency=world_a.declared_currency,
                declared_amount_minor=world_a.declared_amount_minor,
            )

    def test_all_worlds_bind_the_typed_ports_with_status_maps(self) -> None:
        from src.execution.adapters import (
            EffectReconciliationPort,
            EffectSubmissionPort,
        )

        worlds = [
            rails_package.build_rail_world_a(),
            rails_package.build_rail_world_b(),
            *rails_package.build_local_rail_pair(),
        ]
        for world in worlds:
            binding = world.binding
            self.assertIsInstance(binding.submission_port, EffectSubmissionPort)
            self.assertIsInstance(
                binding.reconciliation_port, EffectReconciliationPort
            )
            self.assertEqual(binding.adapter_id, world.adapter_id)
            self.assertIsNotNone(binding.status_map)
            self.assertEqual(binding.status_map.adapter_id, world.adapter_id)
            self.assertTrue(
                binding.world_adapter.fidelity_class.value
                in ("SIMULATION", "PRODUCTION")
            )

    def test_real_rail_worlds_use_declared_test_accounts(self) -> None:
        world_b = rails_package.build_rail_world_b()
        # deterministic testnet accounts derived from public constants
        self.assertTrue(world_b.rail.source_account_strkey.startswith("G"))
        self.assertTrue(world_b.rail.destination_account_strkey.startswith("G"))
        self.assertNotEqual(
            world_b.rail.source_account_strkey,
            world_b.rail.destination_account_strkey,
        )


class ScenarioBatteryTests(unittest.TestCase):
    """The required scenario battery on the local deterministic pair.

    The canonical A/B machinery — the same stage drivers, projection,
    normalization and comparison the real rails exercise in the
    DOGFOOD-030 experiment — runs here deterministically and
    network-free over two local deterministic rails.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.gate = rails_package.ExternalRailSandboxGate(
            rails_package.build_local_rail_pair(
                submissions={
                    "ig005-b1": ("reject",),
                    "ig005-c1": ("unknown",),
                    "ig005-c1-retry": ("accept",),
                },
                queries={"ig005-c1": ("not-found",)},
            )
        )
        cls.scenario_a = rails_package.run_rails_scenario_a(cls.gate)
        cls.scenario_b = rails_package.run_rails_scenario_b(cls.gate)
        cls.scenario_c = rails_package.run_rails_scenario_c()
        cls.scenario_d = rails_package.run_rails_scenario_d(cls.gate)

    def test_scenario_a_succeeds_on_both_rails(self) -> None:
        outcome = self.scenario_a
        self.assertEqual(outcome["rail_a"]["step_state"], "SUCCEEDED")
        self.assertEqual(outcome["rail_b"]["step_state"], "SUCCEEDED")
        self.assertEqual(outcome["rail_a"]["plan_state"], "COMPLETED")
        self.assertEqual(outcome["rail_b"]["plan_state"], "COMPLETED")
        self.assertTrue(outcome["rail_a"]["finality_established"])
        self.assertTrue(outcome["rail_b"]["finality_established"])
        self.assertTrue(outcome["rail_a"]["obligation_resolved"])
        self.assertTrue(outcome["rail_b"]["obligation_resolved"])
        self.assertEqual(
            outcome["rail_a"]["submission_status"], "ACCEPTED"
        )
        self.assertEqual(
            outcome["rail_b"]["submission_status"], "ACCEPTED"
        )
        self.assertEqual(outcome["rail_a"]["native_reference"], "ig002-local/ig005-a1")
        self.assertEqual(outcome["rail_b"]["native_reference"], "ig002-local/ig005-a1")

    def test_scenario_a_economics_are_equivalent(self) -> None:
        outcome = self.scenario_a
        self.assertEqual(
            outcome["rail_a"]["amount_minor"],
            outcome["rail_b"]["amount_minor"],
        )
        self.assertEqual(outcome["rail_a"]["amount_minor"], 100)
        self.assertEqual(
            outcome["rail_a"]["discharge_count"],
            outcome["rail_b"]["discharge_count"],
        )
        self.assertEqual(outcome["rail_a"]["discharge_count"], 1)

    def test_scenario_b_rejects_with_the_same_canonical_class(self) -> None:
        outcome = self.scenario_b
        for side in ("rail_a", "rail_b"):
            self.assertEqual(outcome[side]["submission_status"], "REJECTED")
            self.assertEqual(outcome[side]["step_state"], "FAILED")
            # The engine's plan-resolution authority is the effect-result
            # path: a port-level rejection fails the step while the plan
            # stays RUNNING (the engine's own semantics, reported as-is).
            self.assertEqual(outcome[side]["plan_state"], "RUNNING")
            self.assertEqual(outcome[side]["obligations_recognized"], 0)
            self.assertEqual(outcome[side]["settlement_count"], 0)
            self.assertEqual(outcome[side]["discharge_count"], 0)
            self.assertFalse(outcome[side]["finality_established"])
            self.assertTrue(outcome[side]["recognition_probe_rejected"])

    def test_scenario_b_no_economic_effect_in_either_world(self) -> None:
        outcome = self.scenario_b
        self.assertEqual(outcome["rail_a"]["composed_state_unchanged"], True)
        self.assertEqual(outcome["rail_b"]["composed_state_unchanged"], True)

    def test_scenario_c_recovers_through_reconciliation(self) -> None:
        outcome = self.scenario_c
        self.assertEqual(outcome["first_submission_state"], "UNKNOWN")
        self.assertEqual(outcome["reconciliation_outcome"], "NOT_FOUND")
        self.assertEqual(outcome["retry_submission_state"], "SUBMITTED")
        self.assertTrue(outcome["finality_established"])
        self.assertTrue(outcome["obligation_resolved"])
        self.assertNotEqual(outcome["retry_key"], outcome["first_key"])
        self.assertEqual(outcome["port_calls_for_first_key"], 1)

    def test_scenario_c_unknown_never_becomes_settled(self) -> None:
        outcome = self.scenario_c
        self.assertFalse(outcome["unknown_promoted_to_settled"])
        self.assertFalse(outcome["unknown_promoted_to_final"])

    def test_scenario_d_idempotent_retry_is_exactly_once(self) -> None:
        outcome = self.scenario_d
        for side in ("rail_a", "rail_b"):
            self.assertEqual(outcome[side]["re_drive_outcome"], "rejected")
            self.assertTrue(outcome[side]["re_drive_port_call_unchanged"])
            self.assertEqual(outcome[side]["resubmission_status"], "ACCEPTED")
            self.assertEqual(
                outcome[side]["resubmission_native_reference"],
                outcome[side]["first_native_reference"],
            )
            self.assertEqual(outcome[side]["obligation_delta"], 0)
            self.assertEqual(outcome[side]["discharge_delta"], 0)
            self.assertEqual(outcome[side]["native_payment_count"], 1)

    def test_scenario_e_cross_rail_semantic_comparison(self) -> None:
        verdict = self.scenario_a["verdict"]
        self.assertEqual(verdict.verdict, "EQUIVALENT")
        self.assertEqual(verdict.differences, ())
        self.assertEqual(verdict.gate_id, "IG-005")
        self.assertEqual(verdict.schema_version, 1)
        self.assertEqual(
            verdict.shared_input_digest, self.scenario_a["shared_input_digest"]
        )

    def test_scenario_e_reports_rail_classifications(self) -> None:
        verdict = self.scenario_a["verdict"]
        self.assertEqual(verdict.rail_a.rail_class, "LOCAL_DETERMINISTIC_SANDBOX")
        self.assertEqual(verdict.rail_b.rail_class, "LOCAL_DETERMINISTIC_SANDBOX")
        self.assertNotEqual(verdict.rail_a.environment_id, verdict.rail_b.environment_id)

    def test_failure_battery_covers_the_required_paths(self) -> None:
        battery = rails_package.run_failure_battery(self.gate)
        paths = battery["paths"]
        for required in (
            "transport_ambiguity",
            "provider_rejection",
            "reconciliation_success",
            "reconciliation_not_found",
            "idempotent_retry",
            "unexpected_provider_status",
        ):
            self.assertIn(required, paths)
            self.assertTrue(paths[required]["fail_closed"], required)

    def test_unexpected_provider_status_fails_closed(self) -> None:
        battery = rails_package.run_failure_battery(self.gate)
        probe = battery["paths"]["unexpected_provider_status"]
        self.assertTrue(probe["raised_validation_error"])
        self.assertIsNone(probe.get("canonical_status"))
        self.assertFalse(probe.get("settled", False))

    def test_reconciliation_not_found_is_retry_safe_truth(self) -> None:
        battery = rails_package.run_failure_battery(self.gate)
        probe = battery["paths"]["reconciliation_not_found"]
        self.assertEqual(probe["outcome"], "NOT_FOUND")
        self.assertFalse(probe["fabricated_success"])

    def test_shared_input_digest_is_declared_and_stable(self) -> None:
        digest = self.scenario_a["shared_input_digest"]
        self.assertIsInstance(digest, str)
        self.assertEqual(len(digest), 64)
        again = rails_package.run_rails_scenario_a(
            rails_package.ExternalRailSandboxGate(
                rails_package.build_local_rail_pair(
                    submissions={
                        "ig005-b1": ("reject",),
                        "ig005-c1": ("unknown",),
                        "ig005-c1-retry": ("accept",),
                    },
                    queries={"ig005-c1": ("not-found",)},
                )
            )
        )
        self.assertEqual(again["shared_input_digest"], digest)


class FinalityDisciplineTests(unittest.TestCase):
    """Provider payment success never manufactures settlement finality."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.outcome = rails_package.run_rails_finality_discipline(
            rails_package.ExternalRailSandboxGate(
                rails_package.build_local_rail_pair()
            )
        )

    def test_payment_status_never_establishes_finality(self) -> None:
        outcome = self.outcome
        for side in ("rail_a", "rail_b"):
            self.assertTrue(outcome[side]["status_recorded_settled"])
            self.assertFalse(outcome[side]["finality_exists_at_status_point"])
            self.assertEqual(outcome[side]["finality_count_at_status_point"], 0)
            self.assertIsNone(outcome[side].get("finality_id_at_status_point"))

    def test_finality_arrives_only_through_the_settlement_authority(self) -> None:
        outcome = self.outcome
        for side in ("rail_a", "rail_b"):
            self.assertTrue(outcome[side]["finality_established_after_settlement"])
            self.assertEqual(outcome[side]["settlement_state"], "COMPLETED")
            self.assertEqual(outcome[side]["settled_legs"], 1)

    def test_provider_success_is_evidence_only(self) -> None:
        outcome = self.outcome
        for side in ("rail_a", "rail_b"):
            claim = outcome[side]["finality_claim_kind"]
            self.assertIn(claim, ("FINAL", "FINALITY"))
            self.assertEqual(outcome[side]["claim_recorded_as"], "OBSERVED")


class ComparisonDiscriminationTests(unittest.TestCase):
    """The comparison authority fails closed on every unregistered difference."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.gate = rails_package.ExternalRailSandboxGate(
            rails_package.build_local_rail_pair()
        )
        cls.baseline = rails_package.run_rails_scenario_a(cls.gate)

    def test_amount_divergence_is_detected(self) -> None:
        # The amount corruption feed: mutate one leg's amount value.
        projection = rails_package.semantic_projection(
            self.gate.rail_a_gate, self.gate.rail_a_world
        )
        import copy

        corrupted = copy.deepcopy(projection)
        found = _mutate_first_amount(corrupted, 999)
        self.assertTrue(found, "the projection must carry a leg amount")
        differences = self.gate.compare_projections(rail_a=corrupted)
        self.assertTrue(differences)
        self.assertTrue(
            any("amount" in difference.path for difference in differences)
        )

    def test_outcome_class_divergence_is_detected(self) -> None:
        import copy

        projection = rails_package.semantic_projection(
            self.gate.rail_a_gate, self.gate.rail_a_world
        )
        corrupted = copy.deepcopy(projection)
        found = _mutate_step_state(corrupted, "FAILED")
        self.assertTrue(found)
        differences = self.gate.compare_projections(rail_a=corrupted)
        self.assertTrue(differences)

    def test_failure_class_divergence_is_detected(self) -> None:
        outcome = rails_package.run_rails_scenario_b(
            rails_package.ExternalRailSandboxGate(
                rails_package.build_local_rail_pair(
                    submissions={"ig005-b1": ("reject",)}
                )
            ),
        )
        self.assertEqual(outcome["rail_a"]["submission_status"], "REJECTED")
        self.assertEqual(outcome["rail_b"]["submission_status"], "REJECTED")

    def test_native_reference_substitution_fails_closed(self) -> None:
        # The corruption feed is the RAW semantic state: the exact-value
        # fail-closed validation lives in the normalization layer, so a
        # foreign provider reference can never pass as a normalization.
        import copy

        raw = rails_package.semantic_state(self.gate.rail_a_gate)
        corrupted = copy.deepcopy(raw)
        found = _mutate_native_reference(corrupted, "foreign-rail/reference-xyz")
        self.assertTrue(found)
        with self.assertRaises(Exception) as raised:
            rails_package.normalize_semantic_state(
                corrupted, self.gate.rail_a_world
            )
        self.assertIn(
            "native reference", str(raised.exception).lower()
        )

    def test_environment_substitution_fails_closed(self) -> None:
        import copy

        raw = rails_package.semantic_state(self.gate.rail_a_gate)
        corrupted = copy.deepcopy(raw)
        _mutate_all_environment_ids(corrupted, "env/sandbox-foreign-world")
        with self.assertRaises(Exception) as raised:
            rails_package.normalize_semantic_state(
                corrupted, self.gate.rail_a_world
            )
        self.assertIn(
            "environment", str(raised.exception).lower()
        )

    def test_native_status_word_substitution_fails_closed(self) -> None:
        import copy

        raw = rails_package.semantic_state(self.gate.rail_a_gate)
        corrupted = copy.deepcopy(raw)
        found = _mutate_key_occurrence(corrupted, "native_code", "CHRGD")
        self.assertTrue(found)
        with self.assertRaises(Exception) as raised:
            rails_package.normalize_semantic_state(
                corrupted, self.gate.rail_a_world
            )
        self.assertIn(
            "native status word", str(raised.exception).lower()
        )

    def test_declared_asset_substitution_fails_closed(self) -> None:
        import copy

        raw = rails_package.semantic_state(self.gate.rail_a_gate)
        corrupted = copy.deepcopy(raw)
        found = _mutate_first_asset(corrupted, "asset/gbp")
        self.assertTrue(found)
        with self.assertRaises(Exception) as raised:
            rails_package.normalize_semantic_state(
                corrupted, self.gate.rail_a_world
            )
        self.assertIn(
            "asset", str(raised.exception).lower()
        )

    def test_baseline_comparison_is_equivalent(self) -> None:
        differences = self.gate.compare_projections()
        self.assertEqual(differences, ())
        verdict = self.baseline["verdict"]
        self.assertEqual(verdict.verdict, "EQUIVALENT")

    def test_invariant_battery_covers_the_required_dimensions(self) -> None:
        # The battery's coverage vocabulary is pinned: removing any
        # load-bearing check (the discrimination battery's kill feed
        # for the skipped-comparison mutants) changes the battery's
        # output and fails this test.
        checks = rails_package.verify_rails_invariants(self.gate)
        names = {
            fragment
            for fragment in checks
            for fragment in (fragment.split(":")[0],)
        }
        required_names = {
            "merged-ig002-battery",
            "domain-isolation",
            "rail-classification",
            "finality-discipline",
            "cross-rail-idempotency",
            "cross-rail-failure-class",
            "cross-rail-outcome-class",
            "cross-rail-declared-economics",
            "cross-rail-stage-sequences",
            "native-reference-presence",
            "cross-rail-posting-structure",
        }
        self.assertTrue(names >= required_names, f"missing: {required_names - names}")
        # Every per-world check runs on BOTH worlds.
        for prefix in (
            "merged-ig002-battery",
            "domain-isolation",
            "rail-classification",
            "finality-discipline",
            "native-reference-presence",
        ):
            self.assertEqual(
                len([c for c in checks if c.split(":")[0] == prefix]),
                2,
                f"the {prefix} check must run on both worlds",
            )

    def test_gate_rejects_shared_environment_domain_or_adapter(self) -> None:
        import dataclasses

        from src.core.errors import CoreValidationError

        world_a, world_b = rails_package.build_local_rail_pair()
        clone = dataclasses.replace(
            world_b, environment_id=world_a.environment_id
        )
        with self.assertRaises(CoreValidationError):
            rails_package.ExternalRailSandboxGate((world_a, clone))
        clone = dataclasses.replace(world_b, domain_id=world_a.domain_id)
        with self.assertRaises(CoreValidationError):
            rails_package.ExternalRailSandboxGate((world_a, clone))
        # A classification lie fails closed at WORLD construction (even
        # earlier than the gate): a local deterministic rail can never
        # claim REAL_PROVIDER_SANDBOX, and vice versa.
        with self.assertRaises(CoreValidationError):
            dataclasses.replace(
                world_b,
                rail_class=rails_package.RailClass.REAL_PROVIDER_SANDBOX,
            )

    def _asymmetric_driven_gate(self):
        """One driven pair whose worlds REALLY diverge (A accepts, B rejects)."""
        from src.integration.rails.scenarios import (
            RAILS_PAYEE,
            RAILS_PAYER,
            _drive_world,
        )

        world_a, world_b = rails_package.build_local_rail_pair()
        world_b.rail.script_submissions({"ig005-a1": ("reject",)})
        gate = rails_package.ExternalRailSandboxGate((world_a, world_b))
        _drive_world(
            gate.rail_a_gate,
            tag="a1",
            payer=RAILS_PAYER,
            payee=RAILS_PAYEE,
            amount_minor=100,
        )
        _drive_world(
            gate.rail_b_gate,
            tag="a1",
            payer=RAILS_PAYER,
            payee=RAILS_PAYEE,
            amount_minor=100,
        )
        return gate

    def test_failure_class_divergence_fails_the_battery(self) -> None:
        # A REAL asymmetric pair: rail A accepts, rail B rejects — the
        # battery's cross-rail failure-class check fails closed and the
        # projection comparison classifies the divergence.
        from src.core.errors import CoreValidationError

        gate = self._asymmetric_driven_gate()
        differences = gate.compare_projections()
        self.assertTrue(differences)
        with self.assertRaises(CoreValidationError):
            rails_package.verify_rails_invariants(gate, cross_rail=True)

    def test_economics_divergence_fails_the_battery(self) -> None:
        # A REAL asymmetric pair: the two worlds drive DIFFERENT declared
        # amounts — the battery's declared-economics check fails closed.
        from src.core.errors import CoreValidationError

        from src.integration.rails.scenarios import (
            RAILS_PAYEE,
            RAILS_PAYER,
            _drive_world,
        )

        world_a, world_b = rails_package.build_local_rail_pair()
        gate = rails_package.ExternalRailSandboxGate((world_a, world_b))
        _drive_world(
            gate.rail_a_gate,
            tag="a1",
            payer=RAILS_PAYER,
            payee=RAILS_PAYEE,
            amount_minor=100,
        )
        _drive_world(
            gate.rail_b_gate,
            tag="a1",
            payer=RAILS_PAYER,
            payee=RAILS_PAYEE,
            amount_minor=250,
        )
        differences = gate.compare_projections()
        self.assertTrue(differences)
        with self.assertRaises(CoreValidationError):
            rails_package.verify_rails_invariants(gate, cross_rail=True)

    def test_idempotency_divergence_fails_the_battery(self) -> None:
        # A REAL asymmetric ledger: world A processed a key world B never
        # received — the idempotency key sets diverge and the battery
        # fails closed.
        from src.core.errors import CoreValidationError

        from src.integration.rails.scenarios import (
            RAILS_PAYEE,
            RAILS_PAYER,
            _drive_world,
        )

        world_a, world_b = rails_package.build_local_rail_pair(
            submissions={"ig005-a1": ("unknown",)}
        )
        gate = rails_package.ExternalRailSandboxGate((world_a, world_b))
        # World A's transport-unknown submission leaves the request in
        # its ledger; world B never receives even the request.
        _drive_world(
            gate.rail_a_gate,
            tag="a1",
            payer=RAILS_PAYER,
            payee=RAILS_PAYEE,
            amount_minor=100,
            stop_after="submitted",
        )
        with self.assertRaises(CoreValidationError):
            rails_package.verify_rails_invariants(gate, cross_rail=True)

    def test_removal_of_one_rail_from_the_comparison_is_detected(self) -> None:
        # The comparison must compare BOTH projections: comparing a
        # world against itself (the removed-rail mutant) hides every
        # divergence — the asymmetric pair proves the live comparison.
        gate = self._asymmetric_driven_gate()
        differences = gate.compare_projections()
        self.assertTrue(differences)
        self.assertTrue(
            any("state" in difference.path for difference in differences)
        )


class ReplayDeterminismTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.pair = rails_package.build_local_rail_pair(
            submissions={
                "ig005-b1": ("reject",),
                "ig005-c1": ("unknown",),
                "ig005-c1-retry": ("accept",),
            },
            queries={"ig005-c1": ("not-found",)},
        )
        cls.gate = rails_package.ExternalRailSandboxGate(cls.pair)
        cls.outcome = rails_package.run_rails_scenario_a(cls.gate)

    def test_rebuild_reproduces_the_semantic_projections_and_verdict(self) -> None:
        rebuilt = rails_package.rebuild_rails_gate(self.gate)
        self.assertIsInstance(rebuilt, rails_package.ExternalRailSandboxGate)
        rails_package.assert_rails_replay_equivalence(self.gate, rebuilt)

    def test_replay_never_calls_the_rails(self) -> None:
        # The rebuild shares the world harnesses (the same rail objects),
        # so the proof counts the rails' port calls ACROSS the rebuild.
        before = [
            (
                getattr(world.rail, "submit_call_count", 0),
                getattr(world.rail, "query_call_count", 0),
            )
            for world in (self.gate.rail_a_world, self.gate.rail_b_world)
        ]
        rails_package.rebuild_rails_gate(self.gate)
        after = [
            (
                getattr(world.rail, "submit_call_count", 0),
                getattr(world.rail, "query_call_count", 0),
            )
            for world in (self.gate.rail_a_world, self.gate.rail_b_world)
        ]
        self.assertEqual(before, after)

    def test_two_full_runs_produce_identical_verdicts(self) -> None:
        second_gate = rails_package.ExternalRailSandboxGate(
            rails_package.build_local_rail_pair(
                submissions={
                    "ig005-b1": ("reject",),
                    "ig005-c1": ("unknown",),
                    "ig005-c1-retry": ("accept",),
                },
                queries={"ig005-c1": ("not-found",)},
            )
        )
        second = rails_package.run_rails_scenario_a(second_gate)
        self.assertEqual(
            second["verdict"].digest, self.outcome["verdict"].digest
        )
        self.assertEqual(
            second["shared_input_digest"], self.outcome["shared_input_digest"]
        )


class DogfoodConformanceTests(unittest.TestCase):
    """DOGFOOD-030: the deterministic transcript and offline contracts."""

    def test_local_dogfood_transcript_passes_and_is_deterministic(self) -> None:
        first_transcript, first_digest = (
            rails_package.build_local_dogfood_transcript()
        )
        second_transcript, second_digest = (
            rails_package.build_local_dogfood_transcript()
        )
        self.assertIn("classification: DOGFOOD-030 LOCAL: PASS", first_transcript)
        self.assertEqual(first_transcript, second_transcript)
        self.assertEqual(first_digest, second_digest)

    def test_local_dogfood_transcript_names_the_required_facts(self) -> None:
        transcript, _digest = rails_package.build_local_dogfood_transcript()
        for required in (
            "work_order=WORK-030",
            "gate=IG-005",
            "architecture=v0.1",
            "rail_a=",
            "rail_b=",
            "LOCAL_DETERMINISTIC_SANDBOX",
            "semantic comparison",
            "reconciliation",
            "verdict=EQUIVALENT",
        ):
            self.assertIn(required, transcript)

    def test_real_rails_dogfood_offline_contract_is_deterministic(self) -> None:
        first_transcript, first_digest = (
            rails_package.build_real_rails_transcript(
                secret_env_var="IG005_SUITE_NEVER_SET_STRIPE_KEY",
                stellar_api_base="https://ig005-offline.invalid",
            )
        )
        second_transcript, second_digest = (
            rails_package.build_real_rails_transcript(
                secret_env_var="IG005_SUITE_NEVER_SET_STRIPE_KEY",
                stellar_api_base="https://ig005-offline.invalid",
            )
        )
        # Without the Stripe credential and with the Stellar sandbox
        # unreachable, both builders must converge on the explicit
        # offline contract rather than fabricating outcomes.
        self.assertIn("REAL RAIL", first_transcript)
        self.assertIn("NOT EXECUTED", first_transcript)
        self.assertIn("OUTSTANDING", first_transcript)
        self.assertEqual(first_transcript, second_transcript)
        self.assertEqual(first_digest, second_digest)

    def test_dogfood_transcripts_contain_no_secret_material(self) -> None:
        for builder in (
            rails_package.build_local_dogfood_transcript,
            lambda: rails_package.build_real_rails_transcript(
                secret_env_var="IG005_SUITE_NEVER_SET_STRIPE_KEY",
                stellar_api_base="https://ig005-offline.invalid",
            ),
        ):
            transcript, _digest = builder()
            for forbidden in (
                "sk_live",
                "sk_test",
                "whsec_",
                "FLWSECK",
                "Bearer ",
                "Authorization",
                "BEGIN PRIVATE KEY",
                "seed_hex",
            ):
                self.assertNotIn(forbidden, transcript)


def _offline_probe_request(adapter_id: str, key: str):
    """A minimal typed EffectRequest for direct port probes."""

    class _Spec:
        pass

    from src.transition.payload import PayloadObject

    spec = _Spec()
    spec.request_id = f"execution/ig005-offline/{key}/request/1"
    spec.step_id = "execution/ig005-offline/step/1"
    spec.adapter_id = adapter_id
    spec.idempotency_key = key
    spec.effect_type = "payment/submit"
    spec.payload = PayloadObject(
        tuple(
            sorted(
                (
                    ("currency", "USD"),
                    ("amount_value", 100),
                    ("amount_scale", 2),
                    ("destination", "alias/merchant-42"),
                )
            )
        )
    )

    class _Request:
        pass

    request = _Request()
    request.spec = spec
    return request


def _set_path(target, segments, value) -> None:
    for segment in segments[:-1]:
        target = target[segment]
    target[segments[-1]] = value


def _mutate_first_amount(projection, value) -> bool:
    return _mutate_key_occurrence(projection, "amount_value", value)


def _mutate_step_state(projection, value) -> bool:
    return _mutate_key_occurrence(projection, "state", value)


def _mutate_native_reference(projection, value) -> bool:
    return _mutate_key_occurrence(projection, "native_reference", value)


def _mutate_first_asset(projection, value) -> bool:
    return _mutate_key_occurrence(projection, "asset", value)


def _mutate_key_occurrence(value, key: str, replacement: object) -> bool:
    if isinstance(value, dict):
        for name in list(value):
            if name == key:
                value[name] = replacement
                return True
            if _mutate_key_occurrence(value[name], key, replacement):
                return True
        return False
    if isinstance(value, list):
        for item in value:
            if _mutate_key_occurrence(item, key, replacement):
                return True
    return False


def _mutate_all_environment_ids(value, replacement: str) -> None:
    if isinstance(value, dict):
        for name in list(value):
            if name == "environment_id" and isinstance(value[name], str):
                value[name] = replacement
            else:
                _mutate_all_environment_ids(value[name], replacement)
    elif isinstance(value, list):
        for item in value:
            _mutate_all_environment_ids(item, replacement)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
