from __future__ import annotations

import json
import pathlib
import unittest
from dataclasses import replace

from src.core import ObjectGraph, RelationshipType

from . import (
    TRUST_API_VERSION,
    AuthorityClass,
    AmountBound,
    Approval,
    ApprovalDecision,
    CoreValidationError,
    KeyRecord,
    MandateRecord,
    PrincipalRecord,
    ThresholdApproval,
    ThresholdPolicy,
    TrustRegistry,
    key_rotation_proposal_digest,
)

T0 = "2026-09-02T08:00:00Z"
T1 = "2026-09-02T09:00:00Z"
T2 = "2026-09-02T10:00:00Z"
T3 = "2026-09-02T11:00:00Z"
T4 = "2026-09-02T12:00:00Z"
T5 = "2026-09-02T13:00:00Z"
ENV = "env/test"
ROOT = "trust/principal/root"
ALICE = "trust/principal/alice"
BOB = "trust/principal/bob"
CAROL = "trust/principal/carol"
MERCHANT = "trust/principal/merchant-1"
AGENT = "trust/principal/agent-1"
PAY_DOMAIN = "domain/payments"
USD_CAP = AmountBound("USD", 50000, 2)


def _new_registry() -> TrustRegistry:
    registry = TrustRegistry(environment_id=ENV)
    registry.create_principal(principal_id=ROOT, display_name="Root Authority", as_of=T0)
    registry.create_principal(principal_id=ALICE, display_name="Alice", as_of=T0)
    registry.create_principal(principal_id=BOB, display_name="Bob", as_of=T0)
    registry.create_principal(principal_id=CAROL, display_name="Carol", as_of=T0)
    registry.create_principal(principal_id=MERCHANT, display_name="Merchant One", as_of=T0)
    registry.create_principal(principal_id=AGENT, display_name="Agent One", as_of=T0)
    return registry


def _bootstrap_credentials(registry: TrustRegistry) -> None:
    for principal, suffix, secret in (
        (ROOT, "root-1", "root-secret"),
        (ALICE, "alice-1", "alice-secret"),
        (BOB, "bob-1", "bob-secret"),
        (CAROL, "carol-1", "carol-secret"),
        (AGENT, "agent-1", "agent-secret"),
    ):
        registry.issue_credential(
            credential_id=f"trust/credential/{suffix}",
            principal_id=principal,
            kind="SECRET_DIGEST",
            secret=secret,
            not_before=T1,
            not_after=T4,
            as_of=T1,
            operator=ROOT,
        )


def _bootstrap_grants(registry: TrustRegistry) -> None:
    registry.issue_root_grant(
        grant_id="trust/grant/root-pay",
        authority_principal_id=ROOT,
        grantee_principal_id=ROOT,
        authority_class=AuthorityClass.R4,
        scope_domains=(PAY_DOMAIN,),
        not_before=T0,
        not_after=T4,
        delegation_depth=3,
        amount_limits=(USD_CAP,),
        jurisdictions=("EU",),
        as_of=T1,
        operator=ROOT,
    )
    registry.delegate_grant(
        grant_id="trust/grant/alice-pay",
        grantor_principal_id=ROOT,
        grantee_principal_id=ALICE,
        authority_class=AuthorityClass.R4,
        scope_domains=(PAY_DOMAIN,),
        not_before=T1,
        not_after=T4,
        delegation_depth=2,
        amount_limits=(USD_CAP,),
        jurisdictions=("EU",),
        as_of=T1,
        operator=ROOT,
    )
    registry.delegate_grant(
        grant_id="trust/grant/bob-pay",
        grantor_principal_id=ALICE,
        grantee_principal_id=BOB,
        authority_class=AuthorityClass.R4,
        scope_domains=(PAY_DOMAIN,),
        not_before=T1,
        not_after=T3,
        delegation_depth=1,
        amount_limits=(USD_CAP,),
        jurisdictions=("EU",),
        as_of=T2,
        operator=ROOT,
    )
    registry.delegate_grant(
        grant_id="trust/grant/carol-pay",
        grantor_principal_id=BOB,
        grantee_principal_id=CAROL,
        authority_class=AuthorityClass.R4,
        scope_domains=(PAY_DOMAIN,),
        not_before=T2,
        not_after=T3,
        delegation_depth=0,
        amount_limits=(USD_CAP,),
        jurisdictions=("EU",),
        as_of=T2,
        operator=ROOT,
    )


def _authenticate(registry, principal_id, credential_suffix, secret, nonce, as_of):
    return registry.authenticate(
        principal_id=principal_id,
        credential_id=f"trust/credential/{credential_suffix}",
        secret=secret,
        nonce=nonce,
        as_of=as_of,
    )


class RegistryProjectionTests(unittest.TestCase):
    """The frozen protocol registry is the only source of protocol-visible names."""

    def test_authority_class_vocabulary_is_closed_and_frozen(self) -> None:
        from . import AUTHORITY_CLASSES

        self.assertEqual(len(AUTHORITY_CLASSES), 14)
        self.assertEqual(
            sorted(item.value for item in AUTHORITY_CLASSES),
            sorted(["A0", "A1", "A2", "A3", "A4", "A5", "A6", "A7",
                    "R0", "R1", "R2", "R3", "R4", "R5"]),
        )

    def test_authority_class_validation_fails_closed(self) -> None:
        from . import validate_authority_class

        self.assertIs(validate_authority_class("R4"), AuthorityClass.R4)
        for bad in ("A9", "r4", "A", "", None, 5):
            with self.assertRaises(CoreValidationError):
                validate_authority_class(bad)

    def test_projection_matches_frozen_registry_file(self) -> None:
        from . import AUTHORITY_CLASSES, REGISTRY_OBJECT_TYPES

        repo_root = pathlib.Path(__file__).resolve().parents[2]
        registry_path = repo_root / "spec" / "registry" / "protocol-registry.json"
        self.assertTrue(registry_path.exists(), "frozen protocol registry must be present")
        frozen = json.loads(registry_path.read_text())
        self.assertEqual(
            sorted(item.value for item in AUTHORITY_CLASSES),
            sorted(frozen["registry"]["authorityClasses"]),
        )
        self.assertEqual(sorted(REGISTRY_OBJECT_TYPES), sorted(frozen["registry"]["objectTypes"]))

    def test_internal_object_types_are_not_protocol_visible(self) -> None:
        from . import require_internal_object_type

        for object_type in (
            "trust/principal/v1",
            "trust/credential/v1",
            "trust/key/v1",
            "trust/grant/v1",
            "trust/mandate/v1",
            "trust/authentication/v1",
        ):
            require_internal_object_type(object_type)
        for bad in (
            "payswap/intent/v1",
            "payswap/trust/v1",
            "trust/principal",
            "trust/principal/v2",
            "other/domain/v1",
            "trust/principal/1",
        ):
            with self.assertRaises(CoreValidationError):
                require_internal_object_type(bad)

    def test_public_boundary_is_typed_and_versioned(self) -> None:
        from . import PROTOCOL_VERSION, TRUST_DOMAIN_ID

        self.assertEqual(TRUST_API_VERSION, 1)
        self.assertEqual(PROTOCOL_VERSION, "v0.1")
        self.assertEqual(TRUST_DOMAIN_ID, "domain/trust")


class PrincipalLifecycleTests(unittest.TestCase):
    def _registry(self) -> TrustRegistry:
        return _new_registry()

    def test_create_principal_yields_active_sealed_record(self) -> None:
        registry = self._registry()
        principal = registry.principal(ALICE)
        self.assertEqual(principal.state, "ACTIVE")
        self.assertEqual(principal.principal_id, ALICE)
        self.assertEqual(principal.display_name, "Alice")
        self.assertEqual(principal.envelope.object_id, ALICE)
        self.assertEqual(principal.envelope.object_type, "trust/principal/v1")
        self.assertEqual(principal.envelope.object_version, 1)
        self.assertEqual(principal.envelope.protocol_version, "v0.1")
        self.assertEqual(principal.envelope.environment_id, ENV)
        self.assertIsNotNone(principal.envelope.integrity_hash)
        self.assertEqual(registry.principal("trust/principal/ghost", default=None), None)

    def test_principal_record_round_trips_losslessly(self) -> None:
        registry = self._registry()
        principal = registry.principal(ALICE)
        decoded = PrincipalRecord.from_json(principal.to_json())
        self.assertEqual(decoded, principal)
        self.assertEqual(decoded.to_json(), principal.to_json())

    def test_principal_identifiers_fail_closed(self) -> None:
        registry = self._registry()
        for bad in ("alice", "trust/principal/", "trust/principal/ ", "trust/alice/1"):
            with self.assertRaises(CoreValidationError):
                registry.create_principal(principal_id=bad, display_name="x", as_of=T1)
        with self.assertRaises(CoreValidationError):
            registry.create_principal(principal_id=ALICE, display_name="dup", as_of=T1)

    def test_update_principal_creates_next_version(self) -> None:
        registry = self._registry()
        updated = registry.update_principal(
            principal_id=ALICE,
            display_name="Alice Cooper",
            attributes={"tier": "preferred", "tags": ("retail",)},
            as_of=T2,
            operator=ROOT,
        )
        self.assertEqual(updated.envelope.object_version, 2)
        self.assertEqual(updated.envelope.previous_version, 1)
        self.assertEqual(updated.state, "ACTIVE")
        self.assertEqual(updated.display_name, "Alice Cooper")
        self.assertEqual(dict(updated.attributes)["tier"], "preferred")
        self.assertEqual(dict(updated.attributes)["tags"], ("retail",))
        self.assertEqual(registry.principal(ALICE), updated)
        self.assertEqual(registry.principal(ALICE).envelope.object_id, ALICE)

    def test_update_principal_requires_change_and_active_operator(self) -> None:
        registry = self._registry()
        with self.assertRaises(CoreValidationError):
            registry.update_principal(principal_id=ALICE, as_of=T2, operator=ROOT)
        with self.assertRaises(CoreValidationError):
            registry.update_principal(
                principal_id=ALICE, display_name="x", as_of=T2, operator="trust/principal/ghost"
            )
        registry.suspend_principal(principal_id=ALICE, as_of=T2, operator=ROOT)
        with self.assertRaises(CoreValidationError):
            registry.update_principal(
                principal_id=ALICE, display_name="x", as_of=T2, operator=ALICE
            )

    def test_suspend_and_reinstate_principal(self) -> None:
        registry = self._registry()
        suspended = registry.suspend_principal(principal_id=BOB, as_of=T1, operator=ROOT)
        self.assertEqual(suspended.state, "SUSPENDED")
        self.assertEqual(suspended.envelope.object_version, 2)
        with self.assertRaises(CoreValidationError):
            registry.suspend_principal(principal_id=BOB, as_of=T1, operator=ROOT)
        reinstated = registry.reinstate_principal(principal_id=BOB, as_of=T2, operator=ROOT)
        self.assertEqual(reinstated.state, "ACTIVE")
        self.assertEqual(reinstated.envelope.object_version, 3)
        with self.assertRaises(CoreValidationError):
            registry.reinstate_principal(principal_id=BOB, as_of=T2, operator=ROOT)

    def test_retire_principal_is_terminal(self) -> None:
        registry = self._registry()
        retired = registry.retire_principal(principal_id=BOB, as_of=T1, operator=ROOT)
        self.assertEqual(retired.state, "RETIRED")
        for method, kwargs in (
            (registry.suspend_principal, {}),
            (registry.reinstate_principal, {}),
            (registry.retire_principal, {}),
            (registry.update_principal, {"display_name": "x"}),
        ):
            with self.assertRaises(CoreValidationError):
                method(principal_id=BOB, as_of=T2, operator=ROOT, **kwargs)

    def test_retire_principal_blocked_by_active_dependents(self) -> None:
        registry = self._registry()
        _bootstrap_credentials(registry)
        with self.assertRaises(CoreValidationError):
            registry.retire_principal(principal_id=CAROL, as_of=T2, operator=ROOT)
        registry.revoke_credential(credential_id="trust/credential/carol-1", as_of=T2, operator=ROOT)
        retired = registry.retire_principal(principal_id=CAROL, as_of=T2, operator=ROOT)
        self.assertEqual(retired.state, "RETIRED")

    def test_retire_principal_blocked_by_active_grants(self) -> None:
        registry = self._registry()
        _bootstrap_grants(registry)
        with self.assertRaises(CoreValidationError):
            registry.retire_principal(principal_id=CAROL, as_of=T2, operator=ROOT)
        registry.revoke_grant(grant_id="trust/grant/carol-pay", as_of=T2, operator=ROOT)
        with self.assertRaises(CoreValidationError):
            registry.retire_principal(principal_id=BOB, as_of=T2, operator=ROOT)
        registry.revoke_grant(grant_id="trust/grant/bob-pay", as_of=T2, operator=ROOT)
        self.assertEqual(
            registry.retire_principal(principal_id=BOB, as_of=T2, operator=ROOT).state, "RETIRED"
        )

    def test_tampered_principal_json_is_rejected(self) -> None:
        registry = self._registry()
        encoded = registry.principal(ALICE).to_json()
        for tampered in (
            encoded.replace('"display_name":"Alice"', '"display_name":"Attacker"'),
            encoded.replace('"object_version":1', '"object_version":2'),
        ):
            with self.assertRaises(CoreValidationError):
                PrincipalRecord.from_json(tampered)

    def test_unsealed_principal_record_is_rejected(self) -> None:
        registry = self._registry()
        principal = registry.principal(ALICE)
        unsealed = replace(principal.envelope, integrity_hash=None)
        with self.assertRaises(CoreValidationError):
            PrincipalRecord(
                envelope=unsealed, principal_id=ALICE, display_name="Alice", attributes=()
            )
        data = principal.to_dict()
        data["domain_seal"] = "0" * 64
        with self.assertRaises(CoreValidationError):
            PrincipalRecord.from_dict(data)


class CredentialAuthenticationTests(unittest.TestCase):
    def _registry(self) -> TrustRegistry:
        registry = _new_registry()
        _bootstrap_credentials(registry)
        return registry

    def test_secret_digest_authentication_succeeds_with_correct_secret(self) -> None:
        registry = self._registry()
        event = _authenticate(registry, CAROL, "carol-1", "carol-secret", "nonce-1", T2)
        self.assertEqual(event.outcome, "SUCCESS")
        self.assertIsNone(event.failure_reason)
        self.assertEqual(event.principal_id, CAROL)
        self.assertEqual(event.credential_id, "trust/credential/carol-1")
        self.assertEqual(event.credential_kind, "SECRET_DIGEST")
        self.assertEqual(event.nonce, "nonce-1")
        self.assertEqual(event.occurred_at, T2)
        self.assertEqual(event.envelope.state, "SUCCESS")
        self.assertEqual(event.envelope.object_type, "trust/authentication/v1")
        self.assertTrue(event.authentication_id.startswith("trust/authentication/"))
        self.assertEqual(event.envelope.object_id, event.authentication_id)

    def test_wrong_secret_records_failure_event(self) -> None:
        registry = self._registry()
        event = _authenticate(registry, CAROL, "carol-1", "wrong-secret", "nonce-2", T2)
        self.assertEqual(event.outcome, "FAILURE")
        self.assertEqual(event.failure_reason, "VERIFIER_MISMATCH")
        self.assertEqual(event.envelope.state, "FAILURE")

    def test_suspended_principal_authentication_fails_with_reason(self) -> None:
        registry = self._registry()
        registry.suspend_principal(principal_id=CAROL, as_of=T1, operator=ROOT)
        event = _authenticate(registry, CAROL, "carol-1", "carol-secret", "nonce-3", T2)
        self.assertEqual(event.outcome, "FAILURE")
        self.assertEqual(event.failure_reason, "PRINCIPAL_SUSPENDED")

    def test_retired_principal_authentication_fails_closed(self) -> None:
        registry = self._registry()
        registry.revoke_credential(credential_id="trust/credential/carol-1", as_of=T1, operator=ROOT)
        registry.retire_principal(principal_id=CAROL, as_of=T1, operator=ROOT)
        with self.assertRaises(CoreValidationError):
            _authenticate(registry, CAROL, "carol-1", "carol-secret", "nonce-4", T2)

    def test_unknown_principal_or_credential_fails_closed(self) -> None:
        registry = self._registry()
        with self.assertRaises(CoreValidationError):
            registry.authenticate(
                principal_id="trust/principal/ghost",
                credential_id="trust/credential/carol-1",
                secret="carol-secret",
                nonce="n",
                as_of=T2,
            )
        with self.assertRaises(CoreValidationError):
            registry.authenticate(
                principal_id=CAROL,
                credential_id="trust/credential/ghost-1",
                secret="carol-secret",
                nonce="n",
                as_of=T2,
            )

    def test_credential_window_is_half_open(self) -> None:
        registry = self._registry()
        early = _authenticate(registry, CAROL, "carol-1", "carol-secret", "nonce-early", T0)
        self.assertEqual(early.outcome, "FAILURE")
        self.assertEqual(early.failure_reason, "CREDENTIAL_NOT_YET_VALID")
        boundary = _authenticate(registry, CAROL, "carol-1", "carol-secret", "nonce-open", T1)
        self.assertEqual(boundary.outcome, "SUCCESS")
        expired = _authenticate(registry, CAROL, "carol-1", "carol-secret", "nonce-late", T4)
        self.assertEqual(expired.outcome, "FAILURE")
        self.assertEqual(expired.failure_reason, "CREDENTIAL_EXPIRED")

    def test_revoked_credential_authentication_fails_with_reason(self) -> None:
        registry = self._registry()
        registry.revoke_credential(credential_id="trust/credential/carol-1", as_of=T2, operator=ROOT)
        event = _authenticate(registry, CAROL, "carol-1", "carol-secret", "nonce-5", T3)
        self.assertEqual(event.outcome, "FAILURE")
        self.assertEqual(event.failure_reason, "CREDENTIAL_REVOKED")

    def test_credential_rotation_supersedes_old_credential(self) -> None:
        registry = self._registry()
        successor = registry.rotate_credential(
            credential_id="trust/credential/carol-1",
            successor_credential_id="trust/credential/carol-2",
            secret="carol-secret-2",
            not_before=T2,
            not_after=T4,
            as_of=T2,
            operator=ROOT,
        )
        self.assertEqual(successor.state, "ACTIVE")
        self.assertEqual(successor.principal_id, CAROL)
        self.assertEqual(successor.kind, "SECRET_DIGEST")
        old = registry.credential("trust/credential/carol-1")
        self.assertEqual(old.state, "ROTATED")
        self.assertEqual(old.successor_credential_id, "trust/credential/carol-2")
        self.assertEqual(successor.predecessor_credential_id, "trust/credential/carol-1")
        stale = _authenticate(registry, CAROL, "carol-1", "carol-secret", "nonce-6", T3)
        self.assertEqual(stale.outcome, "FAILURE")
        self.assertEqual(stale.failure_reason, "CREDENTIAL_ROTATED")
        fresh = _authenticate(registry, CAROL, "carol-2", "carol-secret-2", "nonce-7", T3)
        self.assertEqual(fresh.outcome, "SUCCESS")

    def test_credential_rotation_requires_valid_state_and_window(self) -> None:
        registry = self._registry()
        with self.assertRaises(CoreValidationError):
            registry.rotate_credential(
                credential_id="trust/credential/carol-1",
                successor_credential_id="trust/credential/carol-2",
                secret="s2",
                not_before=T0,
                not_after=T4,
                as_of=T2,
                operator=ROOT,
            )
        registry.revoke_credential(credential_id="trust/credential/carol-1", as_of=T2, operator=ROOT)
        with self.assertRaises(CoreValidationError):
            registry.rotate_credential(
                credential_id="trust/credential/carol-1",
                successor_credential_id="trust/credential/carol-2",
                secret="s2",
                not_before=T2,
                not_after=T4,
                as_of=T2,
                operator=ROOT,
            )

    def test_credential_issue_requires_active_principal_and_matching_key(self) -> None:
        registry = self._registry()
        registry.suspend_principal(principal_id=CAROL, as_of=T1, operator=ROOT)
        with self.assertRaises(CoreValidationError):
            registry.issue_credential(
                credential_id="trust/credential/carol-9",
                principal_id=CAROL,
                kind="SECRET_DIGEST",
                secret="s",
                not_before=T2,
                not_after=T4,
                as_of=T2,
                operator=ROOT,
            )
        registry.reinstate_principal(principal_id=CAROL, as_of=T2, operator=ROOT)
        registry.register_key(
            key_id="trust/key/signing-1",
            owner_principal_id=CAROL,
            purpose="SIGNING",
            public_material="carol-signing-public",
            secret_material="carol-signing-secret",
            not_before=T2,
            not_after=T4,
            as_of=T2,
            operator=ROOT,
        )
        with self.assertRaises(CoreValidationError):
            registry.issue_credential(
                credential_id="trust/credential/carol-9",
                principal_id=CAROL,
                kind="KEY_PROOF",
                key_id="trust/key/signing-1",
                not_before=T2,
                not_after=T4,
                as_of=T2,
                operator=ROOT,
            )

    def test_key_proof_credential_authenticates_via_bound_key(self) -> None:
        registry = self._registry()
        registry.register_key(
            key_id="trust/key/carol-auth",
            owner_principal_id=CAROL,
            purpose="AUTHENTICATION",
            public_material="carol-auth-public",
            secret_material="carol-auth-secret",
            not_before=T1,
            not_after=T4,
            as_of=T1,
            operator=ROOT,
        )
        registry.issue_credential(
            credential_id="trust/credential/carol-key",
            principal_id=CAROL,
            kind="KEY_PROOF",
            key_id="trust/key/carol-auth",
            not_before=T1,
            not_after=T4,
            as_of=T1,
            operator=ROOT,
        )
        good = _authenticate(registry, CAROL, "carol-key", "carol-auth-secret", "k-nonce-1", T2)
        self.assertEqual(good.outcome, "SUCCESS")
        bad = _authenticate(registry, CAROL, "carol-key", "wrong", "k-nonce-2", T2)
        self.assertEqual(bad.outcome, "FAILURE")
        self.assertEqual(bad.failure_reason, "VERIFIER_MISMATCH")
        successor = registry.rotate_key(
            key_id="trust/key/carol-auth",
            successor_key_id="trust/key/carol-auth-2",
            successor_public_material="carol-auth-public-2",
            successor_secret_material="carol-auth-secret-2",
            not_before=T2,
            not_after=T4,
            as_of=T2,
            operator=ROOT,
        )
        self.assertEqual(successor.state, "ACTIVE")
        stale = _authenticate(registry, CAROL, "carol-key", "carol-auth-secret", "k-nonce-3", T3)
        self.assertEqual(stale.outcome, "FAILURE")
        self.assertEqual(stale.failure_reason, "KEY_ROTATED")
        registry.revoke_key(key_id="trust/key/carol-auth-2", as_of=T3, operator=ROOT)
        revoked = _authenticate(registry, CAROL, "carol-key", "carol-auth-secret-2", "k-nonce-4", T3)
        self.assertEqual(revoked.outcome, "FAILURE")
        self.assertEqual(revoked.failure_reason, "KEY_REVOKED")

    def test_authentication_events_are_idempotent_and_nonce_unique(self) -> None:
        registry = self._registry()
        first = _authenticate(registry, CAROL, "carol-1", "carol-secret", "dup-nonce", T2)
        replay = _authenticate(registry, CAROL, "carol-1", "carol-secret", "dup-nonce", T2)
        self.assertEqual(first, replay)
        self.assertEqual(len(registry.authentication_events()), 1)
        with self.assertRaises(CoreValidationError):
            _authenticate(registry, CAROL, "carol-1", "wrong-secret", "dup-nonce", T2)

    def test_authentication_event_records_round_trip(self) -> None:
        registry = self._registry()
        event = _authenticate(registry, CAROL, "carol-1", "carol-secret", "rt-nonce", T2)
        from . import AuthenticationEventRecord

        decoded = AuthenticationEventRecord.from_json(event.to_json())
        self.assertEqual(decoded, event)
        self.assertEqual(decoded.to_json(), event.to_json())
        tampered = event.to_json().replace('"nonce":"rt-nonce"', '"nonce":"evil"')
        with self.assertRaises(CoreValidationError):
            AuthenticationEventRecord.from_json(tampered)

    def test_verifier_digest_hides_secret_and_is_deterministic(self) -> None:
        registry = self._registry()
        credential = registry.credential("trust/credential/carol-1")
        self.assertNotIn("carol-secret", credential.to_json())
        self.assertNotEqual(credential.verifier_digest, "carol-secret")
        other = registry.issue_credential(
            credential_id="trust/credential/carol-x",
            principal_id=CAROL,
            kind="SECRET_DIGEST",
            secret="other-secret",
            not_before=T1,
            not_after=T4,
            as_of=T2,
            operator=ROOT,
        )
        self.assertNotEqual(other.verifier_digest, credential.verifier_digest)


class KeyThresholdTests(unittest.TestCase):
    def _registry(self) -> TrustRegistry:
        registry = _new_registry()
        _bootstrap_credentials(registry)
        registry.register_key(
            key_id="trust/key/recovery-1",
            owner_principal_id=ROOT,
            purpose="RECOVERY",
            public_material="recovery-public",
            secret_material="recovery-secret",
            not_before=T0,
            not_after=T4,
            as_of=T1,
            operator=ROOT,
        )
        registry.register_key(
            key_id="trust/key/guarded-1",
            owner_principal_id=ALICE,
            purpose="SIGNING",
            public_material="guarded-public",
            secret_material="guarded-secret",
            not_before=T1,
            not_after=T4,
            as_of=T1,
            operator=ROOT,
            threshold_policy=ThresholdPolicy(threshold=2, approvers=(ROOT, ALICE)),
            recovery_key_id="trust/key/recovery-1",
        )
        return registry

    def test_key_record_is_purpose_bound_and_deterministic(self) -> None:
        registry = self._registry()
        key = registry.key("trust/key/guarded-1")
        self.assertEqual(key.purpose.value, "SIGNING")
        self.assertEqual(key.state, "ACTIVE")
        self.assertEqual(key.envelope.object_type, "trust/key/v1")
        self.assertNotIn("guarded-secret", key.to_json())
        decoded = KeyRecord.from_json(key.to_json())
        self.assertEqual(decoded, key)
        twin = self._registry()
        self.assertEqual(twin.key("trust/key/guarded-1").to_json(), key.to_json())

    def test_threshold_guarded_rotation_requires_approval(self) -> None:
        registry = self._registry()
        with self.assertRaises(CoreValidationError):
            registry.rotate_key(
                key_id="trust/key/guarded-1",
                successor_key_id="trust/key/guarded-2",
                successor_public_material="guarded-public-2",
                successor_secret_material="guarded-secret-2",
                not_before=T2,
                not_after=T4,
                as_of=T2,
                operator=ROOT,
            )

    def _proposal_digest(self) -> str:
        return key_rotation_proposal_digest(
            key_id="trust/key/guarded-1",
            successor_key_id="trust/key/guarded-2",
            successor_public_material="guarded-public-2",
            as_of=T2,
        )

    def test_insufficient_threshold_is_not_approved(self) -> None:
        registry = self._registry()
        digest = self._proposal_digest()
        auth = _authenticate(registry, ROOT, "root-1", "root-secret", "thr-1", T2)
        approval = ThresholdApproval(
            policy=ThresholdPolicy(threshold=2, approvers=(ROOT, ALICE)),
            approvals=(
                Approval(
                    approver_principal_id=ROOT,
                    decision=ApprovalDecision.APPROVE,
                    proposal_digest=digest,
                    authentication=auth,
                ),
            ),
        )
        self.assertEqual(approval.state.value, "PENDING")
        with self.assertRaises(CoreValidationError):
            registry.rotate_key(
                key_id="trust/key/guarded-1",
                successor_key_id="trust/key/guarded-2",
                successor_public_material="guarded-public-2",
                successor_secret_material="guarded-secret-2",
                not_before=T2,
                not_after=T4,
                as_of=T2,
                operator=ROOT,
                threshold_approval=approval,
            )

    def test_threshold_approval_allows_rotation_with_matched_digest(self) -> None:
        registry = self._registry()
        digest = self._proposal_digest()
        auth_root = _authenticate(registry, ROOT, "root-1", "root-secret", "thr-2", T2)
        auth_alice = _authenticate(registry, ALICE, "alice-1", "alice-secret", "thr-3", T2)
        approval = ThresholdApproval(
            policy=ThresholdPolicy(threshold=2, approvers=(ROOT, ALICE)),
            approvals=(
                Approval(ROOT, ApprovalDecision.APPROVE, digest, auth_root),
                Approval(ALICE, ApprovalDecision.APPROVE, digest, auth_alice),
            ),
        )
        self.assertEqual(approval.state.value, "APPROVED")
        successor = registry.rotate_key(
            key_id="trust/key/guarded-1",
            successor_key_id="trust/key/guarded-2",
            successor_public_material="guarded-public-2",
            successor_secret_material="guarded-secret-2",
            not_before=T2,
            not_after=T4,
            as_of=T2,
            operator=ROOT,
            threshold_approval=approval,
        )
        self.assertEqual(successor.state, "ACTIVE")
        self.assertEqual(registry.key("trust/key/guarded-1").state, "ROTATED")
        self.assertEqual(
            registry.key("trust/key/guarded-1").successor_key_id, "trust/key/guarded-2"
        )

    def test_threshold_approval_rejects_wrong_proposal_digest(self) -> None:
        registry = self._registry()
        wrong_digest = "0" * 64
        auth_root = _authenticate(registry, ROOT, "root-1", "root-secret", "thr-4", T2)
        auth_alice = _authenticate(registry, ALICE, "alice-1", "alice-secret", "thr-5", T2)
        approval = ThresholdApproval(
            policy=ThresholdPolicy(threshold=2, approvers=(ROOT, ALICE)),
            approvals=(
                Approval(ROOT, ApprovalDecision.APPROVE, wrong_digest, auth_root),
                Approval(ALICE, ApprovalDecision.APPROVE, wrong_digest, auth_alice),
            ),
        )
        self.assertEqual(approval.state.value, "APPROVED")
        with self.assertRaises(CoreValidationError):
            registry.rotate_key(
                key_id="trust/key/guarded-1",
                successor_key_id="trust/key/guarded-2",
                successor_public_material="guarded-public-2",
                successor_secret_material="guarded-secret-2",
                not_before=T2,
                not_after=T4,
                as_of=T2,
                operator=ROOT,
                threshold_approval=approval,
            )

    def test_threshold_construction_failures(self) -> None:
        registry = self._registry()
        digest = self._proposal_digest()
        auth_root = _authenticate(registry, ROOT, "root-1", "root-secret", "thr-6", T2)
        bad_auth = _authenticate(registry, ROOT, "root-1", "wrong", "thr-7", T2)
        with self.assertRaises(CoreValidationError):
            Approval(
                approver_principal_id=ROOT,
                decision=ApprovalDecision.APPROVE,
                proposal_digest=digest,
                authentication=bad_auth,
            )
        with self.assertRaises(CoreValidationError):
            Approval(
                approver_principal_id=BOB,
                decision=ApprovalDecision.APPROVE,
                proposal_digest=digest,
                authentication=auth_root,
            )
        with self.assertRaises(CoreValidationError):
            ThresholdApproval(
                policy=ThresholdPolicy(threshold=2, approvers=(ROOT, ALICE)),
                approvals=(
                    Approval(ROOT, ApprovalDecision.APPROVE, digest, auth_root),
                    Approval(ROOT, ApprovalDecision.APPROVE, digest, auth_root),
                ),
            )
        auth_alice = _authenticate(registry, ALICE, "alice-1", "alice-secret", "thr-8", T2)
        rejected = ThresholdApproval(
            policy=ThresholdPolicy(threshold=2, approvers=(ROOT, ALICE)),
            approvals=(
                Approval(ROOT, ApprovalDecision.APPROVE, digest, auth_root),
                Approval(ALICE, ApprovalDecision.REJECT, digest, auth_alice),
            ),
        )
        self.assertEqual(rejected.state.value, "REJECTED")

    def test_rejected_threshold_blocks_rotation(self) -> None:
        registry = self._registry()
        digest = self._proposal_digest()
        auth_root = _authenticate(registry, ROOT, "root-1", "root-secret", "thr-9", T2)
        auth_alice = _authenticate(registry, ALICE, "alice-1", "alice-secret", "thr-10", T2)
        rejected = ThresholdApproval(
            policy=ThresholdPolicy(threshold=2, approvers=(ROOT, ALICE)),
            approvals=(
                Approval(ROOT, ApprovalDecision.APPROVE, digest, auth_root),
                Approval(ALICE, ApprovalDecision.REJECT, digest, auth_alice),
            ),
        )
        with self.assertRaises(CoreValidationError):
            registry.rotate_key(
                key_id="trust/key/guarded-1",
                successor_key_id="trust/key/guarded-2",
                successor_public_material="guarded-public-2",
                successor_secret_material="guarded-secret-2",
                not_before=T2,
                not_after=T4,
                as_of=T2,
                operator=ROOT,
                threshold_approval=rejected,
            )

    def test_recovery_key_authorizes_rotation_without_threshold(self) -> None:
        registry = self._registry()
        successor = registry.rotate_key(
            key_id="trust/key/guarded-1",
            successor_key_id="trust/key/guarded-2",
            successor_public_material="guarded-public-2",
            successor_secret_material="guarded-secret-2",
            not_before=T2,
            not_after=T4,
            as_of=T2,
            operator=ROOT,
            recovery_key_id="trust/key/recovery-1",
            recovery_secret="recovery-secret",
        )
        self.assertEqual(successor.state, "ACTIVE")
        registry2 = self._registry()
        with self.assertRaises(CoreValidationError):
            registry2.rotate_key(
                key_id="trust/key/guarded-1",
                successor_key_id="trust/key/guarded-2",
                successor_public_material="guarded-public-2",
                successor_secret_material="guarded-secret-2",
                not_before=T2,
                not_after=T4,
                as_of=T2,
                operator=ROOT,
                recovery_key_id="trust/key/recovery-1",
                recovery_secret="wrong-recovery-secret",
            )

    def test_recovery_key_must_be_bound_and_purpose_recovery(self) -> None:
        registry = self._registry()
        registry.register_key(
            key_id="trust/key/rogue-recovery",
            owner_principal_id=BOB,
            purpose="RECOVERY",
            public_material="rogue-public",
            secret_material="rogue-secret",
            not_before=T1,
            not_after=T4,
            as_of=T2,
            operator=ROOT,
        )
        with self.assertRaises(CoreValidationError):
            registry.rotate_key(
                key_id="trust/key/guarded-1",
                successor_key_id="trust/key/guarded-2",
                successor_public_material="guarded-public-2",
                successor_secret_material="guarded-secret-2",
                not_before=T2,
                not_after=T4,
                as_of=T2,
                operator=ROOT,
                recovery_key_id="trust/key/rogue-recovery",
                recovery_secret="rogue-secret",
            )

    def test_key_revocation_blocks_rotation_and_policy_validation(self) -> None:
        registry = self._registry()
        revoked = registry.revoke_key(key_id="trust/key/guarded-1", as_of=T2, operator=ROOT)
        self.assertEqual(revoked.state, "REVOKED")
        with self.assertRaises(CoreValidationError):
            registry.rotate_key(
                key_id="trust/key/guarded-1",
                successor_key_id="trust/key/guarded-2",
                successor_public_material="p2",
                successor_secret_material="s2",
                not_before=T2,
                not_after=T4,
                as_of=T2,
                operator=ROOT,
                recovery_key_id="trust/key/recovery-1",
                recovery_secret="recovery-secret",
            )
        with self.assertRaises(CoreValidationError):
            ThresholdPolicy(threshold=0, approvers=(ROOT,))
        with self.assertRaises(CoreValidationError):
            ThresholdPolicy(threshold=3, approvers=(ROOT, ALICE))
        with self.assertRaises(CoreValidationError):
            ThresholdPolicy(threshold=2, approvers=(ROOT, ROOT))
        with self.assertRaises(CoreValidationError):
            ThresholdPolicy(threshold=2, approvers=())

    def test_key_owner_must_exist_and_windows_must_be_ordered(self) -> None:
        registry = self._registry()
        with self.assertRaises(CoreValidationError):
            registry.register_key(
                key_id="trust/key/ghost-1",
                owner_principal_id="trust/principal/ghost",
                purpose="SIGNING",
                public_material="p",
                secret_material="s",
                not_before=T1,
                not_after=T4,
                as_of=T1,
                operator=ROOT,
            )
        with self.assertRaises(CoreValidationError):
            registry.register_key(
                key_id="trust/key/bad-window",
                owner_principal_id=ALICE,
                purpose="SIGNING",
                public_material="p",
                secret_material="s",
                not_before=T4,
                not_after=T1,
                as_of=T1,
                operator=ROOT,
            )


class DelegationGrantTests(unittest.TestCase):
    def _registry(self) -> TrustRegistry:
        registry = _new_registry()
        _bootstrap_grants(registry)
        return registry

    def test_root_and_delegated_grants_are_sealed_versioned_records(self) -> None:
        from . import AuthorizationGrantRecord, GrantKind

        registry = self._registry()
        root = registry.grant("trust/grant/root-pay")
        self.assertEqual(root.grant_kind, GrantKind.ROOT)
        self.assertIsNone(root.parent_grant_id)
        self.assertEqual(root.envelope.object_type, "trust/grant/v1")
        self.assertEqual(root.envelope.state, "ACTIVE")
        carol = registry.grant("trust/grant/carol-pay")
        self.assertEqual(carol.grant_kind, GrantKind.DELEGATED)
        self.assertEqual(carol.parent_grant_id, "trust/grant/bob-pay")
        self.assertEqual(carol.delegation_depth, 0)
        decoded = AuthorizationGrantRecord.from_json(carol.to_json())
        self.assertEqual(decoded, carol)
        self.assertEqual(decoded.to_json(), carol.to_json())

    def test_delegation_is_depth_bounded(self) -> None:
        registry = self._registry()
        with self.assertRaises(CoreValidationError):
            registry.delegate_grant(
                grant_id="trust/grant/carol-sub",
                grantor_principal_id=CAROL,
                grantee_principal_id=BOB,
                authority_class=AuthorityClass.R4,
                scope_domains=(PAY_DOMAIN,),
                not_before=T2,
                not_after=T3,
                delegation_depth=0,
                amount_limits=(USD_CAP,),
                jurisdictions=("EU",),
                as_of=T2,
                operator=ROOT,
            )

    def test_delegation_depth_may_not_increase(self) -> None:
        registry = self._registry()
        with self.assertRaises(CoreValidationError):
            registry.delegate_grant(
                grant_id="trust/grant/bob-sub",
                grantor_principal_id=BOB,
                grantee_principal_id=CAROL,
                authority_class=AuthorityClass.R4,
                scope_domains=(PAY_DOMAIN,),
                not_before=T2,
                not_after=T3,
                delegation_depth=1,
                amount_limits=(USD_CAP,),
                jurisdictions=("EU",),
                as_of=T2,
                operator=ROOT,
            )

    def test_delegation_scope_may_not_widen(self) -> None:
        registry = self._registry()
        with self.assertRaises(CoreValidationError):
            registry.delegate_grant(
                grant_id="trust/grant/carol-wide",
                grantor_principal_id=BOB,
                grantee_principal_id=CAROL,
                authority_class=AuthorityClass.R4,
                scope_domains=("domain/treasury",),
                not_before=T2,
                not_after=T3,
                delegation_depth=0,
                amount_limits=(USD_CAP,),
                jurisdictions=("EU",),
                as_of=T2,
                operator=ROOT,
            )
        with self.assertRaises(CoreValidationError):
            registry.delegate_grant(
                grant_id="trust/grant/carol-obj",
                grantor_principal_id=BOB,
                grantee_principal_id=CAROL,
                authority_class=AuthorityClass.R4,
                scope_objects=("intent/1",),
                scope_domains=(PAY_DOMAIN,),
                not_before=T2,
                not_after=T3,
                delegation_depth=0,
                amount_limits=(USD_CAP,),
                jurisdictions=("EU",),
                as_of=T2,
                operator=ROOT,
            )

    def test_delegation_window_may_not_widen(self) -> None:
        registry = self._registry()
        with self.assertRaises(CoreValidationError):
            registry.delegate_grant(
                grant_id="trust/grant/bob-late",
                grantor_principal_id=ALICE,
                grantee_principal_id=BOB,
                authority_class=AuthorityClass.R4,
                scope_domains=(PAY_DOMAIN,),
                not_before=T1,
                not_after=T5,
                delegation_depth=1,
                amount_limits=(USD_CAP,),
                jurisdictions=("EU",),
                as_of=T2,
                operator=ROOT,
            )

    def test_delegation_amount_limits_may_not_widen(self) -> None:
        registry = self._registry()
        with self.assertRaises(CoreValidationError):
            registry.delegate_grant(
                grant_id="trust/grant/bob-cap",
                grantor_principal_id=ALICE,
                grantee_principal_id=BOB,
                authority_class=AuthorityClass.R4,
                scope_domains=(PAY_DOMAIN,),
                not_before=T2,
                not_after=T3,
                delegation_depth=1,
                amount_limits=(AmountBound("USD", 60000, 2),),
                jurisdictions=("EU",),
                as_of=T2,
                operator=ROOT,
            )
        with self.assertRaises(CoreValidationError):
            registry.delegate_grant(
                grant_id="trust/grant/bob-uncapped",
                grantor_principal_id=ALICE,
                grantee_principal_id=BOB,
                authority_class=AuthorityClass.R4,
                scope_domains=(PAY_DOMAIN,),
                not_before=T2,
                not_after=T3,
                delegation_depth=1,
                jurisdictions=("EU",),
                as_of=T2,
                operator=ROOT,
            )

    def test_delegation_jurisdictions_may_not_widen(self) -> None:
        registry = self._registry()
        with self.assertRaises(CoreValidationError):
            registry.delegate_grant(
                grant_id="trust/grant/bob-global",
                grantor_principal_id=ALICE,
                grantee_principal_id=BOB,
                authority_class=AuthorityClass.R4,
                scope_domains=(PAY_DOMAIN,),
                not_before=T2,
                not_after=T3,
                delegation_depth=1,
                amount_limits=(USD_CAP,),
                as_of=T2,
                operator=ROOT,
            )

    def test_delegation_requires_covering_active_parent(self) -> None:
        registry = self._registry()
        with self.assertRaises(CoreValidationError):
            registry.delegate_grant(
                grant_id="trust/grant/merchant-pay",
                grantor_principal_id=MERCHANT,
                grantee_principal_id=AGENT,
                authority_class=AuthorityClass.R4,
                scope_domains=(PAY_DOMAIN,),
                not_before=T2,
                not_after=T3,
                delegation_depth=0,
                amount_limits=(USD_CAP,),
                jurisdictions=("EU",),
                as_of=T2,
                operator=ROOT,
            )
        with self.assertRaises(CoreValidationError):
            registry.delegate_grant(
                grant_id="trust/grant/alice-class",
                grantor_principal_id=ROOT,
                grantee_principal_id=ALICE,
                authority_class=AuthorityClass.R5,
                scope_domains=(PAY_DOMAIN,),
                not_before=T2,
                not_after=T3,
                delegation_depth=1,
                amount_limits=(USD_CAP,),
                jurisdictions=("EU",),
                as_of=T2,
                operator=ROOT,
            )
        registry.suspend_principal(principal_id=ALICE, as_of=T2, operator=ROOT)
        with self.assertRaises(CoreValidationError):
            registry.delegate_grant(
                grant_id="trust/grant/alice-again",
                grantor_principal_id=ALICE,
                grantee_principal_id=BOB,
                authority_class=AuthorityClass.R4,
                scope_domains=(PAY_DOMAIN,),
                not_before=T2,
                not_after=T3,
                delegation_depth=0,
                amount_limits=(USD_CAP,),
                jurisdictions=("EU",),
                as_of=T2,
                operator=ROOT,
            )

    def test_expired_explicit_parent_cannot_delegate_at_later_as_of(self) -> None:
        """Discrimination: an ACTIVE parent whose window ended may not delegate later.

        ``trust/grant/bob-pay`` stays ACTIVE with validity window [T1, T3)
        (half-open) while the requested child window [T2, T3) remains a strict
        subset of it; delegation at any as_of at or after T3 must fail closed.
        """
        registry = self._registry()
        for later_as_of in (T3, T4, T5):
            with self.assertRaises(CoreValidationError):
                registry.delegate_grant(
                    grant_id="trust/grant/bob-expired-child",
                    grantor_principal_id=BOB,
                    grantee_principal_id=CAROL,
                    authority_class=AuthorityClass.R4,
                    scope_domains=(PAY_DOMAIN,),
                    not_before=T2,
                    not_after=T3,
                    delegation_depth=0,
                    amount_limits=(USD_CAP,),
                    jurisdictions=("EU",),
                    parent_grant_id="trust/grant/bob-pay",
                    as_of=later_as_of,
                    operator=ROOT,
                )
        # the rejection is total (no partial mutation) and leaves the parent untouched
        self.assertEqual(registry.grant("trust/grant/bob-pay").state, "ACTIVE")
        with self.assertRaises(CoreValidationError):
            registry.grant("trust/grant/bob-expired-child")

    def test_pre_window_explicit_parent_cannot_delegate(self) -> None:
        """The same guard rejects a parent not yet valid at the delegation instant."""
        registry = self._registry()
        with self.assertRaises(CoreValidationError):
            registry.delegate_grant(
                grant_id="trust/grant/bob-early-child",
                grantor_principal_id=BOB,
                grantee_principal_id=CAROL,
                authority_class=AuthorityClass.R4,
                scope_domains=(PAY_DOMAIN,),
                not_before=T2,
                not_after=T3,
                delegation_depth=0,
                amount_limits=(USD_CAP,),
                jurisdictions=("EU",),
                parent_grant_id="trust/grant/bob-pay",
                as_of=T0,
                operator=ROOT,
            )

    def test_in_window_explicit_parent_delegation_remains_valid(self) -> None:
        """Control: an explicitly supplied parent valid at as_of still delegates."""
        registry = self._registry()
        child = registry.delegate_grant(
            grant_id="trust/grant/bob-explicit-child",
            grantor_principal_id=BOB,
            grantee_principal_id=CAROL,
            authority_class=AuthorityClass.R4,
            scope_domains=(PAY_DOMAIN,),
            not_before=T2,
            not_after=T3,
            delegation_depth=0,
            amount_limits=(USD_CAP,),
            jurisdictions=("EU",),
            parent_grant_id="trust/grant/bob-pay",
            as_of=T2,
            operator=ROOT,
        )
        self.assertEqual(child.parent_grant_id, "trust/grant/bob-pay")
        self.assertEqual(child.state, "ACTIVE")
        self.assertEqual(child.envelope.provenance.recorded_at, T2)
        self.assertIs(registry.grant("trust/grant/bob-explicit-child"), child)

    def test_delegation_requires_distinct_grantee_and_active_grantee(self) -> None:
        registry = self._registry()
        with self.assertRaises(CoreValidationError):
            registry.delegate_grant(
                grant_id="trust/grant/self",
                grantor_principal_id=ALICE,
                grantee_principal_id=ALICE,
                authority_class=AuthorityClass.R4,
                scope_domains=(PAY_DOMAIN,),
                not_before=T2,
                not_after=T3,
                delegation_depth=1,
                amount_limits=(USD_CAP,),
                jurisdictions=("EU",),
                as_of=T2,
                operator=ROOT,
            )
        with self.assertRaises(CoreValidationError):
            registry.delegate_grant(
                grant_id="trust/grant/ghost-grantee",
                grantor_principal_id=ALICE,
                grantee_principal_id="trust/principal/ghost",
                authority_class=AuthorityClass.R4,
                scope_domains=(PAY_DOMAIN,),
                not_before=T2,
                not_after=T3,
                delegation_depth=0,
                amount_limits=(USD_CAP,),
                jurisdictions=("EU",),
                as_of=T2,
                operator=ROOT,
            )

    def test_grant_lifecycle_suspend_resume_revoke(self) -> None:
        registry = self._registry()
        suspended = registry.suspend_grant(grant_id="trust/grant/carol-pay", as_of=T2, operator=ROOT)
        self.assertEqual(suspended.state, "SUSPENDED")
        with self.assertRaises(CoreValidationError):
            registry.suspend_grant(grant_id="trust/grant/carol-pay", as_of=T2, operator=ROOT)
        resumed = registry.resume_grant(grant_id="trust/grant/carol-pay", as_of=T2, operator=ROOT)
        self.assertEqual(resumed.state, "ACTIVE")
        with self.assertRaises(CoreValidationError):
            registry.resume_grant(grant_id="trust/grant/carol-pay", as_of=T2, operator=ROOT)
        revoked = registry.revoke_grant(grant_id="trust/grant/carol-pay", as_of=T2, operator=ROOT)
        self.assertEqual(revoked.state, "REVOKED")
        for method in (registry.suspend_grant, registry.resume_grant, registry.revoke_grant):
            with self.assertRaises(CoreValidationError):
                method(grant_id="trust/grant/carol-pay", as_of=T2, operator=ROOT)

    def test_grant_amendment_may_only_tighten(self) -> None:
        registry = self._registry()
        tightened = registry.amend_grant(
            grant_id="trust/grant/carol-pay",
            scope_domains=(PAY_DOMAIN,),
            not_after=T3,
            delegation_depth=0,
            amount_limits=(AmountBound("USD", 40000, 2),),
            jurisdictions=("EU",),
            as_of=T2,
            operator=ROOT,
        )
        self.assertEqual(tightened.state, "ACTIVE")
        self.assertEqual(tightened.envelope.object_version, 2)
        with self.assertRaises(CoreValidationError):
            registry.amend_grant(
                grant_id="trust/grant/carol-pay",
                not_after=T4,
                as_of=T2,
                operator=ROOT,
            )
        with self.assertRaises(CoreValidationError):
            registry.amend_grant(
                grant_id="trust/grant/carol-pay",
                delegation_depth=1,
                as_of=T2,
                operator=ROOT,
            )

    def test_revoked_parent_denies_descendants_without_mutation(self) -> None:
        registry = self._registry()
        _bootstrap_credentials(registry)
        event = _authenticate(registry, CAROL, "carol-1", "carol-secret", "chain-1", T2)
        from . import AuthorizationRequest

        request = AuthorizationRequest(
            principal_id=CAROL,
            authority_classes=(AuthorityClass.R4,),
            domain_id=PAY_DOMAIN,
            environment_id=ENV,
            as_of=T2,
            authentication=event,
        )
        allowed = registry.decide(request)
        self.assertEqual(allowed.decision, "ALLOW")
        registry.revoke_grant(grant_id="trust/grant/alice-pay", as_of=T2, operator=ROOT)
        denied = registry.decide(request)
        self.assertEqual(denied.decision, "DENY")
        self.assertIn("GRANT_INACTIVE", denied.reasons)
        self.assertEqual(registry.grant("trust/grant/carol-pay").state, "ACTIVE")
        self.assertEqual(registry.grant("trust/grant/bob-pay").state, "ACTIVE")

    def test_forged_delegation_cycle_is_rejected_on_load(self) -> None:
        registry = self._registry()
        data = registry.to_dict()
        grants = {item["payload"]["grant_id"]: item for item in data["grants"]}
        bob_mutated = replace(
            registry.grant("trust/grant/bob-pay"), parent_grant_id="trust/grant/carol-pay"
        )
        carol_mutated = replace(
            registry.grant("trust/grant/carol-pay"), parent_grant_id="trust/grant/bob-pay"
        )
        grants["trust/grant/bob-pay"] = bob_mutated.to_dict()
        grants["trust/grant/carol-pay"] = carol_mutated.to_dict()
        data["grants"] = [
            grants[grant_id] for grant_id in sorted(grants)
        ]
        with self.assertRaises(CoreValidationError):
            TrustRegistry.from_dict(data, environment_id=ENV)

    def test_dangling_parent_grant_is_rejected_on_load(self) -> None:
        registry = self._registry()
        data = registry.to_dict()
        grants = {item["payload"]["grant_id"]: item for item in data["grants"]}
        carol_mutated = replace(
            registry.grant("trust/grant/carol-pay"), parent_grant_id="trust/grant/ghost"
        )
        grants["trust/grant/carol-pay"] = carol_mutated.to_dict()
        data["grants"] = [grants[grant_id] for grant_id in sorted(grants)]
        with self.assertRaises(CoreValidationError):
            TrustRegistry.from_dict(data, environment_id=ENV)


class AuthorizationDecisionTests(unittest.TestCase):
    def _registry(self) -> TrustRegistry:
        registry = _new_registry()
        _bootstrap_grants(registry)
        _bootstrap_credentials(registry)
        return registry

    def _request(self, registry, *, authentication=None, principal_id=CAROL, as_of=T2, **overrides):
        from . import AuthorizationRequest

        if authentication is None:
            authentication = _authenticate(
                registry, principal_id, "carol-1", "carol-secret", "dec-1", as_of
            )
        return AuthorizationRequest(
            principal_id=principal_id,
            authority_classes=overrides.pop("authority_classes", (AuthorityClass.R4,)),
            domain_id=overrides.pop("domain_id", PAY_DOMAIN),
            environment_id=overrides.pop("environment_id", ENV),
            as_of=as_of,
            authentication=authentication,
            **overrides,
        )

    def test_authenticated_chain_allows(self) -> None:
        registry = self._registry()
        decision = registry.decide(self._request(registry))
        self.assertEqual(decision.decision, "ALLOW")
        self.assertEqual(decision.reasons, ())
        self.assertEqual(decision.principal_id, CAROL)
        self.assertEqual(decision.as_of, T2)
        self.assertEqual(len(decision.matched_grant_chains), 1)
        self.assertEqual(decision.matched_grant_chains[0][0], "trust/grant/root-pay")
        self.assertEqual(decision.matched_grant_chains[0][-1], "trust/grant/carol-pay")
        self.assertIsNone(decision.matched_mandate_id)

    def test_decision_requires_authentication(self) -> None:
        from . import AuthorizationRequest

        registry = self._registry()
        request = AuthorizationRequest(
            principal_id=CAROL,
            authority_classes=(AuthorityClass.R4,),
            domain_id=PAY_DOMAIN,
            environment_id=ENV,
            as_of=T2,
            authentication=None,
        )
        decision = registry.decide(request)
        self.assertEqual(decision.decision, "DENY")
        self.assertIn("AUTHENTICATION_REQUIRED", decision.reasons)

    def test_decision_rejects_failed_or_foreign_authentication(self) -> None:
        registry = self._registry()
        failed = _authenticate(registry, CAROL, "carol-1", "wrong", "dec-2", T2)
        decision = registry.decide(self._request(registry, authentication=failed))
        self.assertEqual(decision.decision, "DENY")
        self.assertIn("AUTHENTICATION_INVALID", decision.reasons)
        foreign = _authenticate(registry, BOB, "bob-1", "bob-secret", "dec-3", T2)
        decision = registry.decide(self._request(registry, authentication=foreign))
        self.assertEqual(decision.decision, "DENY")
        self.assertIn("AUTHENTICATION_INVALID", decision.reasons)

    def test_decision_rejects_authentication_from_future(self) -> None:
        registry = self._registry()
        future = _authenticate(registry, CAROL, "carol-1", "carol-secret", "dec-4", T3)
        decision = registry.decide(
            self._request(registry, authentication=future, as_of=T2)
        )
        self.assertEqual(decision.decision, "DENY")
        self.assertIn("AUTHENTICATION_INVALID", decision.reasons)

    def test_decision_denies_unknown_or_inactive_principal(self) -> None:
        registry = self._registry()
        event = _authenticate(registry, CAROL, "carol-1", "carol-secret", "dec-5", T2)
        request = self._request(registry, authentication=event, principal_id="trust/principal/ghost")
        unknown = registry.decide(request)
        self.assertEqual(unknown.decision, "DENY")
        self.assertIn("UNKNOWN_PRINCIPAL", unknown.reasons)
        registry.suspend_principal(principal_id=CAROL, as_of=T2, operator=ROOT)
        denied = registry.decide(self._request(registry, authentication=event))
        self.assertEqual(denied.decision, "DENY")
        self.assertIn("PRINCIPAL_INACTIVE", denied.reasons)

    def test_decision_denies_environment_mismatch(self) -> None:
        registry = self._registry()
        decision = registry.decide(
            self._request(registry, environment_id="env/production")
        )
        self.assertEqual(decision.decision, "DENY")
        self.assertIn("ENVIRONMENT_MISMATCH", decision.reasons)

    def test_decision_denies_uncovered_scope_or_class(self) -> None:
        registry = self._registry()
        decision = registry.decide(self._request(registry, domain_id="domain/treasury"))
        self.assertEqual(decision.decision, "DENY")
        self.assertIn("SCOPE_NOT_COVERED", decision.reasons)
        decision = registry.decide(
            self._request(registry, authority_classes=(AuthorityClass.A1,))
        )
        self.assertEqual(decision.decision, "DENY")
        self.assertIn("AUTHORITY_CLASS_NOT_GRANTED", decision.reasons)

    def test_decision_denies_expired_or_future_grants(self) -> None:
        registry = self._registry()
        early = _authenticate(registry, CAROL, "carol-1", "carol-secret", "dec-6", T1)
        decision = registry.decide(
            self._request(registry, authentication=early, as_of=T1)
        )
        self.assertEqual(decision.decision, "DENY")
        self.assertIn("GRANT_WINDOW_INVALID", decision.reasons)
        event = _authenticate(registry, CAROL, "carol-1", "carol-secret", "dec-7", T2)
        decision = registry.decide(self._request(registry, authentication=event, as_of=T3))
        self.assertEqual(decision.decision, "DENY")
        self.assertIn("GRANT_WINDOW_INVALID", decision.reasons)

    def test_decision_enforces_amount_limits_across_scales(self) -> None:
        registry = self._registry()
        at_cap = registry.decide(self._request(registry, amount=AmountBound("USD", 500, 0)))
        self.assertEqual(at_cap.decision, "ALLOW")
        over_cap = registry.decide(self._request(registry, amount=AmountBound("USD", 501, 0)))
        self.assertEqual(over_cap.decision, "DENY")
        self.assertIn("AMOUNT_EXCEEDS_LIMIT", over_cap.reasons)
        other_asset = registry.decide(self._request(registry, amount=AmountBound("EUR", 999, 0)))
        self.assertEqual(other_asset.decision, "ALLOW")

    def test_decision_enforces_jurisdictions(self) -> None:
        registry = self._registry()
        allowed = registry.decide(self._request(registry, jurisdiction="EU"))
        self.assertEqual(allowed.decision, "ALLOW")
        denied = registry.decide(self._request(registry, jurisdiction="US"))
        self.assertEqual(denied.decision, "DENY")
        self.assertIn("JURISDICTION_NOT_COVERED", denied.reasons)

    def test_decision_requires_all_requested_authority_classes(self) -> None:
        registry = self._registry()
        decision = registry.decide(
            self._request(
                registry,
                authority_classes=(AuthorityClass.R4, AuthorityClass.A1),
            )
        )
        self.assertEqual(decision.decision, "DENY")
        self.assertIn("AUTHORITY_CLASS_NOT_GRANTED", decision.reasons)

    def test_decision_is_deterministic_and_provenance_preserving(self) -> None:
        registry = self._registry()
        request = self._request(registry)
        first = registry.decide(request)
        second = registry.decide(request)
        self.assertEqual(first, second)
        self.assertEqual(first.decision_digest, second.decision_digest)
        self.assertEqual(first.authentication_id, request.authentication.authentication_id)
        self.assertEqual(len(first.request_digest), 64)
        self.assertEqual(len(first.decision_digest), 64)
        self.assertEqual(first.to_dict()["decision"], "ALLOW")

    def test_mandate_required_for_on_behalf_of_actions(self) -> None:
        registry = self._registry()
        decision = registry.decide(self._request(registry, on_behalf_of=MERCHANT))
        self.assertEqual(decision.decision, "DENY")
        self.assertIn("MANDATE_REQUIRED", decision.reasons)

    def test_active_mandate_allows_on_behalf_of_action(self) -> None:
        registry = self._registry()
        event = _authenticate(registry, AGENT, "agent-1", "agent-secret", "dec-8", T2)
        registry.issue_root_grant(
            grant_id="trust/grant/merchant-agent",
            authority_principal_id=MERCHANT,
            grantee_principal_id=AGENT,
            authority_class=AuthorityClass.R4,
            scope_domains=(PAY_DOMAIN,),
            not_before=T1,
            not_after=T4,
            delegation_depth=0,
            as_of=T1,
            operator=ROOT,
        )
        registry.create_mandate(
            mandate_id="trust/mandate/merchant-agent",
            mandator_principal_id=MERCHANT,
            mandatary_principal_id=AGENT,
            purpose="settlement-operations",
            scope_domains=(PAY_DOMAIN,),
            not_before=T1,
            not_after=T4,
            as_of=T1,
            operator=ROOT,
        )
        request = self._request(
            registry, authentication=event, principal_id=AGENT, on_behalf_of=MERCHANT
        )
        denied = registry.decide(request)
        self.assertEqual(denied.decision, "DENY")
        self.assertIn("MANDATE_INACTIVE", denied.reasons)
        registry.activate_mandate(mandate_id="trust/mandate/merchant-agent", as_of=T2, operator=ROOT)
        allowed = registry.decide(request)
        self.assertEqual(allowed.decision, "ALLOW")
        self.assertEqual(allowed.matched_mandate_id, "trust/mandate/merchant-agent")
        registry.revoke_mandate(mandate_id="trust/mandate/merchant-agent", as_of=T2, operator=ROOT)
        revoked = registry.decide(request)
        self.assertEqual(revoked.decision, "DENY")
        self.assertIn("MANDATE_INACTIVE", revoked.reasons)

    def test_request_contract_fails_closed(self) -> None:
        from . import AuthorizationRequest

        registry = self._registry()
        event = _authenticate(registry, CAROL, "carol-1", "carol-secret", "dec-9", T2)
        base = dict(
            principal_id=CAROL,
            domain_id=PAY_DOMAIN,
            environment_id=ENV,
            as_of=T2,
            authentication=event,
        )
        with self.assertRaises(CoreValidationError):
            AuthorizationRequest(authority_classes=(), **base)
        with self.assertRaises(CoreValidationError):
            AuthorizationRequest(authority_classes=(AuthorityClass.R4, AuthorityClass.R4), **base)
        with self.assertRaises(CoreValidationError):
            AuthorizationRequest(authority_classes=("A9",), **base)
        with self.assertRaises(CoreValidationError):
            AuthorizationRequest(
                authority_classes=(AuthorityClass.R4,), **{**base, "as_of": "not-a-time"}
            )
        with self.assertRaises(CoreValidationError):
            AuthorizationRequest(
                authority_classes=(AuthorityClass.R4,), **{**base, "amount": ("USD", 1, 2)}
            )


class MandateLifecycleTests(unittest.TestCase):
    def _registry(self) -> TrustRegistry:
        return _new_registry()

    def _mandate(self, registry: TrustRegistry, *, purpose="settlement-operations"):
        return registry.create_mandate(
            mandate_id="trust/mandate/m-1",
            mandator_principal_id=MERCHANT,
            mandatary_principal_id=AGENT,
            purpose=purpose,
            scope_domains=(PAY_DOMAIN,),
            not_before=T1,
            not_after=T4,
            as_of=T1,
            operator=ROOT,
        )

    def test_mandate_lifecycle_follows_frozen_family(self) -> None:
        registry = self._registry()
        mandate = self._mandate(registry)
        self.assertEqual(mandate.state, "CREATED")
        active = registry.activate_mandate(mandate_id="trust/mandate/m-1", as_of=T1, operator=ROOT)
        self.assertEqual(active.state, "ACTIVE")
        suspended = registry.suspend_mandate(mandate_id="trust/mandate/m-1", as_of=T2, operator=ROOT)
        self.assertEqual(suspended.state, "SUSPENDED")
        with self.assertRaises(CoreValidationError):
            registry.suspend_mandate(mandate_id="trust/mandate/m-1", as_of=T2, operator=ROOT)
        resumed = registry.resume_mandate(mandate_id="trust/mandate/m-1", as_of=T2, operator=ROOT)
        self.assertEqual(resumed.state, "ACTIVE")
        with self.assertRaises(CoreValidationError):
            registry.resume_mandate(mandate_id="trust/mandate/m-1", as_of=T2, operator=ROOT)
        amended = registry.amend_mandate(
            mandate_id="trust/mandate/m-1",
            scope_domains=(PAY_DOMAIN,),
            not_after=T3,
            as_of=T2,
            operator=ROOT,
        )
        self.assertEqual(amended.state, "ACTIVE")
        self.assertEqual(amended.envelope.object_version, 5)
        revoked = registry.revoke_mandate(mandate_id="trust/mandate/m-1", as_of=T2, operator=ROOT)
        self.assertEqual(revoked.state, "REVOKED")
        with self.assertRaises(CoreValidationError):
            registry.activate_mandate(mandate_id="trust/mandate/m-1", as_of=T2, operator=ROOT)

    def test_mandate_amendment_may_only_tighten(self) -> None:
        registry = self._registry()
        self._mandate(registry)
        registry.activate_mandate(mandate_id="trust/mandate/m-1", as_of=T1, operator=ROOT)
        with self.assertRaises(CoreValidationError):
            registry.amend_mandate(
                mandate_id="trust/mandate/m-1",
                not_after=T5,
                as_of=T2,
                operator=ROOT,
            )
        with self.assertRaises(CoreValidationError):
            registry.amend_mandate(
                mandate_id="trust/mandate/m-1",
                scope_domains=("domain/treasury",),
                as_of=T2,
                operator=ROOT,
            )

    def test_mandate_requires_distinct_known_principals_and_purpose(self) -> None:
        registry = self._registry()
        with self.assertRaises(CoreValidationError):
            self._mandate(registry, purpose="")
        with self.assertRaises(CoreValidationError):
            registry.create_mandate(
                mandate_id="trust/mandate/m-3",
                mandator_principal_id=MERCHANT,
                mandatary_principal_id=MERCHANT,
                purpose="p",
                not_before=T1,
                not_after=T4,
                as_of=T1,
                operator=ROOT,
            )
        with self.assertRaises(CoreValidationError):
            registry.create_mandate(
                mandate_id="trust/mandate/m-4",
                mandator_principal_id="trust/principal/ghost",
                mandatary_principal_id=AGENT,
                purpose="p",
                not_before=T1,
                not_after=T4,
                as_of=T1,
                operator=ROOT,
            )

    def test_mandate_record_round_trips(self) -> None:
        registry = self._registry()
        mandate = self._mandate(registry)
        decoded = MandateRecord.from_json(mandate.to_json())
        self.assertEqual(decoded, mandate)
        self.assertEqual(decoded.to_json(), mandate.to_json())
        tampered = mandate.to_json().replace('"purpose":"settlement-operations"', '"purpose":"evil"')
        with self.assertRaises(CoreValidationError):
            MandateRecord.from_json(tampered)


class PersistenceTransformationTests(unittest.TestCase):
    def _full_registry(self) -> TrustRegistry:
        registry = _new_registry()
        _bootstrap_grants(registry)
        _bootstrap_credentials(registry)
        registry.register_key(
            key_id="trust/key/guarded-1",
            owner_principal_id=ALICE,
            purpose="SIGNING",
            public_material="guarded-public",
            secret_material="guarded-secret",
            not_before=T1,
            not_after=T4,
            as_of=T1,
            operator=ROOT,
        )
        registry.create_mandate(
            mandate_id="trust/mandate/merchant-agent",
            mandator_principal_id=MERCHANT,
            mandatary_principal_id=AGENT,
            purpose="settlement-operations",
            scope_domains=(PAY_DOMAIN,),
            not_before=T1,
            not_after=T4,
            as_of=T1,
            operator=ROOT,
        )
        registry.activate_mandate(mandate_id="trust/mandate/merchant-agent", as_of=T2, operator=ROOT)
        registry.authenticate(
            principal_id=CAROL,
            credential_id="trust/credential/carol-1",
            secret="carol-secret",
            nonce="persist-1",
            as_of=T2,
        )
        return registry

    def test_registry_round_trip_is_lossless_and_byte_stable(self) -> None:
        registry = self._full_registry()
        encoded = registry.to_json()
        restored = TrustRegistry.from_json(encoded, environment_id=ENV)
        self.assertEqual(restored.to_json(), encoded)
        self.assertEqual(restored.principal(ALICE), registry.principal(ALICE))
        self.assertEqual(restored.grant("trust/grant/carol-pay"), registry.grant("trust/grant/carol-pay"))
        self.assertEqual(
            restored.credential("trust/credential/carol-1"), registry.credential("trust/credential/carol-1")
        )
        self.assertEqual(restored.key("trust/key/guarded-1"), registry.key("trust/key/guarded-1"))
        self.assertEqual(
            restored.mandate("trust/mandate/merchant-agent"),
            registry.mandate("trust/mandate/merchant-agent"),
        )
        self.assertEqual(restored.authentication_events(), registry.authentication_events())

    def test_registry_rejects_tampered_state(self) -> None:
        registry = self._full_registry()
        data = registry.to_dict()
        data["principals"][1]["payload"]["display_name"] = "Attacker"
        with self.assertRaises(CoreValidationError):
            TrustRegistry.from_dict(data, environment_id=ENV)
        data = registry.to_dict()
        data["principals"][1]["envelope"]["state"] = "EVIL"
        with self.assertRaises(CoreValidationError):
            TrustRegistry.from_dict(data, environment_id=ENV)
        data = registry.to_dict()
        del data["grants"][0]["payload"]["parent_grant_id"]
        with self.assertRaises(CoreValidationError):
            TrustRegistry.from_dict(data, environment_id=ENV)
        data = registry.to_dict()
        data["environment_id"] = "env/production"
        with self.assertRaises(CoreValidationError):
            TrustRegistry.from_dict(data, environment_id=ENV)
        data = registry.to_dict()
        data["unknown"] = []
        with self.assertRaises(CoreValidationError):
            TrustRegistry.from_dict(data, environment_id=ENV)

    def test_registry_rejects_wrong_environment_records(self) -> None:
        registry = self._full_registry()
        data = registry.to_dict()
        data["credentials"][0]["envelope"]["environment_id"] = "env/production"
        with self.assertRaises(CoreValidationError):
            TrustRegistry.from_dict(data, environment_id=ENV)

    def test_registry_construction_fails_closed(self) -> None:
        with self.assertRaises(CoreValidationError):
            TrustRegistry(environment_id="")
        with self.assertRaises(CoreValidationError):
            TrustRegistry(environment_id=ENV, domain_id="")

    def test_identical_sequences_produce_identical_state(self) -> None:
        first = self._full_registry()
        second = self._full_registry()
        self.assertEqual(first.to_json(), second.to_json())
        self.assertEqual(first.build_graph().to_json(), second.build_graph().to_json())


class TrustGraphTests(unittest.TestCase):
    @staticmethod
    def _registry() -> TrustRegistry:
        registry = _new_registry()
        _bootstrap_grants(registry)
        _bootstrap_credentials(registry)
        registry.create_mandate(
            mandate_id="trust/mandate/merchant-agent",
            mandator_principal_id=MERCHANT,
            mandatary_principal_id=AGENT,
            purpose="settlement-operations",
            scope_domains=(PAY_DOMAIN,),
            not_before=T1,
            not_after=T4,
            as_of=T1,
            operator=ROOT,
        )
        registry.authenticate(
            principal_id=CAROL,
            credential_id="trust/credential/carol-1",
            secret="carol-secret",
            nonce="graph-1",
            as_of=T2,
        )
        return registry

    def test_graph_projects_relationships_from_frozen_vocabulary(self) -> None:
        registry = self._registry()
        graph = registry.build_graph()
        self.assertIsInstance(graph, ObjectGraph)
        types = {rel.relationship_type for rel in graph.relationships}
        self.assertIn(RelationshipType.AUTHORIZES, types)
        self.assertIn(RelationshipType.CONTROLS, types)
        self.assertIn(RelationshipType.ATTESTS, types)
        self.assertIn(RelationshipType.ADMINISTERS, types)
        decoded = ObjectGraph.from_json(graph.to_json())
        self.assertEqual(decoded, graph)
        self.assertEqual(decoded.to_json(), graph.to_json())

    def test_graph_is_deterministic(self) -> None:
        first = self._registry().build_graph()
        second = self._registry().build_graph()
        self.assertEqual(first, second)
        self.assertEqual(first.to_json(), second.to_json())

    def test_graph_relationship_endpoints_exist(self) -> None:
        registry = self._registry()
        graph = registry.build_graph()
        known = {obj.object_id for obj in graph.objects}
        self.assertGreater(len(known), 10)
        for rel in graph.relationships:
            self.assertIn(rel.subject_id, known)
            self.assertIn(rel.object_id, known)


class TrustDogfoodingTests(unittest.TestCase):
    """DOGFOOD-004: authenticate a test principal, delegate bounded authority, revoke it, verify denied action."""

    def test_dogfooding_experiment(self) -> None:
        from . import AuthorizationOutcome, AuthorizationRequest

        registry = _new_registry()
        _bootstrap_credentials(registry)

        # 1. authenticate the test principal
        authentication = _authenticate(registry, CAROL, "carol-1", "carol-secret", "dogfood-1", T2)
        self.assertEqual(authentication.outcome, "SUCCESS")

        # 2. delegate bounded authority (root -> alice -> bob -> carol, depth bounded)
        _bootstrap_grants(registry)
        request = AuthorizationRequest(
            principal_id=CAROL,
            authority_classes=(AuthorityClass.R4,),
            domain_id=PAY_DOMAIN,
            environment_id=ENV,
            as_of=T2,
            authentication=authentication,
            amount=AmountBound("USD", 250, 0),
            jurisdiction="EU",
        )
        allowed = registry.decide(request)
        self.assertEqual(allowed.decision, AuthorizationOutcome.ALLOW)

        # 3. revoke the delegated authority mid-chain
        registry.revoke_grant(grant_id="trust/grant/bob-pay", as_of=T3, operator=ROOT)

        # 4. verify the action is now denied (revocation effective through the chain)
        denied = registry.decide(request)
        self.assertEqual(denied.decision, AuthorizationOutcome.DENY)
        self.assertIn("GRANT_INACTIVE", denied.reasons)

        # persistence survives the experiment and stays byte-stable
        encoded = registry.to_json()
        restored = TrustRegistry.from_json(encoded, environment_id=ENV)
        self.assertEqual(restored.decide(request), denied)
        self.assertEqual(restored.to_json(), encoded)


if __name__ == "__main__":
    unittest.main()
