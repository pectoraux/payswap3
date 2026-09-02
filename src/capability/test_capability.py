from __future__ import annotations

import unittest

from . import (
    AuthorityTier,
    BreachReason,
    BreachRecord,
    CoreValidationError,
    CapabilityCommitment,
    CapabilityKind,
    CapabilityRecord,
    CapabilityState,
    CommitmentState,
    CommitmentTerms,
    ObjectEnvelope,
    ObjectGraph,
    OperatingWindow,
    Provenance,
    RelationshipType,
    ServiceLevel,
    VerificationMethod,
    VerificationMetadata,
    VerificationResult,
    activate_capability,
    amend_commitment,
    apply_verification,
    build_attests_relationship,
    build_authorizes_relationship,
    build_dependency_relationship,
    build_services_relationship,
    cancel_commitment,
    create_commitment,
    expire_commitment,
    record_commitment_breach,
    register_capability,
    relationship_from_json,
    relationship_to_json,
    resume_capability,
    retire_capability,
    suspend_capability,
    update_capability,
)


STAMP = "2026-09-02T00:00:00Z"
PROVIDER = "capability/provider/acme-psp"
VERIFIER = "capability/verifier/acme-qa"
AUTHORITY = "capability/authority/ghana-ops"
CAPABILITY_ID = "capability/capability/iss-ghana-1"
COMMITMENT_ID = "capability/commitment/mtc-1"
SANDBOX_ENV = "env/sandbox"
PRODUCTION_ENV = "env/production"
DOMAIN = "domain/demo"
OPENS = "2026-10-01T00:00:00Z"
CLOSES = "2026-12-31T00:00:00Z"
VALID_UNTIL = "2027-06-30T00:00:00Z"
AS_OF = "2026-09-03T00:00:00Z"


def register(**overrides) -> CapabilityRecord:
    kwargs: dict = dict(
        object_id=CAPABILITY_ID,
        provider_id=PROVIDER,
        kind=CapabilityKind.PAYMENT_EXECUTION,
        description="Institutional settlement rail for Ghana",
        authority_tier=AuthorityTier.R1,
        jurisdictions=("GH",),
        protocol_versions=("v0.1",),
        simulation_support=True,
        production_support=False,
        operating_windows=(OperatingWindow(OPENS, CLOSES),),
        environment_id=SANDBOX_ENV,
        domain_id=DOMAIN,
        issuer=PROVIDER,
        source="dogfood",
        recorded_at=STAMP,
    )
    kwargs.update(overrides)
    return register_capability(**kwargs)


def passed_verification(
    method: VerificationMethod = VerificationMethod.CERTIFICATION,
    valid_until: str | None = VALID_UNTIL,
    evidence: tuple[str, ...] = ("evidence/cert-iss-1",),
) -> VerificationMetadata:
    return VerificationMetadata(
        method=method,
        verifier=VERIFIER,
        result=VerificationResult.PASSED,
        verified_at=STAMP,
        valid_until=valid_until,
        evidence_refs=evidence,
    )


def verified(
    tier: AuthorityTier = AuthorityTier.R1,
    valid_until: str | None = VALID_UNTIL,
    evidence: tuple[str, ...] = ("evidence/cert-iss-1",),
    **register_overrides,
) -> CapabilityRecord:
    record = register(authority_tier=tier, **register_overrides)
    return apply_verification(record, passed_verification(valid_until=valid_until, evidence=evidence))


def active(
    tier: AuthorityTier = AuthorityTier.R1,
    valid_until: str | None = VALID_UNTIL,
    evidence: tuple[str, ...] = ("evidence/cert-iss-1",),
    **register_overrides,
) -> CapabilityRecord:
    return activate_capability(
        verified(tier=tier, valid_until=valid_until, evidence=evidence, **register_overrides),
        as_of=AS_OF,
    )


def default_terms(
    opens: str = "2026-11-01T00:00:00Z",
    closes: str = "2026-11-15T00:00:00Z",
    capacity: int = 250,
) -> CommitmentTerms:
    return CommitmentTerms(
        window=OperatingWindow(opens, closes),
        capacity_units=capacity,
        service_level=ServiceLevel(
            max_latency_seconds=30,
            availability_floor_basis_points=9950,
        ),
    )


def sealed_envelope(
    object_type: str = "capability/capability/v1",
    state: str = "REGISTERED",
    object_id: str = CAPABILITY_ID,
    env: str = SANDBOX_ENV,
) -> ObjectEnvelope:
    return ObjectEnvelope(
        object_id=object_id,
        object_type=object_type,
        object_version=1,
        environment_id=env,
        domain_id=DOMAIN,
        schema_version=1,
        protocol_version="v0.1",
        state=state,
        provenance=Provenance(issuer=PROVIDER, source="dogfood", recorded_at=STAMP),
    ).with_integrity_hash()


def capability_payload_dict() -> dict:
    return {
        "provider_id": PROVIDER,
        "kind": "payment_execution",
        "description": "Institutional settlement rail for Ghana",
        "authority_tier": "R1",
        "jurisdictions": ["GH"],
        "protocol_versions": ["v0.1"],
        "simulation_support": True,
        "production_support": False,
        "operating_windows": [{"opens_at": OPENS, "closes_at": CLOSES}],
        "verification": None,
    }


def commitment_payload_dict() -> dict:
    return {
        "capability_id": CAPABILITY_ID,
        "terms": {
            "window": {"opens_at": "2026-11-01T00:00:00Z", "closes_at": "2026-11-15T00:00:00Z"},
            "capacity_units": 250,
            "service_level": {
                "max_latency_seconds": 30,
                "availability_floor_basis_points": 9950,
            },
        },
        "breach": None,
    }


class RegistrationContractTests(unittest.TestCase):
    def test_register_produces_sealed_registered_record(self) -> None:
        record = register()
        self.assertEqual(record.state, CapabilityState.REGISTERED)
        self.assertEqual(record.envelope.object_version, 1)
        self.assertEqual(record.envelope.object_type, "capability/capability/v1")
        self.assertEqual(record.envelope.protocol_version, "v0.1")
        self.assertIsInstance(record.envelope.integrity_hash, str)
        self.assertEqual(len(record.envelope.integrity_hash), 64)
        record.envelope.verify_integrity()

    def test_round_trip_is_lossless(self) -> None:
        record = register()
        self.assertEqual(CapabilityRecord.from_json(record.to_json()), record)
        self.assertEqual(CapabilityRecord.from_dict(record.to_dict()), record)

    def test_serialization_is_deterministic_and_byte_stable(self) -> None:
        first, second = register(), register()
        self.assertEqual(first, second)
        self.assertEqual(first.to_json(), second.to_json())
        self.assertEqual(first.envelope.integrity_hash, second.envelope.integrity_hash)
        encoded = first.to_json()
        self.assertEqual(CapabilityRecord.from_json(encoded).to_json(), encoded)

    def test_from_dict_matches_registered_record(self) -> None:
        record = register()
        decoded = CapabilityRecord.from_dict({
            "envelope": sealed_envelope().to_dict(),
            "payload": capability_payload_dict(),
        })
        self.assertEqual(decoded, record)

    def test_unknown_payload_fields_fail_closed(self) -> None:
        record = register()
        data = record.to_dict()
        data["payload"]["surprise"] = "reject-me"
        with self.assertRaises(CoreValidationError):
            CapabilityRecord.from_dict(data)

    def test_missing_payload_fields_fail_closed(self) -> None:
        data = {"envelope": sealed_envelope().to_dict(), "payload": capability_payload_dict()}
        del data["payload"]["jurisdictions"]
        with self.assertRaises(CoreValidationError):
            CapabilityRecord.from_dict(data)

    def test_non_canonical_top_level_fields_fail_closed(self) -> None:
        data = {"envelope": sealed_envelope().to_dict(), "payload": capability_payload_dict(), "extra": 1}
        with self.assertRaises(CoreValidationError):
            CapabilityRecord.from_dict(data)

    def test_registry_object_types_are_rejected(self) -> None:
        for object_type in ("payswap/intent/v1", "payswap/extension-manifest/v1", "payswap/capability/v1"):
            with self.assertRaises(CoreValidationError):
                CapabilityRecord.from_dict({
                    "envelope": sealed_envelope(object_type=object_type).to_dict(),
                    "payload": capability_payload_dict(),
                })
            with self.assertRaises(CoreValidationError):
                CapabilityRecord(
                    envelope=sealed_envelope(object_type=object_type),
                    provider_id=PROVIDER,
                    kind=CapabilityKind.PAYMENT_EXECUTION,
                    description="Institutional settlement rail for Ghana",
                    authority_tier=AuthorityTier.R1,
                    jurisdictions=("GH",),
                    protocol_versions=("v0.1",),
                    simulation_support=True,
                    production_support=False,
                    operating_windows=(OperatingWindow(OPENS, CLOSES),),
                )

    def test_object_type_must_be_exact_and_versioned(self) -> None:
        with self.assertRaises(CoreValidationError):
            CapabilityRecord.from_dict({
                "envelope": sealed_envelope(object_type="capability/capability/v2").to_dict(),
                "payload": capability_payload_dict(),
            })
        with self.assertRaises(CoreValidationError):
            CapabilityRecord.from_dict({
                "envelope": sealed_envelope(object_type="capability/record/v1").to_dict(),
                "payload": capability_payload_dict(),
            })

    def test_state_vocabulary_is_closed(self) -> None:
        with self.assertRaises(CoreValidationError):
            CapabilityRecord.from_dict({
                "envelope": sealed_envelope(state="HAPPY").to_dict(),
                "payload": capability_payload_dict(),
            })

    def test_unsealed_envelope_is_rejected(self) -> None:
        unsealed = sealed_envelope().next_version(state="VERIFIED")
        with self.assertRaises(CoreValidationError):
            CapabilityRecord(
                envelope=unsealed,
                provider_id=PROVIDER,
                kind=CapabilityKind.PAYMENT_EXECUTION,
                description="Institutional settlement rail for Ghana",
                authority_tier=AuthorityTier.R1,
                jurisdictions=("GH",),
                protocol_versions=("v0.1",),
                simulation_support=True,
                production_support=False,
                operating_windows=(OperatingWindow(OPENS, CLOSES),),
            )
        record = register()
        tampered = record.to_json().replace('"integrity_hash":"', '"integrity_hash":"0', 1)
        with self.assertRaises(CoreValidationError):
            CapabilityRecord.from_json(tampered)

    def test_environment_must_be_classifiable(self) -> None:
        for env in ("env/test", "production", "env/prod", ""):
            with self.assertRaises(CoreValidationError):
                register(environment_id=env)

    def test_sandbox_environment_requires_simulation_support(self) -> None:
        with self.assertRaises(CoreValidationError):
            register(simulation_support=False, production_support=True)

    def test_production_environment_requires_production_support(self) -> None:
        with self.assertRaises(CoreValidationError):
            register(environment_id=PRODUCTION_ENV, simulation_support=True, production_support=False)

    def test_capability_must_support_at_least_one_environment(self) -> None:
        with self.assertRaises(CoreValidationError):
            register(simulation_support=False, production_support=False)

    def test_support_flags_must_be_real_booleans(self) -> None:
        with self.assertRaises(CoreValidationError):
            register(simulation_support=1)
        with self.assertRaises(CoreValidationError):
            register(production_support="true")

    def test_governing_protocol_version_is_required(self) -> None:
        with self.assertRaises(CoreValidationError):
            register(protocol_versions=("v0.2",))
        with self.assertRaises(CoreValidationError):
            register(protocol_versions=())

    def test_protocol_versions_use_versioned_vocabulary(self) -> None:
        with self.assertRaises(CoreValidationError):
            register(protocol_versions=("v0.1", "latest"))
        with self.assertRaises(CoreValidationError):
            register(protocol_versions=("v0.1", 1))

    def test_jurisdictions_are_iso_alpha2_uppercase(self) -> None:
        for bad in ((), ("gh",), ("GHA",), ("G",), ("G1",), ("GH", "")):
            with self.assertRaises(CoreValidationError):
                register(jurisdictions=bad)

    def test_internal_identifier_namespace_is_required(self) -> None:
        for bad in ("", "psp/acme", "trust/principal/acme", "   "):
            with self.assertRaises(CoreValidationError):
                register(provider_id=bad)

    def test_kind_vocabulary_is_closed(self) -> None:
        with self.assertRaises(CoreValidationError):
            CapabilityRecord.from_dict({
                "envelope": sealed_envelope().to_dict(),
                "payload": {**capability_payload_dict(), "kind": "teleportation"},
            })

    def test_authority_tier_vocabulary_is_closed(self) -> None:
        with self.assertRaises(CoreValidationError):
            CapabilityRecord.from_dict({
                "envelope": sealed_envelope().to_dict(),
                "payload": {**capability_payload_dict(), "authority_tier": "R9"},
            })
        with self.assertRaises(CoreValidationError):
            CapabilityRecord.from_dict({
                "envelope": sealed_envelope().to_dict(),
                "payload": {**capability_payload_dict(), "authority_tier": "A1"},
            })


class OperatingWindowContractTests(unittest.TestCase):
    def test_window_requires_explicit_ordering(self) -> None:
        with self.assertRaises(CoreValidationError):
            OperatingWindow(CLOSES, OPENS)
        with self.assertRaises(CoreValidationError):
            OperatingWindow(OPENS, OPENS)

    def test_window_requires_utc_zulu_timestamps(self) -> None:
        for bad in ("2026-10-01T00:00:00+02:00", "2026-10-01T00:00:00", "2026-10-01", "", "not-a-date"):
            with self.assertRaises(CoreValidationError):
                OperatingWindow(bad, CLOSES)
            with self.assertRaises(CoreValidationError):
                OperatingWindow(OPENS, bad)

    def test_windows_must_not_overlap(self) -> None:
        windows = (
            OperatingWindow("2026-10-01T00:00:00Z", "2026-11-15T00:00:00Z"),
            OperatingWindow("2026-11-01T00:00:00Z", "2026-12-31T00:00:00Z"),
        )
        with self.assertRaises(CoreValidationError):
            register(operating_windows=windows)

    def test_adjacent_windows_are_allowed(self) -> None:
        windows = (
            OperatingWindow("2026-10-01T00:00:00Z", "2026-11-01T00:00:00Z"),
            OperatingWindow("2026-11-01T00:00:00Z", "2026-12-31T00:00:00Z"),
        )
        record = register(operating_windows=windows)
        self.assertEqual(record.operating_windows, windows)

    def test_contains_uses_half_open_bounds(self) -> None:
        window = OperatingWindow(OPENS, CLOSES)
        self.assertTrue(window.contains(OPENS))
        self.assertTrue(window.contains("2026-12-30T23:59:59Z"))
        self.assertFalse(window.contains(CLOSES))
        self.assertFalse(window.contains("2026-09-30T23:59:59Z"))
        with self.assertRaises(CoreValidationError):
            window.contains("not-a-timestamp")

    def test_window_round_trips_and_rejects_unknown_fields(self) -> None:
        window = OperatingWindow(OPENS, CLOSES)
        self.assertEqual(OperatingWindow.from_dict(window.to_dict()), window)
        data = window.to_dict()
        data["recurrence"] = "daily"
        with self.assertRaises(CoreValidationError):
            OperatingWindow.from_dict(data)


class VerificationContractTests(unittest.TestCase):
    def test_passing_verification_advances_to_verified(self) -> None:
        record = register()
        verified_record = apply_verification(record, passed_verification())
        self.assertEqual(verified_record.state, CapabilityState.VERIFIED)
        self.assertEqual(verified_record.envelope.object_version, 2)
        self.assertEqual(verified_record.envelope.previous_version, 1)
        self.assertEqual(verified_record.verification, passed_verification())
        verified_record.envelope.verify_integrity()
        self.assertEqual(record.state, CapabilityState.REGISTERED)
        self.assertIsNone(record.verification)

    def test_failed_verification_is_recorded_without_advancing(self) -> None:
        record = register()
        failed = VerificationMetadata(
            method=VerificationMethod.CERTIFICATION,
            verifier=VERIFIER,
            result=VerificationResult.FAILED,
            verified_at=STAMP,
            evidence_refs=("evidence/cert-iss-1",),
        )
        rejected = apply_verification(record, failed)
        self.assertEqual(rejected.state, CapabilityState.REGISTERED)
        self.assertEqual(rejected.verification, failed)

    def test_verification_valid_until_must_follow_verified_at(self) -> None:
        for bad in (STAMP, "2026-09-01T00:00:00Z"):
            with self.assertRaises(CoreValidationError):
                VerificationMetadata(
                    method=VerificationMethod.CERTIFICATION,
                    verifier=VERIFIER,
                    result=VerificationResult.PASSED,
                    verified_at=STAMP,
                    valid_until=bad,
                )

    def test_verification_vocabulary_is_closed(self) -> None:
        base = {
            "method": "bribe",
            "verifier": VERIFIER,
            "result": "PASSED",
            "verified_at": STAMP,
            "valid_until": VALID_UNTIL,
            "evidence_refs": ["evidence/cert-iss-1"],
        }
        with self.assertRaises(CoreValidationError):
            VerificationMetadata.from_dict(base)
        with self.assertRaises(CoreValidationError):
            VerificationMetadata.from_dict({**base, "method": "certification", "result": "MAYBE"})
        with self.assertRaises(CoreValidationError):
            VerificationMetadata.from_dict({
                **base, "method": "certification", "verifier": "qa/acme", "result": "PASSED",
            })

    def test_verification_evidence_refs_must_be_text(self) -> None:
        with self.assertRaises(CoreValidationError):
            VerificationMetadata(
                method=VerificationMethod.ATTESTATION,
                verifier=VERIFIER,
                result=VerificationResult.PASSED,
                verified_at=STAMP,
                evidence_refs=("",),
            )

    def test_verification_renewal_keeps_state(self) -> None:
        record = verified()
        renewed = apply_verification(record, passed_verification(method=VerificationMethod.ATTESTATION))
        self.assertEqual(renewed.state, CapabilityState.VERIFIED)
        self.assertEqual(renewed.envelope.object_version, 3)
        self.assertEqual(renewed.verification.method, VerificationMethod.ATTESTATION)

    def test_retired_capability_rejects_verification(self) -> None:
        retired = retire_capability(active(), reason="provider exit")
        with self.assertRaises(CoreValidationError):
            apply_verification(retired, passed_verification())

    def test_verification_round_trips_through_capability_json(self) -> None:
        record = verified()
        self.assertEqual(CapabilityRecord.from_json(record.to_json()), record)


class ActivationContractTests(unittest.TestCase):
    def test_activation_requires_verified_state(self) -> None:
        with self.assertRaises(CoreValidationError):
            activate_capability(register(), as_of=AS_OF)

    def test_activation_requires_passed_verification(self) -> None:
        record = apply_verification(
            register(),
            VerificationMetadata(
                method=VerificationMethod.CERTIFICATION,
                verifier=VERIFIER,
                result=VerificationResult.FAILED,
                verified_at=STAMP,
                evidence_refs=("evidence/cert-iss-1",),
            ),
        )
        with self.assertRaises(CoreValidationError):
            activate_capability(record, as_of=AS_OF)
        unverified = register()
        with self.assertRaises(CoreValidationError):
            activate_capability(unverified, as_of=AS_OF)

    def test_activation_rejects_expired_verification(self) -> None:
        record = verified(valid_until="2026-10-02T00:00:00Z")
        with self.assertRaises(CoreValidationError):
            activate_capability(record, as_of="2026-10-02T00:00:00Z")
        activated = activate_capability(record, as_of="2026-10-01T23:59:59Z")
        self.assertEqual(activated.state, CapabilityState.ACTIVE)

    def test_activation_requires_valid_as_of_timestamp(self) -> None:
        with self.assertRaises(CoreValidationError):
            activate_capability(verified(), as_of="yesterday")

    def test_higher_tiers_require_bounded_verified_evidence(self) -> None:
        for tier in (AuthorityTier.R3, AuthorityTier.R4, AuthorityTier.R5):
            unbounded = verified(tier=tier, valid_until=None)
            with self.assertRaises(CoreValidationError):
                activate_capability(unbounded, as_of=AS_OF)
            unevidenced = verified(tier=tier, evidence=())
            with self.assertRaises(CoreValidationError):
                activate_capability(unevidenced, as_of=AS_OF)
            strong = verified(tier=tier)
            self.assertEqual(activate_capability(strong, as_of=AS_OF).state, CapabilityState.ACTIVE)
        baseline = verified(tier=AuthorityTier.R1, valid_until=None, evidence=())
        self.assertEqual(activate_capability(baseline, as_of=AS_OF).state, CapabilityState.ACTIVE)

    def test_activation_requires_declared_operating_window(self) -> None:
        record = verified(operating_windows=())
        with self.assertRaises(CoreValidationError):
            activate_capability(record, as_of=AS_OF)

    def test_double_activation_is_rejected(self) -> None:
        with self.assertRaises(CoreValidationError):
            activate_capability(active(), as_of=AS_OF)

    def test_suspension_requires_active_state(self) -> None:
        with self.assertRaises(CoreValidationError):
            suspend_capability(verified(), reason="degradation")
        with self.assertRaises(CoreValidationError):
            suspend_capability(active(), reason="")

    def test_resume_rechecks_verification_validity(self) -> None:
        suspended = suspend_capability(
            active(valid_until="2026-11-01T00:00:00Z"), reason="provider maintenance"
        )
        self.assertEqual(suspended.state, CapabilityState.SUSPENDED)
        with self.assertRaises(CoreValidationError):
            resume_capability(suspended, as_of="2026-11-01T00:00:00Z")
        resumed = resume_capability(suspended, as_of="2026-10-31T23:59:59Z")
        self.assertEqual(resumed.state, CapabilityState.ACTIVE)

    def test_resume_requires_suspended_state(self) -> None:
        with self.assertRaises(CoreValidationError):
            resume_capability(active(), as_of=AS_OF)

    def test_retire_is_blocked_by_active_dependent_commitments(self) -> None:
        record = active()
        with self.assertRaises(CoreValidationError) as caught:
            retire_capability(record, reason="provider exit", active_dependent_commitments=(COMMITMENT_ID,))
        self.assertIn("successor", str(caught.exception))
        retired = retire_capability(
            record,
            reason="provider exit",
            active_dependent_commitments=(COMMITMENT_ID,),
            successor_id="capability/capability/iss-ghana-2",
        )
        self.assertEqual(retired.state, CapabilityState.RETIRED)

    def test_retired_is_terminal(self) -> None:
        retired = retire_capability(register(), reason="provider exit")
        with self.assertRaises(CoreValidationError):
            apply_verification(retired, passed_verification())
        with self.assertRaises(CoreValidationError):
            activate_capability(retired, as_of=AS_OF)
        with self.assertRaises(CoreValidationError):
            suspend_capability(retired, reason="late")
        with self.assertRaises(CoreValidationError):
            retire_capability(retired, reason="twice")

    def test_version_chain_preserves_identity(self) -> None:
        record = active()
        self.assertEqual(record.envelope.object_version, 3)
        self.assertEqual(record.envelope.previous_version, 2)
        original = register()
        for field in ("object_id", "object_type", "environment_id", "domain_id", "schema_version", "protocol_version"):
            self.assertEqual(getattr(record.envelope, field), getattr(original.envelope, field))
        record.envelope.verify_integrity()

    def test_update_revises_declarative_details(self) -> None:
        record = register()
        updated = update_capability(
            record,
            description="Institutional settlement rail for Ghana and CI",
            jurisdictions=("GH", "CI"),
            operating_windows=(OperatingWindow("2026-10-01T00:00:00Z", "2026-12-31T00:00:00Z"),),
        )
        self.assertEqual(updated.state, CapabilityState.REGISTERED)
        self.assertEqual(updated.envelope.object_version, 2)
        self.assertEqual(updated.jurisdictions, ("GH", "CI"))
        updated.envelope.verify_integrity()

    def test_update_rejects_terminal_state_and_invalid_payload(self) -> None:
        retired = retire_capability(register(), reason="provider exit")
        with self.assertRaises(CoreValidationError):
            update_capability(retired, description="changed")
        with self.assertRaises(CoreValidationError):
            update_capability(register(), jurisdictions=("zz",))

    def test_update_of_active_capability_requires_windows(self) -> None:
        record = active()
        with self.assertRaises(CoreValidationError):
            update_capability(record, operating_windows=())
        updated = update_capability(
            record,
            operating_windows=(OperatingWindow("2026-10-01T00:00:00Z", "2027-03-31T00:00:00Z"),),
        )
        self.assertEqual(updated.state, CapabilityState.ACTIVE)


class CommitmentContractTests(unittest.TestCase):
    def test_create_requires_active_capability(self) -> None:
        for record in (register(), verified()):
            with self.assertRaises(CoreValidationError):
                create_commitment(
                    object_id=COMMITMENT_ID,
                    capability=record,
                    terms=default_terms(),
                    issuer=PROVIDER,
                    source="dogfood",
                    recorded_at=STAMP,
                )

    def test_commitment_window_must_fit_operating_window(self) -> None:
        capability = active()
        for opens, closes in (
            ("2026-09-01T00:00:00Z", "2026-09-30T00:00:00Z"),
            ("2026-11-01T00:00:00Z", "2027-01-15T00:00:00Z"),
        ):
            with self.assertRaises(CoreValidationError):
                create_commitment(
                    object_id=COMMITMENT_ID,
                    capability=capability,
                    terms=default_terms(opens=opens, closes=closes),
                    issuer=PROVIDER,
                    source="dogfood",
                    recorded_at=STAMP,
                )

    def test_commitment_window_must_fit_within_a_single_window(self) -> None:
        capability = active(operating_windows=(
            OperatingWindow("2026-10-01T00:00:00Z", "2026-11-01T00:00:00Z"),
            OperatingWindow("2026-11-01T00:00:00Z", "2026-12-31T00:00:00Z"),
        ))
        with self.assertRaises(CoreValidationError):
            create_commitment(
                object_id=COMMITMENT_ID,
                capability=capability,
                terms=default_terms(opens="2026-10-15T00:00:00Z", closes="2026-11-15T00:00:00Z"),
                issuer=PROVIDER,
                source="dogfood",
                recorded_at=STAMP,
            )
        commitment = create_commitment(
            object_id=COMMITMENT_ID,
            capability=capability,
            terms=default_terms(opens="2026-10-15T00:00:00Z", closes="2026-10-31T00:00:00Z"),
            issuer=PROVIDER,
            source="dogfood",
            recorded_at=STAMP,
        )
        self.assertEqual(commitment.state, CommitmentState.ACTIVE)

    def test_commitment_environment_follows_capability(self) -> None:
        capability = active()
        commitment = create_commitment(
            object_id=COMMITMENT_ID,
            capability=capability,
            terms=default_terms(),
            issuer=PROVIDER,
            source="dogfood",
            recorded_at=STAMP,
        )
        self.assertEqual(commitment.envelope.environment_id, capability.envelope.environment_id)
        self.assertEqual(commitment.envelope.domain_id, capability.envelope.domain_id)
        self.assertEqual(commitment.capability_id, capability.envelope.object_id)
        commitment.envelope.verify_integrity()

    def test_capacity_must_be_a_positive_integer(self) -> None:
        capability = active()
        for bad in (0, -1, 1.5, True, "250"):
            with self.assertRaises(CoreValidationError):
                CommitmentTerms(window=OperatingWindow(OPENS, CLOSES), capacity_units=bad)

    def test_service_level_bounds_are_validated(self) -> None:
        for bad in (0, -1, 2.5, True, "30"):
            with self.assertRaises(CoreValidationError):
                ServiceLevel(max_latency_seconds=bad, availability_floor_basis_points=9950)
        for bad in (-1, 10001, 0.5, False, "9950"):
            with self.assertRaises(CoreValidationError):
                ServiceLevel(max_latency_seconds=30, availability_floor_basis_points=bad)
        self.assertEqual(
            ServiceLevel(max_latency_seconds=30, availability_floor_basis_points=0).availability_floor_basis_points,
            0,
        )

    def test_amend_bumps_version_and_keeps_active_state(self) -> None:
        capability = active()
        commitment = create_commitment(
            object_id=COMMITMENT_ID,
            capability=capability,
            terms=default_terms(),
            issuer=PROVIDER,
            source="dogfood",
            recorded_at=STAMP,
        )
        amended = amend_commitment(
            commitment,
            capability=capability,
            terms=default_terms(capacity=400),
        )
        self.assertEqual(amended.state, CommitmentState.ACTIVE)
        self.assertEqual(amended.envelope.object_version, 2)
        self.assertEqual(amended.terms.capacity_units, 400)
        self.assertEqual(commitment.envelope.object_version, 1)
        amended.envelope.verify_integrity()

    def test_amend_requires_active_commitment_and_capability(self) -> None:
        capability = active()
        commitment = create_commitment(
            object_id=COMMITMENT_ID,
            capability=capability,
            terms=default_terms(),
            issuer=PROVIDER,
            source="dogfood",
            recorded_at=STAMP,
        )
        suspended_capability = suspend_capability(capability, reason="provider maintenance")
        with self.assertRaises(CoreValidationError):
            amend_commitment(commitment, capability=suspended_capability, terms=default_terms(capacity=10))
        cancelled = cancel_commitment(commitment, reason="no longer needed")
        with self.assertRaises(CoreValidationError):
            amend_commitment(cancelled, capability=capability, terms=default_terms(capacity=10))

    def test_cancel_requires_active_state_and_reason(self) -> None:
        capability = active()
        commitment = create_commitment(
            object_id=COMMITMENT_ID,
            capability=capability,
            terms=default_terms(),
            issuer=PROVIDER,
            source="dogfood",
            recorded_at=STAMP,
        )
        cancelled = cancel_commitment(commitment, reason="no longer needed")
        self.assertEqual(cancelled.state, CommitmentState.CANCELLED)
        with self.assertRaises(CoreValidationError):
            cancel_commitment(cancelled, reason="twice")
        with self.assertRaises(CoreValidationError):
            cancel_commitment(commitment, reason="")

    def test_expire_requires_closed_window(self) -> None:
        capability = active()
        commitment = create_commitment(
            object_id=COMMITMENT_ID,
            capability=capability,
            terms=default_terms(closes="2026-11-15T00:00:00Z"),
            issuer=PROVIDER,
            source="dogfood",
            recorded_at=STAMP,
        )
        with self.assertRaises(CoreValidationError):
            expire_commitment(commitment, as_of="2026-11-14T23:59:59Z")
        expired = expire_commitment(commitment, as_of="2026-11-15T00:00:00Z")
        self.assertEqual(expired.state, CommitmentState.EXPIRED)
        with self.assertRaises(CoreValidationError):
            expire_commitment(expired, as_of="2026-12-01T00:00:00Z")

    def test_record_breach_marks_commitment_breached(self) -> None:
        capability = active()
        commitment = create_commitment(
            object_id=COMMITMENT_ID,
            capability=capability,
            terms=default_terms(),
            issuer=PROVIDER,
            source="dogfood",
            recorded_at=STAMP,
        )
        breach = BreachRecord(
            reason=BreachReason.COMPLIANCE,
            occurred_at="2026-11-02T00:00:00Z",
            description="Sanctions screening bypassed for two transactions",
            evidence_refs=("evidence/breach-1",),
        )
        breached = record_commitment_breach(commitment, breach=breach)
        self.assertEqual(breached.state, CommitmentState.BREACHED)
        self.assertEqual(breached.breach, breach)
        with self.assertRaises(CoreValidationError):
            record_commitment_breach(breached, breach=breach)

    def test_breach_vocabulary_and_timestamps_are_validated(self) -> None:
        for bad in ("fraud", "CAPACITY", ""):
            with self.assertRaises(CoreValidationError):
                BreachRecord(
                    reason=bad,
                    occurred_at="2026-11-02T00:00:00Z",
                    description="desc",
                )
        with self.assertRaises(CoreValidationError):
            BreachRecord(
                reason=BreachReason.CAPACITY,
                occurred_at="2026-11-02 00:00:00",
                description="desc",
            )
        with self.assertRaises(CoreValidationError):
            BreachRecord(
                reason=BreachReason.CAPACITY,
                occurred_at="2026-11-02T00:00:00Z",
                description="",
            )

    def test_terminal_commitments_reject_all_transitions(self) -> None:
        capability = active()
        for terminal in (
            cancel_commitment(
                create_commitment(
                    object_id=COMMITMENT_ID,
                    capability=capability,
                    terms=default_terms(),
                    issuer=PROVIDER,
                    source="dogfood",
                    recorded_at=STAMP,
                ),
                reason="no longer needed",
            ),
            expire_commitment(
                create_commitment(
                    object_id=COMMITMENT_ID + "-2",
                    capability=capability,
                    terms=default_terms(),
                    issuer=PROVIDER,
                    source="dogfood",
                    recorded_at=STAMP,
                ),
                as_of="2026-11-15T00:00:00Z",
            ),
            record_commitment_breach(
                create_commitment(
                    object_id=COMMITMENT_ID + "-3",
                    capability=capability,
                    terms=default_terms(),
                    issuer=PROVIDER,
                    source="dogfood",
                    recorded_at=STAMP,
                ),
                breach=BreachRecord(
                    reason=BreachReason.LATENCY,
                    occurred_at="2026-11-02T00:00:00Z",
                    description="P99 latency exceeded",
                ),
            ),
        ):
            self.assertNotEqual(terminal.state, CommitmentState.ACTIVE)
            with self.assertRaises(CoreValidationError):
                amend_commitment(terminal, capability=capability, terms=default_terms(capacity=10))
            with self.assertRaises(CoreValidationError):
                cancel_commitment(terminal, reason="late")
            with self.assertRaises(CoreValidationError):
                expire_commitment(terminal, as_of="2027-01-01T00:00:00Z")
            with self.assertRaises(CoreValidationError):
                record_commitment_breach(
                    terminal,
                    breach=BreachRecord(
                        reason=BreachReason.CAPACITY,
                        occurred_at="2026-11-02T00:00:00Z",
                        description="desc",
                    ),
                )

    def test_commitment_object_type_is_internal_and_exact(self) -> None:
        for object_type in ("payswap/obligation/v1", "capability/capability/v1", "capability/commitment/v2"):
            with self.assertRaises(CoreValidationError):
                CapabilityCommitment.from_dict({
                    "envelope": sealed_envelope(
                        object_type=object_type, state="ACTIVE", object_id=COMMITMENT_ID
                    ).to_dict(),
                    "payload": commitment_payload_dict(),
                })

    def test_commitment_round_trip_is_lossless(self) -> None:
        capability = active()
        commitment = create_commitment(
            object_id=COMMITMENT_ID,
            capability=capability,
            terms=default_terms(),
            issuer=PROVIDER,
            source="dogfood",
            recorded_at=STAMP,
        )
        self.assertEqual(CapabilityCommitment.from_json(commitment.to_json()), commitment)
        self.assertEqual(CapabilityCommitment.from_dict(commitment.to_dict()), commitment)
        breached = record_commitment_breach(
            commitment,
            breach=BreachRecord(
                reason=BreachReason.AVAILABILITY,
                occurred_at="2026-11-02T00:00:00Z",
                description="Rail outage",
                evidence_refs=("evidence/breach-2",),
            ),
        )
        self.assertEqual(CapabilityCommitment.from_json(breached.to_json()), breached)
        encoded = commitment.to_json()
        self.assertEqual(CapabilityCommitment.from_json(encoded).to_json(), encoded)

    def test_commitment_determinism(self) -> None:
        capability = active()
        kwargs = dict(
            object_id=COMMITMENT_ID,
            capability=capability,
            terms=default_terms(),
            issuer=PROVIDER,
            source="dogfood",
            recorded_at=STAMP,
        )
        self.assertEqual(create_commitment(**kwargs), create_commitment(**kwargs))


class IntegrityDiscriminationTests(unittest.TestCase):
    def test_tampered_capability_json_is_rejected(self) -> None:
        record = verified()
        encoded = record.to_json()
        for tampered in (
            encoded.replace('"state":"VERIFIED"', '"state":"ACTIVE"'),
            encoded.replace('"issuer":"capability/provider/acme-psp"', '"issuer":"capability/provider/attacker"'),
        ):
            with self.assertRaises(CoreValidationError):
                CapabilityRecord.from_json(tampered)

    def test_tampered_commitment_json_is_rejected(self) -> None:
        capability = active()
        commitment = create_commitment(
            object_id=COMMITMENT_ID,
            capability=capability,
            terms=default_terms(),
            issuer=PROVIDER,
            source="dogfood",
            recorded_at=STAMP,
        )
        tampered = commitment.to_json().replace('"state":"ACTIVE"', '"state":"EXPIRED"')
        with self.assertRaises(CoreValidationError):
            CapabilityCommitment.from_json(tampered)

    def test_forged_envelope_integrity_is_rejected(self) -> None:
        data = {"envelope": sealed_envelope().to_dict(), "payload": capability_payload_dict()}
        data["envelope"]["integrity_hash"] = "0" * 64
        with self.assertRaises(CoreValidationError):
            CapabilityRecord.from_dict(data)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        record = register()
        encoded = record.to_json()
        duplicated = encoded.replace('"payload":{', '"payload":{},"payload":{')
        with self.assertRaises(CoreValidationError):
            CapabilityRecord.from_json(duplicated)

    def test_deep_immutability_of_payload(self) -> None:
        jurisdictions = ["GH"]
        record = register(jurisdictions=jurisdictions)
        jurisdictions.append("XX")
        self.assertEqual(record.jurisdictions, ("GH",))
        windows = [OperatingWindow(OPENS, CLOSES)]
        record = register(operating_windows=windows)
        windows.append(OperatingWindow("2027-01-01T00:00:00Z", "2027-02-01T00:00:00Z"))
        self.assertEqual(len(record.operating_windows), 1)
        with self.assertRaises(CoreValidationError):
            CapabilityRecord(
                envelope=sealed_envelope(),
                provider_id=PROVIDER,
                kind=CapabilityKind.PAYMENT_EXECUTION,
                description="desc",
                authority_tier=AuthorityTier.R1,
                jurisdictions=["GH"],
                protocol_versions=("v0.1",),
                simulation_support=True,
                production_support=False,
                operating_windows=(OperatingWindow(OPENS, CLOSES),),
            )

    def test_identity_fields_are_frozen_across_versions(self) -> None:
        capability = active()
        with self.assertRaises(CoreValidationError):
            capability.envelope.next_version(object_id="capability/capability/other")
        with self.assertRaises(CoreValidationError):
            capability.envelope.next_version(environment_id=PRODUCTION_ENV)
        commitment = create_commitment(
            object_id=COMMITMENT_ID,
            capability=capability,
            terms=default_terms(),
            issuer=PROVIDER,
            source="dogfood",
            recorded_at=STAMP,
        )
        with self.assertRaises(CoreValidationError):
            commitment.envelope.next_version(object_type="capability/other/v1")

    def test_no_wall_clock_dependency_in_lifecycle(self) -> None:
        first = activate_capability(verified(), as_of="2026-09-03T00:00:00Z")
        second = activate_capability(verified(), as_of="2026-09-03T00:00:00Z")
        self.assertEqual(first, second)
        self.assertEqual(first.to_json(), second.to_json())
        expired = expire_commitment(
            create_commitment(
                object_id=COMMITMENT_ID,
                capability=first,
                terms=default_terms(closes="2026-11-15T00:00:00Z"),
                issuer=PROVIDER,
                source="dogfood",
                recorded_at=STAMP,
            ),
            as_of="2026-11-15T00:00:00Z",
        )
        twin = expire_commitment(
            create_commitment(
                object_id=COMMITMENT_ID,
                capability=first,
                terms=default_terms(closes="2026-11-15T00:00:00Z"),
                issuer=PROVIDER,
                source="dogfood",
                recorded_at=STAMP,
            ),
            as_of="2026-11-15T00:00:00Z",
        )
        self.assertEqual(expired, twin)


class RelationshipContractTests(unittest.TestCase):
    def test_relationship_builders_use_closed_core_vocabulary(self) -> None:
        services = build_services_relationship(PROVIDER, CAPABILITY_ID)
        self.assertEqual(services.relationship_type, RelationshipType.SERVICES)
        attests = build_attests_relationship(VERIFIER, CAPABILITY_ID)
        self.assertEqual(attests.relationship_type, RelationshipType.ATTESTS)
        authorizes = build_authorizes_relationship(AUTHORITY, CAPABILITY_ID)
        self.assertEqual(authorizes.relationship_type, RelationshipType.AUTHORIZES)
        depends = build_dependency_relationship(COMMITMENT_ID, CAPABILITY_ID)
        self.assertEqual(depends.relationship_type, RelationshipType.DEPENDS_ON)

    def test_relationship_builders_validate_internal_ids(self) -> None:
        for bad in ("", "psp/acme", "intent/1"):
            with self.assertRaises(CoreValidationError):
                build_services_relationship(bad, CAPABILITY_ID)
            with self.assertRaises(CoreValidationError):
                build_dependency_relationship(COMMITMENT_ID, bad)


class SandboxDogfoodingTests(unittest.TestCase):
    """DOGFOOD-009: register and verify a sandbox provider capability; exercise expiry and breach.

    Real supported path: the public src/capability boundary, canonical JSON
    persistence, core envelope integrity and core relationship vocabulary.
    No execution and no provider side effects: every step is a declarative
    record transition validated against the frozen v0.1 architecture.
    """

    def test_sandbox_capability_lifecycle_conformance(self) -> None:
        capability = register(
            authority_tier=AuthorityTier.R2,
            description="Sandbox instant payment rail for a Ghanaian PSP",
        )
        self.assertEqual(capability.state, CapabilityState.REGISTERED)
        self.assertEqual(capability.envelope.environment_id, SANDBOX_ENV)

        services = build_services_relationship(PROVIDER, CAPABILITY_ID)
        attests = build_attests_relationship(VERIFIER, CAPABILITY_ID)
        authorizes = build_authorizes_relationship(AUTHORITY, CAPABILITY_ID)
        for relationship in (services, attests, authorizes):
            encoded = relationship_to_json(relationship)
            self.assertEqual(relationship_from_json(encoded), relationship)

        verified_capability = apply_verification(
            capability,
            VerificationMetadata(
                method=VerificationMethod.CERTIFICATION,
                verifier=VERIFIER,
                result=VerificationResult.PASSED,
                verified_at=STAMP,
                valid_until=VALID_UNTIL,
                evidence_refs=("evidence/sandbox-cert-1", "evidence/sandbox-cert-2"),
            ),
        )
        self.assertEqual(verified_capability.state, CapabilityState.VERIFIED)

        activated = activate_capability(verified_capability, as_of=AS_OF)
        self.assertEqual(activated.state, CapabilityState.ACTIVE)

        expiring = create_commitment(
            object_id="capability/commitment/mtc-expiry",
            capability=activated,
            terms=CommitmentTerms(
                window=OperatingWindow("2026-11-01T00:00:00Z", "2026-11-15T00:00:00Z"),
                capacity_units=120,
                service_level=ServiceLevel(
                    max_latency_seconds=45,
                    availability_floor_basis_points=9900,
                ),
            ),
            issuer=PROVIDER,
            source="dogfood",
            recorded_at=STAMP,
        )
        expired = expire_commitment(expiring, as_of="2026-11-15T00:00:00Z")
        self.assertEqual(expired.state, CommitmentState.EXPIRED)

        breachable = create_commitment(
            object_id="capability/commitment/mtc-breach",
            capability=activated,
            terms=CommitmentTerms(
                window=OperatingWindow("2026-11-01T00:00:00Z", "2026-12-15T00:00:00Z"),
                capacity_units=90,
            ),
            issuer=PROVIDER,
            source="dogfood",
            recorded_at=STAMP,
        )
        breached = record_commitment_breach(
            breachable,
            breach=BreachRecord(
                reason=BreachReason.COMPLIANCE,
                occurred_at="2026-11-20T00:00:00Z",
                description="Sandbox sanctions-screening check skipped for one settlement",
                evidence_refs=("evidence/sandbox-breach-1",),
            ),
        )
        self.assertEqual(breached.state, CommitmentState.BREACHED)
        self.assertEqual(breached.breach.reason, BreachReason.COMPLIANCE)

        with self.assertRaises(CoreValidationError):
            retire_capability(
                activated,
                reason="provider exit",
                active_dependent_commitments=("capability/commitment/mtc-live",),
            )
        retired = retire_capability(
            activated,
            reason="provider exit",
            active_dependent_commitments=("capability/commitment/mtc-live",),
            successor_id="capability/capability/iss-ghana-2",
        )
        self.assertEqual(retired.state, CapabilityState.RETIRED)

        self.assertEqual(CapabilityRecord.from_json(retired.to_json()), retired)
        self.assertEqual(CapabilityCommitment.from_json(expired.to_json()), expired)
        self.assertEqual(CapabilityCommitment.from_json(breached.to_json()), breached)

    def test_sandbox_graph_persistence_and_tamper_rejection(self) -> None:
        capability = active()
        commitment = create_commitment(
            object_id=COMMITMENT_ID,
            capability=capability,
            terms=default_terms(),
            issuer=PROVIDER,
            source="dogfood",
            recorded_at=STAMP,
        )
        relationship = build_dependency_relationship(COMMITMENT_ID, CAPABILITY_ID)
        graph = ObjectGraph.build([capability.envelope, commitment.envelope], [relationship])

        encoded = graph.to_json()
        self.assertEqual(ObjectGraph.from_json(encoded), graph)
        self.assertEqual(ObjectGraph.from_json(encoded).to_json(), encoded)

        for tampered in (
            encoded.replace('"state":"ACTIVE"', '"state":"RETIRED"'),
            encoded.replace('"object_type":"capability/commitment/v1"', '"object_type":"payswap/obligation/v1"'),
        ):
            with self.assertRaises(CoreValidationError):
                ObjectGraph.from_json(tampered)


if __name__ == "__main__":
    unittest.main()
