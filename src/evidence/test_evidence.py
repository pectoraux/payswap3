"""Contract and discrimination test suite for the evidence domain (WORK-018).

Authored RED-FIRST against the declared public boundary of ``src.evidence``
before any implementation module exists. The suite covers:

- static boundary contracts (versions, internal non-registry object types,
  the closed epistemic-type vocabulary, forbidden sibling imports, no
  wall-clock/randomness/UUID in domain code);
- the frozen v0.1 command families — Evidence
  ``Submit/Verify/Reject/RevokeEvidence`` and Attestation
  ``Issue/Renew/RevokeAttestation`` — as explicit state machines with
  terminal states;
- epistemic-type discrimination (OBSERVED never masquerades as
  PREDICTED/SIMULATED and vice versa; cross-type confusion fails closed at
  submission and at consumption);
- freshness semantics (explicit ``as_of`` + half-open UTC windows; stale and
  pre-window evidence fails closed; staleness is never computed from a
  clock);
- provenance and append-only history (revocation is an explicit status
  transition; history is never rewritten; version chains are immutable);
- uncertainty as typed exact values (intervals, quantiles, bands with
  bounds validation; no float ambiguity);
- seal and tamper rejection, round-trip transformation completeness;
- the append-only archive backed by the transition kernel store
  (WORK-003) and the trust-domain issuer gate (WORK-004);
- DOGFOOD-018 conformance (decision reconstruction from evidence alone,
  sources partitioned by epistemic type).
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_json, canonical_sha256, loads_canonical

from src.evidence import (
    EVIDENCE_API_VERSION,
    ATTESTATION_OBJECT_TYPE,
    EVIDENCE_OBJECT_TYPE,
    EVIDENCE_PROTOCOL_VERSION,
    EVIDENCE_SCHEMA_VERSION,
    OBSERVATION_OBJECT_TYPE,
    UNCERTAINTY_OBJECT_TYPE,
    Attestation,
    AttestationRevocationReason,
    AttestationSpec,
    AttestationState,
    AttestedClaim,
    EpistemicType,
    Evidence,
    EvidenceArchive,
    EvidenceReasonCode,
    EvidenceSpec,
    EvidenceState,
    Observation,
    ObservationSpec,
    ObservationState,
    PayloadRef,
    PayloadRefKind,
    QuantilePoint,
    ScaledValue,
    Uncertainty,
    UncertaintyForm,
    UncertaintySpec,
    UncertaintyState,
    attestation_is_valid_at,
    check_payload_consistency,
    evidence_is_fresh,
    express_uncertainty,
    issue_attestation,
    observation_is_fresh,
    partition_evidence_by_epistemic_type,
    partition_observations_by_epistemic_type,
    record_observation,
    reject_evidence,
    renew_attestation,
    require_fresh_evidence,
    require_fresh_observation,
    require_observed_evidence,
    require_trusted_issuer,
    revoke_attestation,
    revoke_evidence,
    submit_evidence,
    verify_evidence,
)
from src.trust import TrustRegistry

ENV = "env/test"
DOMAIN = "domain/demo"
STAMP = "2026-09-02T00:00:00Z"

T0 = "2026-09-02T00:00:00Z"
T1 = "2026-09-02T00:30:00Z"
T2 = "2026-09-02T01:00:00Z"
T3 = "2026-09-02T02:00:00Z"
T4 = "2026-09-02T06:00:00Z"

SUBJECT = "account/wallet-7"
ISSUER = "trust/principal/issuer-7"
USD = "asset/USD"


def prov(source: str = "evidence/test") -> Provenance:
    return Provenance(
        issuer="principal/evidence-tester",
        source=source,
        recorded_at=STAMP,
        evidence_refs=(),
    )


def scaled(value: int, scale: int = 2, unit: str = USD) -> ScaledValue:
    return ScaledValue(value=value, scale=scale, unit=unit)


def observation_fixture(
    *,
    observation_id: str = "evidence/observation/obs-1",
    epistemic_type: EpistemicType = EpistemicType.OBSERVED,
    subject_ref: str = SUBJECT,
    value: ScaledValue | None = None,
    observed_at: str = T0,
    valid_from: str = T0,
    valid_until: str = T2,
) -> Observation:
    return record_observation(
        observation_id=observation_id,
        subject_ref=subject_ref,
        epistemic_type=epistemic_type,
        observed_at=observed_at,
        valid_from=valid_from,
        valid_until=valid_until,
        value=value if value is not None else scaled(125000),
        environment_id=ENV,
        domain_id=DOMAIN,
        provenance=prov("evidence/observation-fixture"),
    )


def attestation_fixture(
    *,
    attestation_id: str = "evidence/attestation/att-1",
    issuer: str = ISSUER,
    valid_from: str = T0,
    valid_until: str = T3,
) -> Attestation:
    return issue_attestation(
        attestation_id=attestation_id,
        issuer=issuer,
        subject_ref=SUBJECT,
        claims=(AttestedClaim(claim_key="balance-verified", claim_value=scaled(125000)),),
        issued_at=T0,
        valid_from=valid_from,
        valid_until=valid_until,
        evidence_refs=("evidence/observation/obs-1",),
        environment_id=ENV,
        domain_id=DOMAIN,
        provenance=prov("evidence/attestation-fixture"),
    )


def evidence_fixture(
    *,
    evidence_id: str = "evidence/evidence/ev-1",
    epistemic_type: EpistemicType = EpistemicType.OBSERVED,
    observations: tuple[Observation, ...] = (),
    attestations: tuple[Attestation, ...] = (),
    uncertainties: tuple[Uncertainty, ...] = (),
    observed_at: str = T1,
    valid_from: str = T1,
    valid_until: str = T2,
    value: ScaledValue | None = None,
) -> Evidence:
    return submit_evidence(
        evidence_id=evidence_id,
        epistemic_type=epistemic_type,
        subject_ref=SUBJECT,
        observed_at=observed_at,
        valid_from=valid_from,
        valid_until=valid_until,
        value=value if value is not None else scaled(125000),
        observations=observations,
        attestations=attestations,
        uncertainties=uncertainties,
        environment_id=ENV,
        domain_id=DOMAIN,
        provenance=prov("evidence/evidence-fixture"),
    )


def uncertainty_fixture(
    *, uncertainty_id: str = "evidence/uncertainty/unc-1"
) -> Uncertainty:
    return express_uncertainty(
        uncertainty_id=uncertainty_id,
        subject_ref=SUBJECT,
        form=UncertaintyForm.INTERVAL,
        scale=2,
        unit=USD,
        lower_bound=35000,
        upper_bound=45000,
        environment_id=ENV,
        domain_id=DOMAIN,
        provenance=prov("evidence/uncertainty-fixture"),
    )


def registry_fixture() -> TrustRegistry:
    registry = TrustRegistry(environment_id=ENV)
    registry.create_principal(
        principal_id=ISSUER,
        display_name="Issuer Seven",
        as_of=T0,
    )
    return registry


# ---------------------------------------------------------------------------
# 1. Static boundary contracts.
# ---------------------------------------------------------------------------


class StaticContractTests(unittest.TestCase):
    """The typed, versioned public boundary of the evidence domain."""

    def test_api_and_protocol_versions_are_frozen(self) -> None:
        self.assertEqual(EVIDENCE_API_VERSION, "v0.1")
        self.assertEqual(EVIDENCE_PROTOCOL_VERSION, "v0.1")
        self.assertEqual(EVIDENCE_SCHEMA_VERSION, 1)

    def test_object_types_are_internal_non_registry_formats(self) -> None:
        # The frozen protocol registry lists no evidence object type, so —
        # per the sibling convention — every evidence object type uses an
        # internal non-registry "evidence/..." format and never invents a
        # "payswap/..." registry name.
        for object_type in (
            EVIDENCE_OBJECT_TYPE,
            ATTESTATION_OBJECT_TYPE,
            OBSERVATION_OBJECT_TYPE,
            UNCERTAINTY_OBJECT_TYPE,
        ):
            self.assertTrue(object_type.startswith("evidence/"), object_type)
            self.assertFalse(object_type.startswith("payswap/"), object_type)

    def test_epistemic_type_vocabulary_is_closed_and_frozen(self) -> None:
        # The frozen simulation.md "Epistemic separation" vocabulary:
        # OBSERVED, ESTIMATED, PREDICTED, SIMULATED, COUNTERFACTUAL.
        self.assertEqual(
            {member.value for member in EpistemicType},
            {"OBSERVED", "ESTIMATED", "PREDICTED", "SIMULATED", "COUNTERFACTUAL"},
        )
        with self.assertRaises(ValueError):
            EpistemicType("HOPED_FOR")

    def test_lifecycle_state_vocabularies_are_closed(self) -> None:
        self.assertEqual(
            {state.value for state in EvidenceState},
            {"SUBMITTED", "VERIFIED", "REJECTED", "REVOKED"},
        )
        self.assertEqual(
            {state.value for state in AttestationState},
            {"ISSUED", "REVOKED"},
        )
        self.assertEqual(
            {state.value for state in ObservationState},
            {"RECORDED"},
        )
        self.assertEqual(
            {state.value for state in UncertaintyState},
            {"RECORDED"},
        )

    def test_reason_vocabularies_are_closed(self) -> None:
        self.assertEqual(
            {reason.value for reason in EvidenceReasonCode},
            {
                "UNVERIFIABLE",
                "STALE",
                "INCONSISTENT",
                "SOURCE_WITHDRAWN",
                "SUPERSEDED",
                "DISPUTED",
            },
        )
        self.assertEqual(
            {reason.value for reason in AttestationRevocationReason},
            {"ISSUER_WITHDRAWN", "SUBJECT_DISPUTED", "SUPERSEDED"},
        )

    def test_uncertainty_forms_and_payload_kinds_are_closed(self) -> None:
        self.assertEqual(
            {form.value for form in UncertaintyForm},
            {"INTERVAL", "QUANTILES", "BAND"},
        )
        self.assertEqual(
            {kind.value for kind in PayloadRefKind},
            {"OBSERVATION", "ATTESTATION", "UNCERTAINTY"},
        )

    def test_domain_never_imports_unmerged_or_forbidden_siblings(self) -> None:
        package = Path(__file__).parent
        for source in sorted(package.glob("*.py")):
            if source.name == "test_evidence.py":
                continue
            text = source.read_text(encoding="utf-8")
            for forbidden in (
                "src.market",
                "src.value",
                "src.money",
                "src.intent",
                "src.capability",
                "src.interoperability",
                "src.liquidity",
                "src.reservation",
                "src.safety",
            ):
                self.assertNotIn(
                    forbidden, text, f"{source.name} references {forbidden}"
                )

    def test_domain_code_has_no_wall_clock_randomness_or_uuids(self) -> None:
        package = Path(__file__).parent
        for source in sorted(package.glob("*.py")):
            if source.name in ("test_evidence.py", "dogfooding.py"):
                continue
            text = source.read_text(encoding="utf-8")
            for forbidden in (
                "time.time",
                "datetime.now",
                "utcnow",
                "random",
                "uuid",
                "time.monotonic",
            ):
                self.assertNotIn(
                    forbidden, text, f"{source.name} references {forbidden}"
                )

    def test_loaded_modules_never_include_forbidden_siblings(self) -> None:
        # Dynamic boundary: importing the public boundary may only load
        # stdlib, the domain itself, src.core and the declared consumed
        # dependency domains (src.transition, src.trust).
        import src.evidence  # noqa: F401  (boundary already imported above)

        forbidden_prefixes = (
            "src.market",
            "src.value",
            "src.money",
            "src.intent",
            "src.capability",
            "src.interoperability",
            "src.liquidity",
            "src.reservation",
            "src.safety",
        )
        for name in list(sys.modules):
            for prefix in forbidden_prefixes:
                self.assertFalse(name.startswith(prefix), f"loaded {name}")


# ---------------------------------------------------------------------------
# 2. Observations: epistemic type, freshness, immutability.
# ---------------------------------------------------------------------------


class ObservationTests(unittest.TestCase):
    """Observation records: what was observed, when, and for how long."""

    def test_record_observation_builds_a_sealed_recorded_record(self) -> None:
        observation = observation_fixture()
        self.assertEqual(observation.state, ObservationState.RECORDED)
        self.assertEqual(observation.envelope.object_type, OBSERVATION_OBJECT_TYPE)
        self.assertEqual(observation.envelope.object_version, 1)
        self.assertEqual(observation.envelope.schema_version, EVIDENCE_SCHEMA_VERSION)
        self.assertEqual(observation.envelope.protocol_version, EVIDENCE_PROTOCOL_VERSION)
        self.assertIsInstance(observation.envelope, ObjectEnvelope)
        observation.envelope.verify_integrity()

    def test_epistemic_type_is_carried_explicitly(self) -> None:
        for epistemic_type in EpistemicType:
            observation = observation_fixture(epistemic_type=epistemic_type)
            self.assertEqual(observation.spec.epistemic_type, epistemic_type)

    def test_unknown_epistemic_type_fails_closed(self) -> None:
        with self.assertRaises(CoreValidationError):
            ObservationSpec(
                subject_ref=SUBJECT,
                epistemic_type="HOPED_FOR",  # type: ignore[arg-type]
                observed_at=T0,
                valid_from=T0,
                valid_until=T2,
                value=scaled(125000),
            )

    def test_window_must_be_half_open_and_after_observation(self) -> None:
        # valid_until must be strictly after valid_from, and the window
        # may not start before the observation instant.
        with self.assertRaises(CoreValidationError):
            observation_fixture(valid_until=T0)  # empty window
        with self.assertRaises(CoreValidationError):
            observation_fixture(valid_from=T0, observed_at=T1)  # window starts pre-observation

    def test_timestamps_must_be_canonical_utc_z_form(self) -> None:
        with self.assertRaises(CoreValidationError):
            observation_fixture(observed_at="2026-09-02T00:00:00+02:00")
        with self.assertRaises(CoreValidationError):
            observation_fixture(valid_until="not-a-timestamp")

    def test_freshness_is_half_open(self) -> None:
        observation = observation_fixture(valid_from=T1, valid_until=T2)
        self.assertFalse(observation_is_fresh(observation, T0))  # before window
        self.assertTrue(observation_is_fresh(observation, T1))  # window start included
        self.assertTrue(observation_is_fresh(observation, "2026-09-02T00:59:59Z"))
        self.assertFalse(observation_is_fresh(observation, T2))  # window end excluded
        self.assertFalse(observation_is_fresh(observation, T4))  # long stale

    def test_require_fresh_observation_fails_closed_when_stale(self) -> None:
        observation = observation_fixture(valid_from=T1, valid_until=T2)
        require_fresh_observation(observation, T1)  # in-window passes
        with self.assertRaises(CoreValidationError):
            require_fresh_observation(observation, T2)
        with self.assertRaises(CoreValidationError):
            require_fresh_observation(observation, T0)

    def test_observed_values_are_exact_typed_scalars(self) -> None:
        observation = observation_fixture(value=ScaledValue(125000, 2, USD))
        self.assertEqual(observation.spec.value.value, 125000)
        self.assertEqual(observation.spec.value.scale, 2)
        self.assertEqual(observation.spec.value.unit, USD)
        with self.assertRaises(CoreValidationError):
            ScaledValue(value=125000.5, scale=2, unit=USD)  # type: ignore[arg-type]
        with self.assertRaises(CoreValidationError):
            ScaledValue(value=125000, scale=19, unit=USD)
        with self.assertRaises(CoreValidationError):
            ScaledValue(value=125000, scale=2, unit="")

    def test_observation_is_immutable_record_only(self) -> None:
        # Observations have no lifecycle commands: the vocabulary is the
        # single RECORDED state, and no transition function exists.
        observation = observation_fixture()
        self.assertEqual(len(ObservationState), 1)
        self.assertEqual(observation.envelope.object_version, 1)
        self.assertIsNone(observation.envelope.previous_version)

    def test_observation_round_trip_is_lossless(self) -> None:
        observation = observation_fixture(epistemic_type=EpistemicType.PREDICTED)
        decoded = Observation.from_json(observation.to_json())
        self.assertEqual(decoded.to_json(), observation.to_json())
        self.assertEqual(decoded.to_dict(), observation.to_dict())
        self.assertEqual(decoded.spec, observation.spec)

    def test_tampered_observation_fails_closed_on_decode(self) -> None:
        observation = observation_fixture()
        decoded = loads_canonical(observation.to_json())
        decoded["payload"]["value"]["value"] = 999999  # splice the observed value
        with self.assertRaises(CoreValidationError):
            Observation.from_dict(decoded)
        tampered_state = loads_canonical(observation.to_json())
        tampered_state["envelope"]["state"] = "FORGED"
        with self.assertRaises(CoreValidationError):
            Observation.from_dict(tampered_state)

    def test_non_canonical_observation_fields_fail_closed(self) -> None:
        observation = observation_fixture()
        decoded = loads_canonical(observation.to_json())
        decoded["payload"]["extra"] = 1
        with self.assertRaises(CoreValidationError):
            Observation.from_dict(decoded)


# ---------------------------------------------------------------------------
# 3. Uncertainty: typed exact representations with bounds validation.
# ---------------------------------------------------------------------------


class UncertaintyTests(unittest.TestCase):
    """Uncertainty as explicit typed values — no float ambiguity."""

    def test_interval_bounds_are_validated(self) -> None:
        uncertainty = uncertainty_fixture()
        self.assertEqual(uncertainty.spec.form, UncertaintyForm.INTERVAL)
        self.assertEqual(uncertainty.spec.lower_bound, 35000)
        self.assertEqual(uncertainty.spec.upper_bound, 45000)
        with self.assertRaises(CoreValidationError):
            express_uncertainty(
                uncertainty_id="evidence/uncertainty/bad",
                subject_ref=SUBJECT,
                form=UncertaintyForm.INTERVAL,
                scale=2,
                unit=USD,
                lower_bound=45000,
                upper_bound=35000,  # inverted bounds fail closed
                environment_id=ENV,
                domain_id=DOMAIN,
                provenance=prov(),
            )

    def test_interval_requires_both_bounds(self) -> None:
        with self.assertRaises(CoreValidationError):
            express_uncertainty(
                uncertainty_id="evidence/uncertainty/bad",
                subject_ref=SUBJECT,
                form=UncertaintyForm.INTERVAL,
                scale=2,
                unit=USD,
                lower_bound=35000,
                environment_id=ENV,
                domain_id=DOMAIN,
                provenance=prov(),
            )

    def test_quantiles_are_strictly_monotone_and_bounded(self) -> None:
        uncertainty = express_uncertainty(
            uncertainty_id="evidence/uncertainty/quant",
            subject_ref=SUBJECT,
            form=UncertaintyForm.QUANTILES,
            scale=2,
            unit=USD,
            points=(
                QuantilePoint(quantile_bps=1000, value=35000),
                QuantilePoint(quantile_bps=5000, value=40000),
                QuantilePoint(quantile_bps=9000, value=46000),
            ),
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=prov(),
        )
        self.assertEqual(uncertainty.spec.form, UncertaintyForm.QUANTILES)
        self.assertEqual(len(uncertainty.spec.points), 3)
        # duplicated quantile levels fail closed
        with self.assertRaises(CoreValidationError):
            express_uncertainty(
                uncertainty_id="evidence/uncertainty/bad",
                subject_ref=SUBJECT,
                form=UncertaintyForm.QUANTILES,
                scale=2,
                unit=USD,
                points=(
                    QuantilePoint(quantile_bps=5000, value=35000),
                    QuantilePoint(quantile_bps=5000, value=40000),
                ),
                environment_id=ENV,
                domain_id=DOMAIN,
                provenance=prov(),
            )
        # non-monotone values fail closed
        with self.assertRaises(CoreValidationError):
            express_uncertainty(
                uncertainty_id="evidence/uncertainty/bad",
                subject_ref=SUBJECT,
                form=UncertaintyForm.QUANTILES,
                scale=2,
                unit=USD,
                points=(
                    QuantilePoint(quantile_bps=1000, value=46000),
                    QuantilePoint(quantile_bps=9000, value=35000),
                ),
                environment_id=ENV,
                domain_id=DOMAIN,
                provenance=prov(),
            )
        # quantile levels outside [0, 10000] bps fail closed
        with self.assertRaises(CoreValidationError):
            QuantilePoint(quantile_bps=10001, value=35000)
        with self.assertRaises(CoreValidationError):
            QuantilePoint(quantile_bps=-1, value=35000)

    def test_quantiles_require_at_least_two_points(self) -> None:
        with self.assertRaises(CoreValidationError):
            express_uncertainty(
                uncertainty_id="evidence/uncertainty/bad",
                subject_ref=SUBJECT,
                form=UncertaintyForm.QUANTILES,
                scale=2,
                unit=USD,
                points=(QuantilePoint(quantile_bps=5000, value=40000),),
                environment_id=ENV,
                domain_id=DOMAIN,
                provenance=prov(),
            )

    def test_band_bounds_are_ordered(self) -> None:
        uncertainty = express_uncertainty(
            uncertainty_id="evidence/uncertainty/band",
            subject_ref=SUBJECT,
            form=UncertaintyForm.BAND,
            scale=2,
            unit=USD,
            central_value=40000,
            band_low=35000,
            band_high=46000,
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=prov(),
        )
        self.assertEqual(uncertainty.spec.central_value, 40000)
        with self.assertRaises(CoreValidationError):
            express_uncertainty(
                uncertainty_id="evidence/uncertainty/bad",
                subject_ref=SUBJECT,
                form=UncertaintyForm.BAND,
                scale=2,
                unit=USD,
                central_value=34000,  # below the band floor
                band_low=35000,
                band_high=46000,
                environment_id=ENV,
                domain_id=DOMAIN,
                provenance=prov(),
            )

    def test_forms_use_their_own_fields_only(self) -> None:
        # An INTERVAL may not carry quantile points or band fields: the
        # typed representation is unambiguous.
        with self.assertRaises(CoreValidationError):
            express_uncertainty(
                uncertainty_id="evidence/uncertainty/bad",
                subject_ref=SUBJECT,
                form=UncertaintyForm.INTERVAL,
                scale=2,
                unit=USD,
                lower_bound=35000,
                upper_bound=45000,
                points=(QuantilePoint(quantile_bps=1000, value=35000),),
                environment_id=ENV,
                domain_id=DOMAIN,
                provenance=prov(),
            )

    def test_uncertainty_values_reject_floats(self) -> None:
        with self.assertRaises(CoreValidationError):
            QuantilePoint(quantile_bps=1000, value=35000.5)  # type: ignore[arg-type]
        with self.assertRaises(CoreValidationError):
            ScaledValue(value=0.5, scale=2, unit=USD)  # type: ignore[arg-type]

    def test_uncertainty_bounds_accessor_is_deterministic(self) -> None:
        from src.evidence import uncertainty_bounds, value_within_bounds

        interval = uncertainty_fixture()
        self.assertEqual(uncertainty_bounds(interval), (35000, 45000))
        band = express_uncertainty(
            uncertainty_id="evidence/uncertainty/band",
            subject_ref=SUBJECT,
            form=UncertaintyForm.BAND,
            scale=2,
            unit=USD,
            central_value=40000,
            band_low=35000,
            band_high=46000,
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=prov(),
        )
        self.assertEqual(uncertainty_bounds(band), (35000, 46000))
        quantiles = express_uncertainty(
            uncertainty_id="evidence/uncertainty/quant",
            subject_ref=SUBJECT,
            form=UncertaintyForm.QUANTILES,
            scale=2,
            unit=USD,
            points=(
                QuantilePoint(quantile_bps=1000, value=35000),
                QuantilePoint(quantile_bps=9000, value=46000),
            ),
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=prov(),
        )
        self.assertEqual(uncertainty_bounds(quantiles), (35000, 46000))
        self.assertTrue(value_within_bounds(interval, 40000))
        self.assertFalse(value_within_bounds(interval, 45000))  # half-open bounds

    def test_uncertainty_round_trip_is_lossless(self) -> None:
        uncertainty = express_uncertainty(
            uncertainty_id="evidence/uncertainty/quant",
            subject_ref=SUBJECT,
            form=UncertaintyForm.QUANTILES,
            scale=2,
            unit=USD,
            points=(
                QuantilePoint(quantile_bps=1000, value=35000),
                QuantilePoint(quantile_bps=5000, value=40000),
            ),
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=prov(),
        )
        decoded = Uncertainty.from_json(uncertainty.to_json())
        self.assertEqual(decoded.to_json(), uncertainty.to_json())
        self.assertEqual(decoded.spec, uncertainty.spec)

    def test_tampered_uncertainty_fails_closed_on_decode(self) -> None:
        uncertainty = uncertainty_fixture()
        decoded = loads_canonical(uncertainty.to_json())
        decoded["payload"]["upper_bound"] = 1000000  # widen the interval
        with self.assertRaises(CoreValidationError):
            Uncertainty.from_dict(decoded)


# ---------------------------------------------------------------------------
# 4. Attestations: Issue/Renew/RevokeAttestation.
# ---------------------------------------------------------------------------


class AttestationTests(unittest.TestCase):
    """Who attested what, for which validity window."""

    def test_issue_builds_a_sealed_issued_attestation(self) -> None:
        attestation = attestation_fixture()
        self.assertEqual(attestation.state, AttestationState.ISSUED)
        self.assertEqual(attestation.envelope.object_type, ATTESTATION_OBJECT_TYPE)
        self.assertEqual(attestation.envelope.object_version, 1)
        attestation.envelope.verify_integrity()
        self.assertEqual(attestation.spec.issuer, ISSUER)

    def test_issuer_must_be_an_opaque_trust_principal_reference(self) -> None:
        with self.assertRaises(CoreValidationError):
            attestation_fixture(issuer="issuer-7")  # not a trust principal ref
        with self.assertRaises(CoreValidationError):
            attestation_fixture(issuer="")

    def test_attestation_window_is_half_open_and_after_issuance(self) -> None:
        with self.assertRaises(CoreValidationError):
            attestation_fixture(valid_until=T0)  # empty window
        with self.assertRaises(CoreValidationError):
            attestation_fixture(valid_from="2026-09-02T03:00:00+00:00", valid_until=T4)

    def test_claims_are_required_unique_and_typed(self) -> None:
        with self.assertRaises(CoreValidationError):
            issue_attestation(
                attestation_id="evidence/attestation/empty",
                issuer=ISSUER,
                subject_ref=SUBJECT,
                claims=(),  # an attestation attests something
                issued_at=T0,
                valid_from=T0,
                valid_until=T3,
                environment_id=ENV,
                domain_id=DOMAIN,
                provenance=prov(),
            )
        with self.assertRaises(CoreValidationError):
            issue_attestation(
                attestation_id="evidence/attestation/dup",
                issuer=ISSUER,
                subject_ref=SUBJECT,
                claims=(
                    AttestedClaim(claim_key="k", claim_value=scaled(1)),
                    AttestedClaim(claim_key="k", claim_value=scaled(2)),
                ),
                issued_at=T0,
                valid_from=T0,
                valid_until=T3,
                environment_id=ENV,
                domain_id=DOMAIN,
                provenance=prov(),
            )

    def test_attestation_validity_is_half_open(self) -> None:
        attestation = attestation_fixture(valid_from=T1, valid_until=T2)
        self.assertFalse(attestation_is_valid_at(attestation, T0))
        self.assertTrue(attestation_is_valid_at(attestation, T1))
        self.assertFalse(attestation_is_valid_at(attestation, T2))

    def test_revoked_attestation_is_never_valid(self) -> None:
        attestation = revoke_attestation(
            attestation_fixture(),
            reason=AttestationRevocationReason.ISSUER_WITHDRAWN,
            provenance=prov("evidence/revoke-attestation"),
        )
        self.assertEqual(attestation.state, AttestationState.REVOKED)
        self.assertFalse(attestation_is_valid_at(attestation, T1))

    def test_renew_creates_a_new_version_and_never_mutates(self) -> None:
        original = attestation_fixture(valid_from=T0, valid_until=T2)
        renewed = renew_attestation(
            original,
            valid_from=T0,
            valid_until=T3,
            provenance=prov("evidence/renew-attestation"),
        )
        self.assertIsNot(renewed, original)
        self.assertEqual(renewed.envelope.object_version, 2)
        self.assertEqual(renewed.envelope.previous_version, 1)
        self.assertEqual(renewed.state, AttestationState.ISSUED)
        # the attested content is preserved byte-for-byte
        self.assertEqual(renewed.spec.claims, original.spec.claims)
        self.assertEqual(renewed.spec.issuer, original.spec.issuer)
        self.assertEqual(renewed.spec.subject_ref, original.spec.subject_ref)
        # the original version is untouched (append-only history)
        self.assertEqual(original.envelope.object_version, 1)
        self.assertEqual(original.state, AttestationState.ISSUED)
        self.assertEqual(original.spec.valid_until, T2)

    def test_renewal_must_extend_the_validity_horizon(self) -> None:
        original = attestation_fixture(valid_from=T0, valid_until=T2)
        with self.assertRaises(CoreValidationError):
            renew_attestation(
                original,
                valid_from=T0,
                valid_until=T2,  # not an extension
                provenance=prov(),
            )
        with self.assertRaises(CoreValidationError):
            renew_attestation(
                original,
                valid_from=T0,
                valid_until=T1,  # shortening is not renewal
                provenance=prov(),
            )

    def test_renewal_requires_a_valid_half_open_window(self) -> None:
        original = attestation_fixture(valid_from=T0, valid_until=T2)
        with self.assertRaises(CoreValidationError):
            renew_attestation(
                original,
                valid_from=T1,
                valid_until=T1,  # empty window
                provenance=prov(),
            )

    def test_revoked_attestation_cannot_be_renewed(self) -> None:
        revoked = revoke_attestation(
            attestation_fixture(),
            reason=AttestationRevocationReason.SUBJECT_DISPUTED,
            provenance=prov(),
        )
        with self.assertRaises(CoreValidationError):
            renew_attestation(
                revoked,
                valid_from=T0,
                valid_until=T4,
                provenance=prov(),
            )

    def test_revoke_is_terminal_and_append_only(self) -> None:
        live = attestation_fixture()
        revoked = revoke_attestation(
            live,
            reason=AttestationRevocationReason.SUPERSEDED,
            provenance=prov("evidence/revoke-attestation"),
        )
        self.assertEqual(revoked.envelope.object_version, 2)
        self.assertEqual(revoked.envelope.previous_version, 1)
        self.assertEqual(revoked.state, AttestationState.REVOKED)
        # the pre-revocation version still says ISSUED, byte-identical
        self.assertEqual(live.state, AttestationState.ISSUED)
        self.assertEqual(live.envelope.object_version, 1)
        with self.assertRaises(CoreValidationError):
            revoke_attestation(
                revoked,
                reason=AttestationRevocationReason.ISSUER_WITHDRAWN,
                provenance=prov(),
            )

    def test_revocation_requires_a_closed_vocabulary_reason(self) -> None:
        with self.assertRaises(CoreValidationError):
            revoke_attestation(
                attestation_fixture(),
                reason="because",  # type: ignore[arg-type]
                provenance=prov(),
            )

    def test_trusted_issuer_gate_consumes_the_trust_domain(self) -> None:
        registry = registry_fixture()
        attestation = attestation_fixture()
        principal = require_trusted_issuer(attestation, registry)
        self.assertEqual(principal.principal_id, ISSUER)

    def test_trusted_issuer_gate_fails_closed_on_unknown_issuer(self) -> None:
        registry = TrustRegistry(environment_id=ENV)
        with self.assertRaises(CoreValidationError):
            require_trusted_issuer(attestation_fixture(), registry)

    def test_trusted_issuer_gate_fails_closed_on_retired_issuer(self) -> None:
        registry = registry_fixture()
        registry.create_principal(
            principal_id="trust/principal/operator-1",
            display_name="Operator One",
            as_of=T0,
        )
        registry.suspend_principal(
            principal_id=ISSUER,
            as_of=T1,
            operator="trust/principal/operator-1",
        )
        with self.assertRaises(CoreValidationError):
            require_trusted_issuer(attestation_fixture(), registry)

    def test_attestation_round_trip_is_lossless(self) -> None:
        attestation = attestation_fixture()
        decoded = Attestation.from_json(attestation.to_json())
        self.assertEqual(decoded.to_json(), attestation.to_json())
        self.assertEqual(decoded.spec, attestation.spec)

    def test_tampered_attestation_fails_closed_on_decode(self) -> None:
        attestation = attestation_fixture()
        decoded = loads_canonical(attestation.to_json())
        decoded["payload"]["issuer"] = "trust/principal/impostor"
        with self.assertRaises(CoreValidationError):
            Attestation.from_dict(decoded)


# ---------------------------------------------------------------------------
# 5. Evidence: Submit/Verify/Reject/RevokeEvidence.
# ---------------------------------------------------------------------------


class EvidenceLifecycleTests(unittest.TestCase):
    """The frozen Evidence command family as an explicit state machine."""

    def test_submit_builds_a_sealed_submitted_evidence(self) -> None:
        evidence = evidence_fixture()
        self.assertEqual(evidence.state, EvidenceState.SUBMITTED)
        self.assertEqual(evidence.envelope.object_type, EVIDENCE_OBJECT_TYPE)
        self.assertEqual(evidence.envelope.object_version, 1)
        evidence.envelope.verify_integrity()
        self.assertEqual(evidence.spec.epistemic_type, EpistemicType.OBSERVED)

    def test_evidence_window_is_half_open_and_after_observation(self) -> None:
        with self.assertRaises(CoreValidationError):
            evidence_fixture(valid_until=T1)  # empty window
        with self.assertRaises(CoreValidationError):
            evidence_fixture(observed_at=T2, valid_from=T1, valid_until=T2)

    def test_submit_builds_typed_payload_references(self) -> None:
        observation = observation_fixture()
        attestation = attestation_fixture()
        uncertainty = uncertainty_fixture()
        evidence = evidence_fixture(
            observations=(observation,),
            attestations=(attestation,),
            uncertainties=(uncertainty,),
        )
        self.assertEqual(
            evidence.spec.payload_refs,
            (
                PayloadRef(kind=PayloadRefKind.OBSERVATION, ref=observation.object_id),
                PayloadRef(kind=PayloadRefKind.ATTESTATION, ref=attestation.object_id),
                PayloadRef(kind=PayloadRefKind.UNCERTAINTY, ref=uncertainty.object_id),
            ),
        )

    def test_submit_rejects_duplicate_source_object_ids(self) -> None:
        observation = observation_fixture()
        with self.assertRaises(CoreValidationError):
            evidence_fixture(observations=(observation, observation))

    def test_verify_transitions_submitted_to_verified(self) -> None:
        evidence = evidence_fixture(valid_from=T1, valid_until=T2)
        verified = verify_evidence(
            evidence,
            as_of=T1,
            provenance=prov("evidence/verify"),
        )
        self.assertEqual(verified.state, EvidenceState.VERIFIED)
        self.assertEqual(verified.envelope.object_version, 2)
        self.assertEqual(verified.envelope.previous_version, 1)
        # the submitted version is preserved unchanged (append-only)
        self.assertEqual(evidence.state, EvidenceState.SUBMITTED)
        self.assertEqual(evidence.envelope.object_version, 1)
        # the evidenced content never changes across the transition
        self.assertEqual(verified.spec, evidence.spec)

    def test_verify_fails_closed_when_stale(self) -> None:
        evidence = evidence_fixture(valid_from=T1, valid_until=T2)
        with self.assertRaises(CoreValidationError):
            verify_evidence(evidence, as_of=T2, provenance=prov())  # window end
        with self.assertRaises(CoreValidationError):
            verify_evidence(evidence, as_of=T4, provenance=prov())  # long stale

    def test_verify_fails_closed_before_the_window_opens(self) -> None:
        evidence = evidence_fixture(valid_from=T1, valid_until=T2)
        with self.assertRaises(CoreValidationError):
            verify_evidence(evidence, as_of=T0, provenance=prov())

    def test_verify_is_only_valid_from_submitted(self) -> None:
        evidence = verify_evidence(
            evidence_fixture(),
            as_of=T1,
            provenance=prov(),
        )
        with self.assertRaises(CoreValidationError):
            verify_evidence(evidence, as_of=T1, provenance=prov())
        rejected = reject_evidence(
            evidence_fixture(evidence_id="evidence/evidence/ev-2"),
            reason=EvidenceReasonCode.UNVERIFIABLE,
            provenance=prov(),
        )
        with self.assertRaises(CoreValidationError):
            verify_evidence(rejected, as_of=T1, provenance=prov())

    def test_reject_transitions_submitted_to_rejected_terminal(self) -> None:
        evidence = evidence_fixture()
        rejected = reject_evidence(
            evidence,
            reason=EvidenceReasonCode.INCONSISTENT,
            provenance=prov("evidence/reject"),
        )
        self.assertEqual(rejected.state, EvidenceState.REJECTED)
        self.assertEqual(rejected.envelope.object_version, 2)
        with self.assertRaises(CoreValidationError):
            reject_evidence(rejected, reason=EvidenceReasonCode.STALE, provenance=prov())
        with self.assertRaises(CoreValidationError):
            revoke_evidence(
                rejected,
                reason=EvidenceReasonCode.SOURCE_WITHDRAWN,
                provenance=prov(),
            )

    def test_verified_evidence_cannot_be_rejected(self) -> None:
        # rejection is a pre-verification refusal; afterwards only
        # revocation (an explicit status transition) is possible.
        verified = verify_evidence(
            evidence_fixture(),
            as_of=T1,
            provenance=prov(),
        )
        with self.assertRaises(CoreValidationError):
            reject_evidence(verified, reason=EvidenceReasonCode.STALE, provenance=prov())

    def test_revoke_is_an_explicit_terminal_status_transition(self) -> None:
        verified = verify_evidence(
            evidence_fixture(),
            as_of=T1,
            provenance=prov(),
        )
        revoked = revoke_evidence(
            verified,
            reason=EvidenceReasonCode.SOURCE_WITHDRAWN,
            provenance=prov("evidence/revoke"),
        )
        self.assertEqual(revoked.state, EvidenceState.REVOKED)
        self.assertEqual(revoked.envelope.object_version, 3)
        self.assertEqual(revoked.envelope.previous_version, 2)
        with self.assertRaises(CoreValidationError):
            revoke_evidence(
                revoked,
                reason=EvidenceReasonCode.SUPERSEDED,
                provenance=prov(),
            )
        with self.assertRaises(CoreValidationError):
            verify_evidence(revoked, as_of=T1, provenance=prov())

    def test_revoke_from_submitted_is_allowed(self) -> None:
        revoked = revoke_evidence(
            evidence_fixture(),
            reason=EvidenceReasonCode.SUPERSEDED,
            provenance=prov(),
        )
        self.assertEqual(revoked.state, EvidenceState.REVOKED)

    def test_revocation_never_rewrites_history(self) -> None:
        # Constitution invariant 17: historical financial evidence is
        # append-only. The submitted and verified versions keep their
        # exact bytes and states after revocation.
        submitted = evidence_fixture()
        verified = verify_evidence(submitted, as_of=T1, provenance=prov())
        submitted_json = submitted.to_json()
        verified_json = verified.to_json()
        revoked = revoke_evidence(verified, reason=EvidenceReasonCode.DISPUTED, provenance=prov())
        self.assertEqual(submitted.to_json(), submitted_json)
        self.assertEqual(verified.to_json(), verified_json)
        self.assertEqual(revoked.envelope.object_version, 3)
        self.assertEqual(revoked.envelope.previous_version, 2)

    def test_rejection_and_revocation_reasons_are_closed_vocabularies(self) -> None:
        with self.assertRaises(CoreValidationError):
            reject_evidence(
                evidence_fixture(),
                reason="vibes",  # type: ignore[arg-type]
                provenance=prov(),
            )
        with self.assertRaises(CoreValidationError):
            revoke_evidence(
                evidence_fixture(),
                reason="vibes",  # type: ignore[arg-type]
                provenance=prov(),
            )

    def test_evidence_freshness_is_half_open(self) -> None:
        evidence = evidence_fixture(valid_from=T1, valid_until=T2)
        self.assertFalse(evidence_is_fresh(evidence, T0))
        self.assertTrue(evidence_is_fresh(evidence, T1))
        self.assertFalse(evidence_is_fresh(evidence, T2))
        require_fresh_evidence(evidence, T1)
        with self.assertRaises(CoreValidationError):
            require_fresh_evidence(evidence, T4)


class EpistemicDiscriminationTests(unittest.TestCase):
    """OBSERVED never masquerades as PREDICTED/SIMULATED, and vice versa."""

    def test_submit_rejects_cross_type_observation_references(self) -> None:
        # An OBSERVED evidence record may only rest on OBSERVED
        # observations; a PREDICTED or SIMULATED source fails closed.
        predicted_observation = observation_fixture(
            epistemic_type=EpistemicType.PREDICTED
        )
        with self.assertRaises(CoreValidationError):
            evidence_fixture(observations=(predicted_observation,))
        simulated_observation = observation_fixture(
            epistemic_type=EpistemicType.SIMULATED
        )
        with self.assertRaises(CoreValidationError):
            evidence_fixture(observations=(simulated_observation,))

    def test_predicted_evidence_cannot_rest_on_observed_sources(self) -> None:
        observed_observation = observation_fixture(epistemic_type=EpistemicType.OBSERVED)
        with self.assertRaises(CoreValidationError):
            evidence_fixture(
                epistemic_type=EpistemicType.PREDICTED,
                observations=(observed_observation,),
            )

    def test_simulated_evidence_cannot_rest_on_observed_sources(self) -> None:
        observed_observation = observation_fixture(epistemic_type=EpistemicType.OBSERVED)
        with self.assertRaises(CoreValidationError):
            evidence_fixture(
                epistemic_type=EpistemicType.SIMULATED,
                observations=(observed_observation,),
            )

    def test_homogeneous_sources_are_accepted_for_every_type(self) -> None:
        for epistemic_type in EpistemicType:
            observation = observation_fixture(epistemic_type=epistemic_type)
            evidence = evidence_fixture(
                epistemic_type=epistemic_type,
                observations=(observation,),
            )
            self.assertEqual(evidence.spec.epistemic_type, epistemic_type)

    def test_check_payload_consistency_rejects_cross_type_after_decode(self) -> None:
        observation = observation_fixture(epistemic_type=EpistemicType.OBSERVED)
        evidence = evidence_fixture(
            epistemic_type=EpistemicType.OBSERVED,
            observations=(observation,),
        )
        check_payload_consistency(evidence, observations=(observation,))
        predicted_observation = observation_fixture(
            epistemic_type=EpistemicType.PREDICTED,
        )
        with self.assertRaises(CoreValidationError):
            check_payload_consistency(
                evidence,
                observations=(observation, predicted_observation),
            )
        # missing referenced records fail closed
        with self.assertRaises(CoreValidationError):
            check_payload_consistency(evidence, observations=())

    def test_require_observed_evidence_fails_closed_on_simulation(self) -> None:
        observed = evidence_fixture(epistemic_type=EpistemicType.OBSERVED)
        predicted = evidence_fixture(
            evidence_id="evidence/evidence/ev-p",
            epistemic_type=EpistemicType.PREDICTED,
        )
        simulated = evidence_fixture(
            evidence_id="evidence/evidence/ev-s",
            epistemic_type=EpistemicType.SIMULATED,
        )
        self.assertEqual(
            require_observed_evidence((observed,)),
            (observed,),
        )
        with self.assertRaises(CoreValidationError):
            require_observed_evidence((observed, predicted))
        with self.assertRaises(CoreValidationError):
            require_observed_evidence((simulated,))

    def test_partition_by_epistemic_type_is_deterministic(self) -> None:
        observed = evidence_fixture(epistemic_type=EpistemicType.OBSERVED)
        predicted = evidence_fixture(
            evidence_id="evidence/evidence/ev-p",
            epistemic_type=EpistemicType.PREDICTED,
        )
        simulated = evidence_fixture(
            evidence_id="evidence/evidence/ev-s",
            epistemic_type=EpistemicType.SIMULATED,
        )
        partition = partition_evidence_by_epistemic_type(
            (simulated, predicted, observed, predicted)
        )
        self.assertEqual(partition[EpistemicType.OBSERVED], (observed,))
        self.assertEqual(partition[EpistemicType.PREDICTED], (predicted, predicted))
        self.assertEqual(partition[EpistemicType.SIMULATED], (simulated,))
        self.assertEqual(
            set(partition), set(EpistemicType)
        )

    def test_partition_observations_by_epistemic_type(self) -> None:
        observed = observation_fixture(epistemic_type=EpistemicType.OBSERVED)
        simulated = observation_fixture(
            observation_id="evidence/observation/obs-s",
            epistemic_type=EpistemicType.SIMULATED,
        )
        partition = partition_observations_by_epistemic_type((simulated, observed))
        self.assertEqual(partition[EpistemicType.OBSERVED], (observed,))
        self.assertEqual(partition[EpistemicType.SIMULATED], (simulated,))

    def test_epistemic_type_is_immutable_across_versions(self) -> None:
        # No transition can change the epistemic type: a predicted value
        # can never be sealed as OBSERVED. Transitions carry the sealed
        # payload unchanged, and a spliced payload that flips the type
        # fails closed on decode.
        evidence = evidence_fixture(epistemic_type=EpistemicType.PREDICTED)
        verified = verify_evidence(evidence, as_of=T1, provenance=prov())
        self.assertEqual(verified.spec.epistemic_type, EpistemicType.PREDICTED)
        self.assertEqual(verified.spec, evidence.spec)
        spliced = loads_canonical(verified.to_json())
        spliced["payload"]["epistemic_type"] = "OBSERVED"
        with self.assertRaises(CoreValidationError):
            Evidence.from_dict(spliced)


# ---------------------------------------------------------------------------
# 6. Append-only archive (transition-kernel backed store).
# ---------------------------------------------------------------------------


class EvidenceArchiveTests(unittest.TestCase):
    """The evidence archive: append-only history, never rewritten."""

    def test_append_and_get_latest(self) -> None:
        archive = EvidenceArchive()
        evidence = evidence_fixture()
        archive.append(evidence)
        self.assertIs(archive.get("evidence/evidence/ev-1"), evidence)

    def test_get_fails_closed_on_unknown_records(self) -> None:
        archive = EvidenceArchive()
        with self.assertRaises(CoreValidationError):
            archive.get("evidence/evidence/missing")

    def test_append_rejects_history_rewrites(self) -> None:
        # Appending an already-recorded version is a rewrite attempt and
        # fails closed (constitution invariant 17).
        archive = EvidenceArchive()
        evidence = evidence_fixture()
        archive.append(evidence)
        with self.assertRaises(CoreValidationError):
            archive.append(evidence)  # re-appending version 1
        verified = verify_evidence(evidence, as_of=T1, provenance=prov())
        archive.append(verified)  # exact next version is the append path
        with self.assertRaises(CoreValidationError):
            archive.append(verified)  # replaying the latest version

    def test_append_rejects_version_jumps(self) -> None:
        archive = EvidenceArchive()
        evidence = evidence_fixture()
        archive.append(evidence)
        verified = verify_evidence(evidence, as_of=T1, provenance=prov())
        revoked = revoke_evidence(
            verified, reason=EvidenceReasonCode.DISPUTED, provenance=prov()
        )
        with self.assertRaises(CoreValidationError):
            archive.append(revoked)  # version 3 over stored version 1

    def test_history_is_append_only_and_ordered(self) -> None:
        archive = EvidenceArchive()
        submitted = evidence_fixture()
        archive.append(submitted)
        verified = verify_evidence(submitted, as_of=T1, provenance=prov())
        archive.append(verified)
        revoked = revoke_evidence(
            verified, reason=EvidenceReasonCode.DISPUTED, provenance=prov()
        )
        archive.append(revoked)
        history = archive.history("evidence/evidence/ev-1")
        self.assertEqual(
            [record.envelope.object_version for record in history], [1, 2, 3]
        )
        self.assertEqual(
            [record.state for record in history],
            [EvidenceState.SUBMITTED, EvidenceState.VERIFIED, EvidenceState.REVOKED],
        )
        # the original bytes are unchanged after later appends
        self.assertEqual(history[0].to_json(), submitted.to_json())
        self.assertIs(archive.get_version("evidence/evidence/ev-1", 2), verified)

    def test_get_version_fails_closed_when_absent(self) -> None:
        archive = EvidenceArchive()
        archive.append(evidence_fixture())
        with self.assertRaises(CoreValidationError):
            archive.get_version("evidence/evidence/ev-1", 7)
        with self.assertRaises(CoreValidationError):
            archive.get_version("evidence/evidence/missing", 1)

    def test_mixed_record_types_share_the_archive(self) -> None:
        archive = EvidenceArchive()
        observation = observation_fixture()
        attestation = attestation_fixture()
        uncertainty = uncertainty_fixture()
        evidence = evidence_fixture(
            observations=(observation,),
            attestations=(attestation,),
            uncertainties=(uncertainty,),
        )
        for record in (observation, attestation, uncertainty, evidence):
            archive.append(record)
        self.assertIs(archive.get(observation.object_id), observation)
        self.assertIs(archive.get(attestation.object_id), attestation)
        self.assertIs(archive.get(uncertainty.object_id), uncertainty)
        self.assertIs(archive.get(evidence.object_id), evidence)
        self.assertEqual(len(archive.latest()), 4)

    def test_one_object_id_hosts_exactly_one_record_kind(self) -> None:
        # Identity (object type, environment, schema, protocol) is frozen
        # across versions of one object id: a second record kind under
        # the same id fails closed at the kernel-backed append gate.
        archive = EvidenceArchive()
        observation = observation_fixture(observation_id="evidence/shared-id")
        archive.append(observation)
        attestation = attestation_fixture(attestation_id="evidence/shared-id")
        with self.assertRaises(CoreValidationError):
            archive.append(attestation)

    def test_latest_is_deterministically_ordered(self) -> None:
        archive = EvidenceArchive()
        records = [
            evidence_fixture(evidence_id=f"evidence/evidence/ev-{index}")
            for index in range(3, 0, -1)
        ]
        for record in records:
            archive.append(record)
        self.assertEqual(
            [record.object_id for record in archive.latest()],
            [
                "evidence/evidence/ev-1",
                "evidence/evidence/ev-2",
                "evidence/evidence/ev-3",
            ],
        )

    def test_archive_digest_is_deterministic(self) -> None:
        archive_a = EvidenceArchive()
        archive_b = EvidenceArchive()
        for index in (1, 2):
            archive_a.append(
                evidence_fixture(evidence_id=f"evidence/evidence/ev-{index}")
            )
        for index in (1, 2):
            archive_b.append(
                evidence_fixture(evidence_id=f"evidence/evidence/ev-{index}")
            )
        self.assertEqual(archive_a.archive_digest(), archive_b.archive_digest())


# ---------------------------------------------------------------------------
# 7. Transformation completeness: round-trips are lossless and byte-stable.
# ---------------------------------------------------------------------------


class TransformationCompletenessTests(unittest.TestCase):
    """Round-trips preserve every object byte-for-byte (W002/W032 pattern)."""

    ROUND_TRIP_CASES = (
        ("evidence", lambda: evidence_fixture()),
        ("observation", observation_fixture),
        ("attestation", attestation_fixture),
        ("uncertainty", uncertainty_fixture),
    )

    def test_json_round_trips_are_byte_stable(self) -> None:
        for _name, factory in self.ROUND_TRIP_CASES:
            with self.subTest(case=_name):
                record = factory()
                once = record.from_json(record.to_json())
                twice = once.from_json(once.to_json())
                self.assertEqual(record.to_json(), once.to_json())
                self.assertEqual(once.to_json(), twice.to_json())

    def test_dict_round_trips_are_lossless(self) -> None:
        for name, factory in self.ROUND_TRIP_CASES:
            with self.subTest(case=name):
                record = factory()
                decoded = record.from_dict(record.to_dict())
                self.assertEqual(decoded.to_dict(), record.to_dict())

    def test_round_trips_preserve_version_chains(self) -> None:
        evidence = verify_evidence(evidence_fixture(), as_of=T1, provenance=prov())
        decoded = Evidence.from_json(evidence.to_json())
        self.assertEqual(decoded.envelope.object_version, 2)
        self.assertEqual(decoded.envelope.previous_version, 1)
        self.assertEqual(decoded.state, EvidenceState.VERIFIED)
        self.assertEqual(decoded.envelope.integrity_hash, evidence.envelope.integrity_hash)

    def test_renewed_attestation_round_trips(self) -> None:
        renewed = renew_attestation(
            attestation_fixture(),
            valid_from=T0,
            valid_until=T4,
            provenance=prov(),
        )
        decoded = Attestation.from_json(renewed.to_json())
        self.assertEqual(decoded.envelope.object_version, 2)
        self.assertEqual(decoded.spec.valid_until, T4)

    def test_decode_rejects_duplicate_keys(self) -> None:
        evidence = evidence_fixture()
        raw = evidence.to_json()
        # splice a duplicate key into the JSON text
        duplicated = raw[:-1] + ',"object_id":"evidence/evidence/ev-1"}'
        with self.assertRaises(CoreValidationError):
            Evidence.from_json(duplicated)

    def test_decode_rejects_non_canonical_envelopes(self) -> None:
        evidence = evidence_fixture()
        decoded = loads_canonical(evidence.to_json())
        decoded["envelope"].pop("correlation_id")
        with self.assertRaises(CoreValidationError):
            Evidence.from_dict(decoded)

    def test_wrong_object_type_fails_closed_on_decode(self) -> None:
        observation = observation_fixture()
        with self.assertRaises(CoreValidationError):
            Evidence.from_dict(observation.to_dict())

    def test_canonical_json_of_records_is_stable_across_processes(self) -> None:
        # The canonical serialization of a record is a pure function of
        # its content: identical fixtures serialize to identical bytes.
        first = canonical_json(evidence_fixture().to_dict())
        second = canonical_json(evidence_fixture().to_dict())
        self.assertEqual(first, second)
        self.assertEqual(
            canonical_sha256(loads_canonical(first)),
            canonical_sha256(evidence_fixture().to_dict()),
        )


# ---------------------------------------------------------------------------
# 8. DOGFOOD-018 conformance.
# ---------------------------------------------------------------------------


class DogfoodingTests(unittest.TestCase):
    """Decision reconstruction from evidence alone is deterministic."""

    def test_transcript_is_deterministic_with_a_stable_digest(self) -> None:
        from src.evidence.dogfooding import build_transcript

        transcript_a, digest_a = build_transcript()
        transcript_b, digest_b = build_transcript()
        self.assertEqual(transcript_a, transcript_b)
        self.assertEqual(digest_a, digest_b)
        self.assertEqual(digest_a, canonical_sha256({"transcript": transcript_a}))

    def test_transcript_partitions_sources_by_epistemic_type(self) -> None:
        from src.evidence.dogfooding import build_transcript

        transcript, _digest = build_transcript()
        self.assertIn("sources.observed=", transcript)
        self.assertIn("sources.predicted=", transcript)
        self.assertIn("sources.simulated=", transcript)
        self.assertIn("epistemic_partition.OBSERVED=", transcript)
        self.assertIn("epistemic_partition.PREDICTED=", transcript)
        self.assertIn("epistemic_partition.SIMULATED=", transcript)

    def test_transcript_reports_byte_identical_reconstruction(self) -> None:
        from src.evidence.dogfooding import build_transcript

        transcript, _digest = build_transcript()
        self.assertIn("reconstruction.byte_identical=True", transcript)
        self.assertIn("reconstruction.rebuilt_digest=", transcript)
        self.assertIn("DOGFOOD-018: PASS", transcript)

    def test_transcript_reports_the_verdict_decision(self) -> None:
        from src.evidence.dogfooding import build_transcript

        transcript, _digest = build_transcript()
        self.assertIn("decision.verdict=", transcript)
        self.assertIn("decision.worst_case_exposure=", transcript)
        self.assertIn("as_of=", transcript)

    def test_main_returns_the_digest(self) -> None:
        from src.evidence.dogfooding import build_transcript, main

        self.assertEqual(main(), build_transcript()[1])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
