"""DOGFOOD-018: reconstruct a decision from evidence alone.

The dogfooding/conformance contract of WORK-018: build a typed decision
(an exposure verdict over one account) from a set of evidence records —
observed, predicted and simulated — then reconstruct the decision from
the evidence alone: the full version history of the evidence set is
serialized to canonical JSON, every record is rebuilt through the
trusted deserialization path, the append-only archive is replayed, and
the decision is re-evaluated deterministically. The reconstruction is
byte-identical (same decision digest, same archive digest) and the
reconstruction source list is partitioned by epistemic type and
reported. The attestation issuer is gated through the real trust
registry (WORK-004) and the archive replay runs through the transition
kernel store (WORK-003). Everything is explicit: ``as_of``, provenance
and deterministic windows — no clock, no entropy sources.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.core.serialization import canonical_sha256
from src.trust import TrustRegistry

from . import (
    Attestation,
    EpistemicType,
    Evidence,
    EvidenceArchive,
    EvidenceState,
    Observation,
    PayloadRefKind,
    ScaledValue,
    Uncertainty,
    UncertaintyForm,
    uncertainty_bounds,
    partition_evidence_by_epistemic_type,
    partition_observations_by_epistemic_type,
    record_observation,
    require_fresh_evidence,
    require_trusted_issuer,
    express_uncertainty,
    issue_attestation,
    AttestedClaim,
    submit_evidence,
    verify_evidence,
)
from src.core.envelope import Provenance

ENV = "env/test"
DOMAIN = "domain/demo"
STAMP = "2026-09-02T00:00:00Z"
T0 = "2026-09-02T00:00:00Z"
T1 = "2026-09-02T00:30:00Z"
T2 = "2026-09-02T01:00:00Z"
T3 = "2026-09-02T02:00:00Z"

AS_OF = "2026-09-02T00:45:00Z"
SUBJECT = "account/wallet-7"
ISSUER = "trust/principal/bank-7"
USD = "asset/USD"

#: Exposure limit of the decision, in exact minor units.
EXPOSURE_LIMIT = 210000


def prov(source: str) -> Provenance:
    return Provenance(
        issuer="principal/evidence-operator",
        source=source,
        recorded_at=STAMP,
        evidence_refs=(),
    )


@dataclass(frozen=True, slots=True)
class ExposureVerdict:
    """The typed decision reconstructed from the evidence set."""

    as_of: str
    limit: int
    verdict: str
    observed_exposure: int
    predicted_exposure: int
    simulated_exposure: int
    predicted_worst_case: int
    simulated_worst_case: int
    worst_case_exposure: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "as_of": self.as_of,
            "limit": self.limit,
            "verdict": self.verdict,
            "observed_exposure": self.observed_exposure,
            "predicted_exposure": self.predicted_exposure,
            "simulated_exposure": self.simulated_exposure,
            "predicted_worst_case": self.predicted_worst_case,
            "simulated_worst_case": self.simulated_worst_case,
            "worst_case_exposure": self.worst_case_exposure,
        }

    def digest(self) -> str:
        return canonical_sha256(self.to_dict())


def build_registry() -> TrustRegistry:
    registry = TrustRegistry(environment_id=ENV)
    registry.create_principal(
        principal_id=ISSUER,
        display_name="Bank Seven",
        as_of=T0,
    )
    return registry


def _observations() -> tuple[Observation, Observation, Observation]:
    observed = record_observation(
        observation_id="evidence/observation/obs-balance",
        subject_ref=SUBJECT,
        epistemic_type=EpistemicType.OBSERVED,
        observed_at=T0,
        valid_from=T0,
        valid_until=T2,
        value=ScaledValue(value=125000, scale=2, unit=USD),
        environment_id=ENV,
        domain_id=DOMAIN,
        provenance=prov("evidence/observation/balance"),
    )
    predicted = record_observation(
        observation_id="evidence/observation/obs-inflow",
        subject_ref=SUBJECT,
        epistemic_type=EpistemicType.PREDICTED,
        observed_at=T0,
        valid_from=T0,
        valid_until=T2,
        value=ScaledValue(value=40000, scale=2, unit=USD),
        environment_id=ENV,
        domain_id=DOMAIN,
        provenance=prov("evidence/observation/inflow-forecast"),
    )
    simulated = record_observation(
        observation_id="evidence/observation/obs-stress",
        subject_ref=SUBJECT,
        epistemic_type=EpistemicType.SIMULATED,
        observed_at=T0,
        valid_from=T0,
        valid_until=T2,
        value=ScaledValue(value=30000, scale=2, unit=USD),
        environment_id=ENV,
        domain_id=DOMAIN,
        provenance=prov("evidence/observation/stress-world"),
    )
    return observed, predicted, simulated


def _attestation() -> Attestation:
    return issue_attestation(
        attestation_id="evidence/attestation/att-balance",
        issuer=ISSUER,
        subject_ref=SUBJECT,
        claims=(AttestedClaim(claim_key="balance-verified", claim_value=ScaledValue(125000, 2, USD)),),
        issued_at=T0,
        valid_from=T0,
        valid_until=T3,
        evidence_refs=("evidence/observation/obs-balance",),
        environment_id=ENV,
        domain_id=DOMAIN,
        provenance=prov("evidence/attestation/bank-statement"),
    )


def _uncertainties() -> tuple[Uncertainty, Uncertainty, Uncertainty]:
    observed = express_uncertainty(
        uncertainty_id="evidence/uncertainty/unc-observed",
        subject_ref=SUBJECT,
        form=UncertaintyForm.INTERVAL,
        scale=2,
        unit=USD,
        lower_bound=124500,
        upper_bound=125500,
        environment_id=ENV,
        domain_id=DOMAIN,
        provenance=prov("evidence/uncertainty/observed-balance"),
    )
    predicted = express_uncertainty(
        uncertainty_id="evidence/uncertainty/unc-predicted",
        subject_ref=SUBJECT,
        form=UncertaintyForm.INTERVAL,
        scale=2,
        unit=USD,
        lower_bound=35000,
        upper_bound=45000,
        environment_id=ENV,
        domain_id=DOMAIN,
        provenance=prov("evidence/uncertainty/inflow-forecast"),
    )
    simulated = express_uncertainty(
        uncertainty_id="evidence/uncertainty/unc-simulated",
        subject_ref=SUBJECT,
        form=UncertaintyForm.BAND,
        scale=2,
        unit=USD,
        central_value=30000,
        band_low=25000,
        band_high=35000,
        environment_id=ENV,
        domain_id=DOMAIN,
        provenance=prov("evidence/uncertainty/stress-world"),
    )
    return observed, predicted, simulated


def _evidence_history() -> tuple[tuple[Evidence, Evidence], ...]:
    """Build each evidence record and its verified successor version."""
    observed_obs, predicted_obs, simulated_obs = _observations()
    attestation = _attestation()
    unc_observed, unc_predicted, unc_simulated = _uncertainties()

    legs = (
        (
            "evidence/evidence/ev-observed",
            EpistemicType.OBSERVED,
            ScaledValue(value=125000, scale=2, unit=USD),
            (observed_obs,),
            (attestation,),
            (unc_observed,),
        ),
        (
            "evidence/evidence/ev-predicted",
            EpistemicType.PREDICTED,
            ScaledValue(value=40000, scale=2, unit=USD),
            (predicted_obs,),
            (),
            (unc_predicted,),
        ),
        (
            "evidence/evidence/ev-simulated",
            EpistemicType.SIMULATED,
            ScaledValue(value=30000, scale=2, unit=USD),
            (simulated_obs,),
            (),
            (unc_simulated,),
        ),
    )
    history: list[tuple[Evidence, Evidence]] = []
    for evidence_id, epistemic_type, value, observations, attestations, uncertainties in legs:
        submitted = submit_evidence(
            evidence_id=evidence_id,
            epistemic_type=epistemic_type,
            subject_ref=SUBJECT,
            observed_at=T1,
            valid_from=T1,
            valid_until=T2,
            value=value,
            observations=observations,
            attestations=attestations,
            uncertainties=uncertainties,
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=prov("evidence/submit"),
        )
        verified = verify_evidence(
            submitted, as_of=AS_OF, provenance=prov("evidence/verify")
        )
        history.append((submitted, verified))
    return tuple(history)


def evaluate_exposure_verdict(
    evidences: tuple[Evidence, ...],
    uncertainties: tuple[Uncertainty, ...],
    *,
    as_of: str,
    limit: int,
) -> ExposureVerdict:
    """Re-evaluate the decision deterministically from evidence alone.

    Every evidence record must be VERIFIED and fresh at ``as_of`` (fail
    closed otherwise). Observed values are ground; predicted and
    simulated values contribute their worst-case bound from the
    referenced typed uncertainty (interval upper / band high), falling
    back to the evidenced value when no uncertainty is referenced.
    """
    for evidence in evidences:
        if evidence.state is not EvidenceState.VERIFIED:
            raise ValueError(
                f"decision inputs must be VERIFIED evidence; "
                f"{evidence.object_id} is {evidence.state.value}"
            )
        require_fresh_evidence(evidence, as_of)
    uncertainty_map = {uncertainty.object_id: uncertainty for uncertainty in uncertainties}
    partition = partition_evidence_by_epistemic_type(evidences)

    def worst_case(evidence: Evidence, default: int) -> int:
        for ref in evidence.spec.payload_refs:
            if ref.kind is PayloadRefKind.UNCERTAINTY:
                _, high = uncertainty_bounds(uncertainty_map[ref.ref])
                return high
        return default

    observed_exposure = sum(
        evidence.spec.value.value for evidence in partition[EpistemicType.OBSERVED]
    )
    predicted_exposure = sum(
        evidence.spec.value.value for evidence in partition[EpistemicType.PREDICTED]
    )
    simulated_exposure = sum(
        evidence.spec.value.value for evidence in partition[EpistemicType.SIMULATED]
    )
    predicted_worst = sum(
        worst_case(evidence, evidence.spec.value.value)
        for evidence in partition[EpistemicType.PREDICTED]
    )
    simulated_worst = sum(
        worst_case(evidence, evidence.spec.value.value)
        for evidence in partition[EpistemicType.SIMULATED]
    )
    worst_case_exposure = observed_exposure + predicted_worst + simulated_worst
    return ExposureVerdict(
        as_of=as_of,
        limit=limit,
        verdict="APPROVE" if worst_case_exposure <= limit else "REJECT",
        observed_exposure=observed_exposure,
        predicted_exposure=predicted_exposure,
        simulated_exposure=simulated_exposure,
        predicted_worst_case=predicted_worst,
        simulated_worst_case=simulated_worst,
        worst_case_exposure=worst_case_exposure,
    )


def _replay_archive(history: tuple[tuple[Evidence, Evidence], ...]) -> EvidenceArchive:
    archive = EvidenceArchive()
    for submitted, verified in history:
        archive.append(submitted)
        archive.append(verified)
    return archive


def build_transcript() -> tuple[str, str]:
    """Build the deterministic DOGFOOD-018 transcript and its digest."""
    registry = build_registry()
    attestation = _attestation()
    principal = require_trusted_issuer(attestation, registry)
    observations = _observations()
    uncertainties = _uncertainties()
    history = _evidence_history()

    # Original leg: evaluate from the in-memory evidence set.
    archive = _replay_archive(history)
    evidences = tuple(archive.get(evidence_id) for evidence_id in (
        "evidence/evidence/ev-observed",
        "evidence/evidence/ev-predicted",
        "evidence/evidence/ev-simulated",
    ))
    verdict = evaluate_exposure_verdict(
        evidences, uncertainties, as_of=AS_OF, limit=EXPOSURE_LIMIT
    )

    # Reconstruction leg: rebuild the whole evidence set from canonical
    # JSON alone (full version history), replay the append-only archive
    # and re-evaluate the decision deterministically.
    serialized = {
        "history": [
            [record.to_json() for record in versions] for versions in history
        ],
        "observations": [record.to_json() for record in observations],
        "uncertainties": [record.to_json() for record in uncertainties],
        "as_of": AS_OF,
        "limit": EXPOSURE_LIMIT,
    }
    rebuilt_history = tuple(
        (Evidence.from_json(versions[0]), Evidence.from_json(versions[1]))
        for versions in serialized["history"]
    )
    rebuilt_uncertainties = tuple(
        Uncertainty.from_json(raw) for raw in serialized["uncertainties"]
    )
    rebuilt_archive = _replay_archive(rebuilt_history)
    rebuilt_evidences = tuple(
        rebuilt_archive.get(evidence_id) for evidence_id in (
            "evidence/evidence/ev-observed",
            "evidence/evidence/ev-predicted",
            "evidence/evidence/ev-simulated",
        )
    )
    rebuilt_verdict = evaluate_exposure_verdict(
        rebuilt_evidences, rebuilt_uncertainties, as_of=AS_OF, limit=EXPOSURE_LIMIT
    )

    byte_identical = (
        verdict.digest() == rebuilt_verdict.digest()
        and archive.archive_digest() == rebuilt_archive.archive_digest()
    )

    evidence_partition = partition_evidence_by_epistemic_type(evidences)
    observation_partition = partition_observations_by_epistemic_type(observations)
    partition_ok = all(
        len(evidence_partition[member]) > 0
        for member in (EpistemicType.OBSERVED, EpistemicType.PREDICTED, EpistemicType.SIMULATED)
    )

    def ids(records: tuple[Any, ...]) -> str:
        return ",".join(record.object_id for record in records) if records else "-"

    lines = [
        "DOGFOOD-018: reconstruct a decision from evidence alone",
        f"as_of={AS_OF}",
        f"exposure_limit={EXPOSURE_LIMIT}",
        f"issuer_trust_gate={principal.state}",
        f"decision.verdict={verdict.verdict}",
        f"decision.observed_exposure={verdict.observed_exposure}",
        f"decision.predicted_exposure={verdict.predicted_exposure}",
        f"decision.simulated_exposure={verdict.simulated_exposure}",
        f"decision.predicted_worst_case={verdict.predicted_worst_case}",
        f"decision.simulated_worst_case={verdict.simulated_worst_case}",
        f"decision.worst_case_exposure={verdict.worst_case_exposure}",
        f"decision.original_digest={verdict.digest()}",
        f"reconstruction.rebuilt_digest={rebuilt_verdict.digest()}",
        f"reconstruction.archive_digest={archive.archive_digest()}",
        f"reconstruction.byte_identical={byte_identical}",
        f"sources.observed={len(evidence_partition[EpistemicType.OBSERVED])}",
        f"sources.predicted={len(evidence_partition[EpistemicType.PREDICTED])}",
        f"sources.simulated={len(evidence_partition[EpistemicType.SIMULATED])}",
        f"sources.observed.ids={ids(evidence_partition[EpistemicType.OBSERVED])}",
        f"sources.predicted.ids={ids(evidence_partition[EpistemicType.PREDICTED])}",
        f"sources.simulated.ids={ids(evidence_partition[EpistemicType.SIMULATED])}",
        f"sources.observations.observed={len(observation_partition[EpistemicType.OBSERVED])}",
        f"sources.observations.predicted={len(observation_partition[EpistemicType.PREDICTED])}",
        f"sources.observations.simulated={len(observation_partition[EpistemicType.SIMULATED])}",
        f"epistemic_partition.OBSERVED={len(evidence_partition[EpistemicType.OBSERVED])}",
        f"epistemic_partition.ESTIMATED={len(evidence_partition[EpistemicType.ESTIMATED])}",
        f"epistemic_partition.PREDICTED={len(evidence_partition[EpistemicType.PREDICTED])}",
        f"epistemic_partition.SIMULATED={len(evidence_partition[EpistemicType.SIMULATED])}",
        f"epistemic_partition.COUNTERFACTUAL={len(evidence_partition[EpistemicType.COUNTERFACTUAL])}",
    ]
    passed = byte_identical and partition_ok
    lines.append(f"DOGFOOD-018: {'PASS' if passed else 'FAIL'}")
    transcript = "\n".join(lines)
    digest = canonical_sha256({"transcript": transcript})
    return transcript, digest


def main() -> str:
    """Run DOGFOOD-018, print the transcript and return its digest."""
    transcript, digest = build_transcript()
    print(transcript)
    print(f"digest={digest}")
    return digest


if __name__ == "__main__":  # pragma: no cover - manual conformance run
    main()
