"""Fraud signals, fraud assessments and fraud decisions.

This module implements the frozen Safety command family
``SubmitFraudSignal/CreateFraudAssessment/CreateFraudDecision/Hold/
Release/Block`` as explicit state machines:

- :class:`FraudSignal` (``SubmitFraudSignal``) is an immutable
  evidence-plane observation: submitted once, never mutated (IMMUTABLE
  lifecycle class).
- :class:`FraudAssessment` (``CreateFraudAssessment``) is a DERIVED
  immutable record aggregating submitted signals into a typed fraud score
  under the pinned policy version (severity weights sum, capped at the
  explicit scale bound).
- :class:`FraudDecision` (``CreateFraudDecision``/``Hold``/``Release``/
  ``Block``) is the STATEFUL circuit breaker: the verdict is the state
  (``ALLOW``/``STEP_UP``/``DELAY``/``RECONFIRM``/``ESCALATE`` issued
  verdicts, ``HELD`` with an explicit half-open hold window, terminal
  ``RELEASED``/``BLOCKED``).

Decisions are control verdicts only: they are binding inputs for other
domains (routing, execution) but this module never executes anything,
never touches ledgers/holds/postings and never moves funds. Every
creation and command requires evidence-backed provenance, references the
assessment it is based on, and enforces monotonic ``as_of`` time.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any, Iterable, Mapping

from src.core.envelope import ObjectEnvelope
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256

from .contracts import (
    FRAUD_ASSESSMENT_OBJECT_TYPE,
    FRAUD_DECISION_OBJECT_TYPE,
    FRAUD_SIGNAL_OBJECT_TYPE,
    RISK_SCALE_MAX,
    RISK_SCALE_MIN,
    FraudDecisionState,
    FraudKind,
    FraudReleaseReason,
    FraudSeverity,
    RiskBand,
)
from ._validation import (
    offset_utc_timestamp,
    parse_enum,
    parse_utc_timestamp,
    require_digest,
    require_identifier,
    require_identifier_tuple,
    require_int,
    require_provenance_evidence,
    require_utc_timestamp,
    require_utc_timestamp_order,
    require_utc_timestamp_within,
    strict_fields,
)
from .policy import SafetyPolicy, require_active_policy
from .seal import (
    advance_envelope,
    build_domain_envelope,
    composite_to_json,
    decode_composite,
    decode_composite_json,
    seal_composite,
    verify_composite,
)

# -- fraud signals -----------------------------------------------------------


class FraudSignalState(StrEnum):
    """Closed lifecycle vocabulary of a fraud signal (single terminal state)."""

    SUBMITTED = "SUBMITTED"


_SIGNAL_SPEC_FIELDS = frozenset({"subject_id", "kind", "severity", "observed_at"})


@dataclass(frozen=True, slots=True)
class FraudSignalSpec:
    """Immutable fraud signal payload (an external observation)."""

    subject_id: str
    kind: FraudKind
    severity: FraudSeverity
    observed_at: str

    def __post_init__(self) -> None:
        require_identifier("fraud signal subject_id", self.subject_id)
        if not isinstance(self.kind, FraudKind):
            raise CoreValidationError(
                "fraud signal kind must use the closed FraudKind vocabulary"
            )
        if not isinstance(self.severity, FraudSeverity):
            raise CoreValidationError(
                "fraud signal severity must use the closed FraudSeverity vocabulary"
            )
        require_utc_timestamp("fraud signal observed_at", self.observed_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject_id": self.subject_id,
            "kind": self.kind.value,
            "severity": self.severity.value,
            "observed_at": self.observed_at,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "FraudSignalSpec":
        strict_fields("fraud signal", value, _SIGNAL_SPEC_FIELDS)
        return cls(
            subject_id=value["subject_id"],
            kind=parse_enum("fraud signal kind", FraudKind, value["kind"]),
            severity=parse_enum("fraud signal severity", FraudSeverity, value["severity"]),
            observed_at=value["observed_at"],
        )


@dataclass(frozen=True, slots=True)
class FraudSignal:
    """Durable fraud signal record (envelope + sealed payload)."""

    envelope: ObjectEnvelope
    spec: FraudSignalSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = FRAUD_SIGNAL_OBJECT_TYPE

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("fraud signal envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, FraudSignalSpec):
            raise CoreValidationError("fraud signal spec must be a FraudSignalSpec")
        self.envelope.verify_integrity()
        if self.envelope.object_type != FRAUD_SIGNAL_OBJECT_TYPE:
            raise CoreValidationError(
                f"fraud signal object_type must be {FRAUD_SIGNAL_OBJECT_TYPE!r}"
            )
        if self.envelope.state != FraudSignalState.SUBMITTED:
            raise CoreValidationError(
                f"unknown fraud signal state: {self.envelope.state!r}"
            )
        verify_composite(self.envelope, self.spec, self.integrity_hash, self.envelope.object_id)

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> FraudSignalState:
        return FraudSignalState(self.envelope.state)

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "payload": self.spec.to_dict(),
            "integrity_hash": self.integrity_hash,
        }

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "FraudSignal":
        envelope, payload = decode_composite(
            value,
            expected_object_type=FRAUD_SIGNAL_OBJECT_TYPE,
            state_type=FraudSignalState,
        )
        spec = FraudSignalSpec.from_dict(payload)
        return cls(
            envelope=envelope, spec=spec, integrity_hash=value["integrity_hash"]
        )

    @classmethod
    def from_json(cls, value: str) -> "FraudSignal":
        envelope, payload, integrity_hash = decode_composite_json(
            value,
            expected_object_type=FRAUD_SIGNAL_OBJECT_TYPE,
            state_type=FraudSignalState,
        )
        spec = FraudSignalSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=integrity_hash)


def submit_fraud_signal(
    *,
    signal_id: str,
    subject_id: str,
    kind: Any,
    severity: Any,
    observed_at: str,
    environment_id: str,
    domain_id: str,
    provenance,
    correlation_id: str | None = None,
) -> FraudSignal:
    """Submit a fraud signal (the ``SubmitFraudSignal`` command).

    Signals are evidence-plane observations: the creating provenance must
    carry explicit evidence references — a signal without evidence is an
    oracle accusation, and the domain fails closed on it.
    """
    require_provenance_evidence("fraud signal submission", provenance)
    spec = FraudSignalSpec(
        subject_id=subject_id,
        kind=parse_enum("fraud signal kind", FraudKind, kind),
        severity=parse_enum("fraud signal severity", FraudSeverity, severity),
        observed_at=observed_at,
    )
    envelope = build_domain_envelope(
        object_id=require_identifier("fraud signal signal_id", signal_id),
        object_type=FRAUD_SIGNAL_OBJECT_TYPE,
        state=FraudSignalState.SUBMITTED.value,
        environment_id=require_identifier("fraud signal environment_id", environment_id),
        domain_id=require_identifier("fraud signal domain_id", domain_id),
        provenance=provenance,
        correlation_id=correlation_id,
    )
    return FraudSignal(
        envelope=envelope, spec=spec,
        integrity_hash=seal_composite(envelope, spec),
    )


# -- fraud assessments ---------------------------------------------------------


class FraudAssessmentState(StrEnum):
    """Closed lifecycle vocabulary of a fraud assessment (single terminal state)."""

    RECORDED = "RECORDED"


_ASSESSMENT_SPEC_FIELDS = frozenset(
    {
        "subject_id",
        "signal_refs",
        "fraud_score",
        "band",
        "policy_id",
        "policy_version",
        "as_of",
        "signals_digest",
    }
)


@dataclass(frozen=True, slots=True)
class FraudAssessmentSpec:
    """Immutable fraud assessment payload."""

    subject_id: str
    signal_refs: tuple[str, ...]
    fraud_score: int
    band: RiskBand
    policy_id: str
    policy_version: int
    as_of: str
    signals_digest: str

    def __post_init__(self) -> None:
        require_identifier("fraud assessment subject_id", self.subject_id)
        require_identifier_tuple("fraud assessment signal_refs", self.signal_refs)
        if list(self.signal_refs) != sorted(self.signal_refs):
            raise CoreValidationError(
                "fraud assessment signal_refs must be canonically sorted"
            )
        require_int(
            "fraud assessment fraud_score", self.fraud_score,
            minimum=RISK_SCALE_MIN, maximum=RISK_SCALE_MAX,
        )
        if not isinstance(self.band, RiskBand):
            raise CoreValidationError(
                "fraud assessment band must use the closed RiskBand vocabulary"
            )
        require_identifier("fraud assessment policy_id", self.policy_id)
        require_int("fraud assessment policy_version", self.policy_version, minimum=1)
        require_utc_timestamp("fraud assessment as_of", self.as_of)
        require_digest("fraud assessment signals_digest", self.signals_digest)

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject_id": self.subject_id,
            "signal_refs": list(self.signal_refs),
            "fraud_score": self.fraud_score,
            "band": self.band.value,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "as_of": self.as_of,
            "signals_digest": self.signals_digest,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "FraudAssessmentSpec":
        strict_fields("fraud assessment", value, _ASSESSMENT_SPEC_FIELDS)
        refs = value["signal_refs"]
        if not isinstance(refs, list):
            raise CoreValidationError(
                "fraud assessment signal_refs must deserialize from an array"
            )
        return cls(
            subject_id=value["subject_id"],
            signal_refs=tuple(refs),
            fraud_score=value["fraud_score"],
            band=parse_enum("fraud assessment band", RiskBand, value["band"]),
            policy_id=value["policy_id"],
            policy_version=value["policy_version"],
            as_of=value["as_of"],
            signals_digest=value["signals_digest"],
        )


@dataclass(frozen=True, slots=True)
class FraudAssessment:
    """Durable fraud assessment record (envelope + sealed payload)."""

    envelope: ObjectEnvelope
    spec: FraudAssessmentSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = FRAUD_ASSESSMENT_OBJECT_TYPE

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("fraud assessment envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, FraudAssessmentSpec):
            raise CoreValidationError("fraud assessment spec must be a FraudAssessmentSpec")
        self.envelope.verify_integrity()
        if self.envelope.object_type != FRAUD_ASSESSMENT_OBJECT_TYPE:
            raise CoreValidationError(
                f"fraud assessment object_type must be {FRAUD_ASSESSMENT_OBJECT_TYPE!r}"
            )
        if self.envelope.state != FraudAssessmentState.RECORDED:
            raise CoreValidationError(
                f"unknown fraud assessment state: {self.envelope.state!r}"
            )
        verify_composite(self.envelope, self.spec, self.integrity_hash, self.envelope.object_id)

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> FraudAssessmentState:
        return FraudAssessmentState(self.envelope.state)

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "payload": self.spec.to_dict(),
            "integrity_hash": self.integrity_hash,
        }

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "FraudAssessment":
        envelope, payload = decode_composite(
            value,
            expected_object_type=FRAUD_ASSESSMENT_OBJECT_TYPE,
            state_type=FraudAssessmentState,
        )
        spec = FraudAssessmentSpec.from_dict(payload)
        return cls(
            envelope=envelope, spec=spec, integrity_hash=value["integrity_hash"]
        )

    @classmethod
    def from_json(cls, value: str) -> "FraudAssessment":
        envelope, payload, integrity_hash = decode_composite_json(
            value,
            expected_object_type=FRAUD_ASSESSMENT_OBJECT_TYPE,
            state_type=FraudAssessmentState,
        )
        spec = FraudAssessmentSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=integrity_hash)


def assess_fraud(
    *,
    assessment_id: str,
    subject_id: str,
    signals: Iterable[FraudSignal],
    policy: SafetyPolicy,
    as_of: str,
    environment_id: str,
    domain_id: str,
    provenance,
    correlation_id: str | None = None,
) -> FraudAssessment:
    """Aggregate submitted signals into a fraud assessment (``CreateFraudAssessment``).

    The fraud score is the exact sum of the policy severity weights of the
    assessed signals, capped at the explicit scale bound; the assessment
    is signal-order independent (refs are canonicalized sorted) and fails
    closed on foreign subjects, future evidence, duplicate signals and
    retired policies.
    """
    require_active_policy("fraud assessment", policy)
    require_provenance_evidence("fraud assessment", provenance)
    require_utc_timestamp("fraud assessment as_of", as_of)
    if not isinstance(signals, (list, tuple)):
        raise CoreValidationError("fraud assessment signals must be provided as a sequence")
    if not signals:
        raise CoreValidationError("fraud assessment requires at least one signal")
    for signal in signals:
        if not isinstance(signal, FraudSignal):
            raise CoreValidationError("fraud assessment signals must be FraudSignal records")
        if signal.spec.subject_id != subject_id:
            raise CoreValidationError(
                f"fraud signal {signal.object_id} belongs to subject "
                f"{signal.spec.subject_id!r}, not {subject_id!r}"
            )
        if parse_utc_timestamp("fraud signal observed_at", signal.spec.observed_at) > parse_utc_timestamp(
            "fraud assessment as_of", as_of
        ):
            raise CoreValidationError(
                f"fraud signal {signal.object_id} was observed after the assessment "
                "instant; future evidence is rejected"
            )
    signal_refs = sorted(signal.object_id for signal in signals)
    if len(set(signal_refs)) != len(signal_refs):
        raise CoreValidationError("fraud assessment rejects duplicate signals")
    by_id = {signal.object_id: signal for signal in signals}
    spec = policy.spec
    fraud_score = min(
        RISK_SCALE_MAX,
        sum(spec.severity_weight(by_id[ref].spec.severity) for ref in signal_refs),
    )
    band = spec.band_for_score(fraud_score)
    signals_digest = canonical_sha256(
        {
            "signals": [
                {
                    "signal_id": ref,
                    "kind": by_id[ref].spec.kind.value,
                    "severity": by_id[ref].spec.severity.value,
                    "observed_at": by_id[ref].spec.observed_at,
                }
                for ref in signal_refs
            ],
            "policy_id": policy.object_id,
            "policy_version": policy.policy_version,
            "as_of": as_of,
        }
    )
    payload = FraudAssessmentSpec(
        subject_id=subject_id,
        signal_refs=tuple(signal_refs),
        fraud_score=fraud_score,
        band=band,
        policy_id=policy.object_id,
        policy_version=policy.policy_version,
        as_of=as_of,
        signals_digest=signals_digest,
    )
    envelope = build_domain_envelope(
        object_id=require_identifier("fraud assessment assessment_id", assessment_id),
        object_type=FRAUD_ASSESSMENT_OBJECT_TYPE,
        state=FraudAssessmentState.RECORDED.value,
        environment_id=require_identifier("fraud assessment environment_id", environment_id),
        domain_id=require_identifier("fraud assessment domain_id", domain_id),
        provenance=provenance,
        correlation_id=correlation_id,
    )
    return FraudAssessment(
        envelope=envelope, spec=payload,
        integrity_hash=seal_composite(envelope, payload),
    )


# -- fraud decisions: the circuit breaker ---------------------------------------

_CREATION_STATES = frozenset(
    {
        FraudDecisionState.ALLOW,
        FraudDecisionState.STEP_UP,
        FraudDecisionState.DELAY,
        FraudDecisionState.RECONFIRM,
        FraudDecisionState.ESCALATE,
        FraudDecisionState.HELD,
        FraudDecisionState.BLOCKED,
    }
)

_FRAUD_COMMANDS: dict[str, dict[FraudDecisionState, FraudDecisionState]] = {
    "hold": {
        FraudDecisionState.ALLOW: FraudDecisionState.HELD,
        FraudDecisionState.STEP_UP: FraudDecisionState.HELD,
        FraudDecisionState.DELAY: FraudDecisionState.HELD,
        FraudDecisionState.RECONFIRM: FraudDecisionState.HELD,
        FraudDecisionState.ESCALATE: FraudDecisionState.HELD,
    },
    "release": {FraudDecisionState.HELD: FraudDecisionState.RELEASED},
    "block": {
        FraudDecisionState.ALLOW: FraudDecisionState.BLOCKED,
        FraudDecisionState.STEP_UP: FraudDecisionState.BLOCKED,
        FraudDecisionState.DELAY: FraudDecisionState.BLOCKED,
        FraudDecisionState.RECONFIRM: FraudDecisionState.BLOCKED,
        FraudDecisionState.ESCALATE: FraudDecisionState.BLOCKED,
        FraudDecisionState.HELD: FraudDecisionState.BLOCKED,
    },
}

_DECISION_SPEC_FIELDS = frozenset(
    {
        "subject_id",
        "assessment_ref",
        "as_of",
        "hold_from",
        "hold_until",
        "release_reason",
    }
)


@dataclass(frozen=True, slots=True)
class FraudDecisionSpec:
    """Immutable fraud decision payload for one lifecycle version."""

    subject_id: str
    assessment_ref: str
    as_of: str
    hold_from: str | None = None
    hold_until: str | None = None
    release_reason: FraudReleaseReason | None = None

    def __post_init__(self) -> None:
        require_identifier("fraud decision subject_id", self.subject_id)
        require_identifier("fraud decision assessment_ref", self.assessment_ref)
        require_utc_timestamp("fraud decision as_of", self.as_of)
        if self.hold_from is not None:
            require_utc_timestamp("fraud decision hold_from", self.hold_from)
        if self.hold_until is not None:
            require_utc_timestamp("fraud decision hold_until", self.hold_until)
        if (self.hold_from is None) != (self.hold_until is None):
            raise CoreValidationError(
                "fraud decision hold window must declare both bounds or neither"
            )
        if self.hold_from is not None and self.hold_until is not None:
            require_utc_timestamp_order(
                "fraud decision hold_from", self.hold_from,
                "fraud decision hold_until", self.hold_until,
            )
        if self.release_reason is not None and not isinstance(
            self.release_reason, FraudReleaseReason
        ):
            raise CoreValidationError(
                "fraud decision release_reason must use the closed "
                "FraudReleaseReason vocabulary"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject_id": self.subject_id,
            "assessment_ref": self.assessment_ref,
            "as_of": self.as_of,
            "hold_from": self.hold_from,
            "hold_until": self.hold_until,
            "release_reason": (
                None if self.release_reason is None else self.release_reason.value
            ),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "FraudDecisionSpec":
        strict_fields("fraud decision", value, _DECISION_SPEC_FIELDS)
        reason = value["release_reason"]
        return cls(
            subject_id=value["subject_id"],
            assessment_ref=value["assessment_ref"],
            as_of=value["as_of"],
            hold_from=value["hold_from"],
            hold_until=value["hold_until"],
            release_reason=None if reason is None else parse_enum(
                "fraud decision release_reason", FraudReleaseReason, reason
            ),
        )


@dataclass(frozen=True, slots=True)
class FraudDecision:
    """Durable fraud decision record (envelope + sealed payload).

    The verdict is the envelope state; state/payload consistency is
    enforced fail-closed: ``HELD`` requires an active half-open hold
    window containing ``as_of``; ``RELEASED`` requires a release reason
    and retains the released window; ``BLOCKED`` never carries a release
    reason.
    """

    envelope: ObjectEnvelope
    spec: FraudDecisionSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = FRAUD_DECISION_OBJECT_TYPE
    STATE_TYPE = FraudDecisionState

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("fraud decision envelope must be an ObjectEnvelope")
        if not isinstance(self.spec, FraudDecisionSpec):
            raise CoreValidationError("fraud decision spec must be a FraudDecisionSpec")
        self.envelope.verify_integrity()
        if self.envelope.object_type != FRAUD_DECISION_OBJECT_TYPE:
            raise CoreValidationError(
                f"fraud decision object_type must be {FRAUD_DECISION_OBJECT_TYPE!r}"
            )
        state = parse_enum("fraud decision state", FraudDecisionState, self.envelope.state)
        _check_decision_consistency(state, self.spec)
        verify_composite(self.envelope, self.spec, self.integrity_hash, self.envelope.object_id)

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def state(self) -> FraudDecisionState:
        return FraudDecisionState(self.envelope.state)

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "payload": self.spec.to_dict(),
            "integrity_hash": self.integrity_hash,
        }

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "FraudDecision":
        envelope, payload = decode_composite(
            value,
            expected_object_type=FRAUD_DECISION_OBJECT_TYPE,
            state_type=FraudDecisionState,
        )
        spec = FraudDecisionSpec.from_dict(payload)
        return cls(
            envelope=envelope, spec=spec, integrity_hash=value["integrity_hash"]
        )

    @classmethod
    def from_json(cls, value: str) -> "FraudDecision":
        envelope, payload, integrity_hash = decode_composite_json(
            value,
            expected_object_type=FRAUD_DECISION_OBJECT_TYPE,
            state_type=FraudDecisionState,
        )
        spec = FraudDecisionSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=integrity_hash)

    def _advance(
        self,
        new_state: FraudDecisionState,
        spec: FraudDecisionSpec,
        *,
        provenance,
        causation_id: str | None,
    ) -> "FraudDecision":
        envelope = advance_envelope(
            self.envelope,
            state=new_state.value,
            provenance=provenance,
            causation_id=causation_id,
        )
        return FraudDecision(
            envelope=envelope, spec=spec,
            integrity_hash=seal_composite(envelope, spec),
        )


def _check_decision_consistency(state: FraudDecisionState, spec: FraudDecisionSpec) -> None:
    if state is FraudDecisionState.HELD:
        if spec.hold_from is None or spec.hold_until is None:
            raise CoreValidationError(
                "a HELD fraud decision requires an explicit hold window"
            )
        require_utc_timestamp_within(
            "fraud decision as_of", spec.as_of, spec.hold_from, spec.hold_until,
        )
        if spec.release_reason is not None:
            raise CoreValidationError(
                "a HELD fraud decision cannot carry a release reason"
            )
    elif state is FraudDecisionState.RELEASED:
        if spec.release_reason is None:
            raise CoreValidationError(
                "a RELEASED fraud decision requires an explicit release reason"
            )
        if spec.hold_from is None or spec.hold_until is None:
            raise CoreValidationError(
                "a RELEASED fraud decision retains the window of the released hold"
            )
        if parse_utc_timestamp("fraud decision as_of", spec.as_of) < parse_utc_timestamp(
            "fraud decision hold_from", spec.hold_from
        ):
            raise CoreValidationError(
                "a RELEASED fraud decision cannot precede its hold window"
            )
    elif state is FraudDecisionState.BLOCKED:
        if spec.release_reason is not None:
            raise CoreValidationError(
                "a BLOCKED fraud decision cannot carry a release reason"
            )
        if spec.hold_from is not None and parse_utc_timestamp(
            "fraud decision as_of", spec.as_of
        ) < parse_utc_timestamp("fraud decision hold_from", spec.hold_from):
            raise CoreValidationError(
                "a BLOCKED fraud decision cannot precede its hold window"
            )
    else:
        if spec.hold_from is not None or spec.hold_until is not None:
            raise CoreValidationError(
                f"a {state.value} fraud decision cannot carry a hold window"
            )
        if spec.release_reason is not None:
            raise CoreValidationError(
                f"a {state.value} fraud decision cannot carry a release reason"
            )


def create_fraud_decision(
    *,
    decision_id: str,
    subject_id: str,
    assessment_ref: str,
    state: Any,
    as_of: str,
    environment_id: str,
    domain_id: str,
    provenance,
    hold_from: str | None = None,
    hold_until: str | None = None,
    correlation_id: str | None = None,
) -> FraudDecision:
    """Create a fraud decision (the ``CreateFraudDecision`` command).

    Every creation references the fraud assessment it is based on and
    requires evidence-backed provenance. ``RELEASED`` is not a creation
    verdict: releases only originate from the ``Release`` command on a
    held decision.
    """
    require_provenance_evidence("fraud decision creation", provenance)
    verdict = parse_enum("fraud decision state", FraudDecisionState, state)
    if verdict is FraudDecisionState.RELEASED:
        raise CoreValidationError(
            "RELEASED is not a creation verdict; use the Release command on a "
            "held decision"
        )
    if verdict not in _CREATION_STATES:
        raise CoreValidationError(
            f"unknown fraud decision creation verdict: {verdict.value}"
        )
    spec = FraudDecisionSpec(
        subject_id=subject_id,
        assessment_ref=assessment_ref,
        as_of=as_of,
        hold_from=hold_from,
        hold_until=hold_until,
    )
    _check_decision_consistency(verdict, spec)
    envelope = build_domain_envelope(
        object_id=require_identifier("fraud decision decision_id", decision_id),
        object_type=FRAUD_DECISION_OBJECT_TYPE,
        state=verdict.value,
        environment_id=require_identifier("fraud decision environment_id", environment_id),
        domain_id=require_identifier("fraud decision domain_id", domain_id),
        provenance=provenance,
        correlation_id=correlation_id,
    )
    return FraudDecision(
        envelope=envelope, spec=spec,
        integrity_hash=seal_composite(envelope, spec),
    )


def decide_fraud(
    *,
    decision_id: str,
    assessment: FraudAssessment,
    policy: SafetyPolicy,
    as_of: str,
    environment_id: str,
    domain_id: str,
    provenance,
    correlation_id: str | None = None,
) -> FraudDecision:
    """Derive the fraud decision deterministically from an assessment.

    Threshold mapping under the pinned policy: score >= block -> BLOCKED;
    score >= hold -> HELD with the default hold window
    ``[as_of, as_of + default_hold_window_seconds)``; score >= step_up ->
    STEP_UP; otherwise ALLOW. The decision instant cannot precede the
    assessment instant.
    """
    require_active_policy("fraud decision", policy)
    require_provenance_evidence("fraud decision creation", provenance)
    if not isinstance(assessment, FraudAssessment):
        raise CoreValidationError("fraud decision requires a FraudAssessment")
    require_utc_timestamp("fraud decision as_of", as_of)
    if parse_utc_timestamp("fraud decision as_of", as_of) < parse_utc_timestamp(
        "fraud assessment as_of", assessment.spec.as_of
    ):
        raise CoreValidationError(
            "fraud decision instant cannot precede the assessment instant"
        )
    score = assessment.spec.fraud_score
    step_up, hold, block = policy.spec.decision_thresholds
    spec = FraudDecisionSpec(
        subject_id=assessment.spec.subject_id,
        assessment_ref=assessment.object_id,
        as_of=as_of,
    )
    if score >= block:
        verdict = FraudDecisionState.BLOCKED
    elif score >= hold:
        verdict = FraudDecisionState.HELD
        spec = replace(
            spec,
            hold_from=as_of,
            hold_until=offset_utc_timestamp(
                "fraud decision hold_from", as_of,
                policy.spec.default_hold_window_seconds,
            ),
        )
    elif score >= step_up:
        verdict = FraudDecisionState.STEP_UP
    else:
        verdict = FraudDecisionState.ALLOW
    _check_decision_consistency(verdict, spec)
    envelope = build_domain_envelope(
        object_id=require_identifier("fraud decision decision_id", decision_id),
        object_type=FRAUD_DECISION_OBJECT_TYPE,
        state=verdict.value,
        environment_id=require_identifier("fraud decision environment_id", environment_id),
        domain_id=require_identifier("fraud decision domain_id", domain_id),
        provenance=provenance,
        correlation_id=correlation_id,
    )
    return FraudDecision(
        envelope=envelope, spec=spec,
        integrity_hash=seal_composite(envelope, spec),
    )


def _apply_command(
    decision: FraudDecision,
    command: str,
    spec: FraudDecisionSpec,
    *,
    provenance,
    as_of: str,
) -> FraudDecision:
    if not isinstance(decision, FraudDecision):
        raise CoreValidationError("operation requires a FraudDecision")
    require_provenance_evidence(f"fraud {command} command", provenance)
    require_utc_timestamp(f"fraud {command} as_of", as_of)
    current = decision.state
    transitions = _FRAUD_COMMANDS[command]
    if current not in transitions:
        raise CoreValidationError(
            f"fraud decision command {command!r} is not allowed from state "
            f"{current.value}"
        )
    if parse_utc_timestamp(f"fraud {command} as_of", as_of) < parse_utc_timestamp(
        "fraud decision spec as_of", decision.spec.as_of
    ):
        raise CoreValidationError(
            "fraud decision commands cannot move time backwards"
        )
    return decision._advance(
        transitions[current], spec, provenance=provenance,
        causation_id=decision.object_id,
    )


def hold_fraud_decision(
    decision: FraudDecision,
    *,
    as_of: str,
    hold_from: str,
    hold_until: str,
    provenance,
) -> FraudDecision:
    """Trip the circuit breaker (the ``Hold`` command).

    The hold window is explicit and half-open ``[hold_from, hold_until)``;
    the command instant must lie inside the window, so a hold can never
    be born already elapsed.
    """
    spec = replace(
        decision.spec,
        as_of=as_of,
        hold_from=hold_from,
        hold_until=hold_until,
        release_reason=None,
    )
    _check_decision_consistency(FraudDecisionState.HELD, spec)
    return _apply_command(
        decision, "hold", spec, provenance=provenance, as_of=as_of,
    )


def release_fraud_decision(
    decision: FraudDecision,
    *,
    as_of: str,
    reason: Any,
    provenance,
) -> FraudDecision:
    """Release a held decision (the ``Release`` command).

    ``OPERATOR`` releases require the hold window to still be active
    (``as_of`` in ``[hold_from, hold_until)``); ``WINDOW_ELAPSED``
    releases are the system trigger once the window has elapsed
    (``as_of >= hold_until``). The released window is retained on the
    record as provenance of what was held.
    """
    release_reason = parse_enum(
        "fraud release reason", FraudReleaseReason, reason
    )
    hold_from = decision.spec.hold_from
    hold_until = decision.spec.hold_until
    if hold_from is None or hold_until is None:
        raise CoreValidationError(
            "release requires a decision with an explicit hold window"
        )
    if release_reason is FraudReleaseReason.OPERATOR:
        require_utc_timestamp_within(
            "fraud release as_of", as_of, hold_from, hold_until,
        )
    else:  # WINDOW_ELAPSED
        if parse_utc_timestamp("fraud release as_of", as_of) < parse_utc_timestamp(
            "fraud decision hold_until", hold_until
        ):
            raise CoreValidationError(
                "WINDOW_ELAPSED release requires as_of at or after hold_until "
                f"({hold_until}); got {as_of}"
            )
    spec = replace(
        decision.spec,
        as_of=as_of,
        release_reason=release_reason,
    )
    _check_decision_consistency(FraudDecisionState.RELEASED, spec)
    return _apply_command(
        decision, "release", spec, provenance=provenance, as_of=as_of,
    )


def block_fraud_decision(
    decision: FraudDecision,
    *,
    as_of: str,
    provenance,
) -> FraudDecision:
    """Hard-block a decision (the ``Block`` command, terminal).

    The block never carries a release reason; a hold window present on
    the previous version is retained as historical provenance.
    """
    spec = replace(
        decision.spec,
        as_of=as_of,
        release_reason=None,
    )
    _check_decision_consistency(FraudDecisionState.BLOCKED, spec)
    return _apply_command(
        decision, "block", spec, provenance=provenance, as_of=as_of,
    )


def hold_active(decision: FraudDecision, as_of: str) -> bool:
    """Typed predicate: is the circuit-breaker hold active at ``as_of``?"""
    if not isinstance(decision, FraudDecision):
        raise CoreValidationError("hold_active requires a FraudDecision")
    if decision.state is not FraudDecisionState.HELD:
        return False
    require_utc_timestamp("hold_active as_of", as_of)
    if decision.spec.hold_from is None or decision.spec.hold_until is None:
        return False
    return (
        parse_utc_timestamp("hold window start", decision.spec.hold_from)
        <= parse_utc_timestamp("hold_active as_of", as_of)
        < parse_utc_timestamp("hold window end", decision.spec.hold_until)
    )
