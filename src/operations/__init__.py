"""PaySwap protocol operations domain (WORK-024).

The public boundary is typed and versioned:

- **resilience, observability and recovery.** This package owns the
  frozen v0.1 ``Operations`` command family
  ``DeclareDegradation/Failover/Incident/Emergency/Resolve`` (bound to
  the REAL merged transition kernel, never to a private state
  machine), the declared dependency/exposure graph, the declared
  resilience profiles, the derived health/economic metrics and
  systemic-risk assessments, the incident/degradation/failover record
  family and the recovery orchestration evidence;
- **consumed dependencies, never reimplemented.** The transition
  authority is the merged ``src.transition`` kernel (WORK-023), the
  epistemic vocabulary is the evidence domain's
  :class:`src.evidence.EpistemicType` (WORK-018 — fail-closed
  evidence classification), economic exposure is composed from the
  clearing domain's real sealed :class:`src.clearing.Obligation`
  records (never re-derived), and health is probed through
  caller-supplied typed probe ports over public boundaries (ports
  over providers, implementation principle 4). Unmerged sibling
  domains are never reimplemented here;
- **no alternate source of truth.** Operations is an OBSERVER,
  COMPOSER and ORCHESTRATOR of the real merged authorities: it never
  re-derives authoritative sibling state, never mutates sibling
  lifecycles and never becomes a second authority. Failover and
  recovery reference digest-bound evidence of the real records they
  observe, and an ``AuthorityRebuild`` records which authoritative
  state a recovery rebuilt from — it does not fork it;
- **fail-closed degradation.** A dependency that cannot be observed
  is degraded/UNKNOWN, never silently healthy: unknown evidence is
  refused by the exposure gates, degradation severity is ordered and
  monotone, and an in-flight step whose provider died mid-flight ends
  ``UNKNOWN`` (no false success), with an explicit incident,
  degradation and failover record and recovery orchestration back to
  healthy only through sibling public APIs with authority
  conservation;
- every durable object composes the canonical
  :class:`~src.core.envelope.ObjectEnvelope` and carries a domain seal
  computed with the single canonical hash authority, so tampered or
  spliced objects fail closed on the trusted deserialization path.
  No operations object type and no operations event namespace is
  listed in the frozen protocol registry: object types use internal
  non-registry ``operations/...`` formats and events use the ALREADY
  REGISTERED ``governance`` namespace exactly as registered (the
  federation/agents precedent) — no new protocol-visible name is
  invented;
- failure is explicit and typed: validation errors use
  :class:`~src.core.errors.CoreValidationError` (the single error
  authority), and every command validates its source state,
  membership and gate preconditions before advancing through the real
  transition kernel.
"""

from __future__ import annotations

from .contracts import (
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
    DegradationSeverity,
    DependencyKind,
    HealthStatus,
    IncidentState,
    RecoveryActionKind,
    validate_command,
)
from .graph import (
    Dependency,
    DependencyGraph,
    DependencyRecordState,
    DependencySpec,
    make_dependency_record,
)
from .incidents import (
    AuthorityRebuild,
    DegradationFact,
    EmergencyFact,
    FailoverFact,
    Incident,
    IncidentSpec,
    RecoveryActionRecord,
    ResolutionFact,
    make_incident_record,
    degradation_recovery_seconds,
)
from .metrics import (
    EconomicExposure,
    HealthSnapshot,
    ProbeResult,
    SystemicRiskAssessment,
    assess_systemic_risk,
    economic_exposure,
    health_snapshot,
    probe_digest,
)
from .profiles import (
    ResilienceProfile,
    ResilienceProfileSpec,
    classify_health,
    make_profile_record,
)
from .engine import (
    DEFAULT_COMMAND_AUTHORITY_CLASS,
    DEFAULT_ENGINE_ACTOR,
    OperationsEngine,
    OperationsTransition,
)
from .seal import (
    advance_envelope,
    build_domain_envelope,
    composite_to_dict,
    composite_to_json,
    decode_composite,
    decode_composite_json,
    seal_composite,
    verify_composite,
)

__all__ = [
    "AuthorityRebuild",
    "COMMAND_EVENT_TYPES",
    "DEFAULT_COMMAND_AUTHORITY_CLASS",
    "DEFAULT_ENGINE_ACTOR",
    "DEGRADATION_SEVERITY_ORDER",
    "DEPENDENCY_OBJECT_TYPE",
    "DegradationFact",
    "Dependency",
    "DependencyGraph",
    "DependencyKind",
    "DependencyRecordState",
    "DependencySpec",
    "EconomicExposure",
    "EmergencyFact",
    "FailoverFact",
    "HealthSnapshot",
    "HealthStatus",
    "INCIDENT_OBJECT_TYPE",
    "INCIDENT_TERMINAL_STATES",
    "Incident",
    "IncidentSpec",
    "IncidentState",
    "OBJECT_TYPES",
    "OPERATIONS_API_VERSION",
    "OPERATIONS_COMMANDS",
    "OPERATIONS_EVENT_NAMESPACE",
    "OPERATIONS_PROTOCOL_VERSION",
    "OPERATIONS_SCHEMA_VERSION",
    "OPERATIONS_TRANSITIONS",
    "OperationsEngine",
    "OperationsTransition",
    "ProbeResult",
    "RESILIENCE_PROFILE_OBJECT_TYPE",
    "RecoveryActionKind",
    "RecoveryActionRecord",
    "ResilienceProfile",
    "ResilienceProfileSpec",
    "ResolutionFact",
    "SYSTEMIC_RISK_OBJECT_TYPE",
    "SystemicRiskAssessment",
    "advance_envelope",
    "assess_systemic_risk",
    "build_domain_envelope",
    "classify_health",
    "composite_to_dict",
    "composite_to_json",
    "decode_composite",
    "decode_composite_json",
    "degradation_recovery_seconds",
    "economic_exposure",
    "health_snapshot",
    "make_dependency_record",
    "make_incident_record",
    "make_profile_record",
    "probe_digest",
    "seal_composite",
    "validate_command",
    "verify_composite",
]
