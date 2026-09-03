"""Kernel-bound engine for the operations domain (WORK-024).

The :class:`OperationsEngine` binds every command of the frozen
``Operations`` family (``DeclareDegradation/Failover/Incident/Emergency/
Resolve``) to the REAL transition kernel (:class:`src.transition.
TransitionEngine`): validate-then-compute handlers produce
:class:`~src.transition.TransitionApplication` records that the kernel
commits and journals; the incident index is re-populated only through the
trusted decode path (seal verification included), both for live commits
and journal rebuilds.

Authority discipline (constitution invariants 3, 12, 13, 17, 18):

* the operator gate authorizes actors at the engine boundary (kernel
  stage 4);
* the declared dependency graph and resilience profiles are validated
  sealed configuration injected at construction (the execution engine's
  adapter-binding precedent) — declared data, never live sibling state;
* every command's evidence is classified through the single
  deterministic :func:`~src.operations.profiles.classify_health` mapping
  against the declared profile thresholds — payload-declared health is
  never trusted;
* degradation declarations bind the fresh probe digest, the affected
  dependency scope and the affected-authority digests;
* failover is a control-plane decision: the conservation gate requires
  every affected authority's digest to be UNCHANGED since degradation
  was declared (a routing decision must not mutate authoritative state),
  the target must be a declared redundancy of the profile, its probe
  must be HEALTHY, and its adapter contract must be effect-capable (the
  interoperability domain's closed fidelity vocabulary);
* emergency is narrow, time-bounded and audited (governance.md
  "Emergency authority") — it mutates nothing;
* resolution requires fresh HEALTHY probes for the exact affected
  dependency set, full coverage of the declared recovery plan, no
  undeclared recovery actions, recovery within the declared RTO, and
  journal-only rebuild evidence (live index digest == rebuilt index
  digest) for every affected authority — no silent state loss;
* this engine never re-derives or mutates sibling state: recovery
  orchestration happens through sibling public APIs BEFORE the resolve
  command, and only its digest-bound evidence is validated here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.transition import (
    AuthorizationDecision,
    Command,
    ExpectedVersion,
    MemoryStateStore,
    Outcome,
    RejectionReason,
    TransitionApplication,
    TransitionEngine,
    TransitionResult,
)
from src.transition.engine import EngineState
from src.transition.payload import payload_to_json_value
from src.transition.registry import validate_authority_class

from ._validation import (
    elapsed_seconds,
    require_identifier,
    require_mapping,
    require_text,
    require_utc_timestamp,
    strict_fields,
)
from .contracts import (
    COMMAND_EVENT_TYPES,
    DEGRADATION_SEVERITY_ORDER,
    OPERATIONS_COMMANDS,
    OPERATIONS_SCHEMA_VERSION,
    DegradationSeverity,
    HealthStatus,
    IncidentState,
    RecoveryActionKind,
)
from .graph import Dependency, DependencyGraph
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
)
from .metrics import ProbeResult, probe_digest
from .profiles import ResilienceProfile, classify_health
from .seal import advance_envelope, seal_record

DEFAULT_ENGINE_ACTOR = "principal/operations-service"

#: Default command authority class (the operator tier that drives
#: operations commands — the domain-engine convention; operations is a
#: control/decision plane that observes and orchestrates, never a
#: financial-effect authority).
DEFAULT_COMMAND_AUTHORITY_CLASS = "A3"

_COMMAND_NONCE = "operations-command-1"

_INCIDENT_PAYLOAD_FIELDS = frozenset(
    {"incident_id", "dependency_id", "trigger_probe", "summary"}
)
_DEGRADATION_PAYLOAD_FIELDS = frozenset(
    {"incident_id", "probe", "affected_dependencies", "affected_authorities", "detail"}
)
_FAILOVER_PAYLOAD_FIELDS = frozenset(
    {
        "incident_id",
        "target_dependency_id",
        "target_probe",
        "adapter_contract",
        "authority_digests",
        "detail",
    }
)
_EMERGENCY_PAYLOAD_FIELDS = frozenset(
    {"incident_id", "window_from", "window_until", "mandate", "scope"}
)
_RESOLVE_PAYLOAD_FIELDS = frozenset(
    {"incident_id", "probes", "recovery_actions", "authority_evidence", "note"}
)

_SNAPSHOT_FIELDS = frozenset(
    {
        "schema_version",
        "environment_id",
        "domain_id",
        "index",
        "engine",
        "store",
    }
)

#: Closed severity vocabulary as a health-status mapping (the trigger
#: classification must be a degradation, never HEALTHY).
_SEVERITY_BY_HEALTH = {
    HealthStatus.DEGRADED: DegradationSeverity.DEGRADED,
    HealthStatus.UNAVAILABLE: DegradationSeverity.UNAVAILABLE,
}


def _payload_dict(command: Command) -> dict[str, Any]:
    """Decode the command payload into the canonical JSON object form."""
    decoded = payload_to_json_value(command.payload)
    if not isinstance(decoded, dict):
        raise CoreValidationError("operations command payloads must be objects")
    return decoded


def _journal_payload(entry: Any) -> Any:
    payload = payload_to_json_value(entry.payload) if entry.payload is not None else {}
    if not isinstance(payload, dict):
        raise CoreValidationError("operations journal payloads must be objects")
    return payload


def _parse_probe(value: Any, name: str) -> ProbeResult:
    if isinstance(value, ProbeResult):
        return value
    if isinstance(value, Mapping):
        return ProbeResult.from_dict(value)
    raise CoreValidationError(f"{name} must be a ProbeResult or its canonical object")


@dataclass(frozen=True, slots=True)
class OperationsTransition:
    """Explicit decision record for one processed operations command.

    ``outcome`` mirrors the kernel outcome (``accepted`` / ``rejected`` /
    ``duplicate``); rejections carry a closed-vocabulary ``reason``;
    duplicates echo the original decision without emitting a new event.
    """

    command_id: str
    command_type: str
    outcome: Outcome
    reason: RejectionReason | None
    detail: str | None
    result: TransitionResult

    def __post_init__(self) -> None:
        require_text("transition.command_id", self.command_id)
        require_text("transition.command_type", self.command_type)
        if not isinstance(self.outcome, Outcome):
            raise CoreValidationError("transition outcome must use the kernel vocabulary")
        if self.detail is not None:
            require_text("transition.detail", self.detail)
        if not isinstance(self.result, TransitionResult):
            raise CoreValidationError("transition result must be a TransitionResult")
        if self.result.outcome is not self.outcome:
            raise CoreValidationError("transition outcome must mirror the kernel result")
        if self.reason != self.result.reason:
            raise CoreValidationError("transition reason must mirror the kernel result")


class OperationsEngine:
    """Kernel-bound engine for the operations domain (WORK-024).

    The engine owns the incident index (sealed composite records rebuilt
    through the trusted decode path) and one real transition kernel per
    environment. The declared dependency graph and resilience profiles
    are validated configuration injected at construction. It observes
    health through typed probe evidence, drives the incident lifecycle,
    and validates recovery evidence — it never re-derives or mutates
    sibling state and never becomes a second authority.
    """

    def __init__(
        self,
        *,
        environment_id: str,
        domain_id: str,
        dependency_graph: DependencyGraph,
        resilience_profiles: Mapping[str, ResilienceProfile],
        actor: str = DEFAULT_ENGINE_ACTOR,
        command_authority_class: str = DEFAULT_COMMAND_AUTHORITY_CLASS,
        authorized_actors: Iterable[str] = (),
    ) -> None:
        require_text("engine environment_id", environment_id)
        require_identifier("engine domain_id", domain_id)
        require_text("engine actor", actor)
        validate_authority_class("engine command_authority_class", command_authority_class)
        if not isinstance(dependency_graph, DependencyGraph):
            raise CoreValidationError("engine requires a DependencyGraph")
        profiles: dict[str, ResilienceProfile] = {}
        for service_id, profile in dict(resilience_profiles).items():
            require_identifier("engine profile service key", service_id)
            if not isinstance(profile, ResilienceProfile):
                raise CoreValidationError(
                    "engine resilience profiles must be ResilienceProfile records"
                )
            # re-verify the seal on the trusted path (tampered profiles fail)
            ResilienceProfile.from_dict(profile.to_dict())
            if profile.spec.service_id != service_id:
                raise CoreValidationError(
                    f"profile key {service_id!r} does not match the profile's "
                    f"declared service {profile.spec.service_id!r}"
                )
            if service_id in profiles:
                raise CoreValidationError(
                    f"service {service_id!r} declares two resilience profiles"
                )
            for redundancy in profile.spec.redundancy:
                if not dependency_graph.has_dependency(redundancy):
                    raise CoreValidationError(
                        f"profile of service {service_id!r} declares redundancy "
                        f"target {redundancy!r} which is not a declared dependency "
                        "of the graph; failover would not be grounded"
                    )
            profiles[service_id] = profile
        extra_actors = set(authorized_actors)
        for extra in extra_actors:
            require_text("engine authorized actor", extra)
        self._environment_id = environment_id
        self._domain_id = domain_id
        self._actor = actor
        self._command_authority_class = command_authority_class
        self._authorized_actors = frozenset({actor} | extra_actors)
        self._graph = dependency_graph
        self._profiles = dict(profiles)
        self._store = MemoryStateStore()
        self._kernel = self._build_kernel()
        self._records: dict[str, Incident] = {}
        self._transitions: list[OperationsTransition] = []

    # ------------------------------------------------------------------
    # construction and kernel binding
    # ------------------------------------------------------------------

    @property
    def environment_id(self) -> str:
        return self._environment_id

    @property
    def domain_id(self) -> str:
        return self._domain_id

    @property
    def dependency_graph(self) -> DependencyGraph:
        return self._graph

    @property
    def resilience_profiles(self) -> tuple[ResilienceProfile, ...]:
        return tuple(self._profiles[service] for service in sorted(self._profiles))

    @property
    def journal(self) -> tuple[Any, ...]:
        return self._kernel.journal

    def transitions(self) -> tuple[OperationsTransition, ...]:
        """The engine's explicit transition decision records (append-only)."""
        return tuple(self._transitions)

    def _build_kernel(self) -> TransitionEngine:
        kernel = TransitionEngine(
            self._environment_id,
            authorization=self._authorize,
            policy=self._state_policy,
            store=self._store,
        )
        registrations = (
            ("operations/incident", self._handle_incident),
            ("operations/declare-degradation", self._handle_declare_degradation),
            ("operations/failover", self._handle_failover),
            ("operations/emergency", self._handle_emergency),
            ("operations/resolve", self._handle_resolve),
        )
        for command_type, handler in registrations:
            event_type = COMMAND_EVENT_TYPES[command_type]
            kernel.register(command_type, event_type, handler)
        return kernel

    def _authorize(self, command: Command, view: Any) -> AuthorizationDecision:
        """Command-level authorization: the operator gate."""
        if command.actor in self._authorized_actors:
            return AuthorizationDecision(
                granted=True,
                authority=self._command_authority_class,
                reason=None,
            )
        return AuthorizationDecision(
            granted=False,
            authority=None,
            reason=(
                f"actor {command.actor!r} is not authorized to drive operations "
                f"in environment {self._environment_id!r}"
            ),
        )

    def _state_policy(self, command: Command, view: Any) -> str | None:
        """Kernel policy gate: the incident state machine.

        Commands submitted through the raw kernel boundary (without the
        typed public wrappers' fail-fast pre-validation) are gated here:
        a command whose primary target incident sits in a state outside
        the frozen transition table is REJECTED by the kernel (an
        explicit transition decision, journaled as a rejection) instead
        of raising. The typed public wrappers pre-validate the same table
        and raise the explicit typed error; the handlers re-validate a
        third time — defense in depth around the single transition table.
        """
        from .contracts import OPERATIONS_TRANSITIONS

        allowed = OPERATIONS_TRANSITIONS.get(command.command_type)
        if not allowed:
            # creation commands and unknown command types are not gated
            # here (unknown types already fail closed at kernel stage 3).
            return None
        if not command.target_refs:
            return None
        incident_ref = command.target_refs[0]
        envelope = view.get(incident_ref)
        if envelope is None:
            # the handler fails closed with the typed unknown-incident error
            return None
        if envelope.state not in {member.value for member in allowed}:
            return (
                f"{command.command_type} cannot advance from state "
                f"{envelope.state!r}; allowed source states are "
                f"{sorted(member.value for member in allowed)} (the incident "
                "state machine is the frozen transition table)"
            )
        return None

    def _provenance(self, command: Command) -> Provenance:
        return Provenance(
            issuer=command.actor,
            source="operations/domain",
            recorded_at=command.requested_at,
        )

    def _profile_for_dependency(self, dependency_id: str) -> ResilienceProfile:
        service_id = self._graph.service_of(dependency_id)
        profile = self._profiles.get(service_id)
        if profile is None:
            raise CoreValidationError(
                f"service {service_id!r} (owner of dependency {dependency_id!r}) "
                "declares no resilience profile; operations commands fail closed"
            )
        return profile

    def _require_command_state(self, command_type: str, incident_id: str) -> Incident:
        """Typed fail-fast pre-validation of the frozen transition table.

        The public wrappers raise the explicit typed error before any
        command is built or submitted; the kernel's policy gate and the
        handlers re-validate the same table (defense in depth).
        """
        record = self.incident(incident_id)
        self._require_source_state(command_type, record.state)
        return record

    def _classify(self, probe: ProbeResult, dependency_id: str) -> HealthStatus:
        """Classify one probe of one declared dependency (the single mapping)."""
        service_id = self._graph.service_of(dependency_id)
        profile = self._profile_for_dependency(dependency_id)
        return classify_health(probe, profile, dependency_service=service_id)

    # ------------------------------------------------------------------
    # command construction and submission
    # ------------------------------------------------------------------

    def build_raw_command(
        self,
        *,
        command_id: str,
        command_type: str,
        requested_at: str,
        target_refs: Iterable[str],
        payload: Any,
        environment_id: str | None = None,
        domain_id: str | None = None,
        actor: str | None = None,
        expected_versions: Mapping[str, int] | Iterable[ExpectedVersion] | None = None,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> Command:
        """Build a kernel command envelope against this engine's binding.

        ``expected_versions`` accepts either a mapping
        ``{object_ref: version}`` or an iterable of
        :class:`~src.transition.command.ExpectedVersion`. The command's
        idempotency key is derived deterministically from the command id.
        """
        require_text("command_id", command_id)
        from .contracts import validate_command

        validate_command(command_type)
        require_utc_timestamp("requested_at", requested_at)
        targets = tuple(target_refs)
        if not targets:
            raise CoreValidationError("target_refs must declare at least one target object")
        for target in targets:
            require_text("target_ref", target)
        if expected_versions is None:
            expected: tuple[ExpectedVersion, ...] = ()
        elif isinstance(expected_versions, Mapping):
            expected = tuple(
                ExpectedVersion(object_ref=ref, object_version=version)
                for ref, version in expected_versions.items()
            )
        else:
            expected = tuple(expected_versions)
            for item in expected:
                if not isinstance(item, ExpectedVersion):
                    raise CoreValidationError(
                        "expected_versions entries must be ExpectedVersion records"
                    )
        return Command.build(
            command_id=command_id,
            command_type=command_type,
            actor=actor if actor is not None else self._actor,
            target_refs=targets,
            payload=payload,
            environment_id=environment_id if environment_id is not None else self._environment_id,
            domain_id=domain_id if domain_id is not None else self._domain_id,
            expected_versions=expected,
            idempotency_key=f"operations:{command_id}",
            nonce=_COMMAND_NONCE,
            requested_at=requested_at,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )

    def submit(self, command: Command) -> OperationsTransition:
        """Process one command through the real kernel pipeline."""
        if not isinstance(command, Command):
            raise CoreValidationError("submit expects a Command envelope")
        result = self._kernel.process(command)
        if result.outcome is Outcome.ACCEPTED:
            self._apply_event_payload(
                result.event.event_type, payload_to_json_value(result.payload)
            )
        transition = OperationsTransition(
            command_id=command.command_id,
            command_type=command.command_type,
            outcome=result.outcome,
            reason=result.reason,
            detail=result.detail,
            result=result,
        )
        self._transitions.append(transition)
        return transition

    # ------------------------------------------------------------------
    # record index (trusted decode path only)
    # ------------------------------------------------------------------

    def incident(self, incident_id: str) -> Incident:
        require_identifier("incident id", incident_id)
        record = self._records.get(incident_id)
        if record is None or not isinstance(record, Incident):
            raise CoreValidationError(f"unknown incident {incident_id!r}")
        return record

    def incidents(self) -> tuple[Incident, ...]:
        return tuple(self._records[record.object_id] for record in self._records.values())

    def records(self) -> tuple[Any, ...]:
        return tuple(self._records.values())

    def _store_record(self, record: Incident) -> None:
        decoded = Incident.from_dict(record.to_dict())
        self._records[decoded.object_id] = decoded

    def _advance(
        self,
        record: Incident,
        command: Command,
        *,
        state: str,
        spec: IncidentSpec | None = None,
    ) -> Incident:
        envelope = advance_envelope(
            record.envelope,
            state=state,
            provenance=self._provenance(command),
            causation_id=command.command_id,
            correlation_id=command.correlation_id,
        )
        new_spec = spec if spec is not None else record.spec
        integrity = seal_record(envelope, new_spec)
        return Incident(envelope=envelope, spec=new_spec, integrity_hash=integrity)

    def _require_source_state(self, command_type: str, state: IncidentState) -> None:
        from .contracts import OPERATIONS_TRANSITIONS

        allowed = OPERATIONS_TRANSITIONS[command_type]
        if state not in allowed:
            raise CoreValidationError(
                f"{command_type} cannot advance from state {state.value!r}; "
                f"allowed source states are "
                f"{sorted(member.value for member in allowed)}"
            )

    # ------------------------------------------------------------------
    # handlers (validate-then-compute)
    # ------------------------------------------------------------------

    def _handle_incident(self, command: Command, view: Any) -> TransitionApplication:
        payload = _payload_dict(command)
        strict_fields("operations/incident payload", payload, _INCIDENT_PAYLOAD_FIELDS)
        incident_id = require_identifier("payload incident_id", payload["incident_id"])
        dependency_id = require_identifier(
            "payload dependency_id", payload["dependency_id"]
        )
        summary = require_text("payload summary", payload["summary"])
        trigger = _parse_probe(payload["trigger_probe"], "payload trigger_probe")
        if incident_id in self._records:
            raise CoreValidationError(
                f"incident {incident_id!r} already exists; incidents are unique"
            )
        if not self._graph.has_dependency(dependency_id):
            raise CoreValidationError(
                f"incident trigger targets undeclared dependency {dependency_id!r}"
            )
        if trigger.dependency_id != dependency_id:
            raise CoreValidationError(
                f"the incident trigger probe targets dependency "
                f"{trigger.dependency_id!r}, not {dependency_id!r}"
            )
        profile = self._profile_for_dependency(dependency_id)
        status = classify_health(
            trigger,
            profile,
            dependency_service=self._graph.service_of(dependency_id),
        )
        if status is HealthStatus.HEALTHY:
            raise CoreValidationError(
                f"incident triggers require an UNHEALTHY dependency probe; "
                f"dependency {dependency_id!r} classifies HEALTHY — a healthy "
                "trigger would fabricate an incident (fail closed)"
            )
        severity = _SEVERITY_BY_HEALTH[status]
        record = make_incident_record(
            incident_id=incident_id,
            dependency_id=dependency_id,
            summary=summary,
            trigger_probe_digest=probe_digest(trigger),
            trigger_as_of=trigger.as_of,
            opened_at=command.requested_at,
            severity=severity,
            environment_id=command.environment_id,
            domain_id=command.domain_id,
            provenance=self._provenance(command),
            causation_id=command.command_id,
            correlation_id=command.correlation_id,
        )
        return TransitionApplication(
            (record.envelope,), {"incident": record.to_dict()}
        )

    def _handle_declare_degradation(
        self, command: Command, view: Any
    ) -> TransitionApplication:
        payload = _payload_dict(command)
        strict_fields(
            "operations/declare-degradation payload", payload, _DEGRADATION_PAYLOAD_FIELDS
        )
        incident = self.incident(require_identifier("payload incident_id", payload["incident_id"]))
        self._require_source_state("operations/declare-degradation", incident.state)
        probe = _parse_probe(payload["probe"], "payload probe")
        affected = tuple(payload["affected_dependencies"])
        detail = require_text("payload detail", payload["detail"])
        if probe.dependency_id != incident.spec.dependency_id:
            raise CoreValidationError(
                f"the degradation probe targets dependency {probe.dependency_id!r}, "
                f"not the incident's dependency {incident.spec.dependency_id!r}"
            )
        status = self._classify(probe, incident.spec.dependency_id)
        if status is HealthStatus.HEALTHY:
            raise CoreValidationError(
                f"dependency {incident.spec.dependency_id!r} classifies HEALTHY; a "
                "degradation declaration requires an unhealthy probe (fail closed)"
            )
        severity = _SEVERITY_BY_HEALTH[status]
        # The monotone gate compares the new fact against the LAST declared
        # degradation fact: consecutive declarations may only worsen. The
        # FIRST declaration on an open incident is free (the incident's own
        # trigger severity classifies the trigger probe, not the scoped
        # degradation declaration that follows). The incident's recorded
        # severity always tracks the WORST declared fact (the spec's
        # consistency invariant) and improves only through Resolve
        # (recovery is a closure, never a silent improvement).
        facts = incident.spec.degradation_facts
        if facts:
            last = DegradationSeverity(facts[-1].severity)
            if DEGRADATION_SEVERITY_ORDER[severity] < DEGRADATION_SEVERITY_ORDER[last]:
                raise CoreValidationError(
                    f"declared severity {severity.value} improves on the last "
                    f"declared degradation severity {last.value}; degradations "
                    "may only worsen — improvement is recovery and closes "
                    "through Resolve"
                )
        if incident.spec.dependency_id not in affected:
            raise CoreValidationError(
                "the affected dependency scope must include the incident's own "
                f"dependency {incident.spec.dependency_id!r}"
            )
        for dependency_id in affected:
            if not self._graph.has_dependency(dependency_id):
                raise CoreValidationError(
                    f"affected dependency {dependency_id!r} is not declared in the "
                    "dependency graph"
                )
        fact = DegradationFact(
            severity=severity.value,
            probe_digest=probe_digest(probe),
            probe_as_of=probe.as_of,
            affected_dependencies=affected,
            affected_authorities=tuple(
                (entry["authority_ref"], entry["digest"])
                if isinstance(entry, Mapping)
                else (entry[0], entry[1])
                for entry in payload["affected_authorities"]
            ),
            observed_at=command.requested_at,
            detail=detail,
        )
        updated_facts = incident.spec.degradation_facts + (fact,)
        worst_severity = max(
            (DegradationSeverity(entry.severity) for entry in updated_facts),
            key=lambda member: DEGRADATION_SEVERITY_ORDER[member],
        )
        new_spec = IncidentSpec(
            incident_id=incident.spec.incident_id,
            dependency_id=incident.spec.dependency_id,
            summary=incident.spec.summary,
            trigger_probe_digest=incident.spec.trigger_probe_digest,
            trigger_as_of=incident.spec.trigger_as_of,
            opened_at=incident.spec.opened_at,
            severity=worst_severity.value,
            degradation_facts=updated_facts,
            failover_fact=incident.spec.failover_fact,
            emergency_fact=incident.spec.emergency_fact,
            resolution_fact=incident.spec.resolution_fact,
        )
        advanced = self._advance(
            incident,
            command,
            state=IncidentState.DEGRADED.value,
            spec=new_spec,
        )
        return TransitionApplication(
            (advanced.envelope,), {"incident": advanced.to_dict()}
        )

    def _handle_failover(self, command: Command, view: Any) -> TransitionApplication:
        payload = _payload_dict(command)
        strict_fields("operations/failover payload", payload, _FAILOVER_PAYLOAD_FIELDS)
        incident = self.incident(require_identifier("payload incident_id", payload["incident_id"]))
        self._require_source_state("operations/failover", incident.state)
        target_id = require_identifier(
            "payload target_dependency_id", payload["target_dependency_id"]
        )
        target_probe = _parse_probe(payload["target_probe"], "payload target_probe")
        detail = require_text("payload detail", payload["detail"])
        if not self._graph.has_dependency(target_id):
            raise CoreValidationError(
                f"failover target {target_id!r} is not a declared dependency"
            )
        profile = self._profile_for_dependency(incident.spec.dependency_id)
        if target_id not in profile.spec.redundancy:
            raise CoreValidationError(
                f"failover target {target_id!r} is not a declared redundancy of the "
                f"resilience profile of service {profile.spec.service_id!r}; "
                "failover onto an undeclared target fails closed"
            )
        if target_id == incident.spec.dependency_id:
            raise CoreValidationError(
                "failover target must differ from the failed dependency"
            )
        if target_probe.dependency_id != target_id:
            raise CoreValidationError(
                f"the failover target probe targets dependency "
                f"{target_probe.dependency_id!r}, not the declared target {target_id!r}"
            )
        target_status = self._classify(target_probe, target_id)
        if target_status is not HealthStatus.HEALTHY:
            raise CoreValidationError(
                f"failover target {target_id!r} classifies {target_status.value}; "
                "failover onto an unhealthy redundancy fails closed"
            )
        fact = FailoverFact(
            from_dependency=incident.spec.dependency_id,
            target_dependency=target_id,
            target_probe_digest=probe_digest(target_probe),
            target_probe_as_of=target_probe.as_of,
            adapter_contract=dict(payload["adapter_contract"]),
            authority_digests=tuple(
                (entry["authority_ref"], entry["digest"])
                if isinstance(entry, Mapping)
                else (entry[0], entry[1])
                for entry in payload["authority_digests"]
            ),
            executed_at=command.requested_at,
            detail=detail,
        )
        # Authority conservation: a failover decision is control-plane only.
        # Every affected authority recorded at degradation must still carry
        # the exact same digest — the decision must not have mutated
        # authoritative state.
        latest = incident.spec.degradation_facts[-1] if incident.spec.degradation_facts else None
        if latest is None:
            raise CoreValidationError(
                "failover requires a declared degradation with affected authorities"
            )
        declared = {ref: digest for ref, digest in latest.affected_authorities}
        supplied = {ref: digest for ref, digest in fact.authority_digests}
        if declared != supplied:
            raise CoreValidationError(
                "failover conservation gate: the affected-authority digests do not "
                "match the digests recorded at degradation time; a failover "
                "decision must not mutate authoritative state "
                f"(recorded={sorted(declared)}, supplied={sorted(supplied)})"
            )
        new_spec = IncidentSpec(
            incident_id=incident.spec.incident_id,
            dependency_id=incident.spec.dependency_id,
            summary=incident.spec.summary,
            trigger_probe_digest=incident.spec.trigger_probe_digest,
            trigger_as_of=incident.spec.trigger_as_of,
            opened_at=incident.spec.opened_at,
            severity=incident.spec.severity,
            degradation_facts=incident.spec.degradation_facts,
            failover_fact=fact,
            emergency_fact=incident.spec.emergency_fact,
            resolution_fact=incident.spec.resolution_fact,
        )
        advanced = self._advance(
            incident, command, state=IncidentState.FAILED_OVER.value, spec=new_spec
        )
        return TransitionApplication(
            (advanced.envelope,), {"incident": advanced.to_dict()}
        )

    def _handle_emergency(self, command: Command, view: Any) -> TransitionApplication:
        payload = _payload_dict(command)
        strict_fields("operations/emergency payload", payload, _EMERGENCY_PAYLOAD_FIELDS)
        incident = self.incident(require_identifier("payload incident_id", payload["incident_id"]))
        self._require_source_state("operations/emergency", incident.state)
        fact = EmergencyFact(
            window_from=payload["window_from"],
            window_until=payload["window_until"],
            mandate=require_text("payload mandate", payload["mandate"]),
            scope=tuple(payload["scope"]),
            declared_at=command.requested_at,
        )
        if incident.spec.dependency_id not in fact.scope:
            raise CoreValidationError(
                "the emergency scope must include the incident's own dependency "
                f"{incident.spec.dependency_id!r} (emergencies are narrowly scoped)"
            )
        for dependency_id in fact.scope:
            if not self._graph.has_dependency(dependency_id):
                raise CoreValidationError(
                    f"emergency scope dependency {dependency_id!r} is not declared "
                    "in the dependency graph"
                )
        new_spec = IncidentSpec(
            incident_id=incident.spec.incident_id,
            dependency_id=incident.spec.dependency_id,
            summary=incident.spec.summary,
            trigger_probe_digest=incident.spec.trigger_probe_digest,
            trigger_as_of=incident.spec.trigger_as_of,
            opened_at=incident.spec.opened_at,
            severity=incident.spec.severity,
            degradation_facts=incident.spec.degradation_facts,
            failover_fact=incident.spec.failover_fact,
            emergency_fact=fact,
            resolution_fact=incident.spec.resolution_fact,
        )
        advanced = self._advance(
            incident, command, state=IncidentState.ESCALATED.value, spec=new_spec
        )
        return TransitionApplication(
            (advanced.envelope,), {"incident": advanced.to_dict()}
        )

    def _handle_resolve(self, command: Command, view: Any) -> TransitionApplication:
        payload = _payload_dict(command)
        strict_fields("operations/resolve payload", payload, _RESOLVE_PAYLOAD_FIELDS)
        incident = self.incident(require_identifier("payload incident_id", payload["incident_id"]))
        self._require_source_state("operations/resolve", incident.state)
        probes = tuple(
            _parse_probe(entry, "payload probes entry") for entry in payload["probes"]
        )
        actions = tuple(
            RecoveryActionRecord.from_dict(entry) if isinstance(entry, Mapping) else entry
            for entry in payload["recovery_actions"]
        )
        note = require_text("payload note", payload["note"])
        latest = incident.spec.degradation_facts[-1] if incident.spec.degradation_facts else None
        affected = latest.affected_dependencies if latest is not None else (incident.spec.dependency_id,)
        profile = self._profile_for_dependency(incident.spec.dependency_id)

        # Gate 1 — fresh HEALTHY probes for the EXACT affected set.
        probed = {probe.dependency_id: probe for probe in probes}
        if set(probed) != set(affected):
            raise CoreValidationError(
                "resolution probes must cover exactly the affected dependencies "
                f"{sorted(affected)}; got {sorted(probed)} (fail closed on both "
                "missing and unexpected probes)"
            )
        for dependency_id in affected:
            status = self._classify(probed[dependency_id], dependency_id)
            if status is not HealthStatus.HEALTHY:
                raise CoreValidationError(
                    f"resolution requires dependency {dependency_id!r} to classify "
                    f"HEALTHY; it classifies {status.value} — resolving an "
                    "unrecovered dependency would fabricate recovery (fail closed)"
                )

        # Gate 2 — the declared recovery plan is fully covered, with no
        # undeclared actions.
        declared_actions = frozenset(profile.spec.recovery_actions)
        executed_kinds = frozenset(action.action for action in actions)
        if latest is not None:
            if executed_kinds != declared_actions:
                raise CoreValidationError(
                    "resolution recovery coverage gate: the declared recovery plan "
                    f"{sorted(kind.value for kind in declared_actions)} must be "
                    f"exactly covered; executed were "
                    f"{sorted(kind.value for kind in executed_kinds)} "
                    "(fail closed on both missing and undeclared actions)"
                )
        elif actions:
            raise CoreValidationError(
                "an incident without a declared degradation carries no recovery "
                "plan; recovery action records are not applicable (fail closed)"
            )

        # Gate 3 — journal-only rebuild evidence for every affected
        # authority: the live index digest must equal the rebuilt index
        # digest (no silent state loss, constitution invariant 12).
        evidence = tuple(
            AuthorityRebuild.from_dict(entry) if isinstance(entry, Mapping) else entry
            for entry in payload["authority_evidence"]
        )
        if latest is not None:
            recorded_refs = {ref for ref, _ in latest.affected_authorities}
            supplied_refs = {rebuild.authority_ref for rebuild in evidence}
            if recorded_refs != supplied_refs:
                raise CoreValidationError(
                    "resolution authority evidence must cover exactly the affected "
                    f"authorities {sorted(recorded_refs)}; got {sorted(supplied_refs)}"
                )
            for rebuild in evidence:
                if rebuild.live_index_digest != rebuild.rebuilt_index_digest:
                    raise CoreValidationError(
                        f"authority conservation gate for {rebuild.authority_ref!r}: "
                        "the journal-only rebuild index digest diverges from the "
                        "live index digest — authoritative state was lost or "
                        "diverged and resolution fails closed"
                    )
        elif evidence:
            raise CoreValidationError(
                "an incident without a declared degradation records no affected "
                "authorities; authority rebuild evidence is not applicable"
            )

        # Gate 4 — recovery within the declared recovery time objective.
        if latest is not None:
            duration = elapsed_seconds("recovery", latest.observed_at, command.requested_at)
            if duration > profile.spec.recovery_time_objective_seconds:
                raise CoreValidationError(
                    f"recovery took {duration}s, exceeding the declared recovery "
                    f"time objective of {profile.spec.recovery_time_objective_seconds}s "
                    "for service "
                    f"{profile.spec.service_id!r}; resolution fails closed"
                )
        else:
            duration = 0

        fact = ResolutionFact(
            probe_digests=tuple(
                (probe.dependency_id, probe_digest(probe)) for probe in probes
            ),
            recovery_actions=actions,
            authority_rebuilds=evidence,
            recovery_duration_seconds=duration,
            resolved_at=command.requested_at,
            note=note,
        )
        new_spec = IncidentSpec(
            incident_id=incident.spec.incident_id,
            dependency_id=incident.spec.dependency_id,
            summary=incident.spec.summary,
            trigger_probe_digest=incident.spec.trigger_probe_digest,
            trigger_as_of=incident.spec.trigger_as_of,
            opened_at=incident.spec.opened_at,
            severity=incident.spec.severity,
            degradation_facts=incident.spec.degradation_facts,
            failover_fact=incident.spec.failover_fact,
            emergency_fact=incident.spec.emergency_fact,
            resolution_fact=fact,
        )
        advanced = self._advance(
            incident, command, state=IncidentState.RESOLVED.value, spec=new_spec
        )
        return TransitionApplication(
            (advanced.envelope,), {"incident": advanced.to_dict()}
        )

    # ------------------------------------------------------------------
    # public command surface (the frozen family)
    # ------------------------------------------------------------------

    def open_incident(
        self,
        *,
        command_id: str,
        requested_at: str,
        incident_id: str,
        dependency_id: str,
        trigger_probe: ProbeResult | Mapping[str, Any],
        summary: str = "operational incident declared",
    ) -> OperationsTransition:
        """``Operations: Incident`` — declare one incident from an unhealthy probe."""
        if incident_id in self._records:
            # Typed fail-fast duplicate guard: incidents are unique (the
            # kernel's version gate and the handler re-validate).
            raise CoreValidationError(
                f"incident {incident_id!r} already exists; incidents are unique"
            )
        command = self.build_raw_command(
            command_id=command_id,
            command_type="operations/incident",
            requested_at=requested_at,
            target_refs=(incident_id,),
            payload={
                "incident_id": incident_id,
                "dependency_id": dependency_id,
                "trigger_probe": trigger_probe.to_dict()
                if isinstance(trigger_probe, ProbeResult)
                else dict(trigger_probe),
                "summary": summary,
            },
            expected_versions={incident_id: 0},
        )
        return self.submit(command)

    def declare_degradation(
        self,
        *,
        command_id: str,
        requested_at: str,
        incident_id: str,
        probe: ProbeResult | Mapping[str, Any],
        affected_dependencies: Iterable[str],
        affected_authorities: Mapping[str, str] | Iterable[Any],
        detail: str = "degradation declared",
    ) -> OperationsTransition:
        """``Operations: DeclareDegradation`` — declare severity, scope and authority digests."""
        self._require_command_state(
            "operations/declare-degradation", incident_id
        )
        if isinstance(affected_authorities, Mapping):
            authorities = [
                {"authority_ref": ref, "digest": digest}
                for ref, digest in affected_authorities.items()
            ]
        else:
            authorities = [
                {"authority_ref": entry["authority_ref"], "digest": entry["digest"]}
                if isinstance(entry, Mapping)
                else {"authority_ref": entry[0], "digest": entry[1]}
                for entry in affected_authorities
            ]
        command = self.build_raw_command(
            command_id=command_id,
            command_type="operations/declare-degradation",
            requested_at=requested_at,
            target_refs=(incident_id,),
            payload={
                "incident_id": incident_id,
                "probe": probe.to_dict() if isinstance(probe, ProbeResult) else dict(probe),
                "affected_dependencies": list(affected_dependencies),
                "affected_authorities": authorities,
                "detail": detail,
            },
            expected_versions={incident_id: self.incident(incident_id).envelope.object_version},
        )
        return self.submit(command)

    def execute_failover(
        self,
        *,
        command_id: str,
        requested_at: str,
        incident_id: str,
        target_dependency_id: str,
        target_probe: ProbeResult | Mapping[str, Any],
        adapter_contract: Mapping[str, Any],
        authority_digests: Mapping[str, str] | Iterable[Any],
        detail: str = "failover executed",
    ) -> OperationsTransition:
        """``Operations: Failover`` — declare the failover onto a redundancy target."""
        self._require_command_state("operations/failover", incident_id)
        if isinstance(authority_digests, Mapping):
            digests = [
                {"authority_ref": ref, "digest": digest}
                for ref, digest in authority_digests.items()
            ]
        else:
            digests = [
                {"authority_ref": entry["authority_ref"], "digest": entry["digest"]}
                if isinstance(entry, Mapping)
                else {"authority_ref": entry[0], "digest": entry[1]}
                for entry in authority_digests
            ]
        command = self.build_raw_command(
            command_id=command_id,
            command_type="operations/failover",
            requested_at=requested_at,
            target_refs=(incident_id,),
            payload={
                "incident_id": incident_id,
                "target_dependency_id": target_dependency_id,
                "target_probe": target_probe.to_dict()
                if isinstance(target_probe, ProbeResult)
                else dict(target_probe),
                "adapter_contract": dict(adapter_contract),
                "authority_digests": digests,
                "detail": detail,
            },
            expected_versions={incident_id: self.incident(incident_id).envelope.object_version},
        )
        return self.submit(command)

    def declare_emergency(
        self,
        *,
        command_id: str,
        requested_at: str,
        incident_id: str,
        window_from: str,
        window_until: str,
        mandate: str,
        scope: Iterable[str],
    ) -> OperationsTransition:
        """``Operations: Emergency`` — declare a narrow, time-bounded emergency."""
        self._require_command_state("operations/emergency", incident_id)
        command = self.build_raw_command(
            command_id=command_id,
            command_type="operations/emergency",
            requested_at=requested_at,
            target_refs=(incident_id,),
            payload={
                "incident_id": incident_id,
                "window_from": window_from,
                "window_until": window_until,
                "mandate": mandate,
                "scope": list(scope),
            },
            expected_versions={incident_id: self.incident(incident_id).envelope.object_version},
        )
        return self.submit(command)

    def resolve_incident(
        self,
        *,
        command_id: str,
        requested_at: str,
        incident_id: str,
        probes: Iterable[ProbeResult | Mapping[str, Any]],
        recovery_actions: Iterable[RecoveryActionRecord | Mapping[str, Any]],
        authority_evidence: Mapping[str, Any] | Iterable[Any] = (),
        note: str = "incident resolved",
    ) -> OperationsTransition:
        """``Operations: Resolve`` — close with complete recovery evidence."""
        self._require_command_state("operations/resolve", incident_id)
        if isinstance(authority_evidence, Mapping):
            evidence = [
                {
                    "authority_ref": ref,
                    "live_index_digest": digests[0],
                    "rebuilt_index_digest": digests[1],
                }
                for ref, digests in authority_evidence.items()
            ]
        else:
            evidence = [
                entry if isinstance(entry, Mapping) else entry.to_dict()
                for entry in authority_evidence
            ]
        command = self.build_raw_command(
            command_id=command_id,
            command_type="operations/resolve",
            requested_at=requested_at,
            target_refs=(incident_id,),
            payload={
                "incident_id": incident_id,
                "probes": [
                    probe.to_dict() if isinstance(probe, ProbeResult) else dict(probe)
                    for probe in probes
                ],
                "recovery_actions": [
                    action.to_dict()
                    if isinstance(action, RecoveryActionRecord)
                    else dict(action)
                    for action in recovery_actions
                ],
                "authority_evidence": evidence,
                "note": note,
            },
            expected_versions={incident_id: self.incident(incident_id).envelope.object_version},
        )
        return self.submit(command)

    # ------------------------------------------------------------------
    # event folding, snapshots and journal-only rebuild
    # ------------------------------------------------------------------

    def _apply_event_payload(self, event_type: str, payload: Any) -> None:
        if not isinstance(payload, dict):
            raise CoreValidationError("operations journal payloads must be objects")
        if event_type in COMMAND_EVENT_TYPES.values():
            strict_fields("operations journal payload", payload, frozenset({"incident"}))
            self._store_record(Incident.from_dict(payload["incident"]))
            return
        raise CoreValidationError(f"unknown operations event type {event_type!r}")

    def snapshot_state(self) -> dict[str, Any]:
        """Canonical, byte-stable snapshot of the composed engine state."""
        return {
            "schema_version": 1,
            "environment_id": self._environment_id,
            "domain_id": self._domain_id,
            "index": {
                object_id: record.to_dict() for object_id, record in self._records.items()
            },
            "engine": self._kernel.snapshot_state().to_dict(),
            "store": [envelope.to_dict() for envelope in self._store.snapshot()],
        }

    def restore_state(self, snapshot: Mapping[str, Any]) -> None:
        """Rebuild the engine from a canonical snapshot (fail closed)."""
        require_mapping("engine snapshot", snapshot)
        strict_fields("engine snapshot", snapshot, _SNAPSHOT_FIELDS)
        if snapshot["schema_version"] != 1:
            raise CoreValidationError("engine snapshot schema version must be 1")
        if snapshot["environment_id"] != self._environment_id:
            raise CoreValidationError(
                f"snapshot environment {snapshot['environment_id']!r} does not match "
                f"engine environment {self._environment_id!r}"
            )
        if snapshot["domain_id"] != self._domain_id:
            raise CoreValidationError(
                f"snapshot domain {snapshot['domain_id']!r} does not match engine "
                f"domain {self._domain_id!r}"
            )
        index_raw = require_mapping("engine snapshot index", snapshot["index"])
        records: dict[str, Incident] = {}
        for object_id, composite in index_raw.items():
            require_identifier("engine snapshot object_id", object_id)
            record = Incident.from_dict(composite)
            if record.object_id != object_id:
                raise CoreValidationError(
                    f"snapshot key {object_id!r} does not match object id "
                    f"{record.object_id!r}"
                )
            records[object_id] = record
        store_raw = snapshot["store"]
        if not isinstance(store_raw, list):
            raise CoreValidationError("engine snapshot store must deserialize from a list")
        envelopes = tuple(ObjectEnvelope.from_dict(entry) for entry in store_raw)
        store = MemoryStateStore(envelopes)
        store_by_id = {envelope.object_id: envelope for envelope in envelopes}
        for object_id, record in records.items():
            stored = store_by_id.get(object_id)
            if stored is None or stored != record.envelope:
                raise CoreValidationError(
                    f"snapshot index and store disagree on object {object_id!r}"
                )
        engine_state = EngineState.from_dict(snapshot["engine"])
        self._records = records
        self._store = store
        self._kernel = self._build_kernel()
        self._kernel.restore_state(engine_state)
        # The transitions log is an engine-local decision log; it is not
        # part of durable state (the kernel journal is authoritative).

    @classmethod
    def rebuild_from_journal(
        cls,
        *,
        environment_id: str,
        domain_id: str,
        dependency_graph: DependencyGraph,
        resilience_profiles: Mapping[str, ResilienceProfile],
        journal: Iterable[Any],
        actor: str = DEFAULT_ENGINE_ACTOR,
        command_authority_class: str = DEFAULT_COMMAND_AUTHORITY_CLASS,
    ) -> "OperationsEngine":
        """Rebuild the incident index from the kernel journal alone.

        Transformation completeness: the committed event payloads carry
        every resulting record, so folding the journal rebuilds the
        composed domain state deterministically. The kernel's command-id
        dedup restarts after a journal-only rebuild (command envelopes
        are not part of the journal). The declared graph and profiles are
        re-injected as validated configuration (they are not
        journal-derived state).
        """
        engine = cls(
            environment_id=environment_id,
            domain_id=domain_id,
            dependency_graph=dependency_graph,
            resilience_profiles=resilience_profiles,
            actor=actor,
            command_authority_class=command_authority_class,
        )
        entries = tuple(journal)
        for entry in entries:
            engine._apply_event_payload(entry.event.event_type, _journal_payload(entry))
        if entries:
            state = EngineState(
                logical_time=entries[-1].event.logical_time,
                records=(),
                journal=entries,
            )
            engine._store = MemoryStateStore(
                record.envelope for record in engine._records.values()
            )
            engine._kernel = engine._build_kernel()
            engine._kernel.restore_state(state)
        return engine
