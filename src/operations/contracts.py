"""Frozen public-boundary contracts for the operations domain (WORK-024).

This package owns the frozen v0.1 ``Operations`` command family
``DeclareDegradation/Failover/Incident/Emergency/Resolve`` (command-event
model), the declared dependency/exposure graph and the declared resilience
profiles of the frozen architecture's security-risk model ("the protocol
maintains a dependency/exposure graph", "critical services declare
availability, capacity, redundancy, recovery point/time, failover and
dependency policies", "operational failure is isolated and observable"),
plus the derived health/economic metrics and systemic risk assessments of
the canonical object model's "Federation and operations" family.

Registry discipline: NO operations object type and NO operations event
namespace is listed in the frozen protocol registry. Object types
therefore follow the sibling convention and use internal non-registry
``operations/...`` formats, and events use the ALREADY REGISTERED
``governance`` namespace exactly as registered (the federation and agents
module precedents; the frozen governance.md scope — in particular its
"Emergency authority" section, which constrains this domain's ``Emergency``
command to narrow, time-bounded, heavily audited, history-preserving
actions). No new protocol-visible name is invented here.

Boundary discipline ("no alternate source of truth"): this package is an
OBSERVER, COMPOSER and ORCHESTRATOR of the real merged authorities. Health
is probed through caller-supplied typed probe ports over public boundaries
(ports over providers, implementation principle 4), economic exposure is
computed from real clearing obligation records, and recovery happens only
through sibling public APIs with digest-bound evidence — operations never
re-derives authoritative sibling state, never mutates sibling lifecycles,
and never becomes a second authority.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Mapping

from src.core.errors import CoreValidationError
from src.transition.registry import PROTOCOL_VERSION

from ._validation import parse_enum, require_int, require_text

# -- typed, versioned public boundary --------------------------------------

#: Version of this typed, versioned public boundary.
OPERATIONS_API_VERSION = "v0.1"

#: Frozen protocol version consumed (owned by the transition kernel registry).
OPERATIONS_PROTOCOL_VERSION = PROTOCOL_VERSION

#: Schema version of operations-domain durable objects.
OPERATIONS_SCHEMA_VERSION = 1

#: Internal (non-registry) object types of operations-domain durable objects.
DEPENDENCY_OBJECT_TYPE = "operations/dependency/v1"
RESILIENCE_PROFILE_OBJECT_TYPE = "operations/resilience-profile/v1"
INCIDENT_OBJECT_TYPE = "operations/incident/v1"
SYSTEMIC_RISK_OBJECT_TYPE = "operations/systemic-risk/v1"

#: Every object type this package may produce (all internal formats).
OBJECT_TYPES = (
    DEPENDENCY_OBJECT_TYPE,
    RESILIENCE_PROFILE_OBJECT_TYPE,
    INCIDENT_OBJECT_TYPE,
    SYSTEMIC_RISK_OBJECT_TYPE,
)

#: Registry-listed protocol event namespace used by this domain (the
#: federation/agents precedent — no operations namespace is registered, so
#: none is invented; governance.md scope covers operations records).
OPERATIONS_EVENT_NAMESPACE = "governance"

# -- the frozen command family ---------------------------------------------

#: The frozen v0.1 ``Operations`` command family (command-event-model.md):
#: ``DeclareDegradation/Failover/Incident/Emergency/Resolve``.
OPERATIONS_COMMANDS = frozenset(
    {
        "operations/incident",
        "operations/declare-degradation",
        "operations/failover",
        "operations/emergency",
        "operations/resolve",
    }
)

#: Command → canonical event type (all events use the registered
#: ``governance`` namespace; command types are internal free-form strings
#: per the sibling convention).
COMMAND_EVENT_TYPES: Mapping[str, str] = {
    "operations/incident": "governance/operational-incident-declared",
    "operations/declare-degradation": "governance/operational-degradation-declared",
    "operations/failover": "governance/operational-failover-executed",
    "operations/emergency": "governance/operational-emergency-declared",
    "operations/resolve": "governance/operational-incident-resolved",
}


# -- closed lifecycles ------------------------------------------------------


class IncidentState(StrEnum):
    """Closed lifecycle vocabulary of one operational incident.

    ``OPEN`` — declared from an unhealthy dependency probe (the trigger).
    ``DEGRADED`` — a degradation is formally declared with severity,
    affected dependencies and affected-authority digests. ``FAILED_OVER``
    — traffic is declared failed over to a redundancy target from the
    resilience profile. ``ESCALATED`` — a narrow, time-bounded emergency
    is in force (governance.md "Emergency authority": cannot rewrite
    history, erase liabilities, manufacture value or override genuine
    settlement finality). ``RESOLVED`` is terminal: recovery evidence is
    bound and the incident closes (the frozen family has no separate
    cancel command — ``Resolve`` is the single closure path).
    """

    OPEN = "OPEN"
    DEGRADED = "DEGRADED"
    FAILED_OVER = "FAILED_OVER"
    ESCALATED = "ESCALATED"
    RESOLVED = "RESOLVED"

    @classmethod
    def parse(cls, value: object) -> "IncidentState":
        """Fail closed on unknown incident states (implementation principle 6)."""
        return parse_enum("incident state", value, cls)  # type: ignore[return-value]


#: Terminal incident states: history stays immutable after them.
INCIDENT_TERMINAL_STATES = frozenset({IncidentState.RESOLVED})


class DependencyKind(StrEnum):
    """Closed vocabulary of dependency graph node kinds.

    ``PROVIDER_ADAPTER`` — an external effect provider bound through the
    execution domain's typed adapter ports. ``NETWORK_DOMAIN`` — a
    federated peer domain whose health is observed through its published
    state commitments. ``PROTOCOL_SERVICE`` — an internal protocol
    service of the canonical chain whose health is observed through its
    engines' public state.
    """

    PROVIDER_ADAPTER = "PROVIDER_ADAPTER"
    NETWORK_DOMAIN = "NETWORK_DOMAIN"
    PROTOCOL_SERVICE = "PROTOCOL_SERVICE"

    @classmethod
    def parse(cls, value: object) -> "DependencyKind":
        return parse_enum("dependency kind", value, cls)  # type: ignore[return-value]


class HealthStatus(StrEnum):
    """Closed derived classification of one dependency's health.

    DERIVED lifecycle class (ownership-lifecycle.md): never an
    authoritative state — always computed from probe evidence through
    the profile's declared thresholds.
    """

    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"

    @classmethod
    def parse(cls, value: object) -> "HealthStatus":
        return parse_enum("health status", value, cls)  # type: ignore[return-value]


class DegradationSeverity(StrEnum):
    """Closed vocabulary of declared degradation severity.

    ``DEGRADED`` — the dependency is partially available (below the
    profile's healthy threshold but still answering). ``UNAVAILABLE`` —
    the dependency is effectively dead (below the profile's unavailable
    threshold, or not answering at all).
    """

    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"

    @classmethod
    def parse(cls, value: object) -> "DegradationSeverity":
        return parse_enum("degradation severity", value, cls)  # type: ignore[return-value]


#: Frozen severity ordering: a declared degradation may only worsen.
DEGRADATION_SEVERITY_ORDER: Mapping[DegradationSeverity, int] = {
    DegradationSeverity.DEGRADED: 1,
    DegradationSeverity.UNAVAILABLE: 2,
}


class RecoveryActionKind(StrEnum):
    """Closed vocabulary of declared recovery orchestration actions.

    ``REPROBE`` — fresh health probes of the affected dependencies.
    ``RECONCILE`` — query the affected providers through their
    reconciliation ports for in-flight effects (the unknown-outcome
    discipline — reconcile before any unsafe retry). ``RETRY`` — re-arm
    and resubmit reconciled effects through the sibling engines' public
    retry paths. ``REBUILD`` — journal-only rebuild of the affected
    authority proving the state is reproducible and nothing was lost.
    """

    REPROBE = "REPROBE"
    RECONCILE = "RECONCILE"
    RETRY = "RETRY"
    REBUILD = "REBUILD"

    @classmethod
    def parse(cls, value: object) -> "RecoveryActionKind":
        return parse_enum("recovery action kind", value, cls)  # type: ignore[return-value]


# -- transition table -------------------------------------------------------


#: Allowed SOURCE states per command of the frozen family, expressed on
#: the primary object every command advances (the incident). The creation
#: command has an empty source set. The engine's handlers validate these
#: tables before advancing any state.
OPERATIONS_TRANSITIONS: Mapping[str, frozenset] = {
    # Incident opens from an unhealthy probe trigger.
    "operations/incident": frozenset(),
    # A degradation may be declared on an open incident and may WORSEN on
    # an already-degraded one (never improve — improving is recovery, and
    # recovery closes through Resolve).
    "operations/declare-degradation": frozenset(
        {IncidentState.OPEN, IncidentState.DEGRADED}
    ),
    # Failover executes from a declared degradation onto a declared
    # redundancy target of the resilience profile.
    "operations/failover": frozenset({IncidentState.DEGRADED}),
    # An emergency may be declared at any non-terminal point (an outage
    # can become critical before degradation is formally declared).
    "operations/emergency": frozenset(
        {
            IncidentState.OPEN,
            IncidentState.DEGRADED,
            IncidentState.FAILED_OVER,
        }
    ),
    # Resolve is the single closure path of the frozen family (no Cancel
    # command exists): every non-terminal incident closes through it with
    # recovery evidence.
    "operations/resolve": frozenset(
        {
            IncidentState.OPEN,
            IncidentState.DEGRADED,
            IncidentState.FAILED_OVER,
            IncidentState.ESCALATED,
        }
    ),
}


def validate_command(command: str) -> str:
    """Require a command from the frozen operations family."""
    require_text("command", command)
    if command not in OPERATIONS_COMMANDS:
        raise CoreValidationError(
            f"command {command!r} is not part of the frozen operations command family"
        )
    return command


def require_bps(name: str, value: int) -> int:
    """Require an availability/availability-target ratio in basis points."""
    require_int(name, value, minimum=0)
    if value > 10000:
        raise CoreValidationError(f"{name} must not exceed 10000 basis points")
    return value
