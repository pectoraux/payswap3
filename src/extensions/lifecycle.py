"""The frozen extension lifecycle state machine (extensions.md).

``DRAFT → SANDBOX → TESTED → SUBMITTED → SECURITY_REVIEW →
POLICY_REVIEW → PUBLISHED → INSTALLED → ACTIVE → DEGRADED →
SUSPENDED → DEPRECATED → ARCHIVED``.

The transition table lives in :mod:`src.extensions.contracts`
(:data:`LIFECYCLE_TRANSITIONS`); this module maps the command verbs onto
its edges and fails closed on every unknown (verb, state) pair. All
mutations still flow exclusively through the transition kernel — this
module only computes target states; it is not a second state machine.
"""

from __future__ import annotations

from src.core.errors import CoreValidationError

from .contracts import (
    INSTANCE_LIFECYCLE_STATES,
    MANIFEST_LIFECYCLE_STATES,
    ExtensionLifecycleState,
    LIFECYCLE_TRANSITIONS,
)
from ._validation import parse_enum

#: Manifest-command edges (the lifecycle head).
_MANIFEST_EDGES: dict[tuple[str, str], ExtensionLifecycleState] = {
    ("submit", "DRAFT"): ExtensionLifecycleState.SANDBOX,
    ("certify", "SANDBOX"): ExtensionLifecycleState.TESTED,
    ("submit", "TESTED"): ExtensionLifecycleState.SUBMITTED,
    ("approve", "SUBMITTED"): ExtensionLifecycleState.SECURITY_REVIEW,
    ("approve", "SECURITY_REVIEW"): ExtensionLifecycleState.POLICY_REVIEW,
    ("reject", "SUBMITTED"): ExtensionLifecycleState.SANDBOX,
    ("reject", "SECURITY_REVIEW"): ExtensionLifecycleState.SANDBOX,
    ("reject", "POLICY_REVIEW"): ExtensionLifecycleState.SANDBOX,
    ("publish", "POLICY_REVIEW"): ExtensionLifecycleState.PUBLISHED,
}

#: Instance-command edges (the lifecycle tail).
_INSTANCE_EDGES: dict[tuple[str, str], ExtensionLifecycleState] = {
    ("activate", "INSTALLED"): ExtensionLifecycleState.ACTIVE,
    ("degrade", "ACTIVE"): ExtensionLifecycleState.DEGRADED,
    ("suspend", "ACTIVE"): ExtensionLifecycleState.SUSPENDED,
    ("suspend", "DEGRADED"): ExtensionLifecycleState.SUSPENDED,
    ("resume", "SUSPENDED"): ExtensionLifecycleState.ACTIVE,
    ("resume", "DEGRADED"): ExtensionLifecycleState.ACTIVE,
}


def resolve_lifecycle_transition(
    verb: str, current: ExtensionLifecycleState
) -> ExtensionLifecycleState:
    """Resolve the target state of one lifecycle command (fail closed).

    ``deprecate`` is valid from any non-terminal, non-DEPRECATED state;
    ``archive`` is valid from any non-archived state and terminal. The
    specialized verbs (``install``, ``shadow``, ``invoke``, ``measure``,
    ``register``) are not state edges of existing objects and are
    rejected here.
    """
    if not isinstance(verb, str) or not verb.strip():
        raise CoreValidationError("lifecycle verb must be a non-empty string")
    if not isinstance(current, ExtensionLifecycleState):
        current = parse_enum("lifecycle state", ExtensionLifecycleState, current)
    if verb in ("register", "install", "shadow", "invoke", "measure"):
        raise CoreValidationError(
            f"lifecycle verb {verb!r} does not advance an existing object's state"
        )
    key = (verb, current.value)
    if verb in ("deprecate", "archive"):
        if current is ExtensionLifecycleState.ARCHIVED:
            raise CoreValidationError("ARCHIVED is terminal; no lifecycle verb applies")
        if verb == "deprecate" and current is ExtensionLifecycleState.DEPRECATED:
            raise CoreValidationError("DEPRECATED objects cannot be deprecated twice")
        return (
            ExtensionLifecycleState.ARCHIVED
            if verb == "archive"
            else ExtensionLifecycleState.DEPRECATED
        )
    if key in _MANIFEST_EDGES:
        target = _MANIFEST_EDGES[key]
        if target not in LIFECYCLE_TRANSITIONS[current]:
            raise CoreValidationError(
                f"lifecycle transition {current.value} --{verb}--> {target.value} "
                "is not part of the frozen transition table"
            )
        return target
    if key in _INSTANCE_EDGES:
        target = _INSTANCE_EDGES[key]
        if target not in LIFECYCLE_TRANSITIONS[current]:
            raise CoreValidationError(
                f"lifecycle transition {current.value} --{verb}--> {target.value} "
                "is not part of the frozen transition table"
            )
        return target
    raise CoreValidationError(
        f"lifecycle verb {verb!r} has no edge from state {current.value}"
    )


def parse_lifecycle_state(value: object) -> ExtensionLifecycleState:
    return parse_enum("extension lifecycle state", ExtensionLifecycleState, value)


def require_manifest_state(state: ExtensionLifecycleState) -> ExtensionLifecycleState:
    if state not in MANIFEST_LIFECYCLE_STATES:
        raise CoreValidationError(
            f"manifest objects cannot hold the instance lifecycle state {state.value}"
        )
    return state


def require_instance_state(state: ExtensionLifecycleState) -> ExtensionLifecycleState:
    if state not in INSTANCE_LIFECYCLE_STATES:
        raise CoreValidationError(
            f"instance objects cannot hold the manifest lifecycle state {state.value}"
        )
    return state
