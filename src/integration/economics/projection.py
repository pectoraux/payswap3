"""The canonical semantic projection and normalization layer (IG-004).

The projection reads the composed economic state of one world through
the OWNING engines' trusted paths (the public accessors and state
digests of the merged extension runtime, agents engine and the sealed
merchant record — never gate-side caches) and produces the canonical
semantic record set of that execution:

* the sealed merchant checkout record;
* the extension-domain records (manifest, instance, grant,
  invocations, contributions) and the kernel journal events of the
  extension runtime;
* the agents-domain records (models, mandate, context, proposals,
  decision) and the kernel journal events of the agents engine;
* the stage-journal TUPLES (stage, domain, command_id, requested_at,
  outcome) of the gate's own append-only journal.

The normalization layer then applies the frozen, field-bound rule
registry from ``contracts.ECONOMICS_NORMALIZATION_RULES``: environment
identity and the extension runtime's environment mode are normalized
with exact-value validation (a foreign value fails closed instead of
normalizing), and the closed enumerated set of environment-bound
digest fields is excluded from the cross-environment byte comparison
with per-field justification.

Every difference that survives normalization at every other path is a
semantic divergence: the difference walk itself is delegated to the
merged IG-003 ``compare_projections`` authority (WORK-028) — this gate
introduces no second diff authority, it feeds the merged one. There is
no broad "ignore fields" strategy anywhere in this module.
"""

from __future__ import annotations

from typing import Any, Mapping

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.integration.parity import ClassifiedDifference, compare_projections

from src.integration.economics.contracts import (
    CONTRIBUTION_ID,
    ECONOMICS_ENV_BOUND_FIELDS,
    ECONOMICS_GATE_ID,
    ECONOMICS_NORMALIZATION_RULES,
    EXTENSION_ID,
    GRANT_ID,
    INSTANCE_ID,
    MANDATE_ID,
    PRODUCTION_COMPATIBLE_ENVIRONMENT_ID,
    SANDBOX_INVOCATION_ID,
    SHADOW_INVOCATION_ID,
    SIMULATION_ENVIRONMENT_ID,
    TREATMENT_INVOCATION_ID,
)
from src.integration.economics.worlds import EconomicWorld

#: Neutral tokens the normalization layer substitutes.
ENVIRONMENT_TOKEN = "{ENVIRONMENT}"
MODE_TOKEN = "{MODE}"

#: The frozen prefix of the mediation substrate's environment ids (the
#: merged WORK-021 convention: ``env/agents-mediation/<mediation-id>/
#: <proposal-suffix>``). These ids are identical across the two worlds
#: by construction (they derive from the shared mediation id), so they
#: are compared VERBATIM as content: a divergence in them is a real
#: semantic divergence, and any other foreign environment id fails
#: closed.
MEDIATION_ENVIRONMENT_PREFIX = "env/agents-mediation/"

#: The two declared environment ids of the compared worlds (fail-closed
#: validation: a foreign environment id never normalizes).
_DECLARED_ENVIRONMENTS = (
    SIMULATION_ENVIRONMENT_ID,
    PRODUCTION_COMPATIBLE_ENVIRONMENT_ID,
)

#: Fields excluded from byte comparison because they are environment
#: bound derived digests (justified per field in the registry).
_EXCLUDED_FIELDS = frozenset(ECONOMICS_ENV_BOUND_FIELDS)


def _rules_to_dicts() -> list[dict[str, str]]:
    return [
        {
            "rule_id": rule.rule_id,
            "field": rule.field,
            "reason": rule.reason,
            "rule": rule.rule,
            "safety_argument": rule.safety_argument,
        }
        for rule in ECONOMICS_NORMALIZATION_RULES
    ]


#: The digest of the frozen normalization contract itself: the rule
#: registry plus the exclusion set, sealed canonically. The verdict
#: reports it so a change of the normalization layer is visible.
NORMALIZATION_DIGEST = canonical_sha256(
    {
        "rules": _rules_to_dicts(),
        "excluded_digest_fields": sorted(ECONOMICS_ENV_BOUND_FIELDS),
        "declared_environments": list(_DECLARED_ENVIRONMENTS),
        "mediation_environment_prefix": MEDIATION_ENVIRONMENT_PREFIX,
    }
)


def _invocation_ids(world: EconomicWorld) -> tuple[str, ...]:
    """Every invocation id created in this world (sorted, existing only)."""
    known = set(world.treatment_invocation_ids)
    for invocation_id in (
        SANDBOX_INVOCATION_ID,
        TREATMENT_INVOCATION_ID,
        SHADOW_INVOCATION_ID,
    ):
        if world.runtime.store.get(invocation_id) is not None:
            known.add(invocation_id)
    return tuple(sorted(known))


def _extension_section(world: EconomicWorld) -> dict[str, Any]:
    store = world.runtime.store
    manifest = (
        world.runtime.manifest(EXTENSION_ID).to_dict()
        if store.get(EXTENSION_ID) is not None
        else None
    )
    instance = (
        world.runtime.instance(INSTANCE_ID).to_dict()
        if store.get(INSTANCE_ID) is not None
        else None
    )
    grant = (
        world.runtime.grant(GRANT_ID).to_dict()
        if store.get(GRANT_ID) is not None
        else None
    )
    invocations = {
        invocation_id: world.runtime.invocation(invocation_id).to_dict()
        for invocation_id in _invocation_ids(world)
    }
    contributions = {}
    if store.get(CONTRIBUTION_ID) is not None:
        contributions[CONTRIBUTION_ID] = world.runtime.contribution(
            CONTRIBUTION_ID
        ).to_dict()
    return {
        "manifest": manifest,
        "instance": instance,
        "grant": grant,
        "invocations": invocations,
        "contributions": contributions,
        "journal": [
            entry.event.to_dict() for entry in world.runtime.engine.journal
        ],
    }


def _agents_section(world: EconomicWorld) -> dict[str, Any]:
    mandate = world.agents.mandates.get(MANDATE_ID)
    proposals = {}
    for proposal_id in sorted(world.proposals):
        recorded = world.agents.get_proposal(proposal_id)
        if recorded is not None:
            proposals[proposal_id] = recorded.to_dict()
    return {
        "models": [record.to_dict() for record in world.agents.registry.models()],
        "mandate": mandate.to_dict() if mandate is not None else None,
        "context": world.context.to_dict() if world.context is not None else None,
        "proposals": proposals,
        "decision": world.decision.to_dict()
        if world.decision is not None
        else None,
        "journal": [entry.event.to_dict() for entry in world.agents.journal],
    }


def _gate_stage_journal(world: EconomicWorld) -> list[dict[str, Any]]:
    """The gate's stage-journal entries of ONE world (role-filtered)."""
    gate = world.gate
    if gate is None:
        return []
    return [
        entry for entry in gate.stage_journal if entry["role"] == world.role.value
    ]


def economic_state(world: EconomicWorld) -> dict[str, Any]:
    """The canonical semantic state of one composed economic execution.

    Read exclusively through the owning engines' public trusted paths
    (record accessors, state digests and journal projections). The
    stage journal is projected to its semantic TUPLE; the
    environment-bound checkpoint digests stay per world under their
    declared exclusion rules.
    """
    if not isinstance(world, EconomicWorld):
        raise CoreValidationError("economic_state requires an EconomicWorld")
    checkout = world.checkout
    return {
        "schema_version": 1,
        "gate_id": ECONOMICS_GATE_ID,
        "environment_id": world.environment_id,
        "environment_mode": world.environment_mode.value,
        "merchant": checkout.to_dict() if checkout is not None else None,
        "contribution": (
            world.runtime.contribution(CONTRIBUTION_ID).to_record_dict()
            if world.runtime.store.get(CONTRIBUTION_ID) is not None
            else None
        ),
        "extensions": _extension_section(world),
        "agents": _agents_section(world),
        "stage_journal": [
            {
                "stage": entry["stage"],
                "domain": entry["domain"],
                "command_id": entry["command_id"],
                "requested_at": entry["requested_at"],
                "outcome": entry["outcome"],
            }
            for entry in _gate_stage_journal(world)
        ],
        "route_metrics": {
            family: dict(metrics)
            for family, metrics in sorted(world.route_metrics.items())
        },
    }


def normalize_economic_state(
    state: Mapping[str, Any], world: EconomicWorld
) -> dict[str, Any]:
    """Normalize one world's semantic state by the frozen rule registry.

    Only the declared field names are touched, each with exact-value
    validation: a foreign environment id, a foreign environment mode
    or any other unexpected value fails closed instead of normalizing.
    Everything else is copied verbatim — any residual difference
    between the two normalized projections is a semantic divergence.
    """
    if not isinstance(state, Mapping):
        raise CoreValidationError("the economic state must be a mapping")
    if not isinstance(world, EconomicWorld):
        raise CoreValidationError("normalization requires an EconomicWorld")
    if state.get("environment_id") != world.environment_id:
        raise CoreValidationError(
            f"the projected state declares environment {state.get('environment_id')!r} "
            f"which is not this world's environment {world.environment_id!r}; "
            "cross-environment state fails closed"
        )
    return _normalize_value(state, world)


def _normalize_value(value: Any, world: EconomicWorld) -> Any:
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CoreValidationError(
                    "canonical economic state carries non-string keys"
                )
            if key in _EXCLUDED_FIELDS:
                # Environment-bound derived digest: excluded from the
                # byte comparison under its declared, justified rule.
                continue
            if key == "environment_id":
                normalized[key] = _normalize_environment(item)
            elif key == "environment_mode":
                normalized[key] = _normalize_mode(item, world)
            else:
                normalized[key] = _normalize_value(item, world)
        return normalized
    if isinstance(value, list):
        return [_normalize_value(item, world) for item in value]
    if isinstance(value, tuple):
        return [_normalize_value(item, world) for item in value]
    return value


def _normalize_environment(value: Any) -> Any:
    if value is None:
        return None
    if not isinstance(value, str):
        raise CoreValidationError(
            "environment ids must be strings or null in canonical state"
        )
    if value in _DECLARED_ENVIRONMENTS:
        return ENVIRONMENT_TOKEN
    if value.startswith(MEDIATION_ENVIRONMENT_PREFIX):
        # The mediation substrate's environment ids are identical
        # across the two worlds (derived from the shared mediation id):
        # compared verbatim as content — never normalized away.
        return value
    raise CoreValidationError(
        f"environment id {value!r} is neither one of the two declared IG-004 "
        "economics environments nor a mediation-substrate environment; the "
        "normalization layer fails closed on foreign environment identity"
    )


def _normalize_mode(value: Any, world: EconomicWorld) -> Any:
    if value is None:
        return None
    if not isinstance(value, str):
        raise CoreValidationError(
            "environment modes must be strings or null in canonical state"
        )
    if value != world.environment_mode.value:
        raise CoreValidationError(
            f"environment mode {value!r} is not this world's declared mode "
            f"{world.environment_mode.value!r}; the normalization layer fails "
            "closed on foreign mode bindings"
        )
    return MODE_TOKEN


def economic_projection(world: EconomicWorld) -> dict[str, Any]:
    """The normalized canonical semantic projection of one world."""
    return normalize_economic_state(economic_state(world), world)


def economic_projection_digest(projection: Mapping[str, Any]) -> str:
    """The deterministic digest of one normalized semantic projection."""
    return canonical_sha256(projection)


def raw_state_digest(world: EconomicWorld) -> str:
    """The environment-bound digest over one world's raw economic state."""
    return canonical_sha256(economic_state(world))


__all__ = [
    "ClassifiedDifference",
    "ENVIRONMENT_TOKEN",
    "MODE_TOKEN",
    "MEDIATION_ENVIRONMENT_PREFIX",
    "NORMALIZATION_DIGEST",
    "compare_projections",
    "economic_projection",
    "economic_projection_digest",
    "economic_state",
    "normalize_economic_state",
    "raw_state_digest",
]
