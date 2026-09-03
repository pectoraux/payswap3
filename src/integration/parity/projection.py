"""The canonical semantic projection and normalization layer (IG-003).

The projection reads the composed lifecycle state of one world through
the OWNING engines' trusted paths (the same public accessors the IG-002
invariant battery uses — never gate-side caches) and produces the
canonical semantic record set of that execution:

* the declared worlds, compiled plans, execution-plan indexes, plan-hop
  bindings and the stage-journal TUPLES (stage, domain, command_id,
  requested_at, outcome);
* every durable record of the execution, clearing and settlement
  engines plus the execution submission ledger.

The normalization layer then applies the frozen, field-bound rule
registry from ``contracts.NORMALIZATION_RULES``: environment identity,
rail adapter identity and provider-issued native references are
normalized with exact-value validation (a foreign value fails closed
instead of normalizing), and the closed enumerated set of
environment-bound digest fields is excluded from the cross-environment
byte comparison with per-field justification (their binding correctness
is proven per world by the composed invariant battery, and the content
they cover is compared field-by-field).

Every difference that survives normalization at every other path is a
semantic divergence and fails the gate: there is no broad
"ignore fields" strategy anywhere in this module.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256

from .contracts import (
    ENV_BOUND_DIGEST_FIELDS,
    NORMALIZATION_RULES,
    PRODUCTION_ADAPTER_ID,
    PRODUCTION_NATIVE_PREFIX,
    SIMULATION_ADAPTER_ID,
    SIMULATION_NATIVE_PREFIX,
    WorldRole,
)
from .worlds import ParityWorld

#: Neutral tokens the normalization layer substitutes.
ENVIRONMENT_TOKEN = "{ENVIRONMENT}"
RAIL_ADAPTER_TOKEN = "{RAIL_ADAPTER}"
NATIVE_REFERENCE_TOKEN = "rail/"

#: The exact native-reference shape each world's rail issues: an
#: environment prefix plus the idempotency key (provider-issued
#: reference ids are environment-specific; the semantic suffix — which
#: idempotency key's effect the reference belongs to — is preserved).
_NATIVE_REFERENCE_PATTERN = re.compile(
    r"^(?P<prefix>ig003-simulation|ig003-production)/(?P<key>.+)$"
)

#: The two declared environment ids of the compared worlds (fail-closed
#: validation: a foreign environment id never normalizes).
_DECLARED_ENVIRONMENTS = (
    "env/sandbox-ig003-simulation",
    "env/production-ig003-compatible",
)

#: The two declared rail adapter ids of the compared worlds.
_DECLARED_ADAPTERS = (SIMULATION_ADAPTER_ID, PRODUCTION_ADAPTER_ID)

#: The field names carrying the declared normalization rules.
_NORMALIZED_FIELDS = frozenset(
    {"environment_id", "adapter_id", "native_reference"}
) | ENV_BOUND_DIGEST_FIELDS

#: Fields excluded from byte comparison because they are environment
#: bound derived digests (justified per field in NORMALIZATION_RULES).
_EXCLUDED_FIELDS = frozenset(ENV_BOUND_DIGEST_FIELDS)


def _rules_to_dicts() -> list[dict[str, str]]:
    return [
        {
            "rule_id": rule.rule_id,
            "field": rule.field,
            "reason": rule.reason,
            "rule": rule.rule,
            "safety_argument": rule.safety_argument,
        }
        for rule in NORMALIZATION_RULES
    ]


#: The digest of the frozen normalization contract itself: the rule
#: registry plus the exclusion set, sealed canonically. The parity
#: result reports it so a change of the normalization layer is visible.
NORMALIZATION_DIGEST = canonical_sha256(
    {
        "rules": _rules_to_dicts(),
        "excluded_digest_fields": sorted(ENV_BOUND_DIGEST_FIELDS),
    }
)


@dataclass(frozen=True, slots=True)
class ClassifiedDifference:
    """One residual difference between the two normalized projections.

    ``classification`` is always ``SEMANTIC_DIVERGENCE``: differences
    that survive the declared normalization are semantic by
    definition, and the gate fails closed on them.
    """

    path: str
    simulation_value: Any
    production_value: Any
    classification: str = "SEMANTIC_DIVERGENCE"

    def __post_init__(self) -> None:
        if not isinstance(self.path, str) or not self.path:
            raise CoreValidationError("a classified difference requires a path")
        if self.classification != "SEMANTIC_DIVERGENCE":
            raise CoreValidationError(
                "the parity comparison classifies every residual difference "
                "as a semantic divergence; legitimate differences are "
                "normalized by the declared rule registry"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "simulation_value": _json_safe(self.simulation_value),
            "production_value": _json_safe(self.production_value),
            "classification": self.classification,
        }


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    return str(value)


def semantic_state(gate: Any) -> dict[str, Any]:
    """The canonical semantic state of one composed lifecycle execution.

    Read exclusively through the owning engines' public trusted paths
    (the same accessors the IG-002 invariant battery consumes). The
    stage journal is projected to its semantic TUPLE; the environment
    bound composed-state checkpoint digests stay per-world (their
    chaining and honesty are proven per world by the invariant battery
    and the rebuild contract).
    """
    snapshot = gate.snapshot()
    return {
        "schema_version": 1,
        "gate_id": gate.gate_id,
        "environment_id": gate.environment_id,
        "domain_id": gate.domain_id,
        "actor": gate.actor,
        "adapter_ids": sorted(gate.bindings),
        "worlds": [world.to_dict() for world in gate.worlds],
        "plans": [plan.to_dict() for plan in gate.plans],
        "execution_plans": list(gate.execution_plans),
        "plan_hops": {
            plan_id: [dict(record) for record in records]
            for plan_id, records in snapshot["plan_hops"].items()
        },
        "stage_journal": [
            {
                "stage": entry["stage"],
                "domain": entry["domain"],
                "command_id": entry["command_id"],
                "requested_at": entry["requested_at"],
                "outcome": entry["outcome"],
            }
            for entry in gate.stage_journal
        ],
        "execution_records": {
            record.object_id: record.to_dict() for record in gate.execution.objects()
        },
        "clearing_records": {
            record.object_id: record.to_dict() for record in gate.clearing.records()
        },
        "settlement_records": {
            record.object_id: record.to_dict() for record in gate.settlement.records()
        },
        "submission_ledger": gate.execution.submission_ledger().to_dict(),
    }


def normalize_semantic_state(state: Mapping[str, Any], world: ParityWorld) -> dict[str, Any]:
    """Normalize one world's semantic state by the frozen rule registry.

    Only the declared field names are touched, each with exact-value
    validation: a foreign environment id, adapter id or native
    reference shape fails closed instead of normalizing. Everything
    else is copied verbatim — any residual difference between the two
    normalized projections is a semantic divergence.
    """
    if not isinstance(state, Mapping):
        raise CoreValidationError("the semantic state must be a mapping")
    if state.get("environment_id") != world.environment_id:
        raise CoreValidationError(
            f"the projected state declares environment {state.get('environment_id')!r} "
            f"which is not this world's environment {world.environment_id!r}; "
            "cross-environment state fails closed"
        )
    return _normalize_value(state, world)


def _normalize_value(value: Any, world: ParityWorld) -> Any:
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CoreValidationError(
                    "canonical semantic state carries non-string keys"
                )
            if key in _EXCLUDED_FIELDS:
                # Environment-bound derived digest: excluded from the
                # byte comparison under its declared, justified rule.
                continue
            if key == "environment_id":
                normalized[key] = _normalize_environment(item)
            elif key == "adapter_id":
                normalized[key] = _normalize_adapter(item)
            elif key == "adapter_ids":
                # The plural binding list: every entry is a declared
                # rail adapter id (exact-value validation, same rule).
                if not isinstance(item, (list, tuple)):
                    raise CoreValidationError(
                        "adapter id lists must be sequences in canonical state"
                    )
                normalized[key] = [_normalize_adapter(entry) for entry in item]
            elif key == "native_reference":
                normalized[key] = _normalize_native_reference(item)
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
    if not isinstance(value, str) or value not in _DECLARED_ENVIRONMENTS:
        raise CoreValidationError(
            f"environment id {value!r} is not one of the two declared parity "
            "environments; the normalization layer fails closed on foreign "
            "environment identity"
        )
    return ENVIRONMENT_TOKEN


def _normalize_adapter(value: Any) -> Any:
    if value is None:
        return None
    if not isinstance(value, str) or value not in _DECLARED_ADAPTERS:
        raise CoreValidationError(
            f"adapter id {value!r} is not one of the two declared parity rail "
            "adapters; the normalization layer fails closed on foreign "
            "adapter identity"
        )
    return RAIL_ADAPTER_TOKEN


def _normalize_native_reference(value: Any) -> Any:
    if value is None:
        return None
    if not isinstance(value, str):
        raise CoreValidationError(
            "native references must be strings or null in canonical state"
        )
    match = _NATIVE_REFERENCE_PATTERN.match(value)
    if match is None:
        raise CoreValidationError(
            f"native reference {value!r} does not carry the declared "
            "environment prefix shape ig003-(simulation|production)/<key>; "
            "the normalization layer fails closed on foreign provider "
            "references"
        )
    return f"{NATIVE_REFERENCE_TOKEN}{match.group('key')}"


def semantic_projection(gate: Any, world: ParityWorld) -> dict[str, Any]:
    """The normalized canonical semantic projection of one world."""
    return normalize_semantic_state(semantic_state(gate), world)


def semantic_projection_digest(projection: Mapping[str, Any]) -> str:
    """The deterministic digest of one normalized semantic projection."""
    return canonical_sha256(projection)


def raw_state_digest(gate: Any) -> str:
    """The environment-bound digest over one world's raw snapshot."""
    return canonical_sha256(gate.snapshot())


def compare_projections(
    simulation: Mapping[str, Any],
    production: Mapping[str, Any],
) -> tuple[ClassifiedDifference, ...]:
    """Diff the two NORMALIZED projections; every difference is semantic.

    The deep difference walk mirrors the canonical JSON structure: both
    projections come from the same canonical shapes, so any divergence
    is classified and reported with its exact path.
    """
    paths: list[str] = []
    _diff(simulation, production, "", paths)
    return tuple(
        ClassifiedDifference(
            path=path,
            simulation_value=_path_get(simulation, path),
            production_value=_path_get(production, path),
        )
        for path in paths
    )


def _diff(left: Any, right: Any, path: str, paths: list[str]) -> None:
    if type(left) is not type(right):
        if not (
            isinstance(left, Mapping)
            and isinstance(right, Mapping)
            and all(isinstance(k, str) for k in left)
            and all(isinstance(k, str) for k in right)
        ):
            paths.append(path or "<root>")
            return
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        for key in sorted(set(left) | set(right)):
            if key not in left or key not in right:
                paths.append(f"{path}.{key}" if path else key)
                continue
            _diff(left[key], right[key], f"{path}.{key}" if path else key, paths)
        return
    if isinstance(left, list) and isinstance(right, list):
        if len(left) != len(right):
            paths.append(f"{path}[length]")
            return
        for index, (item_left, item_right) in enumerate(zip(left, right)):
            _diff(item_left, item_right, f"{path}[{index}]", paths)
        return
    if left != right:
        paths.append(path or "<root>")


def _path_get(value: Any, path: str) -> Any:
    if not path or path == "<root>":
        return value
    current: Any = value
    for segment in _split_path(path):
        if isinstance(current, Mapping):
            current = current.get(segment)
        elif isinstance(current, list):
            try:
                current = current[int(segment)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return current


def _split_path(path: str) -> list[str]:
    segments: list[str] = []
    current = ""
    index = 0
    while index < len(path):
        char = path[index]
        if char == ".":
            if current:
                segments.append(current)
                current = ""
            index += 1
        elif char == "[":
            if current:
                segments.append(current)
                current = ""
            closing = path.index("]", index)
            segments.append(path[index + 1 : closing])
            index = closing + 1
        else:
            current += char
            index += 1
    if current:
        segments.append(current)
    return segments


def projection_of(gate: Any, role: WorldRole | str) -> dict[str, Any]:
    """Dispatch helper: project the gate of one declared world role."""
    role_name = role.value if isinstance(role, WorldRole) else str(role)
    if role_name == "simulation":
        return semantic_projection(gate, _world_of(gate, role_name))
    raise CoreValidationError(f"unknown projection role {role!r}")


def _world_of(gate: Any, role_name: str) -> ParityWorld:
    world = getattr(gate, f"{role_name}_world", None)
    if world is None:
        raise CoreValidationError(
            f"the gate carries no {role_name!r} world to project"
        )
    return world


def declared_world_observations_digest(world: ParityWorld) -> str:
    """The digest over the world's consumed rail observations.

    The world observations are environment-local evidence: their
    epistemic class is the environment's declared class (SIMULATED in
    the simulation world, OBSERVED in the production-compatible
    world), so the digests are reported per world and never compared
    across environments.
    """
    return world.rail.consumed_observation_digest()


__all__ = [
    "ClassifiedDifference",
    "ENVIRONMENT_TOKEN",
    "NATIVE_REFERENCE_TOKEN",
    "NORMALIZATION_DIGEST",
    "RAIL_ADAPTER_TOKEN",
    "compare_projections",
    "declared_world_observations_digest",
    "normalize_semantic_state",
    "raw_state_digest",
    "semantic_projection",
    "semantic_projection_digest",
    "semantic_state",
]
