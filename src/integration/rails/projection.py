"""The canonical rail-neutral semantic projection (IG-005).

The projection reads the composed lifecycle state of one rail world
through the OWNING engines' trusted paths (the same public accessors
the IG-002 invariant battery uses — never gate-side caches) and
produces the canonical semantic record set of that execution. The
normalization layer then applies the frozen, field-bound rule
registry from ``contracts.RAILS_NORMALIZATION_RULES``:

* every identity field (environment, domain, adapter) is validated
  against the OWNING world's declared identity — a foreign value
  fails closed (cross-world leakage is a divergence, never a
  normalization) — and replaced with a neutral token;
* provider-issued native references are validated against the owning
  world's declared reference pattern (a substituted or foreign
  reference fails closed) and replaced with a neutral token;
* the declared per-rail asset/currency is validated exactly (an
  asset substitution fails closed) and tokenized, while the amount
  value and scale are never touched;
* the closed enumerated set of world-bound digest fields is excluded
  from the cross-rail byte comparison with per-field justification
  (their binding correctness is proven per world by the composed
  invariant battery, and the content they cover is compared
  field-by-field).

Every difference that survives normalization at every other path is a
semantic divergence and fails the gate: there is no broad "ignore
fields" strategy anywhere in this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256

from .contracts import (
    RAILS_ENV_BOUND_DIGEST_FIELDS,
    RAILS_NORMALIZATION_RULES,
)
from .worlds import RailWorld

#: Neutral tokens the normalization layer substitutes.
ENVIRONMENT_TOKEN = "{ENVIRONMENT}"
DOMAIN_TOKEN = "{DOMAIN}"
RAIL_ADAPTER_TOKEN = "{RAIL_ADAPTER}"
NATIVE_REFERENCE_TOKEN = "{NATIVE_REFERENCE}"
NATIVE_STATUS_TOKEN = "{NATIVE_STATUS}"
DECLARED_ASSET_TOKEN = "{DECLARED_ASSET}"

#: The field names carrying the declared normalization rules.
_NORMALIZED_FIELDS = frozenset(
    {
        "environment_id",
        "domain_id",
        "adapter_id",
        "adapter_ids",
        "native_reference",
        "asset",
        "currency",
    }
) | RAILS_ENV_BOUND_DIGEST_FIELDS

#: Fields excluded from byte comparison because they are world-bound
#: derived digests (justified per field in RAILS_NORMALIZATION_RULES).
_EXCLUDED_FIELDS = frozenset(RAILS_ENV_BOUND_DIGEST_FIELDS)


def _rules_to_dicts() -> list[dict[str, str]]:
    return [
        {
            "rule_id": rule.rule_id,
            "field": rule.field,
            "rail_a_representation": rule.rail_a_representation,
            "rail_b_representation": rule.rail_b_representation,
            "reason": rule.reason,
            "rule": rule.rule,
            "safety_argument": rule.safety_argument,
        }
        for rule in RAILS_NORMALIZATION_RULES
    ]


#: The digest of the frozen normalization contract itself: the rule
#: registry plus the exclusion set, sealed canonically. The comparison
#: verdict reports it so a change of the normalization layer is
#: visible.
RAILS_NORMALIZATION_DIGEST = canonical_sha256(
    {
        "rules": _rules_to_dicts(),
        "excluded_digest_fields": sorted(RAILS_ENV_BOUND_DIGEST_FIELDS),
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
    rail_a_value: Any
    rail_b_value: Any
    classification: str = "SEMANTIC_DIVERGENCE"

    def __post_init__(self) -> None:
        if not isinstance(self.path, str) or not self.path:
            raise CoreValidationError("a classified difference requires a path")
        if self.classification != "SEMANTIC_DIVERGENCE":
            raise CoreValidationError(
                "the rail comparison classifies every residual difference "
                "as a semantic divergence; legitimate differences are "
                "normalized by the declared rule registry"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "rail_a_value": _json_safe(self.rail_a_value),
            "rail_b_value": _json_safe(self.rail_b_value),
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
    stage journal is projected to its semantic TUPLE; the world-bound
    composed-state checkpoint digests stay per-world (their chaining
    and honesty are proven per world by the invariant battery and the
    rebuild contract).
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


def normalize_semantic_state(
    state: Mapping[str, Any], world: RailWorld
) -> dict[str, Any]:
    """Normalize one world's semantic state by the frozen rule registry.

    Only the declared field names are touched, each with exact-value
    validation against the OWNING world's declared identities: a
    foreign environment, domain, adapter, native reference shape,
    asset or currency fails closed instead of normalizing (even the
    sibling world's value is a fail-closed divergence — cross-world
    leakage is never a normalization). Everything else is copied
    verbatim — any residual difference between the two normalized
    projections is a semantic divergence.
    """
    if not isinstance(state, Mapping):
        raise CoreValidationError("the semantic state must be a mapping")
    if state.get("environment_id") != world.environment_id:
        raise CoreValidationError(
            f"the projected state declares environment "
            f"{state.get('environment_id')!r} which is not this world's "
            f"environment {world.environment_id!r}; cross-world state "
            "fails closed"
        )
    return _normalize_value(state, world)


def _normalize_value(value: Any, world: RailWorld) -> Any:
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CoreValidationError(
                    "canonical semantic state carries non-string keys"
                )
            if key in _EXCLUDED_FIELDS:
                # World-bound derived digest: excluded from the byte
                # comparison under its declared, justified rule.
                continue
            if key == "environment_id":
                normalized[key] = _normalize_environment(item, world)
            elif key == "domain_id":
                normalized[key] = _normalize_domain(item, world)
            elif key == "adapter_id":
                normalized[key] = _normalize_adapter(item, world)
            elif key == "adapter_ids":
                if not isinstance(item, (list, tuple)):
                    raise CoreValidationError(
                        "adapter id lists must be sequences in canonical state"
                    )
                normalized[key] = [
                    _normalize_adapter(entry, world) for entry in item
                ]
            elif key == "native_reference":
                normalized[key] = _normalize_native_reference(item, world)
            elif key == "native_code":
                normalized[key] = _normalize_native_status(item, world)
            elif key == "asset":
                normalized[key] = _normalize_asset(item, world)
            elif key == "currency":
                normalized[key] = _normalize_currency(item, world)
            else:
                normalized[key] = _normalize_value(item, world)
        return normalized
    if isinstance(value, list):
        return [_normalize_value(item, world) for item in value]
    if isinstance(value, tuple):
        return [_normalize_value(item, world) for item in value]
    return value


def _normalize_environment(value: Any, world: RailWorld) -> Any:
    if value is None:
        return None
    if not isinstance(value, str) or value != world.environment_id:
        raise CoreValidationError(
            f"environment id {value!r} is not this world's declared "
            f"environment {world.environment_id!r}; the normalization "
            "layer fails closed on foreign environment identity"
        )
    return ENVIRONMENT_TOKEN


def _normalize_domain(value: Any, world: RailWorld) -> Any:
    if value is None:
        return None
    derived = world.domain_id + "/"
    if not isinstance(value, str) or not (
        value == world.domain_id or value.startswith(derived)
    ):
        raise CoreValidationError(
            f"domain id {value!r} is not this world's declared domain "
            f"{world.domain_id!r} (or one of its derived engine domains); "
            "the normalization layer fails closed on foreign domain "
            "identity"
        )
    return DOMAIN_TOKEN


def _normalize_adapter(value: Any, world: RailWorld) -> Any:
    if value is None:
        return None
    if not isinstance(value, str) or value != world.adapter_id:
        raise CoreValidationError(
            f"adapter id {value!r} is not this world's declared rail "
            f"adapter {world.adapter_id!r}; the normalization layer fails "
            "closed on foreign adapter identity"
        )
    return RAIL_ADAPTER_TOKEN


def _normalize_native_reference(value: Any, world: RailWorld) -> Any:
    if value is None:
        return None
    if not isinstance(value, str):
        raise CoreValidationError(
            "native references must be strings or null in canonical state"
        )
    if world.native_reference_pattern.match(value) is None:
        raise CoreValidationError(
            f"native reference {value!r} does not carry this world's "
            "declared native-reference shape "
            f"({world.native_reference_pattern.pattern}); the "
            "normalization layer fails closed on foreign provider "
            "references"
        )
    return NATIVE_REFERENCE_TOKEN


def _normalize_native_status(value: Any, world: RailWorld) -> Any:
    """The provider's native status word, validated against the map.

    The native word is the provider's wording of the canonical status
    (which is compared strictly as ``canonical_status``); a word
    outside the owning adapter's declared closed vocabulary fails
    closed (the unexpected-provider-status discipline).
    """
    if value is None:
        return None
    if not isinstance(value, str) or value not in (
        world.native_status_vocabulary
    ):
        raise CoreValidationError(
            f"native status word {value!r} is not declared in the owning "
            "world's adapter status map; the normalization layer fails "
            "closed on undeclared provider status words"
        )
    return NATIVE_STATUS_TOKEN


def _normalize_asset(value: Any, world: RailWorld) -> Any:
    declared_full = f"asset/{world.declared_currency}"
    if value is None:
        return None
    if not isinstance(value, str) or value not in (
        declared_full,
        world.declared_currency,
    ):
        raise CoreValidationError(
            f"asset {value!r} is not this world's declared asset "
            f"({declared_full!r} or its currency word "
            f"{world.declared_currency!r}); a substituted asset fails "
            "closed (never a normalization)"
        )
    return DECLARED_ASSET_TOKEN


def _normalize_currency(value: Any, world: RailWorld) -> Any:
    if value is None:
        return None
    if not isinstance(value, str) or value != world.declared_currency:
        raise CoreValidationError(
            f"currency {value!r} is not this world's declared currency "
            f"{world.declared_currency!r}; a substituted currency fails "
            "closed (never a normalization)"
        )
    return DECLARED_ASSET_TOKEN


def semantic_projection(gate: Any, world: RailWorld) -> dict[str, Any]:
    """The normalized canonical semantic projection of one rail world."""
    return normalize_semantic_state(semantic_state(gate), world)


def semantic_projection_digest(projection: Mapping[str, Any]) -> str:
    """The deterministic digest of one normalized semantic projection."""
    return canonical_sha256(projection)


def raw_state_digest(gate: Any) -> str:
    """The world-bound digest over one world's raw snapshot."""
    return canonical_sha256(gate.snapshot())


def compare_projections(
    rail_a: Mapping[str, Any],
    rail_b: Mapping[str, Any],
) -> tuple[ClassifiedDifference, ...]:
    """Diff the two NORMALIZED projections; every difference is semantic.

    The deep difference walk mirrors the canonical JSON structure: both
    projections come from the same canonical shapes, so any divergence
    is classified and reported with its exact path.
    """
    paths: list[str] = []
    _diff(rail_a, rail_b, "", paths)
    return tuple(
        ClassifiedDifference(
            path=path,
            rail_a_value=_path_get(rail_a, path),
            rail_b_value=_path_get(rail_b, path),
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


__all__ = [
    "ClassifiedDifference",
    "DECLARED_ASSET_TOKEN",
    "DOMAIN_TOKEN",
    "ENVIRONMENT_TOKEN",
    "NATIVE_REFERENCE_TOKEN",
    "NATIVE_STATUS_TOKEN",
    "RAILS_NORMALIZATION_DIGEST",
    "RAIL_ADAPTER_TOKEN",
    "compare_projections",
    "normalize_semantic_state",
    "raw_state_digest",
    "semantic_projection",
    "semantic_projection_digest",
    "semantic_state",
]
