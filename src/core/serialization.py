from __future__ import annotations

import hashlib
import json
import math
from typing import TYPE_CHECKING, Any, Mapping

from .errors import CoreValidationError

if TYPE_CHECKING:  # pragma: no cover - import cycle avoidance for annotations only
    from .envelope import ObjectEnvelope
    from .relationships import Relationship


def _reject_float(name: str, value: float) -> None:
    if math.isnan(value) or math.isinf(value):
        raise CoreValidationError(f"{name} contains a non-finite numeric value")
    raise CoreValidationError(
        f"{name} contains a floating-point value outside the canonical protocol value domain"
    )


def validate_canonical_value(name: str, value: Any) -> None:
    """Validate that value belongs to the explicit protocol-safe JSON domain.

    The domain is exactly: null, booleans, strings, integers, arrays and
    objects with string keys. Floating-point values (including non-finite
    values) and every other Python type are rejected so canonical encodings
    stay deterministic and byte-stable.
    """
    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        _reject_float(name, value)
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            validate_canonical_value(f"{name}[{index}]", item)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CoreValidationError(f"{name} contains a non-string object key")
            validate_canonical_value(f"{name}.{key}", item)
        return
    raise CoreValidationError(
        f"{name} contains a value of unsupported type {type(value).__name__}"
    )


def check_immutable_value(name: str, value: Any) -> None:
    """Validate that value is already in the deeply immutable storage form.

    Immutable form: None, booleans, strings, integers and tuples of such
    values. Lists, mappings, floats and every other type are rejected.
    """
    if value is None or isinstance(value, (bool, str, int)):
        return
    if isinstance(value, float):
        _reject_float(name, value)
    if isinstance(value, tuple):
        for index, item in enumerate(value):
            check_immutable_value(f"{name}[{index}]", item)
        return
    raise CoreValidationError(
        f"{name} contains a value of unsupported type {type(value).__name__} for immutable storage"
    )


def normalize_immutable_value(name: str, value: Any) -> Any:
    """Normalize a value into the deeply immutable storage form.

    Arrays are converted to tuples recursively; scalars pass through;
    mappings, floating-point values and every other type are rejected.
    """
    if value is None or isinstance(value, (bool, str, int)):
        return value
    if isinstance(value, float):
        _reject_float(name, value)
    if isinstance(value, (list, tuple)):
        return tuple(
            normalize_immutable_value(f"{name}[{index}]", item)
            for index, item in enumerate(value)
        )
    raise CoreValidationError(
        f"{name} contains a value of unsupported type {type(value).__name__} for immutable storage"
    )


def canonical_json(value: Any) -> str:
    """Canonical UTF-8-compatible JSON representation used by protocol hashes."""
    validate_canonical_value("canonical value", value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CoreValidationError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def loads_canonical(value: str) -> Any:
    """Decode canonical JSON while rejecting duplicate object keys.

    Duplicate keys would otherwise collapse silently during decoding and
    lose protocol data, so the decoder fails closed instead.
    """
    try:
        return json.loads(value, object_pairs_hook=_reject_duplicate_keys)
    except CoreValidationError:
        raise
    except ValueError as exc:
        raise CoreValidationError(f"invalid canonical JSON: {exc}") from exc


def envelope_to_json(envelope: "ObjectEnvelope") -> str:
    return canonical_json(envelope.to_dict())


def envelope_from_json(value: str) -> "ObjectEnvelope":
    from .envelope import ObjectEnvelope

    decoded = _decode_object(value)
    return ObjectEnvelope.from_dict(decoded)


def relationship_to_json(relationship: "Relationship") -> str:
    return canonical_json(relationship.to_dict())


def relationship_from_json(value: str) -> "Relationship":
    from .relationships import Relationship

    decoded = _decode_object(value)
    return Relationship.from_dict(decoded)


def _decode_object(value: str) -> Mapping[str, Any]:
    decoded = loads_canonical(value)
    if not isinstance(decoded, dict):
        raise CoreValidationError("canonical protocol object must decode to a JSON object")
    return decoded
