from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from src.core.errors import CoreValidationError
from src.core.serialization import validate_canonical_value


@dataclass(frozen=True, slots=True)
class PayloadObject:
    """Immutable canonical JSON object used inside command payloads.

    Mappings are stored as sorted unique ``(key, value)`` pairs so payloads
    are deeply immutable while remaining byte-stable under canonical JSON
    encoding. The pair form is deliberately distinct from tuple arrays, so
    round-trips between JSON objects and JSON arrays stay unambiguous.
    """

    pairs: tuple[tuple[str, Any], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.pairs, tuple):
            raise CoreValidationError("payload object pairs must be a tuple")
        keys: list[str] = []
        for pair in self.pairs:
            if not isinstance(pair, tuple) or len(pair) != 2:
                raise CoreValidationError("payload object pairs must be (key, value) tuples")
            key, value = pair
            if not isinstance(key, str):
                raise CoreValidationError("payload object keys must be strings")
            check_payload_value(f"payload object {key}", value)
            keys.append(key)
        if len(set(keys)) != len(keys):
            raise CoreValidationError("payload object contains duplicate keys")
        if keys != sorted(keys):
            raise CoreValidationError("payload object pairs must be sorted for canonical storage")

    def to_json_value(self) -> dict[str, Any]:
        return {key: payload_to_json_value(value) for key, value in self.pairs}


def check_payload_value(name: str, value: Any) -> None:
    """Validate that value is already in the deeply immutable payload form.

    Immutable form: None, booleans, strings, integers, tuples of immutable
    values and PayloadObject. Lists, mappings, floats and every other type
    are rejected (mirroring the core deep-immutability discipline).
    """
    if value is None or isinstance(value, (bool, str, int)):
        return
    if isinstance(value, float):
        raise CoreValidationError(
            f"{name} contains a floating-point value outside the canonical protocol value domain"
        )
    if isinstance(value, PayloadObject):
        return
    if isinstance(value, tuple):
        for index, item in enumerate(value):
            check_payload_value(f"{name}[{index}]", item)
        return
    raise CoreValidationError(
        f"{name} contains a value of unsupported type {type(value).__name__} "
        "for immutable payload storage"
    )


def normalize_payload(name: str, value: Any) -> Any:
    """Normalize a canonical JSON value into the deeply immutable payload form.

    The value domain is validated by the canonical core authority
    (``src.core.serialization.validate_canonical_value``): lists and tuples
    become tuples, mappings become sorted ``PayloadObject`` pairs, scalars
    pass through, floats and unsafe types fail closed.
    """
    validate_canonical_value(name, value)
    return _to_immutable(name, value)


def _to_immutable(name: str, value: Any) -> Any:
    if isinstance(value, Mapping):
        return PayloadObject(
            pairs=tuple(
                sorted(
                    (key, _to_immutable(f"{name}.{key}", item))
                    for key, item in value.items()
                )
            )
        )
    if isinstance(value, (list, tuple)):
        return tuple(_to_immutable(f"{name}[{index}]", item) for index, item in enumerate(value))
    return value


def payload_to_json_value(value: Any) -> Any:
    """Convert an immutable payload tree back into the canonical JSON value form."""
    check_payload_value("payload", value)
    return _to_json_value(value)


def _to_json_value(value: Any) -> Any:
    if isinstance(value, PayloadObject):
        return value.to_json_value()
    if isinstance(value, tuple):
        return [_to_json_value(item) for item in value]
    return value
