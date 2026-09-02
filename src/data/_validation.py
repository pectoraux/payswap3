"""Strict fail-closed validation helpers for the data domain.

Every failure raises :class:`~src.core.errors.CoreValidationError` — the
single error authority owned by ``src.core`` — with a descriptive
message. No second error authority is introduced.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any, Mapping

from src.core.errors import CoreValidationError
from src.core.serialization import validate_canonical_value

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9/._:+-]*$")
_MAX_IDENTIFIER_LENGTH = 200


def require_text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CoreValidationError(f"{name} must be a non-empty string")
    return value


def require_identifier(name: str, value: str, prefix: str | None = None) -> str:
    """Require a canonical domain identifier (compact opaque token)."""
    require_text(name, value)
    if len(value) > _MAX_IDENTIFIER_LENGTH:
        raise CoreValidationError(f"{name} must not exceed {_MAX_IDENTIFIER_LENGTH} characters")
    if _IDENTIFIER_RE.match(value) is None:
        raise CoreValidationError(
            f"{name} must be a domain identifier matching {_IDENTIFIER_RE.pattern}"
        )
    if prefix is not None and not value.startswith(prefix):
        raise CoreValidationError(f"{name} must start with {prefix!r}")
    return value


def require_int(name: str, value: Any, *, minimum: int | None = None,
                maximum: int | None = None) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise CoreValidationError(f"{name} must be an integer")
    if minimum is not None and value < minimum:
        raise CoreValidationError(f"{name} must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise CoreValidationError(f"{name} must be <= {maximum}")
    return value


def require_bool(name: str, value: Any) -> bool:
    if not isinstance(value, bool):
        raise CoreValidationError(f"{name} must be a boolean")
    return value


def parse_utc_timestamp(name: str, value: str) -> datetime:
    """Parse a canonical UTC timestamp ending in ``Z``.

    Timestamps are declared data, never clock reads: the data domain is
    deterministic and every temporal decision is computed only from
    explicit ``as_of`` instants and declared windows. The canonical ``Z``
    form is required (fail closed on other offsets) so ordering,
    retention arithmetic and window membership are total, unambiguous
    and byte-stable.
    """
    require_text(name, value)
    if not value.endswith("Z"):
        raise CoreValidationError(f"{name} must be an explicit UTC timestamp ending in 'Z'")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CoreValidationError(f"{name} must be an ISO-8601 UTC timestamp") from exc


def require_utc_timestamp(name: str, value: str) -> str:
    parse_utc_timestamp(name, value)
    return value


def require_utc_timestamp_order(name_a: str, value_a: str, name_b: str, value_b: str) -> None:
    if parse_utc_timestamp(name_a, value_a) > parse_utc_timestamp(name_b, value_b):
        raise CoreValidationError(f"{name_b} must not be earlier than {name_a}")


def require_utc_timestamp_strictly_after(
    name_a: str, value_a: str, name_b: str, value_b: str
) -> None:
    """Require ``value_b`` strictly later than ``value_a`` (non-empty window)."""
    if parse_utc_timestamp(name_a, value_a) >= parse_utc_timestamp(name_b, value_b):
        raise CoreValidationError(f"{name_b} must be strictly after {name_a}")


def offset_utc_timestamp(name: str, value: str, seconds: int) -> str:
    """Displace a canonical UTC timestamp by a whole number of seconds."""
    require_int(f"{name} offset seconds", seconds)
    moment = parse_utc_timestamp(name, value)
    return (moment + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def utc_timestamp_within(window_start: str, moment: str, window_end: str) -> bool:
    """Half-open membership test: ``[window_start, window_end)``."""
    return (
        parse_utc_timestamp("window start", window_start)
        <= parse_utc_timestamp("moment", moment)
        < parse_utc_timestamp("window end", window_end)
    )


def parse_enum(name: str, enum_type: type[StrEnum], value: Any) -> StrEnum:
    """Parse a closed-vocabulary enum member, failing closed on unknowns."""
    if isinstance(value, enum_type):
        return value
    try:
        return enum_type(value)
    except ValueError as exc:
        raise CoreValidationError(
            f"unknown {name}: {value!r}; expected one of "
            f"{sorted(member.value for member in enum_type)}"
        ) from exc


def strict_fields(name: str, value: Any, required: set[str] | frozenset[str]) -> Mapping[str, Any]:
    """Fail closed on non-canonical field sets with precise diagnostics."""
    if not isinstance(value, Mapping):
        raise CoreValidationError(f"{name} must be an object")
    if set(value) != set(required):
        missing = sorted(set(required) - set(value))
        extra = sorted(set(value) - set(required))
        raise CoreValidationError(
            f"{name} fields are not canonical; missing={missing}, extra={extra}"
        )
    return value


def require_pairs(
    name: str, value: Any, *, key_name: str, allow_empty: bool = False
) -> tuple[tuple[str, Any], ...]:
    """Normalize a JSON object into sorted unique ``(key, value)`` pairs."""
    if not isinstance(value, Mapping):
        raise CoreValidationError(f"{name} must be an object")
    keys = list(value)
    if not allow_empty and not keys:
        raise CoreValidationError(f"{name} must not be empty")
    if len(set(keys)) != len(keys):
        raise CoreValidationError(f"{name} contains duplicate keys")
    for key in keys:
        require_text(f"{name} key", key)
        validate_canonical_value(f"{name}.{key}", value[key])
    return tuple((key, value[key]) for key in sorted(keys))


def pairs_to_dict(pairs: tuple[tuple[str, Any], ...]) -> dict[str, Any]:
    return {key: value for key, value in pairs}


def require_pair_items(name: str, value: Any) -> list[list[Any]]:
    """Fail closed on malformed serialized pair lists.

    Deserialized composites carry ``[[key, value], ...]`` lists; every
    entry must be a two-element list whose first element is a string so
    malformed input raises the single error authority instead of an
    incidental ``IndexError``/``TypeError``.
    """
    if not isinstance(value, list):
        raise CoreValidationError(f"{name} must deserialize from a list")
    items: list[list[Any]] = []
    for entry in value:
        if not isinstance(entry, list) or len(entry) != 2 or not isinstance(entry[0], str):
            raise CoreValidationError(
                f"{name} entries must be two-element [key, value] lists"
            )
        items.append(entry)
    return items
