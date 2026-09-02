"""Strict fail-closed validation helpers for the reservation domain.

Every failure raises :class:`~src.core.errors.CoreValidationError` — the
single error authority owned by ``src.core`` — with a descriptive message.
No second error authority is introduced.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from typing import Any, Iterable, Mapping

from src.core.errors import CoreValidationError

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9/._:+-]*$")
_MAX_IDENTIFIER_LENGTH = 200
_MAX_TEXT_LENGTH = 2000


def require_text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CoreValidationError(f"{name} must be a non-empty string")
    return value


def require_identifier(name: str, value: str) -> str:
    """Require a canonical domain identifier (compact opaque token)."""
    require_text(name, value)
    if len(value) > _MAX_IDENTIFIER_LENGTH:
        raise CoreValidationError(f"{name} must not exceed {_MAX_IDENTIFIER_LENGTH} characters")
    if _IDENTIFIER_RE.match(value) is None:
        raise CoreValidationError(
            f"{name} must be a domain identifier matching {_IDENTIFIER_RE.pattern}"
        )
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

    Timestamps are declared data, never clock reads: the reservation domain
    is deterministic. The canonical ``Z`` form is required (fail closed on
    other offsets) so ordering, expiry and window arithmetic are total,
    unambiguous and byte-stable.
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


def require_utc_timestamp_before(name_a: str, value_a: str, name_b: str, value_b: str) -> None:
    """Require ``value_a < value_b`` as canonical UTC instants."""
    if parse_utc_timestamp(name_a, value_a) >= parse_utc_timestamp(name_b, value_b):
        raise CoreValidationError(f"{name_a} must be strictly earlier than {name_b}")


def require_utc_timestamp_at_or_after(
    name_a: str, value_a: str, name_b: str, value_b: str
) -> None:
    """Require ``value_a >= value_b`` as canonical UTC instants."""
    if parse_utc_timestamp(name_a, value_a) < parse_utc_timestamp(name_b, value_b):
        raise CoreValidationError(f"{name_a} must not be earlier than {name_b}")


def parse_enum(name: str, enum_type: type[StrEnum], value: Any) -> StrEnum:
    """Parse a closed-vocabulary enum member, failing closed on unknowns."""
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


def require_unique_identifiers(
    name: str, values: Iterable[str]
) -> tuple[str, ...]:
    """Validate an ordered iterable of unique domain identifiers."""
    collected = tuple(values)
    seen: set[str] = set()
    for value in collected:
        require_identifier(f"{name} entry", value)
        if value in seen:
            raise CoreValidationError(f"{name} contains duplicate identifier {value!r}")
        seen.add(value)
    return collected
