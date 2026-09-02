"""Strict fail-closed validation helpers for the liquidity domain.

Every failure raises :class:`~src.core.errors.CoreValidationError` — the
single error authority owned by ``src.core`` — with a descriptive message.
No second error authority is introduced.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from typing import Any, Mapping

from src.core.errors import CoreValidationError

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9/._:+-]*$")
_MAX_IDENTIFIER_LENGTH = 200


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


def require_optional_identifier(name: str, value: str | None) -> str | None:
    if value is None:
        return None
    return require_identifier(name, value)


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


def require_identifier_tuple(
    name: str, value: Any
) -> tuple[str, ...]:
    """Require a duplicate-free tuple of canonical opaque identifiers."""
    if not isinstance(value, tuple):
        raise CoreValidationError(f"{name} must be a tuple")
    items: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise CoreValidationError(f"{name} entries must be strings")
        items.append(require_identifier(f"{name} entry", item))
    if len(set(items)) != len(items):
        raise CoreValidationError(f"{name} must not repeat a reference")
    return tuple(items)


def parse_utc_timestamp(name: str, value: str) -> datetime:
    """Parse a canonical UTC timestamp ending in ``Z``.

    Timestamps are declared data, never clock reads: the liquidity domain
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


def require_utc_window(name_prefix: str, window_start: str, window_end: str) -> None:
    """Require a non-empty half-open UTC window ``[start, end)``.

    An empty window (``start == end``) can never admit any instant and is
    rejected rather than silently accepted as a never-available record.
    """
    start = parse_utc_timestamp(f"{name_prefix}.from", window_start)
    end = parse_utc_timestamp(f"{name_prefix}.until", window_end)
    if start >= end:
        raise CoreValidationError(
            f"{name_prefix}.from must be strictly before {name_prefix}.until; "
            f"got [{window_start}, {window_end})"
        )


def utc_timestamp_within(window_start: str, moment: str, window_end: str) -> bool:
    """Half-open membership test: ``[window_start, window_end)``."""
    return (
        parse_utc_timestamp("window start", window_start)
        <= parse_utc_timestamp("moment", moment)
        < parse_utc_timestamp("window end", window_end)
    )


def parse_enum(name: str, enum_type: type[StrEnum], value: Any) -> StrEnum:
    """Parse a closed-vocabulary enum member, failing closed on unknowns."""
    try:
        return enum_type(value)
    except ValueError as exc:
        raise CoreValidationError(
            f"unknown {name}: {value!r}; expected one of "
            f"{sorted(member.value for member in enum_type)}"
        ) from exc


def strict_fields(
    name: str, value: Any, required: set[str] | frozenset[str]
) -> Mapping[str, Any]:
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
