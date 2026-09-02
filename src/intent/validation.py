"""Strict fail-closed validation helpers for the intent domain.

Every failure raises :class:`~src.core.errors.CoreValidationError` — the
single error authority owned by ``src.core`` — with a descriptive message.
No second error authority is introduced.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Mapping

from src.core.errors import CoreValidationError

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9/._:+-]*$")
_MAX_IDENTIFIER_LENGTH = 200


def require_text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CoreValidationError(f"{name} must be a non-empty string")
    return value


def require_identifier(name: str, value: str) -> str:
    """Require a canonical domain identifier.

    Domain identifiers (object ids and cross-domain references such as
    endpoints, funding sources, policies and slack objects) use compact
    opaque tokens without whitespace so derived identifiers stay
    deterministic and canonical.
    """
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


def parse_timestamp(name: str, value: str) -> datetime:
    """Parse an ISO-8601 timestamp that carries an explicit UTC offset.

    Timestamps are declared data, never wall-clock reads: the intent domain
    is deterministic and never consults a clock. An explicit offset is
    required so comparisons are total and deterministic.
    """
    require_text(name, value)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CoreValidationError(f"{name} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise CoreValidationError(f"{name} must carry an explicit UTC offset")
    return parsed


def require_timestamp(name: str, value: str) -> str:
    parse_timestamp(name, value)
    return value


def require_timestamp_order(name_a: str, value_a: str, name_b: str, value_b: str) -> None:
    if parse_timestamp(name_a, value_a) > parse_timestamp(name_b, value_b):
        raise CoreValidationError(f"{name_b} must not be earlier than {name_a}")


def require_str_tuple(name: str, value: Any, *, identifier: bool = False) -> tuple[str, ...]:
    """Normalize a sequence of strings into an immutable tuple of strings."""
    if not isinstance(value, (list, tuple)):
        raise CoreValidationError(f"{name} must be a sequence of strings")
    items = tuple(value)
    for item in items:
        if identifier:
            require_identifier(f"{name} entry", item)
        else:
            require_text(f"{name} entry", item)
    if len(set(items)) != len(items):
        raise CoreValidationError(f"{name} must not contain duplicate entries")
    return items


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
