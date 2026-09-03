"""Strict fail-closed validation helpers for the agents domain.

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


def require_int(
    name: str,
    value: Any,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise CoreValidationError(f"{name} must be an integer")
    if minimum is not None and value < minimum:
        raise CoreValidationError(f"{name} must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise CoreValidationError(f"{name} must be <= {maximum}")
    return value


def require_digest(name: str, value: str) -> str:
    require_text(name, value)
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise CoreValidationError(f"{name} must be a canonical SHA-256 hex digest")
    return value


def parse_utc_timestamp(name: str, value: str) -> datetime:
    """Parse a canonical UTC timestamp ending in ``Z``.

    Timestamps are declared data, never clock reads: the agents domain is
    deterministic and every instant is supplied explicitly. The canonical
    ``Z`` form is required (fail closed on other offsets) so ordering and
    window arithmetic are total, unambiguous and byte-stable.
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
    if parse_utc_timestamp(name_a, value_a) >= parse_utc_timestamp(name_b, value_b):
        raise CoreValidationError(f"{name_b} must be strictly later than {name_a}")


def utc_timestamp_within(value: str, valid_from: str, valid_until: str) -> bool:
    """Half-open UTC window membership ``[valid_from, valid_until)``."""
    instant = parse_utc_timestamp("instant", value)
    return parse_utc_timestamp("valid_from", valid_from) <= instant < parse_utc_timestamp(
        "valid_until", valid_until
    )


def parse_enum(name: str, value: Any, enum_type: type[StrEnum]) -> StrEnum:
    if isinstance(value, enum_type):
        return value
    if isinstance(value, str):
        try:
            return enum_type(value)
        except ValueError as exc:
            raise CoreValidationError(
                f"{name} must be one of the closed vocabulary "
                f"{sorted(member.value for member in enum_type)}"
            ) from exc
    raise CoreValidationError(
        f"{name} must be a {enum_type.__name__} (or its canonical string value)"
    )


def strict_fields(name: str, value: Mapping[str, Any], fields: frozenset[str]) -> None:
    """Fail closed unless the mapping carries exactly the canonical field set."""
    if not isinstance(value, Mapping):
        raise CoreValidationError(f"{name} must be an object")
    present = set(value)
    expected = set(fields)
    if present != expected:
        missing = sorted(expected - present)
        extra = sorted(present - expected)
        raise CoreValidationError(
            f"{name} fields are not canonical; missing={missing}, extra={extra}"
        )


def require_str_tuple(
    name: str,
    value: Any,
    *,
    distinct: bool = False,
    non_empty: bool = False,
) -> tuple[str, ...]:
    """Normalize a string sequence into a tuple with fail-closed checks."""
    if not isinstance(value, (list, tuple)):
        raise CoreValidationError(f"{name} must be a sequence of strings")
    items = tuple(value)
    if non_empty and not items:
        raise CoreValidationError(f"{name} must not be empty")
    for item in items:
        require_text(f"{name} entry", item)
    if distinct and len(set(items)) != len(items):
        raise CoreValidationError(f"{name} must contain distinct values")
    return items


def require_bool(name: str, value: Any) -> bool:
    if not isinstance(value, bool):
        raise CoreValidationError(f"{name} must be a boolean")
    return value


def sorted_by_key(items: Iterable[Any], key: Any) -> tuple[Any, ...]:
    """Deterministic ordering helper (stable, key-driven)."""
    return tuple(sorted(items, key=key))
