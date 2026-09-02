"""Strict fail-closed validation helpers for the compiler domain.

Every failure raises :class:`~src.core.errors.CoreValidationError` — the
single error authority owned by ``src.core`` — with a descriptive message.
No second error authority is introduced (mirrors the sibling convention of
``src/liquidity/_validation.py`` and ``src/safety/_validation.py``).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Mapping

from src.core.errors import CoreValidationError

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9/._:+-]*$")
_MAX_IDENTIFIER_LENGTH = 200


def require_text(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CoreValidationError(f"{name} must be a non-empty string")
    return value


def require_identifier(name: str, value: Any) -> str:
    """Require a canonical domain identifier (compact opaque token)."""
    require_text(name, value)
    if len(value) > _MAX_IDENTIFIER_LENGTH:
        raise CoreValidationError(f"{name} must not exceed {_MAX_IDENTIFIER_LENGTH} characters")
    if _IDENTIFIER_RE.match(value) is None:
        raise CoreValidationError(
            f"{name} must be a domain identifier matching {_IDENTIFIER_RE.pattern}"
        )
    return value


def require_optional_identifier(name: str, value: Any) -> str | None:
    if value is None:
        return None
    return require_identifier(name, value)


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


def require_bool(name: str, value: Any) -> bool:
    if not isinstance(value, bool):
        raise CoreValidationError(f"{name} must be a boolean")
    return value


def require_digest(name: str, value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise CoreValidationError(f"{name} must be a canonical SHA-256 hex digest")
    return value


def parse_utc_timestamp(name: str, value: Any) -> datetime:
    """Parse a canonical UTC timestamp ending in ``Z``.

    Timestamps are declared data, never clock reads: the compiler domain is
    deterministic. The canonical ``Z`` form is required (fail closed on
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


def require_utc_timestamp(name: str, value: Any) -> str:
    parse_utc_timestamp(name, value)
    return value


def require_utc_window(name_prefix: str, window_start: Any, window_end: Any) -> None:
    """Require a non-empty half-open UTC window ``[start, end)``."""
    start = parse_utc_timestamp(f"{name_prefix}.from", window_start)
    end = parse_utc_timestamp(f"{name_prefix}.until", window_end)
    if start >= end:
        raise CoreValidationError(
            f"{name_prefix}.from must be strictly before {name_prefix}.until; "
            f"got [{window_start}, {window_end})"
        )


def utc_epoch_seconds(name: str, value: str) -> int:
    """Deterministic epoch-seconds projection of one UTC timestamp."""
    moment = parse_utc_timestamp(name, value)
    return int(moment.timestamp())


def format_utc_timestamp(epoch_seconds: int) -> str:
    """Canonical ``Z``-suffixed rendering of an epoch-seconds instant."""
    if not isinstance(epoch_seconds, int) or isinstance(epoch_seconds, bool):
        raise CoreValidationError("epoch seconds must be an integer")
    moment = datetime.fromtimestamp(epoch_seconds, tz=timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


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
