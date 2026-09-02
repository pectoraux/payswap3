"""Strict fail-closed validation helpers for the safety domain.

Every failure raises :class:`~src.core.errors.CoreValidationError` — the
single error authority owned by ``src.core`` — with a descriptive message.
No second error authority is introduced.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any, Mapping

from src.core.envelope import Provenance
from src.core.errors import CoreValidationError

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9/._:+-]*$")
_MAX_IDENTIFIER_LENGTH = 200
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


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


def require_digest(name: str, value: str) -> str:
    """Require a canonical lowercase 64-hex SHA-256 digest."""
    require_text(name, value)
    if _DIGEST_RE.match(value) is None:
        raise CoreValidationError(f"{name} must be a 64-character lowercase hex digest")
    return value


def parse_utc_timestamp(name: str, value: str) -> datetime:
    """Parse a canonical UTC timestamp ending in ``Z``.

    Timestamps are declared data, never clock reads: the safety domain is
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


def require_utc_timestamp(name: str, value: str) -> str:
    parse_utc_timestamp(name, value)
    return value


def require_utc_timestamp_order(name_a: str, value_a: str, name_b: str, value_b: str) -> None:
    if parse_utc_timestamp(name_a, value_a) > parse_utc_timestamp(name_b, value_b):
        raise CoreValidationError(f"{name_b} must not be earlier than {name_a}")


def offset_utc_timestamp(name: str, value: str, seconds: int) -> str:
    """Displace a canonical UTC timestamp by a whole number of seconds.

    Pure calendar arithmetic over declared data; the result is always
    formatted back into the canonical ``Z`` form.
    """
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


def require_utc_timestamp_within(
    name: str, moment: str, window_start: str, window_end: str
) -> None:
    """Fail closed unless ``moment`` lies in the half-open window."""
    if not utc_timestamp_within(window_start, moment, window_end):
        raise CoreValidationError(
            f"{name} {moment} must lie in the half-open window "
            f"[{window_start}, {window_end})"
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


def require_provenance_evidence(name: str, provenance: Provenance) -> Provenance:
    """Every safety decision, assessment, signal and command is evidence-backed.

    A provenance record without explicit evidence references would be an
    oracle decision out of thin air; the safety domain fails closed on it
    (constitution hard invariant 13: material decisions preserve
    provenance).
    """
    if not isinstance(provenance, Provenance):
        raise CoreValidationError(f"{name} provenance must be a Provenance")
    if not provenance.evidence_refs:
        raise CoreValidationError(
            f"{name} requires explicit evidence references in its provenance; "
            "safety decisions are never issued without evidence"
        )
    return provenance


def require_identifier_tuple(name: str, value: Any) -> tuple[str, ...]:
    """Require a non-empty tuple of canonical identifiers (fail closed)."""
    if not isinstance(value, (tuple, list)):
        raise CoreValidationError(f"{name} must be provided as a sequence")
    if not value:
        raise CoreValidationError(f"{name} must not be empty")
    refs = tuple(require_identifier(f"{name} entry", ref) for ref in value)
    if len(set(refs)) != len(refs):
        raise CoreValidationError(f"{name} contains duplicate references")
    return refs
