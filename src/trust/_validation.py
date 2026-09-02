"""Internal fail-closed validation helpers for the trust domain.

All trust-domain value violations raise the single core error authority
(``src.core.errors.CoreValidationError``); this module never introduces a
second error family.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from typing import Any, Mapping

from src.core.errors import CoreValidationError

_IDENTIFIER_SUFFIX = re.compile(r"^[A-Za-z0-9._-]+$")
_INTERNAL_OBJECT_TYPE = re.compile(r"^trust/[a-z0-9-]+/v1$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def require_text(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CoreValidationError(f"{name} must be a non-empty string")
    return value


def require_optional_text(name: str, value: Any) -> str | None:
    if value is None:
        return None
    return require_text(name, value)


def require_identifier(name: str, value: Any, prefix: str) -> str:
    """Validate an internal non-registry domain identifier ``<prefix><slug>``."""
    if not isinstance(value, str):
        raise CoreValidationError(f"{name} must be a string identifier with prefix '{prefix}'")
    if not value.startswith(prefix):
        raise CoreValidationError(f"{name} must start with '{prefix}'")
    suffix = value[len(prefix):]
    if not _IDENTIFIER_SUFFIX.match(suffix):
        raise CoreValidationError(
            f"{name} must have a non-empty slug of [A-Za-z0-9._-] after '{prefix}'"
        )
    return value


def require_positive_int(name: str, value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise CoreValidationError(f"{name} must be a positive integer")
    return value


def require_non_negative_int(name: str, value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise CoreValidationError(f"{name} must be a non-negative integer")
    return value


def parse_timestamp(name: str, value: Any) -> datetime:
    """Parse an offset-aware ISO-8601 timestamp; naive timestamps fail closed."""
    text = require_text(name, value)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CoreValidationError(f"{name} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise CoreValidationError(f"{name} must include a UTC offset")
    return parsed


def require_timestamp(name: str, value: Any) -> str:
    parse_timestamp(name, value)
    return value


def require_hex_digest(name: str, value: Any) -> str:
    if not isinstance(value, str) or not _HEX64.match(value):
        raise CoreValidationError(f"{name} must be a lowercase 64-character hex digest")
    return value


def require_str_enum(name: str, value: Any, enum_cls: type[StrEnum]) -> StrEnum:
    if isinstance(value, enum_cls):
        return value
    if isinstance(value, str):
        try:
            return enum_cls(value)
        except ValueError as exc:
            raise CoreValidationError(
                f"{name} must be one of {[item.value for item in enum_cls]}"
            ) from exc
    raise CoreValidationError(f"{name} must be a member of the closed {enum_cls.__name__} vocabulary")


def require_str_tuple(name: str, value: Any, *, distinct: bool = False) -> tuple[str, ...]:
    """Normalize a list/tuple of non-empty strings into an immutable tuple."""
    if isinstance(value, tuple):
        items = list(value)
    elif isinstance(value, list):
        items = value
    else:
        raise CoreValidationError(f"{name} must be a list or tuple of strings")
    for item in items:
        require_text(f"{name} item", item)
    if distinct and len(set(items)) != len(items):
        raise CoreValidationError(f"{name} contains duplicate values")
    return tuple(items)


def require_attributes(name: str, value: Any) -> tuple[tuple[str, Any], ...]:
    """Normalize an opaque attribute mapping into sorted immutable pairs."""
    from src.core.serialization import normalize_immutable_value

    if value is None:
        return ()
    if not isinstance(value, Mapping):
        raise CoreValidationError(f"{name} must be a mapping")
    keys = list(value)
    for key in keys:
        require_text(f"{name} key", key)
    if len(set(keys)) != len(keys):
        raise CoreValidationError(f"{name} contains duplicate keys")
    return tuple(
        (key, normalize_immutable_value(f"{name}.{key}", value[key])) for key in sorted(keys)
    )


def check_attribute_pairs(name: str, value: Any) -> None:
    """Validate the immutable storage form of normalized attribute pairs.

    Complements ``require_attributes``: records hold the already-normalized
    ``tuple[tuple[str, Any], ...]`` form, which is validated here rather than
    re-normalized (mirrors the core ``check_immutable_value`` discipline).
    """
    from src.core.serialization import check_immutable_value

    if not isinstance(value, tuple):
        raise CoreValidationError(f"{name} must be a tuple of normalized attribute pairs")
    seen: set[str] = set()
    for pair in value:
        if not isinstance(pair, tuple) or len(pair) != 2:
            raise CoreValidationError(f"{name} entries must be (key, value) pairs")
        key, item = pair
        require_text(f"{name} key", key)
        if key in seen:
            raise CoreValidationError(f"{name} contains duplicate keys")
        seen.add(key)
        check_immutable_value(f"{name}.{key}", item)


def require_window(name: str, not_before: Any, not_after: Any) -> tuple[str, str]:
    """Validate a half-open validity window [not_before, not_after)."""
    before = require_timestamp(f"{name}.not_before", not_before)
    after = require_timestamp(f"{name}.not_after", not_after)
    if parse_timestamp(f"{name}.not_before", before) > parse_timestamp(f"{name}.not_after", after):
        raise CoreValidationError(f"{name}.not_before must not be later than {name}.not_after")
    return before, after


def window_contains(not_before: str, not_after: str, stamp: str) -> bool:
    """Half-open window membership: [not_before, not_after)."""
    return (
        parse_timestamp("window.not_before", not_before)
        <= parse_timestamp("window.stamp", stamp)
        < parse_timestamp("window.not_after", not_after)
    )


def require_window_subset(name: str, child: tuple[str, str], parent: tuple[str, str]) -> None:
    """Fail closed unless the child validity window is contained in the parent window."""
    if not window_subset(child, parent):
        raise CoreValidationError(f"{name} is not contained in the parent validity window")


def window_subset(child: tuple[str, str], parent: tuple[str, str]) -> bool:
    """True when the child window is contained in the parent window."""
    child_before, child_after = child
    parent_before, parent_after = parent
    return (
        parse_timestamp("child.not_before", child_before)
        >= parse_timestamp("parent.not_before", parent_before)
        and parse_timestamp("child.not_after", child_after)
        <= parse_timestamp("parent.not_after", parent_after)
    )
