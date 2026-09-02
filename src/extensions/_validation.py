"""Shared fail-closed validation helpers for the extension domain.

All validation raises :class:`src.core.errors.CoreValidationError`, the
single error authority owned by the canonical core. Nothing here
introduces a second authority; these helpers only keep domain error
messages descriptive and deterministic.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Iterable, Mapping

from src.core.errors import CoreValidationError

# Internal domain identifiers deliberately avoid the registry-governed
# "payswap/..." protocol-visible namespace. Manifest identities use the
# bare "extension/" prefix; the derived object kinds (instances, grants,
# invocations, contributions) use their own hyphenated internal prefixes
# ("extension-instance/", "extension-grant/", "extension-invocation/",
# "extension-contribution/"). Each prefix must be followed by a non-empty
# local part.
INTERNAL_ID_PREFIXES = (
    "extension/",
    "extension-instance/",
    "extension-grant/",
    "extension-invocation/",
    "extension-contribution/",
)

_JURISDICTION_PATTERN = re.compile(r"[A-Z]{2}")
_VERSION_PATTERN = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


def require_text(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CoreValidationError(f"{name} must be a non-empty string")
    return value


def require_bool(name: str, value: Any) -> bool:
    if not isinstance(value, bool):
        raise CoreValidationError(f"{name} must be a boolean")
    return value


def require_int(name: str, value: Any, *, minimum: int | None = None) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise CoreValidationError(f"{name} must be an integer")
    if minimum is not None and value < minimum:
        raise CoreValidationError(f"{name} must be an integer >= {minimum}")
    return value


def require_int_in_range(name: str, value: Any, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise CoreValidationError(f"{name} must be an integer")
    if value < minimum or value > maximum:
        raise CoreValidationError(
            f"{name} must be an integer between {minimum} and {maximum}"
        )
    return value


def require_internal_id(name: str, value: Any) -> str:
    require_text(name, value)
    assert isinstance(value, str)
    if value.startswith("payswap/"):
        raise CoreValidationError(
            f"{name} must be an internal extension-domain identifier; registry-governed "
            "'payswap/...' protocol-visible names are never used here"
        )
    for prefix in INTERNAL_ID_PREFIXES:
        if value.startswith(prefix):
            if len(value) > len(prefix):
                return value
            break
    raise CoreValidationError(
        f"{name} must be an internal extension-domain identifier using one of the "
        f"prefixes {list(INTERNAL_ID_PREFIXES)} with a non-empty local part"
    )


def require_digest(name: str, value: Any) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise CoreValidationError(f"{name} must be a lowercase SHA-256 hex digest")
    return value


def validate_timestamp(name: str, value: Any) -> str:
    require_text(name, value)
    assert isinstance(value, str)
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CoreValidationError(f"{name} must be an ISO-8601 timestamp") from exc
    return value


def compare_timestamps(left: str, right: str) -> int:
    """Deterministic ordering of two declared ISO-8601 instants.

    Only declared data is compared — no wall clock is read anywhere in
    this domain. Raises when either value is not a parseable instant.
    """
    left_dt = datetime.fromisoformat(validate_timestamp("left instant", left).replace("Z", "+00:00"))
    right_dt = datetime.fromisoformat(validate_timestamp("right instant", right).replace("Z", "+00:00"))
    if left_dt < right_dt:
        return -1
    if left_dt > right_dt:
        return 1
    return 0


def exact_fields(name: str, value: Any, required: set[str]) -> None:
    if not isinstance(value, Mapping):
        raise CoreValidationError(f"{name} must be an object")
    if set(value) != required:
        missing = sorted(required - set(value))
        extra = sorted(set(value) - required)
        raise CoreValidationError(
            f"{name} fields are not canonical; missing={missing}, extra={extra}"
        )


def normalize_text_tuple(name: str, value: Any) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple)):
        raise CoreValidationError(f"{name} must be a list or tuple of strings")
    result = tuple(value)
    for item in result:
        if not isinstance(item, str) or not item.strip():
            raise CoreValidationError(f"{name} entries must be non-empty strings")
    return result


def require_jurisdictions(name: str, value: Any) -> tuple[str, ...]:
    entries = normalize_text_tuple(name, value)
    if not entries:
        raise CoreValidationError(f"{name} must contain at least one jurisdiction")
    for item in entries:
        if not _JURISDICTION_PATTERN.fullmatch(item):
            raise CoreValidationError(
                f"{name} entries must be ISO 3166-1 alpha-2 codes (e.g. 'GH')"
            )
    return entries


def require_protocol_versions(name: str, value: Any, governing: str) -> tuple[str, ...]:
    entries = normalize_text_tuple(name, value)
    if not entries:
        raise CoreValidationError(f"{name} must contain at least one protocol version")
    for item in entries:
        if not re.fullmatch(r"v\d+\.\d+", item):
            raise CoreValidationError(
                f"{name} entries must be versioned protocol identifiers like 'v0.1'"
            )
    if governing not in entries:
        raise CoreValidationError(
            f"{name} must include the governing frozen protocol version {governing}"
        )
    return entries


def parse_version(name: str, value: Any) -> tuple[int, int, int]:
    require_text(name, value)
    assert isinstance(value, str)
    match = _VERSION_PATTERN.fullmatch(value)
    if match is None:
        raise CoreValidationError(
            f"{name} must be a deterministic 'major.minor.patch' version like '1.2.3'"
        )
    major, minor, patch = (int(part) for part in match.groups())
    return (major, minor, patch)


def parse_enum(name: str, enum_cls: type, value: Any):
    if isinstance(value, enum_cls):
        return value
    try:
        return enum_cls(value)
    except ValueError as exc:
        raise CoreValidationError(f"{name} must use the closed vocabulary") from exc


def pairs_to_dict(name: str, value: Any) -> dict[str, Any]:
    """Convert sorted (key, value) pair tuples into a plain dict (read view)."""
    if not isinstance(value, (tuple, list)):
        raise CoreValidationError(f"{name} must be a list or tuple of pairs")
    result: dict[str, Any] = {}
    for pair in value:
        if not isinstance(pair, (tuple, list)) or len(pair) != 2:
            raise CoreValidationError(f"{name} entries must be (key, value) pairs")
        key, item = pair
        if not isinstance(key, str):
            raise CoreValidationError(f"{name} keys must be strings")
        if key in result:
            raise CoreValidationError(f"{name} contains duplicate key {key!r}")
        result[key] = item
    return result


def normalize_canonical_pairs(name: str, value: Any) -> tuple[tuple[str, Any], ...]:
    """Normalize a mapping or pair list into sorted canonical (key, value) pairs.

    Values are restricted to the canonical immutable domain (no floats);
    nested mappings are converted recursively into sorted pairs.
    """
    from src.core.serialization import validate_canonical_value

    if isinstance(value, Mapping):
        items = list(value.items())
    elif isinstance(value, (tuple, list)) and all(
        isinstance(pair, (tuple, list)) and len(pair) == 2 for pair in value
    ):
        items = [tuple(pair) for pair in value]
    else:
        raise CoreValidationError(f"{name} must be a mapping or a list of pairs")

    def _normalize(key: str, item: Any) -> Any:
        if isinstance(item, Mapping):
            return normalize_canonical_pairs(f"{name}.{key}", item)
        if isinstance(item, (list, tuple)) and not all(
            isinstance(pair, (tuple, list)) and len(pair) == 2 and isinstance(pair[0], str)
            for pair in item
        ):
            return tuple(
                _normalize(f"{name}.{key}[{index}]", entry) for index, entry in enumerate(item)
            )
        validate_canonical_value(f"{name}.{key}", item)
        return item

    normalized = [(require_text(f"{name} key", key), _normalize(key, item)) for key, item in items]
    keys = [key for key, _ in normalized]
    if len(set(keys)) != len(keys):
        raise CoreValidationError(f"{name} contains duplicate keys")
    return tuple(sorted(normalized, key=lambda pair: pair[0]))


def pairs_to_json_value(name: str, value: Any) -> Any:
    """Convert canonical pair tuples back into plain JSON values."""
    if isinstance(value, tuple) and value and all(
        isinstance(pair, tuple) and len(pair) == 2 and isinstance(pair[0], str)
        for pair in value
    ):
        result: dict[str, Any] = {}
        for key, item in value:
            if key in result:
                raise CoreValidationError(f"{name} contains duplicate key {key!r}")
            result[key] = pairs_to_json_value(f"{name}.{key}", item)
        return result
    if isinstance(value, tuple):
        return [pairs_to_json_value(f"{name}[{index}]", item) for index, item in enumerate(value)]
    return value


def unique_entries(name: str, entries: Iterable[Any]) -> tuple[Any, ...]:
    result = tuple(entries)
    if len(set(result)) != len(result):
        raise CoreValidationError(f"{name} contains duplicate entries")
    return result
