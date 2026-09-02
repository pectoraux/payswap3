"""Shared fail-closed validation helpers for the capability domain.

All validation raises :class:`src.core.errors.CoreValidationError`, the single
error authority owned by the canonical core. Nothing here introduces a second
authority; these helpers only keep domain error messages descriptive.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

from ..core.errors import CoreValidationError

# Internal domain identifiers deliberately avoid the registry-governed
# "payswap/..." protocol-visible namespace; they use "capability/..." instead.
INTERNAL_ID_PREFIX = "capability/"

_JURISDICTION_PATTERN = re.compile(r"[A-Z]{2}")
_PROTOCOL_VERSION_PATTERN = re.compile(r"v\d+\.\d+")


def require_text(name: str, value: Any) -> None:
    if not isinstance(value, str) or not value.strip():
        raise CoreValidationError(f"{name} must be a non-empty string")


def require_internal_id(name: str, value: Any) -> None:
    require_text(name, value)
    assert isinstance(value, str)
    if not value.startswith(INTERNAL_ID_PREFIX):
        raise CoreValidationError(
            f"{name} must be an internal capability-domain identifier of the form "
            f"'{INTERNAL_ID_PREFIX}...' (registry-governed protocol-visible names are not used here)"
        )


def require_bool(name: str, value: Any) -> None:
    if not isinstance(value, bool):
        raise CoreValidationError(f"{name} must be a boolean")


def require_positive_int(name: str, value: Any) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise CoreValidationError(f"{name} must be a positive integer")


def require_int_in_range(name: str, value: Any, minimum: int, maximum: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum or value > maximum:
        raise CoreValidationError(f"{name} must be an integer between {minimum} and {maximum}")


def require_non_empty_text_tuple(name: str, value: Any) -> None:
    if not isinstance(value, tuple) or not value:
        raise CoreValidationError(f"{name} must be a non-empty tuple")
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise CoreValidationError(f"{name} entries must be non-empty strings")


def normalize_text_tuple(name: str, value: Iterable[str]) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple)):
        raise CoreValidationError(f"{name} must be a list or tuple of strings")
    result = tuple(value)
    for item in result:
        if not isinstance(item, str) or not item.strip():
            raise CoreValidationError(f"{name} entries must be non-empty strings")
    return result


def parse_enum(name: str, enum_cls: type, value: Any):
    try:
        return enum_cls(value)
    except ValueError as exc:
        raise CoreValidationError(f"{name} must use the closed vocabulary") from exc


def require_jurisdictions(name: str, value: Any) -> None:
    require_non_empty_text_tuple(name, value)
    assert isinstance(value, tuple)
    for item in value:
        if not _JURISDICTION_PATTERN.fullmatch(item):
            raise CoreValidationError(f"{name} entries must be ISO 3166-1 alpha-2 codes (e.g. 'GH')")


def require_protocol_versions(name: str, value: Any, governing: str) -> None:
    require_non_empty_text_tuple(name, value)
    assert isinstance(value, tuple)
    for item in value:
        if not _PROTOCOL_VERSION_PATTERN.fullmatch(item):
            raise CoreValidationError(f"{name} entries must be versioned protocol identifiers like 'v0.1'")
    if governing not in value:
        raise CoreValidationError(
            f"{name} must include the governing frozen protocol version {governing}"
        )
