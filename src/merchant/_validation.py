from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping

from src.core.errors import CoreValidationError


def text(name: str, value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CoreValidationError(f"{name} must be a non-empty string")
    return value


def identifier(name: str, value: object) -> str:
    value = text(name, value)
    if any(ch.isspace() for ch in value):
        raise CoreValidationError(f"{name} must not contain whitespace")
    return value


def timestamp(name: str, value: object) -> str:
    value = text(name, value)
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CoreValidationError(f"{name} must be an ISO-8601 timestamp") from exc
    return value


def fields(name: str, value: Mapping[str, Any], expected: set[str]) -> None:
    if not isinstance(value, Mapping):
        raise CoreValidationError(f"{name} must be an object")
    if set(value) != expected:
        raise CoreValidationError(f"{name} fields are not canonical")
