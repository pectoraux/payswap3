from __future__ import annotations

from datetime import datetime

from src.core.errors import CoreValidationError


def require_text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CoreValidationError(f"{name} must be a non-empty string")
    return value


def validate_timestamp(name: str, value: str) -> None:
    require_text(name, value)
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CoreValidationError(f"{name} must be an ISO-8601 timestamp") from exc


def require_digest(name: str, value: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise CoreValidationError(f"{name} must be a lowercase SHA-256 hex digest")
    return value


def exact_fields(name: str, value, required: set[str]) -> None:
    if set(value) != required:
        missing = sorted(required - set(value))
        extra = sorted(set(value) - required)
        raise CoreValidationError(
            f"{name} fields are not canonical; missing={missing}, extra={extra}"
        )
