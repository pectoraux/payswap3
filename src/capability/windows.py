"""Deterministic operating windows for capability records.

Operating windows are explicit timestamp bounds. They are validated for
ordering and canonical UTC form, and they are only ever compared with other
explicit timestamps supplied by the caller — never with wall-clock time.
Intervals are half-open: ``opens_at`` is included, ``closes_at`` is not.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping

from ..core.errors import CoreValidationError

from ._validation import require_text

_WINDOW_FIELDS = frozenset({"opens_at", "closes_at"})


def validate_utc_timestamp(name: str, value: Any) -> None:
    require_text(name, value)
    assert isinstance(value, str)
    if not value.endswith("Z"):
        raise CoreValidationError(f"{name} must be an explicit UTC timestamp ending in 'Z'")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CoreValidationError(f"{name} must be an ISO-8601 UTC timestamp") from exc


def parse_utc_timestamp(name: str, value: Any) -> datetime:
    validate_utc_timestamp(name, value)
    assert isinstance(value, str)
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@dataclass(frozen=True, slots=True)
class OperatingWindow:
    """Half-open explicit time bound: ``[opens_at, closes_at)`` in UTC."""

    opens_at: str
    closes_at: str

    def __post_init__(self) -> None:
        validate_utc_timestamp("operating window opens_at", self.opens_at)
        validate_utc_timestamp("operating window closes_at", self.closes_at)
        if parse_utc_timestamp("opens_at", self.opens_at) >= parse_utc_timestamp("closes_at", self.closes_at):
            raise CoreValidationError("operating window opens_at must be strictly before closes_at")

    def contains(self, timestamp: str) -> bool:
        """Deterministic membership test against the explicit bounds."""
        moment = parse_utc_timestamp("timestamp", timestamp)
        return (
            parse_utc_timestamp("opens_at", self.opens_at)
            <= moment
            < parse_utc_timestamp("closes_at", self.closes_at)
        )

    def to_dict(self) -> dict[str, Any]:
        return {"opens_at": self.opens_at, "closes_at": self.closes_at}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "OperatingWindow":
        if not isinstance(value, Mapping):
            raise CoreValidationError("operating window must be an object")
        if set(value) != _WINDOW_FIELDS:
            missing = sorted(_WINDOW_FIELDS - set(value))
            extra = sorted(set(value) - _WINDOW_FIELDS)
            raise CoreValidationError(
                f"operating window fields are not canonical; missing={missing}, extra={extra}"
            )
        return cls(opens_at=value["opens_at"], closes_at=value["closes_at"])


def validate_disjoint_windows(name: str, windows: tuple[OperatingWindow, ...]) -> None:
    """Windows attached to one capability must not overlap.

    Touching bounds are allowed because intervals are half-open.
    """
    for index, first in enumerate(windows):
        if not isinstance(first, OperatingWindow):
            raise CoreValidationError(f"{name} entries must be OperatingWindow values")
        for second in windows[index + 1 :]:
            if not isinstance(second, OperatingWindow):
                raise CoreValidationError(f"{name} entries must be OperatingWindow values")
            first_opens = parse_utc_timestamp("opens_at", first.opens_at)
            first_closes = parse_utc_timestamp("closes_at", first.closes_at)
            second_opens = parse_utc_timestamp("opens_at", second.opens_at)
            second_closes = parse_utc_timestamp("closes_at", second.closes_at)
            overlaps = first_opens < second_closes and second_opens < first_closes
            if overlaps:
                raise CoreValidationError(
                    f"{name} overlap between {first.opens_at}..{first.closes_at} "
                    f"and {second.opens_at}..{second.closes_at}"
                )
