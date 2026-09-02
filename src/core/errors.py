from __future__ import annotations


class CoreValidationError(ValueError):
    """Raised when a core protocol value violates its immutable contract."""
