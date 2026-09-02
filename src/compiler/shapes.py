"""Payment-shape enumeration: single payments and deterministic splits.

A payment shape is an ordered set of payments, each carrying one route
and one allocated source-side share of the intent amount. Splitting uses
the money authority's exact ``allocate_equal`` (WORK-006): the parts sum
to the intent amount exactly, with residual minor units distributed by
the largest-remainder rule and the lowest-index tie-break.

Shapes enumerate every K-subset (K = 1..max_payment_count, bounded by
``MAX_SHAPE_CANDIDATES``) of the statically feasible routes in canonical
order. Each route is used by at most one payment of a shape: its
capacity is consumed once. The enumeration is a pure function of the
feasible route set — deterministic, insertion-order independent, and
fail-closed when the structural bound is exceeded.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations
from typing import Any, Iterable, Sequence

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.money import Amount, allocate_equal

from ._validation import require_identifier, require_int
from .contracts import MAX_SHAPE_CANDIDATES
from .routing import Route, route_hop_ids


@dataclass(frozen=True, slots=True)
class PaymentShape:
    """One payment: a route and its allocated source-side amount."""

    route: Route
    source_value: int


@dataclass(frozen=True, slots=True)
class ShapeCandidate:
    """An enumerated payment shape with its canonical digest.

    The digest is the canonical SHA-256 of the semantic projection
    ``{"payments": [[hop_id..., source_value], ...]}`` — the deterministic
    final tie-break of the optimizer, and a collision-free identity of
    the shape's routing decision.
    """

    payments: tuple[PaymentShape, ...]
    digest: str

    @property
    def payment_count(self) -> int:
        return len(self.payments)

    @property
    def hop_count(self) -> int:
        return sum(len(payment.route) for payment in self.payments)


def shape_digest(payments: Sequence[PaymentShape]) -> str:
    projection = {
        "payments": [
            [*route_hop_ids(payment.route), payment.source_value]
            for payment in payments
        ]
    }
    return canonical_sha256(projection)


def enumerate_shapes(
    feasible_routes: Sequence[Route],
    *,
    intent_amount: Amount,
    allow_split: bool,
    max_payment_count: int,
) -> tuple[ShapeCandidate, ...]:
    """Enumerate every bounded payment shape over the feasible routes.

    ``intent_amount`` is the source-side total in the intent asset (the
    money authority splits it exactly). When ``allow_split`` is false,
    only single-payment shapes are enumerated; when no split is allowed
    the slack's ``max_payment_count`` is ignored for K > 1.
    """
    if not isinstance(intent_amount, Amount):
        raise CoreValidationError("shape enumeration requires a money Amount")
    if intent_amount.value < 1:
        raise CoreValidationError("the intent amount must be positive to split")
    if not isinstance(feasible_routes, (list, tuple)) or not feasible_routes:
        raise CoreValidationError("shape enumeration requires feasible routes")
    require_int("max_payment_count", max_payment_count, minimum=1)

    route_count = len(feasible_routes)
    max_k = 1 if not allow_split else min(max_payment_count, route_count)
    total_shapes = 0
    for k in range(1, max_k + 1):
        total_shapes += _binomial(route_count, k)
    if total_shapes > MAX_SHAPE_CANDIDATES:
        raise CoreValidationError(
            f"payment-shape enumeration exceeds the frozen structural bound: "
            f"{total_shapes} candidate shapes over {route_count} routes with up to "
            f"{max_k} payments each; the compiler fails closed instead of "
            f"exploding (bound={MAX_SHAPE_CANDIDATES})"
        )

    shapes: list[ShapeCandidate] = []
    for k in range(1, max_k + 1):
        for subset in combinations(feasible_routes, k):
            parts = allocate_equal(intent_amount, k)
            payments = tuple(
                PaymentShape(route=route, source_value=part.value)
                for route, part in zip(subset, parts)
            )
            shapes.append(
                ShapeCandidate(payments=payments, digest=shape_digest(payments))
            )
    shapes.sort(key=lambda shape: shape.digest)
    return tuple(shapes)


def _binomial(n: int, k: int) -> int:
    from math import comb

    return comb(n, k)


def shape_projection(candidate: "ShapeCandidate") -> dict[str, Any]:
    """Canonical semantic projection used by digests and reports."""
    return {
        "payments": [
            [*route_hop_ids(payment.route), payment.source_value]
            for payment in candidate.payments
        ]
    }


def require_canonical_shape_routes(
    feasible_routes: Iterable[Route],
) -> tuple[Route, ...]:
    """Validate that feasible routes are unique and canonically ordered."""
    routes = tuple(feasible_routes)
    keys = [route_hop_ids(route) for route in routes]
    if len(set(keys)) != len(keys):
        raise CoreValidationError("feasible routes must be unique")
    if keys != sorted(keys):
        raise CoreValidationError("feasible routes must be canonically ordered")
    for route in routes:
        if not route:
            raise CoreValidationError("a feasible route must contain hops")
        require_identifier("route hop", route[0].hop_id)
    return routes
