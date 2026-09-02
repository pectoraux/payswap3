"""Deterministic route enumeration over the declared hop-offer graph.

A route is a simple path of hops that starts in the intent asset (the
payer side), passes only through declared substitute assets (when the
policy allows asset substitution) and returns to the intent asset (the
destination side). One hop may be a same-asset passthrough, which yields
the direct single-hop route.

Enumeration is exhaustive over simple paths bounded by
``MAX_ROUTE_HOPS`` and canonically ordered by
``(hop count, ordered hop identifiers)`` so the candidate set is a pure
function of the input — no entropy, no insertion-order dependence.
"""

from __future__ import annotations

from typing import Iterable

from src.core.errors import CoreValidationError

from ._validation import require_identifier
from .contracts import MAX_ROUTE_HOPS
from .inputs import RouteHopOffer

#: One enumerated route: an ordered tuple of hop offers.
Route = tuple[RouteHopOffer, ...]


def enumerate_routes(
    hop_offers: Iterable[RouteHopOffer],
    *,
    source_asset: str,
    allowed_intermediate_assets: Iterable[str],
    max_hops: int = MAX_ROUTE_HOPS,
) -> tuple[Route, ...]:
    """Enumerate every simple route from ``source_asset`` back to itself.

    Intermediate assets are restricted to
    ``allowed_intermediate_assets`` (the economic slack's substitute
    assets when the policy allows substitution, else empty). Routes are
    simple: no asset repeats except the final return to the source asset.
    The result is canonically sorted by ``(hop count, hop identifiers)``.
    """
    require_identifier("route source_asset", source_asset)
    if not isinstance(max_hops, int) or isinstance(max_hops, bool) or max_hops < 1:
        raise CoreValidationError("route max_hops must be a positive integer")
    intermediates = frozenset(allowed_intermediate_assets)
    if source_asset in intermediates:
        raise CoreValidationError(
            "the source asset cannot simultaneously be a substitute asset"
        )
    offers = tuple(hop_offers)
    by_source: dict[str, list[RouteHopOffer]] = {}
    for offer in offers:
        by_source.setdefault(offer.corridor.source_asset, []).append(offer)
    for candidates in by_source.values():
        candidates.sort(key=lambda offer: offer.hop_id)

    routes: list[Route] = []
    _extend(
        by_source,
        current_asset=source_asset,
        visited=frozenset({source_asset}),
        prefix=(),
        source_asset=source_asset,
        intermediates=intermediates,
        max_hops=max_hops,
        routes=routes,
    )
    routes.sort(key=lambda route: (len(route), tuple(hop.hop_id for hop in route)))
    return tuple(routes)


def _extend(
    by_source: dict[str, list[RouteHopOffer]],
    *,
    current_asset: str,
    visited: frozenset[str],
    prefix: tuple[RouteHopOffer, ...],
    source_asset: str,
    intermediates: frozenset[str],
    max_hops: int,
    routes: list[Route],
) -> None:
    if len(prefix) >= max_hops:
        return
    for offer in by_source.get(current_asset, ()):
        next_asset = offer.corridor.target_asset
        route = prefix + (offer,)
        if next_asset == source_asset:
            routes.append(route)
            continue
        if next_asset in visited:
            continue
        if next_asset not in intermediates:
            continue
        _extend(
            by_source,
            current_asset=next_asset,
            visited=visited | {next_asset},
            prefix=route,
            source_asset=source_asset,
            intermediates=intermediates,
            max_hops=max_hops,
            routes=routes,
        )


def route_assets(route: Route) -> tuple[str, ...]:
    """The asset sequence a route traverses, including both endpoints."""
    if not route:
        raise CoreValidationError("a route must contain at least one hop")
    return (route[0].corridor.source_asset,) + tuple(
        hop.corridor.target_asset for hop in route
    )


def route_latency_seconds(route: Route) -> int:
    return sum(hop.latency_seconds for hop in route)


def route_hop_ids(route: Route) -> tuple[str, ...]:
    return tuple(hop.hop_id for hop in route)
