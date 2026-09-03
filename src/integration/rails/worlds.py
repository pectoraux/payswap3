"""The rail world harnesses of the IG-005 external rail sandbox gate.

Each world is ONE full IG-002 lifecycle composition (the merged
``FulfillmentLifecycleGate`` over the real domain engines) bound to
exactly ONE typed adapter binding — the IG-002 single-binding rule.
The gate composes two worlds per comparison:

* **rail A** — Stripe test mode (``REAL_PROVIDER_SANDBOX``): the
  merged WORK-027 ``StripeTestRail`` reused through import (never
  forked), credential read from ``STRIPE_SECRET_KEY`` at call time;
* **rail B** — the public Stellar testnet (``REAL_PROVIDER_SANDBOX``):
  the IG-005 ``StellarTestnetRail`` behind the same typed ports,
  credential-free;
* the **local deterministic pair** — two merged WORK-027
  ``LocalDeterministicRail`` instances (``LOCAL_DETERMINISTIC_SANDBOX``)
  drive the deterministic failure/investigation battery; they are
  never counted as one of the two external rails.

Rail classification honesty is enforced at construction: a
``REAL_PROVIDER_SANDBOX`` classification may only be declared over a
bound rail of a known REAL rail type, and a
``LOCAL_DETERMINISTIC_SANDBOX`` classification only over the local
deterministic rail type — a classification lie fails closed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from src.core.errors import CoreValidationError
from src.interoperability import (
    AdapterStatusMap,
    EffectInterface,
    IdentifierScheme,
    ObservationInterface,
    WorldAdapter,
)
from src.execution.adapters import AdapterBinding
from src.integration.lifecycle.dogfooding import (
    LOCAL_STATUS_MAP,
    LocalDeterministicRail,
    StripeTestRail,
    make_stripe_binding,
)

from .contracts import (
    LOCAL_RAIL_A_ADAPTER_ID,
    LOCAL_RAIL_A_DOMAIN_ID,
    LOCAL_RAIL_A_ENVIRONMENT_ID,
    LOCAL_RAIL_A_NAME,
    LOCAL_RAIL_B_ADAPTER_ID,
    LOCAL_RAIL_B_DOMAIN_ID,
    LOCAL_RAIL_B_ENVIRONMENT_ID,
    LOCAL_RAIL_B_NAME,
    LOCAL_RAIL_CURRENCY,
    RAIL_A_ADAPTER_ID,
    RAIL_A_CURRENCY,
    RAIL_A_DOMAIN_ID,
    RAIL_A_ENVIRONMENT_ID,
    RAIL_A_NAME,
    RAIL_B_ADAPTER_ID,
    RAIL_B_CURRENCY,
    RAIL_B_DOMAIN_ID,
    RAIL_B_ENVIRONMENT_ID,
    RAIL_B_NAME,
    RAILS_AMOUNT_MINOR,
    RailClass,
)
from .stellar import STELLAR_HORIZON_BASE

#: The declared native-reference pattern of each rail family (the
#: exact-value validation vocabulary of the projection's
#: provider-native-reference rule).
STRIPE_REFERENCE_PATTERN = re.compile(r"^pi_[A-Za-z0-9]+$")
STELLAR_REFERENCE_PATTERN = re.compile(r"^[0-9a-f]{64}$")
LOCAL_REFERENCE_PATTERN = re.compile(r"^ig002-local/[A-Za-z0-9_-]+$")


@dataclass(frozen=True, slots=True)
class RailWorld:
    """One declared rail world of the IG-005 composition.

    ``name`` is the comparison role (rail_a / rail_b / local_a /
    local_b); ``rail_class`` is the frozen classification; the world
    binds exactly one typed adapter binding and declares the world's
    canonical asset word and native-reference pattern. The
    classification is validated against the bound rail's observable
    nature (a REAL classification over a local rail fails closed —
    and vice versa).
    """

    name: str
    rail_class: RailClass
    environment_id: str
    domain_id: str
    adapter_id: str
    rail: Any
    binding: AdapterBinding
    declared_currency: str
    declared_amount_minor: int = RAILS_AMOUNT_MINOR

    def __post_init__(self) -> None:
        RailClass.parse(self.rail_class)
        for field_name in ("name", "environment_id", "domain_id", "adapter_id"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise CoreValidationError(
                    f"rail world requires a non-empty {field_name}"
                )
        if not isinstance(self.binding, AdapterBinding):
            raise CoreValidationError(
                "rail world requires an AdapterBinding over the typed ports"
            )
        if self.binding.adapter_id != self.adapter_id:
            raise CoreValidationError(
                "rail world adapter ids must agree with the binding"
            )
        if not isinstance(self.declared_currency, str) or len(
            self.declared_currency
        ) != 3:
            raise CoreValidationError(
                "the declared currency must be a three-letter asset word"
            )
        # Classification honesty: the declared class must match the
        # bound rail's observable nature, fail closed otherwise.
        real_rails = (StripeTestRail, _STELLAR_RAIL_TYPE())
        if self.rail_class is RailClass.REAL_PROVIDER_SANDBOX:
            if isinstance(self.rail, LocalDeterministicRail):
                raise CoreValidationError(
                    "a LOCAL_DETERMINISTIC_SANDBOX rail can never be "
                    "classified REAL_PROVIDER_SANDBOX (classification "
                    "honesty fails closed)"
                )
            if not isinstance(self.rail, real_rails):
                raise CoreValidationError(
                    "a REAL_PROVIDER_SANDBOX world must bind a known real "
                    "external rail (Stripe test mode or Stellar testnet)"
                )
        elif self.rail_class is RailClass.LOCAL_DETERMINISTIC_SANDBOX:
            if not isinstance(self.rail, LocalDeterministicRail):
                raise CoreValidationError(
                    "a LOCAL_DETERMINISTIC_SANDBOX world must bind the "
                    "merged local deterministic rail"
                )

    @property
    def native_status_vocabulary(self) -> frozenset[str]:
        """The owning adapter's declared native status vocabulary."""
        entries = self.binding.status_map.entries if self.binding.status_map else ()
        return frozenset(entry.native_code for entry in entries)

    @property
    def native_reference_pattern(self) -> re.Pattern[str]:
        if isinstance(self.rail, LocalDeterministicRail):
            return LOCAL_REFERENCE_PATTERN
        if isinstance(self.rail, StripeTestRail):
            return STRIPE_REFERENCE_PATTERN
        return STELLAR_REFERENCE_PATTERN

    @property
    def environment_class(self) -> str:
        """The capability domain's frozen environment class of the id."""
        from src.capability import classify_environment

        return classify_environment(self.environment_id)


def _STELLAR_RAIL_TYPE() -> type:
    from .stellar import StellarTestnetRail

    return StellarTestnetRail


def build_rail_world_a(
    *,
    environment_id: str = RAIL_A_ENVIRONMENT_ID,
    domain_id: str = RAIL_A_DOMAIN_ID,
    decline_keys: Iterable[str] = (),
    secret_env_var: str = "STRIPE_SECRET_KEY",
    rail: StripeTestRail | None = None,
) -> RailWorld:
    """Build rail A: Stripe test mode over the merged WORK-027 rail.

    The Stripe rail is REUSED from the merged IG-002 dogfooding
    module (imported, never forked): the credential is read from the
    ``STRIPE_SECRET_KEY`` environment variable at call time, never
    stored, printed or committed. ``decline_keys`` are the declared
    deterministic rejection keys (the scenario B probe: Stripe's test
    payment method ``pm_card_visa_chargeDeclined``).
    """
    stripe_rail = (
        rail
        if rail is not None
        else StripeTestRail(decline_keys=frozenset(decline_keys))
    )
    if not isinstance(stripe_rail, StripeTestRail):
        raise CoreValidationError("rail A binds the merged StripeTestRail")
    binding = make_stripe_binding(stripe_rail)
    return RailWorld(
        name=RAIL_A_NAME,
        rail_class=RailClass.REAL_PROVIDER_SANDBOX,
        environment_id=environment_id,
        domain_id=domain_id,
        adapter_id=RAIL_A_ADAPTER_ID,
        rail=stripe_rail,
        binding=binding,
        declared_currency=RAIL_A_CURRENCY,
    )


def build_rail_world_b(
    *,
    environment_id: str = RAIL_B_ENVIRONMENT_ID,
    domain_id: str = RAIL_B_DOMAIN_ID,
    reject_keys: Iterable[str] = (),
    api_base: str = STELLAR_HORIZON_BASE,
    rail: Any | None = None,
) -> RailWorld:
    """Build rail B: the public Stellar testnet (credential-free).

    ``reject_keys`` are the declared deterministic rejection keys (the
    scenario B probe: the payment targets the deterministic UNFUNDED
    destination and the network definitively rejects it with
    ``op_no_destination``). ``api_base`` may be pointed at an
    unreachable endpoint to prove the offline contract deterministically.
    """
    from .stellar import StellarTestnetRail, make_stellar_binding

    stellar_rail = (
        rail
        if rail is not None
        else StellarTestnetRail(
            reject_keys=frozenset(reject_keys), api_base=api_base
        )
    )
    if not isinstance(stellar_rail, StellarTestnetRail):
        raise CoreValidationError("rail B binds the StellarTestnetRail")
    binding = make_stellar_binding(stellar_rail)
    return RailWorld(
        name=RAIL_B_NAME,
        rail_class=RailClass.REAL_PROVIDER_SANDBOX,
        environment_id=environment_id,
        domain_id=domain_id,
        adapter_id=RAIL_B_ADAPTER_ID,
        rail=stellar_rail,
        binding=binding,
        declared_currency=RAIL_B_CURRENCY,
    )


def _make_local_world(
    *,
    name: str,
    adapter_id: str,
    environment_id: str,
    domain_id: str,
    rail: LocalDeterministicRail,
) -> RailWorld:
    contract = WorldAdapter(
        adapter_id=adapter_id,
        capability_id=f"capability/{adapter_id.rpartition('/')[2]}",
        observation_interface=ObservationInterface(
            operations=("RESOLVE_ENDPOINT", "PAYMENT_STATUS", "FINALITY")
        ),
        effect_interface=EffectInterface(
            operations=("SUBMIT_PAYMENT",),
            destination_schemes=(IdentifierScheme.ALIAS,),
        ),
        fidelity_class="SIMULATION",
    )
    status_map = AdapterStatusMap(
        adapter_id=adapter_id, entries=LOCAL_STATUS_MAP
    )
    binding = AdapterBinding(
        adapter_id=adapter_id,
        submission_port=rail,
        reconciliation_port=rail,
        world_adapter=contract,
        status_map=status_map,
    )
    return RailWorld(
        name=name,
        rail_class=RailClass.LOCAL_DETERMINISTIC_SANDBOX,
        environment_id=environment_id,
        domain_id=domain_id,
        adapter_id=adapter_id,
        rail=rail,
        binding=binding,
        declared_currency=LOCAL_RAIL_CURRENCY,
    )


def build_local_rail_pair(
    *,
    submissions: Mapping[str, Iterable[str]] | None = None,
    queries: Mapping[str, Iterable[str]] | None = None,
) -> tuple[RailWorld, RailWorld]:
    """Build the local deterministic pair with ONE shared script set.

    The same declared scripts drive both worlds (the shared declared
    input, exactly like the IG-003 environment pair): identical
    world-outcome values, identical idempotency keys — differing only
    in the world binding (environment, domain, adapter identity).
    """
    world_a = _make_local_world(
        name=LOCAL_RAIL_A_NAME,
        adapter_id=LOCAL_RAIL_A_ADAPTER_ID,
        environment_id=LOCAL_RAIL_A_ENVIRONMENT_ID,
        domain_id=LOCAL_RAIL_A_DOMAIN_ID,
        rail=LocalDeterministicRail(
            submissions=submissions, queries=queries
        ),
    )
    world_b = _make_local_world(
        name=LOCAL_RAIL_B_NAME,
        adapter_id=LOCAL_RAIL_B_ADAPTER_ID,
        environment_id=LOCAL_RAIL_B_ENVIRONMENT_ID,
        domain_id=LOCAL_RAIL_B_DOMAIN_ID,
        rail=LocalDeterministicRail(
            submissions=submissions, queries=queries
        ),
    )
    return world_a, world_b


__all__ = [
    "LOCAL_REFERENCE_PATTERN",
    "RailWorld",
    "STELLAR_REFERENCE_PATTERN",
    "STRIPE_REFERENCE_PATTERN",
    "build_local_rail_pair",
    "build_rail_world_a",
    "build_rail_world_b",
]
