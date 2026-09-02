"""Contract and discrimination test suite for the liquidity domain (WORK-011).

Authored RED-FIRST against the declared public boundary of ``src.liquidity``
before any implementation module exists. The suite covers:

- static boundary contracts (versions, internal non-registry object types,
  closed state vocabularies, frozen concentration caps, a forbidden-import
  audit asserting the package imports ONLY stdlib + ``src.core`` +
  ``src.money`` + ``src.value`` + ``src.capability``, and no wall-clock,
  randomness or UUIDs in domain code);
- corridor semantics (opaque source/target asset references, canonical ids);
- the frozen v0.1 lifecycles: LiquidityOffer (Create/Amend/Withdraw/
  Suspend/Resume/Expire), CreditOffer (Create/Amend/Withdraw/Suspend/
  Resume/Expire plus Draw/Repay/Restructure/Default) and CreditExposure
  (Create/Amend/Withdraw/Suspend/Resume/Expire plus Draw/Repay utilization
  accounting against the control limit);
- bounded capacity semantics (positive money amounts, capability reference
  required, availability/utilization/validity windows are half-open
  ``[from, until)`` in explicit UTC, utilization never exceeds a limit);
- exposure controls: per-counterparty/per-corridor aggregation,
  breach detection against limits that individual facility draws can
  legitimately exceed in aggregate, and concentration controls with exact
  integer cross-multiplied shares and deterministic (kind, group)
  ordering and tie-breaks;
- envelope sealing, version chains, round-trip canonical serialization and
  tamper rejection on the trusted deserialization path;
- quality-attribute measurement (scaled deterministic fixture: >= 1200
  credit offers across counterparties and corridors through aggregation,
  assessment and concentration evaluation — measured with
  ``time.process_time``, digest-equal across two independent clean
  processes);
- DOGFOOD-011 conformance (corridor liquidity bootstrap, credit
  availability changes, exposure limit breach).
"""

from __future__ import annotations

import ast
import subprocess
import sys
import time
import unittest
from pathlib import Path

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_json, canonical_sha256
from src.money import Amount, Currency

from src.liquidity import (
    CONCENTRATION_DENOMINATOR_BPS,
    CREDIT_EXPOSURE_OBJECT_TYPE,
    CREDIT_OFFER_OBJECT_TYPE,
    LIQUIDITY_OFFER_OBJECT_TYPE,
    LIQUIDITY_PROTOCOL_VERSION,
    LIQUIDITY_SCHEMA_VERSION,
    MAX_CORRIDOR_CONCENTRATION_BPS,
    MAX_COUNTERPARTY_CONCENTRATION_BPS,
    MAX_PROVIDER_CONCENTRATION_BPS,
    AggregatedExposure,
    ConcentrationControlKind,
    ConcentrationEntry,
    ConcentrationReport,
    Corridor,
    CreditExposure,
    CreditExposureSpec,
    CreditExposureState,
    CreditOffer,
    CreditOfferSpec,
    CreditOfferState,
    ExposureAssessment,
    ExposureCheck,
    ExposureStatus,
    LiquidityOffer,
    LiquidityOfferSpec,
    LiquidityOfferState,
    aggregate_credit_utilization,
    amend_credit_exposure,
    amend_credit_offer,
    amend_liquidity_offer,
    assess_exposure,
    create_credit_exposure,
    create_credit_offer,
    create_liquidity_offer,
    credit_available_capacity,
    default_credit,
    draw_against_exposure,
    draw_credit,
    evaluate_concentration,
    expire_credit_exposure,
    expire_credit_offer,
    expire_liquidity_offer,
    exposure_available_capacity,
    liquidity_offer_available_at,
    repay_against_exposure,
    repay_credit,
    resume_credit_exposure,
    resume_credit_offer,
    resume_liquidity_offer,
    restructure_credit,
    suspend_credit_exposure,
    suspend_credit_offer,
    suspend_liquidity_offer,
    withdraw_credit_exposure,
    withdraw_credit_offer,
    withdraw_liquidity_offer,
)

ENV = "env/test"
DOMAIN = "domain/demo"
STAMP = "2026-09-02T00:00:00Z"

ASSET_USD = "asset/USD"
ASSET_EUR = "asset/EUR"
ASSET_GBP = "asset/GBP"

CORRIDOR_USD_EUR = Corridor(ASSET_USD, ASSET_EUR)
CORRIDOR_EUR_USD = Corridor(ASSET_EUR, ASSET_USD)
CORRIDOR_USD_GBP = Corridor(ASSET_USD, ASSET_GBP)

LIQ_FROM = "2026-09-03T00:00:00Z"
LIQ_UNTIL = "2026-09-03T12:00:00Z"
CRED_FROM = "2026-09-03T00:00:00Z"
CRED_UNTIL = "2026-09-10T00:00:00Z"
EXP_FROM = "2026-09-03T00:00:00Z"
EXP_UNTIL = "2026-09-30T00:00:00Z"

WITHIN = "2026-09-03T01:00:00Z"
LATER = "2026-09-04T01:00:00Z"
AFTER_CRED = "2026-09-11T00:00:00Z"
AFTER_EXP = "2026-10-01T00:00:00Z"

USD = Currency(code="USD", scale=2)
EUR = Currency(code="EUR", scale=2)
GBP = Currency(code="GBP", scale=2)


def usd(value: int) -> Amount:
    return Amount(currency=USD, value=value, scale=2)


def eur(value: int) -> Amount:
    return Amount(currency=EUR, value=value, scale=2)


def prov(source: str = "liquidity/test") -> Provenance:
    return Provenance(
        issuer="principal/liquidity-operator",
        source=source,
        recorded_at=STAMP,
        evidence_refs=("evidence/work-011",),
    )


def offer_fixture(
    offer_id: str = "liquidity/offer/alpha",
    provider: str = "provider/alpha",
    capacity: Amount | None = None,
    corridor: Corridor = CORRIDOR_USD_EUR,
    available_from: str = LIQ_FROM,
    available_until: str = LIQ_UNTIL,
) -> LiquidityOffer:
    return create_liquidity_offer(
        offer_id=offer_id,
        provider=provider,
        provider_capability_id="capability/capability/alpha",
        beneficiary="principal/beneficiary-7",
        corridor=corridor,
        capacity=capacity if capacity is not None else usd(1_000_00),
        available_from=available_from,
        available_until=available_until,
        environment_id=ENV,
        domain_id=DOMAIN,
        provenance=prov(),
    )


def credit_fixture(
    offer_id: str = "liquidity/credit/alpha",
    provider: str = "provider/alpha",
    counterparty: str = "principal/cpty-7",
    limit: Amount | None = None,
    corridor: Corridor = CORRIDOR_USD_EUR,
    utilization_from: str = CRED_FROM,
    utilization_until: str = CRED_UNTIL,
    collateral_refs: tuple[str, ...] = (),
    require_collateral: bool = False,
) -> CreditOffer:
    return create_credit_offer(
        offer_id=offer_id,
        provider=provider,
        provider_capability_id="capability/capability/alpha",
        counterparty=counterparty,
        corridor=corridor,
        limit=limit if limit is not None else usd(1_000_00),
        utilization_from=utilization_from,
        utilization_until=utilization_until,
        collateral_refs=collateral_refs,
        require_collateral=require_collateral,
        environment_id=ENV,
        domain_id=DOMAIN,
        provenance=prov(),
    )


def exposure_fixture(
    exposure_id: str = "liquidity/exposure/gamma",
    counterparty: str = "principal/cpty-7",
    limit: Amount | None = None,
    corridor: Corridor = CORRIDOR_USD_EUR,
    valid_from: str = EXP_FROM,
    valid_until: str = EXP_UNTIL,
) -> CreditExposure:
    return create_credit_exposure(
        exposure_id=exposure_id,
        counterparty=counterparty,
        corridor=corridor,
        limit=limit if limit is not None else usd(1_000_00),
        valid_from=valid_from,
        valid_until=valid_until,
        environment_id=ENV,
        domain_id=DOMAIN,
        provenance=prov(),
    )


# ---------------------------------------------------------------------------
# 1. Static boundary contracts.
# ---------------------------------------------------------------------------


class StaticContractTests(unittest.TestCase):
    """The typed, versioned public boundary of the liquidity domain."""

    def test_protocol_and_schema_versions_are_frozen(self) -> None:
        self.assertEqual(LIQUIDITY_PROTOCOL_VERSION, "v0.1")
        self.assertEqual(LIQUIDITY_SCHEMA_VERSION, 1)

    def test_object_types_are_internal_non_registry_formats(self) -> None:
        # The frozen protocol registry lists no liquidity object types, so —
        # per the sibling convention — every liquidity object type uses an
        # internal non-registry "liquidity/..." format and never invents a
        # "payswap/..." registry name.
        for object_type in (
            LIQUIDITY_OFFER_OBJECT_TYPE,
            CREDIT_OFFER_OBJECT_TYPE,
            CREDIT_EXPOSURE_OBJECT_TYPE,
        ):
            self.assertTrue(object_type.startswith("liquidity/"), object_type)
            self.assertFalse(object_type.startswith("payswap/"), object_type)
            self.assertTrue(object_type.endswith("/v1"), object_type)

    def test_state_vocabularies_are_closed(self) -> None:
        self.assertEqual(
            {state.value for state in LiquidityOfferState},
            {"ACTIVE", "SUSPENDED", "WITHDRAWN", "EXPIRED"},
        )
        self.assertEqual(
            {state.value for state in CreditOfferState},
            {"ACTIVE", "SUSPENDED", "WITHDRAWN", "EXPIRED", "DEFAULTED"},
        )
        self.assertEqual(
            {state.value for state in CreditExposureState},
            {"ACTIVE", "SUSPENDED", "WITHDRAWN", "EXPIRED"},
        )
        self.assertEqual(
            {status.value for status in ExposureStatus},
            {"OK", "BREACH"},
        )
        self.assertEqual(
            {kind.value for kind in ConcentrationControlKind},
            {"PROVIDER", "CORRIDOR", "COUNTERPARTY"},
        )

    def test_terminal_states_are_terminal(self) -> None:
        # Terminal lifecycle states never admit a follow-on command.
        for state in (LiquidityOfferState.WITHDRAWN, LiquidityOfferState.EXPIRED):
            with self.assertRaises(CoreValidationError):
                suspend_liquidity_offer(_offer_in_state(state), provenance=prov())
        for state in (
            CreditOfferState.WITHDRAWN,
            CreditOfferState.EXPIRED,
            CreditOfferState.DEFAULTED,
        ):
            with self.assertRaises(CoreValidationError):
                suspend_credit_offer(_credit_in_state(state), provenance=prov())

    def test_concentration_caps_are_explicit_and_sane(self) -> None:
        self.assertEqual(CONCENTRATION_DENOMINATOR_BPS, 10000)
        for cap in (
            MAX_PROVIDER_CONCENTRATION_BPS,
            MAX_CORRIDOR_CONCENTRATION_BPS,
            MAX_COUNTERPARTY_CONCENTRATION_BPS,
        ):
            self.assertIsInstance(cap, int)
            self.assertGreaterEqual(cap, 1)
            self.assertLess(cap, CONCENTRATION_DENOMINATOR_BPS)

    def test_domain_imports_only_allowed_roots(self) -> None:
        # Import audit: every import in every domain module must resolve to
        # the Python standard library or to an explicitly allowed sibling
        # authority (src.core, src.money, src.value, src.capability) or be a
        # relative import inside this package. Everything else is forbidden.
        allowed_roots = {"src.core", "src.money", "src.value", "src.capability"}
        package = Path(__file__).parent
        for source in sorted(package.glob("*.py")):
            if source.name == "test_liquidity.py":
                continue
            tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        root = alias.name.split(".", 1)[0]
                        if root == "src":
                            prefix = ".".join(alias.name.split(".")[:2])
                            self.assertIn(
                                prefix, allowed_roots,
                                f"{source.name} imports forbidden module {alias.name}",
                            )
                        else:
                            self.assertIn(
                                root, sys.stdlib_module_names,
                                f"{source.name} imports forbidden module {alias.name}",
                            )
                elif isinstance(node, ast.ImportFrom):
                    if node.level >= 1:
                        continue  # relative import inside the liquidity package
                    module = node.module or ""
                    root = module.split(".", 1)[0]
                    if root == "__future__":
                        continue
                    if root == "src":
                        prefix = ".".join(module.split(".")[:2])
                        self.assertIn(
                            prefix, allowed_roots,
                            f"{source.name} imports from forbidden module {module}",
                        )
                    else:
                        self.assertIn(
                            root, sys.stdlib_module_names,
                            f"{source.name} imports from forbidden module {module}",
                        )

    def test_domain_never_imports_unmerged_or_forbidden_siblings(self) -> None:
        package = Path(__file__).parent
        for source in sorted(package.glob("*.py")):
            if source.name == "test_liquidity.py":
                continue
            text = source.read_text(encoding="utf-8")
            for forbidden in (
                "src.transition", "src.trust", "src.intent", "src.market",
                "src.interoperability", "src.reservation", "src.safety",
                "src.evidence",
            ):
                self.assertNotIn(forbidden, text, f"{source.name} references {forbidden}")

    def test_domain_code_has_no_wall_clock_randomness_or_uuids(self) -> None:
        package = Path(__file__).parent
        for source in sorted(package.glob("*.py")):
            if source.name == "test_liquidity.py":
                continue
            text = source.read_text(encoding="utf-8")
            for forbidden in (
                "time.time", "datetime.now", "utcnow", "time.monotonic",
                "random", "uuid",
            ):
                self.assertNotIn(forbidden, text, f"{source.name} references {forbidden}")

    def test_exposure_is_a_control_not_an_accounting_authority(self) -> None:
        # The exposure model must never reach into the value ledger: the
        # liquidity domain holds no reference to ledger, hold, posting or
        # journal machinery (textual complement to the AST import audit).
        package = Path(__file__).parent
        for source in sorted(package.glob("*.py")):
            if source.name == "test_liquidity.py":
                continue
            text = source.read_text(encoding="utf-8")
            for forbidden in ("ValueLedger", "hold_create", "posting_class", "Journal("):
                self.assertNotIn(forbidden, text, f"{source.name} references {forbidden}")


def _offer_in_state(state: LiquidityOfferState) -> LiquidityOffer:
    offer = offer_fixture()
    if state is LiquidityOfferState.SUSPENDED:
        return suspend_liquidity_offer(offer, provenance=prov())
    if state is LiquidityOfferState.WITHDRAWN:
        return withdraw_liquidity_offer(offer, provenance=prov())
    if state is LiquidityOfferState.EXPIRED:
        return expire_liquidity_offer(offer, as_of=LIQ_UNTIL, provenance=prov())
    return offer


def _credit_in_state(state: CreditOfferState) -> CreditOffer:
    credit = credit_fixture()
    if state is CreditOfferState.SUSPENDED:
        return suspend_credit_offer(credit, provenance=prov())
    if state is CreditOfferState.WITHDRAWN:
        return withdraw_credit_offer(credit, provenance=prov())
    if state is CreditOfferState.EXPIRED:
        return expire_credit_offer(credit, as_of=AFTER_CRED, provenance=prov())
    if state is CreditOfferState.DEFAULTED:
        drawn = draw_credit(credit, usd(100_00), as_of=WITHIN, provenance=prov())
        return default_credit(drawn, as_of=LATER, provenance=prov())
    return credit


# ---------------------------------------------------------------------------
# 2. Corridor semantics.
# ---------------------------------------------------------------------------


class CorridorTests(unittest.TestCase):
    """Corridors reference source/target assets as opaque identifiers."""

    def test_corridor_builds_and_derives_its_canonical_id(self) -> None:
        self.assertEqual(CORRIDOR_USD_EUR.source_asset, ASSET_USD)
        self.assertEqual(CORRIDOR_USD_EUR.target_asset, ASSET_EUR)
        self.assertEqual(CORRIDOR_USD_EUR.corridor_id, "asset/USD->asset/EUR")

    def test_corridor_rejects_non_identifier_assets(self) -> None:
        for bad in ("", "not an asset!", " asset/USD", "asset/ USD"):
            with self.assertRaises(CoreValidationError):
                Corridor(bad, ASSET_EUR)
            with self.assertRaises(CoreValidationError):
                Corridor(ASSET_USD, bad)

    def test_corridor_serialization_round_trip(self) -> None:
        encoded = CORRIDOR_EUR_USD.to_dict()
        self.assertEqual(
            encoded, {"source_asset": ASSET_EUR, "target_asset": ASSET_USD}
        )
        decoded = Corridor.from_dict(encoded)
        self.assertEqual(decoded, CORRIDOR_EUR_USD)

    def test_corridor_deserialization_fails_closed_on_extra_fields(self) -> None:
        with self.assertRaises(CoreValidationError):
            Corridor.from_dict(
                {"source_asset": ASSET_USD, "target_asset": ASSET_EUR, "via": "x"}
            )


# ---------------------------------------------------------------------------
# 3. Liquidity offers.
# ---------------------------------------------------------------------------


class LiquidityOfferTests(unittest.TestCase):
    """LiquidityOffer records: bounded capacity, window, lifecycle."""

    def test_create_builds_a_sealed_active_version_one_record(self) -> None:
        offer = offer_fixture()
        self.assertEqual(offer.state, LiquidityOfferState.ACTIVE)
        self.assertEqual(offer.envelope.object_version, 1)
        self.assertIsNone(offer.envelope.previous_version)
        self.assertEqual(offer.envelope.object_id, "liquidity/offer/alpha")
        self.assertEqual(offer.envelope.object_type, LIQUIDITY_OFFER_OBJECT_TYPE)
        self.assertEqual(offer.spec.provider, "provider/alpha")
        self.assertEqual(offer.spec.provider_capability_id, "capability/capability/alpha")
        self.assertEqual(offer.spec.beneficiary, "principal/beneficiary-7")
        self.assertEqual(offer.spec.corridor, CORRIDOR_USD_EUR)
        self.assertEqual(offer.spec.capacity, usd(1_000_00))
        offer.envelope.verify_integrity()

    def test_create_requires_a_provider_capability_reference(self) -> None:
        # Liquidity is a bounded capability model: an offer without an
        # explicit provider capability reference fails closed.
        with self.assertRaises(CoreValidationError):
            create_liquidity_offer(
                offer_id="liquidity/offer/alpha",
                provider="provider/alpha",
                provider_capability_id="",
                beneficiary=None,
                corridor=CORRIDOR_USD_EUR,
                capacity=usd(1_000_00),
                available_from=LIQ_FROM,
                available_until=LIQ_UNTIL,
                environment_id=ENV,
                domain_id=DOMAIN,
                provenance=prov(),
            )

    def test_create_rejects_non_positive_capacity(self) -> None:
        for bad in (0, -1):
            with self.assertRaises(CoreValidationError):
                offer_fixture(capacity=usd(bad))

    def test_create_rejects_capacity_denominated_in_the_wrong_asset(self) -> None:
        # The capacity must be denominated in the corridor source asset.
        with self.assertRaises(CoreValidationError):
            offer_fixture(corridor=CORRIDOR_EUR_USD, capacity=usd(1_000_00))

    def test_create_rejects_empty_and_degenerate_windows(self) -> None:
        with self.assertRaises(CoreValidationError):
            offer_fixture(available_until=LIQ_FROM)
        with self.assertRaises(CoreValidationError):
            offer_fixture(available_from=LIQ_UNTIL)

    def test_create_rejects_non_utc_timestamps(self) -> None:
        with self.assertRaises(CoreValidationError):
            offer_fixture(available_from="2026-09-03T00:00:00+01:00")
        with self.assertRaises(CoreValidationError):
            offer_fixture(available_until="2026-09-03 12:00:00")

    def test_beneficiary_is_optional_but_must_be_canonical_when_present(self) -> None:
        offer = create_liquidity_offer(
            offer_id="liquidity/offer/open",
            provider="provider/alpha",
            provider_capability_id="capability/capability/alpha",
            beneficiary=None,
            corridor=CORRIDOR_USD_EUR,
            capacity=usd(500_00),
            available_from=LIQ_FROM,
            available_until=LIQ_UNTIL,
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=prov(),
        )
        self.assertIsNone(offer.spec.beneficiary)
        with self.assertRaises(CoreValidationError):
            create_liquidity_offer(
                offer_id="liquidity/offer/open",
                provider="provider/alpha",
                provider_capability_id="capability/capability/alpha",
                beneficiary="   ",
                corridor=CORRIDOR_USD_EUR,
                capacity=usd(500_00),
                available_from=LIQ_FROM,
                available_until=LIQ_UNTIL,
                environment_id=ENV,
                domain_id=DOMAIN,
                provenance=prov(),
            )

    def test_amend_updates_capacity_and_window_as_a_new_version(self) -> None:
        offer = offer_fixture()
        amended = amend_liquidity_offer(
            offer, provenance=prov(), capacity=usd(750_00),
            available_until="2026-09-03T18:00:00Z",
        )
        self.assertEqual(amended.state, LiquidityOfferState.ACTIVE)
        self.assertEqual(amended.envelope.object_version, 2)
        self.assertEqual(amended.envelope.previous_version, 1)
        self.assertEqual(amended.spec.capacity, usd(750_00))
        self.assertEqual(amended.spec.available_until, "2026-09-03T18:00:00Z")
        self.assertEqual(amended.object_id, offer.object_id)
        self.assertEqual(amended.envelope.object_type, offer.envelope.object_type)

    def test_amend_requires_at_least_one_change(self) -> None:
        with self.assertRaises(CoreValidationError):
            amend_liquidity_offer(offer_fixture(), provenance=prov())

    def test_amend_revalidates_the_whole_spec(self) -> None:
        with self.assertRaises(CoreValidationError):
            amend_liquidity_offer(offer_fixture(), provenance=prov(), capacity=usd(0))
        with self.assertRaises(CoreValidationError):
            amend_liquidity_offer(
                offer_fixture(), provenance=prov(), available_until=LIQ_FROM
            )

    def test_amend_is_only_legal_while_active(self) -> None:
        suspended = suspend_liquidity_offer(offer_fixture(), provenance=prov())
        with self.assertRaises(CoreValidationError):
            amend_liquidity_offer(suspended, provenance=prov(), capacity=usd(10_00))

    def test_suspend_and_resume_round_trip(self) -> None:
        offer = offer_fixture()
        suspended = suspend_liquidity_offer(offer, provenance=prov())
        self.assertEqual(suspended.state, LiquidityOfferState.SUSPENDED)
        self.assertEqual(suspended.envelope.object_version, 2)
        resumed = resume_liquidity_offer(suspended, provenance=prov())
        self.assertEqual(resumed.state, LiquidityOfferState.ACTIVE)
        self.assertEqual(resumed.envelope.object_version, 3)
        self.assertEqual(resumed.spec, offer.spec)

    def test_suspend_requires_active_and_resume_requires_suspended(self) -> None:
        suspended = suspend_liquidity_offer(offer_fixture(), provenance=prov())
        with self.assertRaises(CoreValidationError):
            suspend_liquidity_offer(suspended, provenance=prov())
        with self.assertRaises(CoreValidationError):
            resume_liquidity_offer(offer_fixture(), provenance=prov())

    def test_withdraw_closes_an_active_or_suspended_offer(self) -> None:
        for source in (
            offer_fixture(),
            suspend_liquidity_offer(offer_fixture(), provenance=prov()),
        ):
            withdrawn = withdraw_liquidity_offer(source, provenance=prov())
            self.assertEqual(withdrawn.state, LiquidityOfferState.WITHDRAWN)
            with self.assertRaises(CoreValidationError):
                withdraw_liquidity_offer(withdrawn, provenance=prov())

    def test_expire_requires_as_of_at_or_after_the_window_end(self) -> None:
        offer = offer_fixture()
        with self.assertRaises(CoreValidationError):
            expire_liquidity_offer(offer, as_of="2026-09-03T11:59:59Z", provenance=prov())
        expired = expire_liquidity_offer(offer, as_of=LIQ_UNTIL, provenance=prov())
        self.assertEqual(expired.state, LiquidityOfferState.EXPIRED)
        with self.assertRaises(CoreValidationError):
            resume_liquidity_offer(expired, provenance=prov())

    def test_availability_window_is_half_open(self) -> None:
        offer = offer_fixture()
        self.assertFalse(liquidity_offer_available_at(offer, "2026-09-02T23:59:59Z"))
        self.assertTrue(liquidity_offer_available_at(offer, LIQ_FROM))
        self.assertTrue(liquidity_offer_available_at(offer, "2026-09-03T06:00:00Z"))
        self.assertFalse(liquidity_offer_available_at(offer, LIQ_UNTIL))

    def test_availability_requires_the_active_state(self) -> None:
        suspended = suspend_liquidity_offer(offer_fixture(), provenance=prov())
        self.assertFalse(liquidity_offer_available_at(suspended, WITHIN))
        withdrawn = withdraw_liquidity_offer(offer_fixture(), provenance=prov())
        self.assertFalse(liquidity_offer_available_at(withdrawn, WITHIN))

    def test_spec_rejects_direct_construction_violations(self) -> None:
        base = dict(
            provider="provider/alpha",
            provider_capability_id="capability/capability/alpha",
            beneficiary=None,
            corridor=CORRIDOR_USD_EUR,
            capacity=usd(1_000_00),
            available_from=LIQ_FROM,
            available_until=LIQ_UNTIL,
        )
        with self.assertRaises(CoreValidationError):
            LiquidityOfferSpec(**{**base, "capacity": usd(0)})
        with self.assertRaises(CoreValidationError):
            LiquidityOfferSpec(**{**base, "corridor": Corridor("bad asset", ASSET_EUR)})
        with self.assertRaises(CoreValidationError):
            LiquidityOfferSpec(**{**base, "provider": ""})


# ---------------------------------------------------------------------------
# 4. Liquidity offer sealing and serialization.
# ---------------------------------------------------------------------------


class LiquidityOfferSealTests(unittest.TestCase):
    """Composite sealing: tampered or spliced offers fail closed."""

    def test_round_trip_through_dict_and_json(self) -> None:
        offer = offer_fixture()
        decoded = LiquidityOffer.from_dict(offer.to_dict())
        self.assertEqual(decoded.to_dict(), offer.to_dict())
        decoded_json = LiquidityOffer.from_json(offer.to_json())
        self.assertEqual(decoded_json.to_json(), offer.to_json())

    def test_version_chain_round_trips_and_preserves_identity(self) -> None:
        offer = resume_liquidity_offer(
            suspend_liquidity_offer(offer_fixture(), provenance=prov()),
            provenance=prov(),
        )
        self.assertEqual(offer.envelope.object_version, 3)
        decoded = LiquidityOffer.from_json(offer.to_json())
        self.assertEqual(decoded.envelope.object_version, 3)
        self.assertEqual(decoded.envelope.previous_version, 2)
        self.assertEqual(decoded.object_id, offer.object_id)

    def test_tampered_payload_is_rejected(self) -> None:
        offer = offer_fixture()
        decoded = dict(offer.to_dict())
        decoded["payload"]["capacity"]["value"] = 999_00
        with self.assertRaises(CoreValidationError):
            LiquidityOffer.from_dict(decoded)

    def test_tampered_state_is_rejected(self) -> None:
        offer = offer_fixture()
        decoded = dict(offer.to_dict())
        decoded["envelope"]["state"] = "SUSPENDED"
        with self.assertRaises(CoreValidationError):
            LiquidityOffer.from_dict(decoded)

    def test_tampered_integrity_hash_is_rejected(self) -> None:
        offer = offer_fixture()
        decoded = dict(offer.to_dict())
        decoded["integrity_hash"] = "0" * 64
        with self.assertRaises(CoreValidationError):
            LiquidityOffer.from_dict(decoded)

    def test_missing_integrity_hash_fails_closed(self) -> None:
        offer = offer_fixture()
        decoded = dict(offer.to_dict())
        del decoded["integrity_hash"]
        with self.assertRaises(CoreValidationError):
            LiquidityOffer.from_dict(decoded)

    def test_unknown_state_fails_closed_on_decode(self) -> None:
        offer = offer_fixture()
        decoded = dict(offer.to_dict())
        decoded["envelope"]["state"] = "PAUSED"
        with self.assertRaises(CoreValidationError):
            LiquidityOffer.from_dict(decoded)

    def test_non_canonical_payload_fields_fail_closed(self) -> None:
        offer = offer_fixture()
        decoded = dict(offer.to_dict())
        decoded["payload"]["extra"] = 1
        with self.assertRaises(CoreValidationError):
            LiquidityOffer.from_dict(decoded)

    def test_json_decode_rejects_duplicate_keys(self) -> None:
        offer = offer_fixture()
        text = offer.to_json()
        duplicated = text.replace(
            '"available_from":', '"available_from":1,"available_from":', 1
        )
        with self.assertRaises(CoreValidationError):
            LiquidityOffer.from_json(duplicated)

    def test_domain_seal_differs_across_different_payloads(self) -> None:
        offer = offer_fixture()
        other = offer_fixture(capacity=usd(1_001_00))
        self.assertNotEqual(offer.integrity_hash, other.integrity_hash)


# ---------------------------------------------------------------------------
# 5. Credit offers (facilities): Create/Amend/Suspend/Resume/Withdraw/Expire.
# ---------------------------------------------------------------------------


class CreditOfferTests(unittest.TestCase):
    """CreditOffer facilities: bounded limit, utilization window, collateral."""

    def test_create_builds_an_active_facility_with_zero_utilization(self) -> None:
        credit = credit_fixture()
        self.assertEqual(credit.state, CreditOfferState.ACTIVE)
        self.assertEqual(credit.envelope.object_version, 1)
        self.assertEqual(credit.envelope.object_type, CREDIT_OFFER_OBJECT_TYPE)
        self.assertEqual(credit.spec.counterparty, "principal/cpty-7")
        self.assertEqual(credit.spec.limit, usd(1_000_00))
        self.assertTrue(credit.spec.utilized.is_zero())
        self.assertEqual(credit_available_capacity(credit), usd(1_000_00))
        self.assertEqual(credit.spec.corridor, CORRIDOR_USD_EUR)
        credit.envelope.verify_integrity()

    def test_create_rejects_non_positive_limits(self) -> None:
        for bad in (0, -5):
            with self.assertRaises(CoreValidationError):
                credit_fixture(limit=usd(bad))

    def test_create_rejects_limit_denominated_in_the_wrong_asset(self) -> None:
        with self.assertRaises(CoreValidationError):
            credit_fixture(corridor=CORRIDOR_EUR_USD, limit=usd(1_000_00))

    def test_create_rejects_degenerate_windows(self) -> None:
        with self.assertRaises(CoreValidationError):
            credit_fixture(utilization_until=CRED_FROM)

    def test_spec_enforces_the_utilized_le_limit_invariant(self) -> None:
        with self.assertRaises(CoreValidationError):
            CreditOfferSpec(
                provider="provider/alpha",
                provider_capability_id="capability/capability/alpha",
                counterparty="principal/cpty-7",
                corridor=CORRIDOR_USD_EUR,
                limit=usd(100_00),
                utilized=usd(101_00),
                utilization_from=CRED_FROM,
                utilization_until=CRED_UNTIL,
                collateral_refs=(),
                require_collateral=False,
            )

    def test_collateral_references_are_opaque_unique_identifiers(self) -> None:
        credit = credit_fixture(
            collateral_refs=("value/hold/coll-1", "value/hold/coll-2")
        )
        self.assertEqual(
            credit.spec.collateral_refs, ("value/hold/coll-1", "value/hold/coll-2")
        )
        with self.assertRaises(CoreValidationError):
            credit_fixture(collateral_refs=("value/hold/coll-1", "value/hold/coll-1"))
        with self.assertRaises(CoreValidationError):
            credit_fixture(collateral_refs=("not a ref!",))

    def test_amend_only_legal_with_zero_utilization(self) -> None:
        credit = credit_fixture()
        drawn = draw_credit(credit, usd(100_00), as_of=WITHIN, provenance=prov())
        with self.assertRaises(CoreValidationError):
            amend_credit_offer(drawn, provenance=prov(), limit=usd(2_000_00))
        clean = amend_credit_offer(credit, provenance=prov(), limit=usd(2_000_00))
        self.assertEqual(clean.spec.limit, usd(2_000_00))
        self.assertEqual(clean.envelope.object_version, 2)
        self.assertEqual(clean.state, CreditOfferState.ACTIVE)

    def test_amend_requires_a_change_and_revalidates(self) -> None:
        with self.assertRaises(CoreValidationError):
            amend_credit_offer(credit_fixture(), provenance=prov())
        with self.assertRaises(CoreValidationError):
            amend_credit_offer(credit_fixture(), provenance=prov(), limit=usd(0))

    def test_amend_cannot_cut_the_limit_below_utilization(self) -> None:
        drawn = draw_credit(credit_fixture(), usd(100_00), as_of=WITHIN, provenance=prov())
        repaid = repay_credit(drawn, usd(100_00), as_of=LATER, provenance=prov())
        # utilization is zero again; a lower limit is legal for a clean amend
        clean = amend_credit_offer(repaid, provenance=prov(), limit=usd(50_00))
        self.assertEqual(clean.spec.limit, usd(50_00))

    def test_suspend_resume_and_withdraw_lifecycle(self) -> None:
        credit = credit_fixture()
        suspended = suspend_credit_offer(credit, provenance=prov())
        self.assertEqual(suspended.state, CreditOfferState.SUSPENDED)
        resumed = resume_credit_offer(suspended, provenance=prov())
        self.assertEqual(resumed.state, CreditOfferState.ACTIVE)
        withdrawn = withdraw_credit_offer(resumed, provenance=prov())
        self.assertEqual(withdrawn.state, CreditOfferState.WITHDRAWN)
        with self.assertRaises(CoreValidationError):
            resume_credit_offer(withdrawn, provenance=prov())

    def test_withdraw_requires_zero_outstanding(self) -> None:
        drawn = draw_credit(credit_fixture(), usd(100_00), as_of=WITHIN, provenance=prov())
        with self.assertRaises(CoreValidationError):
            withdraw_credit_offer(drawn, provenance=prov())
        repaid = repay_credit(drawn, usd(100_00), as_of=LATER, provenance=prov())
        closed = withdraw_credit_offer(repaid, provenance=prov())
        self.assertEqual(closed.state, CreditOfferState.WITHDRAWN)

    def test_expire_requires_window_elapsed_and_zero_outstanding(self) -> None:
        credit = credit_fixture()
        with self.assertRaises(CoreValidationError):
            expire_credit_offer(credit, as_of="2026-09-09T23:59:59Z", provenance=prov())
        drawn = draw_credit(credit, usd(100_00), as_of=WITHIN, provenance=prov())
        with self.assertRaises(CoreValidationError):
            expire_credit_offer(drawn, as_of=AFTER_CRED, provenance=prov())
        repaid = repay_credit(drawn, usd(100_00), as_of=LATER, provenance=prov())
        expired = expire_credit_offer(repaid, as_of=AFTER_CRED, provenance=prov())
        self.assertEqual(expired.state, CreditOfferState.EXPIRED)


# ---------------------------------------------------------------------------
# 6. Credit offers: Draw / Repay / Restructure / Default.
# ---------------------------------------------------------------------------


class CreditUtilizationTests(unittest.TestCase):
    """Draw, Repay, Restructure and Default on credit facilities."""

    def test_draw_within_window_and_limit_succeeds(self) -> None:
        credit = credit_fixture()
        drawn = draw_credit(credit, usd(400_00), as_of=CRED_FROM, provenance=prov())
        self.assertEqual(drawn.spec.utilized, usd(400_00))
        self.assertEqual(drawn.state, CreditOfferState.ACTIVE)
        self.assertEqual(drawn.envelope.object_version, 2)
        self.assertEqual(credit_available_capacity(drawn), usd(600_00))

    def test_utilization_window_is_half_open(self) -> None:
        credit = credit_fixture()
        with self.assertRaises(CoreValidationError):
            draw_credit(credit, usd(10_00), as_of="2026-09-02T23:59:59Z", provenance=prov())
        with self.assertRaises(CoreValidationError):
            draw_credit(credit, usd(10_00), as_of=CRED_UNTIL, provenance=prov())

    def test_draw_fails_closed_beyond_the_facility_limit(self) -> None:
        credit = credit_fixture(limit=usd(500_00))
        with self.assertRaises(CoreValidationError):
            draw_credit(credit, usd(501_00), as_of=WITHIN, provenance=prov())
        drawn = draw_credit(credit, usd(500_00), as_of=WITHIN, provenance=prov())
        with self.assertRaises(CoreValidationError):
            draw_credit(drawn, usd(1_00), as_of=WITHIN, provenance=prov())

    def test_draw_rejects_degenerate_amounts_and_wrong_currency(self) -> None:
        credit = credit_fixture()
        for bad in (usd(0), usd(-10)):
            with self.assertRaises(CoreValidationError):
                draw_credit(credit, bad, as_of=WITHIN, provenance=prov())
        with self.assertRaises(CoreValidationError):
            draw_credit(credit, eur(10_00), as_of=WITHIN, provenance=prov())

    def test_draw_requires_the_active_state(self) -> None:
        suspended = suspend_credit_offer(credit_fixture(), provenance=prov())
        with self.assertRaises(CoreValidationError):
            draw_credit(suspended, usd(10_00), as_of=WITHIN, provenance=prov())

    def test_draw_enforces_the_collateral_requirement_control(self) -> None:
        credit = credit_fixture(require_collateral=True)
        with self.assertRaises(CoreValidationError):
            draw_credit(credit, usd(10_00), as_of=WITHIN, provenance=prov())
        secured = credit_fixture(
            require_collateral=True, collateral_refs=("value/hold/coll-1",)
        )
        drawn = draw_credit(secured, usd(10_00), as_of=WITHIN, provenance=prov())
        self.assertEqual(drawn.spec.utilized, usd(10_00))

    def test_repay_reduces_utilization_and_cannot_over_repay(self) -> None:
        credit = credit_fixture()
        drawn = draw_credit(credit, usd(400_00), as_of=WITHIN, provenance=prov())
        repaid = repay_credit(drawn, usd(150_00), as_of=LATER, provenance=prov())
        self.assertEqual(repaid.spec.utilized, usd(250_00))
        self.assertEqual(repaid.envelope.object_version, 3)
        with self.assertRaises(CoreValidationError):
            repay_credit(repaid, usd(251_00), as_of=LATER, provenance=prov())
        cleared = repay_credit(repaid, usd(250_00), as_of=LATER, provenance=prov())
        self.assertTrue(cleared.spec.utilized.is_zero())

    def test_repay_rejects_degenerate_amounts_and_wrong_currency(self) -> None:
        drawn = draw_credit(credit_fixture(), usd(100_00), as_of=WITHIN, provenance=prov())
        for bad in (usd(0), usd(-1)):
            with self.assertRaises(CoreValidationError):
                repay_credit(drawn, bad, as_of=LATER, provenance=prov())
        with self.assertRaises(CoreValidationError):
            repay_credit(drawn, eur(1_00), as_of=LATER, provenance=prov())

    def test_repay_cannot_precede_the_utilization_window(self) -> None:
        credit = credit_fixture()
        with self.assertRaises(CoreValidationError):
            repay_credit(credit, usd(1_00), as_of="2026-09-02T23:00:00Z", provenance=prov())

    def test_repay_requires_the_active_state(self) -> None:
        drawn = draw_credit(credit_fixture(), usd(100_00), as_of=WITHIN, provenance=prov())
        suspended = suspend_credit_offer(drawn, provenance=prov())
        with self.assertRaises(CoreValidationError):
            repay_credit(suspended, usd(10_00), as_of=LATER, provenance=prov())

    def test_repay_is_legal_after_the_utilization_window_closes(self) -> None:
        # Repaying outstanding after the draw window has elapsed is the
        # normal servicing path (only drawing is window-bound).
        credit = credit_fixture()
        drawn = draw_credit(credit, usd(100_00), as_of=WITHIN, provenance=prov())
        repaid = repay_credit(drawn, usd(100_00), as_of=AFTER_CRED, provenance=prov())
        self.assertTrue(repaid.spec.utilized.is_zero())

    def test_restructure_amends_terms_with_outstanding_exposure(self) -> None:
        credit = credit_fixture()
        drawn = draw_credit(credit, usd(400_00), as_of=WITHIN, provenance=prov())
        restructured = restructure_credit(
            drawn,
            provenance=prov(),
            limit=usd(1_500_00),
            utilization_until="2026-09-20T00:00:00Z",
            collateral_refs=("value/hold/coll-9",),
        )
        self.assertEqual(restructured.spec.limit, usd(1_500_00))
        self.assertEqual(restructured.spec.utilized, usd(400_00))
        self.assertEqual(restructured.spec.utilization_until, "2026-09-20T00:00:00Z")
        self.assertEqual(restructured.spec.collateral_refs, ("value/hold/coll-9",))
        self.assertEqual(restructured.state, CreditOfferState.ACTIVE)
        self.assertEqual(restructured.envelope.object_version, 3)

    def test_restructure_cannot_cut_the_limit_below_outstanding(self) -> None:
        drawn = draw_credit(credit_fixture(), usd(400_00), as_of=WITHIN, provenance=prov())
        with self.assertRaises(CoreValidationError):
            restructure_credit(drawn, provenance=prov(), limit=usd(399_00))

    def test_restructure_requires_a_change(self) -> None:
        with self.assertRaises(CoreValidationError):
            restructure_credit(credit_fixture(), provenance=prov())

    def test_restructure_requires_the_active_state(self) -> None:
        drawn = draw_credit(credit_fixture(), usd(100_00), as_of=WITHIN, provenance=prov())
        defaulted = default_credit(drawn, as_of=LATER, provenance=prov())
        with self.assertRaises(CoreValidationError):
            restructure_credit(defaulted, provenance=prov(), limit=usd(2_000_00))

    def test_default_requires_outstanding_exposure_and_is_terminal(self) -> None:
        credit = credit_fixture()
        with self.assertRaises(CoreValidationError):
            default_credit(credit, as_of=LATER, provenance=prov())
        drawn = draw_credit(credit, usd(400_00), as_of=WITHIN, provenance=prov())
        defaulted = default_credit(drawn, as_of=LATER, provenance=prov())
        self.assertEqual(defaulted.state, CreditOfferState.DEFAULTED)
        self.assertEqual(defaulted.spec.utilized, usd(400_00))
        with self.assertRaises(CoreValidationError):
            draw_credit(defaulted, usd(1_00), as_of=WITHIN, provenance=prov())
        with self.assertRaises(CoreValidationError):
            repay_credit(defaulted, usd(1_00), as_of=LATER, provenance=prov())
        with self.assertRaises(CoreValidationError):
            suspend_credit_offer(defaulted, provenance=prov())
        with self.assertRaises(CoreValidationError):
            withdraw_credit_offer(defaulted, provenance=prov())

    def test_default_is_legal_from_suspension(self) -> None:
        drawn = draw_credit(credit_fixture(), usd(100_00), as_of=WITHIN, provenance=prov())
        suspended = suspend_credit_offer(drawn, provenance=prov())
        defaulted = default_credit(suspended, as_of=LATER, provenance=prov())
        self.assertEqual(defaulted.state, CreditOfferState.DEFAULTED)

    def test_utilized_amounts_serialize_canonically(self) -> None:
        drawn = draw_credit(credit_fixture(), usd(400_00), as_of=WITHIN, provenance=prov())
        decoded = CreditOffer.from_json(drawn.to_json())
        self.assertEqual(decoded.spec.utilized, usd(400_00))
        self.assertEqual(decoded.to_json(), drawn.to_json())


# ---------------------------------------------------------------------------
# 7. Credit offer sealing and serialization.
# ---------------------------------------------------------------------------


class CreditOfferSealTests(unittest.TestCase):
    """Composite sealing of credit facilities."""

    def test_round_trip_through_dict_and_json(self) -> None:
        credit = credit_fixture(collateral_refs=("value/hold/coll-1",))
        self.assertEqual(CreditOffer.from_dict(credit.to_dict()).to_dict(), credit.to_dict())
        self.assertEqual(CreditOffer.from_json(credit.to_json()).to_json(), credit.to_json())

    def test_tampered_collateral_reference_is_rejected(self) -> None:
        credit = credit_fixture(collateral_refs=("value/hold/coll-1",))
        decoded = dict(credit.to_dict())
        decoded["payload"]["collateral_refs"] = ["value/hold/coll-2"]
        with self.assertRaises(CoreValidationError):
            CreditOffer.from_dict(decoded)

    def test_tampered_limit_is_rejected(self) -> None:
        credit = credit_fixture()
        decoded = dict(credit.to_dict())
        decoded["payload"]["limit"]["value"] = 1_000_000_00
        with self.assertRaises(CoreValidationError):
            CreditOffer.from_dict(decoded)

    def test_object_type_mismatch_is_rejected(self) -> None:
        credit = credit_fixture()
        decoded = dict(credit.to_dict())
        decoded["envelope"]["object_type"] = "liquidity/offer/v1"
        with self.assertRaises(CoreValidationError):
            CreditOffer.from_dict(decoded)


# ---------------------------------------------------------------------------
# 8. Credit exposure control records.
# ---------------------------------------------------------------------------


class CreditExposureTests(unittest.TestCase):
    """CreditExposure: per-counterparty/per-corridor limit control records."""

    def test_create_builds_an_active_control_with_zero_utilization(self) -> None:
        exposure = exposure_fixture()
        self.assertEqual(exposure.state, CreditExposureState.ACTIVE)
        self.assertEqual(exposure.envelope.object_type, CREDIT_EXPOSURE_OBJECT_TYPE)
        self.assertEqual(exposure.spec.counterparty, "principal/cpty-7")
        self.assertEqual(exposure.spec.corridor, CORRIDOR_USD_EUR)
        self.assertEqual(exposure.spec.limit, usd(1_000_00))
        self.assertTrue(exposure.spec.utilized.is_zero())
        self.assertEqual(exposure_available_capacity(exposure), usd(1_000_00))
        exposure.envelope.verify_integrity()

    def test_create_rejects_degenerate_limits_and_windows(self) -> None:
        with self.assertRaises(CoreValidationError):
            exposure_fixture(limit=usd(0))
        with self.assertRaises(CoreValidationError):
            exposure_fixture(corridor=CORRIDOR_EUR_USD)
        with self.assertRaises(CoreValidationError):
            exposure_fixture(valid_until=EXP_FROM)

    def test_spec_enforces_the_utilized_le_limit_invariant(self) -> None:
        with self.assertRaises(CoreValidationError):
            CreditExposureSpec(
                counterparty="principal/cpty-7",
                corridor=CORRIDOR_USD_EUR,
                limit=usd(100_00),
                utilized=usd(100_01),
                valid_from=EXP_FROM,
                valid_until=EXP_UNTIL,
            )

    def test_draw_against_exposure_gates_on_limit_and_window(self) -> None:
        exposure = exposure_fixture(limit=usd(500_00))
        drawn = draw_against_exposure(exposure, usd(400_00), as_of=EXP_FROM, provenance=prov())
        self.assertEqual(drawn.spec.utilized, usd(400_00))
        self.assertEqual(drawn.envelope.object_version, 2)
        with self.assertRaises(CoreValidationError):
            draw_against_exposure(drawn, usd(101_00), as_of=WITHIN, provenance=prov())
        with self.assertRaises(CoreValidationError):
            draw_against_exposure(exposure, usd(10_00), as_of="2026-09-02T23:59:59Z", provenance=prov())
        with self.assertRaises(CoreValidationError):
            draw_against_exposure(exposure, usd(10_00), as_of=EXP_UNTIL, provenance=prov())

    def test_draw_against_exposure_rejects_degenerate_and_foreign_amounts(self) -> None:
        exposure = exposure_fixture()
        for bad in (usd(0), usd(-1), eur(5_00)):
            with self.assertRaises(CoreValidationError):
                draw_against_exposure(exposure, bad, as_of=WITHIN, provenance=prov())

    def test_draw_against_exposure_requires_active(self) -> None:
        suspended = suspend_credit_exposure(exposure_fixture(), provenance=prov())
        with self.assertRaises(CoreValidationError):
            draw_against_exposure(suspended, usd(10_00), as_of=WITHIN, provenance=prov())

    def test_repay_against_exposure_reduces_utilization(self) -> None:
        exposure = exposure_fixture()
        drawn = draw_against_exposure(exposure, usd(300_00), as_of=WITHIN, provenance=prov())
        repaid = repay_against_exposure(drawn, usd(100_00), as_of=LATER, provenance=prov())
        self.assertEqual(repaid.spec.utilized, usd(200_00))
        with self.assertRaises(CoreValidationError):
            repay_against_exposure(repaid, usd(201_00), as_of=LATER, provenance=prov())
        with self.assertRaises(CoreValidationError):
            repay_against_exposure(repaid, usd(1_00), as_of="2026-09-02T23:59:59Z", provenance=prov())

    def test_amend_limit_cannot_fall_below_recorded_utilization(self) -> None:
        exposure = exposure_fixture()
        drawn = draw_against_exposure(exposure, usd(300_00), as_of=WITHIN, provenance=prov())
        with self.assertRaises(CoreValidationError):
            amend_credit_exposure(drawn, provenance=prov(), limit=usd(299_00))
        amended = amend_credit_exposure(drawn, provenance=prov(), limit=usd(2_000_00))
        self.assertEqual(amended.spec.limit, usd(2_000_00))
        self.assertEqual(amended.envelope.object_version, 3)

    def test_exposure_lifecycle_commands(self) -> None:
        exposure = exposure_fixture()
        suspended = suspend_credit_exposure(exposure, provenance=prov())
        self.assertEqual(suspended.state, CreditExposureState.SUSPENDED)
        resumed = resume_credit_exposure(suspended, provenance=prov())
        self.assertEqual(resumed.state, CreditExposureState.ACTIVE)
        withdrawn = withdraw_credit_exposure(resumed, provenance=prov())
        self.assertEqual(withdrawn.state, CreditExposureState.WITHDRAWN)
        with self.assertRaises(CoreValidationError):
            resume_credit_exposure(withdrawn, provenance=prov())

    def test_withdraw_and_expire_require_zero_utilization(self) -> None:
        drawn = draw_against_exposure(exposure_fixture(), usd(10_00), as_of=WITHIN, provenance=prov())
        with self.assertRaises(CoreValidationError):
            withdraw_credit_exposure(drawn, provenance=prov())
        with self.assertRaises(CoreValidationError):
            expire_credit_exposure(drawn, as_of=AFTER_EXP, provenance=prov())
        repaid = repay_against_exposure(drawn, usd(10_00), as_of=LATER, provenance=prov())
        closed = withdraw_credit_exposure(repaid, provenance=prov())
        self.assertEqual(closed.state, CreditExposureState.WITHDRAWN)

    def test_expire_requires_as_of_at_or_after_valid_until(self) -> None:
        with self.assertRaises(CoreValidationError):
            expire_credit_exposure(exposure_fixture(), as_of="2026-09-29T23:59:59Z", provenance=prov())
        expired = expire_credit_exposure(exposure_fixture(), as_of=EXP_UNTIL, provenance=prov())
        self.assertEqual(expired.state, CreditExposureState.EXPIRED)

    def test_exposure_serialization_round_trip_and_tamper_rejection(self) -> None:
        exposure = exposure_fixture()
        self.assertEqual(
            CreditExposure.from_dict(exposure.to_dict()).to_dict(), exposure.to_dict()
        )
        self.assertEqual(
            CreditExposure.from_json(exposure.to_json()).to_json(), exposure.to_json()
        )
        decoded = dict(exposure.to_dict())
        decoded["payload"]["limit"]["value"] = 5_000_00
        with self.assertRaises(CoreValidationError):
            CreditExposure.from_dict(decoded)


# ---------------------------------------------------------------------------
# 9. Exposure aggregation, assessment and breach detection.
# ---------------------------------------------------------------------------


class ExposureAggregationTests(unittest.TestCase):
    """Deterministic per-counterparty/per-corridor utilization aggregation."""

    def _facilities(self) -> list[CreditOffer]:
        facilities = [
            credit_fixture(
                offer_id="liquidity/credit/a1",
                counterparty="principal/cpty-a",
                limit=usd(200_00),
            ),
            credit_fixture(
                offer_id="liquidity/credit/a2",
                provider="provider/beta",
                counterparty="principal/cpty-a",
                limit=usd(300_00),
            ),
            credit_fixture(
                offer_id="liquidity/credit/b1",
                counterparty="principal/cpty-b",
                corridor=CORRIDOR_EUR_USD,
                limit=eur(500_00),
            ),
        ]
        drawn = draw_credit(facilities[0], usd(150_00), as_of=WITHIN, provenance=prov())
        drawn2 = draw_credit(facilities[1], usd(200_00), as_of=WITHIN, provenance=prov())
        drawn3 = draw_credit(facilities[2], eur(400_00), as_of=WITHIN, provenance=prov())
        return [drawn, drawn2, drawn3]

    def test_aggregation_groups_by_counterparty_and_corridor(self) -> None:
        aggregates = aggregate_credit_utilization(self._facilities())
        self.assertEqual(len(aggregates), 2)
        by_key = {a.counterparty + "@" + a.corridor.corridor_id: a for a in aggregates}
        a_usd = by_key["principal/cpty-a@asset/USD->asset/EUR"]
        self.assertEqual(a_usd.facility_count, 2)
        self.assertEqual(a_usd.offered_limit, usd(500_00))
        self.assertEqual(a_usd.drawn, usd(350_00))
        b_eur = by_key["principal/cpty-b@asset/EUR->asset/USD"]
        self.assertEqual(b_eur.facility_count, 1)
        self.assertEqual(b_eur.drawn, eur(400_00))

    def test_aggregation_is_sorted_and_excludes_terminal_facilities(self) -> None:
        facilities = self._facilities()
        defaulted = default_credit(facilities[0], as_of=LATER, provenance=prov())
        aggregates = aggregate_credit_utilization(
            [defaulted, facilities[1], facilities[2]]
        )
        keys = [(a.counterparty, a.corridor.corridor_id) for a in aggregates]
        self.assertEqual(keys, sorted(keys))
        a_usd = [a for a in aggregates if a.counterparty == "principal/cpty-a"][0]
        self.assertEqual(a_usd.facility_count, 1)
        self.assertEqual(a_usd.drawn, usd(200_00))

    def test_aggregation_of_empty_input_is_empty(self) -> None:
        self.assertEqual(aggregate_credit_utilization([]), ())

    def test_aggregation_is_order_independent(self) -> None:
        facilities = self._facilities()
        forward = aggregate_credit_utilization(facilities)
        backward = aggregate_credit_utilization(list(reversed(facilities)))
        self.assertEqual([a.to_dict() for a in forward], [a.to_dict() for a in backward])

    def test_assessment_reports_a_breach_only_when_drawn_exceeds_the_limit(self) -> None:
        facilities = self._facilities()
        exposure = exposure_fixture(counterparty="principal/cpty-a", limit=usd(400_00))
        assessment = assess_exposure([exposure], facilities)
        # 350_00 drawn vs 400_00 limit: OK.
        self.assertEqual([c.status for c in assessment.checks], [ExposureStatus.OK])
        self.assertEqual(assessment.breaches, ())
        tight = exposure_fixture(
            exposure_id="liquidity/exposure/tight",
            counterparty="principal/cpty-a",
            limit=usd(300_00),
        )
        breached = assess_exposure([tight], facilities)
        self.assertEqual([c.status for c in breached.checks], [ExposureStatus.BREACH])
        self.assertEqual(len(breached.breaches), 1)
        self.assertEqual(breached.breaches[0].drawn, usd(350_00))
        self.assertEqual(breached.breaches[0].exposure_id, "liquidity/exposure/tight")

    def test_aggregate_breach_is_legitimate_even_when_each_facility_is_within_limit(self) -> None:
        # The realistic breach path: two facilities drawn fully within their
        # own limits whose aggregate exceeds the control-side exposure limit.
        facilities = [
            credit_fixture(
                offer_id="liquidity/credit/f1", limit=usd(250_00),
                counterparty="principal/cpty-a",
            ),
            credit_fixture(
                offer_id="liquidity/credit/f2", limit=usd(250_00),
                provider="provider/beta", counterparty="principal/cpty-a",
            ),
        ]
        facilities = [
            draw_credit(f, f.spec.limit, as_of=WITHIN, provenance=prov())
            for f in facilities
        ]
        exposure = exposure_fixture(counterparty="principal/cpty-a", limit=usd(400_00))
        assessment = assess_exposure([exposure], facilities)
        self.assertEqual(assessment.checks[0].status, ExposureStatus.BREACH)
        self.assertEqual(assessment.checks[0].drawn, usd(500_00))

    def test_assessment_covers_missing_counterparties_with_zero_drawn(self) -> None:
        exposure = exposure_fixture(counterparty="principal/cpty-zzz")
        assessment = assess_exposure([exposure], self._facilities())
        self.assertEqual(assessment.checks[0].drawn, usd(0))
        self.assertEqual(assessment.checks[0].status, ExposureStatus.OK)

    def test_assessment_digest_is_deterministic_and_order_independent(self) -> None:
        facilities = self._facilities()
        exposures = [
            exposure_fixture(counterparty="principal/cpty-a", limit=usd(300_00)),
            exposure_fixture(
                exposure_id="liquidity/exposure/b",
                counterparty="principal/cpty-b",
                corridor=CORRIDOR_EUR_USD,
                limit=eur(1_000_00),
            ),
        ]
        first = assess_exposure(exposures, facilities)
        second = assess_exposure(list(reversed(exposures)), list(reversed(facilities)))
        self.assertEqual(first.digest(), second.digest())
        self.assertNotEqual(first.digest(), "0" * 64)

    def test_empty_assessment_is_stable(self) -> None:
        assessment = assess_exposure([], [])
        self.assertEqual(assessment.aggregates, ())
        self.assertEqual(assessment.checks, ())
        self.assertEqual(assessment.breaches, ())
        self.assertEqual(assess_exposure([], []).digest(), assessment.digest())


# ---------------------------------------------------------------------------
# 10. Concentration controls.
# ---------------------------------------------------------------------------


class ConcentrationTests(unittest.TestCase):
    """Concentration caps with exact integer shares and deterministic order."""

    def _liquidity(
        self,
        capacities: dict[str, int],
        corridor: Corridor = CORRIDOR_USD_EUR,
    ) -> list[LiquidityOffer]:
        if corridor.source_asset == ASSET_EUR:
            amount = eur
        else:
            amount = usd
        offers = []
        for index, (provider, capacity) in enumerate(sorted(capacities.items())):
            offers.append(
                offer_fixture(
                    offer_id=f"liquidity/offer/c{index:03d}",
                    provider=provider,
                    capacity=amount(capacity),
                    corridor=corridor,
                )
            )
        return offers

    def test_provider_concentration_breach_is_flagged(self) -> None:
        offers = self._liquidity(
            {"provider/dominant": 9_000_00, "provider/small": 1_000_00}
        )
        report = evaluate_concentration(liquidity_offers=offers)
        provider_entries = [
            e for e in report.entries if e.kind is ConcentrationControlKind.PROVIDER
        ]
        self.assertEqual(len(provider_entries), 2)
        breaches = [
            e for e in report.breaches if e.kind is ConcentrationControlKind.PROVIDER
        ]
        self.assertEqual(len(breaches), 1)
        self.assertEqual(
            breaches[0].group, ("asset/USD->asset/EUR", "provider/dominant")
        )
        self.assertEqual(breaches[0].cap_bps, MAX_PROVIDER_CONCENTRATION_BPS)

    def test_provider_concentration_uses_exact_rational_comparison(self) -> None:
        # 5001/10001 = 5000.5 bps > 5000 bps cap: a floor-only implementation
        # (share_bps = 5000) would silently miss this breach.
        offers = self._liquidity({"provider/edge": 5001, "provider/rest": 5000})
        report = evaluate_concentration(liquidity_offers=offers)
        breaches = [
            e for e in report.breaches
            if e.kind is ConcentrationControlKind.PROVIDER
            and e.group[1] == "provider/edge"
        ]
        self.assertEqual(len(breaches), 1)
        self.assertEqual(breaches[0].share_bps, 5000)  # floor display value
        self.assertTrue(breaches[0].breach)

    def test_provider_concentration_at_exactly_the_cap_is_not_a_breach(self) -> None:
        offers = self._liquidity({"provider/half": 5_000, "provider/other": 5_000})
        report = evaluate_concentration(liquidity_offers=offers)
        self.assertEqual(
            [e for e in report.breaches if e.kind is ConcentrationControlKind.PROVIDER],
            [],
        )

    def test_corridor_concentration_breach_is_flagged_per_currency(self) -> None:
        offers = self._liquidity(
            {"provider/a": 9_000_00, "provider/b": 1_000_00}
        ) + self._liquidity(
            {"provider/c": 1_000_00, "provider/d": 1_000_00},
            corridor=CORRIDOR_USD_GBP,
        )
        report = evaluate_concentration(liquidity_offers=offers)
        corridor_breaches = [
            e for e in report.breaches if e.kind is ConcentrationControlKind.CORRIDOR
        ]
        self.assertEqual(len(corridor_breaches), 1)
        self.assertEqual(corridor_breaches[0].group[0], "asset/USD->asset/EUR")

    def test_corridors_in_different_currencies_are_measured_separately(self) -> None:
        offers = self._liquidity({"provider/a": 9_000_00, "provider/b": 1_000_00})
        offers += self._liquidity(
            {"provider/e": 9_000_00, "provider/f": 1_000_00},
            corridor=CORRIDOR_EUR_USD,
        )
        # Each currency group has a 90/10 split inside its own corridors;
        # EUR liquidity never dilutes USD concentration.
        report = evaluate_concentration(liquidity_offers=offers)
        usd_corridor = [
            e for e in report.entries
            if e.kind is ConcentrationControlKind.CORRIDOR and e.group[1] == "USD"
        ]
        eur_corridor = [
            e for e in report.entries
            if e.kind is ConcentrationControlKind.CORRIDOR and e.group[1] == "EUR"
        ]
        self.assertEqual(len(usd_corridor), 1)
        self.assertEqual(len(eur_corridor), 1)
        self.assertEqual(usd_corridor[0].whole, usd(10_000_00))
        self.assertEqual(eur_corridor[0].whole, eur(10_000_00))

    def test_counterparty_concentration_breach_is_flagged(self) -> None:
        facilities = [
            credit_fixture(
                offer_id="liquidity/credit/c1",
                counterparty="principal/cpty-dominant",
                limit=usd(900_00),
            ),
            credit_fixture(
                offer_id="liquidity/credit/c2",
                counterparty="principal/cpty-small",
                limit=usd(100_00),
            ),
        ]
        drawn = [
            draw_credit(f, f.spec.limit, as_of=WITHIN, provenance=prov())
            for f in facilities
        ]
        report = evaluate_concentration(credit_offers=drawn)
        breaches = [
            e for e in report.breaches if e.kind is ConcentrationControlKind.COUNTERPARTY
        ]
        self.assertEqual(len(breaches), 1)
        self.assertEqual(breaches[0].group, ("principal/cpty-dominant", "USD"))
        self.assertEqual(breaches[0].part, usd(900_00))
        self.assertEqual(breaches[0].whole, usd(1_000_00))

    def test_concentration_report_is_order_independent_with_deterministic_ties(self) -> None:
        offers = self._liquidity(
            {"provider/tie-a": 5_000, "provider/tie-b": 5_000, "provider/tie-c": 5_000}
        )
        forward = evaluate_concentration(liquidity_offers=offers)
        backward = evaluate_concentration(liquidity_offers=list(reversed(offers)))
        self.assertEqual(forward.digest(), backward.digest())
        keys = [
            (e.kind.value, e.group) for e in forward.entries
            if e.kind is ConcentrationControlKind.PROVIDER
        ]
        self.assertEqual(keys, sorted(keys))
        # Equal shares are broken by the lexicographic group key, so ties
        # never depend on input order.
        shares = [
            e.share_bps for e in forward.entries
            if e.kind is ConcentrationControlKind.PROVIDER
        ]
        self.assertEqual(shares, [3333, 3333, 3333])

    def test_empty_concentration_report_is_stable(self) -> None:
        report = evaluate_concentration()
        self.assertEqual(report.entries, ())
        self.assertEqual(report.breaches, ())
        self.assertEqual(evaluate_concentration().digest(), report.digest())

    def test_concentration_ignores_terminal_offers(self) -> None:
        offers = self._liquidity(
            {"provider/dominant": 9_000_00, "provider/small": 1_000_00}
        )
        closed = [
            withdraw_liquidity_offer(offer, provenance=prov()) for offer in offers
        ]
        report = evaluate_concentration(liquidity_offers=closed)
        self.assertEqual(report.entries, ())
        self.assertEqual(report.breaches, ())
        # A single remaining live provider owns the whole corridor: one
        # PROVIDER entry and one CORRIDOR entry, both flagged.
        mixed = [closed[0], offers[1]]
        report = evaluate_concentration(liquidity_offers=mixed)
        self.assertEqual(len(report.entries), 2)
        self.assertTrue(all(entry.breach for entry in report.entries))


# ---------------------------------------------------------------------------
# 11. Quality-attribute proof (scaled deterministic fixture).
# ---------------------------------------------------------------------------

SCALED_FACILITIES = 1200
SCALED_COUNTERPARTIES = 40
SCALED_CORRIDORS = (
    CORRIDOR_USD_EUR,
    CORRIDOR_EUR_USD,
    CORRIDOR_USD_GBP,
    Corridor(ASSET_GBP, ASSET_USD),
    Corridor(ASSET_USD, ASSET_USD),
    Corridor(ASSET_EUR, ASSET_EUR),
    Corridor(ASSET_GBP, ASSET_GBP),
    Corridor(ASSET_EUR, ASSET_GBP),
)


def _corridor_currency(corridor: Corridor) -> Currency:
    if corridor.source_asset == ASSET_USD:
        return USD
    if corridor.source_asset == ASSET_EUR:
        return EUR
    return GBP


def scaled_facilities() -> list[CreditOffer]:
    """Deterministic scaled fixture: 1200 facilities across 40 counterparties
    and 8 corridors, each drawn within its own facility limit."""
    facilities: list[CreditOffer] = []
    for index in range(SCALED_FACILITIES):
        counterparty = f"principal/cpty/{index % SCALED_COUNTERPARTIES:03d}"
        corridor = SCALED_CORRIDORS[index % len(SCALED_CORRIDORS)]
        currency = _corridor_currency(corridor)
        limit = Amount(currency=currency, value=1_000_00 + (index % 97) * 10, scale=2)
        facility = create_credit_offer(
            offer_id=f"liquidity/credit/scaled/{index:05d}",
            provider=f"provider/scaled/{index % 120:04d}",
            provider_capability_id="capability/capability/scaled",
            counterparty=counterparty,
            corridor=corridor,
            limit=limit,
            utilization_from=CRED_FROM,
            utilization_until=CRED_UNTIL,
            environment_id=ENV,
            domain_id=DOMAIN,
            provenance=prov(),
        )
        drawn_value = 100_00 + (index % 53) * 7
        if drawn_value >= limit.value:
            drawn_value = limit.value
        facilities.append(
            draw_credit(
                facility,
                Amount(currency=currency, value=drawn_value, scale=2),
                as_of=WITHIN,
                provenance=prov(),
            )
        )
    return facilities


def scaled_liquidity() -> list[LiquidityOffer]:
    offers: list[LiquidityOffer] = []
    for index in range(600):
        corridor = SCALED_CORRIDORS[index % len(SCALED_CORRIDORS)]
        currency = _corridor_currency(corridor)
        offers.append(
            offer_fixture(
                offer_id=f"liquidity/offer/scaled/{index:05d}",
                provider=f"provider/scaled/{index % 120:04d}",
                capacity=Amount(currency=currency, value=500_00 + (index % 89) * 11, scale=2),
                corridor=corridor,
            )
        )
    return offers


def scaled_exposures() -> list[CreditExposure]:
    exposures: list[CreditExposure] = []
    for index in range(SCALED_COUNTERPARTIES):
        corridor = SCALED_CORRIDORS[index % len(SCALED_CORRIDORS)]
        currency = _corridor_currency(corridor)
        exposures.append(
            create_credit_exposure(
                exposure_id=f"liquidity/exposure/scaled/{index:03d}",
                counterparty=f"principal/cpty/{index:03d}",
                corridor=corridor,
                limit=Amount(currency=currency, value=50_000_00, scale=2),
                valid_from=EXP_FROM,
                valid_until=EXP_UNTIL,
                environment_id=ENV,
                domain_id=DOMAIN,
                provenance=prov(),
            )
        )
    return exposures


def scaled_digests() -> str:
    facilities = scaled_facilities()
    liquidity = scaled_liquidity()
    exposures = scaled_exposures()
    assessment = assess_exposure(exposures, facilities)
    report = evaluate_concentration(liquidity_offers=liquidity, credit_offers=facilities)
    return f"{assessment.digest()}:{report.digest()}"


class QualityAttributeTests(unittest.TestCase):
    """Scaled deterministic fixture (>= 1200 credit offers across 40
    counterparties and 8 corridors) through exposure aggregation, limit
    assessment and concentration evaluation: measured CPU time
    (harness only), asserted determinism and conservation. Complexity:
    the aggregation is a single linear pass over offers (O(n)); assessment
    and concentration evaluation are linear passes plus sorted output
    construction over the bounded per-key aggregate sets (O(n log n)
    dominated by those sorts); no nested per-offer rescans, so there is
    no hidden quadratic behavior."""

    def test_scaled_assessment_and_concentration_are_deterministic(self) -> None:
        facilities = scaled_facilities()
        liquidity = scaled_liquidity()
        exposures = scaled_exposures()
        first = assess_exposure(exposures, facilities)
        first_report = evaluate_concentration(
            liquidity_offers=liquidity, credit_offers=facilities
        )
        start = time.process_time()
        second = assess_exposure(exposures, facilities)
        second_report = evaluate_concentration(
            liquidity_offers=liquidity, credit_offers=facilities
        )
        measured = time.process_time() - start
        self.assertEqual(first.digest(), second.digest())
        self.assertEqual(first_report.digest(), second_report.digest())
        # Conservation: aggregate drawn equals the sum of facility utilization.
        total_drawn = sum(a.drawn.value for a in second.aggregates)
        self.assertEqual(total_drawn, sum(f.spec.utilized.value for f in facilities))
        # Generous regression tripwire (not the reported number): a linear
        # pass over 1200 immutable facilities must stay far below this.
        self.assertLess(measured, 10.0)

    def test_scaled_digest_matches_across_two_clean_processes(self) -> None:
        repo_root = str(Path(__file__).resolve().parents[2])
        outputs = []
        for _ in range(2):
            completed = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "from src.liquidity.test_liquidity import scaled_digests; "
                    "print(scaled_digests())",
                ],
                capture_output=True,
                text=True,
                cwd=repo_root,
                check=True,
            )
            outputs.append(completed.stdout.strip())
        self.assertEqual(outputs[0], outputs[1])
        self.assertIn(":", outputs[0])


# ---------------------------------------------------------------------------
# 12. DOGFOOD-011 conformance.
# ---------------------------------------------------------------------------


class DogfoodingTests(unittest.TestCase):
    """The dogfooding harness is deterministic and byte-stable."""

    def test_transcript_is_deterministic_with_a_stable_digest(self) -> None:
        from src.liquidity.dogfooding import build_transcript

        transcript_a, digest_a = build_transcript()
        transcript_b, digest_b = build_transcript()
        self.assertEqual(transcript_a, transcript_b)
        self.assertEqual(digest_a, digest_b)
        self.assertEqual(digest_a, canonical_sha256({"transcript": transcript_a}))

    def test_transcript_covers_bootstrap_credit_and_breach(self) -> None:
        from src.liquidity.dogfooding import build_transcript

        transcript, _ = build_transcript()
        self.assertIn("DOGFOOD-011: PASS", transcript)
        self.assertIn("phase=bootstrap", transcript)
        self.assertIn("phase=credit", transcript)
        self.assertIn("phase=exposure", transcript)
        self.assertIn("status=BREACH", transcript)
        # Corridor bootstrap evidence.
        self.assertIn("corridor=asset/USD->asset/EUR", transcript)
        # Credit availability changes.
        self.assertIn("available=60000", transcript)
        self.assertIn("available=70000", transcript)
        # Exposure breach evidence.
        self.assertIn("drawn=80000", transcript)
        self.assertIn("limit=75000", transcript)

    def test_main_returns_the_digest(self) -> None:
        from src.liquidity.dogfooding import build_transcript, main

        self.assertEqual(main(), build_transcript()[1])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
