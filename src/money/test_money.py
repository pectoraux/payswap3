"""Contract and discrimination tests for the WORK-006 money domain.

The suite pins the frozen architecture semantics for fixed-point monetary
arithmetic: exact scaled-integer amounts, explicit integer rounding,
deterministic residual allocation, conservation-preserving FX conversion
and envelope-backed durable FX quotes. Every failure path is explicit and
every deterministic output is byte-stable under canonical serialization.
"""

from __future__ import annotations

import ast
import json
import pathlib
import unittest

from ..core import ObjectEnvelope, Provenance
from ..core.errors import CoreValidationError as CanonicalCoreError
from ..core.serialization import (
    canonical_json,
    canonical_sha256,
    loads_canonical,
    validate_canonical_value,
)
from . import (
    CANONICAL_CURRENCIES,
    FX_QUOTE_OBJECT_TYPE,
    Amount,
    CoreValidationError,
    Currency,
    FxConversion,
    FxQuote,
    FxQuoteState,
    FxRate,
    RoundingMode,
    allocate_equal,
    allocate_weighted,
    convert,
    get_currency,
    round_ratio,
)

STAMP = "2026-09-02T00:00:00Z"


def usd(value: int) -> Amount:
    return Amount(currency=get_currency("USD"), value=value, scale=2)


def eur(value: int) -> Amount:
    return Amount(currency=get_currency("EUR"), value=value, scale=2)


def jpy(value: int) -> Amount:
    return Amount(currency=get_currency("JPY"), value=value, scale=0)


def build_quote(state: str | FxQuoteState = FxQuoteState.ACTIVE) -> FxQuote:
    return FxQuote.build(
        rate=FxRate(
            source=get_currency("USD"),
            target=get_currency("EUR"),
            numerator=91,
            denominator=100,
        ),
        object_id="fx-quote/usd-eur/1",
        environment_id="env/test",
        domain_id="domain/money",
        state=state,
        provenance=Provenance(
            issuer="principal/treasury",
            source="dogfood",
            recorded_at=STAMP,
        ),
        correlation_id="corr/money-1",
    )


def build_dogfood_transcript() -> dict:
    """Replay a canonical multi-currency calculation through the public API."""
    usd_code = get_currency("USD")
    eur_code = get_currency("EUR")
    jpy_code = get_currency("JPY")
    gross = Amount(currency=usd_code, value=125433, scale=2)
    parts = allocate_weighted(gross, (2, 3, 5))
    quote = build_quote()
    conversions = [quote.rate.convert(part, RoundingMode.HALF_EVEN) for part in parts]
    jpy_rate = FxRate(source=eur_code, target=jpy_code, numerator=16311, denominator=100)
    final = jpy_rate.convert(conversions[2].target, RoundingMode.HALF_EVEN)
    return {
        "inputs": {"gross": gross.to_dict(), "weights": [2, 3, 5]},
        "allocation": [part.to_dict() for part in parts],
        "quote": quote.to_dict(),
        "conversions": [record.to_dict() for record in conversions],
        "final_conversion": final.to_dict(),
    }


def dogfood_transcript_json() -> str:
    return canonical_json(build_dogfood_transcript())


class CurrencyTests(unittest.TestCase):
    def test_canonical_currency_scales_are_frozen(self) -> None:
        expected = {"USD": 2, "EUR": 2, "GBP": 2, "JPY": 0, "KRW": 0, "VND": 0,
                    "ISK": 0, "CLP": 0, "KWD": 3, "BHD": 3, "OMR": 3, "TND": 3}
        for code, scale in expected.items():
            self.assertIn(code, CANONICAL_CURRENCIES)
            self.assertEqual(get_currency(code).scale, scale)
        self.assertEqual(get_currency("USD"), Currency("USD", 2))
        with self.assertRaises(CoreValidationError):
            get_currency("XTS")

    def test_currency_validation_rejects_malformed_codes(self) -> None:
        for bad_code in ("usd", "US", "USDD", "U1D", "", 123, None):
            with self.assertRaises(CoreValidationError):
                Currency(code=bad_code, scale=2)
        for bad_scale in (-1, 9, 2.0, True):
            with self.assertRaises(CoreValidationError):
                Currency(code="USD", scale=bad_scale)

    def test_currency_conflicting_scale_against_canonical_table_rejected(self) -> None:
        with self.assertRaises(CoreValidationError):
            Currency(code="USD", scale=3)
        custom = Currency(code="XTS", scale=4)
        self.assertEqual((custom.code, custom.scale), ("XTS", 4))


class RoundingTests(unittest.TestCase):
    def test_round_ratio_positive_rationals(self) -> None:
        cases = {
            (5, 2): {"HALF_EVEN": 2, "HALF_UP": 3, "HALF_DOWN": 2, "FLOOR": 2, "CEILING": 3, "TRUNCATE": 2},
            (7, 2): {"HALF_EVEN": 4, "HALF_UP": 4, "HALF_DOWN": 3, "FLOOR": 3, "CEILING": 4, "TRUNCATE": 3},
            (1, 3): {"HALF_EVEN": 0, "HALF_UP": 0, "HALF_DOWN": 0, "FLOOR": 0, "CEILING": 1, "TRUNCATE": 0},
            (2, 3): {"HALF_EVEN": 1, "HALF_UP": 1, "HALF_DOWN": 1, "FLOOR": 0, "CEILING": 1, "TRUNCATE": 0},
            (6, 3): {"HALF_EVEN": 2, "HALF_UP": 2, "HALF_DOWN": 2, "FLOOR": 2, "CEILING": 2, "TRUNCATE": 2},
        }
        for (numerator, denominator), expected in cases.items():
            for mode_name, expected_value in expected.items():
                self.assertEqual(
                    round_ratio(numerator, denominator, RoundingMode(mode_name)),
                    expected_value,
                    f"round_ratio({numerator}, {denominator}, {mode_name})",
                )

    def test_round_ratio_negative_rationals(self) -> None:
        cases = {
            (-7, 2): {"HALF_EVEN": -4, "HALF_UP": -4, "HALF_DOWN": -3, "FLOOR": -4, "CEILING": -3, "TRUNCATE": -3},
            (-5, 2): {"HALF_EVEN": -2, "HALF_UP": -3, "HALF_DOWN": -2, "FLOOR": -3, "CEILING": -2, "TRUNCATE": -2},
            (-1, 3): {"HALF_EVEN": 0, "HALF_UP": 0, "HALF_DOWN": 0, "FLOOR": -1, "CEILING": 0, "TRUNCATE": 0},
            (-2, 3): {"HALF_EVEN": -1, "HALF_UP": -1, "HALF_DOWN": -1, "FLOOR": -1, "CEILING": 0, "TRUNCATE": 0},
        }
        for (numerator, denominator), expected in cases.items():
            for mode_name, expected_value in expected.items():
                self.assertEqual(
                    round_ratio(numerator, denominator, RoundingMode(mode_name)),
                    expected_value,
                    f"round_ratio({numerator}, {denominator}, {mode_name})",
                )

    def test_round_ratio_rejects_invalid_arguments(self) -> None:
        for numerator, denominator in ((1, 0), (1, -2), (1.5, 2), (1, 2.0), (True, 2), (1, True)):
            with self.assertRaises(CoreValidationError):
                round_ratio(numerator, denominator, RoundingMode.HALF_EVEN)
        for bad_mode in ("HALF_EVEN", "WEIRD", None, 3):
            with self.assertRaises(CoreValidationError):
                round_ratio(1, 2, bad_mode)

    def test_round_ratio_half_even_ties_to_even(self) -> None:
        self.assertEqual(round_ratio(5, 2, RoundingMode.HALF_EVEN), 2)
        self.assertEqual(round_ratio(7, 2, RoundingMode.HALF_EVEN), 4)
        self.assertEqual(round_ratio(-5, 2, RoundingMode.HALF_EVEN), -2)
        self.assertEqual(round_ratio(-7, 2, RoundingMode.HALF_EVEN), -4)


class AmountTests(unittest.TestCase):
    def test_amount_construction_and_validation(self) -> None:
        amount = usd(12345)
        self.assertEqual(amount.value, 12345)
        self.assertEqual(amount.scale, 2)
        self.assertEqual(amount.currency.code, "USD")
        with self.assertRaises(CoreValidationError):
            Amount(currency=get_currency("USD"), value=1.5, scale=2)
        with self.assertRaises(CoreValidationError):
            Amount(currency=get_currency("USD"), value=True, scale=2)
        with self.assertRaises(CoreValidationError):
            Amount(currency=get_currency("USD"), value=1, scale=3)
        with self.assertRaises(CoreValidationError):
            Amount(currency="USD", value=1, scale=2)
        with self.assertRaises(CoreValidationError):
            Amount(currency=get_currency("USD"), value=1, scale=2.0)
        with self.assertRaises(CoreValidationError):
            Amount.from_dict({"currency": "USD", "scale": 2, "value": 1.5})

    def test_amount_dict_and_json_round_trip(self) -> None:
        amount = usd(12345)
        decoded = Amount.from_json(amount.to_json())
        self.assertEqual(decoded, amount)
        self.assertEqual(decoded.to_dict(), {"currency": "USD", "scale": 2, "value": 12345})
        self.assertEqual(Amount.from_dict(amount.to_dict()), amount)
        with self.assertRaises(CoreValidationError):
            Amount.from_dict({"currency": "USD", "scale": 2})
        with self.assertRaises(CoreValidationError):
            Amount.from_dict({"currency": "USD", "scale": 2, "value": 1, "extra": 0})
        with self.assertRaises(CoreValidationError):
            Amount.from_dict("not-a-mapping")
        with self.assertRaises(CoreValidationError):
            Amount.from_json("[1,2]")
        with self.assertRaises(CoreValidationError):
            Amount.from_json('{"currency":"USD","scale":2,"value":1,"value":2}')

    def test_amount_arithmetic_is_exact_and_overflow_safe(self) -> None:
        big = 10 ** 18 + 1
        total = usd(big).add(usd(big + 1))
        self.assertEqual(total.value, 2 * big + 1)
        self.assertEqual(usd(7).multiply(10 ** 12).value, 7 * 10 ** 12)
        self.assertEqual(usd(7).multiply(-3).value, -21)
        self.assertEqual(usd(10).sub(usd(4)).value, 6)
        self.assertEqual(usd(-5).absolute().value, 5)
        self.assertEqual(usd(5).negate().value, -5)

    def test_amount_arithmetic_rejects_currency_mismatch(self) -> None:
        with self.assertRaises(CoreValidationError):
            usd(1).add(eur(1))
        with self.assertRaises(CoreValidationError):
            usd(1).sub(eur(1))
        with self.assertRaises(CoreValidationError):
            usd(1).__lt__(eur(1))
        with self.assertRaises(CoreValidationError):
            usd(1).add("100")
        self.assertFalse(usd(1) == eur(1))
        self.assertTrue(usd(2) < usd(3))
        self.assertTrue(usd(3) <= usd(3))
        self.assertTrue(usd(4) > usd(3))
        self.assertFalse(usd(3) >= usd(4))

    def test_amount_sign_helpers(self) -> None:
        zero = Amount.zero(get_currency("USD"))
        self.assertTrue(zero.is_zero())
        self.assertFalse(zero.is_positive())
        self.assertFalse(zero.is_negative())
        self.assertEqual(zero.scale, 2)
        self.assertTrue(usd(1).is_positive())
        self.assertTrue(usd(-1).is_negative())

    def test_amount_divide_requires_explicit_rounding(self) -> None:
        expected = {
            "HALF_EVEN": 62, "HALF_UP": 63, "HALF_DOWN": 62,
            "FLOOR": 62, "CEILING": 63, "TRUNCATE": 62,
        }
        for mode_name, value in expected.items():
            self.assertEqual(
                usd(125).divide(2, RoundingMode(mode_name)).value,
                value,
                f"divide(125, 2, {mode_name})",
            )

    def test_amount_divide_rejects_invalid_divisor(self) -> None:
        for bad_divisor in (0, -2, 2.5, True):
            with self.assertRaises(CoreValidationError):
                usd(125).divide(bad_divisor, RoundingMode.HALF_EVEN)
        with self.assertRaises(CoreValidationError):
            usd(125).divide(2, "HALF_EVEN")

    def test_amount_quantize_rounds_to_multiple(self) -> None:
        self.assertEqual(usd(12345).quantize(10, RoundingMode.HALF_EVEN).value, 12340)
        self.assertEqual(usd(12345).quantize(10, RoundingMode.HALF_UP).value, 12350)
        self.assertEqual(usd(-12345).quantize(10, RoundingMode.HALF_EVEN).value, -12340)
        self.assertEqual(usd(-12345).quantize(10, RoundingMode.HALF_UP).value, -12350)
        self.assertEqual(usd(12345).quantize(1, RoundingMode.HALF_EVEN).value, 12345)
        for bad_multiple in (0, -10, 1.5, True):
            with self.assertRaises(CoreValidationError):
                usd(12345).quantize(bad_multiple, RoundingMode.HALF_EVEN)

    def test_amount_equality_and_hashing(self) -> None:
        self.assertEqual(hash(usd(5)), hash(usd(5)))
        self.assertEqual(len({usd(5), usd(3), usd(5)}), 2)
        registry = {usd(5): "a"}
        registry[usd(5)] = "b"
        self.assertEqual(registry[usd(5)], "b")

    def test_money_sources_contain_no_float_literals(self) -> None:
        package_dir = pathlib.Path(__file__).resolve().parent
        sources = sorted(
            path
            for path in package_dir.glob("*.py")
            if not path.name.startswith("test")
        )
        self.assertTrue(sources)
        for path in sources:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, float):
                    self.fail(f"float literal found in {path.name} at line {node.lineno}")


class AllocationTests(unittest.TestCase):
    def test_allocate_equal_conserves_value_exactly(self) -> None:
        self.assertEqual([part.value for part in allocate_equal(usd(100), 3)], [34, 33, 33])
        self.assertEqual([part.value for part in allocate_equal(usd(99), 3)], [33, 33, 33])
        self.assertEqual([part.value for part in allocate_equal(usd(0), 3)], [0, 0, 0])
        self.assertEqual([part.value for part in allocate_equal(usd(-7), 3)], [-2, -2, -3])
        self.assertEqual([part.value for part in allocate_equal(usd(100), 1)], [100])
        for part in allocate_equal(usd(100), 3):
            self.assertEqual(part.currency.code, "USD")
            self.assertEqual(part.scale, 2)

    def test_allocate_equal_rejects_invalid_count(self) -> None:
        for bad_count in (0, -1, True, 1.5, "3"):
            with self.assertRaises(CoreValidationError):
                allocate_equal(usd(100), bad_count)

    def test_allocate_weighted_conserves_value_exactly(self) -> None:
        cases = [
            (usd(125433), (2, 3, 5), [25087, 37630, 62716]),
            (usd(5), (1, 2), [2, 3]),
            (usd(3), (1, 1), [2, 1]),
            (usd(-7), (1, 1, 1), [-2, -2, -3]),
            (usd(7), (1,), [7]),
        ]
        for amount, weights, expected in cases:
            parts = allocate_weighted(amount, weights)
            self.assertEqual([part.value for part in parts], expected)
            total = parts[0]
            for part in parts[1:]:
                total = total.add(part)
            self.assertEqual(total, amount)

    def test_allocate_weighted_rejects_invalid_weights(self) -> None:
        for bad_weights in ([], [0], [-1], [1.5], [True], "12", 3):
            with self.assertRaises(CoreValidationError):
                allocate_weighted(usd(100), bad_weights)

    def test_allocation_is_deterministic_and_byte_stable(self) -> None:
        first = [canonical_json(part.to_dict()) for part in allocate_weighted(usd(125433), (2, 3, 5))]
        for _ in range(5):
            again = [canonical_json(part.to_dict()) for part in allocate_weighted(usd(125433), (2, 3, 5))]
            self.assertEqual(again, first)
        self.assertEqual(
            [record for record in first],
            [
                canonical_json(part.to_dict())
                for part in allocate_weighted(usd(125433), [2, 3, 5])
            ],
        )

    def test_allocation_rejects_non_amount_inputs(self) -> None:
        with self.assertRaises(CoreValidationError):
            allocate_equal(100, 3)
        with self.assertRaises(CoreValidationError):
            allocate_weighted(100, (1, 2))


class FxRateTests(unittest.TestCase):
    def test_fx_rate_validation(self) -> None:
        usd_code = get_currency("USD")
        eur_code = get_currency("EUR")
        with self.assertRaises(CoreValidationError):
            FxRate(source=usd_code, target=usd_code, numerator=91, denominator=100)
        for numerator, denominator in ((0, 100), (-91, 100), (91, 0), (91, -100), (9.1, 100), (91, 10.0), (True, 100), (91, True)):
            with self.assertRaises(CoreValidationError):
                FxRate(source=usd_code, target=eur_code, numerator=numerator, denominator=denominator)
        custom = FxRate(source=Currency("XTS", 4), target=eur_code, numerator=5, denominator=2)
        self.assertEqual((custom.source.code, custom.target.code), ("XTS", "EUR"))

    def test_fx_rate_reduces_to_canonical_lowest_terms(self) -> None:
        reduced = FxRate(source=get_currency("USD"), target=get_currency("EUR"), numerator=90, denominator=100)
        self.assertEqual((reduced.numerator, reduced.denominator), (9, 10))
        unchanged = FxRate(source=get_currency("USD"), target=get_currency("JPY"), numerator=15537, denominator=100)
        self.assertEqual((unchanged.numerator, unchanged.denominator), (15537, 100))
        inverted = reduced.inverted()
        self.assertEqual(inverted.source.code, "EUR")
        self.assertEqual(inverted.target.code, "USD")
        self.assertEqual((inverted.numerator, inverted.denominator), (10, 9))

    def test_fx_rate_dict_and_json_round_trip(self) -> None:
        rate = FxRate(source=get_currency("USD"), target=get_currency("JPY"), numerator=15537, denominator=100)
        decoded = FxRate.from_json(rate.to_json())
        self.assertEqual(decoded, rate)
        self.assertEqual(
            decoded.to_dict(),
            {
                "source_currency": "USD",
                "source_scale": 2,
                "target_currency": "JPY",
                "target_scale": 0,
                "rate_numerator": 15537,
                "rate_denominator": 100,
            },
        )
        with self.assertRaises(CoreValidationError):
            FxRate.from_dict({"source_currency": "USD", "source_scale": 2, "target_currency": "JPY"})
        with self.assertRaises(CoreValidationError):
            FxRate.from_dict({**rate.to_dict(), "extra": 0})
        with self.assertRaises(CoreValidationError):
            FxRate.from_dict("not-a-mapping")

    def test_fx_rate_from_dict_rejects_canonical_scale_drift(self) -> None:
        payload = {
            "source_currency": "USD",
            "source_scale": 3,
            "target_currency": "EUR",
            "target_scale": 2,
            "rate_numerator": 9,
            "rate_denominator": 10,
        }
        with self.assertRaises(CoreValidationError):
            FxRate.from_dict(payload)
        custom_payload = {
            "source_currency": "XTS",
            "source_scale": 4,
            "target_currency": "EUR",
            "target_scale": 2,
            "rate_numerator": 5,
            "rate_denominator": 2,
        }
        self.assertEqual(FxRate.from_dict(custom_payload).source.scale, 4)


class FxConversionTests(unittest.TestCase):
    def test_convert_exact_conversion_has_zero_residual(self) -> None:
        rate = FxRate(source=get_currency("USD"), target=get_currency("EUR"), numerator=9, denominator=10)
        conversion = rate.convert(usd(10000), RoundingMode.HALF_EVEN)
        self.assertEqual(conversion.target, eur(9000))
        self.assertEqual(conversion.residual_numerator, 0)
        self.assertEqual(conversion.residual_denominator, 1000)
        scaled = 10000 * 9 * 10 ** 2
        self.assertEqual(
            scaled,
            conversion.target.value * conversion.residual_denominator + conversion.residual_numerator,
        )

    def test_convert_rounding_modes_and_conservation(self) -> None:
        rate = FxRate(source=get_currency("USD"), target=get_currency("JPY"), numerator=15537, denominator=100)
        cases = {
            "HALF_EVEN": (1554, -3000),
            "HALF_UP": (1554, -3000),
            "HALF_DOWN": (1554, -3000),
            "FLOOR": (1553, 7000),
            "CEILING": (1554, -3000),
            "TRUNCATE": (1553, 7000),
        }
        for mode_name, (target_value, residual) in cases.items():
            conversion = convert(rate, usd(1000), RoundingMode(mode_name))
            self.assertEqual(conversion.target.value, target_value, mode_name)
            self.assertEqual(conversion.target.currency.code, "JPY")
            self.assertEqual(conversion.target.scale, 0)
            self.assertEqual(conversion.residual_numerator, residual, mode_name)
            self.assertEqual(conversion.residual_denominator, 10000)
            scaled = 1000 * 15537 * 10 ** 0
            self.assertEqual(
                scaled,
                conversion.target.value * conversion.residual_denominator + conversion.residual_numerator,
            )

    def test_convert_rejects_invalid_inputs(self) -> None:
        rate = FxRate(source=get_currency("USD"), target=get_currency("EUR"), numerator=9, denominator=10)
        with self.assertRaises(CoreValidationError):
            rate.convert(eur(100), RoundingMode.HALF_EVEN)
        with self.assertRaises(CoreValidationError):
            rate.convert(usd(100), "HALF_EVEN")
        with self.assertRaises(CoreValidationError):
            convert("rate", usd(100), RoundingMode.HALF_EVEN)
        with self.assertRaises(CoreValidationError):
            convert(rate, "amount", RoundingMode.HALF_EVEN)

    def test_conversion_dict_round_trip_and_tampering_rejected(self) -> None:
        rate = FxRate(source=get_currency("USD"), target=get_currency("JPY"), numerator=15537, denominator=100)
        conversion = rate.convert(usd(1000), RoundingMode.HALF_EVEN)
        self.assertEqual(FxConversion.from_dict(conversion.to_dict()), conversion)
        self.assertEqual(FxConversion.from_json(conversion.to_json()), conversion)
        tampered_target = conversion.to_dict()
        tampered_target["target"]["value"] = 1555
        with self.assertRaises(CoreValidationError):
            FxConversion.from_dict(tampered_target)
        tampered_residual = conversion.to_dict()
        tampered_residual["residual_numerator"] = 3000
        with self.assertRaises(CoreValidationError):
            FxConversion.from_dict(tampered_residual)
        tampered_mode = conversion.to_dict()
        tampered_mode["rounding_mode"] = "WEIRD"
        with self.assertRaises(CoreValidationError):
            FxConversion.from_dict(tampered_mode)
        mode_mismatch = conversion.to_dict()
        mode_mismatch["rounding_mode"] = "FLOOR"
        with self.assertRaises(CoreValidationError):
            FxConversion.from_dict(mode_mismatch)
        extra_field = conversion.to_dict()
        extra_field["extra"] = 0
        with self.assertRaises(CoreValidationError):
            FxConversion.from_dict(extra_field)
        with self.assertRaises(CoreValidationError):
            FxConversion.from_dict("not-a-mapping")

    def test_convert_scale_up_jpy_to_usd_conserves_value(self) -> None:
        rate = FxRate(source=get_currency("JPY"), target=get_currency("USD"), numerator=1, denominator=150)
        conversion = rate.convert(jpy(1_000_000), RoundingMode.HALF_EVEN)
        self.assertEqual(conversion.target.value, 666_667)
        self.assertEqual(conversion.residual_numerator, -50)
        self.assertEqual(conversion.residual_denominator, 150)
        scaled = 1_000_000 * 1 * 10 ** 2
        self.assertEqual(
            scaled,
            conversion.target.value * conversion.residual_denominator + conversion.residual_numerator,
        )


class FxQuoteTests(unittest.TestCase):
    def test_fx_quote_build_seals_envelope_and_payload(self) -> None:
        quote = build_quote()
        self.assertIsNotNone(quote.envelope.integrity_hash)
        self.assertIsNotNone(quote.quote_integrity_hash)
        quote.envelope.verify_integrity()
        quote.verify_integrity()
        self.assertEqual(FxQuote.from_dict(quote.to_dict()), quote)
        self.assertEqual(FxQuote.from_json(quote.to_json()), quote)
        self.assertEqual(quote.rate.source.code, "USD")
        self.assertEqual(quote.rate.target.code, "EUR")

    def test_fx_quote_rejects_unsealed_envelope(self) -> None:
        rate = FxRate(source=get_currency("USD"), target=get_currency("EUR"), numerator=91, denominator=100)
        envelope = ObjectEnvelope(
            object_id="fx-quote/unsealed/1",
            object_type=FX_QUOTE_OBJECT_TYPE,
            object_version=1,
            environment_id="env/test",
            domain_id="domain/money",
            schema_version=1,
            protocol_version="v0.1",
            state="ACTIVE",
            provenance=Provenance(issuer="principal/treasury", source="dogfood", recorded_at=STAMP),
        )
        with self.assertRaises(CoreValidationError):
            FxQuote(envelope=envelope, rate=rate).with_integrity_hash()
        unsealed_payload = build_quote().to_dict()
        unsealed_payload["envelope"]["integrity_hash"] = None
        with self.assertRaises(CoreValidationError):
            FxQuote.from_dict(unsealed_payload)

    def test_fx_quote_rejects_tampered_rate_payload(self) -> None:
        tampered = build_quote().to_dict()
        tampered["rate"]["rate_numerator"] = 92
        with self.assertRaises(CoreValidationError):
            FxQuote.from_dict(tampered)
        unsealed_quote = build_quote().to_dict()
        unsealed_quote["quote_integrity_hash"] = None
        with self.assertRaises(CoreValidationError):
            FxQuote.from_dict(unsealed_quote)
        bogus_hash = build_quote().to_dict()
        bogus_hash["quote_integrity_hash"] = "0" * 64
        with self.assertRaises(CoreValidationError):
            FxQuote.from_dict(bogus_hash)

    def test_fx_quote_rejects_tampered_envelope(self) -> None:
        tampered = build_quote().to_dict()
        tampered["envelope"]["state"] = "RETIRED"
        with self.assertRaises(CoreValidationError):
            FxQuote.from_dict(tampered)

    def test_fx_quote_boundary_is_typed_and_versioned(self) -> None:
        quote = build_quote()
        self.assertEqual(quote.envelope.object_type, "money/fx-quote/v1")
        self.assertEqual(quote.envelope.schema_version, 1)
        self.assertEqual(quote.envelope.protocol_version, "v0.1")
        registry_path = pathlib.Path(__file__).resolve().parents[2] / "spec" / "registry" / "protocol-registry.json"
        registry = json.loads(registry_path.read_text(encoding="utf-8"))
        self.assertNotIn(quote.envelope.object_type, registry["registry"]["objectTypes"])
        self.assertNotIn(quote.envelope.object_type, registry["registry"]["eventNamespaces"])

    def test_fx_quote_next_version_preserves_identity_and_reseals(self) -> None:
        first = build_quote()
        second = first.next_version(state="RETIRED")
        self.assertEqual(second.envelope.object_version, 2)
        self.assertEqual(second.envelope.previous_version, 1)
        self.assertEqual(second.envelope.object_id, first.envelope.object_id)
        self.assertNotEqual(second.envelope.integrity_hash, first.envelope.integrity_hash)
        self.assertNotEqual(second.quote_integrity_hash, first.quote_integrity_hash)
        second.verify_integrity()
        second.envelope.verify_integrity()
        self.assertEqual(FxQuote.from_json(second.to_json()), second)
        self.assertEqual(first.envelope.object_version, 1)
        with self.assertRaises(CoreValidationError):
            first.next_version(object_id="fx-quote/usd-eur/2")
        with self.assertRaises(CoreValidationError):
            first.next_version(object_version=9)
        with self.assertRaises(CoreValidationError):
            first.next_version(previous_version=9)
        with self.assertRaises(CoreValidationError):
            first.next_version(integrity_hash="0" * 64)
        with self.assertRaises(CoreValidationError):
            first.next_version(state="WEIRD")

    def test_fx_quote_state_vocabulary_is_closed(self) -> None:
        with self.assertRaises(CoreValidationError):
            build_quote(state="WEIRD")
        superseded = build_quote(state=FxQuoteState.SUPERSEDED)
        self.assertEqual(superseded.envelope.state, "SUPERSEDED")
        active = build_quote(state="ACTIVE")
        self.assertEqual(active.envelope.state, "ACTIVE")

    def test_fx_quote_rejects_foreign_object_type(self) -> None:
        envelope = ObjectEnvelope(
            object_id="intent/foreign",
            object_type="payswap/intent/v1",
            object_version=1,
            environment_id="env/test",
            domain_id="domain/foreign",
            schema_version=1,
            protocol_version="v0.1",
            state="AUTHORIZED",
            provenance=Provenance(issuer="principal/test", source="dogfood", recorded_at=STAMP),
        ).with_integrity_hash()
        rate = FxRate(source=get_currency("USD"), target=get_currency("EUR"), numerator=91, denominator=100)
        with self.assertRaises(CoreValidationError):
            FxQuote(envelope=envelope, rate=rate)

    def test_fx_quote_rejects_unknown_protocol_and_schema_versions(self) -> None:
        rate = FxRate(source=get_currency("USD"), target=get_currency("EUR"), numerator=91, denominator=100)
        for field, value in (("protocol_version", "v0.2"), ("schema_version", 2)):
            kwargs = {
                "object_id": "fx-quote/probe/1",
                "object_type": FX_QUOTE_OBJECT_TYPE,
                "object_version": 1,
                "environment_id": "env/test",
                "domain_id": "domain/money",
                "schema_version": 1,
                "protocol_version": "v0.1",
                "state": "ACTIVE",
                "provenance": Provenance(issuer="principal/treasury", source="dogfood", recorded_at=STAMP),
            }
            kwargs[field] = value
            envelope = ObjectEnvelope(**kwargs).with_integrity_hash()
            with self.assertRaises(CoreValidationError):
                FxQuote(envelope=envelope, rate=rate)


class MoneyAuthorityTests(unittest.TestCase):
    def test_money_validation_uses_core_error_authority(self) -> None:
        self.assertIs(CoreValidationError, CanonicalCoreError)
        with self.assertRaises(CoreValidationError):
            Amount(currency=get_currency("USD"), value=1, scale=3)

    def test_dogfooding_replay_is_byte_identical(self) -> None:
        first = dogfood_transcript_json()
        second = dogfood_transcript_json()
        self.assertEqual(first, second)
        decoded = loads_canonical(first)
        self.assertEqual(canonical_json(decoded), first)
        self.assertEqual(canonical_sha256(decoded), canonical_sha256(loads_canonical(second)))
        transcript = build_dogfood_transcript()
        gross = Amount.from_dict(transcript["inputs"]["gross"])
        parts = [Amount.from_dict(record) for record in transcript["allocation"]]
        total = parts[0]
        for part in parts[1:]:
            total = total.add(part)
        self.assertEqual(total, gross)
        for record in transcript["conversions"] + [transcript["final_conversion"]]:
            conversion = FxConversion.from_dict(record)
            scaled = conversion.source.value * conversion.rate.numerator * 10 ** conversion.rate.target.scale
            self.assertEqual(
                scaled,
                conversion.target.value * conversion.residual_denominator + conversion.residual_numerator,
            )

    def test_dogfooding_transcript_is_canonical_and_known_answer(self) -> None:
        transcript = loads_canonical(dogfood_transcript_json())
        validate_canonical_value("dogfood transcript", transcript)
        self.assertEqual([part["value"] for part in transcript["allocation"]], [25087, 37630, 62716])
        self.assertEqual(
            [record["target"]["value"] for record in transcript["conversions"]],
            [22829, 34243, 57072],
        )
        self.assertEqual(
            [record["residual_numerator"] for record in transcript["conversions"]],
            [1700, 3000, -4400],
        )
        self.assertEqual(
            [record["residual_denominator"] for record in transcript["conversions"]],
            [10000, 10000, 10000],
        )
        self.assertEqual(transcript["final_conversion"]["target"]["value"], 93090)
        # exact identity: 57072 * 16311 - 93090 * 10000 == 1392
        self.assertEqual(transcript["final_conversion"]["residual_numerator"], 1392)
        self.assertEqual(transcript["final_conversion"]["residual_denominator"], 10000)
        self.assertEqual(transcript["quote"]["rate"]["rate_numerator"], 91)
        self.assertEqual(transcript["quote"]["envelope"]["object_type"], "money/fx-quote/v1")


if __name__ == "__main__":
    unittest.main()
