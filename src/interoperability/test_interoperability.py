from __future__ import annotations

import unittest

from . import (
    AdapterStatusMap,
    CanonicalPaymentMessage,
    CanonicalPaymentStatus,
    Destination,
    DomesticInstruction,
    EffectInterface,
    EffectOperation,
    Endpoint,
    EndpointDirectory,
    EndpointIdentifier,
    EndpointResolution,
    EndpointState,
    FidelityClass,
    IdentifierScheme,
    IdentifierTranslation,
    InstructedAmount,
    ObservationInterface,
    ObservationOperation,
    Provenance,
    ResolutionMethod,
    StatusMapEntry,
    WorldAdapter,
    apply_status_observation,
    ensure_safe_for_resubmission,
    is_retry_safe_payment_status,
    is_terminal_payment_status,
    requires_reconciliation,
    resolve_endpoint,
    translate_to_domestic,
)
from . import CoreValidationError


STAMP = "2026-09-02T00:00:00Z"

VALID_IBAN = "GB29NWBK60161331926819"
OTHER_VALID_IBAN = "DE89370400440532013000"
INVALID_IBAN = "GB29NWBK60161331926818"
VALID_PHONE = "+849012345678"


def provenance() -> Provenance:
    return Provenance(
        issuer="principal/test",
        source="dogfood",
        recorded_at=STAMP,
    )


def iban_identifier(value: str = VALID_IBAN, jurisdiction: str | None = "GB") -> EndpointIdentifier:
    return EndpointIdentifier(scheme=IdentifierScheme.IBAN, value=value, jurisdiction=jurisdiction)


def endpoint(
    endpoint_id: str = "interoperability/endpoint/ep-0001",
    identifiers: tuple[EndpointIdentifier, ...] | None = None,
    state: str = "ACTIVE",
) -> Endpoint:
    return Endpoint.create(
        endpoint_id=endpoint_id,
        identifiers=identifiers if identifiers is not None else (iban_identifier(),),
        environment_id="env/test",
        domain_id="domain/demo",
        provenance=provenance(),
        correlation_id="corr/1",
        state=state,
    )


class IdentifierSchemeTests(unittest.TestCase):
    """WORK-007: endpoint identifier schemes form a closed, validated vocabulary."""

    def test_closed_vocabulary_rejects_unknown_schemes(self) -> None:
        with self.assertRaises(CoreValidationError):
            EndpointIdentifier(scheme="TELEPATHY", value="anything")  # type: ignore[arg-type]
        with self.assertRaises(CoreValidationError):
            EndpointIdentifier.from_dict({"scheme": "SWIFT", "value": "x", "jurisdiction": None})

    def test_identifier_round_trip_is_lossless(self) -> None:
        identifier = EndpointIdentifier(
            scheme=IdentifierScheme.IBAN, value=VALID_IBAN, jurisdiction="GB"
        )
        self.assertEqual(
            EndpointIdentifier.from_dict(identifier.to_dict()), identifier
        )

    def test_non_canonical_identifier_fields_fail_closed(self) -> None:
        good = iban_identifier().to_dict()
        with self.assertRaises(CoreValidationError):
            EndpointIdentifier.from_dict({**good, "extra": "field"})
        with self.assertRaises(CoreValidationError):
            EndpointIdentifier.from_dict(
                {"scheme": "IBAN", "value": VALID_IBAN}
            )

    def test_iban_check_digits_are_verified(self) -> None:
        with self.assertRaises(CoreValidationError):
            iban_identifier(value=INVALID_IBAN)

    def test_iban_is_normalized_to_electronic_form(self) -> None:
        identifier = EndpointIdentifier(
            scheme=IdentifierScheme.IBAN, value=" gb29 nwbk 6016 1331 9268 19 ", jurisdiction=None
        )
        self.assertEqual(identifier.value, VALID_IBAN)

    def test_iban_structure_is_validated(self) -> None:
        for bad in ("GB29NWBK", "gb29nwBK6016133192681!", "29NWBK60161331926819GB", ""):
            with self.assertRaises(CoreValidationError):
                iban_identifier(value=bad)

    def test_iban_jurisdiction_must_match_country_code(self) -> None:
        with self.assertRaises(CoreValidationError):
            iban_identifier(value=VALID_IBAN, jurisdiction="DE")
        self.assertEqual(
            iban_identifier(value=VALID_IBAN, jurisdiction="GB").jurisdiction, "GB"
        )

    def test_phone_numbers_must_be_e164_shaped(self) -> None:
        for good in (VALID_PHONE, "+15551234567"):
            identifier = EndpointIdentifier(
                scheme=IdentifierScheme.PHONE_NUMBER, value=good
            )
            self.assertEqual(identifier.value, good)
        for bad in ("849012345678", "+0849012345678", "+1234", "+8490123456789012345", "+84 90 123 4567"):
            with self.assertRaises(CoreValidationError):
                EndpointIdentifier(scheme=IdentifierScheme.PHONE_NUMBER, value=bad)

    def test_jurisdiction_is_iso3161_alpha2_or_absent(self) -> None:
        for bad in ("gb", "USA", "G", ""):
            with self.assertRaises(CoreValidationError):
                EndpointIdentifier(
                    scheme=IdentifierScheme.ALIAS, value="alice", jurisdiction=bad
                )
        identifier = EndpointIdentifier(
            scheme=IdentifierScheme.ALIAS, value="alice", jurisdiction="VN"
        )
        self.assertEqual(identifier.jurisdiction, "VN")

    def test_scheme_value_shapes_are_validated(self) -> None:
        cases = {
            IdentifierScheme.ACCOUNT_NUMBER: ("1234567890", "has space", "x" * 65),
            IdentifierScheme.MERCHANT_ID: ("mid-77", "bad space", "x" * 65),
            IdentifierScheme.WALLET_ADDRESS: ("0x9f8f", "has space", "x" * 129),
            IdentifierScheme.ALIAS: ("alice", " padded", "x" * 257),
            IdentifierScheme.QR_DATA: ("000201...", "", "q" * 513),
        }
        for scheme, (good, *bad_values) in cases.items():
            self.assertEqual(
                EndpointIdentifier(scheme=scheme, value=good).value, good
            )
            for bad in bad_values:
                with self.assertRaises(CoreValidationError):
                    EndpointIdentifier(scheme=scheme, value=bad)

    def test_qr_data_may_contain_spaces(self) -> None:
        identifier = EndpointIdentifier(
            scheme=IdentifierScheme.QR_DATA, value="EMV 000201 12"
        )
        self.assertEqual(identifier.value, "EMV 000201 12")


class EndpointRecordTests(unittest.TestCase):
    """WORK-007: endpoints are sealed envelope records with lifecycle discipline."""

    def test_register_creates_sealed_active_v1(self) -> None:
        value = endpoint()
        self.assertEqual(value.envelope.object_version, 1)
        self.assertEqual(value.state, EndpointState.ACTIVE)
        self.assertIsNotNone(value.envelope.integrity_hash)
        self.assertEqual(value.envelope.object_type, "interoperability/endpoint")

    def test_endpoint_round_trip_is_lossless_and_byte_stable(self) -> None:
        value = endpoint(identifiers=(iban_identifier(), EndpointIdentifier(
            scheme=IdentifierScheme.ALIAS, value="alice"
        )))
        encoded = value.to_json()
        self.assertEqual(Endpoint.from_json(encoded), value)
        self.assertEqual(Endpoint.from_json(encoded).to_json(), encoded)

    def test_endpoint_requires_at_least_one_identifier(self) -> None:
        with self.assertRaises(CoreValidationError):
            endpoint(identifiers=())

    def test_endpoint_rejects_duplicate_identifiers(self) -> None:
        with self.assertRaises(CoreValidationError):
            endpoint(identifiers=(iban_identifier(), iban_identifier()))

    def test_endpoint_state_must_use_closed_vocabulary(self) -> None:
        with self.assertRaises(CoreValidationError):
            endpoint(state="HIBERNATING")

    def test_endpoint_object_identity_is_prefix_bound(self) -> None:
        value = endpoint()
        data = value.to_dict()
        data["envelope"] = dict(data["envelope"])
        data["envelope"]["object_id"] = "interoperability/endpoint-res/other-1"
        with self.assertRaises(CoreValidationError):
            Endpoint.from_dict(data)
        data = value.to_dict()
        data["envelope"] = dict(data["envelope"])
        data["envelope"]["object_type"] = "interoperability/payment-message"
        with self.assertRaises(CoreValidationError):
            Endpoint.from_dict(data)

    def test_endpoint_rejects_unsealed_envelopes(self) -> None:
        value = endpoint()
        data = value.to_dict()
        data["envelope"] = dict(data["envelope"])
        data["envelope"]["integrity_hash"] = None
        with self.assertRaises(CoreValidationError):
            Endpoint.from_dict(data)

    def test_endpoint_payload_tampering_is_rejected(self) -> None:
        value = endpoint()
        encoded = value.to_json()
        tampered = encoded.replace(VALID_IBAN, OTHER_VALID_IBAN)
        self.assertNotEqual(tampered, encoded)
        with self.assertRaises(CoreValidationError):
            Endpoint.from_json(tampered)

    def test_endpoint_payload_hash_forgery_is_rejected(self) -> None:
        value = endpoint()
        data = value.to_dict()
        data["payload_hash"] = "0" * 64
        with self.assertRaises(CoreValidationError):
            Endpoint.from_dict(data)

    def test_endpoint_envelope_tampering_is_rejected(self) -> None:
        value = endpoint()
        encoded = value.to_json()
        tampered = encoded.replace('"state":"ACTIVE"', '"state":"SUSPENDED"')
        with self.assertRaises(CoreValidationError):
            Endpoint.from_json(tampered)

    def test_suspend_reactivate_and_close_are_versioned(self) -> None:
        active = endpoint()
        suspended = active.evolve(state=EndpointState.SUSPENDED)
        self.assertEqual(suspended.state, EndpointState.SUSPENDED)
        self.assertEqual(suspended.object_version, 2)
        self.assertEqual(suspended.envelope.previous_version, 1)
        reactivated = suspended.evolve(state=EndpointState.ACTIVE)
        self.assertEqual(reactivated.state, EndpointState.ACTIVE)
        self.assertEqual(reactivated.object_version, 3)
        closed = reactivated.evolve(state=EndpointState.CLOSED)
        self.assertEqual(closed.state, EndpointState.CLOSED)

    def test_closed_endpoint_is_terminal(self) -> None:
        closed = endpoint().evolve(state=EndpointState.CLOSED)
        with self.assertRaises(CoreValidationError):
            closed.evolve(state=EndpointState.ACTIVE)
        with self.assertRaises(CoreValidationError):
            closed.evolve(
                identifiers=(EndpointIdentifier(scheme=IdentifierScheme.ALIAS, value="alice"),)
            )

    def test_evolve_updates_identifiers_without_state_change(self) -> None:
        active = endpoint()
        updated = active.evolve(identifiers=(iban_identifier(value=OTHER_VALID_IBAN, jurisdiction="DE"),))
        self.assertEqual(updated.state, EndpointState.ACTIVE)
        self.assertEqual(updated.object_version, 2)
        self.assertEqual(updated.identifiers[0].value, OTHER_VALID_IBAN)

    def test_evolve_rejects_identity_field_changes(self) -> None:
        active = endpoint()
        with self.assertRaises(CoreValidationError):
            active.envelope.next_version(object_id="interoperability/endpoint/ep-9999")
        with self.assertRaises(CoreValidationError):
            active.evolve(state=EndpointState.SUSPENDED, endpoint_id="interoperability/endpoint/ep-2")

    def test_round_trip_after_evolve(self) -> None:
        value = endpoint().evolve(state=EndpointState.SUSPENDED)
        encoded = value.to_json()
        self.assertEqual(Endpoint.from_json(encoded), value)


class CanonicalStatusVocabularyTests(unittest.TestCase):
    """WORK-007: the canonical payment lifecycle vocabulary is frozen; adapters never redefine it."""

    def test_vocabulary_exactly_matches_frozen_lifecycle(self) -> None:
        expected_chain = (
            "INITIATED", "AUTHORIZED", "ACCEPTED", "RESERVED", "COMMITTED",
            "SUBMITTED", "ACKNOWLEDGED", "PROCESSING", "CAPTURED/POSTED",
            "SETTLED", "FINAL",
        )
        expected_branches = (
            "RETURNED", "REVERSED", "FAILED", "EXPIRED", "DISPUTED", "UNKNOWN",
        )
        from . import (
            BRANCH_PAYMENT_STATUSES,
            CANONICAL_PAYMENT_STATUS_CHAIN,
        )
        self.assertEqual(
            tuple(status.value for status in CANONICAL_PAYMENT_STATUS_CHAIN), expected_chain
        )
        self.assertEqual(
            tuple(status.value for status in BRANCH_PAYMENT_STATUSES), expected_branches
        )
        all_values = set(CanonicalPaymentStatus)
        self.assertEqual(len(all_values), 17)
        self.assertEqual(
            {status.value for status in all_values},
            set(expected_chain) | set(expected_branches),
        )

    def test_unknown_status_string_fails_closed(self) -> None:
        with self.assertRaises(CoreValidationError):
            is_terminal_payment_status("DEFINITELY_DONE")

    def test_terminal_classification(self) -> None:
        for status in (
            CanonicalPaymentStatus.SETTLED,
            CanonicalPaymentStatus.FINAL,
            CanonicalPaymentStatus.RETURNED,
            CanonicalPaymentStatus.REVERSED,
            CanonicalPaymentStatus.FAILED,
            CanonicalPaymentStatus.EXPIRED,
            CanonicalPaymentStatus.DISPUTED,
        ):
            self.assertTrue(is_terminal_payment_status(status), status)
        for status in (
            CanonicalPaymentStatus.INITIATED,
            CanonicalPaymentStatus.AUTHORIZED,
            CanonicalPaymentStatus.PROCESSING,
            CanonicalPaymentStatus.CAPTURED_POSTED,
            CanonicalPaymentStatus.UNKNOWN,
        ):
            self.assertFalse(is_terminal_payment_status(status), status)

    def test_unknown_outcome_requires_reconciliation(self) -> None:
        self.assertTrue(requires_reconciliation(CanonicalPaymentStatus.UNKNOWN))
        for status in CanonicalPaymentStatus:
            if status is not CanonicalPaymentStatus.UNKNOWN:
                self.assertFalse(requires_reconciliation(status), status)

    def test_retry_safety_classification(self) -> None:
        for status in (
            CanonicalPaymentStatus.FAILED,
            CanonicalPaymentStatus.EXPIRED,
            CanonicalPaymentStatus.RETURNED,
            CanonicalPaymentStatus.REVERSED,
        ):
            self.assertTrue(is_retry_safe_payment_status(status), status)
        for status in (
            CanonicalPaymentStatus.UNKNOWN,
            CanonicalPaymentStatus.INITIATED,
            CanonicalPaymentStatus.SUBMITTED,
            CanonicalPaymentStatus.SETTLED,
            CanonicalPaymentStatus.FINAL,
            CanonicalPaymentStatus.DISPUTED,
        ):
            self.assertFalse(is_retry_safe_payment_status(status), status)


class InstructedAmountTests(unittest.TestCase):
    """WORK-007: canonical message amounts use frozen fixed-point integer/scale wire form."""

    def test_fixed_point_form_round_trips(self) -> None:
        amount = InstructedAmount(value=2500, scale=2, currency="USD")
        self.assertEqual(InstructedAmount.from_dict(amount.to_dict()), amount)
        self.assertEqual(amount.to_dict(), {"value": 2500, "scale": 2, "currency": "USD"})

    def test_negative_and_non_integer_values_are_rejected(self) -> None:
        for bad in (-1, True, "2500", 2.5):
            with self.assertRaises(CoreValidationError):
                InstructedAmount(value=bad, scale=2, currency="USD")

    def test_scale_domain_is_bounded(self) -> None:
        for bad in (-1, 19, 2.0, True, "2"):
            with self.assertRaises(CoreValidationError):
                InstructedAmount(value=2500, scale=bad, currency="USD")

    def test_currency_is_alpha3_uppercase(self) -> None:
        for bad in ("usd", "USDD", "US", 7, ""):
            with self.assertRaises(CoreValidationError):
                InstructedAmount(value=2500, scale=2, currency=bad)
        self.assertEqual(InstructedAmount(value=2500, scale=2, currency="VND").currency, "VND")

    def test_non_canonical_fields_fail_closed(self) -> None:
        with self.assertRaises(CoreValidationError):
            InstructedAmount.from_dict({"value": 2500, "scale": 2})
        with self.assertRaises(CoreValidationError):
            InstructedAmount.from_dict(
                {"value": 2500, "scale": 2, "currency": "USD", "extra": 1}
            )


class CanonicalPaymentMessageTests(unittest.TestCase):
    """WORK-007: canonical payment messages are sealed records whose state is the canonical lifecycle."""

    @staticmethod
    def message() -> CanonicalPaymentMessage:
        resolution = resolve_endpoint(
            iban_identifier(),
            (endpoint(),),
            resolution_id="interoperability/endpoint-resolution/res-0001",
            environment_id="env/test",
            domain_id="domain/demo",
            provenance=provenance(),
            resolved_at=STAMP,
        )
        return CanonicalPaymentMessage.create(
            message_id="interoperability/payment-message/msg-0001",
            destination=resolution.destination,
            instructed_amount=InstructedAmount(value=2500, scale=2, currency="USD"),
            end_to_end_id="e2e-0001",
            environment_id="env/test",
            domain_id="domain/demo",
            provenance=provenance(),
            correlation_id="corr/1",
        )

    def test_creation_yields_initiated_v1(self) -> None:
        value = self.message()
        self.assertEqual(value.envelope.object_version, 1)
        self.assertEqual(value.status, CanonicalPaymentStatus.INITIATED)
        self.assertIsNotNone(value.envelope.integrity_hash)

    def test_message_round_trip_is_lossless_and_byte_stable(self) -> None:
        value = self.message()
        encoded = value.to_json()
        self.assertEqual(CanonicalPaymentMessage.from_json(encoded), value)
        self.assertEqual(CanonicalPaymentMessage.from_json(encoded).to_json(), encoded)

    def test_version_one_must_be_initiated(self) -> None:
        value = self.message()
        tampered = value.to_json().replace('"state":"INITIATED"', '"state":"SUBMITTED"')
        with self.assertRaises(CoreValidationError):
            CanonicalPaymentMessage.from_json(tampered)

    def test_message_state_must_use_canonical_vocabulary(self) -> None:
        with self.assertRaises(CoreValidationError):
            CanonicalPaymentMessage.create(
                message_id="interoperability/payment-message/msg-0001",
                destination=self.message().destination,
                instructed_amount=InstructedAmount(value=2500, scale=2, currency="USD"),
                end_to_end_id="e2e-0001",
                environment_id="env/test",
                domain_id="domain/demo",
                provenance=provenance(),
                state="BOGUS",
            )

    def test_with_status_advances_version_chain(self) -> None:
        value = self.message()
        submitted = value.with_status(CanonicalPaymentStatus.SUBMITTED)
        self.assertEqual(submitted.status, CanonicalPaymentStatus.SUBMITTED)
        self.assertEqual(submitted.object_version, 2)
        self.assertEqual(submitted.envelope.previous_version, 1)
        self.assertEqual(value.status, CanonicalPaymentStatus.INITIATED)
        encoded = submitted.to_json()
        self.assertEqual(CanonicalPaymentMessage.from_json(encoded), submitted)

    def test_message_payload_tampering_is_rejected(self) -> None:
        value = self.message()
        encoded = value.to_json()
        tampered = encoded.replace('"end_to_end_id":"e2e-0001"', '"end_to_end_id":"e2e-9999"')
        self.assertNotEqual(tampered, encoded)
        with self.assertRaises(CoreValidationError):
            CanonicalPaymentMessage.from_json(tampered)

    def test_message_envelope_tampering_is_rejected(self) -> None:
        value = self.message()
        encoded = value.to_json()
        tampered = encoded.replace('"issuer":"principal/test"', '"issuer":"principal/attacker"')
        with self.assertRaises(CoreValidationError):
            CanonicalPaymentMessage.from_json(tampered)

    def test_retry_guard_fails_closed_on_unsafe_statuses(self) -> None:
        value = self.message()
        for status in (
            CanonicalPaymentStatus.UNKNOWN,
            CanonicalPaymentStatus.INITIATED,
            CanonicalPaymentStatus.SUBMITTED,
            CanonicalPaymentStatus.SETTLED,
            CanonicalPaymentStatus.FINAL,
            CanonicalPaymentStatus.DISPUTED,
        ):
            with self.assertRaises(CoreValidationError):
                ensure_safe_for_resubmission(value.with_status(status))

    def test_retry_guard_accepts_definitive_failures(self) -> None:
        value = self.message()
        for status in (
            CanonicalPaymentStatus.FAILED,
            CanonicalPaymentStatus.EXPIRED,
            CanonicalPaymentStatus.RETURNED,
            CanonicalPaymentStatus.REVERSED,
        ):
            ensure_safe_for_resubmission(value.with_status(status))

    def test_message_requires_destination_and_reference(self) -> None:
        message = self.message()
        with self.assertRaises(CoreValidationError):
            CanonicalPaymentMessage.create(
                message_id="interoperability/payment-message/msg-0002",
                destination=message.destination,
                instructed_amount=message.instructed_amount,
                end_to_end_id="",
                environment_id="env/test",
                domain_id="domain/demo",
                provenance=provenance(),
            )
        with self.assertRaises(CoreValidationError):
            CanonicalPaymentMessage.create(
                message_id="interoperability/message/msg-0002",
                destination=message.destination,
                instructed_amount=message.instructed_amount,
                end_to_end_id="e2e-0002",
                environment_id="env/test",
                domain_id="domain/demo",
                provenance=provenance(),
            )


class AdapterContractTests(unittest.TestCase):
    """WORK-007: world adapter contracts are typed, closed and fidelity-bound."""

    @staticmethod
    def adapter(
        fidelity: FidelityClass = FidelityClass.SIMULATION,
        effect_operations: tuple[EffectOperation, ...] = (EffectOperation.SUBMIT_PAYMENT,),
        destination_schemes: tuple[IdentifierScheme, ...] = (IdentifierScheme.IBAN,),
    ) -> WorldAdapter:
        return WorldAdapter(
            adapter_id="interoperability/adapter/domestic-ips-1",
            capability_id="capability/domestic-ips-1",
            observation_interface=ObservationInterface(
                operations=(
                    ObservationOperation.RESOLVE_ENDPOINT,
                    ObservationOperation.PAYMENT_STATUS,
                    ObservationOperation.FINALITY,
                )
            ),
            effect_interface=EffectInterface(
                operations=effect_operations, destination_schemes=destination_schemes
            ),
            fidelity_class=fidelity,
        )

    def test_adapter_round_trip_is_lossless(self) -> None:
        adapter = self.adapter()
        self.assertEqual(WorldAdapter.from_dict(adapter.to_dict()), adapter)

    def test_adapter_id_uses_interoperability_prefix(self) -> None:
        for bad_id in ("adapter/domestic-ips-1", "interoperability/adapter/", ""):
            with self.assertRaises(CoreValidationError):
                WorldAdapter(
                    adapter_id=bad_id,
                    capability_id="capability/domestic-ips-1",
                    observation_interface=ObservationInterface(
                        operations=(ObservationOperation.PAYMENT_STATUS,)
                    ),
                    effect_interface=EffectInterface(),
                    fidelity_class=FidelityClass.SIMULATION,
                )

    def test_capability_reference_is_required(self) -> None:
        with self.assertRaises(CoreValidationError):
            WorldAdapter(
                adapter_id="interoperability/adapter/domestic-ips-1",
                capability_id="",
                observation_interface=ObservationInterface(
                    operations=(ObservationOperation.PAYMENT_STATUS,)
                ),
                effect_interface=EffectInterface(),
                fidelity_class=FidelityClass.SIMULATION,
            )

    def test_observation_interface_requires_operations(self) -> None:
        with self.assertRaises(CoreValidationError):
            ObservationInterface(operations=())
        with self.assertRaises(CoreValidationError):
            ObservationInterface(operations=("TELEPATHY",))

    def test_effect_interface_declares_destination_schemes_iff_effectful(self) -> None:
        with self.assertRaises(CoreValidationError):
            EffectInterface(
                operations=(EffectOperation.SUBMIT_PAYMENT,), destination_schemes=()
            )
        with self.assertRaises(CoreValidationError):
            EffectInterface(operations=(), destination_schemes=(IdentifierScheme.IBAN,))
        with self.assertRaises(CoreValidationError):
            EffectInterface(
                operations=(EffectOperation.SUBMIT_PAYMENT,), destination_schemes=("SWIFT",)
            )
        with self.assertRaises(CoreValidationError):
            EffectInterface(
                operations=(
                    EffectOperation.SUBMIT_PAYMENT,
                    EffectOperation.SUBMIT_PAYMENT,
                ),
                destination_schemes=(IdentifierScheme.IBAN,),
            )

    def test_reversal_requires_submission_capability(self) -> None:
        with self.assertRaises(CoreValidationError):
            EffectInterface(
                operations=(EffectOperation.REVERSE_PAYMENT,),
                destination_schemes=(IdentifierScheme.IBAN,),
            )

    def test_non_effect_fidelities_must_be_pure_observation(self) -> None:
        for fidelity in (
            FidelityClass.SHADOW,
            FidelityClass.REPLAY,
            FidelityClass.FORECAST,
        ):
            with self.assertRaises(CoreValidationError):
                self.adapter(fidelity=fidelity)

    def test_fidelity_classes_match_simulation_modes(self) -> None:
        self.assertEqual(
            {fidelity.value for fidelity in FidelityClass},
            {"PRODUCTION", "SHADOW", "SIMULATION", "REPLAY", "FORECAST", "COUNTERFACTUAL"},
        )
        for fidelity in (
            FidelityClass.PRODUCTION,
            FidelityClass.SIMULATION,
            FidelityClass.COUNTERFACTUAL,
        ):
            self.assertIsNotNone(self.adapter(fidelity=fidelity))

    def test_non_canonical_adapter_fields_fail_closed(self) -> None:
        data = self.adapter().to_dict()
        with self.assertRaises(CoreValidationError):
            WorldAdapter.from_dict({**data, "extra": "field"})
        with self.assertRaises(CoreValidationError):
            WorldAdapter.from_dict(
                {key: item for key, item in data.items() if key != "fidelity_class"}
            )

    def test_unknown_fidelity_class_fails_closed(self) -> None:
        data = self.adapter().to_dict()
        data["fidelity_class"] = "HALCYON"
        with self.assertRaises(CoreValidationError):
            WorldAdapter.from_dict(data)


class StatusMapTests(unittest.TestCase):
    """WORK-007: native status mapping is declared, complete and fail-closed."""

    @staticmethod
    def status_map(adapter_id: str = "interoperability/adapter/domestic-ips-1") -> AdapterStatusMap:
        return AdapterStatusMap(
            adapter_id=adapter_id,
            entries=(
                StatusMapEntry(native_code="INIT", canonical_status=CanonicalPaymentStatus.INITIATED),
                StatusMapEntry(native_code="AUTH", canonical_status=CanonicalPaymentStatus.AUTHORIZED),
                StatusMapEntry(native_code="BOOK", canonical_status=CanonicalPaymentStatus.CAPTURED_POSTED),
                StatusMapEntry(native_code="REJT", canonical_status=CanonicalPaymentStatus.FAILED),
                StatusMapEntry(native_code="AMBIG", canonical_status=CanonicalPaymentStatus.UNKNOWN),
            ),
        )

    def test_declared_native_codes_map_into_canonical_vocabulary(self) -> None:
        mapping = self.status_map()
        self.assertEqual(
            mapping.map_status("BOOK"), CanonicalPaymentStatus.CAPTURED_POSTED
        )
        self.assertEqual(
            mapping.map_status("AMBIG"), CanonicalPaymentStatus.UNKNOWN
        )

    def test_undeclared_native_status_fails_closed(self) -> None:
        mapping = self.status_map()
        with self.assertRaises(CoreValidationError):
            mapping.map_status("MYSTERY")

    def test_duplicate_native_codes_are_rejected(self) -> None:
        with self.assertRaises(CoreValidationError):
            AdapterStatusMap(
                adapter_id="interoperability/adapter/domestic-ips-1",
                entries=(
                    StatusMapEntry(native_code="INIT", canonical_status=CanonicalPaymentStatus.INITIATED),
                    StatusMapEntry(native_code="INIT", canonical_status=CanonicalPaymentStatus.SUBMITTED),
                ),
            )

    def test_empty_status_map_is_rejected(self) -> None:
        with self.assertRaises(CoreValidationError):
            AdapterStatusMap(
                adapter_id="interoperability/adapter/domestic-ips-1", entries=()
            )

    def test_status_map_round_trip_is_lossless(self) -> None:
        mapping = self.status_map()
        self.assertEqual(AdapterStatusMap.from_dict(mapping.to_dict()), mapping)

    def test_status_map_binding_requires_status_observation(self) -> None:
        adapter = AdapterContractTests.adapter()
        bound = AdapterStatusMap.for_adapter(adapter, self.status_map().entries)
        self.assertEqual(bound.adapter_id, adapter.adapter_id)
        resolver_only = WorldAdapter(
            adapter_id="interoperability/adapter/lookup-1",
            capability_id="capability/directory-1",
            observation_interface=ObservationInterface(
                operations=(ObservationOperation.RESOLVE_ENDPOINT,)
            ),
            effect_interface=EffectInterface(),
            fidelity_class=FidelityClass.SIMULATION,
        )
        with self.assertRaises(CoreValidationError):
            AdapterStatusMap.for_adapter(resolver_only, self.status_map().entries)
        with self.assertRaises(CoreValidationError):
            AdapterStatusMap.for_adapter(adapter, ())
        with self.assertRaises(CoreValidationError):
            AdapterStatusMap.for_adapter(
                adapter,
                (StatusMapEntry(native_code="X", canonical_status="DONE"),),
            )

    def test_native_codes_must_be_non_empty(self) -> None:
        with self.assertRaises(CoreValidationError):
            StatusMapEntry(native_code="", canonical_status=CanonicalPaymentStatus.INITIATED)

    def test_canonical_status_must_use_closed_vocabulary(self) -> None:
        with self.assertRaises(CoreValidationError):
            StatusMapEntry(native_code="X", canonical_status="DONE")


class EndpointResolutionTests(unittest.TestCase):
    """WORK-007: resolution turns an identifier into a sealed destination through a pure engine."""

    def test_canonical_resolution_matches_registered_endpoint(self) -> None:
        value = endpoint()
        resolution = resolve_endpoint(
            iban_identifier(),
            (value,),
            resolution_id="interoperability/endpoint-resolution/res-0001",
            environment_id="env/test",
            domain_id="domain/demo",
            provenance=provenance(),
            resolved_at=STAMP,
        )
        self.assertEqual(resolution.resolution_method, ResolutionMethod.CANONICAL)
        self.assertIsNone(resolution.adapter_id)
        self.assertEqual(resolution.destination.endpoint_id, value.object_id)
        self.assertEqual(resolution.destination.endpoint_version, value.object_version)
        self.assertEqual(resolution.destination.identifier.scheme, IdentifierScheme.IBAN)
        self.assertEqual(resolution.destination.identifier.value, VALID_IBAN)
        self.assertEqual(
            resolution.destination.resolution_id, resolution.envelope.object_id
        )

    def test_resolution_record_is_sealed_and_round_trips(self) -> None:
        resolution = resolve_endpoint(
            iban_identifier(),
            (endpoint(),),
            resolution_id="interoperability/endpoint-resolution/res-0002",
            environment_id="env/test",
            domain_id="domain/demo",
            provenance=provenance(),
            resolved_at=STAMP,
        )
        encoded = resolution.to_json()
        self.assertEqual(EndpointResolution.from_json(encoded), resolution)
        self.assertEqual(EndpointResolution.from_json(encoded).to_json(), encoded)
        self.assertEqual(resolution.envelope.state, "RESOLVED")

    def test_unresolved_identifier_fails_closed(self) -> None:
        with self.assertRaises(CoreValidationError):
            resolve_endpoint(
                iban_identifier(value=OTHER_VALID_IBAN, jurisdiction="DE"),
                (endpoint(),),
                resolution_id="interoperability/endpoint-resolution/res-0003",
                environment_id="env/test",
                domain_id="domain/demo",
                provenance=provenance(),
                resolved_at=STAMP,
            )

    def test_ambiguous_direct_match_fails_closed(self) -> None:
        left = endpoint()
        right = endpoint(endpoint_id="interoperability/endpoint/ep-0002")
        with self.assertRaises(CoreValidationError):
            resolve_endpoint(
                iban_identifier(),
                (left, right),
                resolution_id="interoperability/endpoint-resolution/res-0004",
                environment_id="env/test",
                domain_id="domain/demo",
                provenance=provenance(),
                resolved_at=STAMP,
            )

    def test_suspended_endpoints_are_not_resolvable(self) -> None:
        suspended = endpoint().evolve(state=EndpointState.SUSPENDED)
        with self.assertRaises(CoreValidationError):
            resolve_endpoint(
                iban_identifier(),
                (suspended,),
                resolution_id="interoperability/endpoint-resolution/res-0005",
                environment_id="env/test",
                domain_id="domain/demo",
                provenance=provenance(),
                resolved_at=STAMP,
            )

    def test_directory_assisted_resolution_translates_and_records_provenance(self) -> None:
        value = endpoint()
        directory = EndpointDirectory.for_adapter(
            WorldAdapter(
                adapter_id="interoperability/adapter/domestic-wallet-1",
                capability_id="capability/domestic-wallet-1",
                observation_interface=ObservationInterface(
                    operations=(ObservationOperation.RESOLVE_ENDPOINT,)
                ),
                effect_interface=EffectInterface(),
                fidelity_class=FidelityClass.SIMULATION,
            ),
            (
                IdentifierTranslation(
                    source=EndpointIdentifier(
                        scheme=IdentifierScheme.PHONE_NUMBER, value=VALID_PHONE
                    ),
                    target=iban_identifier(),
                ),
            ),
        )
        resolution = resolve_endpoint(
            EndpointIdentifier(scheme=IdentifierScheme.PHONE_NUMBER, value=VALID_PHONE),
            (value,),
            directories=(directory,),
            resolution_id="interoperability/endpoint-resolution/res-0006",
            environment_id="env/test",
            domain_id="domain/demo",
            provenance=provenance(),
            resolved_at=STAMP,
        )
        self.assertEqual(resolution.resolution_method, ResolutionMethod.ADAPTER_ASSISTED)
        self.assertEqual(
            resolution.adapter_id, "interoperability/adapter/domestic-wallet-1"
        )
        self.assertEqual(resolution.destination.identifier.value, VALID_IBAN)
        self.assertEqual(resolution.requested_identifier.value, VALID_PHONE)

    def test_conflicting_directories_fail_closed(self) -> None:
        left = EndpointDirectory(
            adapter_id="interoperability/adapter/dir-1",
            translations=(
                IdentifierTranslation(
                    source=EndpointIdentifier(
                        scheme=IdentifierScheme.PHONE_NUMBER, value=VALID_PHONE
                    ),
                    target=iban_identifier(),
                ),
            ),
        )
        right = EndpointDirectory(
            adapter_id="interoperability/adapter/dir-2",
            translations=(
                IdentifierTranslation(
                    source=EndpointIdentifier(
                        scheme=IdentifierScheme.PHONE_NUMBER, value=VALID_PHONE
                    ),
                    target=iban_identifier(value=OTHER_VALID_IBAN, jurisdiction="DE"),
                ),
            ),
        )
        with self.assertRaises(CoreValidationError):
            resolve_endpoint(
                EndpointIdentifier(scheme=IdentifierScheme.PHONE_NUMBER, value=VALID_PHONE),
                (endpoint(),),
                directories=(left, right),
                resolution_id="interoperability/endpoint-resolution/res-0007",
                environment_id="env/test",
                domain_id="domain/demo",
                provenance=provenance(),
                resolved_at=STAMP,
            )

    def test_resolution_payload_tampering_is_rejected(self) -> None:
        resolution = resolve_endpoint(
            iban_identifier(),
            (endpoint(),),
            resolution_id="interoperability/endpoint-resolution/res-0008",
            environment_id="env/test",
            domain_id="domain/demo",
            provenance=provenance(),
            resolved_at=STAMP,
        )
        encoded = resolution.to_json()
        tampered = encoded.replace(VALID_IBAN, OTHER_VALID_IBAN)
        with self.assertRaises(CoreValidationError):
            EndpointResolution.from_json(tampered)

    def test_resolution_rejects_mismatched_destination_binding(self) -> None:
        resolution = resolve_endpoint(
            iban_identifier(),
            (endpoint(),),
            resolution_id="interoperability/endpoint-resolution/res-0009",
            environment_id="env/test",
            domain_id="domain/demo",
            provenance=provenance(),
            resolved_at=STAMP,
        )
        data = resolution.to_dict()
        data["payload"] = dict(data["payload"])
        data["payload"]["destination"] = dict(data["payload"]["destination"])
        data["payload"]["destination"]["resolution_id"] = "interoperability/endpoint-resolution/other"
        with self.assertRaises(CoreValidationError):
            EndpointResolution.from_dict(data)

    def test_directory_construction_is_validated(self) -> None:
        with self.assertRaises(CoreValidationError):
            EndpointDirectory(
                adapter_id="interoperability/adapter/dir-1", translations=()
            )
        with self.assertRaises(CoreValidationError):
            EndpointDirectory(
                adapter_id="adapter/dir-1",
                translations=(
                    IdentifierTranslation(
                        source=EndpointIdentifier(
                            scheme=IdentifierScheme.ALIAS, value="alice"
                        ),
                        target=iban_identifier(),
                    ),
                ),
            )
        with self.assertRaises(CoreValidationError):
            IdentifierTranslation(
                source=EndpointIdentifier(scheme=IdentifierScheme.ALIAS, value="alice"),
                target=EndpointIdentifier(scheme=IdentifierScheme.ALIAS, value="alice"),
            )
        with self.assertRaises(CoreValidationError):
            EndpointDirectory(
                adapter_id="interoperability/adapter/dir-1",
                translations=(
                    IdentifierTranslation(
                        source=EndpointIdentifier(
                            scheme=IdentifierScheme.ALIAS, value="alice"
                        ),
                        target=iban_identifier(),
                    ),
                    IdentifierTranslation(
                        source=EndpointIdentifier(
                            scheme=IdentifierScheme.ALIAS, value="alice"
                        ),
                        target=iban_identifier(value=OTHER_VALID_IBAN, jurisdiction="DE"),
                    ),
                ),
            )

    def test_directory_for_adapter_requires_resolution_capability(self) -> None:
        adapter = WorldAdapter(
            adapter_id="interoperability/adapter/status-only-1",
            capability_id="capability/status-only-1",
            observation_interface=ObservationInterface(
                operations=(ObservationOperation.PAYMENT_STATUS,)
            ),
            effect_interface=EffectInterface(),
            fidelity_class=FidelityClass.SIMULATION,
        )
        with self.assertRaises(CoreValidationError):
            EndpointDirectory.for_adapter(
                adapter,
                (
                    IdentifierTranslation(
                        source=EndpointIdentifier(scheme=IdentifierScheme.ALIAS, value="alice"),
                        target=iban_identifier(),
                    ),
                ),
            )

    def test_resolved_at_must_be_iso8601(self) -> None:
        with self.assertRaises(CoreValidationError):
            resolve_endpoint(
                iban_identifier(),
                (endpoint(),),
                resolution_id="interoperability/endpoint-resolution/res-0010",
                environment_id="env/test",
                domain_id="domain/demo",
                provenance=provenance(),
                resolved_at="not-a-timestamp",
            )


class StatusObservationTests(unittest.TestCase):
    """WORK-007: native observations map into the canonical lifecycle and guards block unsafe retries."""

    @staticmethod
    def observed_message(native_code: str) -> CanonicalPaymentMessage:
        resolution = resolve_endpoint(
            iban_identifier(),
            (endpoint(),),
            resolution_id="interoperability/endpoint-resolution/res-0100",
            environment_id="env/test",
            domain_id="domain/demo",
            provenance=provenance(),
            resolved_at=STAMP,
        )
        message = CanonicalPaymentMessage.create(
            message_id="interoperability/payment-message/msg-0100",
            destination=resolution.destination,
            instructed_amount=InstructedAmount(value=2500, scale=2, currency="USD"),
            end_to_end_id="e2e-0100",
            environment_id="env/test",
            domain_id="domain/demo",
            provenance=provenance(),
        )
        status_map = AdapterStatusMap(
            adapter_id="interoperability/adapter/domestic-ips-1",
            entries=(
                StatusMapEntry(native_code="INIT", canonical_status=CanonicalPaymentStatus.INITIATED),
                StatusMapEntry(native_code="AUTH", canonical_status=CanonicalPaymentStatus.AUTHORIZED),
                StatusMapEntry(native_code="BOOK", canonical_status=CanonicalPaymentStatus.CAPTURED_POSTED),
                StatusMapEntry(native_code="AMBIG", canonical_status=CanonicalPaymentStatus.UNKNOWN),
                StatusMapEntry(native_code="REJT", canonical_status=CanonicalPaymentStatus.FAILED),
            ),
        )
        return apply_status_observation(
            message, status_map, native_code, provenance=provenance()
        )

    def test_observation_maps_native_status_into_canonical_vocabulary(self) -> None:
        observed = self.observed_message("BOOK")
        self.assertEqual(observed.status, CanonicalPaymentStatus.CAPTURED_POSTED)
        self.assertEqual(observed.object_version, 2)

    def test_ambiguous_observation_lands_in_unknown_and_blocks_retry(self) -> None:
        observed = self.observed_message("AMBIG")
        self.assertEqual(observed.status, CanonicalPaymentStatus.UNKNOWN)
        self.assertTrue(requires_reconciliation(observed.status))
        with self.assertRaises(CoreValidationError):
            ensure_safe_for_resubmission(observed)

    def test_observation_of_undeclared_native_code_fails_closed(self) -> None:
        with self.assertRaises(CoreValidationError):
            self.observed_message("MYSTERY")

    def test_observation_preserves_destination_and_amount(self) -> None:
        observed = self.observed_message("AUTH")
        base = self.observed_message("INIT")
        self.assertEqual(observed.destination, base.destination)
        self.assertEqual(observed.instructed_amount, base.instructed_amount)
        self.assertEqual(observed.envelope.object_id, base.envelope.object_id)

    def test_observed_messages_round_trip(self) -> None:
        observed = self.observed_message("BOOK")
        encoded = observed.to_json()
        self.assertEqual(CanonicalPaymentMessage.from_json(encoded), observed)


class DomesticTranslationTests(unittest.TestCase):
    """WORK-007: adapters translate canonical messages into domestic shapes as pure projections."""

    def test_translate_to_domestic_projects_the_canonical_message(self) -> None:
        resolution = resolve_endpoint(
            iban_identifier(),
            (endpoint(),),
            resolution_id="interoperability/endpoint-resolution/res-0200",
            environment_id="env/test",
            domain_id="domain/demo",
            provenance=provenance(),
            resolved_at=STAMP,
        )
        message = CanonicalPaymentMessage.create(
            message_id="interoperability/payment-message/msg-0200",
            destination=resolution.destination,
            instructed_amount=InstructedAmount(value=2500, scale=2, currency="USD"),
            end_to_end_id="e2e-0200",
            environment_id="env/test",
            domain_id="domain/demo",
            provenance=provenance(),
        )
        adapter = WorldAdapter(
            adapter_id="interoperability/adapter/domestic-ips-1",
            capability_id="capability/domestic-ips-1",
            observation_interface=ObservationInterface(
                operations=(ObservationOperation.PAYMENT_STATUS,)
            ),
            effect_interface=EffectInterface(
                operations=(EffectOperation.SUBMIT_PAYMENT,),
                destination_schemes=(IdentifierScheme.IBAN,),
            ),
            fidelity_class=FidelityClass.SIMULATION,
        )
        instruction = translate_to_domestic(message, adapter)
        self.assertEqual(instruction.adapter_id, adapter.adapter_id)
        self.assertEqual(instruction.message_id, message.object_id)
        self.assertEqual(instruction.end_to_end_id, "e2e-0200")
        self.assertEqual(instruction.currency, "USD")
        self.assertEqual(instruction.amount_value, 2500)
        self.assertEqual(instruction.amount_scale, 2)
        self.assertEqual(instruction.destination_scheme, "IBAN")
        self.assertEqual(instruction.destination_value, VALID_IBAN)
        self.assertEqual(instruction.destination_jurisdiction, "GB")
        self.assertEqual(instruction.endpoint_id, resolution.destination.endpoint_id)
        self.assertEqual(
            DomesticInstruction.from_dict(instruction.to_dict()), instruction
        )

    def test_translation_requires_declared_submission_capability(self) -> None:
        resolution = resolve_endpoint(
            iban_identifier(),
            (endpoint(),),
            resolution_id="interoperability/endpoint-resolution/res-0201",
            environment_id="env/test",
            domain_id="domain/demo",
            provenance=provenance(),
            resolved_at=STAMP,
        )
        message = CanonicalPaymentMessage.create(
            message_id="interoperability/payment-message/msg-0201",
            destination=resolution.destination,
            instructed_amount=InstructedAmount(value=2500, scale=2, currency="USD"),
            end_to_end_id="e2e-0201",
            environment_id="env/test",
            domain_id="domain/demo",
            provenance=provenance(),
        )
        observation_only = WorldAdapter(
            adapter_id="interoperability/adapter/status-only-1",
            capability_id="capability/status-only-1",
            observation_interface=ObservationInterface(
                operations=(ObservationOperation.PAYMENT_STATUS,)
            ),
            effect_interface=EffectInterface(),
            fidelity_class=FidelityClass.SIMULATION,
        )
        with self.assertRaises(CoreValidationError):
            translate_to_domestic(message, observation_only)

    def test_translation_rejects_unsupported_destination_schemes(self) -> None:
        resolution = resolve_endpoint(
            iban_identifier(),
            (endpoint(),),
            resolution_id="interoperability/endpoint-resolution/res-0202",
            environment_id="env/test",
            domain_id="domain/demo",
            provenance=provenance(),
            resolved_at=STAMP,
        )
        message = CanonicalPaymentMessage.create(
            message_id="interoperability/payment-message/msg-0202",
            destination=resolution.destination,
            instructed_amount=InstructedAmount(value=2500, scale=2, currency="USD"),
            end_to_end_id="e2e-0202",
            environment_id="env/test",
            domain_id="domain/demo",
            provenance=provenance(),
        )
        wallet_only = WorldAdapter(
            adapter_id="interoperability/adapter/wallet-1",
            capability_id="capability/wallet-1",
            observation_interface=ObservationInterface(
                operations=(ObservationOperation.PAYMENT_STATUS,)
            ),
            effect_interface=EffectInterface(
                operations=(EffectOperation.SUBMIT_PAYMENT,),
                destination_schemes=(IdentifierScheme.WALLET_ADDRESS,),
            ),
            fidelity_class=FidelityClass.SIMULATION,
        )
        with self.assertRaises(CoreValidationError):
            translate_to_domestic(message, wallet_only)


class InteroperabilityDogfoodingTests(unittest.TestCase):
    """DOGFOOD-007: resolve a test endpoint through canonical and domestic-shaped adapters."""

    def test_test_endpoint_resolves_through_canonical_and_domestic_adapters(self) -> None:
        registered = endpoint(
            endpoint_id="interoperability/endpoint/ep-dogfood",
            identifiers=(
                iban_identifier(),
                EndpointIdentifier(scheme=IdentifierScheme.MERCHANT_ID, value="mid-77"),
            ),
        )

        domestic_adapter = WorldAdapter(
            adapter_id="interoperability/adapter/domestic-wallet-1",
            capability_id="capability/domestic-wallet-1",
            observation_interface=ObservationInterface(
                operations=(
                    ObservationOperation.RESOLVE_ENDPOINT,
                    ObservationOperation.PAYMENT_STATUS,
                )
            ),
            effect_interface=EffectInterface(
                operations=(EffectOperation.SUBMIT_PAYMENT,),
                destination_schemes=(IdentifierScheme.IBAN,),
            ),
            fidelity_class=FidelityClass.SIMULATION,
        )
        domestic_directory = EndpointDirectory.for_adapter(
            domestic_adapter,
            (
                IdentifierTranslation(
                    source=EndpointIdentifier(
                        scheme=IdentifierScheme.PHONE_NUMBER, value=VALID_PHONE, jurisdiction="VN"
                    ),
                    target=iban_identifier(),
                ),
            ),
        )
        status_map = AdapterStatusMap.for_adapter(
            domestic_adapter,
            (
                StatusMapEntry(native_code="INIT", canonical_status=CanonicalPaymentStatus.INITIATED),
                StatusMapEntry(native_code="AUTH", canonical_status=CanonicalPaymentStatus.AUTHORIZED),
                StatusMapEntry(native_code="BOOK", canonical_status=CanonicalPaymentStatus.CAPTURED_POSTED),
                StatusMapEntry(native_code="AMBIG", canonical_status=CanonicalPaymentStatus.UNKNOWN),
            ),
        )

        canonical_resolution = resolve_endpoint(
            iban_identifier(),
            (registered,),
            directories=(),
            resolution_id="interoperability/endpoint-resolution/res-canonical",
            environment_id="env/test",
            domain_id="domain/demo",
            provenance=provenance(),
            resolved_at=STAMP,
        )
        domestic_resolution = resolve_endpoint(
            EndpointIdentifier(
                scheme=IdentifierScheme.PHONE_NUMBER, value=VALID_PHONE, jurisdiction="VN"
            ),
            (registered,),
            directories=(domestic_directory,),
            resolution_id="interoperability/endpoint-resolution/res-domestic",
            environment_id="env/test",
            domain_id="domain/demo",
            provenance=provenance(),
            resolved_at=STAMP,
        )

        self.assertEqual(canonical_resolution.resolution_method, ResolutionMethod.CANONICAL)
        self.assertIsNone(canonical_resolution.adapter_id)
        self.assertEqual(
            canonical_resolution.destination.identifier.value, VALID_IBAN
        )
        self.assertEqual(
            domestic_resolution.resolution_method, ResolutionMethod.ADAPTER_ASSISTED
        )
        self.assertEqual(domestic_resolution.adapter_id, domestic_adapter.adapter_id)
        self.assertEqual(
            domestic_resolution.destination.endpoint_id, registered.object_id
        )
        self.assertEqual(
            domestic_resolution.destination.identifier.value, VALID_IBAN
        )

        message = CanonicalPaymentMessage.create(
            message_id="interoperability/payment-message/msg-dogfood",
            destination=domestic_resolution.destination,
            instructed_amount=InstructedAmount(value=2500, scale=2, currency="USD"),
            end_to_end_id="e2e-dogfood",
            environment_id="env/test",
            domain_id="domain/demo",
            provenance=provenance(),
            correlation_id="corr-dogfood",
        )
        instruction = translate_to_domestic(message, domestic_adapter)
        self.assertEqual(instruction.destination_value, VALID_IBAN)
        self.assertEqual(instruction.amount_value, 2500)

        authorized = apply_status_observation(
            message, status_map, "AUTH", provenance=provenance()
        )
        posted = apply_status_observation(
            authorized, status_map, "BOOK", provenance=provenance()
        )
        self.assertEqual(posted.status, CanonicalPaymentStatus.CAPTURED_POSTED)
        self.assertFalse(is_terminal_payment_status(posted.status))

        ambiguous = apply_status_observation(
            message, status_map, "AMBIG", provenance=provenance()
        )
        self.assertEqual(ambiguous.status, CanonicalPaymentStatus.UNKNOWN)
        self.assertTrue(requires_reconciliation(ambiguous.status))
        with self.assertRaises(CoreValidationError):
            ensure_safe_for_resubmission(ambiguous)

        for record in (
            registered,
            canonical_resolution,
            domestic_resolution,
            message,
            posted,
        ):
            encoded = record.to_json()
            self.assertEqual(type(record).from_json(encoded), record)


if __name__ == "__main__":
    unittest.main()
