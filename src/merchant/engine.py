from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from src.core.envelope import Provenance
from src.core.errors import CoreValidationError
from src.transition import AuthorizationDecision, Command, ExpectedVersion, MemoryStateStore, Outcome, TransitionEngine, TransitionResult
from src.transition.payload import payload_to_json_value

from ._validation import text, timestamp
from .contracts import EVENT_TYPES, CheckoutState, validate_command
from .records import Acceptance, Checkout, CheckoutSpec, RefundRoute, SettlementPromise, SettlementPromiseSpec

ACTOR = "principal/merchant-service"
AUTHORITY = "A4"


@dataclass(frozen=True, slots=True)
class MerchantTransition:
    command_id: str
    command_type: str
    result: TransitionResult

    @property
    def outcome(self) -> Outcome:
        return self.result.outcome

    @property
    def reason(self):
        return self.result.reason


class MerchantEngine:
    """Kernel-bound merchant checkout surface; settlement remains authoritative elsewhere."""

    def __init__(self, *, environment_id: str, domain_id: str, actor: str = ACTOR,
                 authorized_actors: Iterable[str] = ()) -> None:
        text("environment_id", environment_id)
        text("domain_id", domain_id)
        text("actor", actor)
        self.environment_id = environment_id
        self.domain_id = domain_id
        self.actor = actor
        self.authorized_actors = frozenset({actor, *authorized_actors})
        self.store = MemoryStateStore()
        self.kernel = TransitionEngine(environment_id, authorization=self._authorize, store=self.store)
        self.records: dict[str, Any] = {}
        self._known_checkout_ids: set[str] = set()
        self._register_handlers()

    def _register_handlers(self) -> None:
        self.kernel.register("merchant/checkout.create", EVENT_TYPES["merchant/checkout.create"], self._handle_create)
        self.kernel.register("merchant/checkout.accept", EVENT_TYPES["merchant/checkout.accept"], self._handle_accept)
        self.kernel.register("merchant/checkout.promise", EVENT_TYPES["merchant/checkout.promise"], self._handle_promise)
        self.kernel.register("merchant/checkout.refund-route", EVENT_TYPES["merchant/checkout.refund-route"], self._handle_refund_route)

    def _authorize(self, command: Command, _view) -> AuthorizationDecision:
        granted = command.actor in self.authorized_actors
        return AuthorizationDecision(granted=granted, authority=AUTHORITY if granted else None,
                                     reason=None if granted else "merchant actor not authorized")

    def _payload(self, command: Command) -> dict[str, Any]:
        payload = payload_to_json_value(command.payload)
        if not isinstance(payload, dict):
            raise CoreValidationError("merchant payload must be an object")
        return payload

    def _provenance(self, command: Command) -> Provenance:
        return Provenance(issuer=command.actor, source="merchant-engine", recorded_at=command.requested_at,
                          evidence_refs=(command.command_id,))

    def _handle_create(self, command, _view):
        spec = CheckoutSpec.from_dict(self._payload(command))
        if spec.checkout_id in self._known_checkout_ids:
            raise CoreValidationError(f"checkout {spec.checkout_id} already exists")
        checkout = Checkout.create(spec=spec, environment_id=self.environment_id, domain_id=self.domain_id,
                                   provenance=self._provenance(command))
        self.records[spec.checkout_id] = checkout
        self._known_checkout_ids.add(spec.checkout_id)
        return TransitionApplication((checkout.envelope,), payload=checkout.to_dict())

    def _handle_accept(self, command, _view):
        payload = self._payload(command)
        checkout = self._require(payload["checkout_id"], Checkout)
        acceptance = Acceptance.create(checkout=checkout, merchant_id=payload["merchant_id"],
                                       provenance=self._provenance(command), accepted_at=payload["accepted_at"])
        updated = checkout.advance(CheckoutState.ACCEPTED, self._provenance(command), command.command_id)
        self.records[updated.spec.checkout_id] = updated
        self.records[acceptance.acceptance_id] = acceptance
        return TransitionApplication((updated.envelope, acceptance.envelope),
                                      payload={"checkout": updated.to_dict(), "acceptance": acceptance.to_dict()})

    def _handle_promise(self, command, _view):
        payload = self._payload(command)
        checkout = self._require(payload["checkout_id"], Checkout)
        spec = SettlementPromiseSpec.from_dict(payload["promise"])
        if spec.checkout_id != checkout.spec.checkout_id or spec.merchant_id != checkout.spec.merchant_id:
            raise CoreValidationError("settlement promise does not bind to checkout")
        promise = SettlementPromise.create(spec=spec, environment_id=self.environment_id, domain_id=self.domain_id,
                                           provenance=self._provenance(command))
        updated = checkout.advance(CheckoutState.PROMISED, self._provenance(command), command.command_id)
        self.records[updated.spec.checkout_id] = updated
        self.records[promise.spec.promise_id] = promise
        return TransitionApplication((updated.envelope, promise.envelope),
                                      payload={"checkout": updated.to_dict(), "promise": promise.to_dict()})

    def _handle_refund_route(self, command, _view):
        payload = self._payload(command)
        checkout = self._require(payload["checkout_id"], Checkout)
        route = RefundRoute.create(checkout=checkout, route_id=payload["route_id"],
                                   settlement_id=payload["settlement_id"], provenance=self._provenance(command))
        self.records[route.route_id] = route
        return TransitionApplication((route.envelope,), payload=route.to_dict())

    def _require(self, object_id: str, expected: type) -> Any:
        record = self.records.get(object_id)
        if not isinstance(record, expected):
            raise CoreValidationError(f"merchant object {object_id} not found")
        return record

    def submit(self, command: Command) -> MerchantTransition:
        validate_command(command.command_type)
        return MerchantTransition(command.command_id, command.command_type, self.kernel.process(command))

    def command(self, *, command_id: str, command_type: str, payload: Any, target_refs: tuple[str, ...],
                expected_versions: tuple[ExpectedVersion, ...] = (), requested_at: str,
                idempotency_key: str | None = None, nonce: str = "merchant-command-1") -> Command:
        validate_command(command_type)
        timestamp("requested_at", requested_at)
        return Command.build(command_id=command_id, command_type=command_type, actor=self.actor,
                             target_refs=target_refs, payload=payload, environment_id=self.environment_id,
                             domain_id=self.domain_id, idempotency_key=idempotency_key or command_id,
                             nonce=nonce, requested_at=requested_at, expected_versions=expected_versions)
