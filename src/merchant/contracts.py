from __future__ import annotations

from enum import StrEnum

from src.core.errors import CoreValidationError
from src.transition.registry import PROTOCOL_VERSION, validate_event_type

API_VERSION = "v0.1"
SCHEMA_VERSION = 1
PROTOCOL = PROTOCOL_VERSION
EVENT_NAMESPACE = "intent"
CHECKOUT_OBJECT_TYPE = "merchant/checkout/v1"
ACCEPTANCE_OBJECT_TYPE = "merchant/acceptance/v1"
PROMISE_OBJECT_TYPE = "merchant/settlement-promise/v1"
REFUND_ROUTE_OBJECT_TYPE = "merchant/refund-route/v1"
OBJECT_TYPES = (ACCEPTANCE_OBJECT_TYPE, CHECKOUT_OBJECT_TYPE, PROMISE_OBJECT_TYPE, REFUND_ROUTE_OBJECT_TYPE)

COMMANDS = frozenset({
    "merchant/checkout.create",
    "merchant/checkout.accept",
    "merchant/checkout.promise",
    "merchant/checkout.refund-route",
})
EVENT_TYPES = {
    "merchant/checkout.create": "intent/merchant-checkout-created",
    "merchant/checkout.accept": "intent/merchant-checkout-accepted",
    "merchant/checkout.promise": "intent/merchant-settlement-promise-issued",
    "merchant/checkout.refund-route": "intent/merchant-refund-route-recorded",
}
for _event_type in EVENT_TYPES.values():
    validate_event_type("merchant event type", _event_type)


class CheckoutState(StrEnum):
    DRAFT = "DRAFT"
    ACCEPTED = "ACCEPTED"
    PROMISED = "PROMISED"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"


class PromiseState(StrEnum):
    PENDING = "PENDING"
    CREDITED = "CREDITED"
    SETTLED = "SETTLED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"


class RefundRouteState(StrEnum):
    OPEN = "OPEN"
    EXECUTED = "EXECUTED"
    CLOSED = "CLOSED"


def validate_command(command_type: str) -> None:
    if command_type not in COMMANDS:
        raise CoreValidationError(f"unknown merchant command type: {command_type}")
