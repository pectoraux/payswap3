"""Merchant checkout and settlement-promise boundary (WORK-025).

This domain orchestrates merchant-facing state without becoming a second
payment compiler, ledger authority, or settlement authority.
"""

from src.core.envelope import Provenance
from src.core.errors import CoreValidationError

from .contracts import (
    ACCEPTANCE_OBJECT_TYPE, API_VERSION, CHECKOUT_OBJECT_TYPE, COMMANDS,
    EVENT_NAMESPACE, EVENT_TYPES, OBJECT_TYPES, PROMISE_OBJECT_TYPE, PROTOCOL,
    REFUND_ROUTE_OBJECT_TYPE, SCHEMA_VERSION, CheckoutState, PromiseState,
    RefundRouteState, validate_command,
)
from .records import (
    Acceptance, AcceptancePayload, Checkout, CheckoutSpec, RefundPayload,
    RefundRoute, SettlementPromise, SettlementPromiseSpec,
)
from .engine import ACTOR, AUTHORITY, MerchantEngine, MerchantTransition
from .seal import build_envelope, decode, decode_json, seal, to_dict, to_json, verify

__all__ = [
    "ACCEPTANCE_OBJECT_TYPE", "API_VERSION", "ACTOR", "AUTHORITY", "CHECKOUT_OBJECT_TYPE",
    "COMMANDS", "CoreValidationError", "EVENT_NAMESPACE", "EVENT_TYPES", "MerchantEngine",
    "MerchantTransition", "OBJECT_TYPES", "PROMISE_OBJECT_TYPE", "PROTOCOL", "Provenance",
    "REFUND_ROUTE_OBJECT_TYPE", "SCHEMA_VERSION", "Checkout", "CheckoutSpec", "CheckoutState",
    "Acceptance", "AcceptancePayload", "PromiseState", "RefundRoute", "RefundPayload",
    "RefundRouteState", "SettlementPromise", "SettlementPromiseSpec", "build_envelope", "seal",
    "verify", "to_dict", "to_json", "decode", "decode_json", "validate_command",
]
