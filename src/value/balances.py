"""Balances: the derived, conservation-checked account positions.

``Balance`` is the DERIVED projection of one account's position in its
single asset at a ledger-wide posting ordinal. It exposes the six
derived balance views of the frozen ledger/posting model:

* ``available``, ``pending``, ``encumbered``, ``restricted`` and
  ``settled`` — the ledger views, computed from posting legs and
  normal-side adjusted (a debit-normal account's position increases
  with debits, a credit-normal account's with credits);
* ``held`` — the value reserved by active hold records (the ledger
  mirror of ``encumbered``; equality is the hold reconciliation
  invariant verified by the reconciliation record, and mid-flight
  divergence is preserved rather than hidden).

Conservation is a construction invariant: ``total`` equals the sum of
the five ledger views exactly, because postings only reclassify value
between views — no journal operation creates or destroys value. ``HELD``
is deliberately excluded from ``total``: it is a reservation record
view, not a separate pool of value.

Derived objects never outrank their source of truth: ``Balance`` is not
envelope-backed history, it is a deterministic, tamper-evident
projection (``derivation_hash`` is a canonical SHA-256 over the balance
content, verified on deserialization) whose authoritative source is the
journal and hold records. Object type ``value/balances/v1`` is internal
(non-registry).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_json, canonical_sha256, loads_canonical

from .contracts import BALANCE_OBJECT_TYPE, VALUE_PROTOCOL_VERSION, VALUE_SCHEMA_VERSION, BalanceView
from .validation import require_identifier, require_int, strict_fields

BALANCE_FIELDS = frozenset(
    {
        "object_type",
        "schema_version",
        "protocol_version",
        "account_id",
        "as_of_ordinal",
        "asset",
        "scale",
        "available",
        "pending",
        "encumbered",
        "restricted",
        "settled",
        "held",
        "total",
        "derivation_hash",
    }
)

_HEX = frozenset("0123456789abcdef")


@dataclass(frozen=True, slots=True)
class Balance:
    """Derived six-view balance of one account in one asset."""

    account_id: str
    as_of_ordinal: int
    asset: str
    scale: int
    available: int
    pending: int
    encumbered: int
    restricted: int
    settled: int
    held: int
    total: int
    derivation_hash: str

    def __post_init__(self) -> None:
        require_identifier("balance.account_id", self.account_id)
        require_int("balance.as_of_ordinal", self.as_of_ordinal, minimum=0)
        require_identifier("balance.asset", self.asset)
        require_int("balance.scale", self.scale, minimum=0)
        for name in ("available", "pending", "encumbered", "restricted", "settled", "held", "total"):
            require_int(f"balance.{name}", getattr(self, name))
        require_int("balance.held", self.held, minimum=0)
        if self.total != self.available + self.pending + self.encumbered + self.restricted + self.settled:
            raise CoreValidationError(
                "balance conservation violated: the total position must equal the sum of the "
                "five ledger views exactly; value is never created or destroyed"
            )
        if not isinstance(self.derivation_hash, str) or len(self.derivation_hash) != 64 or not set(self.derivation_hash) <= _HEX:
            raise CoreValidationError(
                "balance.derivation_hash must be a 64-character lowercase hex digest; use Balance.derive"
            )

    @classmethod
    def derive(
        cls,
        *,
        account_id: str,
        as_of_ordinal: int,
        asset: str,
        scale: int,
        available: int,
        pending: int,
        encumbered: int,
        restricted: int,
        settled: int,
        held: int,
    ) -> "Balance":
        total = available + pending + encumbered + restricted + settled
        core = {
            "object_type": BALANCE_OBJECT_TYPE,
            "schema_version": VALUE_SCHEMA_VERSION,
            "protocol_version": VALUE_PROTOCOL_VERSION,
            "account_id": account_id,
            "as_of_ordinal": as_of_ordinal,
            "asset": asset,
            "scale": scale,
            "available": available,
            "pending": pending,
            "encumbered": encumbered,
            "restricted": restricted,
            "settled": settled,
            "held": held,
            "total": total,
        }
        return cls(
            account_id=account_id,
            as_of_ordinal=as_of_ordinal,
            asset=asset,
            scale=scale,
            available=available,
            pending=pending,
            encumbered=encumbered,
            restricted=restricted,
            settled=settled,
            held=held,
            total=total,
            derivation_hash=canonical_sha256(core),
        )

    def view_value(self, view: BalanceView) -> int:
        """The normal-side position in the requested view (ints in minor units)."""
        if not isinstance(view, BalanceView):
            raise CoreValidationError("balance view must use the closed BalanceView vocabulary")
        if view == BalanceView.AVAILABLE:
            return self.available
        if view == BalanceView.HELD:
            return self.held
        if view == BalanceView.PENDING:
            return self.pending
        if view == BalanceView.ENCUMBERED:
            return self.encumbered
        if view == BalanceView.RESTRICTED:
            return self.restricted
        return self.settled

    def view_values(self) -> dict[str, int]:
        return {view.value: self.view_value(view) for view in BalanceView}

    def core_dict(self) -> dict[str, Any]:
        return {
            "object_type": BALANCE_OBJECT_TYPE,
            "schema_version": VALUE_SCHEMA_VERSION,
            "protocol_version": VALUE_PROTOCOL_VERSION,
            "account_id": self.account_id,
            "as_of_ordinal": self.as_of_ordinal,
            "asset": self.asset,
            "scale": self.scale,
            "available": self.available,
            "pending": self.pending,
            "encumbered": self.encumbered,
            "restricted": self.restricted,
            "settled": self.settled,
            "held": self.held,
            "total": self.total,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.core_dict(), "derivation_hash": self.derivation_hash}

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Balance":
        strict_fields("balance", value, BALANCE_FIELDS)
        if value["object_type"] != BALANCE_OBJECT_TYPE:
            raise CoreValidationError(
                f"balance object_type must be {BALANCE_OBJECT_TYPE!r}, got {value['object_type']!r}"
            )
        if value["schema_version"] != VALUE_SCHEMA_VERSION:
            raise CoreValidationError(
                f"balance schema_version must be {VALUE_SCHEMA_VERSION}, got {value['schema_version']!r}"
            )
        if value["protocol_version"] != VALUE_PROTOCOL_VERSION:
            raise CoreValidationError(
                f"balance rejects unknown protocol version {value['protocol_version']!r}; "
                f"expected {VALUE_PROTOCOL_VERSION!r}"
            )
        balance = cls(
            account_id=value["account_id"],
            as_of_ordinal=value["as_of_ordinal"],
            asset=value["asset"],
            scale=value["scale"],
            available=value["available"],
            pending=value["pending"],
            encumbered=value["encumbered"],
            restricted=value["restricted"],
            settled=value["settled"],
            held=value["held"],
            total=value["total"],
            derivation_hash=value["derivation_hash"],
        )
        if balance.derivation_hash != canonical_sha256(balance.core_dict()):
            raise CoreValidationError(
                f"derivation hash mismatch for balance of account {balance.account_id}"
            )
        return balance

    @classmethod
    def from_json(cls, value: str) -> "Balance":
        decoded = loads_canonical(value)
        if not isinstance(decoded, dict):
            raise CoreValidationError("balance JSON must decode to an object")
        return cls.from_dict(decoded)
