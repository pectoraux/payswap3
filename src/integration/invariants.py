"""The IG-001 cross-layer invariant battery.

Every check here re-derives a property of the composed system from its
canonical representations, INDEPENDENTLY of the projections that produced
them, and fails closed with a precise reason through the single error
authority ``CoreValidationError``:

* double-entry integrity — every posting balances per asset, every journal
  trial-balances per asset, and the per-asset normal-side sheet balances;
* projection consistency — the ledger's derived balances equal an
  independent recomputation from the posting history, and the hold-derived
  ``HELD`` total equals the ledger ``ENCUMBERED`` view;
* money conservation — every recorded FX conversion satisfies the exact
  conservation identity of the money domain (re-verified by reconstructing
  the conversion through the real money API) and every residual allocation
  sums exactly to its allocated amount;
* envelope integrity — every value-domain record in the canonical ledger
  state decodes through its trusted deserialization path (verifying the
  core envelope seal and the domain composite seal), rejecting tampering;
* kernel journal integrity — every journal event's ``payload_hash`` equals
  the canonical digest of the payload it commits to;
* scale authority — every ledger asset scale equals the canonical money
  currency scale for its code;
* trace consistency — the intent terms, hold amounts, FX conversion,
  allocation, fee and posting legs recorded in the journal agree with each
  other exactly, end to end.

The functions are pure over canonical dictionaries so the same battery
runs on live gates, on snapshots and on rebuilt (replayed) state.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.money import (
    Amount as MoneyAmount,
    FxConversion,
    FxRate,
    RoundingMode,
    allocate_weighted,
    convert,
    get_currency,
)
from src.transition import EngineState
from src.value import (
    Account,
    Asset,
    FundingSource,
    Hold,
    Journal,
    Posting,
    Reconciliation,
    ValueInstrument,
)

from .contracts import (
    INTENT_AUTHORIZED_EVENT,
    INTENT_CREATED_EVENT,
    SETTLEMENT_RECONCILED_EVENT,
    SETTLEMENT_SUBMITTED_EVENT,
)

_LEDGER_VIEWS = ("AVAILABLE", "PENDING", "ENCUMBERED", "RESTRICTED", "SETTLED")

#: Collection name -> trusted deserialization class (single core seal
#: authority; the domain classes verify envelope and composite seals).
_STATE_DECODERS: tuple[tuple[str, Any], ...] = (
    ("assets", Asset),
    ("accounts", Account),
    ("journals", Journal),
    ("postings", Posting),
    ("holds", Hold),
    ("instruments", ValueInstrument),
    ("funding_sources", FundingSource),
    ("reconciliations", Reconciliation),
)


def _require_state(state: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(state, Mapping):
        raise CoreValidationError("ledger state must be a mapping")
    return dict(state)


# ---------------------------------------------------------------------------
# Double-entry integrity.
# ---------------------------------------------------------------------------


def _leg_sums(legs: Iterable[Mapping[str, Any]]) -> dict[str, dict[str, int]]:
    sums: dict[str, dict[str, int]] = {}
    for leg in legs:
        if not isinstance(leg, Mapping):
            raise CoreValidationError("posting legs must be objects")
        side = leg["side"]
        amount = leg["amount"]
        asset = amount["asset"]
        bucket = sums.setdefault(asset, {"DEBIT": 0, "CREDIT": 0})
        if side not in bucket:
            raise CoreValidationError(f"unknown posting leg side {side!r}")
        bucket[side] += amount["value"]
    return sums


def assert_postings_balance(state: Mapping[str, Any]) -> None:
    """Every posting balances per asset: Σ debits == Σ credits exactly."""
    state = _require_state(state)
    postings = state.get("postings")
    if not isinstance(postings, list):
        raise CoreValidationError("ledger state postings must be a list")
    for posting in postings:
        envelope = posting["envelope"]
        for asset, totals in _leg_sums(posting["payload"]["legs"]).items():
            if totals["DEBIT"] != totals["CREDIT"]:
                raise CoreValidationError(
                    f"posting {envelope['object_id']} is unbalanced: asset {asset} has "
                    f"debits {totals['DEBIT']} != credits {totals['CREDIT']}"
                )


def assert_trial_balance(state: Mapping[str, Any]) -> None:
    """Per journal, the per-asset totals over all postings balance."""
    state = _require_state(state)
    totals: dict[str, dict[str, dict[str, int]]] = {}
    for posting in state["postings"]:
        journal_id = posting["payload"]["journal_id"]
        bucket = totals.setdefault(journal_id, {})
        for asset, sums in _leg_sums(posting["payload"]["legs"]).items():
            asset_bucket = bucket.setdefault(asset, {"DEBIT": 0, "CREDIT": 0})
            asset_bucket["DEBIT"] += sums["DEBIT"]
            asset_bucket["CREDIT"] += sums["CREDIT"]
    for journal_id, bucket in totals.items():
        for asset, sums in sorted(bucket.items()):
            if sums["DEBIT"] != sums["CREDIT"]:
                raise CoreValidationError(
                    f"journal {journal_id} trial balance failed: asset {asset} has "
                    f"debits {sums['DEBIT']} != credits {sums['CREDIT']}"
                )


# ---------------------------------------------------------------------------
# Projection consistency.
# ---------------------------------------------------------------------------


def account_positions(state: Mapping[str, Any]) -> dict[str, dict[str, int]]:
    """Independent per-account normal-side view recomputation from postings."""
    state = _require_state(state)
    accounts: dict[str, dict[str, Any]] = {}
    for account in state.get("accounts", []):
        accounts[account["envelope"]["object_id"]] = account
    positions: dict[str, dict[str, int]] = {
        account_id: {view: 0 for view in _LEDGER_VIEWS}
        for account_id in accounts
    }
    for posting in state.get("postings", []):
        for leg in posting["payload"]["legs"]:
            account_id = leg["account_id"]
            account = accounts.get(account_id)
            if account is None:
                raise CoreValidationError(f"posting references unknown account {account_id}")
            credit_normal = account["payload"]["normal_side"] == "CREDIT"
            normal_credit = (leg["side"] == "CREDIT") == credit_normal
            view = leg["view"]
            if view not in positions[account_id]:
                raise CoreValidationError(f"posting leg carries unknown view {view!r}")
            positions[account_id][view] += (
                leg["amount"]["value"] if normal_credit else -leg["amount"]["value"]
            )
    return positions


def assert_balances_consistent(
    state: Mapping[str, Any], derived: Mapping[str, Mapping[str, Any]]
) -> None:
    """The ledger's derived balances equal the independent recomputation."""
    state = _require_state(state)
    positions = account_positions(state)
    accounts: dict[str, dict[str, Any]] = {
        account["envelope"]["object_id"]: account for account in state.get("accounts", [])
    }
    for account_id, balance in derived.items():
        if account_id not in accounts:
            raise CoreValidationError(f"derived balance for unknown account {account_id}")
        expected = positions[account_id]
        for view in _LEDGER_VIEWS:
            if balance[view.lower()] != expected[view]:
                raise CoreValidationError(
                    f"account {account_id} derived {view.lower()} "
                    f"{balance[view.lower()]} diverges from the posting history "
                    f"{expected[view]}"
                )
        recomputed_total = sum(expected[view] for view in _LEDGER_VIEWS)
        if balance["total"] != recomputed_total:
            raise CoreValidationError(
                f"account {account_id} derived total {balance['total']} diverges from "
                f"the posting history {recomputed_total}"
            )


def _active_hold_totals(state: Mapping[str, Any]) -> dict[str, int]:
    held: dict[str, int] = {}
    for hold in state.get("holds", []):
        if hold["envelope"]["state"] == "ACTIVE":
            account_id = hold["payload"]["account_id"]
            held[account_id] = held.get(account_id, 0) + hold["payload"]["amount"]["value"]
    return held


def assert_hold_view_reconciliation(state: Mapping[str, Any]) -> None:
    """For every account: Σ active-hold amounts == the ENCUMBERED view."""
    state = _require_state(state)
    positions = account_positions(state)
    held = _active_hold_totals(state)
    touched = set(held) | {account_id for account_id in positions if positions[account_id]["ENCUMBERED"]}
    for account_id in sorted(touched):
        expected_encumbered = positions[account_id]["ENCUMBERED"]
        expected_held = held.get(account_id, 0)
        if expected_encumbered != expected_held:
            raise CoreValidationError(
                f"account {account_id} held {expected_held} != encumbered "
                f"{expected_encumbered}; reservation evidence diverges"
            )


def assert_asset_sheets(state: Mapping[str, Any]) -> None:
    """Per asset, the normal-side account totals balance."""
    state = _require_state(state)
    positions = account_positions(state)
    sheets: dict[str, dict[str, int]] = {}
    for account in state.get("accounts", []):
        account_id = account["envelope"]["object_id"]
        asset = account["payload"]["asset"]
        bucket = sheets.setdefault(asset, {"debit_normal": 0, "credit_normal": 0})
        total = sum(positions[account_id][view] for view in _LEDGER_VIEWS)
        if account["payload"]["normal_side"] == "DEBIT":
            bucket["debit_normal"] += total
        else:
            bucket["credit_normal"] += total
    for asset, bucket in sorted(sheets.items()):
        if bucket["debit_normal"] != bucket["credit_normal"]:
            raise CoreValidationError(
                f"asset {asset} normal-side sheet is off by "
                f"{bucket['debit_normal'] - bucket['credit_normal']}: debit-normal "
                f"{bucket['debit_normal']} != credit-normal {bucket['credit_normal']}"
            )


# ---------------------------------------------------------------------------
# Money conservation.
# ---------------------------------------------------------------------------


def assert_money_conservation(journal_entries: Iterable[Mapping[str, Any]]) -> None:
    """Every recorded conversion conserves value exactly and every residual
    allocation sums exactly to the allocated amount.

    Conversions are re-verified by reconstructing the ``FxConversion``
    through the real money domain (which re-derives the deterministic
    rounded target and residual and rejects any tampering), then the exact
    conservation identity is restated; allocations are recomputed with the
    real allocator and their parts summed.
    """
    for entry in journal_entries:
        payload = entry["payload"]
        if not isinstance(payload, Mapping) or "effects" not in payload:
            continue
        for effect in payload.get("effects", ()):
            kind = effect["kind"]
            if kind == "convert":
                conversion = FxConversion.from_dict(effect["outputs"]["conversion"])
                scaled_numerator = (
                    conversion.source.value
                    * conversion.rate.numerator
                    * 10 ** conversion.rate.target.scale
                )
                if scaled_numerator != (
                    conversion.target.value * conversion.residual_denominator
                    + conversion.residual_numerator
                ):
                    raise CoreValidationError(
                        "fx conversion breaks the exact conservation identity"
                    )
                if not (
                    -conversion.residual_denominator
                    < conversion.residual_numerator
                    < conversion.residual_denominator
                ):
                    raise CoreValidationError(
                        "fx conversion residual magnitude must stay below its denominator"
                    )
            elif kind == "allocate":
                inputs = effect["inputs"]
                amount = MoneyAmount.from_dict(inputs["amount"])
                weights = list(inputs["weights"])
                recorded_parts = effect["outputs"]["parts"]
                recomputed = allocate_weighted(amount, weights)
                if [part.to_dict() for part in recomputed] != recorded_parts:
                    raise CoreValidationError(
                        "recorded allocation parts diverge from the deterministic "
                        "allocation of the money domain"
                    )
                total = sum(part["value"] for part in recorded_parts)
                if total != amount.value:
                    raise CoreValidationError(
                        f"allocation conservation violated: parts sum {total} != "
                        f"allocated amount {amount.value}"
                    )
            elif kind in ("hold_create", "hold_release", "post", "reconcile"):
                continue
            else:
                raise CoreValidationError(f"unknown ledger effect kind {kind!r}")


# ---------------------------------------------------------------------------
# Envelope and journal integrity.
# ---------------------------------------------------------------------------


def assert_state_integrity(state: Mapping[str, Any]) -> None:
    """Every value-domain record decodes through its trusted path."""
    state = _require_state(state)
    for collection, decoder in _STATE_DECODERS:
        records = state.get(collection, [])
        if not isinstance(records, list):
            raise CoreValidationError(f"ledger state {collection} must be a list")
        for record in records:
            decoder.from_dict(record)


def assert_journal_integrity(engine_state: Mapping[str, Any]) -> None:
    """Every journal event's payload hash commits to its exact payload."""
    if not isinstance(engine_state, Mapping):
        raise CoreValidationError("engine state must be a mapping")
    journal = engine_state.get("journal")
    if not isinstance(journal, list):
        raise CoreValidationError("engine state journal must be a list")
    for entry in journal:
        event = entry["event"]
        payload = entry["payload"]
        expected = canonical_sha256(payload if payload is not None else None)
        if event["payload_hash"] != expected:
            raise CoreValidationError(
                f"journal payload hash mismatch for event {event['event_id']}: the "
                f"recorded payload does not match the committed digest"
            )


def journal_digest_from_entries(entries: Iterable[Mapping[str, Any]]) -> str:
    """Canonical digest over the journal entries (events + payloads)."""
    return canonical_sha256([dict(entry) for entry in entries])


# ---------------------------------------------------------------------------
# Scale authority and end-to-end trace consistency.
# ---------------------------------------------------------------------------


def assert_scale_authority(state: Mapping[str, Any]) -> None:
    """Every ledger asset scale equals the canonical money currency scale."""
    state = _require_state(state)
    for asset in state.get("assets", []):
        code = asset["payload"]["code"]
        scale = asset["payload"]["scale"]
        currency = get_currency(code)
        if currency.scale != scale:
            raise CoreValidationError(
                f"asset {code} declares scale {scale}; the canonical money authority "
                f"requires {currency.scale}"
            )


def _effect_by_kind(payload: Mapping[str, Any], kind: str) -> Mapping[str, Any]:
    for effect in payload.get("effects", ()):
        if effect["kind"] == kind:
            return effect
    raise CoreValidationError(f"settlement payload misses the {kind} effect")


def _posting_leg_values(effect: Mapping[str, Any], side: str) -> list[int]:
    legs = effect["outputs"]["posting"]["payload"]["legs"]
    return [leg["amount"]["value"] for leg in legs if leg["side"] == side]


def assert_trace_consistency(journal_entries: Iterable[Mapping[str, Any]]) -> None:
    """The intent terms, hold amounts, conversion, allocation, fee and
    posting legs recorded in the journal agree exactly, end to end."""
    create_terms = None
    authorize_terms = None
    hold_id = None
    hold_amount = None
    for entry in journal_entries:
        event_type = entry["event"]["event_type"]
        payload = entry["payload"]
        terms = payload.get("terms", {})
        if event_type == INTENT_CREATED_EVENT:
            create_terms = terms
        elif event_type == INTENT_AUTHORIZED_EVENT:
            authorize_terms = terms
            hold_create = _effect_by_kind(payload, "hold_create")
            hold_id = hold_create["inputs"]["hold_id"]
            hold_amount = hold_create["inputs"]["amount"]["value"]
        elif event_type == SETTLEMENT_SUBMITTED_EVENT:
            if create_terms is None or authorize_terms is None:
                raise CoreValidationError(
                    "settlement submitted before the intent was authorized"
                )
            if create_terms["source_amount"] != authorize_terms["source_amount"]:
                raise CoreValidationError(
                    f"source_amount diverges between intent creation "
                    f"({create_terms['source_amount']}) and authorization "
                    f"({authorize_terms['source_amount']})"
                )
            if hold_id != terms["hold_id"]:
                raise CoreValidationError(
                    f"settlement holds {terms['hold_id']} but authorization reserved "
                    f"{hold_id}"
                )
            if hold_amount != authorize_terms["source_amount"]:
                raise CoreValidationError(
                    f"reserved amount {hold_amount} diverges from the authorized "
                    f"source_amount {authorize_terms['source_amount']}"
                )
            convert_effect = _effect_by_kind(payload, "convert")
            conversion = convert_effect["outputs"]["conversion"]
            if conversion["source"]["value"] != hold_amount:
                raise CoreValidationError(
                    f"conversion source {conversion['source']['value']} diverges from "
                    f"the reserved amount {hold_amount}"
                )
            allocate_effect = _effect_by_kind(payload, "allocate")
            parts_total = sum(part["value"] for part in allocate_effect["outputs"]["parts"])
            if parts_total != conversion["target"]["value"]:
                raise CoreValidationError(
                    f"allocation parts sum {parts_total} diverges from the converted "
                    f"target {conversion['target']['value']}"
                )
            fee_minor = terms.get("fee_minor")
            if fee_minor is None:
                raise CoreValidationError("settlement terms miss the explicit fee")
            fee_effect = next(
                effect
                for effect in payload["effects"]
                if effect["kind"] == "post" and effect["inputs"]["posting_class"] == "FEE"
            )
            fee_legs = _posting_leg_values(fee_effect, "DEBIT")
            if fee_legs != [fee_minor]:
                raise CoreValidationError(
                    f"fee posting legs {fee_legs} diverge from the declared fee {fee_minor}"
                )
            for effect in payload["effects"]:
                if effect["kind"] != "post":
                    continue
                if effect["inputs"]["posting_class"] == "FX":
                    source = effect["inputs"]["source_asset"]
                    if source == create_terms["source_asset"]:
                        if _posting_leg_values(effect, "DEBIT") != [hold_amount]:
                            raise CoreValidationError(
                                "FX source posting diverges from the reserved amount"
                            )
                    elif source == create_terms["target_asset"]:
                        if _posting_leg_values(effect, "CREDIT") != [
                            part["value"]
                            for part in allocate_effect["outputs"]["parts"]
                        ]:
                            raise CoreValidationError(
                                "FX target posting legs diverge from the allocation parts"
                            )
                    else:
                        raise CoreValidationError(
                            f"FX posting on undeclared asset {source}"
                        )
        elif event_type == SETTLEMENT_RECONCILED_EVENT:
            continue
        else:
            raise CoreValidationError(f"unknown gate event type {event_type!r}")


__all__ = [
    "account_positions",
    "assert_asset_sheets",
    "assert_balances_consistent",
    "assert_hold_view_reconciliation",
    "assert_journal_integrity",
    "assert_money_conservation",
    "assert_postings_balance",
    "assert_scale_authority",
    "assert_state_integrity",
    "assert_trace_consistency",
    "assert_trial_balance",
    "journal_digest_from_entries",
    "verify_invariants",
]


def verify_invariants(gate: Any) -> tuple[str, ...]:
    """Run the full cross-layer battery against one live gate.

    Returns the names of the executed checks (all of them — any breach
    raises ``CoreValidationError`` instead of returning). The battery runs
    after every accepted command and on every rebuilt (replayed) gate, so
    the composed state is never accepted silently.
    """
    state = gate.ledger_state()
    engine_state = gate.engine.snapshot_state().to_dict()
    entries = engine_state["journal"]
    checks: list[str] = []

    def run(name: str, check) -> None:
        check()
        checks.append(name)

    run("postings-balance-per-asset", lambda: assert_postings_balance(state))
    run("journal-trial-balance", lambda: assert_trial_balance(state))
    derived = {
        account["envelope"]["object_id"]: gate.ledger.derive_balances(
            account_id=account["envelope"]["object_id"]
        ).to_dict()
        for account in state["accounts"]
    }
    run("balances-match-posting-history", lambda: assert_balances_consistent(state, derived))
    run("hold-view-reconciliation", lambda: assert_hold_view_reconciliation(state))
    run("asset-sheets-balance", lambda: assert_asset_sheets(state))
    run("money-conservation", lambda: assert_money_conservation(entries))
    run("envelope-integrity", lambda: _verify_gate_envelopes(gate, state))
    run("journal-payload-integrity", lambda: assert_journal_integrity(engine_state))

    def _journal_digest_reproducible() -> None:
        live = gate.journal_digest()
        round_trip = EngineState.from_dict(engine_state)
        rebuilt = journal_digest_from_entries(entry.to_dict() for entry in round_trip.journal)
        if rebuilt != live:
            raise CoreValidationError(
                "kernel journal digest is not reproducible across the canonical "
                "round trip; the journal representation lost or altered semantics"
            )

    run("journal-digest-reproducible", _journal_digest_reproducible)
    run("scale-authority", lambda: assert_scale_authority(state))
    run("trace-consistency", lambda: assert_trace_consistency(entries))
    return tuple(checks)


def _verify_gate_envelopes(gate: Any, state: Mapping[str, Any]) -> None:
    assert_state_integrity(state)
    for envelope in gate.store.snapshot():
        envelope.verify_integrity()
