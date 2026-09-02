"""The IG-001 composition harness.

``IntegrationGate`` binds ONE real transition kernel, ONE real value ledger
and the real money arithmetic together in one environment and one domain,
and drives the frozen payment lifecycle through kernel commands whose
handlers mutate the ledger through its public API only:

```text
integration/intent.create      → intent/created
integration/intent.authorize    → intent/authorized     (real hold_create)
integration/settlement.submit   → settlement/submitted  (real convert +
                                  allocate_weighted + hold_release + posts)
integration/settlement.reconcile→ settlement/reconciled (real reconcile)
```

The kernel owns the protocol intent/settlement object lifecycle
(registry-listed ``payswap/intent/v1`` and ``payswap/settlement/v1``
envelopes in its store); the ledger owns every accounting record; the
journal payloads carry the full ledger ``effects`` (operation inputs and
outputs) so the composed state can be rebuilt from the journal alone.

Failure discipline (fail closed, zero partial value state):

* every handler validates its whole step BEFORE the first ledger mutation
  (validate-then-apply, the WORK-003/WORK-005 remediation pattern): FX
  terms, quoted-payout equality with the exact conversion, positive fees,
  leg construction with per-asset balance and account/asset eligibility —
  a rejected step leaves the ledger byte-identical;
* kernel-level rejections (idempotency, environment, authorization,
  expected versions, policy) run before any handler, so they cannot mutate
  the ledger; the gate additionally asserts this after every rejection;
* every accepted command is followed by the full cross-layer invariant
  battery (:func:`src.integration.invariants.verify_invariants`).

No second authority: the kernel, the ledger and the money domain keep
their behavioral authorities; the gate only composes and asserts, raising
``CoreValidationError`` (the single error authority) with precise reasons.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.money import (
    Amount as MoneyAmount,
    FxRate,
    RoundingMode,
    allocate_weighted,
    convert,
    get_currency,
)
from src.transition import (
    AuthorizationDecision,
    Command,
    EngineState,
    MemoryStateStore,
    Outcome,
    TransitionApplication,
    TransitionEngine,
)
from src.transition.payload import payload_to_json_value
from src.value import (
    AccountState,
    Amount as ValueAmount,
    AssetKind,
    AssetState,
    BalanceView,
    EntrySide,
    Posting,
    PostingClass,
    PostingLeg,
    SegregationClass,
    ValueLedger,
)

from . import invariants
from .contracts import (
    DEFAULT_AUTHORIZED_ACTORS,
    EUR_ASSET_ID,
    FEE_INCOME_ACCOUNT,
    GATE_AUTHORITY_CLASS,
    GATE_JOURNAL_ID,
    GATE_PROVENANCE_SOURCE,
    INTENT_AUTHORIZE_COMMAND,
    INTENT_CREATE_COMMAND,
    INTENT_OBJECT_TYPE,
    PAYEE_ACCOUNT,
    PAYER_ACCOUNT,
    PROVISION_STAMP,
    SAVINGS_ACCOUNT,
    SETTLEMENT_OBJECT_TYPE,
    SETTLEMENT_RECONCILE_COMMAND,
    SETTLEMENT_SUBMIT_COMMAND,
    SOURCE_ASSET_CODE,
    TARGET_ASSET_CODE,
    USD_ASSET_ID,
    VAULT_ACCOUNT,
    house_account_id,
    validate_gate_id,
)

#: Intent lifecycle states of the kernel-level protocol projection.
INTENT_STATE_CREATED = "CREATED"
INTENT_STATE_AUTHORIZED = "AUTHORIZED"
INTENT_STATE_SETTLED = "SETTLED"

#: Settlement lifecycle states of the kernel-level protocol projection.
SETTLEMENT_STATE_SUBMITTED = "SUBMITTED"
SETTLEMENT_STATE_RECONCILED = "RECONCILED"


def _require_text(name: str, value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CoreValidationError(f"{name} must be a non-empty string")
    return value


def _require_positive_int(name: str, value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise CoreValidationError(f"{name} must be a positive integer")
    return value


def _payload_dict(command: Command) -> dict[str, Any]:
    decoded = payload_to_json_value(command.payload)
    if not isinstance(decoded, dict):
        raise CoreValidationError("gate command payloads must be objects")
    return decoded


class IntegrationGate:
    """One IG-001 composed environment: kernel + ledger + money."""

    def __init__(
        self,
        *,
        environment_id: str,
        domain_id: str,
        gate_id: str = "IG-001",
        authorized_actors: Iterable[str] = DEFAULT_AUTHORIZED_ACTORS,
    ) -> None:
        validate_gate_id(gate_id)
        self._gate_id = gate_id
        self._environment_id = _require_text("gate.environment_id", environment_id)
        self._domain_id = _require_text("gate.domain_id", domain_id)
        actors = frozenset(authorized_actors)
        if not actors:
            raise CoreValidationError("the gate requires at least one authorized actor")
        for actor in actors:
            _require_text("gate.authorized_actor", actor)
        self._authorized_actors = actors
        self._provisioned = False
        self._provisioning: dict[str, Any] = {}
        self._ledger = ValueLedger(
            environment_id=self._environment_id, domain_id=self._domain_id
        )
        self._store = MemoryStateStore()
        self._engine = self._build_engine(self._store)

    # ------------------------------------------------------------------
    # read-only access to the real composed implementations
    # ------------------------------------------------------------------

    @property
    def gate_id(self) -> str:
        return self._gate_id

    @property
    def environment_id(self) -> str:
        return self._environment_id

    @property
    def domain_id(self) -> str:
        return self._domain_id

    @property
    def authorized_actors(self) -> frozenset[str]:
        return self._authorized_actors

    @property
    def engine(self) -> TransitionEngine:
        """The real transition kernel driving this gate."""
        return self._engine

    @property
    def ledger(self) -> ValueLedger:
        """The real authoritative value ledger behind this gate."""
        return self._ledger

    @property
    def store(self) -> MemoryStateStore:
        """The kernel's authoritative object store."""
        return self._store

    # ------------------------------------------------------------------
    # deterministic environment provisioning
    # ------------------------------------------------------------------

    def provision(
        self, initial_deposit_minor: int | None = None, *, stamp: str = PROVISION_STAMP
    ) -> None:
        """Provision the deterministic environment: two assets, seven
        accounts, one ACTIVE journal and one funding deposit posting."""
        if self._provisioned:
            raise CoreValidationError(
                "the environment of this gate is already provisioned; provisioning is "
                "a one-shot deterministic bootstrap"
            )
        from .scenarios import DEFAULT_INITIAL_DEPOSIT_MINOR

        if initial_deposit_minor is None:
            initial_deposit_minor = DEFAULT_INITIAL_DEPOSIT_MINOR
        _require_positive_int("initial_deposit_minor", initial_deposit_minor)
        provenance = Provenance(
            issuer="principal/treasury",
            source=GATE_PROVENANCE_SOURCE,
            recorded_at=stamp,
        )
        self._ledger.register_asset(
            object_id=USD_ASSET_ID,
            code=SOURCE_ASSET_CODE,
            scale=get_currency(SOURCE_ASSET_CODE).scale,
            kind=AssetKind.FIAT,
            issuer_id="principal/treasury",
            provenance=provenance,
        )
        self._ledger.register_asset(
            object_id=EUR_ASSET_ID,
            code=TARGET_ASSET_CODE,
            scale=get_currency(TARGET_ASSET_CODE).scale,
            kind=AssetKind.FIAT,
            issuer_id="principal/treasury",
            provenance=provenance,
        )
        self._ledger.activate_asset(object_id=USD_ASSET_ID, provenance=provenance)
        self._ledger.activate_asset(object_id=EUR_ASSET_ID, provenance=provenance)
        accounts = (
            (PAYER_ACCOUNT, SOURCE_ASSET_CODE, SegregationClass.CUSTOMER, EntrySide.CREDIT, "principal/customer-7"),
            (PAYEE_ACCOUNT, TARGET_ASSET_CODE, SegregationClass.MERCHANT_RECEIVABLE, EntrySide.CREDIT, "principal/merchant-7"),
            (SAVINGS_ACCOUNT, TARGET_ASSET_CODE, SegregationClass.MERCHANT_RECEIVABLE, EntrySide.CREDIT, "principal/merchant-7"),
            (house_account_id(SOURCE_ASSET_CODE), SOURCE_ASSET_CODE, SegregationClass.NETWORK, EntrySide.DEBIT, "principal/treasury"),
            (house_account_id(TARGET_ASSET_CODE), TARGET_ASSET_CODE, SegregationClass.NETWORK, EntrySide.DEBIT, "principal/treasury"),
            (VAULT_ACCOUNT, SOURCE_ASSET_CODE, SegregationClass.NETWORK, EntrySide.DEBIT, "principal/treasury"),
            (FEE_INCOME_ACCOUNT, SOURCE_ASSET_CODE, SegregationClass.NETWORK, EntrySide.CREDIT, "principal/treasury"),
        )
        for object_id, asset_code, segregation, normal, owner in accounts:
            self._ledger.create_account(
                object_id=object_id,
                asset_code=asset_code,
                segregation_class=segregation,
                owner_id=owner,
                custodian_id="principal/custodian-1",
                normal_side=normal,
                provenance=provenance,
            )
            self._ledger.activate_account(object_id=object_id, provenance=provenance)
        self._ledger.open_journal(
            object_id=GATE_JOURNAL_ID,
            custodian_id="principal/custodian-1",
            description="IG-001 composed operations journal",
            provenance=provenance,
        )
        deposit = ValueAmount(
            value=initial_deposit_minor,
            scale=get_currency(SOURCE_ASSET_CODE).scale,
            asset=SOURCE_ASSET_CODE,
        )
        self._ledger.post(
            journal_id=GATE_JOURNAL_ID,
            posting_class=PostingClass.EXECUTION,
            legs=(
                PostingLeg(
                    account_id=VAULT_ACCOUNT,
                    side=EntrySide.DEBIT,
                    amount=deposit,
                    view=BalanceView.AVAILABLE,
                ),
                PostingLeg(
                    account_id=PAYER_ACCOUNT,
                    side=EntrySide.CREDIT,
                    amount=deposit,
                    view=BalanceView.AVAILABLE,
                ),
            ),
            description="environment funding deposit",
            provenance=provenance,
        )
        self._provisioned = True
        self._provisioning = {
            "initial_deposit_minor": initial_deposit_minor,
            "stamp": stamp,
        }

    # ------------------------------------------------------------------
    # command submission with cross-layer verification
    # ------------------------------------------------------------------

    def submit(self, command: Command):
        """Process one protocol command through the real kernel.

        Kernel rejections cannot mutate value state (they run before the
        handler); the gate asserts it. Accepted commands are followed by
        the full cross-layer invariant battery — the gate never silently
        accepts an invariant violation.
        """
        if not isinstance(command, Command):
            raise CoreValidationError("submit expects a Command envelope")
        ledger_digest_before = self._ledger.state_digest()
        result = self._engine.process(command)
        if result.outcome is Outcome.REJECTED:
            if self._ledger.state_digest() != ledger_digest_before:
                raise CoreValidationError(
                    f"kernel rejected command {command.command_id} but the value state "
                    "was mutated; failing closed on composed-state divergence"
                )
            return result
        if result.outcome is Outcome.ACCEPTED:
            invariants.verify_invariants(self)
        return result

    def current_version(self, object_ref: str) -> int:
        """Kernel-store version of one object (0 when absent)."""
        _require_text("object_ref", object_ref)
        envelope = self._store.get(object_ref)
        return 0 if envelope is None else envelope.object_version

    # ------------------------------------------------------------------
    # canonical state projection and digests
    # ------------------------------------------------------------------

    def ledger_state(self) -> dict[str, Any]:
        """The ledger's deterministic canonical state projection."""
        return self._ledger.canonical_state()

    def ledger_digest(self) -> str:
        return self._ledger.state_digest()

    def journal_digest(self) -> str:
        return invariants.journal_digest_from_entries(
            entry.to_dict() for entry in self._engine.journal
        )

    def kernel_digest(self) -> str:
        return canonical_sha256(
            {
                "engine": self._engine.snapshot_state().to_dict(),
                "store": [envelope.to_dict() for envelope in self._store.snapshot()],
            }
        )

    def _committed_engine_state(self) -> EngineState:
        """The committed kernel projection: accepted command records only.

        The kernel's idempotency ledger also records REJECTED commands (so a
        retry of a rejection converges to the original verdict instead of
        re-evaluating). Those records are retry-convergence bookkeeping, not
        committed state: no value moved and no object changed. The composed
        state digest deliberately projects the committed history, so a
        fail-closed rejection provably leaves the composed state untouched;
        the full kernel state (including rejection records) stays observable
        through :meth:`kernel_digest` and :meth:`snapshot`.
        """
        state = self._engine.snapshot_state()
        return EngineState(
            logical_time=state.logical_time,
            records=tuple(
                record
                for record in state.records
                if record.result.outcome is Outcome.ACCEPTED
            ),
            journal=state.journal,
        )

    def composed_digest(self) -> str:
        """Digest over the committed composed state (kernel + ledger).

        Kernel rejection records are excluded by design (see
        :meth:`_committed_engine_state`): a fail-closed rejection must leave
        the committed composed state byte-identical, which the gate asserts
        after every rejected command.
        """
        return canonical_sha256(
            {
                "gate_id": self._gate_id,
                "environment_id": self._environment_id,
                "domain_id": self._domain_id,
                "kernel": {
                    "engine": self._committed_engine_state().to_dict(),
                    "store": [envelope.to_dict() for envelope in self._store.snapshot()],
                },
                "ledger": self._ledger.canonical_state(),
            }
        )

    def snapshot(self) -> dict[str, Any]:
        """Canonical, byte-stable snapshot of the composed state."""
        return {
            "schema_version": 1,
            "gate_id": self._gate_id,
            "environment_id": self._environment_id,
            "domain_id": self._domain_id,
            "authorized_actors": sorted(self._authorized_actors),
            "provisioning": dict(self._provisioning),
            "engine": self._engine.snapshot_state().to_dict(),
            "store": [envelope.to_dict() for envelope in self._store.snapshot()],
            "ledger": self._ledger.canonical_state(),
        }

    # ------------------------------------------------------------------
    # kernel construction, handlers and shared effect application
    # ------------------------------------------------------------------

    def _build_engine(self, store: MemoryStateStore) -> TransitionEngine:
        engine = TransitionEngine(
            environment_id=self._environment_id,
            authorization=self._authorize,
            store=store,
        )
        engine.register(INTENT_CREATE_COMMAND, "intent/created", self._intent_create_handler)
        engine.register(
            INTENT_AUTHORIZE_COMMAND, "intent/authorized", self._intent_authorize_handler
        )
        engine.register(
            SETTLEMENT_SUBMIT_COMMAND, "settlement/submitted", self._settlement_submit_handler
        )
        engine.register(
            SETTLEMENT_RECONCILE_COMMAND,
            "settlement/reconciled",
            self._settlement_reconcile_handler,
        )
        return engine

    def _rebind_kernel(self, store: MemoryStateStore, engine_state: EngineState) -> None:
        """Rebuild the kernel onto a fresh store (journal-driven replay)."""
        self._store = store
        self._engine = self._build_engine(store)
        self._engine.restore_state(engine_state)

    def _authorize(self, command: Command, view) -> AuthorizationDecision:
        if command.actor in self._authorized_actors:
            return AuthorizationDecision(
                granted=True, authority=GATE_AUTHORITY_CLASS, reason=None
            )
        return AuthorizationDecision(
            granted=False,
            authority=None,
            reason=f"actor {command.actor} is not authorized in environment {self._environment_id}",
        )

    def _provenance(self, command: Command) -> Provenance:
        return Provenance(
            issuer=command.actor,
            source=GATE_PROVENANCE_SOURCE,
            recorded_at=command.requested_at,
        )

    # -- shared effect application (used by handlers AND replay) ---------

    def _apply_effect(self, kind: str, inputs: Mapping[str, Any]) -> dict[str, Any]:
        """Apply one recorded effect through the REAL domain APIs."""
        if kind == "convert":
            rate = FxRate.from_dict(dict(inputs["rate"]))
            source = MoneyAmount.from_dict(dict(inputs["source"]))
            mode = RoundingMode(inputs["mode"])
            conversion = convert(rate, source, mode)
            return {"conversion": conversion.to_dict()}
        if kind == "allocate":
            amount = MoneyAmount.from_dict(dict(inputs["amount"]))
            weights = list(inputs["weights"])
            parts = allocate_weighted(amount, weights)
            return {"parts": [part.to_dict() for part in parts]}
        if kind == "hold_create":
            amount = ValueAmount.from_dict(dict(inputs["amount"]))
            provenance = Provenance.from_dict(dict(inputs["provenance"]))
            hold = self._ledger.hold_create(
                journal_id=inputs["journal_id"],
                hold_id=inputs["hold_id"],
                account_id=inputs["account_id"],
                amount=amount,
                purpose=inputs.get("purpose"),
                provenance=provenance,
            )
            posting = self._last_posting(inputs["journal_id"])
            return {"hold": hold.to_dict(), "posting": posting.to_dict()}
        if kind == "hold_release":
            provenance = Provenance.from_dict(dict(inputs["provenance"]))
            hold = self._ledger.hold_release(
                journal_id=inputs["journal_id"],
                hold_id=inputs["hold_id"],
                provenance=provenance,
            )
            posting = self._last_posting(inputs["journal_id"])
            return {"hold": hold.to_dict(), "posting": posting.to_dict()}
        if kind == "post":
            legs = tuple(
                PostingLeg(
                    account_id=leg["account_id"],
                    side=EntrySide(leg["side"]),
                    amount=ValueAmount.from_dict(dict(leg["amount"])),
                    view=BalanceView(leg["view"]),
                )
                for leg in inputs["legs"]
            )
            posting = self._ledger.post(
                journal_id=inputs["journal_id"],
                posting_class=PostingClass(inputs["posting_class"]),
                legs=legs,
                provenance=Provenance.from_dict(dict(inputs["provenance"])),
                description=inputs.get("description"),
            )
            return {"posting": posting.to_dict()}
        if kind == "reconcile":
            provenance = Provenance.from_dict(dict(inputs["provenance"]))
            reconciliation = self._ledger.reconcile(
                journal_id=inputs["journal_id"],
                provenance=provenance,
            )
            journal = self._ledger.get_journal(inputs["journal_id"])
            return {
                "reconciliation": reconciliation.to_dict(),
                "journal": journal.to_dict(),
            }
        raise CoreValidationError(f"unknown ledger effect kind {kind!r}")

    def _last_posting(self, journal_id: str) -> Posting:
        postings = self._ledger.journal_postings(journal_id)
        return postings[-1]

    def _find_hold(self, hold_id: str) -> dict[str, Any]:
        for hold in self._ledger.canonical_state()["holds"]:
            if hold["envelope"]["object_id"] == hold_id:
                return hold
        raise CoreValidationError(f"unknown hold {hold_id} in this ledger")

    # -- pre-flight leg validation (before ANY ledger mutation) ----------

    def _preflight_legs(self, legs: tuple[PostingLeg, ...], label: str) -> None:
        debits: dict[str, int] = {}
        credits: dict[str, int] = {}
        for leg in legs:
            account = self._ledger.get_account(leg.account_id)
            if account.envelope.state != AccountState.ACTIVE.value:
                raise CoreValidationError(
                    f"{label} posting requires ACTIVE accounts; {leg.account_id} is "
                    f"{account.envelope.state}"
                )
            asset = self._ledger.get_asset(leg.amount.asset)
            if asset.envelope.state != AssetState.ACTIVE.value:
                raise CoreValidationError(
                    f"{label} posting requires an ACTIVE asset; {leg.amount.asset} is "
                    f"{asset.envelope.state}"
                )
            if not leg.amount.is_positive():
                raise CoreValidationError(
                    f"{label} posting requires positive leg amounts; got {leg.amount.value}"
                )
            if leg.amount.asset != account.payload.asset or leg.amount.scale != account.payload.scale:
                raise CoreValidationError(
                    f"{label} leg on account {leg.account_id} must use asset "
                    f"{account.payload.asset} at scale {account.payload.scale}"
                )
            bucket = debits if leg.side is EntrySide.DEBIT else credits
            bucket[leg.amount.asset] = bucket.get(leg.amount.asset, 0) + leg.amount.value
        for asset in sorted(set(debits) | set(credits)):
            if debits.get(asset, 0) != credits.get(asset, 0):
                raise CoreValidationError(
                    f"{label} posting is unbalanced: asset {asset} has debits "
                    f"{debits.get(asset, 0)} != credits {credits.get(asset, 0)}"
                )

    # -- transition handlers ----------------------------------------------

    def _intent_create_handler(self, command: Command, view) -> TransitionApplication:
        terms = _payload_dict(command)
        for key in ("originator", "beneficiary", "source_asset", "target_asset"):
            _require_text(f"intent.create.{key}", terms.get(key))
        _require_positive_int("intent.create.source_amount", terms.get("source_amount"))
        self._ledger.get_asset(terms["source_asset"])
        self._ledger.get_asset(terms["target_asset"])
        new_refs = [ref for ref in command.target_refs if view.get(ref) is None]
        if len(command.target_refs) != 1 or len(new_refs) != 1:
            raise CoreValidationError(
                "intent.create must target exactly one not-yet-existing intent object"
            )
        intent_ref = new_refs[0]
        envelope = ObjectEnvelope(
            object_id=intent_ref,
            object_type=INTENT_OBJECT_TYPE,
            object_version=1,
            environment_id=command.environment_id,
            domain_id=command.domain_id,
            schema_version=1,
            protocol_version="v0.1",
            state=INTENT_STATE_CREATED,
            provenance=self._provenance(command),
            causation_id=command.command_id,
            correlation_id=command.correlation_id,
        ).with_integrity_hash()
        return TransitionApplication(
            resulting_envelopes=(envelope,),
            payload={"terms": terms, "effects": ()},
        )

    def _intent_authorize_handler(self, command: Command, view) -> TransitionApplication:
        terms = _payload_dict(command)
        for key in ("source_asset", "account_id"):
            _require_text(f"intent.authorize.{key}", terms.get(key))
        source_amount = _require_positive_int(
            "intent.authorize.source_amount", terms.get("source_amount")
        )
        existing = [ref for ref in command.target_refs if view.get(ref) is not None]
        if len(command.target_refs) != 1 or len(existing) != 1:
            raise CoreValidationError(
                "intent.authorize must target exactly one existing intent object"
            )
        intent_ref = existing[0]
        intent = view.get(intent_ref)
        if intent.object_type != INTENT_OBJECT_TYPE:
            raise CoreValidationError(
                f"authorization target {intent_ref} is not an intent object"
            )
        if intent.state != INTENT_STATE_CREATED:
            raise CoreValidationError(
                f"authorization requires a {INTENT_STATE_CREATED} intent; {intent_ref} "
                f"is {intent.state}"
            )
        account = self._ledger.get_account(terms["account_id"])
        if account.payload.asset != terms["source_asset"]:
            raise CoreValidationError(
                f"account {terms['account_id']} holds asset {account.payload.asset}, "
                f"not {terms['source_asset']}"
            )
        hold_id = f"value/hold/{intent_ref.rsplit('/', 1)[-1]}"
        inputs = {
            "journal_id": GATE_JOURNAL_ID,
            "hold_id": hold_id,
            "account_id": terms["account_id"],
            "amount": {
                "value": source_amount,
                "scale": account.payload.scale,
                "asset": account.payload.asset,
            },
            "purpose": f"payment authorization for {intent_ref}",
            "provenance": self._provenance(command).to_dict(),
        }
        outputs = self._apply_effect("hold_create", inputs)
        effects = ({"kind": "hold_create", "inputs": inputs, "outputs": outputs},)
        advanced = intent.next_version(state=INTENT_STATE_AUTHORIZED).with_integrity_hash()
        return TransitionApplication(
            resulting_envelopes=(advanced,),
            payload={"terms": terms, "effects": effects},
        )

    def _settlement_submit_handler(self, command: Command, view) -> TransitionApplication:
        terms = _payload_dict(command)
        for key in ("hold_id", "target_asset"):
            _require_text(f"settlement.submit.{key}", terms.get(key))
        fee_minor = _require_positive_int("settlement.submit.fee_minor", terms.get("fee_minor"))
        rate_terms = terms.get("fx_rate")
        if not isinstance(rate_terms, Mapping):
            raise CoreValidationError("settlement.submit.fx_rate must be an object")
        rate_numerator = _require_positive_int(
            "settlement.submit.fx_rate.numerator", rate_terms.get("numerator")
        )
        rate_denominator = _require_positive_int(
            "settlement.submit.fx_rate.denominator", rate_terms.get("denominator")
        )
        weights = terms.get("allocation_weights")
        if not isinstance(weights, (list, tuple)) or not weights:
            raise CoreValidationError(
                "settlement.submit.allocation_weights must be a non-empty list of "
                "positive integers"
            )
        for weight in weights:
            _require_positive_int("settlement.submit.allocation_weights entry", weight)
        payout_accounts = terms.get("payout_accounts")
        if not isinstance(payout_accounts, (list, tuple)) or len(payout_accounts) != len(weights):
            raise CoreValidationError(
                "settlement.submit.payout_accounts must list one account per "
                "allocation weight"
            )
        for account_id in payout_accounts:
            _require_text("settlement.submit.payout_accounts entry", account_id)
        try:
            mode = RoundingMode(terms.get("rounding_mode"))
        except ValueError as exc:
            raise CoreValidationError(
                f"settlement.submit.rounding_mode must use the closed vocabulary, got "
                f"{terms.get('rounding_mode')!r}"
            ) from exc

        existing = {ref: view.get(ref) for ref in command.target_refs}
        intent_refs = [ref for ref, envelope in existing.items() if envelope is not None]
        new_refs = [ref for ref, envelope in existing.items() if envelope is None]
        if len(command.target_refs) != 2 or len(intent_refs) != 1 or len(new_refs) != 1:
            raise CoreValidationError(
                "settlement.submit must target one existing intent and one new "
                "settlement object"
            )
        intent = existing[intent_refs[0]]
        if intent.object_type != INTENT_OBJECT_TYPE:
            raise CoreValidationError(
                f"settlement target {intent_refs[0]} is not an intent object"
            )
        # The hold IS the authorization evidence: it must exist and be ACTIVE
        # before the intent state is consulted, so an unbacked settlement
        # surfaces the missing authorization (the unknown hold) first.
        hold = self._find_hold(terms["hold_id"])
        if hold["envelope"]["state"] != "ACTIVE":
            raise CoreValidationError(
                f"settlement can only draw from an ACTIVE hold; {terms['hold_id']} is "
                f"{hold['envelope']['state']}"
            )
        if intent.state != INTENT_STATE_AUTHORIZED:
            raise CoreValidationError(
                f"settlement requires an {INTENT_STATE_AUTHORIZED} intent; "
                f"{intent_refs[0]} is {intent.state}"
            )
        hold_amount = hold["payload"]["amount"]
        account_id = hold["payload"]["account_id"]
        source_asset = hold_amount["asset"]
        source_scale = hold_amount["scale"]
        target_asset = terms["target_asset"]
        source_currency = get_currency(source_asset)
        target_currency = get_currency(target_asset)
        target_record = self._ledger.get_asset(target_asset)
        if target_record.payload.scale != target_currency.scale:
            raise CoreValidationError(
                f"target asset {target_asset} scale {target_record.payload.scale} "
                f"diverges from the canonical money scale {target_currency.scale}"
            )
        rate = FxRate(
            source=source_currency,
            target=target_currency,
            numerator=rate_numerator,
            denominator=rate_denominator,
        )
        source_money = MoneyAmount(
            currency=source_currency, value=hold_amount["value"], scale=source_scale
        )
        conversion = convert(rate, source_money, mode)
        quoted_target = terms.get("quoted_target_minor")
        if quoted_target is not None:
            _require_positive_int("settlement.submit.quoted_target_minor", quoted_target)
            if quoted_target != conversion.target.value:
                raise CoreValidationError(
                    f"quoted payout {quoted_target} does not match the exact "
                    f"deterministic conversion {conversion.target.value}; settlement "
                    "refuses to diverge from the money authority"
                )
        parts = allocate_weighted(conversion.target, list(weights))
        provenance = self._provenance(command)

        hold_value_amount = ValueAmount(
            value=hold_amount["value"], scale=source_scale, asset=source_asset
        )
        fx_source_legs = (
            PostingLeg(
                account_id=account_id,
                side=EntrySide.DEBIT,
                amount=hold_value_amount,
                view=BalanceView.AVAILABLE,
            ),
            PostingLeg(
                account_id=house_account_id(source_asset),
                side=EntrySide.CREDIT,
                amount=hold_value_amount,
                view=BalanceView.AVAILABLE,
            ),
        )
        fee_amount = ValueAmount(
            value=fee_minor, scale=source_scale, asset=source_asset
        )
        fee_legs = (
            PostingLeg(
                account_id=account_id,
                side=EntrySide.DEBIT,
                amount=fee_amount,
                view=BalanceView.AVAILABLE,
            ),
            PostingLeg(
                account_id=FEE_INCOME_ACCOUNT,
                side=EntrySide.CREDIT,
                amount=fee_amount,
                view=BalanceView.AVAILABLE,
            ),
        )
        target_amount = ValueAmount(
            value=conversion.target.value,
            scale=conversion.target.scale,
            asset=target_asset,
        )
        fx_target_legs = (
            PostingLeg(
                account_id=house_account_id(target_asset),
                side=EntrySide.DEBIT,
                amount=target_amount,
                view=BalanceView.AVAILABLE,
            ),
        )
        for payout_account, part in zip(payout_accounts, parts):
            fx_target_legs = fx_target_legs + (
                PostingLeg(
                    account_id=payout_account,
                    side=EntrySide.CREDIT,
                    amount=ValueAmount(
                        value=part.value,
                        scale=part.scale,
                        asset=target_asset,
                    ),
                    view=BalanceView.AVAILABLE,
                ),
            )

        # Validate-then-apply: NO ledger mutation may happen before every
        # leg of this step passed the pre-flight (balance, positivity,
        # account/asset eligibility).
        self._preflight_legs(fx_source_legs, "fx source")
        self._preflight_legs(fee_legs, "fee")
        self._preflight_legs(fx_target_legs, "fx target")

        convert_inputs = {
            "rate": rate.to_dict(),
            "source": source_money.to_dict(),
            "mode": mode.value,
        }
        convert_outputs = self._apply_effect("convert", convert_inputs)
        allocate_inputs = {
            "amount": conversion.target.to_dict(),
            "weights": list(weights),
        }
        allocate_outputs = self._apply_effect("allocate", allocate_inputs)
        release_inputs = {
            "journal_id": GATE_JOURNAL_ID,
            "hold_id": terms["hold_id"],
            "provenance": provenance.to_dict(),
        }
        release_outputs = self._apply_effect("hold_release", release_inputs)
        fx_source_inputs = {
            "journal_id": GATE_JOURNAL_ID,
            "posting_class": PostingClass.FX.value,
            "legs": [leg.to_dict() for leg in fx_source_legs],
            "description": f"fx source leg for {intent_refs[0]}",
            "source_asset": source_asset,
            "provenance": provenance.to_dict(),
        }
        fx_source_outputs = self._apply_effect("post", fx_source_inputs)
        fee_inputs = {
            "journal_id": GATE_JOURNAL_ID,
            "posting_class": PostingClass.FEE.value,
            "legs": [leg.to_dict() for leg in fee_legs],
            "description": f"fx fee for {intent_refs[0]}",
            "source_asset": source_asset,
            "provenance": provenance.to_dict(),
        }
        fee_outputs = self._apply_effect("post", fee_inputs)
        fx_target_inputs = {
            "journal_id": GATE_JOURNAL_ID,
            "posting_class": PostingClass.FX.value,
            "legs": [leg.to_dict() for leg in fx_target_legs],
            "description": f"fx target leg for {intent_refs[0]}",
            "source_asset": target_asset,
            "provenance": provenance.to_dict(),
        }
        fx_target_outputs = self._apply_effect("post", fx_target_inputs)
        effects = (
            {"kind": "convert", "inputs": convert_inputs, "outputs": convert_outputs},
            {"kind": "allocate", "inputs": allocate_inputs, "outputs": allocate_outputs},
            {"kind": "hold_release", "inputs": release_inputs, "outputs": release_outputs},
            {"kind": "post", "inputs": fx_source_inputs, "outputs": fx_source_outputs},
            {"kind": "post", "inputs": fee_inputs, "outputs": fee_outputs},
            {"kind": "post", "inputs": fx_target_inputs, "outputs": fx_target_outputs},
        )
        intent_envelope = intent.next_version(state=INTENT_STATE_SETTLED).with_integrity_hash()
        settlement_envelope = ObjectEnvelope(
            object_id=new_refs[0],
            object_type=SETTLEMENT_OBJECT_TYPE,
            object_version=1,
            environment_id=command.environment_id,
            domain_id=command.domain_id,
            schema_version=1,
            protocol_version="v0.1",
            state=SETTLEMENT_STATE_SUBMITTED,
            provenance=provenance,
            causation_id=command.command_id,
            correlation_id=command.correlation_id,
        ).with_integrity_hash()
        return TransitionApplication(
            resulting_envelopes=(intent_envelope, settlement_envelope),
            payload={"terms": terms, "effects": effects},
        )

    def _settlement_reconcile_handler(self, command: Command, view) -> TransitionApplication:
        terms = _payload_dict(command)
        journal_id = _require_text("settlement.reconcile.journal_id", terms.get("journal_id"))
        existing = [ref for ref in command.target_refs if view.get(ref) is not None]
        if len(command.target_refs) != 1 or len(existing) != 1:
            raise CoreValidationError(
                "settlement.reconcile must target exactly one existing settlement object"
            )
        settlement_ref = existing[0]
        settlement = view.get(settlement_ref)
        if settlement.object_type != SETTLEMENT_OBJECT_TYPE:
            raise CoreValidationError(
                f"reconciliation target {settlement_ref} is not a settlement object"
            )
        if settlement.state != SETTLEMENT_STATE_SUBMITTED:
            raise CoreValidationError(
                f"reconciliation requires a {SETTLEMENT_STATE_SUBMITTED} settlement; "
                f"{settlement_ref} is {settlement.state}"
            )
        journal = self._ledger.get_journal(journal_id)
        del journal
        inputs = {
            "journal_id": journal_id,
            "provenance": self._provenance(command).to_dict(),
        }
        outputs = self._apply_effect("reconcile", inputs)
        effects = ({"kind": "reconcile", "inputs": inputs, "outputs": outputs},)
        advanced = settlement.next_version(
            state=SETTLEMENT_STATE_RECONCILED
        ).with_integrity_hash()
        return TransitionApplication(
            resulting_envelopes=(advanced,),
            payload={"terms": terms, "effects": effects},
        )
