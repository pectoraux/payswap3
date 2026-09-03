"""Kernel-bound engine for the clearing domain (WORK-015).

The :class:`ClearingEngine` binds every command of the frozen
``Clearing``/``Obligation``/``Netting`` families (18 command types) to
the REAL transition kernel (:class:`src.transition.TransitionEngine`):
validate-then-compute handlers produce
:class:`~src.transition.TransitionApplication` records that the kernel
commits and journals; the domain index is re-populated only through the
trusted decode path (seal verification included), both for live commits
and journal rebuilds.

Authority discipline (constitution invariant 3 — authority before
financial effect):

* the operator gate authorizes actors at the engine boundary (kernel
  stage 4);
* obligation recognition consumes the execution domain's sealed
  ``EffectResult`` evidence (WORK-014) through its trusted decode path
  and derives the economic facts itself — payload-carried economics are
  never trusted;
* every evidence-bearing obligation command (dispute, restructure,
  default, resolve) requires ``OBSERVED`` epistemic evidence (the
  frozen ``src.evidence`` vocabulary, WORK-018);
* ``MarkDue`` funding evidence uses the reservation domain's closed
  ``ReservationState`` vocabulary (WORK-012) — only ``HELD`` covers a
  due obligation;
* netting finalization RE-DERIVES the complete statement from the
  current members and verifies the digest before resolving anything
  (fabricated or stale statements fail closed);
* this engine never settles and never claims finality (WORK-016 owns
  settlement/finality; constitution invariant 11).
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Iterable, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.value.amount import Amount
from src.core.errors import CoreValidationError
from src.execution.contracts import EffectOutcome
from src.execution.effects import EffectResult
from src.transition import (
    AuthorizationDecision,
    Command,
    ExpectedVersion,
    MemoryStateStore,
    Outcome,
    RejectionReason,
    TransitionApplication,
    TransitionEngine,
    TransitionResult,
)
from src.transition.engine import EngineState
from src.transition.payload import payload_to_json_value
from src.transition.registry import validate_authority_class

from ._validation import (
    parse_utc_timestamp,
    require_identifier,
    require_mapping,
    require_text,
    require_utc_timestamp,
    strict_fields,
)
from .contracts import (
    COMMAND_EVENT_TYPES,
    CLEARING_ALL_COMMANDS,
    CLEARING_CYCLE_OBJECT_TYPE,
    NETTING_CYCLE_OBJECT_TYPE,
    OBLIGATION_OBJECT_TYPE,
    OBLIGATION_VALIDATED_STATES,
    ClearingCycleState,
    NettingCycleState,
    NettingMode,
    ObligationSourceKind,
    ObligationState,
    ResolutionKind,
)
from .cycle import (
    ClearingCycle,
    ClearingCycleSpec,
    RecognitionWindow,
    compute_clearing_statement,
    make_cycle_record,
)
from .netting import (
    NettingCycle,
    NettingCycleSpec,
    ValuationSpec,
    compute_netting_statement,
    derive_issued_obligation,
    make_netting_record,
    parse_calculate_payload,
    parse_create_netting_payload,
    parse_member_payload,
    parse_reason_payload,
)
from .obligations import (
    AmendmentRecord,
    DefaultRecord,
    DisputeRecord,
    DueRecord,
    Obligation,
    ObligationSpec,
    ResolutionRecord,
    RestructureRecord,
    make_obligation_record,
    parse_amend_payload,
    parse_evidence_payload,
    parse_mark_due_payload,
    parse_recognize_payload,
    parse_resolve_payload,
    parse_restructure_payload,
)
from .seal import advance_envelope, seal_composite

DEFAULT_ENGINE_ACTOR = "principal/clearing-service"

#: Default command authority class (the operator tier that drives
#: clearing commands; financial-effect authority for the chain is
#: upstream in execution — WORK-014 — and downstream in settlement —
#: WORK-016).
DEFAULT_COMMAND_AUTHORITY_CLASS = "A3"

_COMMAND_NONCE = "clearing-command-1"

#: The canonical payment-leg detail shape the recognition path requires:
#: an execution effect result's ``detail`` must carry exactly these
#: fields for the obligation facts to be derived from it.
_PAYMENT_LEG_FIELDS = frozenset({"payer", "payee", "asset", "amount"})

_CREATE_CYCLE_PAYLOAD_FIELDS = frozenset({"cycle_id", "window", "description"})
_EMPTY_PAYLOAD_FIELDS = frozenset()
_CANCEL_CYCLE_PAYLOAD_FIELDS = frozenset({"reason"})

_SNAPSHOT_FIELDS = frozenset(
    {
        "schema_version",
        "environment_id",
        "domain_id",
        "index",
        "engine",
        "store",
    }
)

_RECORD_DECODERS = {
    CLEARING_CYCLE_OBJECT_TYPE: ClearingCycle.from_dict,
    OBLIGATION_OBJECT_TYPE: Obligation.from_dict,
    NETTING_CYCLE_OBJECT_TYPE: NettingCycle.from_dict,
}


def _payload_dict(command: Command) -> dict[str, Any]:
    """Decode the command payload into the canonical JSON object form."""
    decoded = payload_to_json_value(command.payload)
    if not isinstance(decoded, dict):
        raise CoreValidationError("clearing command payloads must be objects")
    return decoded


def _journal_payload(entry: Any) -> Any:
    payload = payload_to_json_value(entry.payload) if entry.payload is not None else {}
    if not isinstance(payload, dict):
        raise CoreValidationError("clearing journal payloads must be objects")
    return payload


@dataclass(frozen=True, slots=True)
class ClearingTransition:
    """Explicit decision record for one processed clearing command.

    ``outcome`` mirrors the kernel outcome (``accepted`` / ``rejected`` /
    ``duplicate``); rejections carry a closed-vocabulary ``reason``;
    duplicates echo the original decision without emitting a new event.
    """

    command_id: str
    command_type: str
    outcome: Outcome
    reason: RejectionReason | None
    detail: str | None
    result: TransitionResult

    def __post_init__(self) -> None:
        require_text("transition.command_id", self.command_id)
        require_text("transition.command_type", self.command_type)
        if not isinstance(self.outcome, Outcome):
            raise CoreValidationError("transition outcome must use the kernel vocabulary")
        if self.detail is not None:
            require_text("transition.detail", self.detail)
        if not isinstance(self.result, TransitionResult):
            raise CoreValidationError("transition result must be a TransitionResult")
        if self.result.outcome is not self.outcome:
            raise CoreValidationError("transition outcome must mirror the kernel result")
        if self.reason != self.result.reason:
            raise CoreValidationError("transition reason must mirror the kernel result")


class ClearingEngine:
    """Kernel-bound engine for the clearing domain (WORK-015).

    The engine owns the domain index (sealed composite records rebuilt
    through the trusted decode path) and one real transition kernel per
    environment. It recognizes obligations from execution evidence,
    drives the clearing-cycle, obligation and netting-cycle lifecycles,
    and computes the deterministic gross-to-net statements. It never
    settles, never posts and never claims finality.
    """

    def __init__(
        self,
        *,
        environment_id: str,
        domain_id: str,
        actor: str = DEFAULT_ENGINE_ACTOR,
        command_authority_class: str = DEFAULT_COMMAND_AUTHORITY_CLASS,
        authorized_actors: Iterable[str] = (),
    ) -> None:
        require_text("engine environment_id", environment_id)
        require_text("engine domain_id", domain_id)
        require_text("engine actor", actor)
        validate_authority_class("engine command_authority_class", command_authority_class)
        extra_actors = set(authorized_actors)
        for extra in extra_actors:
            require_text("engine authorized actor", extra)
        self._environment_id = environment_id
        self._domain_id = domain_id
        self._actor = actor
        self._command_authority_class = command_authority_class
        self._authorized_actors = frozenset({actor} | extra_actors)
        self._store = MemoryStateStore()
        self._kernel = self._build_kernel()
        self._records: dict[str, Any] = {}
        self._transitions: list[ClearingTransition] = []

    # ------------------------------------------------------------------
    # construction and kernel binding
    # ------------------------------------------------------------------

    @property
    def environment_id(self) -> str:
        return self._environment_id

    @property
    def domain_id(self) -> str:
        return self._domain_id

    @property
    def journal(self) -> tuple[Any, ...]:
        return self._kernel.journal

    def _build_kernel(self) -> TransitionEngine:
        kernel = TransitionEngine(
            self._environment_id,
            authorization=self._authorize,
            store=self._store,
        )
        registrations = (
            ("clearing/cycle.create", self._handle_cycle_create),
            ("clearing/cycle.validate", self._handle_cycle_validate),
            ("clearing/cycle.finalize", self._handle_cycle_finalize),
            ("clearing/cycle.cancel", self._handle_cycle_cancel),
            ("clearing/obligation.create", self._handle_obligation_create),
            ("clearing/obligation.validate", self._handle_obligation_validate),
            ("clearing/obligation.amend", self._handle_obligation_amend),
            ("clearing/obligation.dispute", self._handle_obligation_dispute),
            ("clearing/obligation.restructure", self._handle_obligation_restructure),
            ("clearing/obligation.mark-due", self._handle_obligation_mark_due),
            ("clearing/obligation.default", self._handle_obligation_default),
            ("clearing/obligation.resolve", self._handle_obligation_resolve),
            ("clearing/netting.create", self._handle_netting_create),
            ("clearing/netting.add", self._handle_netting_add),
            ("clearing/netting.remove", self._handle_netting_remove),
            ("clearing/netting.calculate", self._handle_netting_calculate),
            ("clearing/netting.finalize", self._handle_netting_finalize),
            ("clearing/netting.cancel", self._handle_netting_cancel),
        )
        for command_type, handler in registrations:
            event_type = COMMAND_EVENT_TYPES[command_type]
            kernel.register(command_type, event_type, handler)
        return kernel

    def _authorize(self, command: Command, view: Any) -> AuthorizationDecision:
        """Command-level authorization: the operator gate."""
        if command.actor in self._authorized_actors:
            return AuthorizationDecision(
                granted=True,
                authority=self._command_authority_class,
                reason=None,
            )
        return AuthorizationDecision(
            granted=False,
            authority=None,
            reason=(
                f"actor {command.actor!r} is not authorized to drive clearing "
                f"in environment {self._environment_id!r}"
            ),
        )

    def _provenance(self, command: Command) -> Provenance:
        return Provenance(
            issuer=command.actor,
            source="clearing/domain",
            recorded_at=command.requested_at,
        )

    # ------------------------------------------------------------------
    # command construction and submission
    # ------------------------------------------------------------------

    def build_raw_command(
        self,
        *,
        command_id: str,
        command_type: str,
        requested_at: str,
        target_refs: Iterable[str],
        payload: Any,
        environment_id: str | None = None,
        domain_id: str | None = None,
        actor: str | None = None,
        expected_versions: Mapping[str, int] | Iterable[ExpectedVersion] | None = None,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> Command:
        """Build a kernel command envelope against this engine's binding.

        ``expected_versions`` accepts either a mapping
        ``{object_ref: version}`` or an iterable of
        :class:`~src.transition.command.ExpectedVersion`. The command's
        idempotency key is derived deterministically from the command id.
        """
        require_text("command_id", command_id)
        require_text("command_type", command_type)
        require_utc_timestamp("requested_at", requested_at)
        targets = tuple(target_refs)
        if not targets:
            raise CoreValidationError("target_refs must declare at least one target object")
        for target in targets:
            require_text("target_ref", target)
        if expected_versions is None:
            expected: tuple[ExpectedVersion, ...] = ()
        elif isinstance(expected_versions, Mapping):
            expected = tuple(
                ExpectedVersion(object_ref=ref, object_version=version)
                for ref, version in expected_versions.items()
            )
        else:
            expected = tuple(expected_versions)
            for item in expected:
                if not isinstance(item, ExpectedVersion):
                    raise CoreValidationError(
                        "expected_versions entries must be ExpectedVersion records"
                    )
        return Command.build(
            command_id=command_id,
            command_type=command_type,
            actor=actor if actor is not None else self._actor,
            target_refs=targets,
            payload=payload,
            environment_id=environment_id if environment_id is not None else self._environment_id,
            domain_id=domain_id if domain_id is not None else self._domain_id,
            expected_versions=expected,
            idempotency_key=f"clearing:{command_id}",
            nonce=_COMMAND_NONCE,
            requested_at=requested_at,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )

    def submit(self, command: Command) -> ClearingTransition:
        """Process one command through the real kernel pipeline."""
        if not isinstance(command, Command):
            raise CoreValidationError("submit expects a Command envelope")
        result = self._kernel.process(command)
        if result.outcome is Outcome.ACCEPTED:
            self._apply_accepted(command.command_type, result)
        transition = ClearingTransition(
            command_id=command.command_id,
            command_type=command.command_type,
            outcome=result.outcome,
            reason=result.reason,
            detail=result.detail,
            result=result,
        )
        self._transitions.append(transition)
        return transition

    # ------------------------------------------------------------------
    # record index (trusted decode path only)
    # ------------------------------------------------------------------

    def cycle(self, cycle_id: str) -> ClearingCycle:
        record = self._records.get(cycle_id)
        if record is None or not isinstance(record, ClearingCycle):
            raise CoreValidationError(f"unknown clearing cycle {cycle_id!r}")
        return record

    def obligation(self, obligation_id: str) -> Obligation:
        record = self._records.get(obligation_id)
        if record is None or not isinstance(record, Obligation):
            raise CoreValidationError(f"unknown obligation {obligation_id!r}")
        return record

    def netting(self, netting_id: str) -> NettingCycle:
        record = self._records.get(netting_id)
        if record is None or not isinstance(record, NettingCycle):
            raise CoreValidationError(f"unknown netting cycle {netting_id!r}")
        return record

    def records(self) -> tuple[Any, ...]:
        return tuple(self._records.values())

    def _decode_record(self, composite: Any) -> Any:
        require_mapping("clearing record", composite)
        object_type = composite.get("envelope", {}).get("object_type")
        decoder = _RECORD_DECODERS.get(object_type)
        if decoder is None:
            raise CoreValidationError(
                f"record claims unknown object type {object_type!r}"
            )
        return decoder(composite)

    def _store_record(self, record: Any) -> None:
        self._records[record.object_id] = record

    def _advance(self, record: Any, command: Command, *, state: str, spec: Any = None) -> Any:
        envelope = advance_envelope(
            record.envelope,
            state=state,
            provenance=self._provenance(command),
            causation_id=command.command_id,
            correlation_id=command.correlation_id,
        )
        new_spec = spec if spec is not None else record.spec
        integrity = seal_composite(envelope, new_spec)
        return type(record)(envelope=envelope, spec=new_spec, integrity_hash=integrity)

    def _require_source_state(self, command_type: str, state: Any) -> None:
        from .contracts import CLEARING_TRANSITIONS

        allowed = CLEARING_TRANSITIONS[command_type]
        if state not in allowed:
            raise CoreValidationError(
                f"{command_type} cannot advance from state {state.value!r}; "
                f"allowed source states are "
                f"{sorted(member.value for member in allowed)}"
            )

    def _require_cycle_members_finalizable(self, cycle: ClearingCycle) -> None:
        """Every member must have passed validation and carry no open dispute."""
        for member_id in cycle.spec.member_ids:
            member = self.obligation(member_id)
            if member.state not in OBLIGATION_VALIDATED_STATES:
                raise CoreValidationError(
                    f"obligation {member_id} is {member.state.value}; cycle "
                    "finalization requires every member to have passed "
                    "validation with no open dispute"
                )

    def _require_member_cycle_finalized(self, obligation: Obligation) -> None:
        """A cycle-recognized obligation is nettable only once its cycle cleared."""
        if obligation.spec.cycle_id is None:
            return
        cycle = self.cycle(obligation.spec.cycle_id)
        if cycle.state is not ClearingCycleState.FINALIZED:
            raise CoreValidationError(
                f"obligation {obligation.object_id} belongs to clearing cycle "
                f"{cycle.object_id} which is {cycle.state.value}; netting members "
                "must be cycle-cleared (FINALIZED)"
            )

    def _require_netting_exclusivity(self, obligation_id: str) -> None:
        """An obligation may sit in at most one non-terminal netting cycle."""
        for record in self._records.values():
            if not isinstance(record, NettingCycle):
                continue
            if obligation_id in record.spec.member_ids:
                if record.state not in (
                    NettingCycleState.FINALIZED,
                    NettingCycleState.CANCELLED,
                ):
                    raise CoreValidationError(
                        f"obligation {obligation_id} is already a member of the "
                        f"non-terminal netting cycle {record.object_id} "
                        f"({record.state.value}); an obligation may sit in at most "
                        "one live netting cycle"
                    )

    def _members_of(self, netting: NettingCycle) -> list[Obligation]:
        return [self.obligation(member_id) for member_id in netting.spec.member_ids]

    # ------------------------------------------------------------------
    # public command surface (the frozen families)
    # ------------------------------------------------------------------

    def create_cycle(
        self,
        *,
        command_id: str,
        requested_at: str,
        cycle_id: str,
        opens_at: str,
        closes_at: str,
        description: str = "",
    ) -> ClearingTransition:
        """``Clearing: Create`` — open one recognition window."""
        command = self.build_raw_command(
            command_id=command_id,
            command_type="clearing/cycle.create",
            requested_at=requested_at,
            target_refs=(cycle_id,),
            payload={
                "cycle_id": cycle_id,
                "window": {"opens_at": opens_at, "closes_at": closes_at},
                "description": description,
            },
            expected_versions={cycle_id: 0},
        )
        return self.submit(command)

    def validate_cycle(
        self, *, command_id: str, requested_at: str, cycle_id: str
    ) -> ClearingTransition:
        """``Clearing: Validate`` — verify every member obligation."""
        command = self.build_raw_command(
            command_id=command_id,
            command_type="clearing/cycle.validate",
            requested_at=requested_at,
            target_refs=(cycle_id,),
            payload={},
        )
        return self.submit(command)

    def finalize_cycle(
        self, *, command_id: str, requested_at: str, cycle_id: str
    ) -> ClearingTransition:
        """``Clearing: Finalize`` — bind the clearing statement."""
        command = self.build_raw_command(
            command_id=command_id,
            command_type="clearing/cycle.finalize",
            requested_at=requested_at,
            target_refs=(cycle_id,),
            payload={},
        )
        return self.submit(command)

    def cancel_cycle(
        self, *, command_id: str, requested_at: str, cycle_id: str, reason: str
    ) -> ClearingTransition:
        """``Clearing: Cancel`` — close the batch without a statement."""
        command = self.build_raw_command(
            command_id=command_id,
            command_type="clearing/cycle.cancel",
            requested_at=requested_at,
            target_refs=(cycle_id,),
            payload={"reason": reason},
        )
        return self.submit(command)

    def recognize_obligation(
        self,
        *,
        command_id: str,
        requested_at: str,
        cycle_id: str,
        effect_result: Mapping[str, Any],
        due_from: str,
        due_until: str,
    ) -> ClearingTransition:
        """``Obligation: Create`` — recognize one obligation from execution evidence.

        The obligation facts (obligor, obligee, asset, amount) are
        derived from the sealed effect result's payment-leg detail; they
        are never trusted from the command payload.
        """
        require_identifier("recognize_obligation cycle_id", cycle_id)
        obligation_id = self._derive_obligation_id(effect_result)
        cycle = self.cycle(cycle_id)
        command = self.build_raw_command(
            command_id=command_id,
            command_type="clearing/obligation.create",
            requested_at=requested_at,
            target_refs=(obligation_id, cycle_id),
            payload={
                "cycle_id": cycle_id,
                "effect_result": dict(effect_result),
                "due_window": {"due_from": due_from, "due_until": due_until},
            },
            expected_versions={obligation_id: 0, cycle_id: cycle.envelope.object_version},
        )
        return self.submit(command)

    def validate_obligation(
        self, *, command_id: str, requested_at: str, obligation_id: str
    ) -> ClearingTransition:
        """``Obligation: Validate`` — re-verify the derived facts."""
        command = self.build_raw_command(
            command_id=command_id,
            command_type="clearing/obligation.validate",
            requested_at=requested_at,
            target_refs=(obligation_id,),
            payload={},
        )
        return self.submit(command)

    def amend_obligation(
        self,
        *,
        command_id: str,
        requested_at: str,
        obligation_id: str,
        reason: str,
        amount: Mapping[str, Any] | None = None,
        due_window: Mapping[str, Any] | None = None,
    ) -> ClearingTransition:
        """``Obligation: Amend`` — restructure terms with an explicit reason."""
        command = self.build_raw_command(
            command_id=command_id,
            command_type="clearing/obligation.amend",
            requested_at=requested_at,
            target_refs=(obligation_id,),
            payload={
                "reason": reason,
                "amount": dict(amount) if amount is not None else None,
                "due_window": dict(due_window) if due_window is not None else None,
            },
        )
        return self.submit(command)

    def dispute_obligation(
        self,
        *,
        command_id: str,
        requested_at: str,
        obligation_id: str,
        evidence_ref: str,
        epistemic_type: str,
        reason: str,
    ) -> ClearingTransition:
        """``Obligation: Dispute`` — open a dispute backed by OBSERVED evidence."""
        command = self.build_raw_command(
            command_id=command_id,
            command_type="clearing/obligation.dispute",
            requested_at=requested_at,
            target_refs=(obligation_id,),
            payload={
                "evidence_ref": evidence_ref,
                "epistemic_type": epistemic_type,
                "reason": reason,
            },
        )
        return self.submit(command)

    def restructure_obligation(
        self,
        *,
        command_id: str,
        requested_at: str,
        obligation_id: str,
        evidence_ref: str,
        epistemic_type: str,
        reason: str,
        amount: Mapping[str, Any] | None = None,
        due_window: Mapping[str, Any] | None = None,
    ) -> ClearingTransition:
        """``Obligation: Restructure`` — resolve a dispute with new terms."""
        command = self.build_raw_command(
            command_id=command_id,
            command_type="clearing/obligation.restructure",
            requested_at=requested_at,
            target_refs=(obligation_id,),
            payload={
                "evidence_ref": evidence_ref,
                "epistemic_type": epistemic_type,
                "reason": reason,
                "amount": dict(amount) if amount is not None else None,
                "due_window": dict(due_window) if due_window is not None else None,
            },
        )
        return self.submit(command)

    def mark_due_obligation(
        self,
        *,
        command_id: str,
        requested_at: str,
        obligation_id: str,
        funding: Mapping[str, Any] | None = None,
    ) -> ClearingTransition:
        """``Obligation: MarkDue`` — make the obligation claimable."""
        command = self.build_raw_command(
            command_id=command_id,
            command_type="clearing/obligation.mark-due",
            requested_at=requested_at,
            target_refs=(obligation_id,),
            payload={"funding": dict(funding) if funding is not None else None},
        )
        return self.submit(command)

    def default_obligation(
        self,
        *,
        command_id: str,
        requested_at: str,
        obligation_id: str,
        evidence_ref: str,
        epistemic_type: str,
        reason: str,
    ) -> ClearingTransition:
        """``Obligation: Default`` — terminal default with OBSERVED evidence."""
        command = self.build_raw_command(
            command_id=command_id,
            command_type="clearing/obligation.default",
            requested_at=requested_at,
            target_refs=(obligation_id,),
            payload={
                "evidence_ref": evidence_ref,
                "epistemic_type": epistemic_type,
                "reason": reason,
            },
        )
        return self.submit(command)

    def resolve_obligation(
        self,
        *,
        command_id: str,
        requested_at: str,
        obligation_id: str,
        evidence_ref: str,
        evidence_digest: str,
        reason: str,
    ) -> ClearingTransition:
        """``Obligation: Resolve`` — close with recorded discharge evidence.

        Recording discharge evidence NEVER establishes settlement
        finality (constitution invariant 11); settlement and finality
        are WORK-016's authority.
        """
        command = self.build_raw_command(
            command_id=command_id,
            command_type="clearing/obligation.resolve",
            requested_at=requested_at,
            target_refs=(obligation_id,),
            payload={
                "evidence_ref": evidence_ref,
                "evidence_digest": evidence_digest,
                "reason": reason,
            },
        )
        return self.submit(command)

    def create_netting(
        self,
        *,
        command_id: str,
        requested_at: str,
        netting_id: str,
        mode: str,
        due_from: str,
        due_until: str,
    ) -> ClearingTransition:
        """``Netting: Create`` — open one netting batch."""
        command = self.build_raw_command(
            command_id=command_id,
            command_type="clearing/netting.create",
            requested_at=requested_at,
            target_refs=(netting_id,),
            payload={
                "netting_id": netting_id,
                "mode": mode,
                "due_window": {"due_from": due_from, "due_until": due_until},
            },
            expected_versions={netting_id: 0},
        )
        return self.submit(command)

    def add_netting_member(
        self, *, command_id: str, requested_at: str, netting_id: str, obligation_id: str
    ) -> ClearingTransition:
        """``Netting: Add`` — add one obligation to the netting set."""
        netting = self.netting(netting_id)
        obligation = self.obligation(obligation_id)
        command = self.build_raw_command(
            command_id=command_id,
            command_type="clearing/netting.add",
            requested_at=requested_at,
            target_refs=(netting_id, obligation_id),
            payload={"obligation_id": obligation_id},
            expected_versions={
                netting_id: netting.envelope.object_version,
                obligation_id: obligation.envelope.object_version,
            },
        )
        return self.submit(command)

    def remove_netting_member(
        self, *, command_id: str, requested_at: str, netting_id: str, obligation_id: str
    ) -> ClearingTransition:
        """``Netting: Remove`` — remove one obligation from the netting set."""
        command = self.build_raw_command(
            command_id=command_id,
            command_type="clearing/netting.remove",
            requested_at=requested_at,
            target_refs=(netting_id,),
            payload={"obligation_id": obligation_id},
        )
        return self.submit(command)

    def calculate_netting(
        self,
        *,
        command_id: str,
        requested_at: str,
        netting_id: str,
        valuation: Mapping[str, Any] | None = None,
    ) -> ClearingTransition:
        """``Netting: Calculate`` — bind the deterministic netting statement."""
        command = self.build_raw_command(
            command_id=command_id,
            command_type="clearing/netting.calculate",
            requested_at=requested_at,
            target_refs=(netting_id,),
            payload={"valuation": dict(valuation) if valuation is not None else None},
        )
        return self.submit(command)

    def finalize_netting(
        self, *, command_id: str, requested_at: str, netting_id: str
    ) -> ClearingTransition:
        """``Netting: Finalize`` — make the statement binding.

        Resolves every member obligation (kind ``NETTING``), issues the
        net obligations (bilateral mode) and re-derives the complete
        statement from the current members — a stale or fabricated
        statement fails closed before anything is committed.
        """
        netting = self.netting(netting_id)
        statement = netting.spec.statement
        if statement is None:
            raise CoreValidationError(
                f"netting cycle {netting_id!r} carries no calculated statement"
            )
        # Expected versions are pinned to the members' CURRENT versions:
        # the kernel passes a mutation-free command into the handler,
        # where the statement's member bindings are re-verified against
        # the current state (a member that advanced after calculation
        # fails closed as a stale statement — the load-bearing check).
        members = self._members_of(netting)
        targets: list[str] = [netting_id]
        expected: dict[str, int] = {netting_id: netting.envelope.object_version}
        for member in members:
            targets.append(member.object_id)
            expected[member.object_id] = member.envelope.object_version
        for group in statement.groups:
            for pair in group.pairs:
                if pair.issued_obligation_id is not None:
                    targets.append(pair.issued_obligation_id)
                    expected[pair.issued_obligation_id] = 0
        command = self.build_raw_command(
            command_id=command_id,
            command_type="clearing/netting.finalize",
            requested_at=requested_at,
            target_refs=targets,
            payload={},
            expected_versions=expected,
        )
        return self.submit(command)

    def cancel_netting(
        self, *, command_id: str, requested_at: str, netting_id: str, reason: str
    ) -> ClearingTransition:
        """``Netting: Cancel`` — abandon the batch before finalization."""
        command = self.build_raw_command(
            command_id=command_id,
            command_type="clearing/netting.cancel",
            requested_at=requested_at,
            target_refs=(netting_id,),
            payload={"reason": reason},
        )
        return self.submit(command)

    # ------------------------------------------------------------------
    # kernel handlers (validate-then-compute; never index mutation)
    # ------------------------------------------------------------------

    def _handle_cycle_create(self, command: Command, view: Any) -> TransitionApplication:
        payload = _payload_dict(command)
        strict_fields("cycle.create payload", payload, _CREATE_CYCLE_PAYLOAD_FIELDS)
        cycle_id = require_identifier("cycle.create cycle_id", payload["cycle_id"])
        window = RecognitionWindow.from_dict(payload["window"])
        if not isinstance(payload["description"], str):
            raise CoreValidationError("cycle.create description must be a string")
        if command.target_refs[0] != cycle_id:
            raise CoreValidationError(
                "cycle.create target_refs must declare the created cycle id"
            )
        spec = ClearingCycleSpec(
            cycle_id=cycle_id, window=window, description=payload["description"]
        )
        record = make_cycle_record(
            spec=spec,
            environment_id=command.environment_id,
            domain_id=command.domain_id,
            provenance=self._provenance(command),
            causation_id=command.command_id,
            correlation_id=command.correlation_id,
        )
        return TransitionApplication((record.envelope,), {"cycle": record.to_dict()})

    def _handle_cycle_validate(self, command: Command, view: Any) -> TransitionApplication:
        cycle = self.cycle(command.target_refs[0])
        self._require_source_state("clearing/cycle.validate", cycle.state)
        self._require_cycle_members_finalizable(cycle)
        validated = self._advance(cycle, command, state=ClearingCycleState.VALIDATED.value)
        return TransitionApplication((validated.envelope,), {"cycle": validated.to_dict()})

    def _handle_cycle_finalize(self, command: Command, view: Any) -> TransitionApplication:
        cycle = self.cycle(command.target_refs[0])
        self._require_source_state("clearing/cycle.finalize", cycle.state)
        self._require_cycle_members_finalizable(cycle)
        members = [self.obligation(member_id) for member_id in cycle.spec.member_ids]
        if not members:
            raise CoreValidationError(
                "cycle finalization requires at least one member obligation"
            )
        statement = compute_clearing_statement(
            members=members, finalized_at=command.requested_at
        )
        new_spec = replace(cycle.spec, statement=statement)
        finalized = self._advance(
            cycle, command, state=ClearingCycleState.FINALIZED.value, spec=new_spec
        )
        return TransitionApplication((finalized.envelope,), {"cycle": finalized.to_dict()})

    def _handle_cycle_cancel(self, command: Command, view: Any) -> TransitionApplication:
        payload = _payload_dict(command)
        strict_fields("cycle.cancel payload", payload, _CANCEL_CYCLE_PAYLOAD_FIELDS)
        require_text("cycle.cancel reason", payload["reason"])
        cycle = self.cycle(command.target_refs[0])
        self._require_source_state("clearing/cycle.cancel", cycle.state)
        cancelled = self._advance(cycle, command, state=ClearingCycleState.CANCELLED.value)
        return TransitionApplication((cancelled.envelope,), {"cycle": cancelled.to_dict()})

    def _derive_obligation_id(self, effect_result: Mapping[str, Any]) -> str:
        """Derive the obligation id from the execution evidence identity."""
        result = self._decode_effect_result(effect_result)
        return f"{result.object_id}/obligation"

    def _decode_effect_result(self, effect_result: Any) -> EffectResult:
        """Decode execution evidence through its own trusted path.

        The composite seal is verified by the execution domain's decode
        path; a tampered or spliced result fails closed here, before any
        obligation fact is derived.
        """
        if not isinstance(effect_result, Mapping):
            raise CoreValidationError(
                "obligation recognition requires an execution EffectResult composite"
            )
        return EffectResult.from_dict(effect_result)

    def _derive_payment_leg(self, result: EffectResult) -> dict[str, Any]:
        """Derive the canonical payment-leg facts from the evidence detail."""
        if result.spec.outcome is not EffectOutcome.SUCCEEDED:
            raise CoreValidationError(
                "obligations are recognized only from SUCCEEDED effect results; "
                f"the evidence outcome is {result.spec.outcome.value}"
            )
        detail = payload_to_json_value(result.spec.detail)
        if not isinstance(detail, dict):
            raise CoreValidationError(
                "effect result detail must be an object carrying the payment leg"
            )
        if set(detail) != _PAYMENT_LEG_FIELDS:
            missing = sorted(_PAYMENT_LEG_FIELDS - set(detail))
            extra = sorted(set(detail) - _PAYMENT_LEG_FIELDS)
            raise CoreValidationError(
                "effect result detail must carry exactly the canonical payment-leg "
                f"fields; missing={missing}, extra={extra}"
            )
        return dict(detail)

    def _handle_obligation_create(self, command: Command, view: Any) -> TransitionApplication:
        payload = parse_recognize_payload(_payload_dict(command))
        result = self._decode_effect_result(payload["effect_result"])
        leg = self._derive_payment_leg(result)
        obligation_id = f"{result.object_id}/obligation"
        if command.target_refs[0] != obligation_id:
            raise CoreValidationError(
                "obligation.create target_refs must declare the derived obligation id "
                f"{obligation_id!r}"
            )
        cycle_id = payload["cycle_id"]
        if cycle_id is None:
            raise CoreValidationError(
                "obligation recognition requires an open clearing cycle; the "
                "cycle-less path is reserved for netting issuance"
            )
        cycle = self.cycle(cycle_id)
        if cycle.state is not ClearingCycleState.OPEN:
            raise CoreValidationError(
                f"clearing cycle {cycle_id} is {cycle.state.value}; obligations are "
                "recognized only into OPEN cycles"
            )
        if cycle_id not in command.target_refs:
            raise CoreValidationError(
                "obligation.create target_refs must declare the recognition cycle"
            )
        amount = Amount.from_dict(leg["amount"])
        spec = ObligationSpec(
            obligation_id=obligation_id,
            cycle_id=cycle_id,
            obligor=leg["payer"],
            obligee=leg["payee"],
            asset=leg["asset"],
            amount=amount,
            source_kind=ObligationSourceKind.EXECUTION_EVIDENCE.value,
            source_ref=result.object_id,
            source_digest=result.integrity_hash,
            due_window=payload["due_window"],
        )
        record = make_obligation_record(
            spec=spec,
            environment_id=command.environment_id,
            domain_id=command.domain_id,
            provenance=self._provenance(command),
            causation_id=command.command_id,
            correlation_id=command.correlation_id,
        )
        new_cycle_spec = replace(
            cycle.spec, member_ids=cycle.spec.member_ids + (obligation_id,)
        )
        advanced_cycle = self._advance(
            cycle, command, state=ClearingCycleState.OPEN.value, spec=new_cycle_spec
        )
        return TransitionApplication(
            (record.envelope, advanced_cycle.envelope),
            {
                "obligation": record.to_dict(),
                "cycle": advanced_cycle.to_dict(),
            },
        )

    def _handle_obligation_validate(self, command: Command, view: Any) -> TransitionApplication:
        obligation = self.obligation(command.target_refs[0])
        self._require_source_state("clearing/obligation.validate", obligation.state)
        # Re-validation runs the spec through the canonical round-trip:
        # every derived fact (positivity, window order, participant
        # distinctness, source binding shape) is re-verified on the
        # trusted path before the obligation advances.
        ObligationSpec.from_dict(obligation.spec.to_dict())
        validated = self._advance(
            obligation, command, state=ObligationState.VALIDATED.value
        )
        return TransitionApplication(
            (validated.envelope,), {"obligation": validated.to_dict()}
        )

    def _handle_obligation_amend(self, command: Command, view: Any) -> TransitionApplication:
        payload = parse_amend_payload(_payload_dict(command))
        obligation = self.obligation(command.target_refs[0])
        self._require_source_state("clearing/obligation.amend", obligation.state)
        new_spec = replace(
            obligation.spec,
            amount=payload["amount"] if payload["amount"] is not None else obligation.spec.amount,
            due_window=(
                payload["due_window"]
                if payload["due_window"] is not None
                else obligation.spec.due_window
            ),
            amendment=AmendmentRecord(
                reason=payload["reason"], amended_at=command.requested_at
            ),
        )
        amended = self._advance(
            obligation, command, state=ObligationState.AMENDED.value, spec=new_spec
        )
        return TransitionApplication((amended.envelope,), {"obligation": amended.to_dict()})

    def _handle_obligation_dispute(self, command: Command, view: Any) -> TransitionApplication:
        payload = _payload_dict(command)
        gate = parse_evidence_payload(
            "obligation.dispute payload",
            payload,
            frozenset({"evidence_ref", "epistemic_type", "reason"}),
        )
        obligation = self.obligation(command.target_refs[0])
        self._require_source_state("clearing/obligation.dispute", obligation.state)
        if obligation.spec.dispute is not None:
            raise CoreValidationError(
                f"obligation {obligation.object_id} already carries an open dispute"
            )
        new_spec = replace(
            obligation.spec,
            dispute=DisputeRecord(
                evidence_ref=gate.evidence_ref,
                epistemic_type=gate.epistemic_type,
                reason=gate.reason,
                disputed_at=command.requested_at,
            ),
        )
        disputed = self._advance(
            obligation, command, state=ObligationState.DISPUTED.value, spec=new_spec
        )
        return TransitionApplication((disputed.envelope,), {"obligation": disputed.to_dict()})

    def _handle_obligation_restructure(
        self, command: Command, view: Any
    ) -> TransitionApplication:
        payload = parse_restructure_payload(_payload_dict(command))
        gate = payload["gate"]
        obligation = self.obligation(command.target_refs[0])
        self._require_source_state("clearing/obligation.restructure", obligation.state)
        new_spec = replace(
            obligation.spec,
            amount=payload["amount"] if payload["amount"] is not None else obligation.spec.amount,
            due_window=(
                payload["due_window"]
                if payload["due_window"] is not None
                else obligation.spec.due_window
            ),
            restructure=RestructureRecord(
                evidence_ref=gate.evidence_ref,
                epistemic_type=gate.epistemic_type,
                reason=gate.reason,
                restructured_at=command.requested_at,
            ),
            # The old due marker is cleared: restructured terms carry a
            # new claimability window and must be explicitly re-marked.
            due=None,
        )
        restructured = self._advance(
            obligation, command, state=ObligationState.RESTRUCTURED.value, spec=new_spec
        )
        return TransitionApplication(
            (restructured.envelope,), {"obligation": restructured.to_dict()}
        )

    def _handle_obligation_mark_due(self, command: Command, view: Any) -> TransitionApplication:
        payload = parse_mark_due_payload(_payload_dict(command))
        obligation = self.obligation(command.target_refs[0])
        self._require_source_state("clearing/obligation.mark-due", obligation.state)
        if obligation.spec.due is not None:
            raise CoreValidationError(
                f"obligation {obligation.object_id} is already marked due"
            )
        requested = parse_utc_timestamp("mark-due requested_at", command.requested_at)
        due_from = parse_utc_timestamp("mark-due due_from", obligation.spec.due_window.due_from)
        if requested < due_from:
            raise CoreValidationError(
                f"obligation {obligation.object_id} cannot be marked due before its "
                f"due window opens ({command.requested_at} < {obligation.spec.due_window.due_from})"
            )
        new_spec = replace(
            obligation.spec,
            due=DueRecord(marked_at=command.requested_at, funding=payload["funding"]),
        )
        marked = self._advance(
            obligation, command, state=ObligationState.DUE.value, spec=new_spec
        )
        return TransitionApplication((marked.envelope,), {"obligation": marked.to_dict()})

    def _handle_obligation_default(self, command: Command, view: Any) -> TransitionApplication:
        payload = _payload_dict(command)
        gate = parse_evidence_payload(
            "obligation.default payload",
            payload,
            frozenset({"evidence_ref", "epistemic_type", "reason"}),
        )
        obligation = self.obligation(command.target_refs[0])
        self._require_source_state("clearing/obligation.default", obligation.state)
        new_spec = replace(
            obligation.spec,
            default=DefaultRecord(
                evidence_ref=gate.evidence_ref,
                epistemic_type=gate.epistemic_type,
                reason=gate.reason,
                defaulted_at=command.requested_at,
            ),
        )
        defaulted = self._advance(
            obligation, command, state=ObligationState.DEFAULTED.value, spec=new_spec
        )
        return TransitionApplication((defaulted.envelope,), {"obligation": defaulted.to_dict()})

    def _handle_obligation_resolve(self, command: Command, view: Any) -> TransitionApplication:
        payload = parse_resolve_payload(_payload_dict(command))
        obligation = self.obligation(command.target_refs[0])
        self._require_source_state("clearing/obligation.resolve", obligation.state)
        new_spec = replace(
            obligation.spec,
            resolution=ResolutionRecord(
                kind=ResolutionKind.DISCHARGE_EVIDENCE.value,
                ref=payload["evidence_ref"],
                digest=payload["evidence_digest"],
                resolved_at=command.requested_at,
            ),
        )
        resolved = self._advance(
            obligation, command, state=ObligationState.RESOLVED.value, spec=new_spec
        )
        return TransitionApplication((resolved.envelope,), {"obligation": resolved.to_dict()})

    def _handle_netting_create(self, command: Command, view: Any) -> TransitionApplication:
        payload = parse_create_netting_payload(_payload_dict(command))
        if command.target_refs[0] != payload["netting_id"]:
            raise CoreValidationError(
                "netting.create target_refs must declare the created netting id"
            )
        spec = NettingCycleSpec(
            netting_id=payload["netting_id"],
            mode=payload["mode"].value,
            due_window=payload["due_window"],
        )
        record = make_netting_record(
            spec=spec,
            environment_id=command.environment_id,
            domain_id=command.domain_id,
            provenance=self._provenance(command),
            causation_id=command.command_id,
            correlation_id=command.correlation_id,
        )
        return TransitionApplication((record.envelope,), {"netting": record.to_dict()})

    def _handle_netting_add(self, command: Command, view: Any) -> TransitionApplication:
        obligation_id = parse_member_payload(
            "netting.add payload", _payload_dict(command)
        )
        netting = self.netting(command.target_refs[0])
        self._require_source_state("clearing/netting.add", netting.state)
        obligation = self.obligation(obligation_id)
        if (
            obligation.spec.source_kind == ObligationSourceKind.NETTING_ISSUANCE.value
            and obligation.spec.source_ref == netting.object_id
        ):
            raise CoreValidationError(
                f"obligation {obligation_id} was issued by netting cycle "
                f"{netting.object_id}; a cycle cannot net its own issuance"
            )
        if obligation_id in netting.spec.member_ids:
            raise CoreValidationError(
                f"obligation {obligation_id} is already a member of netting cycle "
                f"{netting.object_id}"
            )
        if obligation.state not in OBLIGATION_VALIDATED_STATES:
            raise CoreValidationError(
                f"obligation {obligation_id} is {obligation.state.value}; netting "
                "members must have passed validation and carry no open dispute"
            )
        self._require_member_cycle_finalized(obligation)
        self._require_netting_exclusivity(obligation_id)
        new_spec = replace(
            netting.spec, member_ids=netting.spec.member_ids + (obligation_id,)
        )
        advanced = self._advance(
            netting, command, state=NettingCycleState.OPEN.value, spec=new_spec
        )
        return TransitionApplication((advanced.envelope,), {"netting": advanced.to_dict()})

    def _handle_netting_remove(self, command: Command, view: Any) -> TransitionApplication:
        obligation_id = parse_member_payload(
            "netting.remove payload", _payload_dict(command)
        )
        netting = self.netting(command.target_refs[0])
        self._require_source_state("clearing/netting.remove", netting.state)
        if obligation_id not in netting.spec.member_ids:
            raise CoreValidationError(
                f"obligation {obligation_id} is not a member of netting cycle "
                f"{netting.object_id}"
            )
        remaining = tuple(
            entry for entry in netting.spec.member_ids if entry != obligation_id
        )
        new_spec = replace(netting.spec, member_ids=remaining)
        advanced = self._advance(
            netting, command, state=NettingCycleState.OPEN.value, spec=new_spec
        )
        return TransitionApplication((advanced.envelope,), {"netting": advanced.to_dict()})

    def _handle_netting_calculate(self, command: Command, view: Any) -> TransitionApplication:
        payload = parse_calculate_payload(_payload_dict(command))
        netting = self.netting(command.target_refs[0])
        self._require_source_state("clearing/netting.calculate", netting.state)
        members = self._members_of(netting)
        if not members:
            raise CoreValidationError(
                "netting calculation requires at least one member obligation"
            )
        statement = compute_netting_statement(
            netting_id=netting.object_id,
            members=members,
            mode=NettingMode(netting.spec.mode),
            calculated_at=command.requested_at,
            valuation_spec=payload["valuation"],
        )
        new_spec = replace(netting.spec, statement=statement)
        calculated = self._advance(
            netting, command, state=NettingCycleState.CALCULATED.value, spec=new_spec
        )
        return TransitionApplication((calculated.envelope,), {"netting": calculated.to_dict()})

    def _handle_netting_finalize(self, command: Command, view: Any) -> TransitionApplication:
        netting = self.netting(command.target_refs[0])
        self._require_source_state("clearing/netting.finalize", netting.state)
        statement = netting.spec.statement
        if statement is None:
            raise CoreValidationError(
                f"netting cycle {netting.object_id} carries no calculated statement"
            )
        members: list[Obligation] = []
        for binding in statement.members:
            member = self.obligation(binding.obligation_id)
            if member.envelope.object_version != binding.object_version:
                raise CoreValidationError(
                    f"obligation {binding.obligation_id} advanced to version "
                    f"{member.envelope.object_version} after the statement bound "
                    f"version {binding.object_version}; the statement is stale — "
                    "recalculate before finalizing"
                )
            if member.spec.amount.value != binding.amount_value:
                raise CoreValidationError(
                    f"obligation {binding.obligation_id} amount changed after the "
                    "statement was calculated; the statement is stale — recalculate "
                    "before finalizing"
                )
            if member.spec.obligor != binding.obligor or member.spec.obligee != binding.obligee:
                raise CoreValidationError(
                    f"obligation {binding.obligation_id} participants changed after "
                    "the statement was calculated; the statement is stale — "
                    "recalculate before finalizing"
                )
            if member.state not in OBLIGATION_VALIDATED_STATES:
                raise CoreValidationError(
                    f"obligation {member.object_id} is {member.state.value}; netting "
                    "finalization requires every member to have passed validation "
                    "with no open dispute"
                )
            members.append(member)
        # Re-derive the complete statement from the current members: a
        # fabricated or mutated statement fails closed here.
        valuation_spec = None
        if statement.valuation is not None:
            valuation_spec = ValuationSpec(
                base_currency=statement.valuation.base_currency,
                rounding=statement.valuation.rounding,
                asset_currencies=tuple(
                    (entry.asset, entry.currency)
                    for entry in statement.valuation.conversions
                ),
                rates=tuple(
                    entry.rate
                    for entry in statement.valuation.conversions
                    if entry.rate is not None
                ),
            )
        rederived = compute_netting_statement(
            netting_id=netting.object_id,
            members=members,
            mode=NettingMode(netting.spec.mode),
            calculated_at=statement.calculated_at,
            valuation_spec=valuation_spec,
        )
        if rederived.digest != statement.digest:
            raise CoreValidationError(
                "netting statement re-derivation mismatch: the bound statement does "
                "not match the current members — the statement is stale or forged; "
                "recalculate before finalizing"
            )

        resolved_records: list[Obligation] = []
        for member in members:
            new_spec = replace(
                member.spec,
                resolution=ResolutionRecord(
                    kind=ResolutionKind.NETTING.value,
                    ref=netting.object_id,
                    digest=statement.digest,
                    resolved_at=command.requested_at,
                ),
            )
            resolved = self._advance(
                member, command, state=ObligationState.RESOLVED.value, spec=new_spec
            )
            resolved_records.append(resolved)

        issued_records: list[Obligation] = []
        for group in statement.groups:
            for pair in group.pairs:
                if pair.issued_obligation_id is None:
                    continue
                issued_records.append(
                    derive_issued_obligation(
                        pair=pair,
                        group=group,
                        netting_cycle=netting,
                        statement_digest=statement.digest,
                        environment_id=command.environment_id,
                        domain_id=command.domain_id,
                        provenance=self._provenance(command),
                        causation_id=command.command_id,
                        correlation_id=command.correlation_id,
                    )
                )

        finalized = self._advance(
            netting, command, state=NettingCycleState.FINALIZED.value
        )
        envelopes = [finalized.envelope]
        envelopes.extend(record.envelope for record in resolved_records)
        envelopes.extend(record.envelope for record in issued_records)
        payload = {
            "netting": finalized.to_dict(),
            "resolved": [record.to_dict() for record in resolved_records],
            "issued": [record.to_dict() for record in issued_records],
        }
        return TransitionApplication(tuple(envelopes), payload)

    def _handle_netting_cancel(self, command: Command, view: Any) -> TransitionApplication:
        reason = parse_reason_payload("netting.cancel payload", _payload_dict(command))
        netting = self.netting(command.target_refs[0])
        self._require_source_state("clearing/netting.cancel", netting.state)
        cancelled = self._advance(
            netting, command, state=NettingCycleState.CANCELLED.value
        )
        return TransitionApplication((cancelled.envelope,), {"netting": cancelled.to_dict()})

    # ------------------------------------------------------------------
    # committed-event application (the single mutation path)
    # ------------------------------------------------------------------

    def _apply_accepted(self, command_type: str, result: TransitionResult) -> None:
        event_type = COMMAND_EVENT_TYPES.get(command_type)
        if event_type is None:
            raise CoreValidationError(f"command {command_type!r} is not registered")
        payload = payload_to_json_value(result.payload) if result.payload is not None else {}
        self._apply_event_payload(event_type, payload)

    def _apply_event_payload(self, event_type: str, payload: Any) -> None:
        """Apply one committed event payload to the index.

        This is the single mutation path, shared by live commits and
        journal rebuilds; every record re-enters through the trusted
        decode path (seal verification included).
        """
        if not isinstance(payload, Mapping):
            raise CoreValidationError("committed clearing payloads must be objects")
        if event_type == "clearing/cycle-created":
            self._store_record(self._decode_record(payload["cycle"]))
        elif event_type in ("clearing/cycle-validated", "clearing/cycle-finalized"):
            self._store_record(self._decode_record(payload["cycle"]))
        elif event_type == "clearing/cycle-cancelled":
            self._store_record(self._decode_record(payload["cycle"]))
        elif event_type == "clearing/obligation-created":
            self._store_record(self._decode_record(payload["obligation"]))
            if payload.get("cycle") is not None:
                self._store_record(self._decode_record(payload["cycle"]))
        elif event_type in (
            "clearing/obligation-validated",
            "clearing/obligation-amended",
            "clearing/obligation-disputed",
            "clearing/obligation-restructured",
            "clearing/obligation-due",
            "clearing/obligation-defaulted",
            "clearing/obligation-resolved",
        ):
            self._store_record(self._decode_record(payload["obligation"]))
        elif event_type in (
            "clearing/netting-created",
            "clearing/netting-member-added",
            "clearing/netting-member-removed",
            "clearing/netting-calculated",
            "clearing/netting-cancelled",
        ):
            self._store_record(self._decode_record(payload["netting"]))
        elif event_type == "clearing/netting-finalized":
            self._store_record(self._decode_record(payload["netting"]))
            for composite in payload["resolved"]:
                self._store_record(self._decode_record(composite))
            for composite in payload["issued"]:
                self._store_record(self._decode_record(composite))
        else:
            raise CoreValidationError(f"unknown clearing event type {event_type!r}")

    # ------------------------------------------------------------------
    # snapshot, restore and journal rebuild
    # ------------------------------------------------------------------

    def snapshot_state(self) -> dict[str, Any]:
        """Canonical, byte-stable snapshot of the composed engine state."""
        return {
            "schema_version": 1,
            "environment_id": self._environment_id,
            "domain_id": self._domain_id,
            "index": {
                object_id: record.to_dict() for object_id, record in self._records.items()
            },
            "engine": self._kernel.snapshot_state().to_dict(),
            "store": [envelope.to_dict() for envelope in self._store.snapshot()],
        }

    def restore_state(self, snapshot: Mapping[str, Any]) -> None:
        """Rebuild the engine from a canonical snapshot (fail closed)."""
        require_mapping("engine snapshot", snapshot)
        strict_fields("engine snapshot", snapshot, _SNAPSHOT_FIELDS)
        if snapshot["schema_version"] != 1:
            raise CoreValidationError("engine snapshot schema version must be 1")
        if snapshot["environment_id"] != self._environment_id:
            raise CoreValidationError(
                f"snapshot environment {snapshot['environment_id']!r} does not match "
                f"engine environment {self._environment_id!r}"
            )
        if snapshot["domain_id"] != self._domain_id:
            raise CoreValidationError(
                f"snapshot domain {snapshot['domain_id']!r} does not match engine "
                f"domain {self._domain_id!r}"
            )
        index_raw = require_mapping("engine snapshot index", snapshot["index"])
        records: dict[str, Any] = {}
        for object_id, composite in index_raw.items():
            require_identifier("engine snapshot object_id", object_id)
            record = self._decode_record(composite)
            if record.object_id != object_id:
                raise CoreValidationError(
                    f"snapshot key {object_id!r} does not match object id "
                    f"{record.object_id!r}"
                )
            records[object_id] = record
        store_raw = snapshot["store"]
        if not isinstance(store_raw, list):
            raise CoreValidationError("engine snapshot store must deserialize from a list")
        envelopes = tuple(ObjectEnvelope.from_dict(entry) for entry in store_raw)
        store = MemoryStateStore(envelopes)
        store_by_id = {envelope.object_id: envelope for envelope in envelopes}
        for object_id, record in records.items():
            stored = store_by_id.get(object_id)
            if stored is None or stored != record.envelope:
                raise CoreValidationError(
                    f"snapshot index and store disagree on object {object_id!r}"
                )
        engine_state = EngineState.from_dict(snapshot["engine"])
        self._records = records
        self._store = store
        self._kernel = self._build_kernel()
        self._kernel.restore_state(engine_state)
        # The transitions log is an engine-local decision log; it is not
        # part of durable state (the kernel journal is authoritative).

    @classmethod
    def rebuild_from_journal(
        cls,
        *,
        environment_id: str,
        domain_id: str,
        journal: Iterable[Any],
        actor: str = DEFAULT_ENGINE_ACTOR,
        command_authority_class: str = DEFAULT_COMMAND_AUTHORITY_CLASS,
    ) -> "ClearingEngine":
        """Rebuild the domain index from the kernel journal alone.

        Transformation completeness: the committed event payloads carry
        every resulting record, so folding the journal rebuilds the
        composed domain state deterministically. The kernel's command-id
        dedup restarts after a journal-only rebuild (command envelopes
        are not part of the journal).
        """
        engine = cls(
            environment_id=environment_id,
            domain_id=domain_id,
            actor=actor,
            command_authority_class=command_authority_class,
        )
        entries = tuple(journal)
        for entry in entries:
            engine._apply_event_payload(entry.event.event_type, _journal_payload(entry))
        if entries:
            state = EngineState(
                logical_time=entries[-1].event.logical_time,
                records=(),
                journal=entries,
            )
            engine._store = MemoryStateStore(
                record.envelope for record in engine._records.values()
            )
            engine._kernel = engine._build_kernel()
            engine._kernel.restore_state(state)
        return engine
