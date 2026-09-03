"""Kernel-bound engine for the settlement domain (WORK-016).

The :class:`SettlementEngine` binds every command of the frozen
``Settlement``/``Finality``/``Recourse`` families (18 command types) to
the REAL transition kernel (:class:`src.transition.TransitionEngine`):
validate-then-compute handlers produce
:class:`~src.transition.TransitionApplication` records that the kernel
commits and journals; the domain index and the append-only posting
journal are re-populated only through the trusted decode path (seal
verification included), both for live commits and journal rebuilds.

Authority discipline (constitution invariant 3 — authority before
financial effect):

* the operator gate authorizes actors at the engine boundary (kernel
  stage 4);
* discharge instructions are derived from the clearing domain's sealed
  ``DUE`` obligations (WORK-015) through their trusted decode path —
  payload-carried economics are never trusted; an obligation may sit in
  at most one non-terminal settlement;
* rail evidence is the execution domain's recorded
  ``ExternalObservation`` composites (WORK-014), decoded through their
  trusted path: only ``OBSERVED`` epistemics, digest-bound subjects and
  the canonical content shapes fold legs; settlement never re-evaluates
  a rail outcome and never records one itself;
* finality certificates are established only from finality-class
  observations covering every settled leg of a ``COMPLETED``
  settlement (constitution §4 and invariant 11 — a payment status is
  never allowed to stand in for settlement finality);
* recourse is opened only by ``OBSERVED`` evidence (the frozen
  ``src.evidence`` vocabulary, WORK-018) and a reversal is
  digest-bound to the withdrawn finality certificate;
* the posting journal is append-only: postings are derived
  deterministically from committed events; reversals are explicit
  compensation postings and refunds are new linked settlements — no
  command edits, rewrites or deletes a posting (the Work Order's
  forbidden surfaces "no false finality" and "no arbitrary ledger
  edits").
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.clearing.contracts import ObligationState
from src.clearing.obligations import Obligation
from src.evidence.contracts import EpistemicType
from src.execution.contracts import FinalityClaim, ObservationKind
from src.execution.effects import ExternalObservation
from src.interoperability.status import CanonicalPaymentStatus
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
    FINALITY_OBJECT_TYPE,
    RECOURSE_CASE_OBJECT_TYPE,
    SETTLEMENT_OBJECT_TYPE,
    SETTLEMENT_TRANSITIONS,
    FinalityState,
    InstructionSourceKind,
    LegState,
    PostingKind,
    RecourseKind,
    RecourseCaseState,
    SettlementState,
    validate_command,
)
from .finality import (
    ChallengeRecord,
    Finality,
    FinalityClaimBinding,
    RevocationRecord,
    advance_finality,
    make_finality_record,
    parse_challenge_payload,
    parse_revoke_payload,
    parse_validate_claim_payload,
)
from .postings import (
    PostingEntry,
    discharge_pair,
    journal_digest,
    refund_pair,
    reversal_pair,
    suspense_pair,
    suspense_release_pair,
)
from .recourse import (
    RecourseCase,
    RecourseEvidence,
    RecourseExecution,
    RecourseRejection,
    RefundCompilation,
    advance_recourse,
    make_recourse_record,
    parse_execute_refund_payload,
    parse_request_payload,
)
from .records import (
    CancellationRecord,
    LegOutcome,
    ReconciliationRecord,
    Settlement,
    SettlementInstruction,
    SettlementWindow,
    advance_settlement,
    make_settlement_record,
    parse_cancel_payload,
    parse_create_payload,
    parse_reconcile_payload,
)

DEFAULT_ENGINE_ACTOR = "principal/settlement-service"

#: Default command authority class (the operator tier that drives
#: settlement commands; financial-effect authority for the chain is
#: upstream in clearing — WORK-015 — and finality claims are validated
#: against execution-recorded external evidence — WORK-014).
DEFAULT_COMMAND_AUTHORITY_CLASS = "A3"

_COMMAND_NONCE = "settlement-command-1"

_ESTABLISH_PAYLOAD_FIELDS = frozenset()
_EXECUTE_REVERSAL_PAYLOAD_FIELDS = frozenset()
_COMPILE_PAYLOAD_FIELDS = frozenset({"window"})
_DECISION_REASON_FIELDS = frozenset({"reason"})

#: Rail payment statuses that resolve a settlement leg as settled. These
#: are payment-status terms (the frozen interoperability vocabulary) and —
#: per constitution §4 — they NEVER stand in for settlement finality:
#: finality certificates require finality-class observations.
_LEG_SETTLED_STATUSES = frozenset(
    {
        CanonicalPaymentStatus.SETTLED,
        CanonicalPaymentStatus.CAPTURED_POSTED,
        CanonicalPaymentStatus.FINAL,
    }
)

#: Rail payment statuses that resolve a settlement leg as failed (the
#: frozen vocabulary's retry-safe definitive negatives).
_LEG_FAILED_STATUSES = frozenset(
    {
        CanonicalPaymentStatus.FAILED,
        CanonicalPaymentStatus.RETURNED,
        CanonicalPaymentStatus.REVERSED,
        CanonicalPaymentStatus.EXPIRED,
    }
)

#: Rail payment statuses that leave the leg in explicit suspense (the
#: frozen vocabulary's reconciliation-required ambiguity, plus a
#: contested dispute — never a silent loss or success classification).
_LEG_SUSPENSE_STATUSES = frozenset(
    {
        CanonicalPaymentStatus.UNKNOWN,
        CanonicalPaymentStatus.DISPUTED,
    }
)

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
    SETTLEMENT_OBJECT_TYPE: Settlement.from_dict,
    FINALITY_OBJECT_TYPE: Finality.from_dict,
    RECOURSE_CASE_OBJECT_TYPE: RecourseCase.from_dict,
}

#: Claims that can validate into a finality certificate: a rail
#: finality-class claim of FINAL or SETTLED (REVOKED is revocation
#: evidence, never establishment evidence).
_ESTABLISHMENT_CLAIMS = frozenset({FinalityClaim.FINAL, FinalityClaim.SETTLED})


def _payload_dict(command: Command) -> dict[str, Any]:
    """Decode the command payload into the canonical JSON object form."""
    decoded = payload_to_json_value(command.payload)
    if not isinstance(decoded, dict):
        raise CoreValidationError("settlement command payloads must be objects")
    return decoded


def _journal_payload(entry: Any) -> Any:
    payload = payload_to_json_value(entry.payload) if entry.payload is not None else {}
    if not isinstance(payload, dict):
        raise CoreValidationError("settlement journal payloads must be objects")
    return payload


@dataclass(frozen=True, slots=True)
class SettlementTransition:
    """Explicit decision record for one processed settlement command.

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


class SettlementEngine:
    """Kernel-bound engine for the settlement domain (WORK-016).

    The engine owns the domain index (sealed composite records rebuilt
    through the trusted decode path), the append-only posting journal
    (derived from committed events, never edited) and one real
    transition kernel per environment. It settles sealed clearing
    obligations, folds execution-recorded rail observations, issues and
    withdraws finality certificates, and executes the explicit recourse
    (refund/reversal) boundaries. It never edits the clearing domain's
    obligation lifecycle and never claims finality beyond the recorded
    external evidence.
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
        self._postings: list[PostingEntry] = []
        self._transitions: list[SettlementTransition] = []

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
            ("settlement/create", self._handle_settlement_create),
            ("settlement/authorize", self._handle_settlement_authorize),
            ("settlement/submit", self._handle_settlement_submit),
            ("settlement/cancel", self._handle_settlement_cancel),
            ("settlement/reconcile", self._handle_settlement_reconcile),
            ("finality/validate", self._handle_finality_validate),
            ("finality/establish", self._handle_finality_establish),
            ("finality/challenge", self._handle_finality_challenge),
            ("finality/revoke-claim", self._handle_finality_revoke),
            ("recourse/refund.request", self._handle_refund_request),
            ("recourse/refund.approve", self._handle_refund_approve),
            ("recourse/refund.reject", self._handle_refund_reject),
            ("recourse/refund.compile", self._handle_refund_compile),
            ("recourse/refund.execute", self._handle_refund_execute),
            ("recourse/reversal.request", self._handle_reversal_request),
            ("recourse/reversal.approve", self._handle_reversal_approve),
            ("recourse/reversal.reject", self._handle_reversal_reject),
            ("recourse/reversal.execute", self._handle_reversal_execute),
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
                f"actor {command.actor!r} is not authorized to drive settlement "
                f"in environment {self._environment_id!r}"
            ),
        )

    def _provenance(self, command: Command) -> Provenance:
        return Provenance(
            issuer=command.actor,
            source="settlement/domain",
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
        validate_command(command_type)
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
            idempotency_key=f"settlement:{command_id}",
            nonce=_COMMAND_NONCE,
            requested_at=requested_at,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )

    def submit(self, command: Command) -> SettlementTransition:
        """Process one command through the real kernel pipeline."""
        if not isinstance(command, Command):
            raise CoreValidationError("submit expects a Command envelope")
        result = self._kernel.process(command)
        if result.outcome is Outcome.ACCEPTED:
            self._apply_accepted(command.command_type, result)
        transition = SettlementTransition(
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

    def settlement(self, settlement_id: str) -> Settlement:
        record = self._records.get(settlement_id)
        if record is None or not isinstance(record, Settlement):
            raise CoreValidationError(f"unknown settlement {settlement_id!r}")
        return record

    def finality(self, finality_id: str) -> Finality:
        record = self._records.get(finality_id)
        if record is None or not isinstance(record, Finality):
            raise CoreValidationError(f"unknown finality certificate {finality_id!r}")
        return record

    def recourse_case(self, case_id: str) -> RecourseCase:
        record = self._records.get(case_id)
        if record is None or not isinstance(record, RecourseCase):
            raise CoreValidationError(f"unknown recourse case {case_id!r}")
        return record

    def finality_for_settlement(self, settlement_id: str) -> Finality | None:
        """The (at most one) finality certificate of a settlement."""
        for record in self._records.values():
            if isinstance(record, Finality) and record.spec.settlement_id == settlement_id:
                return record
        return None

    def records(self) -> tuple[Any, ...]:
        return tuple(self._records.values())

    def postings(self) -> tuple[PostingEntry, ...]:
        """The append-only settlement posting journal (event order)."""
        return tuple(self._postings)

    def postings_digest(self) -> str:
        return journal_digest(self._postings)

    def discharge_evidence(self, settlement_id: str) -> tuple[dict[str, str], ...]:
        """Discharge evidence bindings for driving clearing resolves.

        For every settled leg: the leg's identifier and the sealed rail
        observation digest that settled it. The clearing domain's
        ``obligation.resolve`` command (kind ``DISCHARGE_EVIDENCE``)
        consumes exactly these bindings — settlement never mutates the
        clearing lifecycle itself.
        """
        settlement = self.settlement(settlement_id)
        evidence: list[dict[str, str]] = []
        for outcome in settlement.spec.leg_outcomes:
            if LegState(outcome.state) is not LegState.SETTLED:
                continue
            instruction = self._instruction_of(settlement, outcome.instruction_id)
            if InstructionSourceKind(instruction.source_kind) is not InstructionSourceKind.OBLIGATION:
                continue
            evidence.append(
                {
                    "obligation_id": instruction.obligation_id or "",
                    "evidence_ref": outcome.instruction_id,
                    "evidence_digest": outcome.observation_digest or "",
                }
            )
        return tuple(evidence)

    def _decode_record(self, composite: Any) -> Any:
        require_mapping("settlement record", composite)
        object_type = composite.get("envelope", {}).get("object_type")
        decoder = _RECORD_DECODERS.get(object_type)
        if decoder is None:
            raise CoreValidationError(
                f"record claims unknown object type {object_type!r}"
            )
        return decoder(composite)

    def _store_record(self, record: Any) -> None:
        self._records[record.object_id] = record

    def _advance_record(self, record: Any, command: Command, *, state: str, spec: Any = None) -> Any:
        if isinstance(record, Settlement):
            return advance_settlement(
                record,
                state=state,
                provenance=self._provenance(command),
                causation_id=command.command_id,
                correlation_id=command.correlation_id,
                spec=spec,
            )
        if isinstance(record, Finality):
            return advance_finality(
                record,
                state=state,
                provenance=self._provenance(command),
                causation_id=command.command_id,
                correlation_id=command.correlation_id,
                spec=spec,
            )
        return advance_recourse(
            record,
            state=state,
            provenance=self._provenance(command),
            causation_id=command.command_id,
            correlation_id=command.correlation_id,
            spec=spec,
        )

    def _require_source_state(self, command_type: str, state: Any) -> None:
        allowed = SETTLEMENT_TRANSITIONS[command_type]
        if state not in allowed:
            raise CoreValidationError(
                f"{command_type} cannot advance from state {state.value!r}; "
                f"allowed source states are "
                f"{sorted(member.value for member in allowed)}"
            )

    # ------------------------------------------------------------------
    # consumed-evidence decode paths (trusted, fail closed)
    # ------------------------------------------------------------------

    def _decode_obligation(self, composite: Any) -> Obligation:
        """Decode clearing obligations through their own trusted path.

        The composite seal is verified by the clearing domain's decode
        path; a tampered or spliced obligation fails closed here, before
        any instruction fact is derived.
        """
        if not isinstance(composite, Mapping):
            raise CoreValidationError(
                "settlement creation requires clearing Obligation composites"
            )
        return Obligation.from_dict(composite)

    def _decode_observation(self, composite: Any) -> ExternalObservation:
        """Decode execution observations through their own trusted path."""
        if not isinstance(composite, Mapping):
            raise CoreValidationError(
                "settlement reconciliation requires execution observation composites"
            )
        return ExternalObservation.from_dict(composite)

    def _require_observed(self, observation: ExternalObservation) -> None:
        """Only OBSERVED knowledge may fold a leg (constitution §4).

        Defense-in-depth: the execution domain's observation spec already
        fails closed on non-OBSERVED epistemics at construction, so this
        gate re-asserts the invariant at the settlement boundary.
        """
        if observation.spec.epistemic is not EpistemicType.OBSERVED:
            raise CoreValidationError(
                "rail evidence must be OBSERVED knowledge; a "
                f"{observation.spec.epistemic.value} observation can never advance "
                "a settlement leg"
            )

    def _leg_state_for_status(
        self, status: CanonicalPaymentStatus
    ) -> LegState | None:
        """Map the frozen rail payment status onto the leg lifecycle.

        In-flight statuses resolve nothing (the observation is recorded,
        the leg stays ``SUBMITTED``); settling, negative and ambiguous
        statuses resolve the leg to ``SETTLED``/``FAILED``/``UNKNOWN``
        respectively.
        """
        if status in _LEG_SETTLED_STATUSES:
            return LegState.SETTLED
        if status in _LEG_FAILED_STATUSES:
            return LegState.FAILED
        if status in _LEG_SUSPENSE_STATUSES:
            return LegState.UNKNOWN
        return None

    def _require_subject_binding(
        self, observation: ExternalObservation, instruction: SettlementInstruction
    ) -> None:
        """The observation must be digest-bound to this exact leg."""
        if observation.spec.subject_ref != instruction.instruction_id:
            raise CoreValidationError(
                f"observation subject {observation.spec.subject_ref!r} does not "
                f"reference leg {instruction.instruction_id!r}"
            )
        if observation.spec.subject_request_digest != instruction.instruction_digest():
            raise CoreValidationError(
                f"observation digest binding failed for leg {instruction.instruction_id}; "
                "a rail observation cannot be spliced onto a different instruction"
            )

    # ------------------------------------------------------------------
    # shared gates
    # ------------------------------------------------------------------

    def _require_settlement_exclusivity(self, obligation_id: str) -> None:
        """An obligation may sit in at most one non-terminal settlement."""
        for record in self._records.values():
            if not isinstance(record, Settlement):
                continue
            if record.state in SettlementState and record.state not in (
                SettlementState.COMPLETED,
                SettlementState.FAILED,
                SettlementState.CANCELLED,
            ):
                for instruction in record.spec.instructions:
                    if instruction.obligation_id == obligation_id:
                        raise CoreValidationError(
                            f"obligation {obligation_id} is already a leg of the "
                            f"non-terminal settlement {record.object_id} "
                            f"({record.state.value}); an obligation may sit in at "
                            "most one live settlement"
                        )

    def _instruction_of(self, settlement: Settlement, instruction_id: str) -> SettlementInstruction:
        for instruction in settlement.spec.instructions:
            if instruction.instruction_id == instruction_id:
                return instruction
        raise CoreValidationError(
            f"settlement {settlement.object_id} has no instruction {instruction_id!r}"
        )

    def _outcome_of(self, settlement: Settlement, instruction_id: str) -> LegOutcome | None:
        for outcome in settlement.spec.leg_outcomes:
            if outcome.instruction_id == instruction_id:
                return outcome
        return None

    # ------------------------------------------------------------------
    # handlers: the Settlement family
    # ------------------------------------------------------------------

    def _handle_settlement_create(self, command: Command, view: Any) -> TransitionApplication:
        payload = parse_create_payload(_payload_dict(command))
        instructions: list[SettlementInstruction] = []
        seen_obligations: set[str] = set()
        for composite in payload["obligations"]:
            obligation = self._decode_obligation(composite)
            if obligation.state is not ObligationState.DUE:
                raise CoreValidationError(
                    "settlement discharges DUE obligations only; obligation "
                    f"{obligation.object_id} is {obligation.state.value}"
                )
            if obligation.object_id in seen_obligations:
                raise CoreValidationError(
                    f"obligation {obligation.object_id} appears twice in the batch"
                )
            seen_obligations.add(obligation.object_id)
            self._require_settlement_exclusivity(obligation.object_id)
            spec = obligation.spec
            instructions.append(
                SettlementInstruction(
                    instruction_id=f"{payload['settlement_id']}/leg/{obligation.object_id}",
                    source_kind=InstructionSourceKind.OBLIGATION.value,
                    obligation_id=obligation.object_id,
                    obligation_version=obligation.envelope.object_version,
                    obligation_digest=obligation.integrity_hash,
                    refund_case_id=None,
                    source_instruction_id=None,
                    obligor=spec.obligor,
                    obligee=spec.obligee,
                    amount=spec.amount,
                )
            )
        settlement = make_settlement_record(
            settlement_id=payload["settlement_id"],
            environment_id=self._environment_id,
            domain_id=self._domain_id,
            provenance=self._provenance(command),
            window=payload["window"],
            instructions=tuple(instructions),
            causation_id=command.command_id,
            correlation_id=command.correlation_id,
        )
        return TransitionApplication(
            (settlement.envelope,),
            {"settlement": settlement.to_dict()},
        )

    def _handle_settlement_authorize(self, command: Command, view: Any) -> TransitionApplication:
        settlement = self.settlement(command.target_refs[0])
        self._require_source_state("settlement/authorize", settlement.state)
        authorized = self._advance_record(
            settlement, command, state=SettlementState.AUTHORIZED.value
        )
        return TransitionApplication(
            (authorized.envelope,),
            {"settlement": authorized.to_dict()},
        )

    def _handle_settlement_submit(self, command: Command, view: Any) -> TransitionApplication:
        settlement = self.settlement(command.target_refs[0])
        self._require_source_state("settlement/submit", settlement.state)
        submitted_at = command.requested_at
        if parse_utc_timestamp("settlement submitted_at", submitted_at) > parse_utc_timestamp(
            "settlement window.submit_by", settlement.spec.window.submit_by
        ):
            raise CoreValidationError(
                f"settlement {settlement.object_id} cannot be submitted after its "
                f"window closes at {settlement.spec.window.submit_by}"
            )
        outcomes = tuple(
            LegOutcome(
                instruction_id=instruction.instruction_id,
                state=LegState.SUBMITTED.value,
                native_reference=None,
                observation_digest=None,
                observed_at=None,
                suspense=False,
            )
            for instruction in settlement.spec.instructions
        )
        new_spec = _replace_spec(settlement, submitted_at=submitted_at, leg_outcomes=outcomes)
        submitted = self._advance_record(
            settlement,
            command,
            state=SettlementState.SUBMITTED.value,
            spec=new_spec,
        )
        return TransitionApplication(
            (submitted.envelope,),
            {"settlement": submitted.to_dict()},
        )

    def _handle_settlement_cancel(self, command: Command, view: Any) -> TransitionApplication:
        payload = parse_cancel_payload(_payload_dict(command))
        settlement = self.settlement(command.target_refs[0])
        self._require_source_state("settlement/cancel", settlement.state)
        new_spec = _replace_spec(
            settlement,
            cancellation=CancellationRecord(
                reason=payload["reason"], cancelled_at=command.requested_at
            ),
        )
        cancelled = self._advance_record(
            settlement,
            command,
            state=SettlementState.CANCELLED.value,
            spec=new_spec,
        )
        return TransitionApplication(
            (cancelled.envelope,),
            {"settlement": cancelled.to_dict()},
        )

    def _handle_settlement_reconcile(self, command: Command, view: Any) -> TransitionApplication:
        payload = parse_reconcile_payload(_payload_dict(command))
        settlement = self.settlement(command.target_refs[0])
        self._require_source_state("settlement/reconcile", settlement.state)
        as_of = parse_utc_timestamp("settlement.reconcile as_of", payload["as_of"])

        instructions = {
            instruction.instruction_id: instruction
            for instruction in settlement.spec.instructions
        }
        current = {
            outcome.instruction_id: outcome
            for outcome in settlement.spec.leg_outcomes
        }
        postings: list[PostingEntry] = []
        settled: list[str] = []
        failed: list[str] = []
        unknown: list[str] = []
        digests: list[str] = []

        for composite in payload["observations"]:
            observation = self._decode_observation(composite)
            if observation.spec.kind is not ObservationKind.STATUS:
                raise CoreValidationError(
                    "settlement reconciliation folds STATUS observations only; "
                    f"observation {observation.object_id} claims kind "
                    f"{observation.spec.kind.value}"
                )
            self._require_observed(observation)
            instruction = instructions.get(observation.spec.subject_ref)
            if instruction is None:
                raise CoreValidationError(
                    f"observation subject {observation.spec.subject_ref!r} is not a "
                    f"leg of settlement {settlement.object_id}"
                )
            self._require_subject_binding(observation, instruction)
            outcome = current.get(instruction.instruction_id)
            if outcome is None:
                raise CoreValidationError(
                    f"leg {instruction.instruction_id} has no submitted outcome to "
                    "reconcile"
                )
            leg_state = LegState(outcome.state)
            if leg_state in (LegState.SETTLED, LegState.FAILED):
                raise CoreValidationError(
                    f"leg {instruction.instruction_id} is already terminal "
                    f"({leg_state.value}); a terminal leg cannot be re-observed — "
                    "late discrepancies flow through the finality and recourse paths"
                )
            digests.append(observation.integrity_hash)
            new_state = self._leg_state_for_status(observation.spec.canonical_status)
            if new_state is None:
                # An in-flight status is recorded evidence that does not
                # resolve the leg (reconciliation continues).
                continue
            postings.extend(
                self._postings_for_leg_transition(
                    settlement=settlement,
                    instruction=instruction,
                    previous=outcome,
                    new_state=new_state,
                    event_id=command.command_id,
                    event_type=COMMAND_EVENT_TYPES["settlement/reconcile"],
                    posted_at=command.requested_at,
                )
            )
            current[instruction.instruction_id] = LegOutcome(
                instruction_id=instruction.instruction_id,
                state=new_state.value,
                native_reference=None,
                observation_digest=observation.integrity_hash,
                observed_at=observation.spec.observed_at,
                suspense=(new_state is LegState.UNKNOWN),
            )
            if new_state is LegState.SETTLED:
                settled.append(instruction.instruction_id)
            elif new_state is LegState.FAILED:
                failed.append(instruction.instruction_id)
            else:
                unknown.append(instruction.instruction_id)

        # Window aging: legs still SUBMITTED past the settlement window
        # become UNKNOWN with an explicit suspense posting (a state,
        # never a silent classification).
        for instruction in settlement.spec.instructions:
            outcome = current.get(instruction.instruction_id)
            if outcome is None:
                continue
            if LegState(outcome.state) is not LegState.SUBMITTED:
                continue
            if as_of <= parse_utc_timestamp(
                "settlement window.settle_by", settlement.spec.window.settle_by
            ):
                continue
            postings.extend(
                self._postings_for_leg_transition(
                    settlement=settlement,
                    instruction=instruction,
                    previous=outcome,
                    new_state=LegState.UNKNOWN,
                    event_id=command.command_id,
                    event_type=COMMAND_EVENT_TYPES["settlement/reconcile"],
                    posted_at=command.requested_at,
                )
            )
            current[instruction.instruction_id] = LegOutcome(
                instruction_id=instruction.instruction_id,
                state=LegState.UNKNOWN.value,
                native_reference=None,
                observation_digest=None,
                observed_at=None,
                suspense=True,
            )
            unknown.append(instruction.instruction_id)

        states = [LegState(outcome.state) for outcome in current.values()]
        if all(state is LegState.SETTLED for state in states):
            new_settlement_state = SettlementState.COMPLETED
        elif all(state in (LegState.SETTLED, LegState.FAILED) for state in states) and (
            LegState.FAILED in states
        ):
            new_settlement_state = SettlementState.FAILED
        else:
            new_settlement_state = SettlementState.SUBMITTED

        reconciliation = ReconciliationRecord(
            reconciled_at=payload["as_of"],
            settled=tuple(sorted(settled)),
            failed=tuple(sorted(failed)),
            unknown=tuple(sorted(unknown)),
            observation_digests=tuple(digests),
        )
        new_spec = _replace_spec(
            settlement,
            leg_outcomes=tuple(current[instruction.instruction_id] for instruction in settlement.spec.instructions),
            reconciliations=settlement.spec.reconciliations + (reconciliation,),
        )
        reconciled = self._advance_record(
            settlement,
            command,
            state=new_settlement_state.value,
            spec=new_spec,
        )
        return TransitionApplication(
            (reconciled.envelope,),
            {
                "settlement": reconciled.to_dict(),
                "postings": [entry.to_dict() for entry in postings],
                "report": reconciliation.to_dict(),
            },
        )

    def _postings_for_leg_transition(
        self,
        *,
        settlement: Settlement,
        instruction: SettlementInstruction,
        previous: LegOutcome,
        new_state: LegState,
        event_id: str,
        event_type: str,
        posted_at: str,
    ) -> list[PostingEntry]:
        """The balanced postings implied by one leg transition.

        Terminal transitions from a suspense state first release the
        suspense pair (exact compensation); settled legs additionally
        emit the discharge (or refund) pair. Nothing here edits an
        existing posting: releases and reversals are new compensation
        entries (constitution invariant 17).
        """
        postings: list[PostingEntry] = []
        previous_state = LegState(previous.state)
        is_refund_linked = settlement.spec.linked_ref is not None
        if previous.suspense and new_state in (LegState.SETTLED, LegState.FAILED):
            postings.append(
                suspense_release_pair(
                    event_id=event_id,
                    event_type=event_type,
                    instruction_ref=instruction.instruction_id,
                    obligor=instruction.obligor,
                    obligee=instruction.obligee,
                    asset=instruction.amount.asset,
                    scale=instruction.amount.scale,
                    amount_value=instruction.amount.value,
                    posted_at=posted_at,
                )
            )
        if new_state is LegState.UNKNOWN and not previous.suspense:
            # Idempotent: a leg already in suspense never re-posts the
            # suspense pair (repeated UNKNOWN observations fold to one
            # explicit suspense position).
            postings.append(
                suspense_pair(
                    event_id=event_id,
                    event_type=event_type,
                    instruction_ref=instruction.instruction_id,
                    obligor=instruction.obligor,
                    obligee=instruction.obligee,
                    asset=instruction.amount.asset,
                    scale=instruction.amount.scale,
                    amount_value=instruction.amount.value,
                    posted_at=posted_at,
                )
            )
        elif new_state is LegState.SETTLED:
            if is_refund_linked:
                postings.append(
                    refund_pair(
                        event_id=event_id,
                        event_type=event_type,
                        instruction_ref=instruction.instruction_id,
                        obligor=instruction.obligor,
                        obligee=instruction.obligee,
                        asset=instruction.amount.asset,
                        scale=instruction.amount.scale,
                        amount_value=instruction.amount.value,
                        posted_at=posted_at,
                    )
                )
            else:
                postings.append(
                    discharge_pair(
                        event_id=event_id,
                        event_type=event_type,
                        instruction_ref=instruction.instruction_id,
                        obligor=instruction.obligor,
                        obligee=instruction.obligee,
                        asset=instruction.amount.asset,
                        scale=instruction.amount.scale,
                        amount_value=instruction.amount.value,
                        posted_at=posted_at,
                    )
                )
        _ = previous_state
        return postings

    # ------------------------------------------------------------------
    # handlers: the Finality family
    # ------------------------------------------------------------------

    def _handle_finality_validate(self, command: Command, view: Any) -> TransitionApplication:
        payload = parse_validate_claim_payload(_payload_dict(command))
        settlement = self.settlement(payload["settlement_id"])
        observation = self._decode_observation(payload["observation"])
        if observation.spec.kind is not ObservationKind.FINALITY:
            raise CoreValidationError(
                "finality certificates validate FINALITY-class observations only; "
                f"observation {observation.object_id} claims kind "
                f"{observation.spec.kind.value} — a payment status can never stand "
                "in for settlement finality (constitution §4)"
            )
        self._require_observed(observation)
        claim = observation.spec.finality_claim
        # The execution spec enforces the canonical FINALITY content shape
        # ({claim, native_reference}) at construction, so direct access is
        # the trusted path here.
        content = observation.spec.content
        native_reference = content["native_reference"]
        require_identifier("finality claim native_reference", native_reference)
        if claim not in _ESTABLISHMENT_CLAIMS:
            raise CoreValidationError(
                f"finality claim {claim.value!r} cannot validate into a "
                "certificate; only FINAL or SETTLED claims establish finality "
                "(REVOKED claims are revocation evidence)"
            )
        instruction = self._instruction_of(settlement, observation.spec.subject_ref)
        self._require_subject_binding(observation, instruction)
        outcome = self._outcome_of(settlement, instruction.instruction_id)
        if outcome is None or LegState(outcome.state) is not LegState.SETTLED:
            raise CoreValidationError(
                f"finality claims cover SETTLED legs only; leg "
                f"{instruction.instruction_id} is "
                f"{LegState(outcome.state).value if outcome else 'unsubmitted'}"
            )
        binding = FinalityClaimBinding(
            instruction_id=instruction.instruction_id,
            native_reference=native_reference,
            claim=claim.value,
            observation_id=observation.object_id,
            observation_digest=observation.integrity_hash,
            observed_at=observation.spec.observed_at,
        )
        existing = self._records.get(payload["finality_id"])
        if existing is not None:
            if not isinstance(existing, Finality):
                raise CoreValidationError(
                    f"finality identifier {payload['finality_id']!r} is already "
                    "used by another settlement-domain object"
                )
            certificate = existing
            if certificate.spec.settlement_id != settlement.object_id:
                raise CoreValidationError(
                    "a finality certificate is bound to one settlement; "
                    f"{payload['finality_id']!r} already covers "
                    f"{certificate.spec.settlement_id!r}"
                )
            self._require_source_state("finality/validate", certificate.state)
            for bound in certificate.spec.claims:
                if bound.instruction_id == instruction.instruction_id:
                    raise CoreValidationError(
                        f"leg {instruction.instruction_id} already carries a "
                        "validated finality claim on this certificate"
                    )
            new_spec = _replace_finality_spec(certificate, claims=certificate.spec.claims + (binding,))
            updated = self._advance_record(
                certificate,
                command,
                state=FinalityState.PENDING.value,
                spec=new_spec,
            )
            return TransitionApplication(
                (updated.envelope,),
                {"finality": updated.to_dict()},
            )
        for record in self._records.values():
            if (
                isinstance(record, Finality)
                and record.spec.settlement_id == settlement.object_id
            ):
                raise CoreValidationError(
                    f"settlement {settlement.object_id} already carries finality "
                    f"certificate {record.object_id}; at most one certificate per "
                    "settlement"
                )
        certificate = make_finality_record(
            finality_id=payload["finality_id"],
            settlement_id=settlement.object_id,
            settlement_digest=settlement.spec.instructions_digest,
            claims=(binding,),
            environment_id=self._environment_id,
            domain_id=self._domain_id,
            provenance=self._provenance(command),
            causation_id=command.command_id,
            correlation_id=command.correlation_id,
        )
        return TransitionApplication(
            (certificate.envelope,),
            {"finality": certificate.to_dict()},
        )

    def _handle_finality_establish(self, command: Command, view: Any) -> TransitionApplication:
        strict_fields(
            "finality.establish payload", _payload_dict(command), _ESTABLISH_PAYLOAD_FIELDS
        )
        certificate = self.finality(command.target_refs[0])
        self._require_source_state("finality/establish", certificate.state)
        settlement = self.settlement(certificate.spec.settlement_id)
        if settlement.state not in (SettlementState.COMPLETED, SettlementState.FAILED):
            raise CoreValidationError(
                "finality can be established only for a terminal settlement; "
                f"settlement {settlement.object_id} is {settlement.state.value} "
                "(constitution invariant 11 — PaySwap never overstates "
                "settlement finality)"
            )
        if certificate.spec.settlement_digest != settlement.spec.instructions_digest:
            raise CoreValidationError(
                "finality certificate and settlement disagree on the instruction "
                "set digest; the certificate cannot be established"
            )
        covered = {binding.instruction_id for binding in certificate.spec.claims}
        settled = {
            outcome.instruction_id
            for outcome in settlement.spec.leg_outcomes
            if LegState(outcome.state) is LegState.SETTLED
        }
        if covered != settled:
            missing = sorted(settled - covered)
            extra = sorted(covered - settled)
            raise CoreValidationError(
                "finality establishment requires a validated claim covering every "
                f"settled leg; missing={missing}, extra={extra}"
            )
        if not settled:
            raise CoreValidationError(
                "finality establishment requires at least one settled leg; the "
                "certificate must certify something real"
            )
        new_spec = _replace_finality_spec(
            certificate, established_at=command.requested_at
        )
        established = self._advance_record(
            certificate,
            command,
            state=FinalityState.ESTABLISHED.value,
            spec=new_spec,
        )
        return TransitionApplication(
            (established.envelope,),
            {"finality": established.to_dict()},
        )

    def _handle_finality_challenge(self, command: Command, view: Any) -> TransitionApplication:
        payload = parse_challenge_payload(_payload_dict(command))
        certificate = self.finality(command.target_refs[0])
        self._require_source_state("finality/challenge", certificate.state)
        new_spec = _replace_finality_spec(
            certificate,
            challenge=ChallengeRecord(
                evidence_ref=payload["evidence_ref"],
                evidence_digest=payload["evidence_digest"],
                reason=payload["reason"],
                challenged_at=command.requested_at,
            ),
        )
        challenged = self._advance_record(
            certificate,
            command,
            state=FinalityState.CHALLENGED.value,
            spec=new_spec,
        )
        return TransitionApplication(
            (challenged.envelope,),
            {"finality": challenged.to_dict()},
        )

    def _handle_finality_revoke(self, command: Command, view: Any) -> TransitionApplication:
        payload = parse_revoke_payload(_payload_dict(command))
        certificate = self.finality(command.target_refs[0])
        self._require_source_state("finality/revoke-claim", certificate.state)
        new_spec = _replace_finality_spec(
            certificate,
            revocation=RevocationRecord(
                evidence_ref=payload["evidence_ref"],
                evidence_digest=payload["evidence_digest"],
                reason=payload["reason"],
                revoked_at=command.requested_at,
            ),
        )
        revoked = self._advance_record(
            certificate,
            command,
            state=FinalityState.REVOKED.value,
            spec=new_spec,
        )
        return TransitionApplication(
            (revoked.envelope,),
            {"finality": revoked.to_dict()},
        )

    # ------------------------------------------------------------------
    # handlers: the Recourse families
    # ------------------------------------------------------------------

    def _handle_recourse_request(
        self, command: Command, view: Any, expected_kind: RecourseKind
    ) -> TransitionApplication:
        payload = parse_request_payload(_payload_dict(command))
        if payload["kind"] is not expected_kind:
            raise CoreValidationError(
                f"command {command.command_type!r} requires a {expected_kind.value} "
                f"case, got {payload['kind'].value}"
            )
        settlement = self.settlement(payload["settlement_id"])
        instruction_map = {
            instruction.instruction_id: instruction
            for instruction in settlement.spec.instructions
        }
        for instruction_id in payload["instruction_ids"]:
            if instruction_id not in instruction_map:
                raise CoreValidationError(
                    f"recourse references unknown instruction {instruction_id!r} "
                    f"of settlement {settlement.object_id}"
                )
            outcome = self._outcome_of(settlement, instruction_id)
            if outcome is None or LegState(outcome.state) is not LegState.SETTLED:
                raise CoreValidationError(
                    "recourse covers SETTLED legs only; leg "
                    f"{instruction_id} is "
                    f"{LegState(outcome.state).value if outcome else 'unsubmitted'}"
                )
        certificate = self.finality_for_settlement(settlement.object_id)
        if expected_kind is RecourseKind.REFUND:
            if settlement.state not in (SettlementState.COMPLETED, SettlementState.FAILED):
                raise CoreValidationError(
                    "a refund case requires a terminal settlement with settled "
                    f"legs; settlement {settlement.object_id} is "
                    f"{settlement.state.value}"
                )
        else:
            if certificate is None or certificate.state not in (
                FinalityState.REVOKED,
                FinalityState.CHALLENGED,
            ):
                raise CoreValidationError(
                    "a reversal case requires the settlement's finality "
                    "certificate to be REVOKED or CHALLENGED; reversals "
                    "compensate discharges whose finality was explicitly "
                    "withdrawn (constitution invariant 11)"
                )
            if payload["evidence_ref"] != certificate.object_id:
                raise CoreValidationError(
                    "reversal evidence must reference the withdrawn finality "
                    f"certificate {certificate.object_id!r}"
                )
            if payload["evidence_digest"] != certificate.integrity_hash:
                raise CoreValidationError(
                    "reversal evidence must be digest-bound to the withdrawn "
                    "finality certificate"
                )
        case = make_recourse_record(
            case_id=payload["case_id"],
            kind=expected_kind.value,
            settlement_id=settlement.object_id,
            instruction_ids=payload["instruction_ids"],
            evidence=RecourseEvidence(
                evidence_ref=payload["evidence_ref"],
                evidence_digest=payload["evidence_digest"],
                epistemic_type=payload["epistemic_type"],
                reason=payload["reason"],
            ),
            environment_id=self._environment_id,
            domain_id=self._domain_id,
            provenance=self._provenance(command),
            causation_id=command.command_id,
            correlation_id=command.correlation_id,
        )
        return TransitionApplication((case.envelope,), {"case": case.to_dict()})

    def _handle_recourse_decision(
        self,
        command: Command,
        view: Any,
        *,
        command_type: str,
        approved: bool,
    ) -> TransitionApplication:
        fields = frozenset() if approved else _DECISION_REASON_FIELDS
        payload = _payload_dict(command)
        strict_fields(f"{command_type} payload", payload, fields)
        reason = payload.get("reason")
        if not approved:
            require_text(f"{command_type} reason", reason)
        case = self.recourse_case(command.target_refs[0])
        self._require_source_state(command_type, case.state)
        if approved:
            updated = self._advance_record(
                case, command, state=RecourseCaseState.APPROVED.value
            )
        else:
            new_spec = _replace_recourse_spec(
                case,
                rejection=RecourseRejection(
                    reason=reason, rejected_at=command.requested_at
                ),
            )
            updated = self._advance_record(
                case,
                command,
                state=RecourseCaseState.REJECTED.value,
                spec=new_spec,
            )
        return TransitionApplication((updated.envelope,), {"case": updated.to_dict()})

    def _handle_refund_compile(self, command: Command, view: Any) -> TransitionApplication:
        payload = _payload_dict(command)
        strict_fields(
            "recourse refund.compile payload", payload, _COMPILE_PAYLOAD_FIELDS
        )
        window = SettlementWindow.parse("recourse refund.compile window", payload["window"])
        case = self.recourse_case(command.target_refs[0])
        self._require_source_state("recourse/refund.compile", case.state)
        if RecourseKind(case.spec.kind) is not RecourseKind.REFUND:
            raise CoreValidationError("only refund cases compile a refund settlement")
        settlement = self.settlement(case.spec.settlement_id)
        refund_settlement_id = f"{case.object_id}/refund"
        if refund_settlement_id in self._records:
            raise CoreValidationError(
                f"refund settlement {refund_settlement_id!r} already exists"
            )
        instruction_map = {
            instruction.instruction_id: instruction
            for instruction in settlement.spec.instructions
        }
        refund_instructions = tuple(
            SettlementInstruction(
                instruction_id=f"{refund_settlement_id}/leg/{instruction_id}",
                source_kind=InstructionSourceKind.REFUND_LEG.value,
                obligation_id=None,
                obligation_version=None,
                obligation_digest=None,
                refund_case_id=case.object_id,
                source_instruction_id=instruction_id,
                obligor=instruction_map[instruction_id].obligee,
                obligee=instruction_map[instruction_id].obligor,
                amount=instruction_map[instruction_id].amount,
            )
            for instruction_id in case.spec.instruction_ids
        )
        refund_settlement = make_settlement_record(
            settlement_id=refund_settlement_id,
            environment_id=self._environment_id,
            domain_id=self._domain_id,
            provenance=self._provenance(command),
            window=window,
            instructions=refund_instructions,
            linked_ref=settlement.object_id,
            causation_id=command.command_id,
            correlation_id=command.correlation_id,
        )
        new_spec = _replace_recourse_spec(
            case,
            compilation=RefundCompilation(
                compiled_settlement_id=refund_settlement_id,
                compiled_at=command.requested_at,
            ),
        )
        compiled = self._advance_record(
            case,
            command,
            state=RecourseCaseState.COMPILED.value,
            spec=new_spec,
        )
        return TransitionApplication(
            (compiled.envelope, refund_settlement.envelope),
            {"case": compiled.to_dict(), "settlement": refund_settlement.to_dict()},
        )

    def _handle_refund_execute(self, command: Command, view: Any) -> TransitionApplication:
        payload = parse_execute_refund_payload(_payload_dict(command))
        case = self.recourse_case(command.target_refs[0])
        self._require_source_state("recourse/refund.execute", case.state)
        refund_settlement_id = case.spec.compilation.compiled_settlement_id
        if payload["settlement_id"] != refund_settlement_id:
            raise CoreValidationError(
                "refund execution must reference the compiled settlement "
                f"{refund_settlement_id!r}"
            )
        refund_settlement = self.settlement(refund_settlement_id)
        if refund_settlement.state is not SettlementState.COMPLETED:
            raise CoreValidationError(
                "a refund case executes only once its linked refund settlement "
                f"COMPLETED; settlement {refund_settlement.object_id} is "
                f"{refund_settlement.state.value}"
            )
        refund_instruction_ids = {
            instruction.instruction_id for instruction in refund_settlement.spec.instructions
        }
        posting_refs = tuple(
            entry.entry_id
            for entry in self._postings
            if entry.kind == PostingKind.REFUND.value
            and entry.instruction_ref in refund_instruction_ids
        )
        if not posting_refs:
            raise CoreValidationError(
                "refund execution requires the linked settlement's refund "
                "postings to exist"
            )
        new_spec = _replace_recourse_spec(
            case,
            execution=RecourseExecution(
                executed_at=command.requested_at, posting_refs=posting_refs
            ),
        )
        executed = self._advance_record(
            case,
            command,
            state=RecourseCaseState.EXECUTED.value,
            spec=new_spec,
        )
        return TransitionApplication((executed.envelope,), {"case": executed.to_dict()})

    def _handle_reversal_execute(self, command: Command, view: Any) -> TransitionApplication:
        strict_fields(
            "recourse reversal.execute payload",
            _payload_dict(command),
            _EXECUTE_REVERSAL_PAYLOAD_FIELDS,
        )
        case = self.recourse_case(command.target_refs[0])
        self._require_source_state("recourse/reversal.execute", case.state)
        if RecourseKind(case.spec.kind) is not RecourseKind.REVERSAL:
            raise CoreValidationError("only reversal cases execute compensation postings")
        settlement = self.settlement(case.spec.settlement_id)
        instruction_map = {
            instruction.instruction_id: instruction
            for instruction in settlement.spec.instructions
        }
        postings: list[PostingEntry] = []
        for instruction_id in case.spec.instruction_ids:
            instruction = instruction_map[instruction_id]
            postings.append(
                reversal_pair(
                    event_id=command.command_id,
                    event_type=COMMAND_EVENT_TYPES["recourse/reversal.execute"],
                    instruction_ref=instruction_id,
                    obligor=instruction.obligor,
                    obligee=instruction.obligee,
                    asset=instruction.amount.asset,
                    scale=instruction.amount.scale,
                    amount_value=instruction.amount.value,
                    posted_at=command.requested_at,
                )
            )
        new_spec = _replace_recourse_spec(
            case,
            execution=RecourseExecution(
                executed_at=command.requested_at,
                posting_refs=tuple(entry.entry_id for entry in postings),
            ),
        )
        executed = self._advance_record(
            case,
            command,
            state=RecourseCaseState.EXECUTED.value,
            spec=new_spec,
        )
        return TransitionApplication(
            (executed.envelope,),
            {"case": executed.to_dict(), "postings": [entry.to_dict() for entry in postings]},
        )

    # ------------------------------------------------------------------
    # thin family wrappers (command kind checks)
    # ------------------------------------------------------------------

    def _handle_refund_request(self, command: Command, view: Any) -> TransitionApplication:
        return self._handle_recourse_request(command, view, RecourseKind.REFUND)

    def _handle_reversal_request(self, command: Command, view: Any) -> TransitionApplication:
        return self._handle_recourse_request(command, view, RecourseKind.REVERSAL)

    def _handle_refund_approve(self, command: Command, view: Any) -> TransitionApplication:
        return self._handle_recourse_decision(
            command, view, command_type="recourse/refund.approve", approved=True
        )

    def _handle_refund_reject(self, command: Command, view: Any) -> TransitionApplication:
        return self._handle_recourse_decision(
            command, view, command_type="recourse/refund.reject", approved=False
        )

    def _handle_reversal_approve(self, command: Command, view: Any) -> TransitionApplication:
        return self._handle_recourse_decision(
            command, view, command_type="recourse/reversal.approve", approved=True
        )

    def _handle_reversal_reject(self, command: Command, view: Any) -> TransitionApplication:
        return self._handle_recourse_decision(
            command, view, command_type="recourse/reversal.reject", approved=False
        )

    # ------------------------------------------------------------------
    # public command surface (the frozen families)
    # ------------------------------------------------------------------

    def create_settlement(
        self,
        *,
        command_id: str,
        requested_at: str,
        settlement_id: str,
        obligations: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...],
        submit_by: str,
        settle_by: str,
    ) -> SettlementTransition:
        """``Settlement: Create`` — draft one discharge batch.

        The instruction economics (obligor, obligee, asset, amount) are
        derived from the sealed clearing obligations; they are never
        trusted from the command payload.
        """
        command = self.build_raw_command(
            command_id=command_id,
            command_type="settlement/create",
            requested_at=requested_at,
            target_refs=(settlement_id,),
            payload={
                "settlement_id": settlement_id,
                "window": {"submit_by": submit_by, "settle_by": settle_by},
                "obligations": list(obligations),
            },
            expected_versions={settlement_id: 0},
        )
        return self.submit(command)

    def authorize_settlement(
        self, *, command_id: str, requested_at: str, settlement_id: str
    ) -> SettlementTransition:
        """``Settlement: Authorize`` — the authority gate before submission."""
        settlement = self.settlement(settlement_id)
        command = self.build_raw_command(
            command_id=command_id,
            command_type="settlement/authorize",
            requested_at=requested_at,
            target_refs=(settlement_id,),
            payload={},
            expected_versions={settlement_id: settlement.envelope.object_version},
        )
        return self.submit(command)

    def submit_settlement(
        self, *, command_id: str, requested_at: str, settlement_id: str
    ) -> SettlementTransition:
        """``Settlement: Submit`` — submit every leg to the rail (in window)."""
        settlement = self.settlement(settlement_id)
        command = self.build_raw_command(
            command_id=command_id,
            command_type="settlement/submit",
            requested_at=requested_at,
            target_refs=(settlement_id,),
            payload={},
            expected_versions={settlement_id: settlement.envelope.object_version},
        )
        return self.submit(command)

    def cancel_settlement(
        self, *, command_id: str, requested_at: str, settlement_id: str, reason: str
    ) -> SettlementTransition:
        """``Settlement: Cancel`` — abandon the batch before submission."""
        settlement = self.settlement(settlement_id)
        command = self.build_raw_command(
            command_id=command_id,
            command_type="settlement/cancel",
            requested_at=requested_at,
            target_refs=(settlement_id,),
            payload={"reason": reason},
            expected_versions={settlement_id: settlement.envelope.object_version},
        )
        return self.submit(command)

    def reconcile_settlement(
        self,
        *,
        command_id: str,
        requested_at: str,
        settlement_id: str,
        as_of: str,
        observations: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...],
    ) -> SettlementTransition:
        """``Settlement: Reconcile`` — fold the recorded rail evidence."""
        settlement = self.settlement(settlement_id)
        command = self.build_raw_command(
            command_id=command_id,
            command_type="settlement/reconcile",
            requested_at=requested_at,
            target_refs=(settlement_id,),
            payload={"as_of": as_of, "observations": list(observations)},
            expected_versions={settlement_id: settlement.envelope.object_version},
        )
        return self.submit(command)

    def validate_finality_claim(
        self,
        *,
        command_id: str,
        requested_at: str,
        finality_id: str,
        settlement_id: str,
        observation: Mapping[str, Any],
    ) -> SettlementTransition:
        """``Finality: Validate`` — validate one rail finality claim."""
        settlement = self.settlement(settlement_id)
        existing = self._records.get(finality_id)
        expected_version = (
            existing.envelope.object_version
            if isinstance(existing, Finality)
            else 0
        )
        command = self.build_raw_command(
            command_id=command_id,
            command_type="finality/validate",
            requested_at=requested_at,
            target_refs=(finality_id, settlement_id),
            payload={
                "finality_id": finality_id,
                "settlement_id": settlement_id,
                "observation": dict(observation),
            },
            expected_versions={
                finality_id: expected_version,
                settlement_id: settlement.envelope.object_version,
            },
        )
        return self.submit(command)

    def establish_finality(
        self, *, command_id: str, requested_at: str, finality_id: str
    ) -> SettlementTransition:
        """``Finality: Establish`` — issue the certificate (strict gates)."""
        certificate = self.finality(finality_id)
        command = self.build_raw_command(
            command_id=command_id,
            command_type="finality/establish",
            requested_at=requested_at,
            target_refs=(finality_id,),
            payload={},
            expected_versions={finality_id: certificate.envelope.object_version},
        )
        return self.submit(command)

    def challenge_finality(
        self,
        *,
        command_id: str,
        requested_at: str,
        finality_id: str,
        evidence_ref: str,
        evidence_digest: str,
        reason: str,
    ) -> SettlementTransition:
        """``Finality: Challenge`` — suspend reliance on the certificate."""
        certificate = self.finality(finality_id)
        command = self.build_raw_command(
            command_id=command_id,
            command_type="finality/challenge",
            requested_at=requested_at,
            target_refs=(finality_id,),
            payload={
                "evidence_ref": evidence_ref,
                "evidence_digest": evidence_digest,
                "reason": reason,
            },
            expected_versions={finality_id: certificate.envelope.object_version},
        )
        return self.submit(command)

    def revoke_finality_claim(
        self,
        *,
        command_id: str,
        requested_at: str,
        finality_id: str,
        evidence_ref: str,
        evidence_digest: str,
        reason: str,
    ) -> SettlementTransition:
        """``Finality: RevokeClaim`` — withdraw the certificate (terminal)."""
        certificate = self.finality(finality_id)
        command = self.build_raw_command(
            command_id=command_id,
            command_type="finality/revoke-claim",
            requested_at=requested_at,
            target_refs=(finality_id,),
            payload={
                "evidence_ref": evidence_ref,
                "evidence_digest": evidence_digest,
                "reason": reason,
            },
            expected_versions={finality_id: certificate.envelope.object_version},
        )
        return self.submit(command)

    def request_refund(
        self,
        *,
        command_id: str,
        requested_at: str,
        case_id: str,
        settlement_id: str,
        instruction_ids: list[str] | tuple[str, ...],
        evidence_ref: str,
        evidence_digest: str,
        epistemic_type: str,
        reason: str,
    ) -> SettlementTransition:
        """``Recourse: Request`` (refund) — open a return case with evidence."""
        command = self.build_raw_command(
            command_id=command_id,
            command_type="recourse/refund.request",
            requested_at=requested_at,
            target_refs=(case_id,),
            payload={
                "case_id": case_id,
                "kind": RecourseKind.REFUND.value,
                "settlement_id": settlement_id,
                "instruction_ids": list(instruction_ids),
                "evidence_ref": evidence_ref,
                "evidence_digest": evidence_digest,
                "epistemic_type": epistemic_type,
                "reason": reason,
            },
            expected_versions={case_id: 0},
        )
        return self.submit(command)

    def approve_refund(
        self, *, command_id: str, requested_at: str, case_id: str
    ) -> SettlementTransition:
        """``Recourse: Approve`` (refund)."""
        case = self.recourse_case(case_id)
        command = self.build_raw_command(
            command_id=command_id,
            command_type="recourse/refund.approve",
            requested_at=requested_at,
            target_refs=(case_id,),
            payload={},
            expected_versions={case_id: case.envelope.object_version},
        )
        return self.submit(command)

    def reject_refund(
        self, *, command_id: str, requested_at: str, case_id: str, reason: str
    ) -> SettlementTransition:
        """``Recourse: Reject`` (refund)."""
        case = self.recourse_case(case_id)
        command = self.build_raw_command(
            command_id=command_id,
            command_type="recourse/refund.reject",
            requested_at=requested_at,
            target_refs=(case_id,),
            payload={"reason": reason},
            expected_versions={case_id: case.envelope.object_version},
        )
        return self.submit(command)

    def compile_refund(
        self,
        *,
        command_id: str,
        requested_at: str,
        case_id: str,
        submit_by: str,
        settle_by: str,
    ) -> SettlementTransition:
        """``Recourse: Compile`` — derive the linked refund settlement."""
        case = self.recourse_case(case_id)
        refund_settlement_id = f"{case_id}/refund"
        command = self.build_raw_command(
            command_id=command_id,
            command_type="recourse/refund.compile",
            requested_at=requested_at,
            target_refs=(case_id, refund_settlement_id),
            payload={"window": {"submit_by": submit_by, "settle_by": settle_by}},
            expected_versions={
                case_id: case.envelope.object_version,
                refund_settlement_id: 0,
            },
        )
        return self.submit(command)

    def execute_refund(
        self,
        *,
        command_id: str,
        requested_at: str,
        case_id: str,
        settlement_id: str,
    ) -> SettlementTransition:
        """``Recourse: ExecuteRefund`` — execute against the linked settlement."""
        case = self.recourse_case(case_id)
        command = self.build_raw_command(
            command_id=command_id,
            command_type="recourse/refund.execute",
            requested_at=requested_at,
            target_refs=(case_id,),
            payload={"settlement_id": settlement_id},
            expected_versions={case_id: case.envelope.object_version},
        )
        return self.submit(command)

    def request_reversal(
        self,
        *,
        command_id: str,
        requested_at: str,
        case_id: str,
        settlement_id: str,
        instruction_ids: list[str] | tuple[str, ...],
        evidence_ref: str,
        evidence_digest: str,
        epistemic_type: str,
        reason: str,
    ) -> SettlementTransition:
        """``Recourse: Request`` (reversal) — compensate a withdrawn discharge."""
        command = self.build_raw_command(
            command_id=command_id,
            command_type="recourse/reversal.request",
            requested_at=requested_at,
            target_refs=(case_id,),
            payload={
                "case_id": case_id,
                "kind": RecourseKind.REVERSAL.value,
                "settlement_id": settlement_id,
                "instruction_ids": list(instruction_ids),
                "evidence_ref": evidence_ref,
                "evidence_digest": evidence_digest,
                "epistemic_type": epistemic_type,
                "reason": reason,
            },
            expected_versions={case_id: 0},
        )
        return self.submit(command)

    def approve_reversal(
        self, *, command_id: str, requested_at: str, case_id: str
    ) -> SettlementTransition:
        """``Recourse: Approve`` (reversal)."""
        case = self.recourse_case(case_id)
        command = self.build_raw_command(
            command_id=command_id,
            command_type="recourse/reversal.approve",
            requested_at=requested_at,
            target_refs=(case_id,),
            payload={},
            expected_versions={case_id: case.envelope.object_version},
        )
        return self.submit(command)

    def reject_reversal(
        self, *, command_id: str, requested_at: str, case_id: str, reason: str
    ) -> SettlementTransition:
        """``Recourse: Reject`` (reversal)."""
        case = self.recourse_case(case_id)
        command = self.build_raw_command(
            command_id=command_id,
            command_type="recourse/reversal.reject",
            requested_at=requested_at,
            target_refs=(case_id,),
            payload={"reason": reason},
            expected_versions={case_id: case.envelope.object_version},
        )
        return self.submit(command)

    def execute_reversal(
        self, *, command_id: str, requested_at: str, case_id: str
    ) -> SettlementTransition:
        """``Recourse: ExecuteReversal`` — post the compensation entries."""
        case = self.recourse_case(case_id)
        command = self.build_raw_command(
            command_id=command_id,
            command_type="recourse/reversal.execute",
            requested_at=requested_at,
            target_refs=(case_id,),
            payload={},
            expected_versions={case_id: case.envelope.object_version},
        )
        return self.submit(command)

    # ------------------------------------------------------------------
    # event application (the single mutation path)
    # ------------------------------------------------------------------

    def _apply_accepted(self, command_type: str, result: TransitionResult) -> None:
        event_type = COMMAND_EVENT_TYPES.get(command_type)
        if event_type is None:
            raise CoreValidationError(f"command {command_type!r} is not registered")
        payload = payload_to_json_value(result.payload) if result.payload is not None else {}
        self._apply_event_payload(event_type, payload)

    def _apply_event_payload(self, event_type: str, payload: Any) -> None:
        """Apply one committed event payload to the index and journal.

        This is the single mutation path, shared by live commits and
        journal rebuilds; every record re-enters through the trusted
        decode path (seal verification included) and every posting is
        appended — never edited.
        """
        if not isinstance(payload, Mapping):
            raise CoreValidationError("committed settlement payloads must be objects")
        if event_type == "settlement/settlement-created":
            self._store_record(self._decode_record(payload["settlement"]))
        elif event_type in (
            "settlement/settlement-authorized",
            "settlement/settlement-submitted",
            "settlement/settlement-cancelled",
        ):
            self._store_record(self._decode_record(payload["settlement"]))
        elif event_type == "settlement/settlement-reconciled":
            self._store_record(self._decode_record(payload["settlement"]))
            for entry in payload["postings"]:
                self._postings.append(PostingEntry.from_dict(entry))
        elif event_type in (
            "settlement/finality-validated",
            "settlement/finality-established",
            "settlement/finality-challenged",
            "settlement/finality-revoked",
        ):
            self._store_record(self._decode_record(payload["finality"]))
        elif event_type == "settlement/refund-compiled":
            self._store_record(self._decode_record(payload["case"]))
            self._store_record(self._decode_record(payload["settlement"]))
        elif event_type in (
            "settlement/refund-requested",
            "settlement/refund-approved",
            "settlement/refund-rejected",
            "settlement/refund-executed",
            "settlement/reversal-requested",
            "settlement/reversal-approved",
            "settlement/reversal-rejected",
        ):
            self._store_record(self._decode_record(payload["case"]))
        elif event_type == "settlement/reversal-executed":
            self._store_record(self._decode_record(payload["case"]))
            for entry in payload["postings"]:
                self._postings.append(PostingEntry.from_dict(entry))
        else:
            raise CoreValidationError(f"unknown settlement event type {event_type!r}")

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
        # The append-only posting journal is recomputed from the
        # committed journal (transformation completeness: the postings
        # are a deterministic fold of the event payloads).
        self._postings = []
        for entry in self._kernel.journal:
            self._fold_journal_entry(entry)
        # The transitions log is an engine-local decision log; it is not
        # part of durable state (the kernel journal is authoritative).

    def _fold_journal_entry(self, entry: Any) -> None:
        self._apply_event_payload(entry.event.event_type, _journal_payload(entry))

    @classmethod
    def rebuild_from_journal(
        cls,
        *,
        environment_id: str,
        domain_id: str,
        journal: Iterable[Any],
        actor: str = DEFAULT_ENGINE_ACTOR,
        command_authority_class: str = DEFAULT_COMMAND_AUTHORITY_CLASS,
    ) -> "SettlementEngine":
        """Rebuild the domain index and posting journal from the journal alone.

        Transformation completeness: the committed event payloads carry
        every resulting record and posting, so folding the journal
        rebuilds the composed domain state deterministically. The
        kernel's command-id dedup restarts after a journal-only rebuild
        (command envelopes are not part of the journal).
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
            engine._kernel = engine._build_kernel()
            engine._kernel.restore_state(state)
        return engine


# -- spec replacement helpers ------------------------------------------------


def _replace_spec(settlement: Settlement, **changes: Any) -> Any:
    from dataclasses import replace

    return replace(settlement.spec, **changes)


def _replace_finality_spec(certificate: Finality, **changes: Any) -> Any:
    from dataclasses import replace

    return replace(certificate.spec, **changes)


def _replace_recourse_spec(case: RecourseCase, **changes: Any) -> Any:
    from dataclasses import replace

    return replace(case.spec, **changes)
