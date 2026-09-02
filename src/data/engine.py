"""Kernel-bound data-governance engine (WORK-022).

:class:`DataGovernanceEngine` binds every data-governance lifecycle
transition to the ONE transition kernel (WORK-003, ``src.transition``):

* every public operation issues a typed internal command (free-form
  ``data/…`` / ``disclosure/…`` / ``selective/…`` / ``retention/…`` /
  ``recourse/…`` command types per the W026 sibling precedent) through
  ``TransitionEngine.process`` — there is no second state machine and no
  second authority anywhere in this module;
* handlers are pure validate-then-compute functions over the command
  payload plus the committed pre-state; they call the domain constructors
  of ``policy``/``disclosure``/``selective``/``retention``/``cases`` and
  hand the sealed resulting envelopes to the kernel, which owns the
  event envelope, the logical clock, the append-only journal, the
  idempotency ledger and the optimistic-concurrency store commits;
* authorization is a closed policy: exactly the registered ACTIVE
  operator principal may issue data-governance commands (registry-listed
  authority class A2); every other actor is denied and recorded;
* command ids, idempotency keys and nonces are deterministic digests of
  the command's semantic content — replaying an identical operation
  converges to the recorded result (duplicate convergence) while any
  content difference produces a fresh command;
* the typed domain objects returned by the public methods are rebuilt
  exclusively from the kernel's committed results (resulting envelopes
  plus the journaled payload), so the engine holds no authority of its
  own — the kernel store is the committed authority and the in-memory
  index is a derived materialized projection.

Fail-closed paths: unknown policy/case/retention/disclosure identifiers,
inactive policies, ambiguous active-policy selection, unregistered or
suspended principals, unresolvable evidence, state-machine violations,
leakage-gate violations and kernel rejections (environment mismatch,
version conflict, unknown command type, unauthorized actor) all raise
:class:`~src.core.errors.CoreValidationError` — the single error
authority. No wall-clock reads and no entropy exist anywhere in this
module: every instant is explicit declared ``as_of`` data.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.transition import (
    AuthorizationDecision,
    Command,
    ExpectedVersion,
    MemoryStateStore,
    Outcome,
    TransitionApplication,
    TransitionEngine,
)
from src.transition.payload import payload_to_json_value

from .cases import (
    Case,
    CASE_OBJECT_TYPE,
    CasePayload,
    Claim,
    ExecutionRecord,
    Investigation,
    RecourseDecision,
    RefundPackage,
    ReversalPackage,
    close_case,
    compile_refund,
    compile_reversal,
    decide_case,
    execute_refund,
    execute_reversal,
    investigate_case,
    open_case,
    record_claim,
)
from .contracts import (
    ASSESSMENT_ID_PREFIX,
    CASE_CLAIM_COMMAND,
    CASE_CLAIM_EVENT,
    CASE_CLOSE_COMMAND,
    CASE_CLOSED_EVENT,
    CASE_COMPILE_REFUND_COMMAND,
    CASE_REFUND_COMPILED_EVENT,
    CASE_COMPILE_REVERSAL_COMMAND,
    CASE_REVERSAL_COMPILED_EVENT,
    CASE_DECIDE_COMMAND,
    CASE_DECIDED_EVENT,
    CASE_EXECUTE_REFUND_COMMAND,
    CASE_REFUND_EXECUTED_EVENT,
    CASE_EXECUTE_REVERSAL_COMMAND,
    CASE_REVERSAL_EXECUTED_EVENT,
    CASE_INVESTIGATE_COMMAND,
    CASE_INVESTIGATED_EVENT,
    CASE_OPEN_COMMAND,
    CASE_OPENED_EVENT,
    DATA_AUTHORITY_CLASS,
    DATA_DOMAIN_ID,
    DATA_GOVERNANCE_SOURCE,
    DATA_POLICY_OBJECT_TYPE,
    DISCLOSURE_DISCLOSE_COMMAND,
    DISCLOSURE_DISCLOSED_EVENT,
    DISCLOSURE_OBJECT_TYPE,
    DISCLOSURE_REJECT_COMMAND,
    DISCLOSURE_REJECTED_EVENT,
    DISCLOSURE_REQUESTED_EVENT,
    DISCLOSURE_REQUEST_COMMAND,
    PRIVACY_ASSESSMENT_OBJECT_TYPE,
    POLICY_ACTIVATE_COMMAND,
    POLICY_ACTIVATED_EVENT,
    POLICY_DECLARE_COMMAND,
    POLICY_DECLARED_EVENT,
    POLICY_RETIRE_COMMAND,
    POLICY_RETIRED_EVENT,
    PROOF_PRODUCE_COMMAND,
    PROOF_PRODUCED_EVENT,
    PROOF_REVOKE_COMMAND,
    PROOF_REVOKED_EVENT,
    RETENTION_ARCHIVE_COMMAND,
    RETENTION_ARCHIVED_EVENT,
    RETENTION_HOLD_COMMAND,
    RETENTION_HOLD_EVENT,
    RETENTION_MARK_DUE_COMMAND,
    RETENTION_DUE_EVENT,
    RETENTION_MARK_EXPIRED_COMMAND,
    RETENTION_EXPIRED_EVENT,
    RETENTION_OBJECT_TYPE,
    RETENTION_RECORD_COMMAND,
    RETENTION_RECORDED_EVENT,
    RETENTION_RELEASE_COMMAND,
    RETENTION_RELEASE_EVENT,
    SELECTIVE_PROOF_OBJECT_TYPE,
    DataClass,
)
from .disclosure import (
    AssessmentSpec,
    DisclosurePayload,
    DisclosureRecord,
    DisclosureRequest,
    PrivacyAssessment,
    disclose,
    evaluate_disclosure_request,
    reject_disclosure,
    request_disclosure,
    require_active_principal,
)
from .policy import (
    DataPolicy,
    DataPolicySpec,
    activate_policy,
    declare_policy,
    policy_is_active_at,
    retire_policy,
)
from .retention import (
    LegalHold,
    RetentionPayload,
    RetentionRecord,
    archive_retention_record,
    create_retention_record,
    declare_retention_hold,
    mark_retention_due,
    mark_retention_expired,
    release_retention_hold,
)
from .selective import (
    DatasetCommitment,
    IsolatedDataset,
    ProofPayload,
    SelectiveDisclosureProof,
    produce_disclosure_proof,
    revoke_disclosure_proof,
)
from .seal import seal_composite
from ._validation import (
    parse_utc_timestamp,
    require_identifier,
    require_text,
    require_utc_timestamp,
)

# Composite rebuild map: internal object type -> (composite, payload class).
_COMPOSITE_TYPES: dict[str, tuple[type, type]] = {
    DATA_POLICY_OBJECT_TYPE: (DataPolicy, DataPolicySpec),
    PRIVACY_ASSESSMENT_OBJECT_TYPE: (PrivacyAssessment, AssessmentSpec),
    DISCLOSURE_OBJECT_TYPE: (DisclosureRecord, DisclosurePayload),
    RETENTION_OBJECT_TYPE: (RetentionRecord, RetentionPayload),
    CASE_OBJECT_TYPE: (Case, CasePayload),
    SELECTIVE_PROOF_OBJECT_TYPE: (SelectiveDisclosureProof, ProofPayload),
}


def _rebuild_composite(envelope: ObjectEnvelope, payload_json: Any) -> Any:
    """Rebuild one typed composite purely from the committed kernel result.

    The recomputed domain seal must match, so a spliced or tampered
    (envelope, payload) pair fails closed exactly like every other
    trusted-deserialization path.
    """
    try:
        composite_cls, payload_cls = _COMPOSITE_TYPES[envelope.object_type]
    except KeyError:
        raise CoreValidationError(
            f"kernel result carries unknown data object type {envelope.object_type!r}"
        ) from None
    if not isinstance(payload_json, Mapping):
        raise CoreValidationError(
            f"kernel payload for {envelope.object_id} must be an object"
        )
    payload = payload_cls.from_dict(payload_json)
    return composite_cls.from_dict(
        {
            "envelope": envelope.to_dict(),
            "payload": payload.to_dict(),
            "integrity_hash": seal_composite(envelope, payload),
        }
    )


def assessment_id_for_disclosure(disclosure_id: str) -> str:
    """Deterministic assessment identifier bound to one disclosure request."""
    require_identifier("disclosure_id", disclosure_id)
    suffix = disclosure_id.split("/", 1)[1] if "/" in disclosure_id else disclosure_id
    return f"{ASSESSMENT_ID_PREFIX}{suffix}"


class DataGovernanceEngine:
    """The kernel-bound facade for the whole data-governance domain."""

    __slots__ = (
        "_environment_id",
        "_operator",
        "_trust_registry",
        "_evidence_archive",
        "_kernel",
        "_store",
        "_index",
    )

    def __init__(
        self,
        *,
        environment_id: str,
        operator: str,
        trust_registry: Any,
        evidence_archive: Any,
        store: MemoryStateStore | None = None,
    ) -> None:
        require_text("environment_id", environment_id)
        require_text("operator", operator)
        # The operator must be a registered ACTIVE trust principal: the
        # data domain never decides who may operate it (WORK-004 owns
        # principals) — it references and fails closed.
        require_active_principal(operator, trust_registry)
        self._environment_id = environment_id
        self._operator = operator
        self._trust_registry = trust_registry
        self._evidence_archive = evidence_archive
        self._store = store if store is not None else MemoryStateStore()
        self._kernel = self._build_kernel()
        self._index: dict[str, Any] = {}

    # ------------------------------------------------------------------
    # kernel wiring
    # ------------------------------------------------------------------

    @property
    def environment_id(self) -> str:
        return self._environment_id

    @property
    def engine(self) -> TransitionEngine:
        """The bound transition kernel (single state-machine authority)."""
        return self._kernel

    @property
    def store(self) -> MemoryStateStore:
        """The kernel-owned committed object store."""
        return self._store

    @property
    def journal(self):
        return self._kernel.journal

    def _build_kernel(self) -> TransitionEngine:
        kernel = TransitionEngine(
            environment_id=self._environment_id,
            authorization=self._authorize,
            store=self._store,
        )
        kernel.register(POLICY_DECLARE_COMMAND, POLICY_DECLARED_EVENT, self._policy_declare_handler)
        kernel.register(POLICY_ACTIVATE_COMMAND, POLICY_ACTIVATED_EVENT, self._policy_activate_handler)
        kernel.register(POLICY_RETIRE_COMMAND, POLICY_RETIRED_EVENT, self._policy_retire_handler)
        kernel.register(DISCLOSURE_REQUEST_COMMAND, DISCLOSURE_REQUESTED_EVENT, self._disclosure_request_handler)
        kernel.register(DISCLOSURE_DISCLOSE_COMMAND, DISCLOSURE_DISCLOSED_EVENT, self._disclosure_disclose_handler)
        kernel.register(DISCLOSURE_REJECT_COMMAND, DISCLOSURE_REJECTED_EVENT, self._disclosure_reject_handler)
        kernel.register(PROOF_PRODUCE_COMMAND, PROOF_PRODUCED_EVENT, self._proof_produce_handler)
        kernel.register(PROOF_REVOKE_COMMAND, PROOF_REVOKED_EVENT, self._proof_revoke_handler)
        kernel.register(RETENTION_RECORD_COMMAND, RETENTION_RECORDED_EVENT, self._retention_record_handler)
        kernel.register(RETENTION_MARK_DUE_COMMAND, RETENTION_DUE_EVENT, self._retention_mark_due_handler)
        kernel.register(RETENTION_MARK_EXPIRED_COMMAND, RETENTION_EXPIRED_EVENT, self._retention_mark_expired_handler)
        kernel.register(RETENTION_ARCHIVE_COMMAND, RETENTION_ARCHIVED_EVENT, self._retention_archive_handler)
        kernel.register(RETENTION_HOLD_COMMAND, RETENTION_HOLD_EVENT, self._retention_hold_handler)
        kernel.register(RETENTION_RELEASE_COMMAND, RETENTION_RELEASE_EVENT, self._retention_release_handler)
        kernel.register(CASE_OPEN_COMMAND, CASE_OPENED_EVENT, self._case_open_handler)
        kernel.register(CASE_CLAIM_COMMAND, CASE_CLAIM_EVENT, self._case_claim_handler)
        kernel.register(CASE_INVESTIGATE_COMMAND, CASE_INVESTIGATED_EVENT, self._case_investigate_handler)
        kernel.register(CASE_DECIDE_COMMAND, CASE_DECIDED_EVENT, self._case_decide_handler)
        kernel.register(CASE_COMPILE_REFUND_COMMAND, CASE_REFUND_COMPILED_EVENT, self._case_compile_refund_handler)
        kernel.register(CASE_COMPILE_REVERSAL_COMMAND, CASE_REVERSAL_COMPILED_EVENT, self._case_compile_reversal_handler)
        kernel.register(CASE_EXECUTE_REFUND_COMMAND, CASE_REFUND_EXECUTED_EVENT, self._case_execute_refund_handler)
        kernel.register(CASE_EXECUTE_REVERSAL_COMMAND, CASE_REVERSAL_EXECUTED_EVENT, self._case_execute_reversal_handler)
        kernel.register(CASE_CLOSE_COMMAND, CASE_CLOSED_EVENT, self._case_close_handler)
        return kernel

    def _authorize(self, command: Command, view: Any) -> AuthorizationDecision:
        if command.actor == self._operator:
            return AuthorizationDecision(
                granted=True, authority=DATA_AUTHORITY_CLASS, reason=None
            )
        return AuthorizationDecision(
            granted=False,
            authority=None,
            reason=(
                f"actor {command.actor} is not the data-governance operator "
                f"of environment {self._environment_id}"
            ),
        )

    def _provenance(
        self, command: Command, evidence_refs: Iterable[str] = ()
    ) -> Provenance:
        return Provenance(
            issuer=command.actor,
            source=DATA_GOVERNANCE_SOURCE,
            recorded_at=command.requested_at,
            evidence_refs=tuple(evidence_refs),
        )

    # ------------------------------------------------------------------
    # command construction and result application
    # ------------------------------------------------------------------

    def _current_version(self, object_id: str) -> int:
        envelope = self._store.get(object_id)
        return 0 if envelope is None else envelope.object_version

    def _build_command(
        self,
        *,
        verb: str,
        object_refs: tuple[str, ...],
        inputs: Mapping[str, Any],
        requested_at: str,
        evidence_refs: tuple[str, ...] = (),
        creation: bool = False,
    ) -> Command:
        """Build a command whose identity is a digest of its own content.

        Identical semantic content produces an identical command id and
        idempotency key (duplicate convergence); any difference produces
        a distinct command. No entropy, no clock reads. ``creation`` pins
        every declared target at version 0 (the object must not exist
        yet), which keeps creation commands replay-convergent after the
        first commit.
        """
        if creation:
            expected = tuple(
                ExpectedVersion(object_ref, 0) for object_ref in object_refs
            )
        else:
            expected = tuple(
                ExpectedVersion(object_ref, self._current_version(object_ref))
                for object_ref in object_refs
            )
        seed = canonical_sha256(
            {
                "verb": verb,
                "object_refs": list(object_refs),
                "inputs": dict(inputs),
                "requested_at": requested_at,
                "expected_versions": [item.to_dict() for item in expected],
            }
        )
        return Command.build(
            command_id=f"command/{verb}/{seed[:24]}",
            command_type=verb,
            actor=self._operator,
            target_refs=tuple(object_refs),
            payload={"inputs": dict(inputs), "evidence_refs": list(evidence_refs)},
            environment_id=self._environment_id,
            domain_id=DATA_DOMAIN_ID,
            expected_versions=expected,
            idempotency_key=f"idem/{verb}/{seed[:24]}",
            nonce=f"nonce/{verb}/{seed[:24]}",
            requested_at=requested_at,
        )

    def _process(self, command: Command, object_ids: tuple[str, ...]) -> tuple[Any, ...]:
        """Process one command; rebuild and index the committed composites."""
        result = self._kernel.process(command)
        if result.outcome is Outcome.REJECTED:
            raise CoreValidationError(
                f"data-governance command {command.command_type} was rejected by the "
                f"kernel ({result.reason.value if result.reason else 'unknown'}): "
                f"{result.detail}"
            )
        payload_json = payload_to_json_value(result.payload)
        if not isinstance(payload_json, Mapping) or "objects" not in payload_json:
            raise CoreValidationError(
                "data-governance command payloads must carry their resulting objects"
            )
        objects = payload_json["objects"]
        if not isinstance(objects, Mapping):
            raise CoreValidationError("data-governance payload objects must be an object")
        rebuilt: list[Any] = []
        by_id = {envelope.object_id: envelope for envelope in result.resulting_envelopes}
        for object_id in object_ids:
            envelope = by_id.get(object_id)
            if envelope is None:
                raise CoreValidationError(
                    f"kernel result does not carry object {object_id}"
                )
            if object_id not in objects:
                raise CoreValidationError(
                    f"kernel payload does not carry object {object_id}"
                )
            composite = _rebuild_composite(envelope, objects[object_id])
            self._index[object_id] = composite
            rebuilt.append(composite)
        return tuple(rebuilt)

    def _require_index(self, object_id: str, kind: str) -> Any:
        composite = self._index.get(object_id)
        if composite is None:
            raise CoreValidationError(f"unknown data {kind}: {object_id}")
        return composite

    def _inputs(self, command: Command) -> dict[str, Any]:
        payload_json = payload_to_json_value(command.payload)
        if not isinstance(payload_json, Mapping) or "inputs" not in payload_json:
            raise CoreValidationError(
                "data-governance commands must carry an inputs object"
            )
        inputs = payload_json["inputs"]
        if not isinstance(inputs, Mapping):
            raise CoreValidationError("data-governance command inputs must be an object")
        return dict(inputs)

    def _evidence_refs(self, command: Command) -> tuple[str, ...]:
        payload_json = payload_to_json_value(command.payload)
        refs = payload_json.get("evidence_refs") if isinstance(payload_json, Mapping) else None
        if not isinstance(refs, list):
            raise CoreValidationError(
                "data-governance commands must declare their provenance evidence refs"
            )
        return tuple(refs)

    def _require_unique_active_policy(self, as_of: str) -> DataPolicy:
        """Fail closed unless exactly one declared policy is ACTIVE at as_of.

        Zero active policies and ambiguous multi-policy states both fail
        closed: the engine never silently selects among competing
        declared policies (no second authority, no invented precedence).
        """
        parse_utc_timestamp("as_of", as_of)
        active = [
            policy
            for policy in self._index.values()
            if isinstance(policy, DataPolicy) and policy_is_active_at(policy, as_of)
        ]
        if not active:
            raise CoreValidationError(
                f"no declared data policy is active at {as_of}; disclosures and "
                "retention records fail closed without an active policy"
            )
        if len(active) > 1:
            policy_ids = sorted(policy.policy_id for policy in active)
            raise CoreValidationError(
                f"ambiguous active data policies at {as_of}: {policy_ids}; "
                "explicit policy selection is required"
            )
        return active[0]

    # ------------------------------------------------------------------
    # policy lifecycle handlers
    # ------------------------------------------------------------------

    def _policy_declare_handler(self, command: Command, view: Any) -> TransitionApplication:
        inputs = self._inputs(command)
        if "spec" not in inputs:
            raise CoreValidationError("policy.declare requires a spec")
        spec = DataPolicySpec.from_dict(inputs["spec"])
        policy = declare_policy(
            spec=spec,
            environment_id=command.environment_id,
            domain_id=command.domain_id,
            provenance=self._provenance(command),
        )
        return TransitionApplication(
            resulting_envelopes=(policy.envelope,),
            payload={"objects": {policy.policy_id: policy.spec.to_dict()}},
        )

    def _policy_activate_handler(self, command: Command, view: Any) -> TransitionApplication:
        inputs = self._inputs(command)
        policy = self._require_index(inputs["policy_id"], "policy")
        as_of = require_utc_timestamp("policy.activate.as_of", inputs["as_of"])
        if parse_utc_timestamp("policy.activate.as_of", as_of) < parse_utc_timestamp(
            "policy.declared_at", policy.spec.declared_at
        ):
            raise CoreValidationError(
                f"policy {policy.policy_id} cannot be activated at {as_of} before its "
                f"declaration at {policy.spec.declared_at}"
            )
        activated = activate_policy(policy, provenance=self._provenance(command))
        return TransitionApplication(
            resulting_envelopes=(activated.envelope,),
            payload={"objects": {activated.policy_id: activated.spec.to_dict()}},
        )

    def _policy_retire_handler(self, command: Command, view: Any) -> TransitionApplication:
        inputs = self._inputs(command)
        policy = self._require_index(inputs["policy_id"], "policy")
        as_of = require_utc_timestamp("policy.retire.as_of", inputs["as_of"])
        if parse_utc_timestamp("policy.retire.as_of", as_of) < parse_utc_timestamp(
            "policy.declared_at", policy.spec.declared_at
        ):
            raise CoreValidationError(
                f"policy {policy.policy_id} cannot be retired at {as_of} before its "
                f"declaration at {policy.spec.declared_at}"
            )
        retired = retire_policy(policy, provenance=self._provenance(command))
        return TransitionApplication(
            resulting_envelopes=(retired.envelope,),
            payload={"objects": {retired.policy_id: retired.spec.to_dict()}},
        )

    # ------------------------------------------------------------------
    # disclosure handlers
    # ------------------------------------------------------------------

    def _disclosure_request_handler(self, command: Command, view: Any) -> TransitionApplication:
        inputs = self._inputs(command)
        request = DisclosureRequest.from_dict(inputs["request"])
        policy = self._require_index(inputs["policy_id"], "policy")
        disclosure_id = inputs["disclosure_id"]
        assessment_id = assessment_id_for_disclosure(disclosure_id)
        record = request_disclosure(
            disclosure_id=disclosure_id,
            request=request,
            environment_id=command.environment_id,
            domain_id=command.domain_id,
            provenance=self._provenance(command),
        )
        assessment = evaluate_disclosure_request(
            assessment_id=assessment_id,
            request=request,
            policy=policy,
            as_of=request.requested_at,
            environment_id=command.environment_id,
            domain_id=command.domain_id,
            provenance=self._provenance(command),
        )
        return TransitionApplication(
            resulting_envelopes=(record.envelope, assessment.envelope),
            payload={
                "objects": {
                    record.disclosure_id: record.payload.to_dict(),
                    assessment.assessment_id: assessment.spec.to_dict(),
                }
            },
        )

    def _disclosure_disclose_handler(self, command: Command, view: Any) -> TransitionApplication:
        inputs = self._inputs(command)
        record = self._require_index(inputs["disclosure_id"], "disclosure")
        assessment = self._require_index(
            assessment_id_for_disclosure(inputs["disclosure_id"]), "assessment"
        )
        disclosed = disclose(
            record,
            assessment=assessment,
            disclosed_values=inputs["disclosed_values"],
            as_of=require_utc_timestamp("disclosure.disclose.as_of", inputs["as_of"]),
            provenance=self._provenance(
                command, evidence_refs=self._evidence_refs(command)
            ),
            selective_proof_id=inputs.get("selective_proof_id"),
        )
        return TransitionApplication(
            resulting_envelopes=(disclosed.envelope,),
            payload={"objects": {disclosed.disclosure_id: disclosed.payload.to_dict()}},
        )

    def _disclosure_reject_handler(self, command: Command, view: Any) -> TransitionApplication:
        inputs = self._inputs(command)
        record = self._require_index(inputs["disclosure_id"], "disclosure")
        assessment = self._require_index(
            assessment_id_for_disclosure(inputs["disclosure_id"]), "assessment"
        )
        rejected = reject_disclosure(
            record,
            assessment=assessment,
            as_of=require_utc_timestamp("disclosure.reject.as_of", inputs["as_of"]),
            provenance=self._provenance(
                command, evidence_refs=self._evidence_refs(command)
            ),
            note=inputs.get("note"),
        )
        return TransitionApplication(
            resulting_envelopes=(rejected.envelope,),
            payload={"objects": {rejected.disclosure_id: rejected.payload.to_dict()}},
        )

    # ------------------------------------------------------------------
    # selective-disclosure handlers
    # ------------------------------------------------------------------

    def _proof_produce_handler(self, command: Command, view: Any) -> TransitionApplication:
        inputs = self._inputs(command)
        dataset = IsolatedDataset.from_dict(inputs["dataset"])
        commitment = DatasetCommitment.from_dict(inputs["commitment"])
        request = DisclosureRequest.from_dict(inputs["request"])
        policy = self._require_index(inputs["policy_id"], "policy")
        proof = produce_disclosure_proof(
            proof_id=inputs["proof_id"],
            dataset=dataset,
            commitment=commitment,
            request=request,
            policy=policy,
            as_of=require_utc_timestamp("proof.produce.as_of", inputs["as_of"]),
            environment_id=command.environment_id,
            domain_id=command.domain_id,
            provenance=self._provenance(command),
        )
        return TransitionApplication(
            resulting_envelopes=(proof.envelope,),
            payload={"objects": {proof.proof_id: proof.payload.to_dict()}},
        )

    def _proof_revoke_handler(self, command: Command, view: Any) -> TransitionApplication:
        inputs = self._inputs(command)
        proof = self._require_index(inputs["proof_id"], "proof")
        revoked = revoke_disclosure_proof(
            proof, provenance=self._provenance(command)
        )
        return TransitionApplication(
            resulting_envelopes=(revoked.envelope,),
            payload={"objects": {revoked.proof_id: revoked.payload.to_dict()}},
        )

    # ------------------------------------------------------------------
    # retention handlers
    # ------------------------------------------------------------------

    def _retention_record_handler(self, command: Command, view: Any) -> TransitionApplication:
        inputs = self._inputs(command)
        policy = self._require_index(inputs["policy_id"], "policy")
        record = create_retention_record(
            retention_id=inputs["retention_id"],
            subject_ref=inputs["subject_ref"],
            data_class=inputs["data_class"],
            collected_at=require_utc_timestamp(
                "retention.record.collected_at", inputs["collected_at"]
            ),
            policy=policy,
            environment_id=command.environment_id,
            domain_id=command.domain_id,
            provenance=self._provenance(command),
        )
        return TransitionApplication(
            resulting_envelopes=(record.envelope,),
            payload={"objects": {record.retention_id: record.payload.to_dict()}},
        )

    def _retention_mark_due_handler(self, command: Command, view: Any) -> TransitionApplication:
        inputs = self._inputs(command)
        record = self._require_index(inputs["retention_id"], "retention record")
        due = mark_retention_due(
            record,
            as_of=require_utc_timestamp("retention.mark_due.as_of", inputs["as_of"]),
            provenance=self._provenance(command),
        )
        return TransitionApplication(
            resulting_envelopes=(due.envelope,),
            payload={"objects": {due.retention_id: due.payload.to_dict()}},
        )

    def _retention_mark_expired_handler(self, command: Command, view: Any) -> TransitionApplication:
        inputs = self._inputs(command)
        record = self._require_index(inputs["retention_id"], "retention record")
        expired = mark_retention_expired(
            record,
            as_of=require_utc_timestamp("retention.mark_expired.as_of", inputs["as_of"]),
            provenance=self._provenance(command),
        )
        return TransitionApplication(
            resulting_envelopes=(expired.envelope,),
            payload={"objects": {expired.retention_id: expired.payload.to_dict()}},
        )

    def _retention_archive_handler(self, command: Command, view: Any) -> TransitionApplication:
        inputs = self._inputs(command)
        record = self._require_index(inputs["retention_id"], "retention record")
        archived = archive_retention_record(
            record,
            as_of=require_utc_timestamp("retention.archive.as_of", inputs["as_of"]),
            provenance=self._provenance(command),
            archive_ref=inputs["archive_ref"],
        )
        return TransitionApplication(
            resulting_envelopes=(archived.envelope,),
            payload={"objects": {archived.retention_id: archived.payload.to_dict()}},
        )

    def _retention_hold_handler(self, command: Command, view: Any) -> TransitionApplication:
        inputs = self._inputs(command)
        record = self._require_index(inputs["retention_id"], "retention record")
        held = declare_retention_hold(
            record,
            hold=LegalHold.from_dict(inputs["hold"]),
            provenance=self._provenance(command),
        )
        return TransitionApplication(
            resulting_envelopes=(held.envelope,),
            payload={"objects": {held.retention_id: held.payload.to_dict()}},
        )

    def _retention_release_handler(self, command: Command, view: Any) -> TransitionApplication:
        inputs = self._inputs(command)
        record = self._require_index(inputs["retention_id"], "retention record")
        released = release_retention_hold(
            record,
            as_of=require_utc_timestamp("retention.release.as_of", inputs["as_of"]),
            provenance=self._provenance(command),
        )
        return TransitionApplication(
            resulting_envelopes=(released.envelope,),
            payload={"objects": {released.retention_id: released.payload.to_dict()}},
        )

    # ------------------------------------------------------------------
    # case/recourse handlers
    # ------------------------------------------------------------------

    def _case_open_handler(self, command: Command, view: Any) -> TransitionApplication:
        inputs = self._inputs(command)
        claims = tuple(Claim.from_dict(item) for item in inputs["claims"])
        case = open_case(
            case_id=inputs["case_id"],
            subject_ref=inputs["subject_ref"],
            opened_by=inputs["opened_by"],
            opened_at=require_utc_timestamp("case.open.opened_at", inputs["opened_at"]),
            claims=claims,
            trust_registry=self._trust_registry,
            environment_id=command.environment_id,
            domain_id=command.domain_id,
            provenance=self._provenance(
                command, evidence_refs=self._evidence_refs(command)
            ),
        )
        return TransitionApplication(
            resulting_envelopes=(case.envelope,),
            payload={"objects": {case.case_id: case.payload.to_dict()}},
        )

    def _case_claim_handler(self, command: Command, view: Any) -> TransitionApplication:
        inputs = self._inputs(command)
        case = self._require_index(inputs["case_id"], "case")
        extended = record_claim(
            case,
            claim=Claim.from_dict(inputs["claim"]),
            trust_registry=self._trust_registry,
            provenance=self._provenance(
                command, evidence_refs=self._evidence_refs(command)
            ),
        )
        return TransitionApplication(
            resulting_envelopes=(extended.envelope,),
            payload={"objects": {extended.case_id: extended.payload.to_dict()}},
        )

    def _case_investigate_handler(self, command: Command, view: Any) -> TransitionApplication:
        inputs = self._inputs(command)
        case = self._require_index(inputs["case_id"], "case")
        investigation = Investigation.from_dict(inputs["investigation"])
        investigated = investigate_case(
            case,
            investigation=investigation,
            evidence_archive=self._evidence_archive,
            provenance=self._provenance(
                command, evidence_refs=self._evidence_refs(command)
            ),
            trust_registry=self._trust_registry,
        )
        return TransitionApplication(
            resulting_envelopes=(investigated.envelope,),
            payload={"objects": {investigated.case_id: investigated.payload.to_dict()}},
        )

    def _case_decide_handler(self, command: Command, view: Any) -> TransitionApplication:
        inputs = self._inputs(command)
        case = self._require_index(inputs["case_id"], "case")
        decision = RecourseDecision.from_dict(inputs["decision"])
        decided = decide_case(
            case,
            decision=decision,
            trust_registry=self._trust_registry,
            evidence_archive=self._evidence_archive,
            provenance=self._provenance(
                command, evidence_refs=self._evidence_refs(command)
            ),
        )
        return TransitionApplication(
            resulting_envelopes=(decided.envelope,),
            payload={"objects": {decided.case_id: decided.payload.to_dict()}},
        )

    def _case_compile_refund_handler(self, command: Command, view: Any) -> TransitionApplication:
        inputs = self._inputs(command)
        case = self._require_index(inputs["case_id"], "case")
        compiled = compile_refund(
            case,
            package=RefundPackage.from_dict(inputs["package"]),
            provenance=self._provenance(
                command, evidence_refs=self._evidence_refs(command)
            ),
        )
        return TransitionApplication(
            resulting_envelopes=(compiled.envelope,),
            payload={"objects": {compiled.case_id: compiled.payload.to_dict()}},
        )

    def _case_compile_reversal_handler(self, command: Command, view: Any) -> TransitionApplication:
        inputs = self._inputs(command)
        case = self._require_index(inputs["case_id"], "case")
        compiled = compile_reversal(
            case,
            package=ReversalPackage.from_dict(inputs["package"]),
            provenance=self._provenance(
                command, evidence_refs=self._evidence_refs(command)
            ),
        )
        return TransitionApplication(
            resulting_envelopes=(compiled.envelope,),
            payload={"objects": {compiled.case_id: compiled.payload.to_dict()}},
        )

    def _case_execute_refund_handler(self, command: Command, view: Any) -> TransitionApplication:
        inputs = self._inputs(command)
        case = self._require_index(inputs["case_id"], "case")
        executed = execute_refund(
            case,
            execution=ExecutionRecord.from_dict(inputs["execution"]),
            provenance=self._provenance(
                command, evidence_refs=self._evidence_refs(command)
            ),
        )
        return TransitionApplication(
            resulting_envelopes=(executed.envelope,),
            payload={"objects": {executed.case_id: executed.payload.to_dict()}},
        )

    def _case_execute_reversal_handler(self, command: Command, view: Any) -> TransitionApplication:
        inputs = self._inputs(command)
        case = self._require_index(inputs["case_id"], "case")
        executed = execute_reversal(
            case,
            execution=ExecutionRecord.from_dict(inputs["execution"]),
            provenance=self._provenance(
                command, evidence_refs=self._evidence_refs(command)
            ),
        )
        return TransitionApplication(
            resulting_envelopes=(executed.envelope,),
            payload={"objects": {executed.case_id: executed.payload.to_dict()}},
        )

    def _case_close_handler(self, command: Command, view: Any) -> TransitionApplication:
        inputs = self._inputs(command)
        case = self._require_index(inputs["case_id"], "case")
        closed = close_case(
            case,
            closed_at=require_utc_timestamp("case.close.closed_at", inputs["closed_at"]),
            close_reason=require_text("case.close.close_reason", inputs["close_reason"]),
            provenance=self._provenance(
                command, evidence_refs=self._evidence_refs(command)
            ),
        )
        return TransitionApplication(
            resulting_envelopes=(closed.envelope,),
            payload={"objects": {closed.case_id: closed.payload.to_dict()}},
        )

    # ------------------------------------------------------------------
    # public operations (policy)
    # ------------------------------------------------------------------

    def declare_policy(self, *, spec: DataPolicySpec) -> DataPolicy:
        if not isinstance(spec, DataPolicySpec):
            raise CoreValidationError("declare_policy requires a DataPolicySpec")
        command = self._build_command(
            verb=POLICY_DECLARE_COMMAND,
            object_refs=(spec.policy_id,),
            inputs={"spec": spec.to_dict()},
            requested_at=spec.declared_at,
            creation=True,
        )
        return self._process(command, (spec.policy_id,))[0]

    def activate_policy(self, *, policy_id: str, as_of: str) -> DataPolicy:
        policy = self._require_index(policy_id, "policy")
        command = self._build_command(
            verb=POLICY_ACTIVATE_COMMAND,
            object_refs=(policy_id,),
            inputs={"policy_id": policy_id, "as_of": as_of},
            requested_at=require_utc_timestamp("as_of", as_of),
        )
        return self._process(command, (policy_id,))[0]

    def retire_policy(self, *, policy_id: str, as_of: str) -> DataPolicy:
        policy = self._require_index(policy_id, "policy")
        command = self._build_command(
            verb=POLICY_RETIRE_COMMAND,
            object_refs=(policy_id,),
            inputs={"policy_id": policy_id, "as_of": as_of},
            requested_at=require_utc_timestamp("as_of", as_of),
        )
        return self._process(command, (policy_id,))[0]

    def get(self, policy_id: str) -> DataPolicy:
        return self._require_index(policy_id, "policy")

    # ------------------------------------------------------------------
    # public operations (disclosure)
    # ------------------------------------------------------------------

    def request_disclosure(
        self, *, disclosure_id: str, request: DisclosureRequest
    ) -> DisclosureRecord:
        if not isinstance(request, DisclosureRequest):
            raise CoreValidationError("request_disclosure requires a DisclosureRequest")
        policy = self._require_unique_active_policy(request.requested_at)
        command = self._build_command(
            verb=DISCLOSURE_REQUEST_COMMAND,
            object_refs=(disclosure_id, assessment_id_for_disclosure(disclosure_id)),
            inputs={
                "disclosure_id": disclosure_id,
                "request": request.to_dict(),
                "policy_id": policy.policy_id,
            },
            requested_at=request.requested_at,
            creation=True,
        )
        return self._process(
            command, (disclosure_id, assessment_id_for_disclosure(disclosure_id))
        )[0]

    def disclose(
        self,
        *,
        disclosure_id: str,
        disclosed_values: Mapping[str, Any],
        as_of: str,
        selective_proof_id: str | None = None,
    ) -> DisclosureRecord:
        record = self._require_index(disclosure_id, "disclosure")
        assessment_id = assessment_id_for_disclosure(disclosure_id)
        command = self._build_command(
            verb=DISCLOSURE_DISCLOSE_COMMAND,
            object_refs=(disclosure_id,),
            inputs={
                "disclosure_id": disclosure_id,
                "disclosed_values": dict(disclosed_values),
                "as_of": as_of,
                "selective_proof_id": selective_proof_id,
            },
            requested_at=require_utc_timestamp("as_of", as_of),
            evidence_refs=(assessment_id,),
        )
        return self._process(command, (disclosure_id,))[0]

    def reject_disclosure(
        self,
        *,
        disclosure_id: str,
        note: str | None = None,
        as_of: str,
    ) -> DisclosureRecord:
        record = self._require_index(disclosure_id, "disclosure")
        assessment_id = assessment_id_for_disclosure(disclosure_id)
        command = self._build_command(
            verb=DISCLOSURE_REJECT_COMMAND,
            object_refs=(disclosure_id,),
            inputs={
                "disclosure_id": disclosure_id,
                "note": note,
                "as_of": as_of,
            },
            requested_at=require_utc_timestamp("as_of", as_of),
            evidence_refs=(assessment_id,),
        )
        return self._process(command, (disclosure_id,))[0]

    def get_disclosure(self, disclosure_id: str) -> DisclosureRecord:
        return self._require_index(disclosure_id, "disclosure")

    def get_assessment(self, disclosure_id: str) -> PrivacyAssessment:
        return self._require_index(
            assessment_id_for_disclosure(disclosure_id), "assessment"
        )

    # ------------------------------------------------------------------
    # public operations (selective disclosure)
    # ------------------------------------------------------------------

    def produce_proof(
        self,
        *,
        proof_id: str,
        dataset: IsolatedDataset,
        commitment: DatasetCommitment,
        request: DisclosureRequest,
        policy_id: str,
        as_of: str,
    ) -> SelectiveDisclosureProof:
        if not isinstance(dataset, IsolatedDataset) or not isinstance(
            commitment, DatasetCommitment
        ):
            raise CoreValidationError(
                "produce_proof requires an IsolatedDataset and DatasetCommitment"
            )
        if not isinstance(request, DisclosureRequest):
            raise CoreValidationError("produce_proof requires a DisclosureRequest")
        self._require_index(policy_id, "policy")
        command = self._build_command(
            verb=PROOF_PRODUCE_COMMAND,
            object_refs=(proof_id,),
            inputs={
                "proof_id": proof_id,
                "dataset": dataset.to_dict(),
                "commitment": commitment.to_dict(),
                "request": request.to_dict(),
                "policy_id": policy_id,
                "as_of": as_of,
            },
            requested_at=require_utc_timestamp("as_of", as_of),
            creation=True,
        )
        return self._process(command, (proof_id,))[0]

    def revoke_proof(self, *, proof_id: str, as_of: str) -> SelectiveDisclosureProof:
        proof = self._require_index(proof_id, "proof")
        command = self._build_command(
            verb=PROOF_REVOKE_COMMAND,
            object_refs=(proof_id,),
            inputs={"proof_id": proof_id, "as_of": as_of},
            requested_at=require_utc_timestamp("as_of", as_of),
        )
        return self._process(command, (proof_id,))[0]

    def get_proof(self, proof_id: str) -> SelectiveDisclosureProof:
        return self._require_index(proof_id, "proof")

    # ------------------------------------------------------------------
    # public operations (retention)
    # ------------------------------------------------------------------

    def record_retention(
        self,
        *,
        retention_id: str,
        subject_ref: str,
        data_class: Any,
        collected_at: str,
        policy_id: str,
    ) -> RetentionRecord:
        self._require_index(policy_id, "policy")
        command = self._build_command(
            verb=RETENTION_RECORD_COMMAND,
            object_refs=(retention_id,),
            inputs={
                "retention_id": retention_id,
                "subject_ref": subject_ref,
                "data_class": DataClass(data_class).value
                if isinstance(data_class, DataClass)
                else data_class,
                "collected_at": collected_at,
                "policy_id": policy_id,
            },
            requested_at=require_utc_timestamp("collected_at", collected_at),
            creation=True,
        )
        return self._process(command, (retention_id,))[0]

    def mark_retention_due(self, *, retention_id: str, as_of: str) -> RetentionRecord:
        self._require_index(retention_id, "retention record")
        command = self._build_command(
            verb=RETENTION_MARK_DUE_COMMAND,
            object_refs=(retention_id,),
            inputs={"retention_id": retention_id, "as_of": as_of},
            requested_at=require_utc_timestamp("as_of", as_of),
        )
        return self._process(command, (retention_id,))[0]

    def mark_retention_expired(self, *, retention_id: str, as_of: str) -> RetentionRecord:
        self._require_index(retention_id, "retention record")
        command = self._build_command(
            verb=RETENTION_MARK_EXPIRED_COMMAND,
            object_refs=(retention_id,),
            inputs={"retention_id": retention_id, "as_of": as_of},
            requested_at=require_utc_timestamp("as_of", as_of),
        )
        return self._process(command, (retention_id,))[0]

    def archive_retention(
        self, *, retention_id: str, as_of: str, archive_ref: str
    ) -> RetentionRecord:
        self._require_index(retention_id, "retention record")
        command = self._build_command(
            verb=RETENTION_ARCHIVE_COMMAND,
            object_refs=(retention_id,),
            inputs={
                "retention_id": retention_id,
                "as_of": as_of,
                "archive_ref": archive_ref,
            },
            requested_at=require_utc_timestamp("as_of", as_of),
        )
        return self._process(command, (retention_id,))[0]

    def declare_retention_hold(
        self, *, retention_id: str, hold: LegalHold
    ) -> RetentionRecord:
        if not isinstance(hold, LegalHold):
            raise CoreValidationError("declare_retention_hold requires a LegalHold")
        self._require_index(retention_id, "retention record")
        command = self._build_command(
            verb=RETENTION_HOLD_COMMAND,
            object_refs=(retention_id,),
            inputs={"retention_id": retention_id, "hold": hold.to_dict()},
            requested_at=hold.declared_at,
            evidence_refs=(hold.hold_id,),
        )
        return self._process(command, (retention_id,))[0]

    def release_retention_hold(self, *, retention_id: str, as_of: str) -> RetentionRecord:
        self._require_index(retention_id, "retention record")
        command = self._build_command(
            verb=RETENTION_RELEASE_COMMAND,
            object_refs=(retention_id,),
            inputs={"retention_id": retention_id, "as_of": as_of},
            requested_at=require_utc_timestamp("as_of", as_of),
        )
        return self._process(command, (retention_id,))[0]

    def get_retention(self, retention_id: str) -> RetentionRecord:
        return self._require_index(retention_id, "retention record")

    # ------------------------------------------------------------------
    # public operations (cases and recourse)
    # ------------------------------------------------------------------

    def open_case(
        self,
        *,
        case_id: str,
        subject_ref: str,
        opened_by: str,
        opened_at: str,
        claims: tuple[Claim, ...],
    ) -> Case:
        if not isinstance(claims, tuple) or not claims:
            raise CoreValidationError("open_case requires a non-empty claims tuple")
        for claim in claims:
            if not isinstance(claim, Claim):
                raise CoreValidationError("open_case claims must be Claim records")
        claim_evidence: list[str] = []
        for claim in claims:
            for ref in claim.evidence_refs:
                if ref not in claim_evidence:
                    claim_evidence.append(ref)
        command = self._build_command(
            verb=CASE_OPEN_COMMAND,
            object_refs=(case_id,),
            inputs={
                "case_id": case_id,
                "subject_ref": subject_ref,
                "opened_by": opened_by,
                "opened_at": opened_at,
                "claims": [claim.to_dict() for claim in claims],
            },
            requested_at=require_utc_timestamp("opened_at", opened_at),
            evidence_refs=tuple(sorted(claim_evidence)),
            creation=True,
        )
        return self._process(command, (case_id,))[0]

    def record_claim(self, *, case_id: str, claim: Claim) -> Case:
        if not isinstance(claim, Claim):
            raise CoreValidationError("record_claim requires a Claim")
        self._require_index(case_id, "case")
        command = self._build_command(
            verb=CASE_CLAIM_COMMAND,
            object_refs=(case_id,),
            inputs={"case_id": case_id, "claim": claim.to_dict()},
            requested_at=claim.asserted_at,
            evidence_refs=tuple(claim.evidence_refs),
        )
        return self._process(command, (case_id,))[0]

    def investigate(self, *, case_id: str, investigation: Investigation) -> Case:
        if not isinstance(investigation, Investigation):
            raise CoreValidationError("investigate requires an Investigation")
        self._require_index(case_id, "case")
        command = self._build_command(
            verb=CASE_INVESTIGATE_COMMAND,
            object_refs=(case_id,),
            inputs={"case_id": case_id, "investigation": investigation.to_dict()},
            requested_at=investigation.investigated_at,
            evidence_refs=tuple(investigation.evidence_refs),
        )
        return self._process(command, (case_id,))[0]

    def decide(self, *, case_id: str, decision: RecourseDecision) -> Case:
        if not isinstance(decision, RecourseDecision):
            raise CoreValidationError("decide requires a RecourseDecision")
        self._require_index(case_id, "case")
        command = self._build_command(
            verb=CASE_DECIDE_COMMAND,
            object_refs=(case_id,),
            inputs={"case_id": case_id, "decision": decision.to_dict()},
            requested_at=decision.decided_at,
            evidence_refs=tuple(decision.evidence_refs),
        )
        return self._process(command, (case_id,))[0]

    def compile_refund(self, *, case_id: str, package: RefundPackage) -> Case:
        if not isinstance(package, RefundPackage):
            raise CoreValidationError("compile_refund requires a RefundPackage")
        self._require_index(case_id, "case")
        command = self._build_command(
            verb=CASE_COMPILE_REFUND_COMMAND,
            object_refs=(case_id,),
            inputs={"case_id": case_id, "package": package.to_dict()},
            requested_at=package.compiled_at,
            evidence_refs=tuple(package.evidence_refs),
        )
        return self._process(command, (case_id,))[0]

    def compile_reversal(self, *, case_id: str, package: ReversalPackage) -> Case:
        if not isinstance(package, ReversalPackage):
            raise CoreValidationError("compile_reversal requires a ReversalPackage")
        self._require_index(case_id, "case")
        command = self._build_command(
            verb=CASE_COMPILE_REVERSAL_COMMAND,
            object_refs=(case_id,),
            inputs={"case_id": case_id, "package": package.to_dict()},
            requested_at=package.compiled_at,
            evidence_refs=tuple(package.evidence_refs),
        )
        return self._process(command, (case_id,))[0]

    def execute_refund(self, *, case_id: str, execution: ExecutionRecord) -> Case:
        if not isinstance(execution, ExecutionRecord):
            raise CoreValidationError("execute_refund requires an ExecutionRecord")
        case = self._require_index(case_id, "case")
        package = case.payload.refund_package
        if package is None:
            raise CoreValidationError(
                f"case {case_id} carries no compiled refund package to execute"
            )
        command = self._build_command(
            verb=CASE_EXECUTE_REFUND_COMMAND,
            object_refs=(case_id,),
            inputs={"case_id": case_id, "execution": execution.to_dict()},
            requested_at=execution.executed_at,
            evidence_refs=tuple(package.evidence_refs),
        )
        return self._process(command, (case_id,))[0]

    def execute_reversal(self, *, case_id: str, execution: ExecutionRecord) -> Case:
        if not isinstance(execution, ExecutionRecord):
            raise CoreValidationError("execute_reversal requires an ExecutionRecord")
        case = self._require_index(case_id, "case")
        package = case.payload.reversal_package
        if package is None:
            raise CoreValidationError(
                f"case {case_id} carries no compiled reversal package to execute"
            )
        command = self._build_command(
            verb=CASE_EXECUTE_REVERSAL_COMMAND,
            object_refs=(case_id,),
            inputs={"case_id": case_id, "execution": execution.to_dict()},
            requested_at=execution.executed_at,
            evidence_refs=tuple(package.evidence_refs),
        )
        return self._process(command, (case_id,))[0]

    def close_case(
        self, *, case_id: str, closed_at: str, close_reason: str
    ) -> Case:
        case = self._require_index(case_id, "case")
        decision = case.payload.decision
        if decision is None:
            raise CoreValidationError(
                f"case {case_id} carries no decision; premature closure fails closed"
            )
        command = self._build_command(
            verb=CASE_CLOSE_COMMAND,
            object_refs=(case_id,),
            inputs={
                "case_id": case_id,
                "closed_at": closed_at,
                "close_reason": close_reason,
            },
            requested_at=require_utc_timestamp("closed_at", closed_at),
            evidence_refs=tuple(decision.evidence_refs),
        )
        return self._process(command, (case_id,))[0]

    def get_case(self, case_id: str) -> Case:
        return self._require_index(case_id, "case")

    # ------------------------------------------------------------------
    # deterministic state projection
    # ------------------------------------------------------------------

    def state_digest(self) -> str:
        """Canonical digest over the committed kernel and store state."""
        return canonical_sha256(
            {
                "environment_id": self._environment_id,
                "operator": self._operator,
                "kernel": self._kernel.snapshot_state().to_dict(),
                "store": [envelope.to_dict() for envelope in self._store.snapshot()],
            }
        )

    def snapshot(self) -> dict[str, Any]:
        """Canonical byte-stable snapshot of the committed engine state."""
        return {
            "environment_id": self._environment_id,
            "operator": self._operator,
            "kernel": self._kernel.snapshot_state().to_dict(),
            "store": [envelope.to_dict() for envelope in self._store.snapshot()],
        }
