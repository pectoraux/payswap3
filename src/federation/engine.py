"""Kernel-bound engine for the federation domain (WORK-023).

The :class:`FederationEngine` binds every command of the frozen
``Federation`` family (7 command types) to the REAL transition kernel
(:class:`src.transition.TransitionEngine`). One engine instance is
bound to exactly one environment AND one domain — its own network
domain — and the kernel's own domain binding (stage 5: a command of
one domain can never touch an object of another; stage 7: resulting
objects must belong to the commanding domain) is the structural
enforcement of the Work Order's forbidden surface "no unilateral
foreign-domain mutation": foreign state enters this engine only as
sealed composites decoded read-only through their trusted paths, and
the only objects an engine ever creates are its own domain's objects.

Authority discipline (constitution invariant 3 — authority before
financial effect; §5 — no ambient authority):

* the operator gate authorizes actors at the engine boundary (kernel
  stage 4);
* domain authority facts (state authority, anchor keys, rotation and
  transfer history) are re-derived from sealed trust-domain key
  records (WORK-004) through their trusted decode path — payload text
  is never trusted;
* state commitments are signed with the domain's purpose-bound
  ``DOMAIN_STATE_COMMITMENT`` key; the signing secret is a
  caller-supplied parameter proven against the registered key's
  verification digest at the engine boundary and NEVER persisted in
  any command payload, event, journal entry or record;
* acceptance of a foreign commitment verifies the signature against
  the anchor key recorded at join time (knowledge of the exchanged
  secret material proven against the anchor's verification digest) —
  the cross-domain boundary is exactly where cryptographic verification
  happens, so a commitment forged inside a compromised domain still
  fails closed at the peer;
* finality evidence is the settlement domain's sealed finality
  certificates (WORK-016) decoded through their trusted path — only
  ``ESTABLISHED`` certificates bind (constitution §4 and invariant 11:
  no false finality);
* commitments, messages and acceptances are immutable append-only
  records; a superseding commitment is a new sequence, never an edit
  (invariant 17);
* replayed inter-domain messages are rejected: accepted message
  identities are derived from the acceptance records, so the replay
  gate is rebuild-safe and journal-only reconstructible.
"""

from __future__ import annotations

from dataclasses import dataclass
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
    RejectionReason,
    TransitionApplication,
    TransitionEngine,
    TransitionResult,
)
from src.transition.engine import EngineState
from src.transition.payload import payload_to_json_value
from src.transition.registry import validate_authority_class

from ._validation import (
    require_identifier,
    require_mapping,
    require_text,
    require_utc_timestamp,
    strict_fields,
)
from .authority import (
    StateAuthority,
    decode_authority_key,
    require_secret_matches_key,
    sign_commitment,
    state_authority_from_key,
    verify_commitment_signature,
)
from .commitments import (
    StateCommitment,
    commitment_payload_digest,
    decode_finality_certificate,
    finality_binding_from_certificate,
    make_commitment_record,
    parse_publish_payload,
)
from .contracts import (
    COMMAND_EVENT_TYPES,
    DOMAIN_OBJECT_TYPE,
    DOMAIN_TERMINAL_STATES,
    DomainState,
    FEDERATION_TRANSITIONS,
    MessageKind,
    validate_command,
)
from .domains import (
    AuthorityUpdate,
    JoinFact,
    NetworkDomain,
    TransferFact,
    advance_domain,
    make_domain_record,
    parse_join_payload,
    parse_leave_payload,
    parse_register_payload,
    parse_transfer_payload,
    parse_update_authority_payload,
)
from .messages import (
    CommitmentAcceptance,
    InterDomainMessage,
    make_acceptance_record,
    make_message_record,
    parse_accept_payload,
)
from .seal import build_domain_envelope  # noqa: F401  (re-exported boundary)

DEFAULT_ENGINE_ACTOR = "principal/federation-service"

#: Default command authority class (the operator tier that drives
#: federation commands; domain authority itself is proven by key
#: knowledge, and cross-domain acceptance adds signature verification).
DEFAULT_COMMAND_AUTHORITY_CLASS = "A3"

_COMMAND_NONCE = "federation-command-1"

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
    DOMAIN_OBJECT_TYPE: NetworkDomain.from_dict,
    "federation/state-commitment/v1": StateCommitment.from_dict,
    "federation/inter-domain-message/v1": InterDomainMessage.from_dict,
    "federation/commitment-acceptance/v1": CommitmentAcceptance.from_dict,
}


def _payload_dict(command: Command) -> dict[str, Any]:
    """Decode the command payload into the canonical JSON object form."""
    decoded = payload_to_json_value(command.payload)
    if not isinstance(decoded, dict):
        raise CoreValidationError("federation command payloads must be objects")
    return decoded


def _journal_payload(entry: Any) -> Any:
    payload = payload_to_json_value(entry.payload) if entry.payload is not None else {}
    if not isinstance(payload, dict):
        raise CoreValidationError("federation journal payloads must be objects")
    return payload


@dataclass(frozen=True, slots=True)
class FederationTransition:
    """Explicit decision record for one processed federation command.

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


class FederationEngine:
    """Kernel-bound engine for the federation domain (WORK-023).

    The engine owns the domain index (sealed composite records rebuilt
    through the trusted decode path) and one real transition kernel per
    environment+domain pair. It registers its own network domain,
    records federation anchors, rotates and transfers the governed
    authority, publishes signed state commitments (creating inter-domain
    messages atomically), and accepts foreign commitments with full
    signature and replay verification. It never mutates a foreign
    domain's objects and never persists key secrets.
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
        require_identifier("engine domain_id", domain_id)
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
        self._transitions: list[FederationTransition] = []

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
            ("federation/register", self._handle_register),
            ("federation/join", self._handle_join),
            ("federation/leave", self._handle_leave),
            ("federation/update-authority", self._handle_update_authority),
            ("federation/publish-commitment", self._handle_publish_commitment),
            ("federation/accept-commitment", self._handle_accept_commitment),
            ("federation/transfer-domain", self._handle_transfer_domain),
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
                f"actor {command.actor!r} is not authorized to drive federation "
                f"commands in domain {self._domain_id!r}"
            ),
        )

    def _provenance(self, command: Command) -> Provenance:
        return Provenance(
            issuer=command.actor,
            source="federation/domain",
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
            idempotency_key=f"federation:{command_id}",
            nonce=_COMMAND_NONCE,
            requested_at=requested_at,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )

    def submit(self, command: Command) -> FederationTransition:
        """Process one command through the real kernel pipeline."""
        if not isinstance(command, Command):
            raise CoreValidationError("submit expects a Command envelope")
        result = self._kernel.process(command)
        if result.outcome is Outcome.ACCEPTED:
            self._apply_accepted(command.command_type, result)
        transition = FederationTransition(
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

    def domain(self, domain_id: str) -> NetworkDomain:
        record = self._records.get(domain_id)
        if record is None or not isinstance(record, NetworkDomain):
            raise CoreValidationError(f"unknown network domain {domain_id!r}")
        return record

    def commitment(self, commitment_id: str) -> StateCommitment:
        record = self._records.get(commitment_id)
        if record is None or not isinstance(record, StateCommitment):
            raise CoreValidationError(f"unknown state commitment {commitment_id!r}")
        return record

    def message(self, message_id: str) -> InterDomainMessage:
        record = self._records.get(message_id)
        if record is None or not isinstance(record, InterDomainMessage):
            raise CoreValidationError(f"unknown inter-domain message {message_id!r}")
        return record

    def acceptance(self, acceptance_id: str) -> CommitmentAcceptance:
        record = self._records.get(acceptance_id)
        if record is None or not isinstance(record, CommitmentAcceptance):
            raise CoreValidationError(f"unknown commitment acceptance {acceptance_id!r}")
        return record

    def records(self) -> tuple[Any, ...]:
        return tuple(self._records.values())

    def accepted_message_ids(self) -> frozenset[str]:
        """Message identities already accepted (derived from records)."""
        return frozenset(
            record.spec.message_id
            for record in self._records.values()
            if isinstance(record, CommitmentAcceptance)
        )

    def latest_commitment_sequence(self) -> int:
        """The highest published commitment sequence (0 when none)."""
        sequences = [
            record.spec.sequence
            for record in self._records.values()
            if isinstance(record, StateCommitment)
        ]
        return max(sequences, default=0)

    def state_digest(self) -> str:
        """Canonical digest of the committed domain state history.

        Deterministic: the digest covers the kernel's append-only journal
        (every committed event and payload) — the exact state a
        published commitment signs.
        """
        return canonical_sha256(
            {"journal": [entry.to_dict() for entry in self._kernel.journal]}
        )

    def _own_domain(self) -> NetworkDomain:
        return self.domain(self._domain_id)

    def _decode_record(self, composite: Any) -> Any:
        require_mapping("federation record", composite)
        object_type = composite.get("envelope", {}).get("object_type")
        decoder = _RECORD_DECODERS.get(object_type)
        if decoder is None:
            raise CoreValidationError(
                f"record claims unknown object type {object_type!r}"
            )
        return decoder(composite)

    def _store_record(self, record: Any) -> None:
        self._records[record.object_id] = record

    def _require_source_state(self, command_type: str, state: Any) -> None:
        allowed = FEDERATION_TRANSITIONS[command_type]
        if state not in allowed:
            raise CoreValidationError(
                f"{command_type} cannot advance from state {state.value!r}; "
                f"allowed source states are "
                f"{sorted(member.value for member in allowed)}"
            )

    # ------------------------------------------------------------------
    # public command surface
    # ------------------------------------------------------------------

    def register_domain(
        self,
        *,
        command_id: str,
        requested_at: str,
        domain_id: str,
        authority_key: Mapping[str, Any],
    ) -> FederationTransition:
        """``Federation: Register`` — create this engine's own domain record.

        The authority facts are derived from the sealed trust key
        composite (purpose ``DOMAIN_STATE_COMMITMENT``, ACTIVE); a
        federation engine registers exactly its own domain.
        """
        require_identifier("register domain_id", domain_id)
        if domain_id != self._domain_id:
            raise CoreValidationError(
                f"a federation engine registers exactly its own domain; this "
                f"engine governs {self._domain_id!r}, not {domain_id!r}"
            )
        if self._records.get(domain_id) is not None:
            raise CoreValidationError(f"domain {domain_id!r} is already registered")
        decode_authority_key(authority_key)
        command = self.build_raw_command(
            command_id=command_id,
            command_type="federation/register",
            requested_at=requested_at,
            target_refs=(domain_id,),
            payload={
                "domain_id": domain_id,
                "authority_key": dict(authority_key),
            },
            expected_versions={domain_id: 0},
        )
        return self.submit(command)

    def join_federation(
        self,
        *,
        command_id: str,
        requested_at: str,
        domain_id: str,
        anchor_domain_id: str,
        anchor_key: Mapping[str, Any],
    ) -> FederationTransition:
        """``Federation: Join`` — record the federation anchor.

        The anchor facts (peer domain and its commitment key) become the
        trust root for every foreign commitment accepted from that peer.
        """
        domain = self.domain(domain_id)
        anchor_key_record = decode_authority_key(anchor_key)
        command = self.build_raw_command(
            command_id=command_id,
            command_type="federation/join",
            requested_at=requested_at,
            target_refs=(domain_id,),
            payload={
                "anchor_domain_id": anchor_domain_id,
                "anchor_key": dict(anchor_key_record.to_dict()),
            },
            expected_versions={domain_id: domain.envelope.object_version},
        )
        return self.submit(command)

    def leave_federation(
        self,
        *,
        command_id: str,
        requested_at: str,
        domain_id: str,
        reason: str,
    ) -> FederationTransition:
        """``Federation: Leave`` — explicit, terminal departure."""
        domain = self.domain(domain_id)
        command = self.build_raw_command(
            command_id=command_id,
            command_type="federation/leave",
            requested_at=requested_at,
            target_refs=(domain_id,),
            payload={"reason": reason},
            expected_versions={domain_id: domain.envelope.object_version},
        )
        return self.submit(command)

    def update_authority(
        self,
        *,
        command_id: str,
        requested_at: str,
        domain_id: str,
        new_key: Mapping[str, Any],
        current_secret_material: str,
    ) -> FederationTransition:
        """``Federation: UpdateAuthority`` — rotate the commitment key.

        Consent: the caller must prove knowledge of the CURRENT key's
        secret material (verified against the registered verification
        digest at this boundary; the secret is never persisted). The new
        key must belong to the same authority principal.
        """
        domain = self.domain(domain_id)
        current = domain.spec.authority
        require_secret_matches_key(
            key_id=current.key_id,
            public_material=current.public_material,
            verification_digest=current.verification_digest,
            secret_material=current_secret_material,
            role="current authority",
        )
        new_key_record = decode_authority_key(new_key)
        if new_key_record.owner_principal_id != current.principal_id:
            raise CoreValidationError(
                "a commitment key rotation must stay with the same authority "
                f"principal; key {new_key_record.key_id} belongs to "
                f"{new_key_record.owner_principal_id!r}, the domain authority is "
                f"{current.principal_id!r}"
            )
        command = self.build_raw_command(
            command_id=command_id,
            command_type="federation/update-authority",
            requested_at=requested_at,
            target_refs=(domain_id,),
            payload={"new_key": dict(new_key_record.to_dict())},
            expected_versions={domain_id: domain.envelope.object_version},
        )
        return self.submit(command)

    def transfer_domain(
        self,
        *,
        command_id: str,
        requested_at: str,
        domain_id: str,
        new_principal_id: str,
        new_key: Mapping[str, Any],
        outgoing_secret_material: str,
        incoming_secret_material: str,
    ) -> FederationTransition:
        """``Federation: TransferDomain`` — governed authority handover.

        Dual consent: knowledge of the OUTGOING authority's secret
        (verified against the current key's verification digest) and of
        the INCOMING authority's secret (verified against the new key's
        verification digest). The authority is replaced in ONE atomic
        version bump — no dual-authority interval.
        """
        domain = self.domain(domain_id)
        current = domain.spec.authority
        require_secret_matches_key(
            key_id=current.key_id,
            public_material=current.public_material,
            verification_digest=current.verification_digest,
            secret_material=outgoing_secret_material,
            role="outgoing authority",
        )
        new_key_record = decode_authority_key(new_key)
        require_secret_matches_key(
            key_id=new_key_record.key_id,
            public_material=new_key_record.public_material,
            verification_digest=new_key_record.verification_digest,
            secret_material=incoming_secret_material,
            role="incoming authority",
        )
        if new_key_record.owner_principal_id != new_principal_id:
            raise CoreValidationError(
                f"the incoming commitment key {new_key_record.key_id} belongs to "
                f"{new_key_record.owner_principal_id!r}, not the declared successor "
                f"{new_principal_id!r}"
            )
        command = self.build_raw_command(
            command_id=command_id,
            command_type="federation/transfer-domain",
            requested_at=requested_at,
            target_refs=(domain_id,),
            payload={
                "new_principal_id": new_principal_id,
                "new_key": dict(new_key_record.to_dict()),
            },
            expected_versions={domain_id: domain.envelope.object_version},
        )
        return self.submit(command)

    def publish_commitment(
        self,
        *,
        command_id: str,
        requested_at: str,
        commitment_id: str,
        sequence: int,
        finality_certificates: list[Mapping[str, Any]]
        | tuple[Mapping[str, Any], ...] = (),
        secret_material: str,
        destination_domain_id: str | None = None,
        message_id: str | None = None,
        message_nonce: str | None = None,
    ) -> FederationTransition:
        """``Federation: PublishCommitment`` — sign and publish domain state.

        The commitment covers the canonical state digest of this
        engine's committed journal plus digest-bound finality evidence
        (only ``ESTABLISHED`` settlement certificates bind). When a
        destination domain is declared, the immutable inter-domain
        message is created in the SAME atomic kernel transition. The
        signing secret is proven against the current authority key and
        never persisted.
        """
        domain = self._own_domain()
        current = domain.spec.authority
        require_secret_matches_key(
            key_id=current.key_id,
            public_material=current.public_material,
            verification_digest=current.verification_digest,
            secret_material=secret_material,
            role="commitment signing",
        )
        certificates = tuple(finality_certificates)
        decoded: list[Any] = []
        seen: set[str] = set()
        for composite in certificates:
            certificate = decode_finality_certificate(composite)
            if certificate.object_id in seen:
                raise CoreValidationError(
                    f"finality certificate {certificate.object_id} appears twice"
                )
            seen.add(certificate.object_id)
            decoded.append(certificate)
        bindings = tuple(
            finality_binding_from_certificate(certificate) for certificate in decoded
        )
        if sequence != self.latest_commitment_sequence() + 1:
            raise CoreValidationError(
                f"commitment sequence must be exactly "
                f"{self.latest_commitment_sequence() + 1} (the next sequence); "
                f"got {sequence}"
            )
        if destination_domain_id is not None:
            if message_id is None or message_nonce is None:
                raise CoreValidationError(
                    "a destination commitment requires message_id and message_nonce"
                )
            if destination_domain_id == self._domain_id:
                raise CoreValidationError(
                    "an inter-domain message must address a foreign domain"
                )
        else:
            if message_id is not None or message_nonce is not None:
                raise CoreValidationError(
                    "a destinationless commitment must not declare a message"
                )
        state_digest = self.state_digest()
        payload_digest = commitment_payload_digest(
            commitment_id=commitment_id,
            domain_id=self._domain_id,
            sequence=sequence,
            state_digest=state_digest,
            finality_bindings=bindings,
        )
        signature = sign_commitment(
            key_id=current.key_id,
            public_material=current.public_material,
            secret_material=secret_material,
            payload_digest=payload_digest,
        )
        targets: tuple[str, ...] = (commitment_id,)
        expected: dict[str, int] = {commitment_id: 0}
        if message_id is not None:
            targets = (commitment_id, message_id)
            expected[message_id] = 0
        command = self.build_raw_command(
            command_id=command_id,
            command_type="federation/publish-commitment",
            requested_at=requested_at,
            target_refs=targets,
            payload={
                "commitment_id": commitment_id,
                "sequence": sequence,
                "state_digest": state_digest,
                "finality_bindings": [binding.to_dict() for binding in bindings],
                "key_id": current.key_id,
                "public_material": current.public_material,
                "signature": signature,
                "destination_domain_id": destination_domain_id,
                "message_id": message_id,
                "message_nonce": message_nonce,
            },
            expected_versions=expected,
        )
        return self.submit(command)

    def accept_commitment(
        self,
        *,
        command_id: str,
        requested_at: str,
        acceptance_id: str,
        message: Mapping[str, Any],
        commitment: Mapping[str, Any],
        anchor_secret_material: str,
    ) -> FederationTransition:
        """``Federation: AcceptCommitment`` — verify and record foreign state.

        Full cross-domain verification: the message and commitment are
        decoded through their trusted seal-verification paths; the
        message must address this domain and originate from the joined
        anchor; the commitment must claim the anchor's key; the
        signature must verify against the anchor key with the exchanged
        secret material (itself proven against the anchor's registered
        verification digest); and the message must not have been
        accepted before (replay protection).
        """
        domain = self._own_domain()
        if domain.spec.join is None:
            raise CoreValidationError(
                "a domain must join an anchor before accepting foreign commitments"
            )
        anchor = domain.spec.join
        message_record = InterDomainMessage.from_dict(message)
        commitment_record = StateCommitment.from_dict(commitment)
        self._verify_foreign_commitment(anchor, message_record, commitment_record)
        require_secret_matches_key(
            key_id=anchor.anchor_key_id,
            public_material=anchor.anchor_public_material,
            verification_digest=anchor.anchor_verification_digest,
            secret_material=anchor_secret_material,
            role="anchor",
        )
        payload_digest = commitment_payload_digest(
            commitment_id=commitment_record.object_id,
            domain_id=commitment_record.envelope.domain_id,
            sequence=commitment_record.spec.sequence,
            state_digest=commitment_record.spec.state_digest,
            finality_bindings=commitment_record.spec.finality_bindings,
        )
        verify_commitment_signature(
            commitment_record.spec.signature,
            key_id=anchor.anchor_key_id,
            public_material=anchor.anchor_public_material,
            secret_material=anchor_secret_material,
            payload_digest=payload_digest,
        )
        if message_record.object_id in self.accepted_message_ids():
            raise CoreValidationError(
                f"replayed inter-domain message {message_record.object_id!r} was "
                "already accepted; replay is rejected"
            )
        command = self.build_raw_command(
            command_id=command_id,
            command_type="federation/accept-commitment",
            requested_at=requested_at,
            target_refs=(acceptance_id,),
            payload={
                "acceptance_id": acceptance_id,
                "message": dict(message),
                "commitment": dict(commitment),
            },
            expected_versions={acceptance_id: 0},
        )
        return self.submit(command)

    def _verify_foreign_commitment(
        self,
        anchor: JoinFact,
        message_record: InterDomainMessage,
        commitment_record: StateCommitment,
    ) -> None:
        """Journaled-fact verification of a foreign message/commitment pair.

        Shared by the engine boundary and the kernel handler (the
        handler re-asserts every gate derivable from committed facts;
        secret-knowledge proofs are boundary-only).
        """
        if message_record.spec.destination_domain != self._domain_id:
            raise CoreValidationError(
                f"inter-domain message {message_record.object_id!r} addresses "
                f"{message_record.spec.destination_domain!r}, not this domain "
                f"{self._domain_id!r}"
            )
        if message_record.envelope.environment_id != self._environment_id:
            raise CoreValidationError(
                f"inter-domain message {message_record.object_id!r} belongs to "
                f"environment {message_record.envelope.environment_id!r}, not "
                f"{self._environment_id!r}"
            )
        if message_record.spec.origin_domain != anchor.anchor_domain_id:
            raise CoreValidationError(
                f"inter-domain message {message_record.object_id!r} originates from "
                f"{message_record.spec.origin_domain!r}, but this domain's anchor is "
                f"{anchor.anchor_domain_id!r}"
            )
        if commitment_record.envelope.domain_id != anchor.anchor_domain_id:
            raise CoreValidationError(
                f"state commitment {commitment_record.object_id!r} belongs to domain "
                f"{commitment_record.envelope.domain_id!r}, but this domain's anchor "
                f"is {anchor.anchor_domain_id!r}"
            )
        if commitment_record.spec.key_id != anchor.anchor_key_id:
            raise CoreValidationError(
                f"state commitment {commitment_record.object_id!r} claims key "
                f"{commitment_record.spec.key_id!r}; the anchor key is "
                f"{anchor.anchor_key_id!r}"
            )
        if message_record.spec.commitment_id != commitment_record.object_id:
            raise CoreValidationError(
                "the inter-domain message and the commitment must agree on the "
                "commitment identity"
            )
        if message_record.spec.commitment_digest != commitment_record.integrity_hash:
            raise CoreValidationError(
                "the inter-domain message is not digest-bound to this commitment"
            )

    # ------------------------------------------------------------------
    # kernel handlers (validate-then-compute)
    # ------------------------------------------------------------------

    def _handle_register(self, command: Command, view: Any) -> TransitionApplication:
        payload = parse_register_payload(_payload_dict(command))
        if payload["domain_id"] != self._domain_id:
            raise CoreValidationError(
                "a federation engine registers exactly its own domain; the "
                f"command addresses {payload['domain_id']!r}"
            )
        if self._records.get(self._domain_id) is not None:
            raise CoreValidationError(f"domain {self._domain_id!r} is already registered")
        key = decode_authority_key(payload["authority_key"])
        authority = state_authority_from_key(key)
        record = make_domain_record(
            domain_id=self._domain_id,
            environment_id=self._environment_id,
            provenance=self._provenance(command),
            authority=authority,
            registered_at=command.requested_at,
            causation_id=command.command_id,
            correlation_id=command.correlation_id,
        )
        return TransitionApplication(
            (record.envelope,),
            {"domain": record.to_dict()},
        )

    def _handle_join(self, command: Command, view: Any) -> TransitionApplication:
        payload = parse_join_payload(_payload_dict(command))
        domain = self._own_domain()
        self._require_source_state("federation/join", domain.state)
        anchor_key = decode_authority_key(payload["anchor_key"])
        join = JoinFact(
            anchor_domain_id=payload["anchor_domain_id"],
            anchor_key_id=anchor_key.key_id,
            anchor_public_material=anchor_key.public_material,
            anchor_verification_digest=anchor_key.verification_digest,
            joined_at=command.requested_at,
        )
        from dataclasses import replace as _replace

        joined = advance_domain(
            domain,
            state=DomainState.JOINED.value,
            provenance=self._provenance(command),
            causation_id=command.command_id,
            correlation_id=command.correlation_id,
            spec=_replace(domain.spec, join=join),
        )
        return TransitionApplication(
            (joined.envelope,),
            {"domain": joined.to_dict()},
        )

    def _handle_leave(self, command: Command, view: Any) -> TransitionApplication:
        payload = parse_leave_payload(_payload_dict(command))
        domain = self._own_domain()
        self._require_source_state("federation/leave", domain.state)
        from dataclasses import replace as _replace

        left = advance_domain(
            domain,
            state=DomainState.LEFT.value,
            provenance=self._provenance(command),
            causation_id=command.command_id,
            correlation_id=command.correlation_id,
            spec=_replace(domain.spec, left_at=command.requested_at),
        )
        return TransitionApplication(
            (left.envelope,),
            {"domain": left.to_dict()},
        )

    def _handle_update_authority(
        self, command: Command, view: Any
    ) -> TransitionApplication:
        payload = parse_update_authority_payload(_payload_dict(command))
        domain = self._own_domain()
        self._require_source_state("federation/update-authority", domain.state)
        new_key = decode_authority_key(payload["new_key"])
        current = domain.spec.authority
        if new_key.owner_principal_id != current.principal_id:
            raise CoreValidationError(
                "a commitment key rotation must stay with the same authority "
                f"principal; key {new_key.key_id} belongs to "
                f"{new_key.owner_principal_id!r}"
            )
        from dataclasses import replace as _replace

        update = AuthorityUpdate(
            prior_key_id=current.key_id,
            new_key_id=new_key.key_id,
            new_public_material=new_key.public_material,
            new_verification_digest=new_key.verification_digest,
            updated_at=command.requested_at,
        )
        new_authority = StateAuthority(
            principal_id=new_key.owner_principal_id,
            key_id=new_key.key_id,
            public_material=new_key.public_material,
            verification_digest=new_key.verification_digest,
        )
        updated = advance_domain(
            domain,
            state=domain.state.value,
            provenance=self._provenance(command),
            causation_id=command.command_id,
            correlation_id=command.correlation_id,
            spec=_replace(
                domain.spec,
                authority=new_authority,
                authority_updates=domain.spec.authority_updates + (update,),
            ),
        )
        return TransitionApplication(
            (updated.envelope,),
            {"domain": updated.to_dict()},
        )

    def _handle_transfer_domain(
        self, command: Command, view: Any
    ) -> TransitionApplication:
        payload = parse_transfer_payload(_payload_dict(command))
        domain = self._own_domain()
        self._require_source_state("federation/transfer-domain", domain.state)
        new_key = decode_authority_key(payload["new_key"])
        current = domain.spec.authority
        new_principal_id = payload["new_principal_id"]
        if new_key.owner_principal_id != new_principal_id:
            raise CoreValidationError(
                f"the incoming commitment key {new_key.key_id} belongs to "
                f"{new_key.owner_principal_id!r}, not the declared successor "
                f"{new_principal_id!r}"
            )
        from dataclasses import replace as _replace

        transfer = TransferFact(
            prior_principal_id=current.principal_id,
            prior_key_id=current.key_id,
            new_principal_id=new_principal_id,
            new_key_id=new_key.key_id,
            new_public_material=new_key.public_material,
            new_verification_digest=new_key.verification_digest,
            transferred_at=command.requested_at,
        )
        new_authority = StateAuthority(
            principal_id=new_principal_id,
            key_id=new_key.key_id,
            public_material=new_key.public_material,
            verification_digest=new_key.verification_digest,
        )
        transferred = advance_domain(
            domain,
            state=domain.state.value,
            provenance=self._provenance(command),
            causation_id=command.command_id,
            correlation_id=command.correlation_id,
            spec=_replace(
                domain.spec,
                authority=new_authority,
                transfers=domain.spec.transfers + (transfer,),
            ),
        )
        return TransitionApplication(
            (transferred.envelope,),
            {"domain": transferred.to_dict()},
        )

    def _handle_publish_commitment(
        self, command: Command, view: Any
    ) -> TransitionApplication:
        payload = parse_publish_payload(_payload_dict(command))
        domain = self._own_domain()
        if domain.state in DOMAIN_TERMINAL_STATES:
            raise CoreValidationError(
                f"a {domain.state.value} domain can no longer publish commitments"
            )
        authority = domain.spec.authority
        if (
            payload["key_id"] != authority.key_id
            or payload["public_material"] != authority.public_material
        ):
            raise CoreValidationError(
                "a state commitment must be signed with the domain's current "
                f"authority key {authority.key_id!r}; the payload claims "
                f"{payload['key_id']!r}"
            )
        if payload["sequence"] != self.latest_commitment_sequence() + 1:
            raise CoreValidationError(
                f"commitment sequence must be exactly "
                f"{self.latest_commitment_sequence() + 1} (the next sequence); "
                f"got {payload['sequence']}"
            )
        if payload["state_digest"] != self.state_digest():
            raise CoreValidationError(
                "the commitment's state digest does not match this domain's "
                "committed state; a state commitment must sign the exact journal "
                "digest"
            )
        commitment = make_commitment_record(
            commitment_id=payload["commitment_id"],
            environment_id=self._environment_id,
            domain_id=self._domain_id,
            provenance=self._provenance(command),
            sequence=payload["sequence"],
            state_digest=payload["state_digest"],
            finality_bindings=payload["finality_bindings"],
            key_id=payload["key_id"],
            public_material=payload["public_material"],
            signature=payload["signature"],
            causation_id=command.command_id,
            correlation_id=command.correlation_id,
        )
        application_payload: dict[str, Any] = {
            "commitment": commitment.to_dict(),
            "message": None,
        }
        if payload["destination_domain_id"] is not None:
            message = make_message_record(
                message_id=payload["message_id"],
                environment_id=self._environment_id,
                domain_id=self._domain_id,
                provenance=self._provenance(command),
                origin_domain=self._domain_id,
                destination_domain=payload["destination_domain_id"],
                kind=MessageKind.STATE_COMMITMENT,
                nonce=payload["message_nonce"],
                commitment_id=commitment.object_id,
                commitment_digest=commitment.integrity_hash,
                issued_at=command.requested_at,
                causation_id=command.command_id,
                correlation_id=command.correlation_id,
            )
            application_payload["message"] = message.to_dict()
            return TransitionApplication(
                (commitment.envelope, message.envelope),
                application_payload,
            )
        return TransitionApplication(
            (commitment.envelope,),
            application_payload,
        )

    def _handle_accept_commitment(
        self, command: Command, view: Any
    ) -> TransitionApplication:
        payload = parse_accept_payload(_payload_dict(command))
        domain = self._own_domain()
        if domain.spec.join is None:
            raise CoreValidationError(
                "a domain must join an anchor before accepting foreign commitments"
            )
        anchor = domain.spec.join
        message_record = InterDomainMessage.from_dict(payload["message"])
        commitment_record = StateCommitment.from_dict(payload["commitment"])
        self._verify_foreign_commitment(anchor, message_record, commitment_record)
        if message_record.object_id in self.accepted_message_ids():
            raise CoreValidationError(
                f"replayed inter-domain message {message_record.object_id!r} was "
                "already accepted; replay is rejected"
            )
        acceptance = make_acceptance_record(
            acceptance_id=payload["acceptance_id"],
            environment_id=self._environment_id,
            domain_id=self._domain_id,
            provenance=self._provenance(command),
            origin_domain=message_record.spec.origin_domain,
            message_id=message_record.object_id,
            message_digest=message_record.integrity_hash,
            commitment_id=commitment_record.object_id,
            commitment_digest=commitment_record.integrity_hash,
            sequence=commitment_record.spec.sequence,
            anchor_key_id=anchor.anchor_key_id,
            accepted_at=command.requested_at,
            causation_id=command.command_id,
            correlation_id=command.correlation_id,
        )
        return TransitionApplication(
            (acceptance.envelope,),
            {"acceptance": acceptance.to_dict()},
        )

    # ------------------------------------------------------------------
    # committed-event application (single mutation path)
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
            raise CoreValidationError("committed federation payloads must be objects")
        if event_type in (
            "governance/domain-registered",
            "governance/domain-joined",
            "governance/domain-left",
            "governance/domain-authority-updated",
            "governance/domain-transferred",
        ):
            self._store_record(self._decode_record(payload["domain"]))
        elif event_type == "governance/state-commitment-published":
            self._store_record(self._decode_record(payload["commitment"]))
            if payload.get("message") is not None:
                self._store_record(self._decode_record(payload["message"]))
        elif event_type == "governance/commitment-accepted":
            self._store_record(self._decode_record(payload["acceptance"]))
        else:
            raise CoreValidationError(f"unknown federation event type {event_type!r}")

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
    ) -> "FederationEngine":
        """Rebuild the domain index from the journal alone.

        Transformation completeness: the committed event payloads carry
        every resulting record, so folding the journal rebuilds the
        composed domain state deterministically (accepted-message replay
        protection included — it is derived from the acceptance records).
        The kernel's command-id dedup restarts after a journal-only
        rebuild (command envelopes are not part of the journal).
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
