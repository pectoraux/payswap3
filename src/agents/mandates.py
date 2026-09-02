"""Bounded proposal mandates: agent-scoped, typed, explicit (WORK-021).

The frozen canonical object model places ``Mandate`` in the "Identity and
authority" family, and that concept is owned by the merged trust domain
(``src/trust`` — one principal acting on behalf of another). This module
does NOT create a second Mandate authority: :class:`ProposalMandate` is
the strictly weaker, agent-scoped bound on what one agent may PROPOSE —
explicit scope (proposal kinds plus route families), explicit limits (a
proposal budget), explicit expiry (a half-open window) and the authority
class frozen to exactly the registry ``R2`` PROPOSE tier of the frozen
extension authority ladder.

A proposal mandate grants zero financial authority: it cannot move value,
reserve, execute, or authorize any effect. It bounds what may enter
mediation, never what may be executed (constitution invariant 5: no
agent receives ambient financial authority). Every violation — out of
scope, wrong kind, expired window, exhausted budget, wrong agent, tier
above PROPOSE — fails closed.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.transition import Command, TransitionApplication, payload_to_json_value

from .contracts import (
    PROPOSAL_AUTHORITY_CLASS,
    PROPOSAL_MANDATE_ID_PREFIX,
    PROPOSAL_MANDATE_OBJECT_TYPE,
    ProposalKind,
    require_agents_identifier,
    validate_proposal_authority_class,
)
from ._validation import (
    parse_enum,
    require_identifier,
    require_int,
    require_str_tuple,
    require_text,
    require_utc_timestamp,
    require_utc_timestamp_order,
    strict_fields,
    utc_timestamp_within,
)
from .seal import (
    build_domain_envelope,
    composite_to_json,
    decode_composite,
    decode_composite_json,
    seal_composite,
    verify_composite,
)


class MandateState(StrEnum):
    """Closed lifecycle vocabulary of a proposal mandate (v0.1: ACTIVE)."""

    ACTIVE = "ACTIVE"


_MANDATE_SPEC_FIELDS = frozenset(
    {
        "mandate_id",
        "agent_principal",
        "issued_by",
        "proposal_kinds",
        "route_families",
        "max_proposals",
        "not_before",
        "not_after",
        "authority_class",
        "issued_at",
    }
)

_AUTHORIZE_FIELDS = frozenset(
    {
        "mandate_id",
        "agent_principal",
        "proposal_kinds",
        "route_families",
        "max_proposals",
        "not_before",
        "not_after",
        "authority_class",
    }
)


@dataclass(frozen=True, slots=True)
class MandateSpec:
    """Immutable bounded proposal mandate payload."""

    mandate_id: str
    agent_principal: str
    issued_by: str
    proposal_kinds: tuple[ProposalKind, ...]
    route_families: tuple[str, ...]
    max_proposals: int
    not_before: str
    not_after: str
    authority_class: str
    issued_at: str

    def __post_init__(self) -> None:
        require_agents_identifier(
            "mandate.mandate_id", self.mandate_id, PROPOSAL_MANDATE_ID_PREFIX
        )
        require_identifier("mandate.agent_principal", self.agent_principal)
        require_identifier("mandate.issued_by", self.issued_by)
        if self.agent_principal == self.issued_by:
            raise CoreValidationError(
                "proposal mandate issuer and agent must be distinct principals"
            )
        object.__setattr__(
            self,
            "proposal_kinds",
            self._require_kinds(self.proposal_kinds),
        )
        object.__setattr__(
            self,
            "route_families",
            require_str_tuple(
                "mandate.route_families", self.route_families, non_empty=True, distinct=True
            ),
        )
        require_int("mandate.max_proposals", self.max_proposals, minimum=1)
        require_utc_timestamp("mandate.not_before", self.not_before)
        require_utc_timestamp("mandate.not_after", self.not_after)
        require_utc_timestamp_order(
            "mandate.not_before", self.not_before, "mandate.not_after", self.not_after
        )
        validate_proposal_authority_class(
            "mandate.authority_class", self.authority_class
        )
        require_utc_timestamp("mandate.issued_at", self.issued_at)

    def _require_kinds(self, value: Any) -> tuple[ProposalKind, ...]:
        if not isinstance(value, (list, tuple)) or not value:
            raise CoreValidationError(
                "mandate.proposal_kinds must be a non-empty sequence of ProposalKind"
            )
        kinds = tuple(
            parse_enum("mandate.proposal_kind", item, ProposalKind) for item in value
        )
        if len(set(kinds)) != len(kinds):
            raise CoreValidationError("mandate.proposal_kinds must be distinct")
        return kinds

    def to_dict(self) -> dict[str, Any]:
        return {
            "mandate_id": self.mandate_id,
            "agent_principal": self.agent_principal,
            "issued_by": self.issued_by,
            "proposal_kinds": [kind.value for kind in self.proposal_kinds],
            "route_families": list(self.route_families),
            "max_proposals": self.max_proposals,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "authority_class": self.authority_class,
            "issued_at": self.issued_at,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "MandateSpec":
        strict_fields("mandate", value, _MANDATE_SPEC_FIELDS)
        return cls(
            mandate_id=value["mandate_id"],
            agent_principal=value["agent_principal"],
            issued_by=value["issued_by"],
            proposal_kinds=tuple(value["proposal_kinds"]),
            route_families=tuple(value["route_families"]),
            max_proposals=value["max_proposals"],
            not_before=value["not_before"],
            not_after=value["not_after"],
            authority_class=value["authority_class"],
            issued_at=value["issued_at"],
        )


@dataclass(frozen=True, slots=True)
class ProposalMandate:
    """Durable bounded proposal mandate record (envelope + sealed payload)."""

    envelope: ObjectEnvelope
    spec: MandateSpec
    integrity_hash: str

    EXPECTED_OBJECT_TYPE = PROPOSAL_MANDATE_OBJECT_TYPE

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError(
                "proposal mandate envelope must be an ObjectEnvelope"
            )
        if not isinstance(self.spec, MandateSpec):
            raise CoreValidationError("proposal mandate spec must be a MandateSpec")
        self.envelope.verify_integrity()
        if self.envelope.object_type != PROPOSAL_MANDATE_OBJECT_TYPE:
            raise CoreValidationError(
                f"proposal mandate object_type must be {PROPOSAL_MANDATE_OBJECT_TYPE!r}"
            )
        try:
            MandateState(self.envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"unknown proposal mandate state: {self.envelope.state!r}"
            ) from exc
        if self.envelope.object_id != self.spec.mandate_id:
            raise CoreValidationError(
                "proposal mandate identity mismatch: envelope and spec must name "
                "the same mandate"
            )
        verify_composite(
            self.envelope, self.spec, self.integrity_hash, self.spec.mandate_id
        )

    @property
    def mandate_id(self) -> str:
        return self.spec.mandate_id

    @property
    def state(self) -> str:
        return self.envelope.state

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "payload": self.spec.to_dict(),
            "integrity_hash": self.integrity_hash,
        }

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ProposalMandate":
        envelope, payload = decode_composite(
            value,
            expected_object_type=PROPOSAL_MANDATE_OBJECT_TYPE,
            state_type=MandateState,
        )
        spec = MandateSpec.from_dict(payload)
        return cls(
            envelope=envelope, spec=spec, integrity_hash=value["integrity_hash"]
        )

    @classmethod
    def from_json(cls, value: str) -> "ProposalMandate":
        envelope, payload, integrity_hash = decode_composite_json(
            value,
            expected_object_type=PROPOSAL_MANDATE_OBJECT_TYPE,
            state_type=MandateState,
        )
        spec = MandateSpec.from_dict(payload)
        return cls(envelope=envelope, spec=spec, integrity_hash=integrity_hash)


class MandateBook:
    """Typed mandate store applying ``agent/authorize-mandate`` commands."""

    def __init__(self, *, environment_id: str, domain_id: str) -> None:
        require_identifier("mandate book environment_id", environment_id)
        require_identifier("mandate book domain_id", domain_id)
        self._environment_id = environment_id
        self._domain_id = domain_id
        self._mandates: dict[str, ProposalMandate] = {}
        self._budget_consumed: dict[str, int] = {}

    # -- read-only surface --------------------------------------------------

    def get(self, mandate_id: str) -> ProposalMandate | None:
        require_agents_identifier(
            "mandate_id", mandate_id, PROPOSAL_MANDATE_ID_PREFIX
        )
        return self._mandates.get(mandate_id)

    def require_mandate(self, mandate_id: str) -> ProposalMandate:
        mandate = self.get(mandate_id)
        if mandate is None:
            raise CoreValidationError(
                f"unknown proposal mandate {mandate_id!r}: the domain fails closed "
                "on unknown mandate identity"
            )
        return mandate

    def mandates(self) -> tuple[ProposalMandate, ...]:
        return tuple(self._mandates[mandate_id] for mandate_id in sorted(self._mandates))

    def budget_consumed(self, mandate_id: str) -> int:
        self.require_mandate(mandate_id)
        return self._budget_consumed.get(mandate_id, 0)

    def state_digest(self) -> str:
        """Canonical digest of the mandate state (records + budget)."""
        return canonical_sha256(
            {
                "mandates": [mandate.to_dict() for mandate in self.mandates()],
                "budget_consumed": [
                    [mandate_id, self._budget_consumed.get(mandate_id, 0)]
                    for mandate_id in sorted(self._mandates)
                ],
            }
        )

    # -- bounded authority evaluation ----------------------------------------

    def authorize_proposal(
        self,
        *,
        mandate_id: str,
        agent_principal: str,
        proposal_kind: ProposalKind,
        route_family: str,
        as_of: str,
        consumed: int,
    ) -> None:
        """Fail closed unless the mandate covers exactly this proposal.

        The window is half-open ``[not_before, not_after)``: a proposal at
        or after expiry fails closed. Scope covers the proposal kind and
        the route family; the budget is explicit; the agent must be the
        principal the mandate is bound to.
        """
        mandate = self.require_mandate(mandate_id)
        require_identifier("proposal agent_principal", agent_principal)
        if not isinstance(proposal_kind, ProposalKind):
            raise CoreValidationError(
                "proposal kind must use the closed ProposalKind vocabulary"
            )
        require_text("proposal route_family", route_family)
        require_utc_timestamp("proposal authorization instant", as_of)
        require_int("consumed proposal budget", consumed, minimum=0)
        if agent_principal != mandate.spec.agent_principal:
            raise CoreValidationError(
                f"proposal mandate {mandate_id!r} is bound to agent "
                f"{mandate.spec.agent_principal!r}, not {agent_principal!r}"
            )
        if not utc_timestamp_within(as_of, mandate.spec.not_before, mandate.spec.not_after):
            raise CoreValidationError(
                f"proposal mandate {mandate_id!r} is not active at {as_of}: "
                "bounded mandates expire and expiry fails closed"
            )
        if proposal_kind not in mandate.spec.proposal_kinds:
            raise CoreValidationError(
                f"proposal kind {proposal_kind.value} is outside the scope of "
                f"mandate {mandate_id!r}"
            )
        if route_family not in mandate.spec.route_families:
            raise CoreValidationError(
                f"route family {route_family!r} is outside the declared scope of "
                f"mandate {mandate_id!r}: undeclared scope fails closed"
            )
        if consumed >= mandate.spec.max_proposals:
            raise CoreValidationError(
                f"proposal mandate {mandate_id!r} budget exhausted "
                f"({consumed}/{mandate.spec.max_proposals}): explicit limits fail "
                "closed when exceeded"
            )

    def consume_budget(self, mandate_id: str) -> None:
        """Record one accepted proposal against the mandate budget."""
        self.require_mandate(mandate_id)
        self._budget_consumed[mandate_id] = (
            self._budget_consumed.get(mandate_id, 0) + 1
        )

    # -- semantic gate + transition handler -----------------------------------

    def evaluate_command(self, command: Command) -> str | None:
        if command.command_type != "agent/authorize-mandate":
            raise CoreValidationError(
                f"mandate book received command {command.command_type!r}"
            )
        try:
            data = payload_to_json_value(command.payload)
            if not isinstance(data, Mapping):
                raise CoreValidationError("mandate command payload must be an object")
            strict_fields("mandate command", data, _AUTHORIZE_FIELDS)
            require_agents_identifier(
                "mandate command mandate_id", data["mandate_id"], PROPOSAL_MANDATE_ID_PREFIX
            )
            if data["mandate_id"] in self._mandates:
                raise CoreValidationError(
                    f"proposal mandate {data['mandate_id']!r} is already authorized"
                )
            if command.actor == data["agent_principal"]:
                raise CoreValidationError(
                    "a proposal mandate must be issued by a principal distinct "
                    "from the agent"
                )
            MandateSpec(
                mandate_id=data["mandate_id"],
                agent_principal=data["agent_principal"],
                issued_by=command.actor,
                proposal_kinds=tuple(data["proposal_kinds"]),
                route_families=tuple(data["route_families"]),
                max_proposals=data["max_proposals"],
                not_before=data["not_before"],
                not_after=data["not_after"],
                authority_class=data["authority_class"],
                issued_at=command.requested_at,
            )
        except CoreValidationError as exc:
            return f"mandate command fails closed: {exc}"
        return None

    def apply_command(self, command: Command) -> TransitionApplication:
        data = payload_to_json_value(command.payload)
        if not isinstance(data, Mapping):
            raise CoreValidationError("mandate command payload must be an object")
        strict_fields("mandate command", data, _AUTHORIZE_FIELDS)
        if data["mandate_id"] in self._mandates:
            raise CoreValidationError(
                f"proposal mandate {data['mandate_id']!r} is already authorized"
            )
        spec = MandateSpec(
            mandate_id=data["mandate_id"],
            agent_principal=data["agent_principal"],
            issued_by=command.actor,
            proposal_kinds=tuple(data["proposal_kinds"]),
            route_families=tuple(data["route_families"]),
            max_proposals=data["max_proposals"],
            not_before=data["not_before"],
            not_after=data["not_after"],
            authority_class=data["authority_class"],
            issued_at=command.requested_at,
        )
        envelope = build_domain_envelope(
            object_id=spec.mandate_id,
            object_type=PROPOSAL_MANDATE_OBJECT_TYPE,
            state=MandateState.ACTIVE.value,
            environment_id=self._environment_id,
            domain_id=self._domain_id,
            provenance=Provenance(
                issuer=command.actor,
                source="agents/agent-authorize-mandate",
                recorded_at=command.requested_at,
                evidence_refs=(spec.mandate_id,),
            ),
            causation_id=command.command_id,
            correlation_id=command.correlation_id,
        )
        mandate = ProposalMandate(
            envelope=envelope, spec=spec, integrity_hash=seal_composite(envelope, spec)
        )
        self._mandates[spec.mandate_id] = mandate
        self._budget_consumed[spec.mandate_id] = 0
        return TransitionApplication(
            resulting_envelopes=(envelope,), payload=spec.to_dict()
        )
