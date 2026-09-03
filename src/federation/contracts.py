"""Frozen public-boundary contracts for the federation domain (WORK-023).

This package owns the frozen v0.1 ``Federation`` command family
``Register/Join/Leave/UpdateAuthority/PublishCommitment/AcceptCommitment/
TransferDomain`` (governance.md "Federated state": authoritative domains
with governed state authorities that publish state commitments and
finality evidence; ownership-lifecycle "an authoritative object has
exactly one authoritative state domain at a time" and "domain transfer
is explicit and leaves no dual-authority interval").

Registry discipline: NO federation object type and NO federation event
namespace is listed in the frozen protocol registry. Following the
sibling convention for unregistered domain-local record kinds
(WORK-018 precedent), every federation object type below uses an
internal non-registry ``federation/...`` format and every federation
event uses the REGISTERED ``governance`` namespace — the namespace whose
governing document (``governance.md``) explicitly covers federation and
institutional boundaries, the same precedent the agents domain
(WORK-021) set. No new protocol-visible name is invented here.

Boundary with the sibling Work Orders: this package consumes the trust
domain's purpose-bound key records (WORK-004 — the
``DOMAIN_STATE_COMMITMENT`` and ``FINALITY_EVIDENCE`` key purposes are
frozen in the trust contract) through their trusted decode path, and
consumes the settlement domain's sealed finality certificates (WORK-016)
through their trusted decode path — a state commitment binds finality
evidence, it never re-evaluates or manufactures it. The kernel's own
domain binding (a command of one domain can never read or write an
object of another domain) is the structural enforcement of the Work
Order's forbidden surface "no unilateral foreign-domain mutation".
"""

from __future__ import annotations

from enum import StrEnum
from typing import Mapping

from src.core.errors import CoreValidationError
from src.transition.registry import PROTOCOL_VERSION

from ._validation import parse_enum, require_text

# -- typed, versioned public boundary --------------------------------------


#: Typed public API version of the federation domain boundary.
FEDERATION_API_VERSION = "v0.1"

#: The frozen kernel protocol version every federation record is bound to.
FEDERATION_PROTOCOL_VERSION = PROTOCOL_VERSION

#: Schema version of the federation composite record encoding.
FEDERATION_SCHEMA_VERSION = 1


#: Internal (non-registry) network domain object type following the
#: sibling convention for domain-local record kinds.
DOMAIN_OBJECT_TYPE = "federation/network-domain/v1"

#: Internal (non-registry) state commitment object type.
COMMITMENT_OBJECT_TYPE = "federation/state-commitment/v1"

#: Internal (non-registry) inter-domain message object type.
MESSAGE_OBJECT_TYPE = "federation/inter-domain-message/v1"

#: Internal (non-registry) commitment acceptance object type.
ACCEPTANCE_OBJECT_TYPE = "federation/commitment-acceptance/v1"

#: Object types owned by this domain.
OBJECT_TYPES = (
    DOMAIN_OBJECT_TYPE,
    COMMITMENT_OBJECT_TYPE,
    MESSAGE_OBJECT_TYPE,
    ACCEPTANCE_OBJECT_TYPE,
)

#: The registry-listed event namespace every federation event uses
#: (governance.md covers federation and institutional boundaries; the
#: agents domain set the same precedent for unregistered domains).
FEDERATION_EVENT_NAMESPACE = "governance"


# -- frozen command family --------------------------------------------------


FEDERATION_COMMANDS = frozenset(
    {
        "federation/register",
        "federation/join",
        "federation/leave",
        "federation/update-authority",
        "federation/publish-commitment",
        "federation/accept-commitment",
        "federation/transfer-domain",
    }
)

#: Canonical event type per command (all in the registered
#: ``governance`` namespace; rejected commands emit the kernel's audit
#: rejection events, never a domain event).
COMMAND_EVENT_TYPES: Mapping[str, str] = {
    "federation/register": "governance/domain-registered",
    "federation/join": "governance/domain-joined",
    "federation/leave": "governance/domain-left",
    "federation/update-authority": "governance/domain-authority-updated",
    "federation/publish-commitment": "governance/state-commitment-published",
    "federation/accept-commitment": "governance/commitment-accepted",
    "federation/transfer-domain": "governance/domain-transferred",
}


# -- closed lifecycles -------------------------------------------------------


class DomainState(StrEnum):
    """Closed lifecycle of a network domain.

    ``REGISTERED → JOINED → LEFT``. Registering creates the domain with
    its governed state authority; joining records the federation anchor
    (the peer domain whose commitment key this domain trusts); leaving
    is an explicit, terminal departure (ownership-lifecycle: an object
    may not terminate while active dependents require it unless a
    governed successor exists — departure is a governed decision).
    ``LEFT`` is terminal: a departed domain's authority facts freeze and
    no further federation command advances the record.
    """

    REGISTERED = "REGISTERED"
    JOINED = "JOINED"
    LEFT = "LEFT"

    @classmethod
    def parse(cls, value: object) -> "DomainState":
        return parse_enum("domain state", value, cls)  # type: ignore[return-value]


#: Terminal domain states (no federation command may advance them).
DOMAIN_TERMINAL_STATES = frozenset({DomainState.LEFT})


class CommitmentState(StrEnum):
    """A state commitment is an immutable append-only record (the
    ownership-lifecycle IMMUTABLE class covers commitments and
    attestations): it is created ``PUBLISHED`` and never transitions.
    A superseding commitment is a new record at the next sequence, not
    an edit (constitution invariant 17)."""

    PUBLISHED = "PUBLISHED"

    @classmethod
    def parse(cls, value: object) -> "CommitmentState":
        return parse_enum("commitment state", value, cls)  # type: ignore[return-value]


class MessageState(StrEnum):
    """An inter-domain message is immutable once issued."""

    ISSUED = "ISSUED"

    @classmethod
    def parse(cls, value: object) -> "MessageState":
        return parse_enum("message state", value, cls)  # type: ignore[return-value]


class AcceptanceState(StrEnum):
    """A commitment acceptance is immutable once recorded (the replay
    gate keys on the accepted message identity)."""

    ACCEPTED = "ACCEPTED"

    @classmethod
    def parse(cls, value: object) -> "AcceptanceState":
        return parse_enum("acceptance state", value, cls)  # type: ignore[return-value]


class MessageKind(StrEnum):
    """Closed vocabulary of inter-domain message kinds.

    ``STATE_COMMITMENT`` — a message carrying one published state
    commitment from the origin domain to the destination domain.
    """

    STATE_COMMITMENT = "STATE_COMMITMENT"

    @classmethod
    def parse(cls, value: object) -> "MessageKind":
        return parse_enum("message kind", value, cls)  # type: ignore[return-value]


# -- transition table --------------------------------------------------------


#: Allowed SOURCE states per command of the frozen family, expressed on
#: the primary object the command advances (the network domain record
#: for the domain-scoped commands). Commands that create their primary
#: object (register) or create immutable records (publish/accept) have
#: empty source sets; the engine's handlers validate these tables before
#: advancing any state.
FEDERATION_TRANSITIONS: Mapping[str, frozenset] = {
    "federation/register": frozenset(),
    "federation/join": frozenset({DomainState.REGISTERED}),
    "federation/leave": frozenset({DomainState.JOINED}),
    # Authority amendment and governed transfer are valid while the
    # domain is live (registered or joined); a LEFT domain is frozen.
    "federation/update-authority": frozenset({DomainState.REGISTERED, DomainState.JOINED}),
    "federation/transfer-domain": frozenset({DomainState.REGISTERED, DomainState.JOINED}),
    "federation/publish-commitment": frozenset(),
    "federation/accept-commitment": frozenset(),
}


def validate_command(command: str) -> str:
    """Require a command from the frozen federation family."""
    require_text("command", command)
    if command not in FEDERATION_COMMANDS:
        raise CoreValidationError(
            f"command {command!r} is not part of the frozen federation command family"
        )
    return command
