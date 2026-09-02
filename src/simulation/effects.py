"""The effect policy and the authorization boundary (WORK-019).

Environments differ in world state and permitted external effects — never
financial semantics. The effect policy is the ONLY thing that differs
between environments:

* ``SIMULATION``/``REPLAY``/``FORECAST``/``COUNTERFACTUAL`` — effect
  intents are **recorded** (typed ``RECORDED`` records); execution is
  impossible by construction;
* ``SHADOW`` — effect intents are **shadowed** (typed ``SHADOWED``
  records: live-style observations, no production effects);
* ``PRODUCTION`` — effect intents require an explicit
  :class:`EffectAuthorization` (typed, windowed, registry authority
  class) and even then this package only emits authorized effect
  records. There is no out-of-environment execution path in this
  package: real execution lives outside the simulation domain, behind
  the records produced here (constitution invariant 14 — simulation
  cannot mutate production state or create production effects).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.transition.payload import normalize_payload, payload_to_json_value
from src.transition.registry import validate_authority_class

from ._validation import (
    parse_utc_timestamp,
    require_identifier,
    require_text,
    require_utc_timestamp,
    require_utc_timestamp_order,
    strict_fields,
)
from .contracts import EffectDecision, EnvironmentMode

_EFFECT_TYPE_RE = re.compile(r"^[a-z0-9][a-z0-9-]+/[a-z0-9][a-z0-9.-]+$")

_INTENT_FIELDS = frozenset(
    {
        "effect_id",
        "effect_type",
        "payload",
        "idempotency_key",
        "requested_at",
    }
)
_AUTHORIZATION_FIELDS = frozenset(
    {
        "authorizer",
        "authority_class",
        "authorized_types",
        "valid_from",
        "valid_until",
    }
)
_RECORD_FIELDS = frozenset(
    {
        "effect_id",
        "effect_type",
        "decision",
        "environment_id",
        "mode",
        "command_id",
        "idempotency_key",
        "requested_at",
        "reason",
        "authorization_digest",
        "fault_reason",
        "payload_digest",
        "integrity_hash",
    }
)


def _require_effect_type(name: str, effect_type: str) -> str:
    require_text(name, effect_type)
    if _EFFECT_TYPE_RE.match(effect_type) is None:
        raise CoreValidationError(
            f"{name} must use the '<family>/<name>' effect type format"
        )
    return effect_type


def seal_effect_record(content: Mapping[str, Any]) -> str:
    """Domain seal over the canonical effect record content."""
    return canonical_sha256(dict(content))


@dataclass(frozen=True, slots=True)
class EffectIntent:
    """One typed external-effect intent declared by a protocol transition.

    Intents are business semantics (identical across environments — the
    parity invariant covers them); the policy decides what becomes of
    them. Payloads are normalized into the deeply immutable form owned by
    the kernel's public payload utilities (floats fail closed).
    """

    effect_id: str
    effect_type: str
    payload: Any
    idempotency_key: str
    requested_at: str

    def __post_init__(self) -> None:
        require_identifier("effect intent effect_id", self.effect_id)
        _require_effect_type("effect intent effect_type", self.effect_type)
        require_text("effect intent idempotency_key", self.idempotency_key)
        require_utc_timestamp("effect intent requested_at", self.requested_at)
        object.__setattr__(
            self, "payload", normalize_payload("effect intent payload", self.payload)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "effect_id": self.effect_id,
            "effect_type": self.effect_type,
            "payload": payload_to_json_value(self.payload),
            "idempotency_key": self.idempotency_key,
            "requested_at": self.requested_at,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EffectIntent":
        if not isinstance(value, Mapping):
            raise CoreValidationError("effect intent must be an object")
        strict_fields("effect intent", value, _INTENT_FIELDS)
        return cls(
            effect_id=value["effect_id"],
            effect_type=value["effect_type"],
            payload=value["payload"],
            idempotency_key=value["idempotency_key"],
            requested_at=value["requested_at"],
        )

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_dict())


@dataclass(frozen=True, slots=True)
class EffectAuthorization:
    """Explicit, typed, windowed authorization for production effects.

    An authorization covers a closed set of effect types over the
    fail-closed coverage window — an effect request is covered only
    strictly after ``valid_from`` (the authorization must exist before
    the request, never at the same instant) and strictly before
    ``valid_until`` — and is exercised by a principal holding one of the
    frozen registry authority classes (validated through the kernel's
    registry authority — no second authority vocabulary).
    Authorizations exist only in production policies; attaching one to a
    non-production policy fails closed.
    """

    authorizer: str
    authority_class: str
    authorized_types: frozenset[str]
    valid_from: str
    valid_until: str

    def __post_init__(self) -> None:
        require_identifier("effect authorization authorizer", self.authorizer)
        validate_authority_class("effect authorization authority_class", self.authority_class)
        if not isinstance(self.authorized_types, (frozenset, set)):
            raise CoreValidationError(
                "effect authorization authorized_types must be a frozenset"
            )
        if not self.authorized_types:
            raise CoreValidationError(
                "effect authorization must cover at least one effect type"
            )
        for effect_type in self.authorized_types:
            _require_effect_type("authorized effect type", effect_type)
        if isinstance(self.authorized_types, set):
            object.__setattr__(
                self, "authorized_types", frozenset(self.authorized_types)
            )
        require_utc_timestamp("effect authorization valid_from", self.valid_from)
        require_utc_timestamp("effect authorization valid_until", self.valid_until)
        require_utc_timestamp_order(
            "effect authorization valid_from",
            self.valid_from,
            "effect authorization valid_until",
            self.valid_until,
        )

    def covers(self, effect_type: str, at: str) -> bool:
        """Whether the authorization covers one effect type at one instant.

        Fail-closed coverage window: the instant must be strictly later
        than ``valid_from`` (an authorization never covers a request made
        at the very instant it comes into being) and strictly earlier
        than ``valid_until``.
        """
        _require_effect_type("effect type", effect_type)
        require_utc_timestamp("authorization instant", at)
        if effect_type not in self.authorized_types:
            return False
        instant = parse_utc_timestamp("authorization instant", at)
        return (
            parse_utc_timestamp("effect authorization valid_from", self.valid_from)
            < instant
            < parse_utc_timestamp("effect authorization valid_until", self.valid_until)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "authorizer": self.authorizer,
            "authority_class": self.authority_class,
            "authorized_types": sorted(self.authorized_types),
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EffectAuthorization":
        if not isinstance(value, Mapping):
            raise CoreValidationError("effect authorization must be an object")
        strict_fields("effect authorization", value, _AUTHORIZATION_FIELDS)
        types_raw = value["authorized_types"]
        if not isinstance(types_raw, list):
            raise CoreValidationError(
                "effect authorization types must deserialize from a list"
            )
        return cls(
            authorizer=value["authorizer"],
            authority_class=value["authority_class"],
            authorized_types=frozenset(types_raw),
            valid_from=value["valid_from"],
            valid_until=value["valid_until"],
        )

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_dict())


class EffectPolicy:
    """The effect policy — the only environment-dependent component.

    Given the same effect intent, different modes produce different typed
    outcomes while the protocol transitions stay identical (parity).
    Production requires an explicit authorization and still only emits
    records; every unauthorized production attempt fails closed.
    """

    __slots__ = ("_mode", "_authorization")

    def __init__(
        self,
        mode: EnvironmentMode,
        authorization: EffectAuthorization | None = None,
    ) -> None:
        if not isinstance(mode, EnvironmentMode):
            raise CoreValidationError("effect policy mode must be an EnvironmentMode")
        if authorization is not None:
            if not isinstance(authorization, EffectAuthorization):
                raise CoreValidationError(
                    "effect policy authorization must be an EffectAuthorization"
                )
            if mode is not EnvironmentMode.PRODUCTION:
                raise CoreValidationError(
                    "effect authorization is a production-only boundary; mode "
                    f"{mode.value} must not carry one"
                )
        self._mode = mode
        self._authorization = authorization

    @classmethod
    def for_mode(cls, mode: EnvironmentMode) -> "EffectPolicy":
        return cls(mode)

    @property
    def mode(self) -> EnvironmentMode:
        return self._mode

    @property
    def authorization(self) -> EffectAuthorization | None:
        return self._authorization

    def decide(
        self, intent: EffectIntent
    ) -> tuple[EffectDecision, str, str | None]:
        """Decide the typed outcome of one effect intent under this policy.

        Returns ``(decision, reason, authorization_digest)``. Production
        intents without a covering authorization fail closed
        (CoreValidationError) — never a silent drop.
        """
        if not isinstance(intent, EffectIntent):
            raise CoreValidationError("effect policy decides EffectIntent records")
        if self._mode is EnvironmentMode.PRODUCTION:
            if self._authorization is None:
                raise CoreValidationError(
                    "production effect intents fail closed: no effect authorization "
                    "is configured for this environment"
                )
            if not self._authorization.covers(intent.effect_type, intent.requested_at):
                raise CoreValidationError(
                    f"production effect intent {intent.effect_id!r} of type "
                    f"{intent.effect_type!r} is not covered by the configured "
                    "effect authorization (type set or validity window)"
                )
            return (
                EffectDecision.AUTHORIZED,
                "authorized for real execution behind the effect authorization boundary",
                self._authorization.digest,
            )
        if self._mode is EnvironmentMode.SHADOW:
            return (
                EffectDecision.SHADOWED,
                "shadow environment: live-style observations, no production effects",
                None,
            )
        return (
            EffectDecision.RECORDED,
            f"{self._mode.value} environment records effects; execution is "
            "impossible by construction",
            None,
        )


@dataclass(frozen=True, slots=True)
class EffectRecord:
    """One sealed, typed effect outcome record.

    The record is the durable representation of what the effect policy
    decided — including authorized production decisions, which carry the
    authorization digest. Records never mutate protocol state and never
    execute anything.
    """

    effect_id: str
    effect_type: str
    decision: EffectDecision
    environment_id: str
    mode: EnvironmentMode
    command_id: str
    idempotency_key: str
    requested_at: str
    reason: str
    authorization_digest: str | None
    fault_reason: str | None
    payload_digest: str
    integrity_hash: str | None = None

    def __post_init__(self) -> None:
        require_identifier("effect record effect_id", self.effect_id)
        _require_effect_type("effect record effect_type", self.effect_type)
        if not isinstance(self.decision, EffectDecision):
            raise CoreValidationError(
                "effect record decision must be an EffectDecision"
            )
        require_identifier("effect record environment_id", self.environment_id)
        if not isinstance(self.mode, EnvironmentMode):
            raise CoreValidationError("effect record mode must be an EnvironmentMode")
        require_identifier("effect record command_id", self.command_id)
        require_text("effect record idempotency_key", self.idempotency_key)
        require_utc_timestamp("effect record requested_at", self.requested_at)
        require_text("effect record reason", self.reason)
        if self.authorization_digest is not None:
            require_text("effect record authorization_digest", self.authorization_digest)
        if self.fault_reason is not None:
            require_text("effect record fault_reason", self.fault_reason)
        require_text("effect record payload_digest", self.payload_digest)
        expected = seal_effect_record(self._content())
        if self.integrity_hash is None:
            object.__setattr__(self, "integrity_hash", expected)
        elif self.integrity_hash != expected:
            raise CoreValidationError(
                f"integrity hash mismatch for effect record {self.effect_id}"
            )

    def _content(self) -> dict[str, Any]:
        return {
            "effect_id": self.effect_id,
            "effect_type": self.effect_type,
            "decision": self.decision.value,
            "environment_id": self.environment_id,
            "mode": self.mode.value,
            "command_id": self.command_id,
            "idempotency_key": self.idempotency_key,
            "requested_at": self.requested_at,
            "reason": self.reason,
            "authorization_digest": self.authorization_digest,
            "fault_reason": self.fault_reason,
            "payload_digest": self.payload_digest,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._content(), "integrity_hash": self.integrity_hash}

    @classmethod
    def build(
        cls,
        intent: EffectIntent,
        *,
        decision: EffectDecision,
        reason: str,
        environment_id: str,
        mode: EnvironmentMode,
        command_id: str,
        authorization_digest: str | None,
        fault_reason: str | None = None,
    ) -> "EffectRecord":
        return cls(
            effect_id=intent.effect_id,
            effect_type=intent.effect_type,
            decision=decision,
            environment_id=environment_id,
            mode=mode,
            command_id=command_id,
            idempotency_key=intent.idempotency_key,
            requested_at=intent.requested_at,
            reason=reason,
            authorization_digest=authorization_digest,
            fault_reason=fault_reason,
            payload_digest=intent.digest,
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EffectRecord":
        if not isinstance(value, Mapping):
            raise CoreValidationError("effect record must be an object")
        strict_fields("effect record", value, _RECORD_FIELDS)
        return cls(
            effect_id=value["effect_id"],
            effect_type=value["effect_type"],
            decision=EffectDecision(value["decision"]),
            environment_id=value["environment_id"],
            mode=EnvironmentMode.parse(value["mode"]),
            command_id=value["command_id"],
            idempotency_key=value["idempotency_key"],
            requested_at=value["requested_at"],
            reason=value["reason"],
            authorization_digest=value["authorization_digest"],
            fault_reason=value["fault_reason"],
            payload_digest=value["payload_digest"],
            integrity_hash=value["integrity_hash"],
        )


def record_effects(
    policy: EffectPolicy,
    intents: Iterable[EffectIntent],
    *,
    environment_id: str,
    command_id: str,
    faults: Mapping[str, str],
) -> tuple[EffectRecord, ...]:
    """Apply the effect policy to every intent of one accepted transition.

    ``faults`` maps effect types to active injected-fault reasons; a
    faulted effect is still decided by the policy (authorized in
    production) but carries the failure reason — the record models a rail
    that failed after authorization, never a silent success.
    """
    records: list[EffectRecord] = []
    for intent in intents:
        if not isinstance(intent, EffectIntent):
            raise CoreValidationError("effect intents must be EffectIntent records")
        decision, reason, authorization_digest = policy.decide(intent)
        fault_reason = faults.get(intent.effect_type)
        records.append(
            EffectRecord.build(
                intent,
                decision=decision,
                reason=reason,
                environment_id=environment_id,
                mode=policy.mode,
                command_id=command_id,
                authorization_digest=authorization_digest,
                fault_reason=fault_reason,
            )
        )
    return tuple(records)
