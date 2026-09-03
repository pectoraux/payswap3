"""Declared data policies: typed references to governance declarations.

A :class:`DataPolicy` is a VERSIONED durable record of a DECLARED data
policy (canonical object model "Safety and knowledge" family:
``PrivacyPolicy``). The declared content is typed policy parameters only
— per-field data classification, per-purpose grants of data classes,
retention horizons and an opaque legal-basis *reference*. The data domain
never invents legal rules and never embeds legal text as authoritative
content: the legal basis is recorded as an uninterpreted typed reference
declared by governance, and enforcement is purely mechanical over the
declared parameters. Unknown policy identifiers, unclassified fields,
ungranted purposes and inactive policies all fail closed.

The lifecycle follows the frozen Governance command family verbs
(Create/Activate/Retire collapsed to the data-domain internal command
types ``data/policy.declare`` / ``data/policy.activate`` /
``data/policy.retire``): declaration lands in ``DECLARED``, activation
pins the exact object version every disclosure, retention record, proof
and case must reference, and retirement is terminal. History is
append-only (constitution invariant 17).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.transition import MemoryStateStore

from .contracts import (
    DATA_POLICY_OBJECT_TYPE,
    LEGAL_BASIS_PREFIX,
    POLICY_ID_PREFIX,
    PRINCIPAL_PREFIX,
    DataClass,
    PolicyState,
)
from ._validation import (
    parse_enum,
    parse_utc_timestamp,
    require_identifier,
    require_int,
    require_pairs,
    require_text,
    require_utc_timestamp,
    require_utc_timestamp_order,
    require_utc_timestamp_strictly_after,
    strict_fields,
    utc_timestamp_within,
)
from .seal import (
    advance_envelope,
    build_domain_envelope,
    composite_to_dict,
    composite_to_json,
    decode_composite,
    decode_composite_json,
    seal_composite,
    verify_composite,
)

_SPEC_FIELDS = frozenset(
    {
        "policy_id",
        "declared_by",
        "declared_at",
        "effective_from",
        "valid_until",
        "legal_basis_ref",
        "purpose_grants",
        "field_rules",
        "retention_rules",
    }
)


@dataclass(frozen=True, slots=True)
class FieldRule:
    """One declared field classification: field name -> data class."""

    field_name: str
    data_class: DataClass

    def __post_init__(self) -> None:
        require_text("field_rule.field_name", self.field_name)
        object.__setattr__(
            self, "data_class", parse_enum("field_rule.data_class", DataClass, self.data_class)
        )

    def to_dict(self) -> dict[str, Any]:
        return {"field_name": self.field_name, "data_class": self.data_class.value}

    @classmethod
    def from_dict(cls, value: object) -> "FieldRule":
        if not isinstance(value, Mapping) or set(value) != {"field_name", "data_class"}:
            raise CoreValidationError(
                "field rule fields are not canonical; expected {field_name, data_class}"
            )
        return cls(field_name=value["field_name"], data_class=value["data_class"])


@dataclass(frozen=True, slots=True)
class RetentionRule:
    """One declared retention horizon for a data class, in whole seconds."""

    data_class: DataClass
    retain_seconds: int

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "data_class", parse_enum("retention_rule.data_class", DataClass, self.data_class)
        )
        require_int("retention_rule.retain_seconds", self.retain_seconds, minimum=0)

    def to_dict(self) -> dict[str, Any]:
        return {"data_class": self.data_class.value, "retain_seconds": self.retain_seconds}

    @classmethod
    def from_dict(cls, value: object) -> "RetentionRule":
        if not isinstance(value, Mapping) or set(value) != {"data_class", "retain_seconds"}:
            raise CoreValidationError(
                "retention rule fields are not canonical; "
                "expected {data_class, retain_seconds}"
            )
        return cls(data_class=value["data_class"], retain_seconds=value["retain_seconds"])


@dataclass(frozen=True, slots=True)
class PurposeGrant:
    """One declared purpose grant: the data classes disclosable for a purpose."""

    purpose: Any
    allowed_classes: tuple[DataClass, ...]

    def __post_init__(self) -> None:
        from .contracts import DisclosurePurpose

        object.__setattr__(
            self, "purpose", parse_enum("purpose_grant.purpose", DisclosurePurpose, self.purpose)
        )
        if not isinstance(self.allowed_classes, tuple) or not self.allowed_classes:
            raise CoreValidationError(
                "purpose_grant.allowed_classes must be a non-empty tuple of DataClass"
            )
        classes = [
            parse_enum("purpose_grant.allowed_class", DataClass, item)
            for item in self.allowed_classes
        ]
        if len(set(classes)) != len(classes):
            raise CoreValidationError("purpose_grant.allowed_classes must be unique")
        object.__setattr__(self, "allowed_classes", tuple(sorted(classes)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "purpose": self.purpose.value,
            "allowed_classes": [item.value for item in self.allowed_classes],
        }

    @classmethod
    def from_dict(cls, value: object) -> "PurposeGrant":
        if not isinstance(value, Mapping) or set(value) != {"purpose", "allowed_classes"}:
            raise CoreValidationError(
                "purpose grant fields are not canonical; expected {purpose, allowed_classes}"
            )
        return cls(purpose=value["purpose"], allowed_classes=tuple(value["allowed_classes"]))


@dataclass(frozen=True, slots=True)
class DataPolicySpec:
    """Immutable declared policy payload (typed references only).

    - ``policy_id``: the governance-declared policy identifier this
      object records (typed reference, fail-closed on unknown).
    - ``declared_by``: an opaque trust-domain principal reference that
      declared the policy.
    - ``legal_basis_ref``: an opaque typed reference to the declared
      legal basis. The data domain records it and never interprets it.
    - ``purpose_grants``: per purpose, the data classes that may be
      disclosed; absence of a purpose grant denies that purpose.
    - ``field_rules``: per-field data classification. A field that is
      not classified can never be disclosed (fail closed).
    - ``retention_rules``: per data class, the retention horizon in
      whole seconds. Every classified data class must have one.
    """

    policy_id: str
    declared_by: str
    declared_at: str
    effective_from: str
    valid_until: str
    legal_basis_ref: str
    purpose_grants: tuple[PurposeGrant, ...]
    field_rules: tuple[FieldRule, ...]
    retention_rules: tuple[RetentionRule, ...]

    def __post_init__(self) -> None:
        require_identifier("policy.policy_id", self.policy_id, prefix=POLICY_ID_PREFIX)
        require_identifier("policy.declared_by", self.declared_by, prefix=PRINCIPAL_PREFIX)
        require_identifier(
            "policy.legal_basis_ref", self.legal_basis_ref, prefix=LEGAL_BASIS_PREFIX
        )
        for name in ("declared_at", "effective_from", "valid_until"):
            require_utc_timestamp(f"policy.{name}", getattr(self, name))
        require_utc_timestamp_order(
            "policy.declared_at", self.declared_at,
            "policy.effective_from", self.effective_from,
        )
        require_utc_timestamp_strictly_after(
            "policy.effective_from", self.effective_from,
            "policy.valid_until", self.valid_until,
        )
        if not isinstance(self.purpose_grants, tuple) or not self.purpose_grants:
            raise CoreValidationError("policy.purpose_grants must be a non-empty tuple")
        purposes = [grant.purpose for grant in self.purpose_grants]
        if len(set(purposes)) != len(purposes):
            raise CoreValidationError("policy purpose grants must be unique")
        if not isinstance(self.field_rules, tuple) or not self.field_rules:
            raise CoreValidationError("policy.field_rules must be a non-empty tuple")
        fields = [rule.field_name for rule in self.field_rules]
        if len(set(fields)) != len(fields):
            raise CoreValidationError("policy field rules must be unique")
        if not isinstance(self.retention_rules, tuple) or not self.retention_rules:
            raise CoreValidationError("policy.retention_rules must be a non-empty tuple")
        classes = [rule.data_class for rule in self.retention_rules]
        if len(set(classes)) != len(classes):
            raise CoreValidationError("policy retention rules must be unique")
        covered = {rule.data_class for rule in self.retention_rules}
        for rule in self.field_rules:
            if rule.data_class not in covered:
                raise CoreValidationError(
                    "every declared field class must carry a retention rule; "
                    f"class {rule.data_class.value} is uncovered"
                )

    def data_class_for(self, field_name: str) -> DataClass:
        for rule in self.field_rules:
            if rule.field_name == field_name:
                return rule.data_class
        raise CoreValidationError(
            f"field {field_name!r} is not classified by policy {self.policy_id}"
        )

    def classes_for(self, purpose: Any) -> frozenset[DataClass]:
        from .contracts import DisclosurePurpose

        purpose = parse_enum("purpose", DisclosurePurpose, purpose)
        for grant in self.purpose_grants:
            if grant.purpose == purpose:
                return frozenset(grant.allowed_classes)
        return frozenset()

    def retain_seconds_for(self, data_class: DataClass) -> int:
        data_class = parse_enum("data_class", DataClass, data_class)
        for rule in self.retention_rules:
            if rule.data_class == data_class:
                return rule.retain_seconds
        raise CoreValidationError(
            f"policy {self.policy_id} declares no retention rule for class "
            f"{data_class.value}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "declared_by": self.declared_by,
            "declared_at": self.declared_at,
            "effective_from": self.effective_from,
            "valid_until": self.valid_until,
            "legal_basis_ref": self.legal_basis_ref,
            "purpose_grants": [grant.to_dict() for grant in self.purpose_grants],
            "field_rules": [rule.to_dict() for rule in self.field_rules],
            "retention_rules": [rule.to_dict() for rule in self.retention_rules],
        }

    @classmethod
    def from_dict(cls, value: object) -> "DataPolicySpec":
        strict_fields("policy spec", value, _SPEC_FIELDS)
        return cls(
            policy_id=value["policy_id"],
            declared_by=value["declared_by"],
            declared_at=value["declared_at"],
            effective_from=value["effective_from"],
            valid_until=value["valid_until"],
            legal_basis_ref=value["legal_basis_ref"],
            purpose_grants=tuple(
                PurposeGrant.from_dict(item) for item in value["purpose_grants"]
            ),
            field_rules=tuple(FieldRule.from_dict(item) for item in value["field_rules"]),
            retention_rules=tuple(
                RetentionRule.from_dict(item) for item in value["retention_rules"]
            ),
        )


@dataclass(frozen=True, slots=True)
class DataPolicy:
    """Immutable durable data-policy record (envelope + declared spec + seal)."""

    envelope: ObjectEnvelope
    spec: DataPolicySpec
    integrity_hash: str

    def __post_init__(self) -> None:
        if not isinstance(self.spec, DataPolicySpec):
            raise CoreValidationError("data policy payload must be a DataPolicySpec")
        validate_envelope = decode_composite(
            composite_to_dict(self.envelope, self.spec, self.integrity_hash),
            expected_object_type=DATA_POLICY_OBJECT_TYPE,
            state_type=PolicyState,
        )
        if validate_envelope[0].object_id != self.spec.policy_id:
            raise CoreValidationError(
                "data policy object id must equal the declared policy identifier"
            )
        verify_composite(self.envelope, self.spec, self.integrity_hash, self.envelope.object_id)

    @property
    def policy_id(self) -> str:
        return self.spec.policy_id

    @property
    def state(self) -> PolicyState:
        return PolicyState(self.envelope.state)

    def to_dict(self) -> dict[str, Any]:
        return composite_to_dict(self.envelope, self.spec, self.integrity_hash)

    def to_json(self) -> str:
        return composite_to_json(self.envelope, self.spec, self.integrity_hash)

    @classmethod
    def from_dict(cls, value: object) -> "DataPolicy":
        envelope, payload = decode_composite(
            value, expected_object_type=DATA_POLICY_OBJECT_TYPE, state_type=PolicyState
        )
        integrity_hash = value["integrity_hash"]
        return cls(
            envelope=envelope,
            spec=DataPolicySpec.from_dict(payload),
            integrity_hash=integrity_hash,
        )

    @classmethod
    def from_json(cls, value: str) -> "DataPolicy":
        decoded = decode_composite_json(
            value, expected_object_type=DATA_POLICY_OBJECT_TYPE, state_type=PolicyState
        )
        return cls.from_dict(
            {"envelope": decoded[0].to_dict(), "payload": decoded[1], "integrity_hash": decoded[2]}
        )


def declare_policy(
    *,
    spec: DataPolicySpec,
    environment_id: str,
    domain_id: str,
    provenance: Provenance,
    causation_id: str | None = None,
    correlation_id: str | None = None,
) -> DataPolicy:
    """Record a declared policy as sealed version 1 in state DECLARED."""
    if not isinstance(spec, DataPolicySpec):
        raise CoreValidationError("declare_policy requires a DataPolicySpec")
    envelope = build_domain_envelope(
        object_id=spec.policy_id,
        object_type=DATA_POLICY_OBJECT_TYPE,
        state=PolicyState.DECLARED.value,
        environment_id=environment_id,
        domain_id=domain_id,
        provenance=provenance,
        causation_id=causation_id,
        correlation_id=correlation_id,
    )
    policy = DataPolicy(
        envelope=envelope, spec=spec, integrity_hash=seal_composite(envelope, spec)
    )
    return policy


def activate_policy(policy: DataPolicy, *, provenance: Provenance) -> DataPolicy:
    """Activate a DECLARED policy (DECLARED -> ACTIVE)."""
    if policy.state is not PolicyState.DECLARED:
        raise CoreValidationError(
            f"policy {policy.policy_id} cannot be activated from state {policy.state.value}"
        )
    envelope = advance_envelope(policy.envelope, state=PolicyState.ACTIVE.value, provenance=provenance)
    return DataPolicy(
        envelope=envelope, spec=policy.spec, integrity_hash=seal_composite(envelope, policy.spec)
    )


def retire_policy(policy: DataPolicy, *, provenance: Provenance) -> DataPolicy:
    """Retire an ACTIVE policy (ACTIVE -> RETIRED, terminal)."""
    if policy.state is not PolicyState.ACTIVE:
        raise CoreValidationError(
            f"policy {policy.policy_id} cannot be retired from state {policy.state.value}"
        )
    envelope = advance_envelope(policy.envelope, state=PolicyState.RETIRED.value, provenance=provenance)
    return DataPolicy(
        envelope=envelope, spec=policy.spec, integrity_hash=seal_composite(envelope, policy.spec)
    )


def policy_is_active_at(policy: DataPolicy, as_of: str) -> bool:
    """True only when the policy is ACTIVE and its window contains ``as_of``."""
    parse_utc_timestamp("as_of", as_of)
    if policy.state is not PolicyState.ACTIVE:
        return False
    return utc_timestamp_within(policy.spec.effective_from, as_of, policy.spec.valid_until)


def require_active_policy(policy: DataPolicy, as_of: str) -> DataPolicy:
    """Fail closed unless the policy is ACTIVE at the declared instant."""
    if not policy_is_active_at(policy, as_of):
        raise CoreValidationError(
            f"policy {policy.policy_id} is not active at {as_of} "
            f"(state {policy.state.value}, window "
            f"[{policy.spec.effective_from}, {policy.spec.valid_until}))"
        )
    return policy


def field_data_class(policy: DataPolicy, field_name: str) -> DataClass:
    return policy.spec.data_class_for(field_name)


def purpose_classes(policy: DataPolicy, purpose: Any) -> frozenset[DataClass]:
    return policy.spec.classes_for(purpose)


def retention_seconds_for(policy: DataPolicy, data_class: DataClass) -> int:
    return policy.spec.retain_seconds_for(data_class)


class DataPolicyRegistry:
    """Typed registry of declared data policies; fail-closed on unknown ids.

    The registry keeps every version of every policy and never rewrites
    history: appends are gated by the transition kernel's
    :class:`~src.transition.store.MemoryStateStore` (WORK-003), whose
    strict commit semantics — instance checks, envelope integrity,
    duplicate ids, exact version-chain advancement and frozen identity
    fields — are the append-only authority. There is no second store
    authority here.
    """

    __slots__ = ("_store", "_records")

    def __init__(self, policies: Iterable[DataPolicy] = ()) -> None:
        self._store = MemoryStateStore()
        self._records: dict[str, dict[int, DataPolicy]] = {}
        for policy in policies:
            self.append(policy)

    def declare(
        self,
        *,
        spec: DataPolicySpec,
        environment_id: str,
        domain_id: str,
        provenance: Provenance,
    ) -> DataPolicy:
        if spec.policy_id in self._records:
            raise CoreValidationError(
                f"policy {spec.policy_id} is already declared; declared policy content is "
                "immutable — declare a new policy identifier instead"
            )
        policy = declare_policy(
            spec=spec,
            environment_id=environment_id,
            domain_id=domain_id,
            provenance=provenance,
        )
        return self.append(policy)

    def activate(self, policy_id: str, *, as_of: str, provenance: Provenance) -> DataPolicy:
        policy = self.get(policy_id)
        if parse_utc_timestamp("as_of", as_of) < parse_utc_timestamp(
            "policy.declared_at", policy.spec.declared_at
        ):
            raise CoreValidationError(
                f"policy {policy_id} cannot be activated at {as_of} before its declaration "
                f"at {policy.spec.declared_at}"
            )
        return self.append(activate_policy(policy, provenance=provenance))

    def retire(self, policy_id: str, *, as_of: str, provenance: Provenance) -> DataPolicy:
        policy = self.get(policy_id)
        if parse_utc_timestamp("as_of", as_of) < parse_utc_timestamp(
            "policy.declared_at", policy.spec.declared_at
        ):
            raise CoreValidationError(
                f"policy {policy_id} cannot be retired at {as_of} before its declaration"
            )
        return self.append(retire_policy(policy, provenance=provenance))

    def append(self, policy: DataPolicy) -> DataPolicy:
        if not isinstance(policy, DataPolicy):
            raise CoreValidationError("the registry stores DataPolicy records only")
        # the kernel store validates integrity, exact version advancement
        # and frozen identity fields before anything is recorded.
        self._store.commit((policy.envelope,))
        versions = self._records.setdefault(policy.policy_id, {})
        versions[policy.envelope.object_version] = policy
        return policy

    def get(self, policy_id: str) -> DataPolicy:
        versions = self._records.get(policy_id)
        if not versions:
            raise CoreValidationError(f"unknown data policy: {policy_id}")
        return versions[max(versions)]

    def get_version(self, policy_id: str, version: int) -> DataPolicy:
        versions = self._records.get(policy_id, {})
        if version not in versions:
            raise CoreValidationError(f"policy {policy_id} has no recorded version {version}")
        return versions[version]

    def require_active(self, policy_id: str, as_of: str) -> DataPolicy:
        return require_active_policy(self.get(policy_id), as_of)

    def history(self, policy_id: str) -> tuple[DataPolicy, ...]:
        versions = self._records.get(policy_id, {})
        return tuple(versions[version] for version in sorted(versions))

    def __len__(self) -> int:
        return len(self._records)
