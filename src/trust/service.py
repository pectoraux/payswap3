"""The trust registry: authoritative in-memory state for one environment.

``TrustRegistry`` owns the current version of every trust record for a single
environment and domain (no dual authority interval: an environment's trust
state has exactly one authoritative holder). All mutations are explicit
command-family operations that produce new immutable sealed versions; history
stays append-only at the event level (authentication events) while versioned
records advance through ``next_version``.

Administrative guards: every mutating operation records an ``operator``
principal that must exist and be ACTIVE (structural fail-closed guard). The
full command-authorization pipeline (who may issue which command) is the
transition kernel's plane (WORK-003) and is integrated there, not duplicated
here.

Key security semantics implemented here (CRITICAL assurance):

* delegation is bounded (depth strictly decreases; scope, window, amount
  limits and jurisdictions are tighten-only from a covering parent grant);
* revocation is effective immediately through the live chain: any revoked or
  suspended link denies authorization without mutating descendants;
* denial is fail-closed and default-deny: unknown or inactive principals,
  missing/invalid authentication, uncovered scope, over-limit amounts,
  uncovered jurisdictions, environment mismatch and missing/inactive mandates
  all deny with explicit reasons.
"""

from __future__ import annotations

import hmac as _hmac
from typing import Any, Iterable, Mapping

from src.core import ObjectEnvelope, ObjectGraph, Relationship, RelationshipType
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_json, canonical_sha256, loads_canonical

from ._validation import (
    parse_timestamp,
    require_identifier,
    require_window_subset,
    require_optional_text,
    require_str_enum,
    require_str_tuple,
    require_text,
    require_timestamp,
    require_window,
    window_contains,
    window_subset,
)
from .authentication import (
    AuthenticationEventRecord,
    AuthenticationFailureReason,
    AuthenticationOutcome,
    derive_authentication_id,
)
from .authority import (
    AuthorizationGrantRecord,
    GrantKind,
    GrantState,
)
from .authorization import (
    AuthorizationDecision,
    AuthorizationDenialReason,
    AuthorizationOutcome,
    AuthorizationRequest,
)
from .credentials import (
    CredentialKind,
    CredentialRecord,
    CredentialState,
    derive_credential_verifier,
)
from .keys import (
    KeyPurpose,
    KeyRecord,
    KeyState,
    ThresholdApproval,
    ThresholdApprovalState,
    derive_key_verification_digest,
    key_rotation_proposal_digest,
)
from .mandates import MandateRecord, MandateState
from .objects import (
    AmountBound,
    advance_envelope,
    amount_limits_bounded_by,
    build_envelope,
    jurisdictions_subset,
    scope_subset,
)
from .principal import PrincipalRecord, PrincipalState
from .registry import validate_authority_class

TRUST_DOMAIN_ID = "domain/trust"
AUTHENTICATION_SERVICE_ISSUER = "trust/service/authentication"
GENESIS_SOURCE = "trust/genesis"
OPERATOR_SOURCE = "trust/operator"

_MISSING = object()

_REGISTRY_KEYS = frozenset(
    {
        "schema_version",
        "protocol_version",
        "environment_id",
        "domain_id",
        "principals",
        "credentials",
        "keys",
        "grants",
        "mandates",
        "authentication_events",
    }
)
_REGISTRY_SCHEMA_VERSION = 1
_REGISTRY_PROTOCOL_VERSION = "v0.1"


class TrustRegistry:
    """Authoritative trust state for one environment and domain."""

    def __init__(self, *, environment_id: str, domain_id: str = TRUST_DOMAIN_ID) -> None:
        self._environment_id = require_text("registry.environment_id", environment_id)
        self._domain_id = require_text("registry.domain_id", domain_id)
        self._principals: dict[str, PrincipalRecord] = {}
        self._credentials: dict[str, CredentialRecord] = {}
        self._keys: dict[str, KeyRecord] = {}
        self._grants: dict[str, AuthorizationGrantRecord] = {}
        self._mandates: dict[str, MandateRecord] = {}
        self._authentications: dict[str, AuthenticationEventRecord] = {}

    # ------------------------------------------------------------------
    # Read accessors
    # ------------------------------------------------------------------

    @property
    def environment_id(self) -> str:
        return self._environment_id

    @property
    def domain_id(self) -> str:
        return self._domain_id

    def principal(self, principal_id: str, *, default: Any = _MISSING) -> Any:
        record = self._principals.get(principal_id)
        if record is None:
            if default is not _MISSING:
                return default
            raise CoreValidationError(f"unknown principal: {principal_id}")
        return record

    def credential(self, credential_id: str) -> CredentialRecord:
        record = self._credentials.get(credential_id)
        if record is None:
            raise CoreValidationError(f"unknown credential: {credential_id}")
        return record

    def key(self, key_id: str) -> KeyRecord:
        record = self._keys.get(key_id)
        if record is None:
            raise CoreValidationError(f"unknown key: {key_id}")
        return record

    def grant(self, grant_id: str) -> AuthorizationGrantRecord:
        record = self._grants.get(grant_id)
        if record is None:
            raise CoreValidationError(f"unknown grant: {grant_id}")
        return record

    def mandate(self, mandate_id: str) -> MandateRecord:
        record = self._mandates.get(mandate_id)
        if record is None:
            raise CoreValidationError(f"unknown mandate: {mandate_id}")
        return record

    def authentication_event(self, authentication_id: str) -> AuthenticationEventRecord:
        record = self._authentications.get(authentication_id)
        if record is None:
            raise CoreValidationError(f"unknown authentication event: {authentication_id}")
        return record

    def principals(self) -> tuple[PrincipalRecord, ...]:
        return tuple(self._principals[key] for key in sorted(self._principals))

    def credentials(self) -> tuple[CredentialRecord, ...]:
        return tuple(self._credentials[key] for key in sorted(self._credentials))

    def keys(self) -> tuple[KeyRecord, ...]:
        return tuple(self._keys[key] for key in sorted(self._keys))

    def grants(self) -> tuple[AuthorizationGrantRecord, ...]:
        return tuple(self._grants[key] for key in sorted(self._grants))

    def mandates(self) -> tuple[MandateRecord, ...]:
        return tuple(self._mandates[key] for key in sorted(self._mandates))

    def authentication_events(self) -> tuple[AuthenticationEventRecord, ...]:
        return tuple(self._authentications[key] for key in sorted(self._authentications))

    # ------------------------------------------------------------------
    # Internal guards
    # ------------------------------------------------------------------

    def _envelope(
        self,
        *,
        object_id: str,
        object_type: str,
        state: str,
        issuer: str,
        source: str,
        recorded_at: str,
        correlation_id: str | None = None,
    ) -> ObjectEnvelope:
        return build_envelope(
            object_id=object_id,
            object_type=object_type,
            state=state,
            environment_id=self._environment_id,
            domain_id=self._domain_id,
            issuer=issuer,
            source=source,
            recorded_at=recorded_at,
            correlation_id=correlation_id,
        )

    def _require_operator(self, operator: object, as_of: str) -> PrincipalRecord:
        operator_id = require_identifier("operator", operator, "trust/principal/")
        record = self._principals.get(operator_id)
        if record is None:
            raise CoreValidationError(f"operator principal is unknown: {operator_id}")
        if record.state != PrincipalState.ACTIVE.value:
            raise CoreValidationError(
                f"operator principal {operator_id} is {record.state} and may not operate the registry"
            )
        return record

    def _require_active_principal(self, principal_id: object, as_of: str, role: str) -> PrincipalRecord:
        identifier = require_identifier(role, principal_id, "trust/principal/")
        record = self._principals.get(identifier)
        if record is None:
            raise CoreValidationError(f"{role} principal is unknown: {identifier}")
        if record.state != PrincipalState.ACTIVE.value:
            raise CoreValidationError(
                f"{role} principal {identifier} is {record.state} and must be ACTIVE"
            )
        return record

    def _require_new_id(self, collection: Mapping[str, Any], identifier: str, role: str) -> str:
        if identifier in collection:
            raise CoreValidationError(f"{role} already exists: {identifier}")
        return identifier

    # ------------------------------------------------------------------
    # Principal lifecycle (Create/Update/Suspend/Reinstate/Retire)
    # ------------------------------------------------------------------

    def create_principal(
        self,
        *,
        principal_id: str,
        display_name: str,
        attributes: Mapping[str, Any] | None = None,
        as_of: str,
        correlation_id: str | None = None,
    ) -> PrincipalRecord:
        """Genesis identity creation (self-standing; no operator principal yet)."""
        identifier = require_identifier("principal.principal_id", principal_id, "trust/principal/")
        self._require_new_id(self._principals, identifier, "principal")
        require_text("principal.display_name", display_name)
        require_timestamp("as_of", as_of)
        from ._validation import require_attributes

        normalized_attributes = require_attributes("principal.attributes", attributes)
        envelope = self._envelope(
            object_id=identifier,
            object_type="trust/principal/v1",
            state=PrincipalState.ACTIVE.value,
            issuer=identifier,
            source=GENESIS_SOURCE,
            recorded_at=as_of,
            correlation_id=correlation_id,
        )
        record = PrincipalRecord(
            envelope=envelope,
            principal_id=identifier,
            display_name=display_name,
            attributes=normalized_attributes,
        )
        self._principals[identifier] = record
        return record

    def update_principal(
        self,
        *,
        principal_id: str,
        display_name: str | None = None,
        attributes: Mapping[str, Any] | None = None,
        as_of: str,
        operator: str,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> PrincipalRecord:
        record = self.principal(principal_id)
        self._require_operator(operator, as_of)
        if record.state == PrincipalState.RETIRED.value:
            raise CoreValidationError("a RETIRED principal cannot be updated")
        if display_name is None and attributes is None:
            raise CoreValidationError("update_principal requires a display_name or attributes change")
        new_display_name = display_name if display_name is not None else record.display_name
        if attributes is None:
            new_attributes = record.attributes
        else:
            from ._validation import require_attributes

            new_attributes = require_attributes("principal.attributes", attributes)
        envelope = advance_envelope(
            record.envelope,
            issuer=operator,
            source=OPERATOR_SOURCE,
            recorded_at=as_of,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )
        updated = PrincipalRecord(
            envelope=envelope,
            principal_id=record.principal_id,
            display_name=new_display_name,
            attributes=new_attributes,
        )
        self._principals[record.principal_id] = updated
        return updated

    def _principal_transition(
        self,
        *,
        principal_id: str,
        as_of: str,
        operator: str,
        target: PrincipalState,
        allowed_from: tuple[str, ...],
        causation_id: str | None,
        correlation_id: str | None,
    ) -> PrincipalRecord:
        record = self.principal(principal_id)
        self._require_operator(operator, as_of)
        if record.state not in allowed_from:
            raise CoreValidationError(
                f"principal {principal_id} is {record.state}; transition to {target.value} "
                f"requires one of {list(allowed_from)}"
            )
        envelope = advance_envelope(
            record.envelope,
            state=target.value,
            issuer=operator,
            source=OPERATOR_SOURCE,
            recorded_at=as_of,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )
        updated = PrincipalRecord(
            envelope=envelope,
            principal_id=record.principal_id,
            display_name=record.display_name,
            attributes=record.attributes,
        )
        self._principals[record.principal_id] = updated
        return updated

    def suspend_principal(
        self,
        *,
        principal_id: str,
        as_of: str,
        operator: str,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> PrincipalRecord:
        return self._principal_transition(
            principal_id=principal_id,
            as_of=as_of,
            operator=operator,
            target=PrincipalState.SUSPENDED,
            allowed_from=(PrincipalState.ACTIVE.value,),
            causation_id=causation_id,
            correlation_id=correlation_id,
        )

    def reinstate_principal(
        self,
        *,
        principal_id: str,
        as_of: str,
        operator: str,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> PrincipalRecord:
        return self._principal_transition(
            principal_id=principal_id,
            as_of=as_of,
            operator=operator,
            target=PrincipalState.ACTIVE,
            allowed_from=(PrincipalState.SUSPENDED.value,),
            causation_id=causation_id,
            correlation_id=correlation_id,
        )

    def retire_principal(
        self,
        *,
        principal_id: str,
        as_of: str,
        operator: str,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> PrincipalRecord:
        record = self.principal(principal_id)
        self._require_operator(operator, as_of)
        if record.state == PrincipalState.RETIRED.value:
            raise CoreValidationError("a RETIRED principal is terminal")
        blockers: list[str] = []
        for credential in self._sorted(self._credentials):
            if credential.principal_id == principal_id and credential.state == CredentialState.ACTIVE.value:
                blockers.append(credential.credential_id)
        for key in self._sorted(self._keys):
            if key.owner_principal_id == principal_id and key.state == KeyState.ACTIVE.value:
                blockers.append(key.key_id)
        for grant in self._sorted(self._grants):
            if (
                principal_id in (grant.grantor_principal_id, grant.grantee_principal_id)
                and grant.state in (GrantState.ACTIVE.value, GrantState.SUSPENDED.value)
            ):
                blockers.append(grant.grant_id)
        for mandate in self._sorted(self._mandates):
            if (
                principal_id in (mandate.mandator_principal_id, mandate.mandatary_principal_id)
                and mandate.state
                in (MandateState.ACTIVE.value, MandateState.SUSPENDED.value)
            ):
                blockers.append(mandate.mandate_id)
        if blockers:
            raise CoreValidationError(
                f"principal {principal_id} has active dependents and cannot retire: {blockers}"
            )
        return self._principal_transition(
            principal_id=principal_id,
            as_of=as_of,
            operator=operator,
            target=PrincipalState.RETIRED,
            allowed_from=(PrincipalState.ACTIVE.value, PrincipalState.SUSPENDED.value),
            causation_id=causation_id,
            correlation_id=correlation_id,
        )

    @staticmethod
    def _sorted(collection: Mapping[str, Any]) -> list[Any]:
        return [collection[key] for key in sorted(collection)]

    # ------------------------------------------------------------------
    # Credential lifecycle (Issue/Rotate/Revoke)
    # ------------------------------------------------------------------

    def issue_credential(
        self,
        *,
        credential_id: str,
        principal_id: str,
        kind: str,
        secret: str | None = None,
        key_id: str | None = None,
        not_before: str,
        not_after: str,
        as_of: str,
        operator: str,
        correlation_id: str | None = None,
    ) -> CredentialRecord:
        identifier = require_identifier("credential.credential_id", credential_id, "trust/credential/")
        self._require_new_id(self._credentials, identifier, "credential")
        self._require_active_principal(principal_id, as_of, "credential principal")
        credential_kind = require_str_enum("credential.kind", kind, CredentialKind)
        require_timestamp("as_of", as_of)
        before, after = require_window("credential window", not_before, not_after)
        self._require_operator(operator, as_of)
        verifier_digest = None
        if credential_kind is CredentialKind.SECRET_DIGEST:
            if secret is None:
                raise CoreValidationError("SECRET_DIGEST credentials require a secret")
            require_text("secret", secret)
            verifier_digest = derive_credential_verifier(identifier, secret)
        else:
            key_record = self._require_bound_authentication_key(
                key_id=key_id,
                owner_principal_id=self.principal(principal_id).principal_id,
                as_of=as_of,
            )
            require_window_subset(
                "credential window", (before, after), (key_record.not_before, key_record.not_after)
            )
        envelope = self._envelope(
            object_id=identifier,
            object_type="trust/credential/v1",
            state=CredentialState.ACTIVE.value,
            issuer=operator,
            source=OPERATOR_SOURCE,
            recorded_at=as_of,
            correlation_id=correlation_id,
        )
        record = CredentialRecord(
            envelope=envelope,
            credential_id=identifier,
            principal_id=self.principal(principal_id).principal_id,
            kind=credential_kind,
            key_id=key_id if credential_kind is CredentialKind.KEY_PROOF else None,
            verifier_digest=verifier_digest,
            not_before=before,
            not_after=after,
        )
        self._credentials[identifier] = record
        return record

    def _require_bound_authentication_key(
        self, *, key_id: object, owner_principal_id: str, as_of: str
    ) -> KeyRecord:
        identifier = require_identifier("key_id", key_id, "trust/key/")
        record = self._keys.get(identifier)
        if record is None:
            raise CoreValidationError(f"credential key is unknown: {identifier}")
        if record.owner_principal_id != owner_principal_id:
            raise CoreValidationError(
                f"credential key {identifier} is owned by {record.owner_principal_id}, "
                f"not by {owner_principal_id}"
            )
        if record.purpose is not KeyPurpose.AUTHENTICATION:
            raise CoreValidationError(
                f"credential key {identifier} must have purpose AUTHENTICATION, found {record.purpose.value}"
            )
        if record.state != KeyState.ACTIVE.value:
            raise CoreValidationError(
                f"credential key {identifier} is {record.state} and must be ACTIVE"
            )
        if not window_contains(record.not_before, record.not_after, as_of):
            raise CoreValidationError(
                f"credential key {identifier} is not valid at the issue instant"
            )
        return record

    def rotate_credential(
        self,
        *,
        credential_id: str,
        successor_credential_id: str,
        secret: str | None = None,
        key_id: str | None = None,
        not_before: str,
        not_after: str,
        as_of: str,
        operator: str,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> CredentialRecord:
        current = self.credential(credential_id)
        self._require_operator(operator, as_of)
        if current.state != CredentialState.ACTIVE.value:
            raise CoreValidationError(
                f"credential {credential_id} is {current.state} and cannot be rotated"
            )
        successor_id = require_identifier(
            "credential.successor_credential_id", successor_credential_id, "trust/credential/"
        )
        self._require_new_id(self._credentials, successor_id, "credential")
        before, after = require_window("successor credential window", not_before, not_after)
        if not window_subset((before, after), (current.not_before, current.not_after)):
            raise CoreValidationError(
                "successor credential window must be within the current credential window"
            )
        verifier_digest = None
        successor_key_id = None
        if current.kind is CredentialKind.SECRET_DIGEST:
            if secret is None:
                raise CoreValidationError("SECRET_DIGEST successors require a secret")
            require_text("secret", secret)
            verifier_digest = derive_credential_verifier(successor_id, secret)
        else:
            key_record = self._require_bound_authentication_key(
                key_id=key_id, owner_principal_id=current.principal_id, as_of=as_of
            )
            successor_key_id = key_record.key_id
            require_window_subset(
                "successor credential window",
                (before, after),
                (key_record.not_before, key_record.not_after),
            )
        successor_envelope = self._envelope(
            object_id=successor_id,
            object_type="trust/credential/v1",
            state=CredentialState.ACTIVE.value,
            issuer=operator,
            source=OPERATOR_SOURCE,
            recorded_at=as_of,
            correlation_id=correlation_id,
        )
        successor = CredentialRecord(
            envelope=successor_envelope,
            credential_id=successor_id,
            principal_id=current.principal_id,
            kind=current.kind,
            key_id=successor_key_id,
            verifier_digest=verifier_digest,
            not_before=before,
            not_after=after,
            predecessor_credential_id=current.credential_id,
        )
        self._credentials[successor_id] = successor
        rotated_envelope = advance_envelope(
            current.envelope,
            state=CredentialState.ROTATED.value,
            issuer=operator,
            source=OPERATOR_SOURCE,
            recorded_at=as_of,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )
        rotated = CredentialRecord(
            envelope=rotated_envelope,
            credential_id=current.credential_id,
            principal_id=current.principal_id,
            kind=current.kind,
            key_id=current.key_id,
            verifier_digest=current.verifier_digest,
            not_before=current.not_before,
            not_after=current.not_after,
            successor_credential_id=successor_id,
            predecessor_credential_id=current.predecessor_credential_id,
        )
        self._credentials[current.credential_id] = rotated
        return successor

    def revoke_credential(
        self,
        *,
        credential_id: str,
        as_of: str,
        operator: str,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> CredentialRecord:
        current = self.credential(credential_id)
        self._require_operator(operator, as_of)
        if current.state == CredentialState.REVOKED.value:
            raise CoreValidationError("a REVOKED credential is terminal")
        envelope = advance_envelope(
            current.envelope,
            state=CredentialState.REVOKED.value,
            issuer=operator,
            source=OPERATOR_SOURCE,
            recorded_at=as_of,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )
        revoked = CredentialRecord(
            envelope=envelope,
            credential_id=current.credential_id,
            principal_id=current.principal_id,
            kind=current.kind,
            key_id=current.key_id,
            verifier_digest=current.verifier_digest,
            not_before=current.not_before,
            not_after=current.not_after,
            successor_credential_id=current.successor_credential_id,
            predecessor_credential_id=current.predecessor_credential_id,
        )
        self._credentials[current.credential_id] = revoked
        return revoked

    # ------------------------------------------------------------------
    # Key lifecycle (register/rotate/recover/revoke) with threshold guard
    # ------------------------------------------------------------------

    def register_key(
        self,
        *,
        key_id: str,
        owner_principal_id: str,
        purpose: str,
        public_material: str,
        secret_material: str,
        not_before: str,
        not_after: str,
        as_of: str,
        operator: str,
        threshold_policy: Any | None = None,
        recovery_key_id: str | None = None,
        correlation_id: str | None = None,
    ) -> KeyRecord:
        identifier = require_identifier("key.key_id", key_id, "trust/key/")
        self._require_new_id(self._keys, identifier, "key")
        owner = self._require_active_principal(owner_principal_id, as_of, "key owner")
        key_purpose = require_str_enum("key.purpose", purpose, KeyPurpose)
        require_text("key.public_material", public_material)
        require_text("key.secret_material", secret_material)
        before, after = require_window("key window", not_before, not_after)
        self._require_operator(operator, as_of)
        policy = threshold_policy
        if policy is not None and not isinstance(policy, ThresholdApproval.__mro__[0]):
            from .keys import ThresholdPolicy

            if not isinstance(policy, ThresholdPolicy):
                raise CoreValidationError("key.threshold_policy must be a ThresholdPolicy or None")
        if recovery_key_id is not None:
            recovery = self.key(recovery_key_id)
            if recovery.purpose is not KeyPurpose.RECOVERY:
                raise CoreValidationError(
                    f"recovery key {recovery_key_id} must have purpose RECOVERY"
                )
        verification_digest = derive_key_verification_digest(
            identifier, key_purpose, public_material, secret_material
        )
        envelope = self._envelope(
            object_id=identifier,
            object_type="trust/key/v1",
            state=KeyState.ACTIVE.value,
            issuer=operator,
            source=OPERATOR_SOURCE,
            recorded_at=as_of,
            correlation_id=correlation_id,
        )
        record = KeyRecord(
            envelope=envelope,
            key_id=identifier,
            owner_principal_id=owner.principal_id,
            purpose=key_purpose,
            public_material=public_material,
            verification_digest=verification_digest,
            not_before=before,
            not_after=after,
            threshold_policy=policy,
            recovery_key_id=recovery_key_id,
        )
        self._keys[identifier] = record
        return record

    def rotate_key(
        self,
        *,
        key_id: str,
        successor_key_id: str,
        successor_public_material: str,
        successor_secret_material: str,
        not_before: str,
        not_after: str,
        as_of: str,
        operator: str,
        threshold_approval: Any | None = None,
        recovery_key_id: str | None = None,
        recovery_secret: str | None = None,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> KeyRecord:
        current = self.key(key_id)
        self._require_operator(operator, as_of)
        if current.state == KeyState.REVOKED.value:
            raise CoreValidationError(f"key {key_id} is REVOKED and cannot be rotated")
        successor_id = require_identifier(
            "key.successor_key_id", successor_key_id, "trust/key/"
        )
        self._require_new_id(self._keys, successor_id, "key")
        before, after = require_window("successor key window", not_before, not_after)
        if not window_subset((before, after), (current.not_before, current.not_after)):
            raise CoreValidationError(
                "successor key window must be within the current key window"
            )
        require_text("successor_public_material", successor_public_material)
        require_text("successor_secret_material", successor_secret_material)
        require_timestamp("as_of", as_of)
        proposal_digest = key_rotation_proposal_digest(
            key_id=current.key_id,
            successor_key_id=successor_id,
            successor_public_material=successor_public_material,
            as_of=as_of,
        )
        if current.threshold_policy is not None:
            self._authorize_privileged_key_operation(
                current=current,
                proposal_digest=proposal_digest,
                as_of=as_of,
                threshold_approval=threshold_approval,
                recovery_key_id=recovery_key_id,
                recovery_secret=recovery_secret,
            )
        elif threshold_approval is not None:
            raise CoreValidationError(
                f"key {key_id} has no threshold policy; a threshold approval cannot authorize its rotation"
            )
        verification_digest = derive_key_verification_digest(
            successor_id, current.purpose, successor_public_material, successor_secret_material
        )
        successor_envelope = self._envelope(
            object_id=successor_id,
            object_type="trust/key/v1",
            state=KeyState.ACTIVE.value,
            issuer=operator,
            source=OPERATOR_SOURCE,
            recorded_at=as_of,
            correlation_id=correlation_id,
        )
        successor = KeyRecord(
            envelope=successor_envelope,
            key_id=successor_id,
            owner_principal_id=current.owner_principal_id,
            purpose=current.purpose,
            public_material=successor_public_material,
            verification_digest=verification_digest,
            not_before=before,
            not_after=after,
            predecessor_key_id=current.key_id,
            threshold_policy=current.threshold_policy,
            recovery_key_id=current.recovery_key_id,
        )
        self._keys[successor_id] = successor
        rotated_envelope = advance_envelope(
            current.envelope,
            state=KeyState.ROTATED.value,
            issuer=operator,
            source=OPERATOR_SOURCE,
            recorded_at=as_of,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )
        rotated = KeyRecord(
            envelope=rotated_envelope,
            key_id=current.key_id,
            owner_principal_id=current.owner_principal_id,
            purpose=current.purpose,
            public_material=current.public_material,
            verification_digest=current.verification_digest,
            not_before=current.not_before,
            not_after=current.not_after,
            successor_key_id=successor_id,
            predecessor_key_id=current.predecessor_key_id,
            threshold_policy=current.threshold_policy,
            recovery_key_id=current.recovery_key_id,
        )
        self._keys[current.key_id] = rotated
        return successor

    def revoke_key(
        self,
        *,
        key_id: str,
        as_of: str,
        operator: str,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> KeyRecord:
        current = self.key(key_id)
        self._require_operator(operator, as_of)
        if current.state == KeyState.REVOKED.value:
            raise CoreValidationError("a REVOKED key is terminal")
        envelope = advance_envelope(
            current.envelope,
            state=KeyState.REVOKED.value,
            issuer=operator,
            source=OPERATOR_SOURCE,
            recorded_at=as_of,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )
        revoked = KeyRecord(
            envelope=envelope,
            key_id=current.key_id,
            owner_principal_id=current.owner_principal_id,
            purpose=current.purpose,
            public_material=current.public_material,
            verification_digest=current.verification_digest,
            not_before=current.not_before,
            not_after=current.not_after,
            successor_key_id=current.successor_key_id,
            predecessor_key_id=current.predecessor_key_id,
            threshold_policy=current.threshold_policy,
            recovery_key_id=current.recovery_key_id,
        )
        self._keys[current.key_id] = revoked
        return revoked

    def _authorize_privileged_key_operation(
        self,
        *,
        current: KeyRecord,
        proposal_digest: str,
        as_of: str,
        threshold_approval: Any | None,
        recovery_key_id: str | None,
        recovery_secret: str | None,
    ) -> None:
        guard = current.threshold_policy
        assert guard is not None  # narrowed by caller
        if recovery_key_id is not None or recovery_secret is not None:
            if current.recovery_key_id is None:
                raise CoreValidationError(
                    f"key {current.key_id} has no bound recovery key; recovery cannot authorize rotation"
                )
            if recovery_key_id != current.recovery_key_id:
                raise CoreValidationError(
                    f"recovery key {recovery_key_id} is not the recovery key bound to {current.key_id}"
                )
            self._verify_recovery_proof(current.recovery_key_id, recovery_secret, as_of)
            return
        if threshold_approval is None:
            raise CoreValidationError(
                f"key {current.key_id} is threshold-guarded; its rotation requires a threshold "
                "approval or the bound recovery key"
            )
        if not isinstance(threshold_approval, ThresholdApproval):
            raise CoreValidationError("threshold_approval must be a ThresholdApproval")
        if threshold_approval.policy != guard:
            raise CoreValidationError(
                f"threshold approval policy does not match the guard policy of key {current.key_id}"
            )
        if threshold_approval.state is not ThresholdApprovalState.APPROVED:
            raise CoreValidationError(
                f"threshold approval is {threshold_approval.state.value}; only APPROVED "
                "approvals authorize the rotation"
            )
        for approval in threshold_approval.approvals:
            if approval.proposal_digest != proposal_digest:
                raise CoreValidationError(
                    "threshold approval is bound to a different proposal digest; "
                    "it cannot authorize this rotation"
                )
            if parse_timestamp("authentication.occurred_at", approval.authentication.occurred_at) > parse_timestamp("as_of", as_of):
                raise CoreValidationError(
                    "threshold approval authentication must not be newer than the operation instant"
                )

    def _verify_recovery_proof(
        self, recovery_key_id: str, recovery_secret: object, as_of: str
    ) -> None:
        record = self.key(recovery_key_id)
        if record.purpose is not KeyPurpose.RECOVERY:
            raise CoreValidationError(
                f"recovery key {recovery_key_id} must have purpose RECOVERY"
            )
        if record.state != KeyState.ACTIVE.value:
            raise CoreValidationError(
                f"recovery key {recovery_key_id} is {record.state} and must be ACTIVE"
            )
        if not window_contains(record.not_before, record.not_after, as_of):
            raise CoreValidationError(
                f"recovery key {recovery_key_id} is not valid at the operation instant"
            )
        if recovery_secret is None:
            raise CoreValidationError("a recovery proof requires the recovery key secret material")
        require_text("recovery_secret", recovery_secret)
        expected = derive_key_verification_digest(
            record.key_id, record.purpose, record.public_material, recovery_secret
        )
        if not _hmac.compare_digest(expected, record.verification_digest):
            raise CoreValidationError(
                f"recovery proof rejected for key {recovery_key_id}: verifier mismatch"
            )

    # ------------------------------------------------------------------
    # Authorization grants (Grant/Amend/RevokeAuthority + delegation)
    # ------------------------------------------------------------------

    def issue_root_grant(
        self,
        *,
        grant_id: str,
        authority_principal_id: str,
        grantee_principal_id: str,
        authority_class: str,
        scope_objects: Iterable[str] = (),
        scope_domains: Iterable[str] = (),
        not_before: str,
        not_after: str,
        delegation_depth: int,
        amount_limits: tuple = (),
        jurisdictions: Iterable[str] = (),
        as_of: str,
        operator: str,
        correlation_id: str | None = None,
    ) -> AuthorizationGrantRecord:
        """Explicit bootstrap of authority: a ROOT grant from an active authority principal."""
        identifier = require_identifier("grant.grant_id", grant_id, "trust/grant/")
        self._require_new_id(self._grants, identifier, "grant")
        authority = self._require_active_principal(authority_principal_id, as_of, "grant authority")
        grantee = self._require_active_principal(grantee_principal_id, as_of, "grant grantee")
        self._require_operator(operator, as_of)
        klass = validate_authority_class(authority_class)
        scope_objs = require_str_tuple("grant.scope_objects", tuple(scope_objects), distinct=True)
        scope_doms = require_str_tuple("grant.scope_domains", tuple(scope_domains), distinct=True)
        before, after = require_window("grant window", not_before, not_after)
        from ._validation import require_non_negative_int

        depth = require_non_negative_int("grant.delegation_depth", delegation_depth)
        limits = self._normalize_amount_limits(amount_limits)
        jurisdictions_tuple = require_str_tuple("grant.jurisdictions", tuple(jurisdictions), distinct=True)
        envelope = self._envelope(
            object_id=identifier,
            object_type="trust/grant/v1",
            state=GrantState.ACTIVE.value,
            issuer=operator,
            source="trust/authority",
            recorded_at=as_of,
            correlation_id=correlation_id,
        )
        record = AuthorizationGrantRecord(
            envelope=envelope,
            grant_id=identifier,
            grant_kind=GrantKind.ROOT,
            authority_class=klass,
            grantor_principal_id=authority.principal_id,
            grantee_principal_id=grantee.principal_id,
            scope_objects=scope_objs,
            scope_domains=scope_doms,
            not_before=before,
            not_after=after,
            delegation_depth=depth,
            amount_limits=limits,
            jurisdictions=jurisdictions_tuple,
        )
        self._grants[identifier] = record
        return record

    @staticmethod
    def _normalize_amount_limits(value: object) -> tuple:
        if not isinstance(value, tuple):
            raise CoreValidationError("grant.amount_limits must be a tuple of AmountBound values")
        for item in value:
            if not isinstance(item, AmountBound):
                raise CoreValidationError("grant.amount_limits must contain AmountBound values")
        if len({item.asset for item in value}) != len(value):
            raise CoreValidationError("amount limits contain duplicate asset bounds")
        return value

    def delegate_grant(
        self,
        *,
        grant_id: str,
        grantor_principal_id: str,
        grantee_principal_id: str,
        authority_class: str,
        scope_objects: Iterable[str] = (),
        scope_domains: Iterable[str] = (),
        not_before: str,
        not_after: str,
        delegation_depth: int,
        amount_limits: tuple = (),
        jurisdictions: Iterable[str] = (),
        parent_grant_id: str | None = None,
        as_of: str,
        operator: str,
        correlation_id: str | None = None,
    ) -> AuthorizationGrantRecord:
        """Bounded delegation from a currently valid covering parent grant."""
        identifier = require_identifier("grant.grant_id", grant_id, "trust/grant/")
        self._require_new_id(self._grants, identifier, "grant")
        grantor = self._require_active_principal(grantor_principal_id, as_of, "delegation grantor")
        grantee = self._require_active_principal(grantee_principal_id, as_of, "delegation grantee")
        if grantor.principal_id == grantee.principal_id:
            raise CoreValidationError(
                "delegate_grant cannot grant to the grantor itself; use issue_root_grant for bootstrap"
            )
        self._require_operator(operator, as_of)
        klass = validate_authority_class(authority_class)
        scope_objs = require_str_tuple("grant.scope_objects", tuple(scope_objects), distinct=True)
        scope_doms = require_str_tuple("grant.scope_domains", tuple(scope_domains), distinct=True)
        before, after = require_window("grant window", not_before, not_after)
        from ._validation import require_non_negative_int

        depth = require_non_negative_int("grant.delegation_depth", delegation_depth)
        limits = self._normalize_amount_limits(amount_limits)
        jurisdictions_tuple = require_str_tuple(
            "grant.jurisdictions", tuple(jurisdictions), distinct=True
        )
        parent = self._resolve_parent_grant(
            grantor_principal_id=grantor.principal_id,
            authority_class=klass,
            scope_objects=scope_objs,
            scope_domains=scope_doms,
            window=(before, after),
            delegation_depth=depth,
            amount_limits=limits,
            jurisdictions=jurisdictions_tuple,
            parent_grant_id=parent_grant_id,
            as_of=as_of,
        )
        self._require_delegation_bounded(
            grant_id=identifier,
            child_scope_objects=scope_objs,
            child_scope_domains=scope_doms,
            child_window=(before, after),
            child_depth=depth,
            child_limits=limits,
            child_jurisdictions=jurisdictions_tuple,
            parent=parent,
        )
        envelope = self._envelope(
            object_id=identifier,
            object_type="trust/grant/v1",
            state=GrantState.ACTIVE.value,
            issuer=operator,
            source="trust/authority",
            recorded_at=as_of,
            correlation_id=correlation_id,
        )
        record = AuthorizationGrantRecord(
            envelope=envelope,
            grant_id=identifier,
            grant_kind=GrantKind.DELEGATED,
            authority_class=klass,
            grantor_principal_id=grantor.principal_id,
            grantee_principal_id=grantee.principal_id,
            scope_objects=scope_objs,
            scope_domains=scope_doms,
            not_before=before,
            not_after=after,
            delegation_depth=depth,
            amount_limits=limits,
            jurisdictions=jurisdictions_tuple,
            parent_grant_id=parent.grant_id,
        )
        self._grants[identifier] = record
        return record

    def _resolve_parent_grant(
        self,
        *,
        grantor_principal_id: str,
        authority_class: Any,
        scope_objects: tuple[str, ...],
        scope_domains: tuple[str, ...],
        window: tuple[str, str],
        delegation_depth: int,
        amount_limits: tuple,
        jurisdictions: tuple[str, ...],
        parent_grant_id: str | None,
        as_of: str,
    ) -> AuthorizationGrantRecord:
        candidates = [
            grant
            for grant in self._sorted(self._grants)
            if grant.grantee_principal_id == grantor_principal_id
            and grant.authority_class == authority_class
            and grant.state == GrantState.ACTIVE.value
            and grant.envelope.environment_id == self._environment_id
        ]
        if parent_grant_id is not None:
            require_identifier("grant.parent_grant_id", parent_grant_id, "trust/grant/")
            parent = next((grant for grant in candidates if grant.grant_id == parent_grant_id), None)
            if parent is None:
                raise CoreValidationError(
                    f"parent grant {parent_grant_id} is not an ACTIVE covering grant of {grantor_principal_id}"
                )
            if not window_contains(parent.not_before, parent.not_after, as_of):
                raise CoreValidationError(
                    f"parent grant {parent_grant_id} is not valid at the delegation instant"
                )
            return parent
        candidates.sort(key=lambda grant: (-grant.delegation_depth, grant.grant_id))
        for parent in candidates:
            try:
                self._require_delegation_bounded(
                    grant_id="(candidate selection)",
                    child_scope_objects=scope_objects,
                    child_scope_domains=scope_domains,
                    child_window=window,
                    child_depth=delegation_depth,
                    child_limits=amount_limits,
                    child_jurisdictions=jurisdictions,
                    parent=parent,
                )
                if not window_contains(parent.not_before, parent.not_after, as_of):
                    continue
                return parent
            except CoreValidationError:
                continue
        raise CoreValidationError(
            f"no ACTIVE covering grant held by {grantor_principal_id} for the requested "
            f"delegation of {authority_class.value}"
        )

    def _require_delegation_bounded(
        self,
        *,
        grant_id: str,
        child_scope_objects: tuple[str, ...],
        child_scope_domains: tuple[str, ...],
        child_window: tuple[str, str],
        child_depth: int,
        child_limits: tuple,
        child_jurisdictions: tuple[str, ...],
        parent: AuthorizationGrantRecord,
    ) -> None:
        if not scope_subset(
            child_scope_objects, child_scope_domains, parent.scope_objects, parent.scope_domains
        ):
            raise CoreValidationError(
                f"delegation {grant_id} widens the parent grant scope"
            )
        if not window_subset(child_window, (parent.not_before, parent.not_after)):
            raise CoreValidationError(
                f"delegation {grant_id} widens the parent grant validity window"
            )
        if parent.delegation_depth < 1 or child_depth > parent.delegation_depth - 1:
            raise CoreValidationError(
                f"delegation {grant_id} exceeds the parent delegation depth budget "
                f"(parent depth {parent.delegation_depth})"
            )
        amount_limits_bounded_by(f"delegation {grant_id}", child_limits, parent.amount_limits)
        if not jurisdictions_subset(child_jurisdictions, parent.jurisdictions):
            raise CoreValidationError(
                f"delegation {grant_id} widens the parent grant jurisdictions"
            )

    def _grant_transition(
        self,
        *,
        grant_id: str,
        as_of: str,
        operator: str,
        target: GrantState,
        allowed_from: tuple[str, ...],
        causation_id: str | None,
        correlation_id: str | None,
    ) -> AuthorizationGrantRecord:
        current = self.grant(grant_id)
        self._require_operator(operator, as_of)
        if current.state not in allowed_from:
            raise CoreValidationError(
                f"grant {grant_id} is {current.state}; transition to {target.value} "
                f"requires one of {list(allowed_from)}"
            )
        envelope = advance_envelope(
            current.envelope,
            state=target.value,
            issuer=operator,
            source=OPERATOR_SOURCE,
            recorded_at=as_of,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )
        updated = self._rebuild_grant(current, envelope)
        self._grants[current.grant_id] = updated
        return updated

    @staticmethod
    def _rebuild_grant(
        current: AuthorizationGrantRecord, envelope: ObjectEnvelope, **changes: Any
    ) -> AuthorizationGrantRecord:
        fields = dict(
            grant_id=current.grant_id,
            grant_kind=current.grant_kind,
            authority_class=current.authority_class,
            grantor_principal_id=current.grantor_principal_id,
            grantee_principal_id=current.grantee_principal_id,
            scope_objects=current.scope_objects,
            scope_domains=current.scope_domains,
            not_before=current.not_before,
            not_after=current.not_after,
            delegation_depth=current.delegation_depth,
            amount_limits=current.amount_limits,
            jurisdictions=current.jurisdictions,
            parent_grant_id=current.parent_grant_id,
        )
        fields.update(changes)
        return AuthorizationGrantRecord(envelope=envelope, **fields)

    def suspend_grant(
        self,
        *,
        grant_id: str,
        as_of: str,
        operator: str,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> AuthorizationGrantRecord:
        return self._grant_transition(
            grant_id=grant_id,
            as_of=as_of,
            operator=operator,
            target=GrantState.SUSPENDED,
            allowed_from=(GrantState.ACTIVE.value,),
            causation_id=causation_id,
            correlation_id=correlation_id,
        )

    def resume_grant(
        self,
        *,
        grant_id: str,
        as_of: str,
        operator: str,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> AuthorizationGrantRecord:
        return self._grant_transition(
            grant_id=grant_id,
            as_of=as_of,
            operator=operator,
            target=GrantState.ACTIVE,
            allowed_from=(GrantState.SUSPENDED.value,),
            causation_id=causation_id,
            correlation_id=correlation_id,
        )

    def revoke_grant(
        self,
        *,
        grant_id: str,
        as_of: str,
        operator: str,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> AuthorizationGrantRecord:
        """Revoke a grant. Effective immediately for the whole descendant chain."""
        return self._grant_transition(
            grant_id=grant_id,
            as_of=as_of,
            operator=operator,
            target=GrantState.REVOKED,
            allowed_from=(GrantState.ACTIVE.value, GrantState.SUSPENDED.value),
            causation_id=causation_id,
            correlation_id=correlation_id,
        )

    def amend_grant(
        self,
        *,
        grant_id: str,
        scope_objects: tuple[str, ...] | None = None,
        scope_domains: tuple[str, ...] | None = None,
        not_before: str | None = None,
        not_after: str | None = None,
        delegation_depth: int | None = None,
        amount_limits: tuple | None = None,
        jurisdictions: tuple[str, ...] | None = None,
        as_of: str,
        operator: str,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> AuthorizationGrantRecord:
        """Amend a grant; amendments may only tighten (scope, window, depth, limits, jurisdictions)."""
        current = self.grant(grant_id)
        self._require_operator(operator, as_of)
        if current.state not in (GrantState.ACTIVE.value, GrantState.SUSPENDED.value):
            raise CoreValidationError(
                f"grant {grant_id} is {current.state} and cannot be amended"
            )
        if all(
            value is None
            for value in (
                scope_objects,
                scope_domains,
                not_before,
                not_after,
                delegation_depth,
                amount_limits,
                jurisdictions,
            )
        ):
            raise CoreValidationError("amend_grant requires at least one amended field")
        new_scope_objects = (
            require_str_tuple("grant.scope_objects", scope_objects, distinct=True)
            if scope_objects is not None
            else current.scope_objects
        )
        new_scope_domains = (
            require_str_tuple("grant.scope_domains", scope_domains, distinct=True)
            if scope_domains is not None
            else current.scope_domains
        )
        new_not_before = not_before if not_before is not None else current.not_before
        new_not_after = not_after if not_after is not None else current.not_after
        before, after = require_window("amended grant window", new_not_before, new_not_after)
        from ._validation import require_non_negative_int

        new_depth = (
            require_non_negative_int("grant.delegation_depth", delegation_depth)
            if delegation_depth is not None
            else current.delegation_depth
        )
        new_limits = (
            self._normalize_amount_limits(amount_limits)
            if amount_limits is not None
            else current.amount_limits
        )
        new_jurisdictions = (
            require_str_tuple("grant.jurisdictions", jurisdictions, distinct=True)
            if jurisdictions is not None
            else current.jurisdictions
        )
        if not scope_subset(
            new_scope_objects, new_scope_domains, current.scope_objects, current.scope_domains
        ):
            raise CoreValidationError(f"amendment of {grant_id} widens the grant scope")
        if not window_subset((before, after), (current.not_before, current.not_after)):
            raise CoreValidationError(f"amendment of {grant_id} widens the grant window")
        if new_depth > current.delegation_depth:
            raise CoreValidationError(f"amendment of {grant_id} widens the delegation depth")
        amount_limits_bounded_by(f"amendment of {grant_id}", new_limits, current.amount_limits)
        if not jurisdictions_subset(new_jurisdictions, current.jurisdictions):
            raise CoreValidationError(f"amendment of {grant_id} widens the grant jurisdictions")
        envelope = advance_envelope(
            current.envelope,
            issuer=operator,
            source=OPERATOR_SOURCE,
            recorded_at=as_of,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )
        updated = self._rebuild_grant(
            current,
            envelope,
            scope_objects=new_scope_objects,
            scope_domains=new_scope_domains,
            not_before=before,
            not_after=after,
            delegation_depth=new_depth,
            amount_limits=new_limits,
            jurisdictions=new_jurisdictions,
        )
        self._grants[current.grant_id] = updated
        return updated

    # ------------------------------------------------------------------
    # Mandates (Create/Activate/Suspend/Resume/Amend/Revoke)
    # ------------------------------------------------------------------

    def create_mandate(
        self,
        *,
        mandate_id: str,
        mandator_principal_id: str,
        mandatary_principal_id: str,
        purpose: str,
        scope_objects: Iterable[str] = (),
        scope_domains: Iterable[str] = (),
        not_before: str,
        not_after: str,
        amount_limits: tuple = (),
        jurisdictions: Iterable[str] = (),
        as_of: str,
        operator: str,
        correlation_id: str | None = None,
    ) -> MandateRecord:
        identifier = require_identifier("mandate.mandate_id", mandate_id, "trust/mandate/")
        self._require_new_id(self._mandates, identifier, "mandate")
        mandator = self._require_active_principal(mandator_principal_id, as_of, "mandate mandator")
        mandatary = self._require_active_principal(mandatary_principal_id, as_of, "mandate mandatary")
        self._require_operator(operator, as_of)
        require_text("mandate.purpose", purpose)
        scope_objs = require_str_tuple("mandate.scope_objects", tuple(scope_objects), distinct=True)
        scope_doms = require_str_tuple("mandate.scope_domains", tuple(scope_domains), distinct=True)
        before, after = require_window("mandate window", not_before, not_after)
        limits = self._normalize_amount_limits(amount_limits)
        jurisdictions_tuple = require_str_tuple(
            "mandate.jurisdictions", tuple(jurisdictions), distinct=True
        )
        envelope = self._envelope(
            object_id=identifier,
            object_type="trust/mandate/v1",
            state=MandateState.CREATED.value,
            issuer=operator,
            source=OPERATOR_SOURCE,
            recorded_at=as_of,
            correlation_id=correlation_id,
        )
        record = MandateRecord(
            envelope=envelope,
            mandate_id=identifier,
            mandator_principal_id=mandator.principal_id,
            mandatary_principal_id=mandatary.principal_id,
            purpose=purpose,
            scope_objects=scope_objs,
            scope_domains=scope_doms,
            not_before=before,
            not_after=after,
            amount_limits=limits,
            jurisdictions=jurisdictions_tuple,
        )
        self._mandates[identifier] = record
        return record

    def _mandate_transition(
        self,
        *,
        mandate_id: str,
        as_of: str,
        operator: str,
        target: MandateState,
        allowed_from: tuple[str, ...],
        causation_id: str | None,
        correlation_id: str | None,
    ) -> MandateRecord:
        current = self.mandate(mandate_id)
        self._require_operator(operator, as_of)
        if current.state not in allowed_from:
            raise CoreValidationError(
                f"mandate {mandate_id} is {current.state}; transition to {target.value} "
                f"requires one of {list(allowed_from)}"
            )
        envelope = advance_envelope(
            current.envelope,
            state=target.value,
            issuer=operator,
            source=OPERATOR_SOURCE,
            recorded_at=as_of,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )
        updated = MandateRecord(
            envelope=envelope,
            mandate_id=current.mandate_id,
            mandator_principal_id=current.mandator_principal_id,
            mandatary_principal_id=current.mandatary_principal_id,
            purpose=current.purpose,
            scope_objects=current.scope_objects,
            scope_domains=current.scope_domains,
            not_before=current.not_before,
            not_after=current.not_after,
            amount_limits=current.amount_limits,
            jurisdictions=current.jurisdictions,
        )
        self._mandates[current.mandate_id] = updated
        return updated

    def activate_mandate(
        self, *, mandate_id: str, as_of: str, operator: str, causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> MandateRecord:
        return self._mandate_transition(
            mandate_id=mandate_id,
            as_of=as_of,
            operator=operator,
            target=MandateState.ACTIVE,
            allowed_from=(MandateState.CREATED.value,),
            causation_id=causation_id,
            correlation_id=correlation_id,
        )

    def suspend_mandate(
        self, *, mandate_id: str, as_of: str, operator: str, causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> MandateRecord:
        return self._mandate_transition(
            mandate_id=mandate_id,
            as_of=as_of,
            operator=operator,
            target=MandateState.SUSPENDED,
            allowed_from=(MandateState.ACTIVE.value,),
            causation_id=causation_id,
            correlation_id=correlation_id,
        )

    def resume_mandate(
        self, *, mandate_id: str, as_of: str, operator: str, causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> MandateRecord:
        return self._mandate_transition(
            mandate_id=mandate_id,
            as_of=as_of,
            operator=operator,
            target=MandateState.ACTIVE,
            allowed_from=(MandateState.SUSPENDED.value,),
            causation_id=causation_id,
            correlation_id=correlation_id,
        )

    def revoke_mandate(
        self, *, mandate_id: str, as_of: str, operator: str, causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> MandateRecord:
        return self._mandate_transition(
            mandate_id=mandate_id,
            as_of=as_of,
            operator=operator,
            target=MandateState.REVOKED,
            allowed_from=(
                MandateState.CREATED.value,
                MandateState.ACTIVE.value,
                MandateState.SUSPENDED.value,
            ),
            causation_id=causation_id,
            correlation_id=correlation_id,
        )

    def amend_mandate(
        self,
        *,
        mandate_id: str,
        scope_objects: tuple[str, ...] | None = None,
        scope_domains: tuple[str, ...] | None = None,
        not_before: str | None = None,
        not_after: str | None = None,
        amount_limits: tuple | None = None,
        jurisdictions: tuple[str, ...] | None = None,
        as_of: str,
        operator: str,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> MandateRecord:
        current = self.mandate(mandate_id)
        self._require_operator(operator, as_of)
        if current.state not in (MandateState.ACTIVE.value, MandateState.SUSPENDED.value):
            raise CoreValidationError(
                f"mandate {mandate_id} is {current.state} and cannot be amended"
            )
        if all(
            value is None
            for value in (scope_objects, scope_domains, not_before, not_after, amount_limits, jurisdictions)
        ):
            raise CoreValidationError("amend_mandate requires at least one amended field")
        new_scope_objects = (
            require_str_tuple("mandate.scope_objects", scope_objects, distinct=True)
            if scope_objects is not None
            else current.scope_objects
        )
        new_scope_domains = (
            require_str_tuple("mandate.scope_domains", scope_domains, distinct=True)
            if scope_domains is not None
            else current.scope_domains
        )
        new_not_before = not_before if not_before is not None else current.not_before
        new_not_after = not_after if not_after is not None else current.not_after
        before, after = require_window("amended mandate window", new_not_before, new_not_after)
        new_limits = (
            self._normalize_amount_limits(amount_limits)
            if amount_limits is not None
            else current.amount_limits
        )
        new_jurisdictions = (
            require_str_tuple("mandate.jurisdictions", jurisdictions, distinct=True)
            if jurisdictions is not None
            else current.jurisdictions
        )
        if not scope_subset(
            new_scope_objects, new_scope_domains, current.scope_objects, current.scope_domains
        ):
            raise CoreValidationError(f"amendment of {mandate_id} widens the mandate scope")
        if not window_subset((before, after), (current.not_before, current.not_after)):
            raise CoreValidationError(f"amendment of {mandate_id} widens the mandate window")
        amount_limits_bounded_by(f"amendment of {mandate_id}", new_limits, current.amount_limits)
        if not jurisdictions_subset(new_jurisdictions, current.jurisdictions):
            raise CoreValidationError(f"amendment of {mandate_id} widens the mandate jurisdictions")
        envelope = advance_envelope(
            current.envelope,
            issuer=operator,
            source=OPERATOR_SOURCE,
            recorded_at=as_of,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )
        updated = MandateRecord(
            envelope=envelope,
            mandate_id=current.mandate_id,
            mandator_principal_id=current.mandator_principal_id,
            mandatary_principal_id=current.mandatary_principal_id,
            purpose=current.purpose,
            scope_objects=new_scope_objects,
            scope_domains=new_scope_domains,
            not_before=before,
            not_after=after,
            amount_limits=new_limits,
            jurisdictions=new_jurisdictions,
        )
        self._mandates[current.mandate_id] = updated
        return updated

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def authenticate(
        self,
        *,
        principal_id: str,
        credential_id: str,
        secret: str,
        nonce: str,
        as_of: str,
        correlation_id: str | None = None,
    ) -> AuthenticationEventRecord:
        """Authenticate a principal via a credential (proof of control).

        Unknown principals/credentials fail closed with ``CoreValidationError``.
        Known-but-unusable states (suspended principal, revoked/rotated/
        expired/not-yet-valid credential or key) and wrong secrets record
        explicit FAILURE events with a closed reason vocabulary.
        """
        principal = self._principals.get(
            require_identifier("principal_id", principal_id, "trust/principal/")
        )
        if principal is None:
            raise CoreValidationError(f"unknown principal: {principal_id}")
        credential = self._credentials.get(
            require_identifier("credential_id", credential_id, "trust/credential/")
        )
        if credential is None:
            raise CoreValidationError(f"unknown credential: {credential_id}")
        if credential.principal_id != principal.principal_id:
            raise CoreValidationError(
                f"credential {credential.credential_id} is not issued to principal {principal.principal_id}"
            )
        require_text("secret", secret)
        require_text("nonce", nonce)
        require_timestamp("as_of", as_of)
        failure: AuthenticationFailureReason | None = None
        if principal.state == PrincipalState.RETIRED.value:
            raise CoreValidationError(
                f"principal {principal.principal_id} is RETIRED and cannot authenticate"
            )
        if principal.state == PrincipalState.SUSPENDED.value:
            failure = AuthenticationFailureReason.PRINCIPAL_SUSPENDED
        elif credential.state == CredentialState.REVOKED.value:
            failure = AuthenticationFailureReason.CREDENTIAL_REVOKED
        elif credential.state == CredentialState.ROTATED.value:
            failure = AuthenticationFailureReason.CREDENTIAL_ROTATED
        elif parse_timestamp("as_of", as_of) < parse_timestamp(
            "credential.not_before", credential.not_before
        ):
            failure = AuthenticationFailureReason.CREDENTIAL_NOT_YET_VALID
        elif parse_timestamp("as_of", as_of) >= parse_timestamp(
            "credential.not_after", credential.not_after
        ):
            failure = AuthenticationFailureReason.CREDENTIAL_EXPIRED
        else:
            failure = self._verify_credential_proof(credential, secret, as_of)
        outcome = (
            AuthenticationOutcome.SUCCESS if failure is None else AuthenticationOutcome.FAILURE
        )
        authentication_id = derive_authentication_id(
            principal.principal_id, credential.credential_id, nonce, as_of
        )
        envelope = self._envelope(
            object_id=authentication_id,
            object_type="trust/authentication/v1",
            state=outcome.value,
            issuer=AUTHENTICATION_SERVICE_ISSUER,
            source="trust/authentication",
            recorded_at=as_of,
            correlation_id=correlation_id,
        )
        record = AuthenticationEventRecord(
            envelope=envelope,
            authentication_id=authentication_id,
            principal_id=principal.principal_id,
            credential_id=credential.credential_id,
            credential_kind=credential.kind,
            nonce=nonce,
            outcome=outcome,
            failure_reason=failure,
            occurred_at=as_of,
        )
        existing = self._authentications.get(authentication_id)
        if existing is not None:
            if existing == record:
                return existing
            raise CoreValidationError(
                f"authentication nonce collision for {authentication_id}; "
                "the nonce must be unique per distinct attempt"
            )
        self._authentications[authentication_id] = record
        return record

    def _verify_credential_proof(
        self, credential: CredentialRecord, secret: str, as_of: str
    ) -> AuthenticationFailureReason | None:
        if credential.kind is CredentialKind.SECRET_DIGEST:
            expected = derive_credential_verifier(credential.credential_id, secret)
            if not _hmac.compare_digest(expected, credential.verifier_digest):
                return AuthenticationFailureReason.VERIFIER_MISMATCH
            return None
        key = self._keys.get(credential.key_id)
        if key is None:
            raise CoreValidationError(
                f"credential {credential.credential_id} references unknown key {credential.key_id}"
            )
        if key.purpose is not KeyPurpose.AUTHENTICATION:
            raise CoreValidationError(
                f"key {key.key_id} must have purpose AUTHENTICATION for KEY_PROOF credentials"
            )
        # A KEY_PROOF presentation identifies the key in the credential's
        # rotation chain by its verification digest: the bound key first,
        # then its registered successors. The failure reason reflects the
        # state of the key the presented proof actually belongs to, so a
        # stale pre-rotation secret reports KEY_ROTATED while a revoked
        # successor's secret reports KEY_REVOKED.
        chain_key = key
        matched = False
        visited: set[str] = set()
        while True:
            if chain_key.key_id in visited:
                raise CoreValidationError(
                    f"key rotation chain for {credential.key_id} contains a cycle at "
                    f"{chain_key.key_id}"
                )
            visited.add(chain_key.key_id)
            expected = derive_key_verification_digest(
                chain_key.key_id, chain_key.purpose, chain_key.public_material, secret
            )
            if _hmac.compare_digest(expected, chain_key.verification_digest):
                matched = True
                break
            if chain_key.successor_key_id is None:
                break
            successor = self._keys.get(chain_key.successor_key_id)
            if successor is None:
                raise CoreValidationError(
                    f"key {chain_key.key_id} references unknown successor "
                    f"{chain_key.successor_key_id}"
                )
            if successor.purpose is not KeyPurpose.AUTHENTICATION:
                raise CoreValidationError(
                    f"key {successor.key_id} must have purpose AUTHENTICATION for KEY_PROOF "
                    "credentials"
                )
            chain_key = successor
        if not matched:
            return AuthenticationFailureReason.VERIFIER_MISMATCH
        if chain_key.state == KeyState.REVOKED.value:
            return AuthenticationFailureReason.KEY_REVOKED
        if chain_key.state == KeyState.ROTATED.value:
            return AuthenticationFailureReason.KEY_ROTATED
        if parse_timestamp("as_of", as_of) < parse_timestamp("key.not_before", chain_key.not_before):
            return AuthenticationFailureReason.KEY_NOT_YET_VALID
        if parse_timestamp("as_of", as_of) >= parse_timestamp("key.not_after", chain_key.not_after):
            return AuthenticationFailureReason.KEY_EXPIRED
        return None

    # ------------------------------------------------------------------
    # Authorization decision
    # ------------------------------------------------------------------

    def decide(self, request: AuthorizationRequest) -> AuthorizationDecision:
        """Deterministic, default-deny authorization decision over live state."""
        if not isinstance(request, AuthorizationRequest):
            raise CoreValidationError("decide requires an AuthorizationRequest")
        reasons: list[AuthorizationDenialReason] = []
        if request.environment_id != self._environment_id:
            reasons.append(AuthorizationDenialReason.ENVIRONMENT_MISMATCH)
        principal = self._principals.get(request.principal_id)
        if principal is None:
            reasons.append(AuthorizationDenialReason.UNKNOWN_PRINCIPAL)
        elif principal.state != PrincipalState.ACTIVE.value:
            reasons.append(AuthorizationDenialReason.PRINCIPAL_INACTIVE)
        authentication = request.authentication
        authentication_id: str | None = None
        if authentication is None:
            reasons.append(AuthorizationDenialReason.AUTHENTICATION_REQUIRED)
        else:
            authentication_id = authentication.authentication_id
            if not self._authentication_valid(authentication, request):
                reasons.append(AuthorizationDenialReason.AUTHENTICATION_INVALID)
        matched_mandate_id = None
        if request.on_behalf_of is not None:
            mandate_reasons, matched_mandate_id = self._evaluate_mandate(request)
            reasons.extend(mandate_reasons)
        chains: list[tuple[str, ...]] = []
        for authority_class in request.authority_classes:
            class_reasons, chain = self._evaluate_authority_class(authority_class, request)
            if chain is None:
                reasons.extend(class_reasons)
            else:
                chains.append(chain)
        if reasons:
            # Multiple failure paths (e.g. several authority classes) can emit
            # the same denial reason; the decision vocabulary is a set, so
            # collapse deterministically while preserving first-seen order.
            return AuthorizationDecision(
                decision=AuthorizationOutcome.DENY,
                reasons=tuple(dict.fromkeys(reasons)),
                principal_id=request.principal_id,
                as_of=request.as_of,
                environment_id=request.environment_id,
                authentication_id=authentication_id,
                matched_grant_chains=(),
                matched_mandate_id=None,
                request_digest=request.request_digest,
            )
        return AuthorizationDecision(
            decision=AuthorizationOutcome.ALLOW,
            reasons=(),
            principal_id=request.principal_id,
            as_of=request.as_of,
            environment_id=request.environment_id,
            authentication_id=authentication_id,
            matched_grant_chains=tuple(chains),
            matched_mandate_id=matched_mandate_id,
            request_digest=request.request_digest,
        )

    def _authentication_valid(
        self, authentication: AuthenticationEventRecord, request: AuthorizationRequest
    ) -> bool:
        if authentication.outcome is not AuthenticationOutcome.SUCCESS:
            return False
        if authentication.principal_id != request.principal_id:
            return False
        if authentication.envelope.environment_id != request.environment_id:
            return False
        if parse_timestamp("authentication.occurred_at", authentication.occurred_at) > parse_timestamp(
            "request.as_of", request.as_of
        ):
            return False
        return True

    def _evaluate_mandate(
        self, request: AuthorizationRequest
    ) -> tuple[list[AuthorizationDenialReason], str | None]:
        candidates = [
            mandate
            for mandate in self._sorted(self._mandates)
            if mandate.mandator_principal_id == request.on_behalf_of
            and mandate.mandatary_principal_id == request.principal_id
        ]
        if not candidates:
            return [AuthorizationDenialReason.MANDATE_REQUIRED], None
        reasons: list[AuthorizationDenialReason] = []
        for mandate in candidates:
            mandate_reasons = self._mandate_reasons(mandate, request)
            if not mandate_reasons:
                return [], mandate.mandate_id
            reasons.extend(mandate_reasons)
        return reasons, None

    def _mandate_reasons(
        self, mandate: MandateRecord, request: AuthorizationRequest
    ) -> list[AuthorizationDenialReason]:
        reasons: list[AuthorizationDenialReason] = []
        if mandate.state != MandateState.ACTIVE.value:
            reasons.append(AuthorizationDenialReason.MANDATE_INACTIVE)
        if not window_contains(mandate.not_before, mandate.not_after, request.as_of):
            reasons.append(AuthorizationDenialReason.MANDATE_WINDOW_INVALID)
        if mandate.envelope.environment_id != request.environment_id:
            reasons.append(AuthorizationDenialReason.MANDATE_ENVIRONMENT_MISMATCH)
        if not self._scope_covers(mandate.scope_objects, mandate.scope_domains, request):
            reasons.append(AuthorizationDenialReason.MANDATE_SCOPE_NOT_COVERED)
        amount_reason = self._amount_reason(mandate.amount_limits, request)
        if amount_reason is not None:
            reasons.append(AuthorizationDenialReason.MANDATE_AMOUNT_EXCEEDS_LIMIT)
        if request.jurisdiction is not None and mandate.jurisdictions:
            if request.jurisdiction not in mandate.jurisdictions:
                reasons.append(AuthorizationDenialReason.MANDATE_JURISDICTION_NOT_COVERED)
        return reasons

    def _evaluate_authority_class(
        self, authority_class: Any, request: AuthorizationRequest
    ) -> tuple[list[AuthorizationDenialReason], tuple[str, ...] | None]:
        candidates = [
            grant
            for grant in self._sorted(self._grants)
            if grant.grantee_principal_id == request.principal_id
            and grant.authority_class == authority_class
        ]
        if not candidates:
            return [AuthorizationDenialReason.AUTHORITY_CLASS_NOT_GRANTED], None
        reasons: list[AuthorizationDenialReason] = []
        for grant in candidates:
            chain, chain_reasons = self._walk_grant_chain(grant, request)
            if chain is not None:
                return [], chain
            reasons.extend(chain_reasons)
        return reasons, None

    def _walk_grant_chain(
        self, leaf: AuthorizationGrantRecord, request: AuthorizationRequest
    ) -> tuple[tuple[str, ...] | None, list[AuthorizationDenialReason]]:
        chain_ids: list[str] = []
        visited: set[str] = set()
        reasons: list[AuthorizationDenialReason] = []
        current = leaf
        while True:
            if current.grant_id in visited:
                return None, [AuthorizationDenialReason.DELEGATION_CHAIN_INVALID]
            visited.add(current.grant_id)
            reasons.extend(self._grant_link_reasons(current, request))
            chain_ids.append(current.grant_id)
            if current.grant_kind is GrantKind.ROOT:
                break
            parent = self._grants.get(current.parent_grant_id)
            if parent is None:
                return None, [AuthorizationDenialReason.DELEGATION_CHAIN_INVALID]
            if parent.grantee_principal_id != current.grantor_principal_id:
                return None, [AuthorizationDenialReason.DELEGATION_CHAIN_INVALID]
            if parent.authority_class != current.authority_class:
                return None, [AuthorizationDenialReason.DELEGATION_CHAIN_INVALID]
            if parent.envelope.environment_id != current.envelope.environment_id:
                return None, [AuthorizationDenialReason.DELEGATION_CHAIN_INVALID]
            current = parent
        if reasons:
            return None, reasons
        return tuple(reversed(chain_ids)), []

    def _grant_link_reasons(
        self, grant: AuthorizationGrantRecord, request: AuthorizationRequest
    ) -> list[AuthorizationDenialReason]:
        reasons: list[AuthorizationDenialReason] = []
        if grant.state != GrantState.ACTIVE.value:
            reasons.append(AuthorizationDenialReason.GRANT_INACTIVE)
        if not window_contains(grant.not_before, grant.not_after, request.as_of):
            reasons.append(AuthorizationDenialReason.GRANT_WINDOW_INVALID)
        if grant.envelope.environment_id != request.environment_id:
            reasons.append(AuthorizationDenialReason.ENVIRONMENT_MISMATCH)
        if not self._scope_covers(grant.scope_objects, grant.scope_domains, request):
            reasons.append(AuthorizationDenialReason.SCOPE_NOT_COVERED)
        if self._amount_reason(grant.amount_limits, request) is not None:
            reasons.append(AuthorizationDenialReason.AMOUNT_EXCEEDS_LIMIT)
        if request.jurisdiction is not None and grant.jurisdictions:
            if request.jurisdiction not in grant.jurisdictions:
                reasons.append(AuthorizationDenialReason.JURISDICTION_NOT_COVERED)
        return reasons

    @staticmethod
    def _scope_covers(
        scope_objects: tuple[str, ...], scope_domains: tuple[str, ...], request: AuthorizationRequest
    ) -> bool:
        if request.domain_id in scope_domains:
            return True
        return request.object_ref is not None and request.object_ref in scope_objects

    @staticmethod
    def _amount_reason(amount_limits: tuple, request: AuthorizationRequest) -> str | None:
        if request.amount is None:
            return None
        for limit in amount_limits:
            if limit.asset == request.amount.asset and not limit.covers(request.amount):
                return "AMOUNT_EXCEEDS_LIMIT"
        return None

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": _REGISTRY_SCHEMA_VERSION,
            "protocol_version": _REGISTRY_PROTOCOL_VERSION,
            "environment_id": self._environment_id,
            "domain_id": self._domain_id,
            "principals": [record.to_dict() for record in self.principals()],
            "credentials": [record.to_dict() for record in self.credentials()],
            "keys": [record.to_dict() for record in self.keys()],
            "grants": [record.to_dict() for record in self.grants()],
            "mandates": [record.to_dict() for record in self.mandates()],
            "authentication_events": [
                record.to_dict() for record in self.authentication_events()
            ],
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, value: object, *, environment_id: str) -> "TrustRegistry":
        if not isinstance(value, Mapping):
            raise CoreValidationError("trust registry state must decode from an object")
        if set(value) != _REGISTRY_KEYS:
            missing = sorted(_REGISTRY_KEYS - set(value))
            extra = sorted(set(value) - _REGISTRY_KEYS)
            raise CoreValidationError(
                f"trust registry fields are not canonical; missing={missing}, extra={extra}"
            )
        if value["schema_version"] != _REGISTRY_SCHEMA_VERSION:
            raise CoreValidationError("trust registry schema_version must be 1")
        if value["protocol_version"] != _REGISTRY_PROTOCOL_VERSION:
            raise CoreValidationError("trust registry protocol_version must be v0.1")
        registry = cls(environment_id=environment_id)
        if value["environment_id"] != registry._environment_id:
            raise CoreValidationError(
                "trust registry environment_id does not match the requested environment"
            )
        if value["domain_id"] != registry._domain_id:
            raise CoreValidationError(
                "trust registry state was not persisted for the canonical trust domain"
            )
        registry._load_collection("principals", value["principals"], PrincipalRecord, registry._principals, "principal_id")
        registry._load_collection("credentials", value["credentials"], CredentialRecord, registry._credentials, "credential_id")
        registry._load_collection("keys", value["keys"], KeyRecord, registry._keys, "key_id")
        registry._load_collection("grants", value["grants"], AuthorizationGrantRecord, registry._grants, "grant_id")
        registry._load_collection("mandates", value["mandates"], MandateRecord, registry._mandates, "mandate_id")
        registry._load_collection(
            "authentication_events",
            value["authentication_events"],
            AuthenticationEventRecord,
            registry._authentications,
            "authentication_id",
        )
        registry._validate_loaded_references()
        return registry

    @classmethod
    def from_json(cls, value: str, *, environment_id: str) -> "TrustRegistry":
        decoded = loads_canonical(value)
        if not isinstance(decoded, dict):
            raise CoreValidationError("trust registry JSON must decode to an object")
        return cls.from_dict(decoded, environment_id=environment_id)

    def _load_collection(self, name, value, record_cls, target, id_field) -> None:
        if not isinstance(value, list):
            raise CoreValidationError(f"trust registry {name} must deserialize from a list")
        for item in value:
            record = record_cls.from_dict(item)
            record_id = getattr(record, id_field)
            if record_id in target:
                raise CoreValidationError(f"trust registry {name} contains duplicate id {record_id}")
            if record.envelope.environment_id != self._environment_id:
                raise CoreValidationError(
                    f"trust record {record_id} was persisted for a different environment"
                )
            if record.envelope.domain_id != self._domain_id:
                raise CoreValidationError(
                    f"trust record {record_id} was persisted for a different domain"
                )
            target[record_id] = record

    def _validate_loaded_references(self) -> None:
        for credential in self._credentials.values():
            if credential.principal_id not in self._principals:
                raise CoreValidationError(
                    f"credential {credential.credential_id} references unknown principal "
                    f"{credential.principal_id}"
                )
        for key in self._keys.values():
            if key.owner_principal_id not in self._principals:
                raise CoreValidationError(
                    f"key {key.key_id} references unknown principal {key.owner_principal_id}"
                )
            if key.recovery_key_id is not None:
                recovery = self._keys.get(key.recovery_key_id)
                if recovery is None or recovery.purpose is not KeyPurpose.RECOVERY:
                    raise CoreValidationError(
                        f"key {key.key_id} references invalid recovery key {key.recovery_key_id}"
                    )
            for field in ("successor_key_id", "predecessor_key_id"):
                linked = getattr(key, field)
                if linked is not None and linked not in self._keys:
                    raise CoreValidationError(
                        f"key {key.key_id} references unknown key {linked}"
                    )
        for grant in self._grants.values():
            for principal_id in (grant.grantor_principal_id, grant.grantee_principal_id):
                if principal_id not in self._principals:
                    raise CoreValidationError(
                        f"grant {grant.grant_id} references unknown principal {principal_id}"
                    )
        for grant in self._grants.values():
            self._validate_grant_chain_acyclic(grant)
        for credential in self._credentials.values():
            for field in ("successor_credential_id", "predecessor_credential_id"):
                linked = getattr(credential, field)
                if linked is not None and linked not in self._credentials:
                    raise CoreValidationError(
                        f"credential {credential.credential_id} references unknown credential {linked}"
                    )
        for mandate in self._mandates.values():
            for principal_id in (mandate.mandator_principal_id, mandate.mandatary_principal_id):
                if principal_id not in self._principals:
                    raise CoreValidationError(
                        f"mandate {mandate.mandate_id} references unknown principal {principal_id}"
                    )
        for event in self._authentications.values():
            if event.principal_id not in self._principals:
                raise CoreValidationError(
                    f"authentication {event.authentication_id} references unknown principal "
                    f"{event.principal_id}"
                )
            if event.credential_id not in self._credentials:
                raise CoreValidationError(
                    f"authentication {event.authentication_id} references unknown credential "
                    f"{event.credential_id}"
                )

    def _validate_grant_chain_acyclic(self, grant: AuthorizationGrantRecord) -> None:
        visited: set[str] = set()
        current: AuthorizationGrantRecord | None = grant
        while current is not None:
            if current.grant_id in visited:
                raise CoreValidationError(
                    f"grant delegation chain contains a cycle at {current.grant_id}"
                )
            visited.add(current.grant_id)
            if current.grant_kind is GrantKind.ROOT:
                if current.parent_grant_id is not None:
                    raise CoreValidationError(
                        f"ROOT grant {current.grant_id} must not reference a parent grant"
                    )
                return
            parent_id = current.parent_grant_id
            parent = self._grants.get(parent_id) if parent_id is not None else None
            if parent is None:
                raise CoreValidationError(
                    f"grant {current.grant_id} references unknown parent grant {parent_id}"
                )
            if parent.grantee_principal_id != current.grantor_principal_id:
                raise CoreValidationError(
                    f"grant {current.grant_id} parent {parent_id} is not held by its grantor"
                )
            if parent.authority_class != current.authority_class:
                raise CoreValidationError(
                    f"grant {current.grant_id} parent {parent_id} has a different authority class"
                )
            if parent.envelope.environment_id != current.envelope.environment_id:
                raise CoreValidationError(
                    f"grant {current.grant_id} parent {parent_id} belongs to a different environment"
                )
            current = parent

    # ------------------------------------------------------------------
    # Relationship graph projection
    # ------------------------------------------------------------------

    def build_graph(self) -> ObjectGraph:
        """Project current trust state onto the canonical object/relationship graph."""
        envelopes: list[ObjectEnvelope] = []
        envelopes.extend(record.envelope for record in self.principals())
        envelopes.extend(record.envelope for record in self.credentials())
        envelopes.extend(record.envelope for record in self.keys())
        envelopes.extend(record.envelope for record in self.grants())
        envelopes.extend(record.envelope for record in self.mandates())
        envelopes.extend(record.envelope for record in self.authentication_events())
        envelopes.sort(key=lambda envelope: envelope.object_id)
        relationships: list[Relationship] = []
        for grant in self.grants():
            relationships.append(
                Relationship.build(
                    RelationshipType.AUTHORIZES,
                    grant.grantor_principal_id,
                    grant.grantee_principal_id,
                    attributes={
                        "grant_id": grant.grant_id,
                        "authority_class": grant.authority_class.value,
                        "delegation_depth": grant.delegation_depth,
                        "state": grant.state,
                    },
                )
            )
        for mandate in self.mandates():
            relationships.append(
                Relationship.build(
                    RelationshipType.ADMINISTERS,
                    mandate.mandatary_principal_id,
                    mandate.mandator_principal_id,
                    attributes={
                        "mandate_id": mandate.mandate_id,
                        "purpose": mandate.purpose,
                        "state": mandate.state,
                    },
                )
            )
        for credential in self.credentials():
            relationships.append(
                Relationship.build(
                    RelationshipType.CONTROLS,
                    credential.principal_id,
                    credential.credential_id,
                    attributes={
                        "credential_id": credential.credential_id,
                        "kind": credential.kind.value,
                        "state": credential.state,
                    },
                )
            )
        for key in self.keys():
            relationships.append(
                Relationship.build(
                    RelationshipType.CONTROLS,
                    key.owner_principal_id,
                    key.key_id,
                    attributes={
                        "key_id": key.key_id,
                        "purpose": key.purpose.value,
                        "state": key.state,
                    },
                )
            )
        for event in self.authentication_events():
            relationships.append(
                Relationship.build(
                    RelationshipType.ATTESTS,
                    event.authentication_id,
                    event.principal_id,
                    attributes={
                        "authentication_id": event.authentication_id,
                        "outcome": event.outcome.value,
                    },
                )
            )
        relationships.sort(
            key=lambda relationship: (
                relationship.relationship_type.value,
                relationship.subject_id,
                relationship.object_id,
            )
        )
        return ObjectGraph.build(envelopes, relationships)
