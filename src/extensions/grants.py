"""Capability grants and installed extension instances.

An :class:`ExtensionInstance` is one installed materialization of a
PUBLISHED manifest in exactly one environment (kernel-bound). A
:class:`CapabilityGrant` authorizes that instance to exercise ONE
declared capability, scoped by jurisdictions, a validity window and a
typed resource budget. Grants are the security boundary of the
invocation runtime: without a covering, unexpired, in-scope grant a
sandboxed invocation fails closed.

Both objects use internal non-registry ``extension/...`` object types
(the registry lists only ``payswap/extension-manifest/v1``) and their
lifecycle state lives on sealed kernel envelopes — the manifest state
head is owned by the manifest, the instance tail here.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Mapping

from src.core.envelope import ObjectEnvelope
from src.core.errors import CoreValidationError
from src.simulation import EnvironmentMode

from .contracts import (
    CAPABILITY_GRANT_OBJECT_TYPE,
    EXTENSION_INSTANCE_OBJECT_TYPE,
    EXTENSIONS_PROTOCOL_VERSION,
    EXTENSIONS_SCHEMA_VERSION,
    INSTANCE_LIFECYCLE_STATES,
    ExtensionCapability,
    ExtensionLifecycleState,
)
from ._validation import (
    exact_fields,
    parse_enum,
    require_internal_id,
    require_int,
    require_jurisdictions,
    require_text,
    validate_timestamp,
)


@dataclass(frozen=True, slots=True)
class ResourceBudget:
    """Typed invocation budget: count within a declared time window."""

    max_invocations: int
    window_start: str
    window_end: str

    def __post_init__(self) -> None:
        require_int("budget.max_invocations", self.max_invocations, minimum=1)
        validate_timestamp("budget.window_start", self.window_start)
        validate_timestamp("budget.window_end", self.window_end)
        from ._validation import compare_timestamps

        if compare_timestamps(self.window_start, self.window_end) > 0:
            raise CoreValidationError(
                "budget.window_start must not be after budget.window_end"
            )

    def contains(self, as_of: str) -> bool:
        from ._validation import compare_timestamps

        validate_timestamp("budget as_of", as_of)
        return (
            compare_timestamps(as_of, self.window_start) >= 0
            and compare_timestamps(as_of, self.window_end) <= 0
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_invocations": self.max_invocations,
            "window_start": self.window_start,
            "window_end": self.window_end,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ResourceBudget":
        if not isinstance(value, Mapping):
            raise CoreValidationError("resource budget must be an object")
        exact_fields("resource budget", value, {"max_invocations", "window_start", "window_end"})
        return cls(
            max_invocations=value["max_invocations"],
            window_start=value["window_start"],
            window_end=value["window_end"],
        )


@dataclass(frozen=True, slots=True)
class CapabilityGrant:
    """One capability grant bound to an installed instance."""

    grant_id: str
    instance_id: str
    extension_id: str
    capability: ExtensionCapability
    granted_by: str
    valid_from: str
    valid_until: str
    jurisdictions: tuple[str, ...]
    budget: ResourceBudget
    envelope: ObjectEnvelope | None = None

    def __post_init__(self) -> None:
        require_internal_id("grant.grant_id", self.grant_id)
        require_internal_id("grant.instance_id", self.instance_id)
        require_internal_id("grant.extension_id", self.extension_id)
        if not isinstance(self.capability, ExtensionCapability):
            object.__setattr__(
                self, "capability", ExtensionCapability.parse(self.capability)
            )
        require_text("grant.granted_by", self.granted_by)
        validate_timestamp("grant.valid_from", self.valid_from)
        validate_timestamp("grant.valid_until", self.valid_until)
        require_jurisdictions("grant.jurisdictions", self.jurisdictions)
        if not isinstance(self.budget, ResourceBudget):
            object.__setattr__(self, "budget", ResourceBudget.from_dict(self.budget))
        from ._validation import compare_timestamps

        if compare_timestamps(self.valid_from, self.valid_until) > 0:
            raise CoreValidationError(
                "grant.valid_from must not be after grant.valid_until"
            )
        if self.envelope is not None and not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("grant envelope must be an ObjectEnvelope")

    @property
    def state(self) -> ExtensionLifecycleState:
        if self.envelope is None:
            raise CoreValidationError("grant state requires the bound kernel envelope")
        return parse_enum("grant state", ExtensionLifecycleState, self.envelope.state)

    def covers(self, *, as_of: str, jurisdiction: str) -> bool:
        """Window + jurisdiction scope check for one invocation."""
        from ._validation import compare_timestamps

        validate_timestamp("grant as_of", as_of)
        require_text("grant jurisdiction", jurisdiction)
        if compare_timestamps(as_of, self.valid_from) < 0:
            return False
        if compare_timestamps(as_of, self.valid_until) > 0:
            return False
        return jurisdiction in self.jurisdictions

    def bind_envelope(self, envelope: ObjectEnvelope) -> "CapabilityGrant":
        if not isinstance(envelope, ObjectEnvelope):
            raise CoreValidationError("grant envelope must be an ObjectEnvelope")
        if envelope.integrity_hash is None:
            raise CoreValidationError(
                "grant envelope must be sealed with with_integrity_hash()"
            )
        if envelope.object_id != self.grant_id:
            raise CoreValidationError("grant envelope object_id must equal grant_id")
        if envelope.object_type != CAPABILITY_GRANT_OBJECT_TYPE:
            raise CoreValidationError(
                f"grant envelope object_type must be exactly {CAPABILITY_GRANT_OBJECT_TYPE}"
            )
        if envelope.protocol_version != EXTENSIONS_PROTOCOL_VERSION:
            raise CoreValidationError(
                f"grant envelope protocol_version must be {EXTENSIONS_PROTOCOL_VERSION}"
            )
        if envelope.schema_version != EXTENSIONS_SCHEMA_VERSION:
            raise CoreValidationError(
                "grant envelope schema_version must be the domain schema version"
            )
        return replace(self, envelope=envelope)

    def to_record_dict(self) -> dict[str, Any]:
        return {
            "grant_id": self.grant_id,
            "instance_id": self.instance_id,
            "extension_id": self.extension_id,
            "capability": self.capability.value,
            "granted_by": self.granted_by,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "jurisdictions": list(self.jurisdictions),
            "budget": self.budget.to_dict(),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict() if self.envelope is not None else None,
            "record": self.to_record_dict(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CapabilityGrant":
        if not isinstance(value, Mapping):
            raise CoreValidationError("grant must be an object")
        exact_fields("grant", value, {"envelope", "record"})
        record = value["record"]
        if not isinstance(record, Mapping):
            raise CoreValidationError("grant record must be an object")
        exact_fields(
            "grant record",
            record,
            {
                "grant_id",
                "instance_id",
                "extension_id",
                "capability",
                "granted_by",
                "valid_from",
                "valid_until",
                "jurisdictions",
                "budget",
            },
        )
        grant = cls(
            grant_id=record["grant_id"],
            instance_id=record["instance_id"],
            extension_id=record["extension_id"],
            capability=record["capability"],
            granted_by=record["granted_by"],
            valid_from=record["valid_from"],
            valid_until=record["valid_until"],
            jurisdictions=tuple(record["jurisdictions"]),
            budget=ResourceBudget.from_dict(record["budget"]),
        )
        if value["envelope"] is None:
            return grant
        return grant.bind_envelope(ObjectEnvelope.from_dict(value["envelope"]))


@dataclass(frozen=True, slots=True)
class ExtensionInstance:
    """One installed extension materialization in exactly one environment."""

    instance_id: str
    manifest_id: str
    extension_id: str
    version: str
    environment_mode: EnvironmentMode
    shadow: bool
    jurisdictions: tuple[str, ...]
    envelope: ObjectEnvelope | None = None

    def __post_init__(self) -> None:
        require_internal_id("instance.instance_id", self.instance_id)
        require_internal_id("instance.manifest_id", self.manifest_id)
        require_internal_id("instance.extension_id", self.extension_id)
        from .manifest import parse_version

        parse_version(self.version)
        if not isinstance(self.environment_mode, EnvironmentMode):
            object.__setattr__(
                self, "environment_mode", EnvironmentMode.parse(self.environment_mode)
            )
        if not isinstance(self.shadow, bool):
            raise CoreValidationError("instance.shadow must be a boolean")
        require_jurisdictions("instance.jurisdictions", self.jurisdictions)
        if self.envelope is not None and not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("instance envelope must be an ObjectEnvelope")

    @property
    def state(self) -> ExtensionLifecycleState:
        if self.envelope is None:
            raise CoreValidationError(
                "instance state requires the bound kernel envelope"
            )
        state = parse_enum(
            "instance state", ExtensionLifecycleState, self.envelope.state
        )
        if state not in INSTANCE_LIFECYCLE_STATES:
            raise CoreValidationError(
                f"instance objects cannot hold the manifest lifecycle state {state.value}"
            )
        return state

    def bind_envelope(self, envelope: ObjectEnvelope) -> "ExtensionInstance":
        if not isinstance(envelope, ObjectEnvelope):
            raise CoreValidationError("instance envelope must be an ObjectEnvelope")
        if envelope.integrity_hash is None:
            raise CoreValidationError(
                "instance envelope must be sealed with with_integrity_hash()"
            )
        if envelope.object_id != self.instance_id:
            raise CoreValidationError(
                "instance envelope object_id must equal instance_id"
            )
        if envelope.object_type != EXTENSION_INSTANCE_OBJECT_TYPE:
            raise CoreValidationError(
                f"instance envelope object_type must be exactly {EXTENSION_INSTANCE_OBJECT_TYPE}"
            )
        if envelope.protocol_version != EXTENSIONS_PROTOCOL_VERSION:
            raise CoreValidationError(
                f"instance envelope protocol_version must be {EXTENSIONS_PROTOCOL_VERSION}"
            )
        if envelope.schema_version != EXTENSIONS_SCHEMA_VERSION:
            raise CoreValidationError(
                "instance envelope schema_version must be the domain schema version"
            )
        state = parse_enum("instance state", ExtensionLifecycleState, envelope.state)
        if state not in INSTANCE_LIFECYCLE_STATES:
            raise CoreValidationError(
                f"instance objects cannot hold the manifest lifecycle state {state.value}"
            )
        return replace(self, envelope=envelope)

    def to_record_dict(self) -> dict[str, Any]:
        return {
            "instance_id": self.instance_id,
            "manifest_id": self.manifest_id,
            "extension_id": self.extension_id,
            "version": self.version,
            "environment_mode": self.environment_mode.value,
            "shadow": self.shadow,
            "jurisdictions": list(self.jurisdictions),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict() if self.envelope is not None else None,
            "record": self.to_record_dict(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ExtensionInstance":
        if not isinstance(value, Mapping):
            raise CoreValidationError("instance must be an object")
        exact_fields("instance", value, {"envelope", "record"})
        record = value["record"]
        if not isinstance(record, Mapping):
            raise CoreValidationError("instance record must be an object")
        exact_fields(
            "instance record",
            record,
            {
                "instance_id",
                "manifest_id",
                "extension_id",
                "version",
                "environment_mode",
                "shadow",
                "jurisdictions",
            },
        )
        instance = cls(
            instance_id=record["instance_id"],
            manifest_id=record["manifest_id"],
            extension_id=record["extension_id"],
            version=record["version"],
            environment_mode=EnvironmentMode.parse(record["environment_mode"]),
            shadow=record["shadow"],
            jurisdictions=tuple(record["jurisdictions"]),
        )
        if value["envelope"] is None:
            return instance
        return instance.bind_envelope(ObjectEnvelope.from_dict(value["envelope"]))
