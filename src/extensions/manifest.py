"""Extension manifests: the frozen typed marketplace contract.

An :class:`ExtensionManifest` is a versioned, immutable record carrying
every frozen v0.1 field (extensions.md): extension_id, developer,
version, code_hash, capabilities_provided[], capabilities_required[],
permissions[], dependencies[], inputs[], outputs[], pricing,
resource_requirements, authority_class, risk_class, jurisdictions[],
protocol_versions[], schema_versions[], simulation_support,
production_support — plus the typed authority-tier requirement carriers
(``verification`` evidence, ``risk_controls`` collateral/monitoring/
risk limits) that fail closed when missing for the declared R0-R5 tier.

The manifest object is the protocol-visible marketplace identity and uses
the registry-listed ``payswap/extension-manifest/v1`` object type; the
lifecycle state lives on the sealed kernel envelope
(:meth:`ExtensionManifest.bind_envelope`). Manifests are records, never
executors: this module performs no execution and causes no side effects.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from src.core.envelope import ObjectEnvelope
from src.core.errors import CoreValidationError
from src.safety.contracts import RiskBand

from .contracts import (
    CAPABILITY_DOMAIN_MIRROR,
    EXTENSION_MANIFEST_OBJECT_TYPE,
    EXTENSIONS_PROTOCOL_VERSION,
    EXTENSIONS_SCHEMA_VERSION,
    FORBIDDEN_PERMISSIONS,
    MANIFEST_LIFECYCLE_STATES,
    TIER_MAXIMUM_EXPOSURE_MINOR,
    TIER_MINIMUM_COLLATERAL_MINOR,
    TIER_MINIMUM_MONITORING,
    ExtensionArtifactKind,
    ExtensionCapability,
    ExtensionLifecycleState,
    ExtensionPermission,
    FinancialCollateral,
    MonitoringLevel,
    PricingModel,
    require_extension_tier,
)
from ._validation import (
    exact_fields,
    parse_enum,
    parse_version as parse_version_value,
    require_bool,
    require_digest,
    require_internal_id,
    require_int,
    require_int_in_range,
    require_jurisdictions,
    require_protocol_versions,
    require_text,
    unique_entries,
)


# ---------------------------------------------------------------------------
# version parsing and dependency bounds
# ---------------------------------------------------------------------------


def parse_version(version: str) -> tuple[int, int, int]:
    """Parse a deterministic ``major.minor.patch`` version (fail closed)."""
    return parse_version_value("extension version", version)


@dataclass(frozen=True, slots=True)
class DependencySpec:
    """One dependency declaration with inclusive version bounds."""

    extension_id: str
    min_version: str | None = None
    max_version: str | None = None

    def __post_init__(self) -> None:
        require_internal_id("dependency.extension_id", self.extension_id)
        for name, value in (
            ("dependency.min_version", self.min_version),
            ("dependency.max_version", self.max_version),
        ):
            if value is not None:
                parse_version_value(name, value)
        if (
            self.min_version is not None
            and self.max_version is not None
            and parse_version(self.min_version) > parse_version(self.max_version)
        ):
            raise CoreValidationError(
                "dependency.min_version must not exceed dependency.max_version"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "extension_id": self.extension_id,
            "min_version": self.min_version,
            "max_version": self.max_version,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "DependencySpec":
        if not isinstance(value, Mapping):
            raise CoreValidationError("dependency spec must be an object")
        exact_fields("dependency spec", value, {"extension_id", "min_version", "max_version"})
        return cls(
            extension_id=value["extension_id"],
            min_version=value["min_version"],
            max_version=value["max_version"],
        )


def version_in_bounds(version: str, spec: DependencySpec) -> bool:
    """Inclusive bound check of one concrete version against a spec."""
    parsed = parse_version(version)
    if spec.min_version is not None and parsed < parse_version(spec.min_version):
        return False
    if spec.max_version is not None and parsed > parse_version(spec.max_version):
        return False
    return True


# ---------------------------------------------------------------------------
# typed manifest value structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PricingSpec:
    """Typed marketplace pricing for one manifest version."""

    model: PricingModel
    amount_minor: int
    asset: str
    share_bps: int

    def __post_init__(self) -> None:
        if not isinstance(self.model, PricingModel):
            object.__setattr__(self, "model", PricingModel.parse(self.model))
        require_int("pricing.amount_minor", self.amount_minor, minimum=0)
        require_text("pricing.asset", self.asset)
        require_int_in_range("pricing.share_bps", self.share_bps, 0, 10_000)
        if self.model is PricingModel.REVENUE_SHARE and self.amount_minor != 0:
            raise CoreValidationError(
                "revenue-share pricing must not declare a fixed amount_minor"
            )
        if self.model is not PricingModel.REVENUE_SHARE and self.share_bps != 0:
            raise CoreValidationError(
                "only revenue-share pricing declares share_bps"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model.value,
            "amount_minor": self.amount_minor,
            "asset": self.asset,
            "share_bps": self.share_bps,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PricingSpec":
        if not isinstance(value, Mapping):
            raise CoreValidationError("pricing must be an object")
        exact_fields("pricing", value, {"model", "amount_minor", "asset", "share_bps"})
        return cls(
            model=PricingModel.parse(value["model"]),
            amount_minor=value["amount_minor"],
            asset=value["asset"],
            share_bps=value["share_bps"],
        )


@dataclass(frozen=True, slots=True)
class ResourceRequirements:
    """Typed sandbox resource quotas declared by the manifest."""

    max_invocations_per_window: int
    max_artifact_bytes: int

    def __post_init__(self) -> None:
        require_int(
            "resource_requirements.max_invocations_per_window",
            self.max_invocations_per_window,
            minimum=1,
        )
        require_int(
            "resource_requirements.max_artifact_bytes",
            self.max_artifact_bytes,
            minimum=1,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_invocations_per_window": self.max_invocations_per_window,
            "max_artifact_bytes": self.max_artifact_bytes,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ResourceRequirements":
        if not isinstance(value, Mapping):
            raise CoreValidationError("resource requirements must be an object")
        exact_fields(
            "resource requirements", value, {"max_invocations_per_window", "max_artifact_bytes"}
        )
        return cls(
            max_invocations_per_window=value["max_invocations_per_window"],
            max_artifact_bytes=value["max_artifact_bytes"],
        )


@dataclass(frozen=True, slots=True)
class RiskLimits:
    """Typed declared risk limits (bounded by the tier schedule)."""

    max_single_exposure_minor: int

    def __post_init__(self) -> None:
        require_int(
            "risk_limits.max_single_exposure_minor",
            self.max_single_exposure_minor,
            minimum=0,
        )

    def to_dict(self) -> dict[str, Any]:
        return {"max_single_exposure_minor": self.max_single_exposure_minor}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RiskLimits":
        if not isinstance(value, Mapping):
            raise CoreValidationError("risk limits must be an object")
        exact_fields("risk limits", value, {"max_single_exposure_minor"})
        return cls(max_single_exposure_minor=value["max_single_exposure_minor"])


@dataclass(frozen=True, slots=True)
class RiskControls:
    """Typed authority-tier control package: collateral + monitoring + limits."""

    collateral: FinancialCollateral | None
    monitoring_level: MonitoringLevel | None
    risk_limits: RiskLimits | None

    def __post_init__(self) -> None:
        if self.collateral is not None and not isinstance(self.collateral, FinancialCollateral):
            object.__setattr__(
                self, "collateral", FinancialCollateral.from_dict(self.collateral)
            )
        if self.monitoring_level is not None and not isinstance(
            self.monitoring_level, MonitoringLevel
        ):
            object.__setattr__(
                self, "monitoring_level", MonitoringLevel.parse(self.monitoring_level)
            )
        if self.risk_limits is not None and not isinstance(self.risk_limits, RiskLimits):
            object.__setattr__(self, "risk_limits", RiskLimits.from_dict(self.risk_limits))

    def to_dict(self) -> dict[str, Any]:
        return {
            "collateral": self.collateral.to_dict() if self.collateral is not None else None,
            "monitoring_level": (
                self.monitoring_level.value if self.monitoring_level is not None else None
            ),
            "risk_limits": self.risk_limits.to_dict() if self.risk_limits is not None else None,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RiskControls":
        if not isinstance(value, Mapping):
            raise CoreValidationError("risk controls must be an object")
        exact_fields("risk controls", value, {"collateral", "monitoring_level", "risk_limits"})
        raw_collateral = value["collateral"]
        raw_limits = value["risk_limits"]
        return cls(
            collateral=(
                FinancialCollateral.from_dict(raw_collateral)
                if raw_collateral is not None
                else None
            ),
            monitoring_level=(
                MonitoringLevel.parse(value["monitoring_level"])
                if value["monitoring_level"] is not None
                else None
            ),
            risk_limits=RiskLimits.from_dict(raw_limits) if raw_limits is not None else None,
        )


@dataclass(frozen=True, slots=True)
class VerificationEvidence:
    """Typed verification evidence required for tiers above R0."""

    method: str
    evidence_refs: tuple[str, ...]
    review_digest: str

    def __post_init__(self) -> None:
        require_text("verification.method", self.method)
        if not isinstance(self.evidence_refs, tuple) or not self.evidence_refs:
            raise CoreValidationError(
                "verification.evidence_refs must be a non-empty tuple"
            )
        for ref in self.evidence_refs:
            require_text("verification.evidence_ref", ref)
        require_digest("verification.review_digest", self.review_digest)

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "evidence_refs": list(self.evidence_refs),
            "review_digest": self.review_digest,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "VerificationEvidence":
        if not isinstance(value, Mapping):
            raise CoreValidationError("verification evidence must be an object")
        exact_fields(
            "verification evidence", value, {"method", "evidence_refs", "review_digest"}
        )
        refs = value["evidence_refs"]
        if not isinstance(refs, list):
            raise CoreValidationError(
                "verification.evidence_refs must deserialize from a list"
            )
        return cls(
            method=value["method"],
            evidence_refs=tuple(refs),
            review_digest=value["review_digest"],
        )


# ---------------------------------------------------------------------------
# the manifest itself
# ---------------------------------------------------------------------------

_MANIFEST_RECORD_FIELDS = (
    "extension_id",
    "developer",
    "version",
    "code_hash",
    "capabilities_provided",
    "capabilities_required",
    "permissions",
    "dependencies",
    "inputs",
    "outputs",
    "pricing",
    "resource_requirements",
    "authority_class",
    "risk_class",
    "jurisdictions",
    "protocol_versions",
    "schema_versions",
    "simulation_support",
    "production_support",
    "verification",
    "risk_controls",
)


def require_tier_requirements(name: str, manifest: "ExtensionManifest") -> None:
    """Fail closed unless the manifest satisfies its authority tier schedule.

    Higher tiers require stronger verification, collateral, monitoring
    and risk limits (extensions.md): verification from R1 up, monitoring
    from R2 up, and the full collateral/monitoring/limits package from
    the reserve tier R3 up, with the deterministic schedules exported by
    :mod:`src.extensions.contracts`.
    """
    tier = manifest.authority_class
    if tier in ("R1", "R2", "R3", "R4", "R5") and manifest.verification is None:
        raise CoreValidationError(
            f"{name}: authority tier {tier} requires typed verification evidence"
        )
    required_monitoring = TIER_MINIMUM_MONITORING[tier]
    if required_monitoring is not None:
        controls = manifest.risk_controls
        if controls is None or controls.monitoring_level is None:
            raise CoreValidationError(
                f"{name}: authority tier {tier} requires monitoring level "
                f"{required_monitoring.value} or stronger"
            )
        if controls.monitoring_level.strength < required_monitoring.strength:
            raise CoreValidationError(
                f"{name}: authority tier {tier} requires monitoring level "
                f"{required_monitoring.value} or stronger, declared "
                f"{controls.monitoring_level.value}"
            )
    minimum_collateral = TIER_MINIMUM_COLLATERAL_MINOR[tier]
    if minimum_collateral > 0:
        controls = manifest.risk_controls
        if controls is None or controls.collateral is None:
            raise CoreValidationError(
                f"{name}: authority tier {tier} requires financial collateral of at "
                f"least {minimum_collateral} minor units"
            )
        if controls.collateral.amount_minor < minimum_collateral:
            raise CoreValidationError(
                f"{name}: authority tier {tier} requires financial collateral of at "
                f"least {minimum_collateral} minor units, declared "
                f"{controls.collateral.amount_minor}"
            )
        if controls.risk_limits is None:
            raise CoreValidationError(
                f"{name}: authority tier {tier} requires typed risk limits"
            )
        maximum_exposure = TIER_MAXIMUM_EXPOSURE_MINOR[tier]
        if controls.risk_limits.max_single_exposure_minor > maximum_exposure:
            raise CoreValidationError(
                f"{name}: authority tier {tier} caps declared single-exposure risk "
                f"limits at {maximum_exposure} minor units, declared "
                f"{controls.risk_limits.max_single_exposure_minor}"
            )


@dataclass(frozen=True, slots=True)
class ExtensionManifest:
    """Immutable, validated extension manifest record.

    Direct construction validates the whole frozen contract including the
    authority-tier schedule; :meth:`bind_envelope` attaches the sealed
    kernel envelope (registry-listed ``payswap/extension-manifest/v1``)
    whose ``state`` carries the manifest lifecycle head.
    """

    extension_id: str
    developer: str
    version: str
    code_hash: str
    capabilities_provided: tuple[ExtensionCapability, ...]
    capabilities_required: tuple[ExtensionCapability, ...]
    permissions: tuple[ExtensionPermission, ...]
    dependencies: tuple[DependencySpec, ...]
    inputs: tuple[ExtensionArtifactKind, ...]
    outputs: tuple[ExtensionArtifactKind, ...]
    pricing: PricingSpec
    resource_requirements: ResourceRequirements
    authority_class: str
    risk_class: RiskBand
    jurisdictions: tuple[str, ...]
    protocol_versions: tuple[str, ...]
    schema_versions: tuple[int, ...]
    simulation_support: bool
    production_support: bool
    verification: VerificationEvidence | None = None
    risk_controls: RiskControls | None = None
    envelope: ObjectEnvelope | None = None

    def __post_init__(self) -> None:
        require_internal_id("manifest.extension_id", self.extension_id)
        require_text("manifest.developer", self.developer)
        parse_version(self.version)
        require_digest("manifest.code_hash", self.code_hash)
        self._coerce_capabilities()
        self._coerce_permissions()
        if not isinstance(self.dependencies, tuple):
            raise CoreValidationError("manifest.dependencies must be a tuple")
        for spec in self.dependencies:
            if not isinstance(spec, DependencySpec):
                raise CoreValidationError("manifest.dependencies entries must be DependencySpec")
        # Self-dependencies are NOT rejected here: a manifest record is a
        # declaration, and the dependency graph is the authority that
        # detects a self-dependency as a cycle (fail closed at build).
        unique_entries("manifest.dependencies", self.dependencies)
        self._coerce_artifact_kinds()
        if not isinstance(self.pricing, PricingSpec):
            object.__setattr__(self, "pricing", PricingSpec.from_dict(self.pricing))
        if not isinstance(self.resource_requirements, ResourceRequirements):
            object.__setattr__(
                self, "resource_requirements", ResourceRequirements.from_dict(
                    self.resource_requirements
                )
            )
        require_extension_tier("manifest.authority_class", self.authority_class)
        if not isinstance(self.risk_class, RiskBand):
            object.__setattr__(
                self, "risk_class", parse_enum("manifest.risk_class", RiskBand, self.risk_class)
            )
        require_jurisdictions("manifest.jurisdictions", self.jurisdictions)
        require_protocol_versions(
            "manifest.protocol_versions", self.protocol_versions, EXTENSIONS_PROTOCOL_VERSION
        )
        if not isinstance(self.schema_versions, tuple) or not self.schema_versions:
            raise CoreValidationError("manifest.schema_versions must be a non-empty tuple")
        for schema_version in self.schema_versions:
            require_int("manifest.schema_versions entry", schema_version, minimum=1)
        if EXTENSIONS_SCHEMA_VERSION not in self.schema_versions:
            raise CoreValidationError(
                f"manifest.schema_versions must include the domain schema version "
                f"{EXTENSIONS_SCHEMA_VERSION}"
            )
        require_bool("manifest.simulation_support", self.simulation_support)
        require_bool("manifest.production_support", self.production_support)
        if not self.simulation_support and not self.production_support:
            raise CoreValidationError(
                "manifest must declare simulation or production support"
            )
        if self.verification is not None and not isinstance(
            self.verification, VerificationEvidence
        ):
            object.__setattr__(
                self, "verification", VerificationEvidence.from_dict(self.verification)
            )
        if self.risk_controls is not None and not isinstance(
            self.risk_controls, RiskControls
        ):
            object.__setattr__(self, "risk_controls", RiskControls.from_dict(self.risk_controls))
        require_tier_requirements("manifest", self)
        if self.envelope is not None and not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("manifest envelope must be an ObjectEnvelope")

    # -- parsing helpers ----------------------------------------------------

    def _coerce_capabilities(self) -> None:
        for name, required_non_empty in (
            ("capabilities_provided", True),
            ("capabilities_required", False),
        ):
            value = getattr(self, name)
            if not isinstance(value, tuple):
                raise CoreValidationError(f"manifest.{name} must be a tuple")
            if required_non_empty and not value:
                raise CoreValidationError(
                    "manifest.capabilities_provided must declare at least one capability"
                )
            parsed = tuple(
                item if isinstance(item, ExtensionCapability) else ExtensionCapability.parse(item)
                for item in value
            )
            unique_entries(f"manifest.{name}", parsed)
            object.__setattr__(self, name, parsed)
        if set(self.capabilities_provided) & set(self.capabilities_required):
            raise CoreValidationError(
                "manifest capabilities_provided and capabilities_required must be disjoint"
            )

    def _coerce_permissions(self) -> None:
        if not isinstance(self.permissions, tuple):
            raise CoreValidationError("manifest.permissions must be a tuple")
        for item in self.permissions:
            if isinstance(item, str) and item in FORBIDDEN_PERMISSIONS:
                raise CoreValidationError(
                    f"manifest permission {item!r} is forbidden by the frozen "
                    "extension security model (extensions cannot directly mutate "
                    "authoritative ledger state, modify finality, grant authority, "
                    "bypass compliance or access undeclared resources)"
                )
        parsed = tuple(
            item if isinstance(item, ExtensionPermission) else ExtensionPermission.parse(item)
            for item in self.permissions
        )
        unique_entries("manifest.permissions", parsed)
        object.__setattr__(self, "permissions", parsed)

    def _coerce_artifact_kinds(self) -> None:
        for name in ("inputs", "outputs"):
            value = getattr(self, name)
            if not isinstance(value, tuple) or not value:
                raise CoreValidationError(
                    f"manifest.{name} must be a non-empty tuple of declared artifact kinds"
                )
            parsed = tuple(
                item if isinstance(item, ExtensionArtifactKind) else ExtensionArtifactKind.parse(item)
                for item in value
            )
            unique_entries(f"manifest.{name}", parsed)
            object.__setattr__(self, name, parsed)

    # -- envelope binding ---------------------------------------------------

    @property
    def state(self) -> ExtensionLifecycleState:
        if self.envelope is None:
            raise CoreValidationError(
                "manifest state requires the bound kernel envelope"
            )
        state = parse_enum(
            "manifest state", ExtensionLifecycleState, self.envelope.state
        )
        if state not in MANIFEST_LIFECYCLE_STATES:
            raise CoreValidationError(
                f"manifest object cannot hold the instance lifecycle state {state.value}"
            )
        return state

    def bind_envelope(self, envelope: ObjectEnvelope) -> "ExtensionManifest":
        """Attach the sealed kernel envelope; identity must match exactly."""
        if not isinstance(envelope, ObjectEnvelope):
            raise CoreValidationError("manifest envelope must be an ObjectEnvelope")
        if envelope.integrity_hash is None:
            raise CoreValidationError(
                "manifest envelope must be sealed with with_integrity_hash()"
            )
        if envelope.object_id != self.extension_id:
            raise CoreValidationError(
                "manifest envelope object_id must equal the manifest extension_id"
            )
        if envelope.object_type != EXTENSION_MANIFEST_OBJECT_TYPE:
            raise CoreValidationError(
                f"manifest envelope object_type must be exactly {EXTENSION_MANIFEST_OBJECT_TYPE}"
            )
        if envelope.protocol_version != EXTENSIONS_PROTOCOL_VERSION:
            raise CoreValidationError(
                f"manifest envelope protocol_version must be {EXTENSIONS_PROTOCOL_VERSION}"
            )
        if envelope.schema_version != EXTENSIONS_SCHEMA_VERSION:
            raise CoreValidationError(
                "manifest envelope schema_version must be the domain schema version"
            )
        state = parse_enum("manifest state", ExtensionLifecycleState, envelope.state)
        if state not in MANIFEST_LIFECYCLE_STATES:
            raise CoreValidationError(
                f"manifest object cannot hold the instance lifecycle state {state.value}"
            )
        from dataclasses import replace

        return replace(self, envelope=envelope)

    # -- canonical serialization -------------------------------------------

    def to_record_dict(self) -> dict[str, Any]:
        """Canonical record payload (the frozen field set, envelope-free)."""
        return {
            "extension_id": self.extension_id,
            "developer": self.developer,
            "version": self.version,
            "code_hash": self.code_hash,
            "capabilities_provided": [item.value for item in self.capabilities_provided],
            "capabilities_required": [item.value for item in self.capabilities_required],
            "permissions": [item.value for item in self.permissions],
            "dependencies": [spec.to_dict() for spec in self.dependencies],
            "inputs": [item.value for item in self.inputs],
            "outputs": [item.value for item in self.outputs],
            "pricing": self.pricing.to_dict(),
            "resource_requirements": self.resource_requirements.to_dict(),
            "authority_class": self.authority_class,
            "risk_class": self.risk_class.value,
            "jurisdictions": list(self.jurisdictions),
            "protocol_versions": list(self.protocol_versions),
            "schema_versions": list(self.schema_versions),
            "simulation_support": self.simulation_support,
            "production_support": self.production_support,
            "verification": (
                self.verification.to_dict() if self.verification is not None else None
            ),
            "risk_controls": (
                self.risk_controls.to_dict() if self.risk_controls is not None else None
            ),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict() if self.envelope is not None else None,
            "record": self.to_record_dict(),
        }

    @classmethod
    def from_record_dict(cls, value: Mapping[str, Any]) -> "ExtensionManifest":
        if not isinstance(value, Mapping):
            raise CoreValidationError("manifest record must be an object")
        exact_fields("manifest record", value, set(_MANIFEST_RECORD_FIELDS))
        dependencies = value["dependencies"]
        if not isinstance(dependencies, list):
            raise CoreValidationError("manifest.dependencies must deserialize from a list")
        return cls(
            extension_id=value["extension_id"],
            developer=value["developer"],
            version=value["version"],
            code_hash=value["code_hash"],
            capabilities_provided=tuple(value["capabilities_provided"]),
            capabilities_required=tuple(value["capabilities_required"]),
            permissions=tuple(value["permissions"]),
            dependencies=tuple(DependencySpec.from_dict(item) for item in dependencies),
            inputs=tuple(value["inputs"]),
            outputs=tuple(value["outputs"]),
            pricing=PricingSpec.from_dict(value["pricing"]),
            resource_requirements=ResourceRequirements.from_dict(
                value["resource_requirements"]
            ),
            authority_class=value["authority_class"],
            risk_class=value["risk_class"],
            jurisdictions=tuple(value["jurisdictions"]),
            protocol_versions=tuple(value["protocol_versions"]),
            schema_versions=tuple(value["schema_versions"]),
            simulation_support=value["simulation_support"],
            production_support=value["production_support"],
            verification=(
                VerificationEvidence.from_dict(value["verification"])
                if value["verification"] is not None
                else None
            ),
            risk_controls=(
                RiskControls.from_dict(value["risk_controls"])
                if value["risk_controls"] is not None
                else None
            ),
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ExtensionManifest":
        if not isinstance(value, Mapping):
            raise CoreValidationError("manifest must be an object")
        exact_fields("manifest", value, {"envelope", "record"})
        manifest = cls.from_record_dict(value["record"])
        if value["envelope"] is None:
            return manifest
        envelope = ObjectEnvelope.from_dict(value["envelope"])
        return manifest.bind_envelope(envelope)


#: The capability-domain mirror re-exported for manifest consumers.
CAPABILITY_KIND_MIRROR = CAPABILITY_DOMAIN_MIRROR
