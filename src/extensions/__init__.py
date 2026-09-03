"""Extension runtime and capability marketplace (WORK-020).

This package owns the frozen v0.1 ``extensions.md`` abstraction:

* the typed, versioned marketplace contract (:class:`ExtensionManifest`
  carrying every frozen field plus the R0-R5 authority-tier requirement
  schedules — verification, collateral, monitoring, risk limits);
* the capability marketplace vocabulary mirroring the capability domain
  (:data:`CAPABILITY_DOMAIN_MIRROR`) and the closed permission and
  artifact-kind vocabularies;
* the frozen 13-state lifecycle
  ``DRAFT → SANDBOX → TESTED → SUBMITTED → SECURITY_REVIEW →
  POLICY_REVIEW → PUBLISHED → INSTALLED → ACTIVE → DEGRADED →
  SUSPENDED → DEPRECATED → ARCHIVED`` driven exclusively through the
  real transition kernel (no second state machine);
* the sandboxed invocation runtime: declared capability/inputs/outputs/
  resources only, grants, quotas, no ambient authority;
* the dependency DAG with version bounds and fail-closed cycle
  detection;
* contribution measurement: verified incremental contribution against a
  counterfactual baseline/treatment comparison with the three distinct
  typed economic quantities (resource credits, real economic earnings,
  financial collateral) — activity volume alone is never contribution.

Registry discipline: ``payswap/extension-manifest/v1`` and the
``extension`` event namespace are ALREADY listed in the frozen protocol
registry; every other extension object kind follows the sibling
convention and uses internal non-registry ``extension/...`` formats.
Command types are internal free-form strings (the frozen 12-verb
``Extension`` family plus the documented internal triggers
``certify``/``shadow``/``invoke``/``measure``).

Security model (constitution invariants 5/6/16): extensions are bounded
capability providers — they never directly mutate authoritative ledger
state, modify finality, grant authority, bypass compliance or access
undeclared resources; sandboxed invocations exchange typed artifacts
with explicit declared data only.
"""

from __future__ import annotations

from src.core.errors import CoreValidationError

from .contracts import (
    CAPABILITY_DOMAIN_MIRROR,
    CAPABILITY_GRANT_OBJECT_TYPE,
    CERTIFY_MIN_SANDBOX_INVOCATIONS,
    CONSUMED_SURFACES,
    CONTRIBUTION_METRICS,
    CREDIT_PER_BYTE,
    DEFAULT_AUTHORIZED_ACTORS,
    EXTENSION_AUTHORITY_TIERS,
    EXTENSION_COMMAND_TYPES,
    EXTENSION_CONTRIBUTION_OBJECT_TYPE,
    EXTENSION_INSTANCE_OBJECT_TYPE,
    EXTENSION_INVOCATION_OBJECT_TYPE,
    EXTENSION_MANIFEST_OBJECT_TYPE,
    EXTENSIONS_API_VERSION,
    EXTENSIONS_EVENT_NAMESPACE,
    EXTENSIONS_PROTOCOL_VERSION,
    EXTENSIONS_SCHEMA_VERSION,
    FROZEN_EXTENSION_COMMAND_VERBS,
    FORBIDDEN_PERMISSIONS,
    INSTANCE_LIFECYCLE_STATES,
    INVOCATION_BASE_CREDIT,
    InvocationEffectMode,
    LIFECYCLE_TRANSITIONS,
    MANIFEST_LIFECYCLE_STATES,
    MonitoringLevel,
    PricingModel,
    RISK_BANDS,
    ResourceCredits,
    TIER_MAXIMUM_EXPOSURE_MINOR,
    TIER_MINIMUM_COLLATERAL_MINOR,
    TIER_MINIMUM_MONITORING,
    ContributionMetric,
    EconomicEarnings,
    ExtensionArtifactKind,
    ExtensionCapability,
    ExtensionLifecycleState,
    ExtensionPermission,
    FinancialCollateral,
)
from .manifest import (
    CAPABILITY_KIND_MIRROR,
    DependencySpec,
    ExtensionManifest,
    PricingSpec,
    ResourceRequirements,
    RiskControls,
    RiskLimits,
    VerificationEvidence,
    parse_version,
    require_tier_requirements,
    version_in_bounds,
)
from .lifecycle import (
    parse_lifecycle_state,
    require_instance_state,
    require_manifest_state,
    resolve_lifecycle_transition,
)
from .artifacts import ExtensionArtifact
from .dag import DependencyGraph, require_acyclic
from .grants import CapabilityGrant, ExtensionInstance, ResourceBudget
from .runtime import (
    SANDBOX_CONTEXT_FIELDS,
    CodeRepository,
    ExtensionInvocation,
    InvocationRequest,
    SandboxContext,
    execute_sandboxed_invocation,
)
from .contribution import (
    BPS_DENOMINATOR,
    ExtensionContribution,
    OutcomeMeasurement,
    measure_contribution,
)
from .engine import (
    EXTENSION_EVENT_TYPES,
    RUNTIME_AUTHORITY_CLASS,
    ExtensionRuntime,
    SANDBOX_WINDOW_KEY,
)

__all__ = [
    # -- typed, versioned public boundary --------------------------------
    "EXTENSIONS_API_VERSION",
    "EXTENSIONS_PROTOCOL_VERSION",
    "EXTENSIONS_SCHEMA_VERSION",
    "EXTENSION_MANIFEST_OBJECT_TYPE",
    "EXTENSION_INSTANCE_OBJECT_TYPE",
    "CAPABILITY_GRANT_OBJECT_TYPE",
    "EXTENSION_INVOCATION_OBJECT_TYPE",
    "EXTENSION_CONTRIBUTION_OBJECT_TYPE",
    "EXTENSIONS_EVENT_NAMESPACE",
    "FROZEN_EXTENSION_COMMAND_VERBS",
    "EXTENSION_COMMAND_TYPES",
    "CONSUMED_SURFACES",
    "EXTENSION_EVENT_TYPES",
    # -- closed vocabularies ---------------------------------------------
    "ExtensionLifecycleState",
    "MANIFEST_LIFECYCLE_STATES",
    "INSTANCE_LIFECYCLE_STATES",
    "LIFECYCLE_TRANSITIONS",
    "ExtensionArtifactKind",
    "ExtensionPermission",
    "FORBIDDEN_PERMISSIONS",
    "ExtensionCapability",
    "CAPABILITY_DOMAIN_MIRROR",
    "CAPABILITY_KIND_MIRROR",
    "MonitoringLevel",
    "TIER_MINIMUM_COLLATERAL_MINOR",
    "TIER_MINIMUM_MONITORING",
    "TIER_MAXIMUM_EXPOSURE_MINOR",
    "EXTENSION_AUTHORITY_TIERS",
    "PricingModel",
    "ContributionMetric",
    "CONTRIBUTION_METRICS",
    "InvocationEffectMode",
    "RISK_BANDS",
    "BPS_DENOMINATOR",
    # -- distinct typed economic quantities ------------------------------
    "ResourceCredits",
    "EconomicEarnings",
    "FinancialCollateral",
    "INVOCATION_BASE_CREDIT",
    "CREDIT_PER_BYTE",
    "CERTIFY_MIN_SANDBOX_INVOCATIONS",
    # -- manifest contract -------------------------------------------------
    "ExtensionManifest",
    "DependencySpec",
    "PricingSpec",
    "ResourceRequirements",
    "RiskLimits",
    "RiskControls",
    "VerificationEvidence",
    "parse_version",
    "version_in_bounds",
    "require_tier_requirements",
    # -- lifecycle ---------------------------------------------------------
    "resolve_lifecycle_transition",
    "parse_lifecycle_state",
    "require_manifest_state",
    "require_instance_state",
    # -- composition artifacts --------------------------------------------
    "ExtensionArtifact",
    # -- dependency DAG ----------------------------------------------------
    "DependencyGraph",
    "require_acyclic",
    # -- grants and instances ----------------------------------------------
    "ExtensionInstance",
    "CapabilityGrant",
    "ResourceBudget",
    # -- sandboxed invocation runtime --------------------------------------
    "SANDBOX_CONTEXT_FIELDS",
    "SandboxContext",
    "InvocationRequest",
    "ExtensionInvocation",
    "CodeRepository",
    "execute_sandboxed_invocation",
    # -- contribution measurement -------------------------------------------
    "OutcomeMeasurement",
    "ExtensionContribution",
    "measure_contribution",
    # -- kernel-bound runtime ------------------------------------------------
    "ExtensionRuntime",
    "RUNTIME_AUTHORITY_CLASS",
    "SANDBOX_WINDOW_KEY",
    "DEFAULT_AUTHORIZED_ACTORS",
    # -- single error authority (re-export from the canonical core) ---------
    "CoreValidationError",
]
