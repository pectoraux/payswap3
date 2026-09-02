"""Frozen public-boundary contracts for the extension domain (WORK-020).

This package owns the frozen v0.1 ``extensions.md`` abstraction: the
manifest, the capability marketplace, the sandboxed invocation runtime,
capability grants, the dependency DAG, resource quotas and contribution
measurement.

Registry discipline: ``payswap/extension-manifest/v1`` and the
``extension`` event namespace are ALREADY listed in the frozen protocol
registry; every other extension object kind below follows the sibling
convention and uses internal non-registry ``extension/...`` formats. No
new protocol-visible name is invented here.

The authority-tier vocabulary R0-R5 is the frozen registry authority
class projection of the extension tiers
``R0 OBSERVE / R1 ANALYZE / R2 PROPOSE / R3 RESERVE / R4 EXECUTE /
R5 FINANCIAL_EXPOSURE``; the extension capability vocabulary mirrors the
capability domain's closed ``CapabilityKind`` names for the four shared
kinds (WORK-009 dependency). The risk vocabulary is owned by
``src.safety`` (WORK-017 dependency) and the epistemic vocabulary by
``src.evidence`` (WORK-018 dependency).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Mapping

from src.capability.records import CapabilityKind
from src.core.errors import CoreValidationError
from src.safety.contracts import RiskBand
from src.transition.registry import PROTOCOL_VERSION

from ._validation import require_int, require_int_in_range, require_text

# -- typed, versioned public boundary --------------------------------------

#: Version of this typed, versioned public boundary.
EXTENSIONS_API_VERSION = "v0.1"

#: Frozen protocol version consumed (owned by the transition kernel registry).
EXTENSIONS_PROTOCOL_VERSION = PROTOCOL_VERSION

#: Schema version of extension-domain durable objects.
EXTENSIONS_SCHEMA_VERSION = 1

#: Registry-listed protocol object type of the extension manifest identity.
EXTENSION_MANIFEST_OBJECT_TYPE = "payswap/extension-manifest/v1"

#: Internal (non-registry) object types of extension-domain durable objects.
EXTENSION_INSTANCE_OBJECT_TYPE = "extension/instance/v1"
CAPABILITY_GRANT_OBJECT_TYPE = "extension/grant/v1"
EXTENSION_INVOCATION_OBJECT_TYPE = "extension/invocation/v1"
EXTENSION_CONTRIBUTION_OBJECT_TYPE = "extension/contribution/v1"

#: Registry-listed protocol event namespace owned by this domain.
EXTENSIONS_EVENT_NAMESPACE = "extension"

#: The frozen ``Extension`` command family (command-event-model.md):
#: Register/Submit/Approve/Reject/Publish/Install/Activate/Degrade/
#: Suspend/Resume/Deprecate/Archive.
FROZEN_EXTENSION_COMMAND_VERBS = frozenset(
    {
        "register",
        "submit",
        "approve",
        "reject",
        "publish",
        "install",
        "activate",
        "degrade",
        "suspend",
        "resume",
        "deprecate",
        "archive",
    }
)

#: Internal command types: the frozen family plus the documented internal
#: trigger verbs (certify = the sandbox-evidence certification trigger,
#: shadow = the observation-mode switch, invoke = the sandboxed
#: invocation lifecycle, measure = contribution measurement). Command
#: types are internal free-form strings following the W026 sibling
#: precedent; only the EVENT namespace is registry-governed.
EXTENSION_COMMAND_TYPES = frozenset(
    {
        "extension/register",
        "extension/submit",
        "extension/certify",
        "extension/approve",
        "extension/reject",
        "extension/publish",
        "extension/install",
        "extension/activate",
        "extension/shadow",
        "extension/invoke",
        "extension/measure",
        "extension/degrade",
        "extension/suspend",
        "extension/resume",
        "extension/deprecate",
        "extension/archive",
    }
)

#: The merged public contracts this domain actually consumes (its declared
#: WORK-020 dependency surfaces plus the canonical core and the kernel).
CONSUMED_SURFACES = frozenset(
    {"core", "transition", "capability", "safety", "evidence", "simulation"}
)

#: Default marketplace operators authorized to drive extension commands.
DEFAULT_AUTHORIZED_ACTORS = frozenset({"principal/marketplace-operator"})


class ExtensionLifecycleState(StrEnum):
    """The frozen 13-state extension lifecycle (extensions.md).

    ``DRAFT → SANDBOX → TESTED → SUBMITTED → SECURITY_REVIEW →
    POLICY_REVIEW → PUBLISHED → INSTALLED → ACTIVE → DEGRADED →
    SUSPENDED → DEPRECATED → ARCHIVED``.

    The manifest object owns the head of the chain (DRAFT..PUBLISHED plus
    the terminal DEPRECATED/ARCHIVED); the instance object owns the tail
    (INSTALLED..ARCHIVED). The union is exactly the frozen chain and the
    ``install`` command realizes the PUBLISHED→INSTALLED edge by creating
    the instance object.
    """

    DRAFT = "DRAFT"
    SANDBOX = "SANDBOX"
    TESTED = "TESTED"
    SUBMITTED = "SUBMITTED"
    SECURITY_REVIEW = "SECURITY_REVIEW"
    POLICY_REVIEW = "POLICY_REVIEW"
    PUBLISHED = "PUBLISHED"
    INSTALLED = "INSTALLED"
    ACTIVE = "ACTIVE"
    DEGRADED = "DEGRADED"
    SUSPENDED = "SUSPENDED"
    DEPRECATED = "DEPRECATED"
    ARCHIVED = "ARCHIVED"


MANIFEST_LIFECYCLE_STATES = frozenset(
    {
        ExtensionLifecycleState.DRAFT,
        ExtensionLifecycleState.SANDBOX,
        ExtensionLifecycleState.TESTED,
        ExtensionLifecycleState.SUBMITTED,
        ExtensionLifecycleState.SECURITY_REVIEW,
        ExtensionLifecycleState.POLICY_REVIEW,
        ExtensionLifecycleState.PUBLISHED,
        ExtensionLifecycleState.DEPRECATED,
        ExtensionLifecycleState.ARCHIVED,
    }
)

INSTANCE_LIFECYCLE_STATES = frozenset(
    {
        ExtensionLifecycleState.INSTALLED,
        ExtensionLifecycleState.ACTIVE,
        ExtensionLifecycleState.DEGRADED,
        ExtensionLifecycleState.SUSPENDED,
        ExtensionLifecycleState.DEPRECATED,
        ExtensionLifecycleState.ARCHIVED,
    }
)

#: The full frozen transition table over the 13 states. Review rejections
#: return a manifest to the sandbox; every non-archived state may be
#: deprecated; every non-archived state may be archived (terminal).
LIFECYCLE_TRANSITIONS: Mapping[ExtensionLifecycleState, frozenset[ExtensionLifecycleState]] = {
    ExtensionLifecycleState.DRAFT: frozenset(
        {ExtensionLifecycleState.SANDBOX, ExtensionLifecycleState.DEPRECATED, ExtensionLifecycleState.ARCHIVED}
    ),
    ExtensionLifecycleState.SANDBOX: frozenset(
        {ExtensionLifecycleState.TESTED, ExtensionLifecycleState.DEPRECATED, ExtensionLifecycleState.ARCHIVED}
    ),
    ExtensionLifecycleState.TESTED: frozenset(
        {ExtensionLifecycleState.SUBMITTED, ExtensionLifecycleState.DEPRECATED, ExtensionLifecycleState.ARCHIVED}
    ),
    ExtensionLifecycleState.SUBMITTED: frozenset(
        {
            ExtensionLifecycleState.SECURITY_REVIEW,
            ExtensionLifecycleState.SANDBOX,
            ExtensionLifecycleState.DEPRECATED,
            ExtensionLifecycleState.ARCHIVED,
        }
    ),
    ExtensionLifecycleState.SECURITY_REVIEW: frozenset(
        {
            ExtensionLifecycleState.POLICY_REVIEW,
            ExtensionLifecycleState.SANDBOX,
            ExtensionLifecycleState.DEPRECATED,
            ExtensionLifecycleState.ARCHIVED,
        }
    ),
    ExtensionLifecycleState.POLICY_REVIEW: frozenset(
        {
            ExtensionLifecycleState.PUBLISHED,
            ExtensionLifecycleState.SANDBOX,
            ExtensionLifecycleState.DEPRECATED,
            ExtensionLifecycleState.ARCHIVED,
        }
    ),
    ExtensionLifecycleState.PUBLISHED: frozenset(
        {
            # The install edge PUBLISHED -> INSTALLED is realized by the
            # install command creating the instance object (the frozen
            # chain is one continuous lifecycle across the manifest head
            # and the instance tail).
            ExtensionLifecycleState.INSTALLED,
            ExtensionLifecycleState.DEPRECATED,
            ExtensionLifecycleState.ARCHIVED,
        }
    ),
    ExtensionLifecycleState.INSTALLED: frozenset(
        {ExtensionLifecycleState.ACTIVE, ExtensionLifecycleState.DEPRECATED, ExtensionLifecycleState.ARCHIVED}
    ),
    ExtensionLifecycleState.ACTIVE: frozenset(
        {
            ExtensionLifecycleState.DEGRADED,
            ExtensionLifecycleState.SUSPENDED,
            ExtensionLifecycleState.DEPRECATED,
            ExtensionLifecycleState.ARCHIVED,
        }
    ),
    ExtensionLifecycleState.DEGRADED: frozenset(
        {
            ExtensionLifecycleState.ACTIVE,
            ExtensionLifecycleState.SUSPENDED,
            ExtensionLifecycleState.DEPRECATED,
            ExtensionLifecycleState.ARCHIVED,
        }
    ),
    ExtensionLifecycleState.SUSPENDED: frozenset(
        {ExtensionLifecycleState.ACTIVE, ExtensionLifecycleState.DEPRECATED, ExtensionLifecycleState.ARCHIVED}
    ),
    ExtensionLifecycleState.DEPRECATED: frozenset({ExtensionLifecycleState.ARCHIVED}),
    ExtensionLifecycleState.ARCHIVED: frozenset(),
}


class ExtensionArtifactKind(StrEnum):
    """Closed vocabulary of the frozen composition artifacts (extensions.md).

    Extensions exchange typed artifacts such as DemandSignal,
    RouteProposal, QuoteSet, RiskAssessment, ComplianceProof,
    Attestation, ExecutionAdapter and SettlementInstruction. Artifacts
    carry schema version, producer, provenance, expiry, confidence,
    dependencies and risk.
    """

    DEMAND_SIGNAL = "demand_signal"
    ROUTE_PROPOSAL = "route_proposal"
    QUOTE_SET = "quote_set"
    RISK_ASSESSMENT = "risk_assessment"
    COMPLIANCE_PROOF = "compliance_proof"
    ATTESTATION = "attestation"
    EXECUTION_ADAPTER = "execution_adapter"
    SETTLEMENT_INSTRUCTION = "settlement_instruction"

    @classmethod
    def parse(cls, value: object) -> "ExtensionArtifactKind":
        from ._validation import parse_enum

        return parse_enum("extension artifact kind", cls, value)  # type: ignore[return-value]


class ExtensionPermission(StrEnum):
    """Closed vocabulary of sandboxed runtime permissions.

    Permissions are the ONLY resources a sandboxed invocation may request
    beyond its declared typed inputs. The architecture-forbidden powers
    (ledger mutation, finality change, authority grant, compliance
    bypass, undeclared resource access) are NOT members of this closed
    vocabulary and claiming them fails closed at manifest validation.
    """

    OBSERVE_PROTOCOL_STATE = "observe_protocol_state"
    READ_MARKET_DATA = "read_market_data"
    READ_COUNTERPARTY_DIRECTORY = "read_counterparty_directory"

    @classmethod
    def parse(cls, value: object) -> "ExtensionPermission":
        from ._validation import parse_enum

        return parse_enum("extension permission", cls, value)  # type: ignore[return-value]


#: Powers extensions can never hold (extensions.md "Security"; constitution
#: invariants 6 and 16). Claiming any of them fails closed with an
#: explicit reason — they are not members of the closed permission
#: vocabulary, and this list gives the distinct error message.
FORBIDDEN_PERMISSIONS = frozenset(
    {
        "ledger_write",
        "finality_modify",
        "authority_grant",
        "compliance_bypass",
        "undeclared_resource_access",
    }
)


class ExtensionCapability(StrEnum):
    """Closed vocabulary of marketplace capabilities extensions provide.

    The four shared names mirror the capability domain's frozen
    ``CapabilityKind`` vocabulary exactly (WORK-009 dependency — see
    :data:`CAPABILITY_DOMAIN_MIRROR`); the composition-aligned names
    follow the frozen artifact kinds.
    """

    ROUTE_PROPOSAL = "route_proposal"
    RISK_ASSESSMENT = "risk_assessment"
    COMPLIANCE_VERIFICATION = "compliance_verification"
    PAYMENT_EXECUTION = "payment_execution"
    SETTLEMENT = "settlement"
    LIQUIDITY_PROVISION = "liquidity_provision"
    QUOTE_PROVISION = "quote_provision"
    ATTESTATION = "attestation"

    @classmethod
    def parse(cls, value: object) -> "ExtensionCapability":
        from ._validation import parse_enum

        return parse_enum("extension capability", cls, value)  # type: ignore[return-value]


#: The capability-domain mirror: every capability name that also exists in
#: ``src.capability.CapabilityKind`` must equal it exactly. A static test
#: pins this so the two closed vocabularies can never drift.
CAPABILITY_DOMAIN_MIRROR: Mapping[ExtensionCapability, CapabilityKind] = {
    ExtensionCapability.COMPLIANCE_VERIFICATION: CapabilityKind.COMPLIANCE_VERIFICATION,
    ExtensionCapability.PAYMENT_EXECUTION: CapabilityKind.PAYMENT_EXECUTION,
    ExtensionCapability.SETTLEMENT: CapabilityKind.SETTLEMENT,
    ExtensionCapability.LIQUIDITY_PROVISION: CapabilityKind.LIQUIDITY_PROVISION,
}


class MonitoringLevel(StrEnum):
    """Closed vocabulary of tier monitoring levels (ordered strength)."""

    STANDARD = "STANDARD"
    ENHANCED = "ENHANCED"
    INTENSIVE = "INTENSIVE"

    @classmethod
    def parse(cls, value: object) -> "MonitoringLevel":
        from ._validation import parse_enum

        return parse_enum("monitoring level", cls, value)  # type: ignore[return-value]

    @property
    def strength(self) -> int:
        return _MONITORING_STRENGTH[self]


_MONITORING_STRENGTH: Mapping[MonitoringLevel, int] = {
    MonitoringLevel.STANDARD: 0,
    MonitoringLevel.ENHANCED: 1,
    MonitoringLevel.INTENSIVE: 2,
}


#: Minimum financial collateral (minor units) per authority tier
#: (extensions.md: higher tiers require stronger collateral). R0-R2 are
#: observation/analysis/proposal tiers with no reserved value at risk.
TIER_MINIMUM_COLLATERAL_MINOR: Mapping[str, int] = {
    "R0": 0,
    "R1": 0,
    "R2": 0,
    "R3": 1_000_000,
    "R4": 5_000_000,
    "R5": 25_000_000,
}

#: Minimum monitoring level per authority tier (None = not required).
TIER_MINIMUM_MONITORING: Mapping[str, MonitoringLevel | None] = {
    "R0": None,
    "R1": None,
    "R2": MonitoringLevel.STANDARD,
    "R3": MonitoringLevel.STANDARD,
    "R4": MonitoringLevel.ENHANCED,
    "R5": MonitoringLevel.INTENSIVE,
}

#: Maximum declared single-exposure risk limit (minor units) per tier.
TIER_MAXIMUM_EXPOSURE_MINOR: Mapping[str, int] = {
    "R0": 0,
    "R1": 0,
    "R2": 0,
    "R3": 10_000_000,
    "R4": 100_000_000,
    "R5": 1_000_000_000,
}

#: Extension authority tiers R0-R5 (registry-listed authority classes).
EXTENSION_AUTHORITY_TIERS = frozenset(
    {"R0", "R1", "R2", "R3", "R4", "R5"}
)


class PricingModel(StrEnum):
    """Closed vocabulary of marketplace pricing models."""

    FIXED = "fixed"
    PER_INVOCATION = "per_invocation"
    REVENUE_SHARE = "revenue_share"

    @classmethod
    def parse(cls, value: object) -> "PricingModel":
        from ._validation import parse_enum

        return parse_enum("pricing model", cls, value)  # type: ignore[return-value]


class ContributionMetric(StrEnum):
    """Closed vocabulary of contribution metrics.

    Activity volume is deliberately NOT a member: activity volume alone
    is not a valid contribution measure (extensions.md "Economics").
    Every metric is an outcome dimension comparable between a
    counterfactual baseline and a treatment measurement.
    """

    FULFILLMENT_QUALITY = "fulfillment_quality"
    COST_SAVINGS_MINOR = "cost_savings_minor"
    LATENCY_IMPROVEMENT_MS = "latency_improvement_ms"
    RISK_REDUCTION_BPS = "risk_reduction_bps"

    @classmethod
    def parse(cls, value: object) -> "ContributionMetric":
        from ._validation import parse_enum

        return parse_enum("contribution metric", cls, value)  # type: ignore[return-value]


CONTRIBUTION_METRICS = frozenset({metric.value for metric in ContributionMetric})


class InvocationEffectMode(StrEnum):
    """Closed vocabulary of invocation effect semantics.

    Extensions never produce production effects themselves: invocations
    either produce candidate typed artifacts for the protocol to consume
    through its own authoritative paths (``RECORDED``) or are measured
    without any application (``SHADOWED`` — live observation, non-
    production effects, simulation.md mode SHADOW).
    """

    RECORDED = "recorded"
    SHADOWED = "shadowed"

    @classmethod
    def parse(cls, value: object) -> "InvocationEffectMode":
        from ._validation import parse_enum

        return parse_enum("invocation effect mode", cls, value)  # type: ignore[return-value]


# -- distinct typed economic quantities (extensions.md "Economics") --------


@dataclass(frozen=True, slots=True)
class ResourceCredits:
    """Sandbox resource consumption credits (quantity 1: metered usage).

    Distinct from real economic earnings and from financial collateral:
    the three are separate typed quantities and can never be conflated.
    """

    credits: int

    def __post_init__(self) -> None:
        require_int("resource credits", self.credits, minimum=0)

    def to_dict(self) -> dict[str, int]:
        return {"resource_credits": self.credits}

    @classmethod
    def from_dict(cls, value: object) -> "ResourceCredits":
        from ._validation import exact_fields

        exact_fields("resource credits", value, {"resource_credits"})
        assert isinstance(value, dict)
        return cls(credits=value["resource_credits"])


@dataclass(frozen=True, slots=True)
class EconomicEarnings:
    """Real economic earnings in exact minor units of the declared asset.

    Earnings are measured rewards based on VERIFIED incremental
    contribution — never on activity volume. This is a record, not a
    ledger posting: the extension domain never mutates authoritative
    value state.
    """

    amount_minor: int
    asset: str

    def __post_init__(self) -> None:
        require_int("economic earnings", self.amount_minor, minimum=0)
        require_text("economic earnings asset", self.asset)

    def to_dict(self) -> dict[str, object]:
        return {"earnings_minor": self.amount_minor, "asset": self.asset}

    @classmethod
    def from_dict(cls, value: object) -> "EconomicEarnings":
        from ._validation import exact_fields

        exact_fields("economic earnings", value, {"earnings_minor", "asset"})
        assert isinstance(value, dict)
        return cls(amount_minor=value["earnings_minor"], asset=value["asset"])


@dataclass(frozen=True, slots=True)
class FinancialCollateral:
    """Financial collateral pledged for higher authority tiers.

    Distinct typed quantity from resource credits and from real earnings.
    A pledge is a typed manifest field required (fail closed) for tiers
    R3+; the runtime never moves it — value stays with the authoritative
    value domain.
    """

    amount_minor: int
    asset: str

    def __post_init__(self) -> None:
        require_int("financial collateral", self.amount_minor, minimum=0)
        require_text("financial collateral asset", self.asset)

    def to_dict(self) -> dict[str, object]:
        return {"collateral_minor": self.amount_minor, "asset": self.asset}

    @classmethod
    def from_dict(cls, value: object) -> "FinancialCollateral":
        from ._validation import exact_fields

        exact_fields("financial collateral", value, {"collateral_minor", "asset"})
        assert isinstance(value, dict)
        return cls(amount_minor=value["collateral_minor"], asset=value["asset"])


#: Resource credit units consumed by one completed invocation (base unit).
INVOCATION_BASE_CREDIT = 1

#: Additional resource credit units per canonical output artifact byte.
CREDIT_PER_BYTE = 1

#: Minimum successful sandbox invocations required before certification.
CERTIFY_MIN_SANDBOX_INVOCATIONS = 1

#: Risk band vocabulary re-export (owned by src.safety, WORK-017).
RISK_BANDS = frozenset({band.value for band in RiskBand})


def require_extension_tier(name: str, value: object) -> str:
    """Fail closed unless the authority class is an extension tier R0-R5."""
    if not isinstance(value, str) or value not in EXTENSION_AUTHORITY_TIERS:
        raise CoreValidationError(
            f"{name} must be one of the extension authority tiers "
            f"{sorted(EXTENSION_AUTHORITY_TIERS)} (registry authority classes; "
            "protocol A-classes are not extension tiers)"
        )
    return value


def require_confidence_bps(name: str, value: object) -> int:
    return require_int_in_range(name, value, 0, 10_000)


def parse_risk_band(name: str, value: object) -> RiskBand:
    from ._validation import parse_enum

    return parse_enum(name, RiskBand, value)
