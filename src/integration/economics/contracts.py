"""IG-004 gate contracts: identity, vocabulary and boundary constants.

The extension/agent economic integration gate
(``spec/integration-gates.md`` row IG-004: "extension/agent economic
integration | WORK-020, 021, 028") proves *agent + extension
composition, authority containment, simulation-first decision and
economic contribution* by composing ONLY already-merged
implementations:

* the WORK-020 extension runtime + capability marketplace (the real
  manifests, sandboxed invocations, grants and contribution
  measurement);
* the WORK-021 models/agents/decision-mediation surface (the real
  model registry lifecycle, bounded proposal mandates, hypothetical-only
  agent contexts, kernel-recorded route proposals and the
  simulation-first mediation);
* the WORK-028 IG-003 comparison authority (the merged public
  ``ClassifiedDifference`` diff walk classifying every residual
  cross-environment difference as a semantic divergence);
* the real merchant checkout record boundary (WORK-025) as the demand
  source of the composed scenario, and the merged money FX authority
  (WORK-006) for cross-currency conservation of the measured
  attribution.

This module declares the gate's typed, versioned identity and freezes
the vocabularies the composition uses. It introduces no domain
semantics of its own: every behavioral authority stays with the
consumed implementations.

Identity discipline:

* ``IG-004`` is the gate identifier listed in
  ``spec/integration-gates.md``; unknown gate ids fail closed
  everywhere. The IG-001/IG-002/IG-003/IG-005 gate ids stay unknown
  HERE on purpose (one validator per gate, no shared mutation of the
  merged sibling gates' contract surfaces — the house discipline of
  every integration subpackage).
* The gate projects NO new protocol-visible name: every registry-listed
  object type and event namespace it touches belongs to the consumed
  domain engines, which use the frozen registry exactly as registered.
* The two environments share their domain bindings (one domain, many
  environments — the frozen simulation contract's state model); only
  the environment identity, the extension runtime's environment mode
  and the world-observation epistemic class differ.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from src.core.errors import CoreValidationError

#: The identifier of this gate (spec/integration-gates.md, IG-004 row).
ECONOMICS_GATE_ID = "IG-004"

#: Typed, versioned public boundary version of the gate package.
ECONOMICS_API_VERSION = "v0.1"

#: Schema version of the gate's canonical economic-result representation.
ECONOMICS_SCHEMA_VERSION = 1

#: The gate identifiers this package knows how to execute.
KNOWN_ECONOMICS_GATES = frozenset({ECONOMICS_GATE_ID})

#: The only implementation roots the gate may import (AST-audited by
#: the contract suite). Anything else is a second authority or an
#: unmerged sibling and is forbidden. ``src.extensions`` is the merged
#: WORK-020 public boundary (the marketplace + runtime the gate
#: composes); ``src.agents`` is the merged WORK-021 public boundary
#: (models, mandates, proposals, mediation); ``src.merchant`` is the
#: merged WORK-025 record boundary (the demand source);
#: ``src.integration.parity`` is the merged WORK-028 IG-003 comparison
#: authority (the ClassifiedDifference diff walk this gate consumes);
#: ``src.money``/``src.value`` are the merged value/FX authorities the
#: economic-conservation checks consume; ``src.simulation`` is the
#: merged WORK-019 environment/mode/epistemic contract.
CONSUMED_SURFACES = (
    "src.agents",
    "src.core",
    "src.evidence",
    "src.extensions",
    "src.integration.parity",
    "src.merchant",
    "src.money",
    "src.simulation",
    "src.transition",
    "src.value",
)

# -- the two declared environments -------------------------------------------

#: The simulation world's environment identity (sandbox class: the
#: capability domain's frozen environment-class vocabulary).
SIMULATION_ENVIRONMENT_ID = "env/sandbox-ig004-economics"

#: The production-compatible world's environment identity (production
#: class: the extension runtime binds PRODUCTION mode — extensions
#: produce candidate artifacts for the protocol's own authoritative
#: paths, never production effects; the agent side stays
#: hypothetical-world-only in BOTH worlds — that asymmetry IS the
#: authority-containment proof).
PRODUCTION_COMPATIBLE_ENVIRONMENT_ID = "env/production-ig004-economics"

#: The ONE shared domain bindings (one domain, many environments).
EXTENSIONS_DOMAIN_ID = "domain/ig004-extensions"
AGENTS_DOMAIN_ID = "domain/ig004-agents"
MERCHANT_DOMAIN_ID = "domain/ig004-merchant"

# -- declared principals -------------------------------------------------------

#: The marketplace operator driving extension commands.
DEFAULT_ECONOMICS_ACTOR = "principal/ig004-marketplace-operator"

#: The actors authorized in the composed environments.
DEFAULT_AUTHORIZED_ACTORS = frozenset(
    {DEFAULT_ECONOMICS_ACTOR, "principal/ig004-payer"}
)

#: The governance-side mediator (mediation/select requires an
#: A-family registry authority class; distinct from every agent).
MEDIATION_ACTOR = "principal/ig004-ops-mediator"

#: The model developer and approver (A1 registry class holders).
MODEL_DEVELOPER = "principal/ig004-model-developer"
MODEL_APPROVER = "principal/ig004-model-approver"

#: The proposing agent (exactly the frozen R2 PROPOSE tier).
AGENT_PRINCIPAL = "principal/agent-ig004-advisor"

#: An execute-tier principal used by the escalation probe (R4).
ESCALATOR_PRINCIPAL = "principal/agent-ig004-escalator"

#: The merchant principal owning the demand checkout.
MERCHANT_ACTOR = "principal/merchant-ig004-acme"

#: The governance authority class of the agents-domain fixture table.
GOVERNANCE_AUTHORITY_CLASS = "A2"

#: The proposal authority class of the agent's bounded mandate — exactly
#: the frozen R2 PROPOSE tier of the merged agents domain (the gate
#: never grants an execute-tier class).
PROPOSAL_AUTHORITY_CLASS = "R2"

# -- declared fixture identities (deterministic, shared by both worlds) ------

#: The merchant checkout record id (the demand source).
MERCHANT_CHECKOUT_ID = "checkout/ig004-1"

#: The demand signal artifact id derived from the checkout.
DEMAND_ARTIFACT_ID = "extension-artifact/ig004-demand-1"

#: The REAL extension: a deterministic route-advisor provider.
EXTENSION_ID = "extension/ig004-route-advisor"

#: The code hash of the in-repo deterministic handler (declared data).
EXTENSION_CODE_HASH = "a" * 64

#: The installed instance + covering capability grant.
INSTANCE_ID = "extension-instance/ig004-route-advisor"
GRANT_ID = "extension-grant/ig004-route-advisor"

#: The deployed models backing the agent's proposals.
MODEL_COST_ID = "model/ig004-cost-model"
MODEL_RELIABILITY_ID = "model/ig004-reliability-model"

#: The bounded proposal mandate, the agent context and the proposals.
MANDATE_ID = "agent-mandate/ig004-1"
CONTEXT_ID = "agent/ig004-advisor-1"
PROPOSAL_ALPHA_ID = "agent-proposal/ig004-alpha-premium"
PROPOSAL_BRAVO_ID = "agent-proposal/ig004-bravo-economy"

#: The mediation session and the sealed decision.
MEDIATION_ID = "mediation/ig004-1"
DECISION_ID = "mediation-decision/ig004-1"

#: The treatment invocation + the sealed contribution measurements.
TREATMENT_INVOCATION_ID = "extension-invocation/ig004-treatment-1"
SHADOW_INVOCATION_ID = "extension-invocation/ig004-shadow-1"
SANDBOX_INVOCATION_ID = "extension-invocation/ig004-sandbox-1"
CONTRIBUTION_ID = "extension-contribution/ig004-treatment"
SHADOW_REMEASURE_ID = "extension-contribution/ig004-shadow"
UNVERIFIED_CONTRIBUTION_ID = "extension-contribution/ig004-unverified"

# -- the declared economic data (exact integers, shared by both worlds) ------

#: The merchant demand: 120,000.00 USD (minor units, scale 2).
DEMAND_VOLUME_MINOR = 12_000_000
DEMAND_ASSET = "USD"
DEMAND_SCALE = 2

#: The default (no-extension) premium route economics.
PREMIUM_FAMILY = "premium"
PREMIUM_COST_MINOR = 195_000
PREMIUM_LATENCY_MS = 120
PREMIUM_RELIABILITY_BPS = 9980

#: The extension-backed economy route economics (derived: the cost is
#: the default cost minus the extension's declared savings).
ECONOMY_FAMILY = "economy"
ECONOMY_LATENCY_MS = 480
ECONOMY_RELIABILITY_BPS = 9650

#: The deterministic mediation policy (explicit basis-point weights).
POLICY_ID = "policy/ig004-mediation"
POLICY_COST_WEIGHT_BPS = 6000
POLICY_LATENCY_WEIGHT_BPS = 1000
POLICY_RELIABILITY_WEIGHT_BPS = 3000

#: The extension pricing: 10% revenue share of verified savings.
REVENUE_SHARE_BPS = 1000
PRICING_ASSET = "USD"

#: The declared USD->GHS rate of the conservation scenario (the money
#: domain's exact FX authority; GHS scale 2 like USD).
FX_USD_GHS_NUMERATOR = 15
FX_USD_GHS_DENOMINATOR = 1

# -- declared instants (no clock reads anywhere) ------------------------------

T_REGISTER = "2026-09-04T00:10:00Z"
T_SANDBOX = "2026-09-04T00:12:00Z"
T_REVIEW = "2026-09-04T00:14:00Z"
T_INSTALL = "2026-09-04T00:16:00Z"
T_TREATMENT = "2026-09-04T00:18:00Z"
T_MODELS = "2026-09-04T00:20:00Z"
T_MANDATE = "2026-09-04T00:22:00Z"
T_OUTPUT = "2026-09-04T00:23:00Z"
T_PROPOSE = "2026-09-04T00:24:00Z"
T_MEDIATE = "2026-09-04T00:25:00Z"
T_MEASURE = "2026-09-04T00:26:00Z"
T_SHADOW = "2026-09-04T00:27:00Z"
T_EXPIRY = "2026-09-05T00:00:00Z"


class EconomicRole(StrEnum):
    """The closed vocabulary of the two composed environment roles."""

    SIMULATION = "simulation"
    PRODUCTION_COMPATIBLE = "production-compatible"

    @classmethod
    def parse(cls, value: object) -> "EconomicRole":
        if not isinstance(value, cls):
            raise CoreValidationError(
                f"economic role must be an EconomicRole member, got {value!r}"
            )
        return value


@dataclass(frozen=True, slots=True)
class EconomicsNormalizationRule:
    """One declared normalization rule of the semantic comparison layer.

    A rule is field-bound (it names exactly one field name), documented
    (why the field legitimately differs between the environments),
    exact (the transformation rule) and justified (why the
    normalization cannot erase semantic differences). Broad "ignore
    field" strategies are forbidden: every rule must prove it compares
    the semantics. This mirrors the merged IG-003 rule discipline; the
    registries are separate because the compared surfaces are separate
    (lifecycle parity there, composed economics here).
    """

    rule_id: str
    field: str
    reason: str
    rule: str
    safety_argument: str

    def __post_init__(self) -> None:
        for name in ("rule_id", "field", "reason", "rule", "safety_argument"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise CoreValidationError(
                    f"economics normalization rule {self.rule_id!r} requires a "
                    f"non-empty {name}"
                )


#: The closed set of field names excluded from the cross-environment
#: byte comparison because they are environment-bound derived values.
#: Each entry carries its own rule below with the full justification;
#: their covered CONTENT is compared field-by-field after
#: normalization, and their binding correctness is proven per world by
#: the invariant battery (seals verify on every trusted decode in the
#: consumed domains).
ECONOMICS_ENV_BOUND_FIELDS = frozenset(
    {
        "integrity_hash",
        "payload_hash",
        "state_before",
        "state_after",
    }
)

#: The frozen normalization registry: exactly the fields that may
#: legitimately differ between the simulation and the
#: production-compatible execution of the SAME declared economic
#: composition. Every other difference at every other path is a
#: semantic divergence classified by the merged IG-003 diff authority
#: and fails the gate. The registry is pinned by the contract suite (a
#: mutation of the registry is detectable by the discrimination
#: battery).
ECONOMICS_NORMALIZATION_RULES: tuple[EconomicsNormalizationRule, ...] = (
    EconomicsNormalizationRule(
        rule_id="environment-identity",
        field="environment_id",
        reason=(
            "the two composed executions intentionally run in two distinct "
            "environments; the frozen one-machine/many-worlds contract expects "
            "the same protocol transitions ACROSS environments with the "
            "environment identity being the declared separator"
        ),
        rule=(
            "wherever the field name environment_id appears at any depth, "
            "validate the value is exactly one of the two declared IG-004 "
            "economics environment ids (fail closed on any foreign value) and "
            "replace it with the neutral token {ENVIRONMENT}"
        ),
        safety_argument=(
            "environment ids never enter amounts, contribution values, "
            "transition states, authority classes or epistemic classes; a "
            "foreign value is visible to the projection as a fail-closed "
            "rejection instead of a normalization"
        ),
    ),
    EconomicsNormalizationRule(
        rule_id="extension-runtime-mode",
        field="environment_mode",
        reason=(
            "the extension invocation records carry the runtime's environment "
            "mode, which is the declared world binding: SIMULATION in the "
            "sandbox world and PRODUCTION in the production-compatible world "
            "(the extension manifest declares support for both and the same "
            "code runs in each)"
        ),
        rule=(
            "wherever the field name environment_mode appears with a string "
            "value, validate the value is exactly the owning world's declared "
            "mode (fail closed on any other value, including SHADOW) and "
            "replace it with the neutral token {MODE}"
        ),
        safety_argument=(
            "the mode is the environment binding, not an economic semantic: "
            "the invocation economics (capability, inputs, outputs, credits) "
            "are compared field-by-field and are identical; the mediation "
            "substrate mode stays SIMULATION in both worlds and is compared "
            "verbatim as content"
        ),
    ),
    EconomicsNormalizationRule(
        rule_id="envelope-seal",
        field="integrity_hash",
        reason=(
            "every durable record's seal is computed by the single canonical "
            "hash authority over canonical content that embeds the "
            "environment identity, so the seal bytes legitimately differ "
            "between environments"
        ),
        rule=(
            "exclude the integrity_hash value from the cross-environment byte "
            "comparison; seal integrity is proven per world (every consumed "
            "domain verifies seals on every trusted decode, and the invariant "
            "battery re-runs on both worlds), and the semantic content the "
            "seal covers is compared field-by-field after normalization"
        ),
        safety_argument=(
            "the seal is a derived value over the very content the projection "
            "compares; removing semantic content changes the compared fields, "
            "and per-world tampering is caught by the domain seals themselves"
        ),
    ),
    EconomicsNormalizationRule(
        rule_id="kernel-event-payload-digest",
        field="payload_hash",
        reason=(
            "the kernel journal events pin the digest of their transition "
            "payload, whose envelopes embed the environment identity, so the "
            "digests legitimately differ between environments"
        ),
        rule=(
            "exclude the payload_hash value from the cross-environment byte "
            "comparison; the events' semantic tuples (event type, command id, "
            "actor, authority, occurred_at, logical_time) are compared as "
            "content and the journal is proven append-only per world"
        ),
        safety_argument=(
            "the digest is a derived value over environment-bound envelope "
            "content; the semantic event identity is the compared tuple"
        ),
    ),
    EconomicsNormalizationRule(
        rule_id="composed-state-checkpoint-before",
        field="state_before",
        reason=(
            "the gate's stage journal records composed-state digests before "
            "and after every stage; the composed digest embeds the "
            "environment identity by construction"
        ),
        rule=(
            "exclude the state_before digests from the cross-environment byte "
            "comparison; the stage TUPLES (stage, role, domain, command_id, "
            "requested_at, outcome) are compared and each journal's chaining "
            "and honesty are proven per world by the invariant battery"
        ),
        safety_argument=(
            "the state-machine semantics are the compared stage tuples plus "
            "the compared record states; the checkpoints are derived values "
            "over the environment-bound composed state"
        ),
    ),
    EconomicsNormalizationRule(
        rule_id="composed-state-checkpoint-after",
        field="state_after",
        reason=(
            "identical to the state_before rule: the stage journal's "
            "after-checkpoints are derived digests over environment-bound "
            "composed state"
        ),
        rule=(
            "exclude the state_after digests from the cross-environment byte "
            "comparison; the stage TUPLES are compared"
        ),
        safety_argument=(
            "derived checkpoints over environment-bound composed state, "
            "never compared semantics"
        ),
    ),
)

#: The closed vocabulary of the authority-containment probes (the
#: discrimination surface of the gate: every probe must be CONTAINED —
#: rejected/failed closed — with the composed state byte-unchanged).
CONTAINMENT_PROBES = frozenset(
    {
        "tier-escalation-r5",
        "forbidden-permission",
        "undeclared-resource",
        "undeclared-capability",
        "execute-tier-proposal",
        "out-of-scope-family",
        "production-agent-context",
        "observed-model-output",
        "volume-metric",
        "suspended-model",
        "mandate-authority-class",
        "agent-self-mediation",
        "foreign-domain-command",
    }
)


def validate_economics_gate_id(gate_id: object) -> str:
    """Fail closed unless ``gate_id`` names the economic integration gate."""
    if not isinstance(gate_id, str) or gate_id not in KNOWN_ECONOMICS_GATES:
        raise CoreValidationError(
            f"unknown economics gate {gate_id!r}; this package executes only "
            f"{sorted(KNOWN_ECONOMICS_GATES)}"
        )
    return gate_id
