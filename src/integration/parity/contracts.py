"""IG-003 gate contracts: identity, vocabulary and boundary constants.

The simulation parity integration gate (``spec/integration-gates.md`` row
IG-003) proves *identical protocol semantics across simulation and
production-compatible environments* by composing ONLY already-merged
implementations: the WORK-019 simulation semantics (the frozen
one-machine/many-worlds vocabulary: environment modes, the deterministic
world-adapter boundary, the frozen mode→epistemic binding), the WORK-026
IG-001 integration conventions and the WORK-027 IG-002 fulfillment
lifecycle harness over the real domain engines. This module declares the
gate's typed, versioned identity and freezes the vocabularies the parity
composition uses. It introduces no domain semantics of its own: every
behavioral authority stays with the consumed implementations.

Identity discipline:

* ``IG-003`` is the gate identifier listed in
  ``spec/integration-gates.md``; unknown gate ids fail closed everywhere.
  The IG-001 and IG-002 gate ids stay unknown HERE on purpose (one
  validator per gate, no shared mutation of the merged sibling gates'
  contract surfaces).
* The gate projects NO new protocol-visible name: every registry-listed
  object type and event namespace it touches belongs to the consumed
  domain engines, which use the frozen registry exactly as registered.
* The two environments share ONE domain binding (the one-domain,
  many-environments model of the frozen simulation contract); only the
  environment identity, the rail adapter identity, the declared rail
  fidelity class and the world-observation epistemic class differ.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from src.core.errors import CoreValidationError

#: The identifier of this gate (spec/integration-gates.md, IG-003 row).
PARITY_GATE_ID = "IG-003"

#: Typed, versioned public boundary version of the gate package.
PARITY_API_VERSION = "v0.1"

#: Schema version of the gate's canonical parity-result representation.
PARITY_SCHEMA_VERSION = 1

#: The gate identifiers this package knows how to execute.
KNOWN_PARITY_GATES = frozenset({PARITY_GATE_ID})

#: The only implementation roots the gate may import (AST-audited by the
#: contract suite). Anything else is a second authority or an unmerged
#: sibling and is forbidden. ``src.integration.lifecycle`` is the merged
#: WORK-027 public boundary (the composed lifecycle harness the gate
#: executes in both environments); ``src.simulation`` is the merged
#: WORK-019 public boundary (the deterministic world-adapter semantics
#: both environment rails consume).
CONSUMED_SURFACES = (
    "src.core",
    "src.transition",
    "src.evidence",
    "src.capability",
    "src.interoperability",
    "src.execution",
    "src.clearing",
    "src.settlement",
    "src.simulation",
    "src.integration.lifecycle",
)

#: The simulation world's environment identity (sandbox class: the
#: capability domain's frozen environment-class vocabulary requires
#: sandbox-environment capabilities to declare simulation support, which
#: the declared world's capabilities do).
SIMULATION_ENVIRONMENT_ID = "env/sandbox-ig003-simulation"

#: The production-compatible world's environment identity (production
#: class: production-environment capabilities must declare production
#: support, which the same declared capabilities do — the environment
#: class discipline itself is part of the compared semantics).
PRODUCTION_COMPATIBLE_ENVIRONMENT_ID = "env/production-ig003-compatible"

#: The ONE shared domain binding of both worlds (one domain, many
#: environments — the frozen simulation contract's state model).
PARITY_DOMAIN_ID = "domain/ig003-parity"

#: The simulation world's rail adapter identity (declared contract).
SIMULATION_ADAPTER_ID = "interoperability/adapter/ig003-simulation-rail"

#: The production-compatible world's rail adapter identity.
PRODUCTION_ADAPTER_ID = "interoperability/adapter/ig003-production-rail"

#: Provider-issued native-reference prefixes: the rails issue references
#: from their own environment's prefix plus the idempotency key, exactly
#: as the IG-002 local deterministic rail derives references from
#: declared data (environment-specific issuer identity, semantic suffix).
SIMULATION_NATIVE_PREFIX = "ig003-simulation/"
PRODUCTION_NATIVE_PREFIX = "ig003-production/"

#: The declared instant both worlds' rail observations are recorded at
#: (declared data; never a clock read). The SAME instant in both worlds:
#: the declared world outcomes are semantically identical, so the world
#: observations differ only in their epistemic class.
PARITY_WORLD_OBSERVATION_AS_OF = "2026-09-04T00:36:30Z"

#: The default gate actor and authorized actors of the composed
#: environments (mirroring the IG-002 gate convention).
DEFAULT_PARITY_ACTOR = "principal/ig003-ops"
DEFAULT_AUTHORIZED_ACTORS = frozenset(
    {"principal/ig003-ops", "principal/payer-ig003"}
)

#: The canonical payer/payee of the parity scenarios (declared data).
PARITY_PAYER = "principal/payer-ig003"
PARITY_PAYEE = "principal/merchant-42"

#: The canonical scenario amount (100.00 USD, minor units, exact integer).
PARITY_AMOUNT_MINOR = 10000


class WorldRole(StrEnum):
    """The closed vocabulary of the two compared environment roles."""

    SIMULATION = "simulation"
    PRODUCTION_COMPATIBLE = "production-compatible"

    @classmethod
    def parse(cls, value: object) -> "WorldRole":
        if not isinstance(value, cls):
            raise CoreValidationError(
                f"world role must be a WorldRole member, got {value!r}"
            )
        return value


@dataclass(frozen=True, slots=True)
class NormalizationRule:
    """One declared normalization rule of the semantic comparison layer.

    A rule is field-bound (it names exactly one field name), documented
    (why the field legitimately differs between the environments), exact
    (the transformation rule) and justified (why the normalization cannot
    erase semantic differences). Broad "ignore field" strategies are
    forbidden: every rule must prove it compares the semantics.
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
                    f"normalization rule {self.rule_id!r} requires a non-empty "
                    f"{name}"
                )


#: The closed set of digest-valued field names excluded from the
#: cross-environment byte comparison because they are environment-bound
#: derived values: each one is a seal or digest binding computed OVER
#: canonical content that legitimately embeds the environment identity
#: (record envelopes, provider-issued references, adapter identity).
#: Their semantics are proven PER WORLD — the composed invariant battery
#: (WORK-027) verifies every binding points at exactly the sealed record
#: it claims, and this gate's parity battery re-runs it on both worlds —
#: while the parity comparison proves the semantic CONTENT those digests
#: cover is identical after normalization. Each field below carries its
#: own NormalizationRule entry with the full justification.
ENV_BOUND_DIGEST_FIELDS = frozenset(
    {
        "integrity_hash",
        "plan_digest",
        "source_digest",
        "observation_digest",
        "observation_digests",
        "subject_request_digest",
        "evidence_digest",
        "request_digest",
        "obligation_digest",
        "instructions_digest",
        "settlement_digest",
        "digest",
        "state_before",
        "state_after",
    }
)

#: The frozen normalization registry: exactly the fields that may differ
#: legitimately between the simulation and the production-compatible
#: execution of the SAME declared scenario, with per-field rules. Every
#: other difference at every other path is a semantic divergence and
#: fails the gate. The registry is consumed by the projection layer and
#: pinned by the contract suite (a mutation of the registry is detectable
#: by the discrimination battery).
NORMALIZATION_RULES: tuple[NormalizationRule, ...] = (
    NormalizationRule(
        rule_id="environment-identity",
        field="environment_id",
        reason=(
            "the two compared executions intentionally run in two distinct "
            "environments; the frozen parity invariant expects protocol "
            "transitions to be identical ACROSS environments, with the "
            "environment identity being the declared separator"
        ),
        rule=(
            "wherever the field name environment_id appears at any depth, "
            "validate the value is exactly one of the two declared world "
            "environment ids (fail closed on any foreign value) and replace "
            "it with the neutral token {ENVIRONMENT}"
        ),
        safety_argument=(
            "environment ids never enter amounts, states, transitions, "
            "authorization decisions or evidence classes; a value change "
            "here is visible to the projection as a foreign id that fails "
            "closed instead of normalizing"
        ),
    ),
    NormalizationRule(
        rule_id="rail-adapter-identity",
        field="adapter_id",
        reason=(
            "each world binds its own declared rail adapter contract "
            "(SIMULATION vs PRODUCTION fidelity over the same typed ports); "
            "the adapter identity is transport-level environment metadata"
        ),
        rule=(
            "wherever the field name adapter_id appears, validate the value "
            "is exactly one of the two declared parity adapter ids (fail "
            "closed on any foreign value) and replace it with the neutral "
            "token {RAIL_ADAPTER}"
        ),
        safety_argument=(
            "the adapter identity carries no lifecycle semantics; the effect "
            "types, status vocabulary and typed port protocol are identical "
            "across the two declared adapters and are compared as content"
        ),
    ),
    NormalizationRule(
        rule_id="provider-issued-reference",
        field="native_reference",
        reason=(
            "provider-issued reference ids are environment-specific: each "
            "rail issues references from its own environment prefix plus the "
            "idempotency key, exactly like the IG-002 sandbox rails"
        ),
        rule=(
            "wherever the field name native_reference appears with a string "
            "value, require the exact declared shape "
            "ig003-(simulation|production)/<idempotency key> (fail closed on "
            "any other shape) and replace the environment prefix with the "
            "neutral token rail/, preserving the full idempotency-key suffix; "
            "None values stay None"
        ),
        safety_argument=(
            "the preserved suffix pins which idempotency key's effect the "
            "reference belongs to; a mutated or fabricated reference either "
            "breaks the declared shape (fail closed) or changes the compared "
            "suffix (divergence)"
        ),
    ),
    NormalizationRule(
        rule_id="envelope-seal",
        field="integrity_hash",
        reason=(
            "every durable record's seal is computed by the single canonical "
            "hash authority over canonical content that embeds the "
            "environment identity and provider-issued references, so the "
            "seal bytes legitimately differ between environments"
        ),
        rule=(
            "exclude the envelope integrity_hash value from the "
            "cross-environment byte comparison; seal integrity is proven per "
            "world (every consumed domain verifies seals on every trusted "
            "decode, and the composed invariant battery re-runs on both "
            "worlds), and the semantic content the seal covers is compared "
            "field-by-field after normalization"
        ),
        safety_argument=(
            "the seal is a derived value over the very content the "
            "projection compares; removing semantic content changes the "
            "compared fields, and per-world tampering is caught by the "
            "domain seals themselves"
        ),
    ),
    NormalizationRule(
        rule_id="compiler-plan-digest",
        field="plan_digest",
        reason=(
            "the compiler's plan digest covers the compiled plan content, "
            "whose hop projections embed the environment identity"
        ),
        rule=(
            "exclude plan_digest from the cross-environment byte "
            "comparison; determinism of compilation is proven per world "
            "(the IG-002 replay contract recompiles and compares plan "
            "digests inside one environment) and the plan content is "
            "compared field-by-field after normalization"
        ),
        safety_argument=(
            "the plan's payments, routes, amounts and states are compared "
            "directly; only the derived digest over environment-bound "
            "content is excluded"
        ),
    ),
    NormalizationRule(
        rule_id="source-seal-binding",
        field="source_digest",
        reason=(
            "obligation and netting records pin the seal of their sealed "
            "authority (execution evidence or netting statement), and seals "
            "are environment-bound"
        ),
        rule=(
            "exclude source_digest from the cross-environment byte "
            "comparison; the authority-routing invariant (run per world) "
            "proves each binding points at exactly the sealed record of its "
            "declared kind, and the bound records' content is compared after "
            "normalization"
        ),
        safety_argument=(
            "a rebinding to a different record would violate the per-world "
            "authority-routing invariant; semantic equality of the bound "
            "records is proven by the content comparison"
        ),
    ),
    NormalizationRule(
        rule_id="settlement-observation-binding",
        field="observation_digest",
        reason=(
            "settled legs pin the digest of their folded leg observation, "
            "whose record embeds the environment identity and the "
            "provider-issued reference"
        ),
        rule=(
            "exclude observation_digest from the cross-environment byte "
            "comparison; the settlement-truth invariant (run per world) "
            "proves every settled leg carries its binding, and the folded "
            "observation records are compared after normalization"
        ),
        safety_argument=(
            "the folded observations are execution-domain records compared "
            "in full; only the derived binding digest is excluded"
        ),
    ),
    NormalizationRule(
        rule_id="observation-subject-binding",
        field="subject_request_digest",
        reason=(
            "leg observations pin the instruction digest of their "
            "settlement leg; the digest covers instruction content that "
            "transitively embeds environment-bound seals"
        ),
        rule=(
            "exclude subject_request_digest from the cross-environment byte "
            "comparison; the instructions and the observations are compared "
            "as content after normalization"
        ),
        safety_argument=(
            "the instruction and leg records are compared directly; the "
            "binding is a derived digest over that same compared content"
        ),
    ),
    NormalizationRule(
        rule_id="discharge-evidence-binding",
        field="evidence_digest",
        reason=(
            "obligation resolution pins the settlement discharge evidence "
            "digest, which covers environment-bound settlement records"
        ),
        rule=(
            "exclude evidence_digest from the cross-environment byte "
            "comparison; the discharge evidence and postings are compared as "
            "content after normalization, and the resolution invariant runs "
            "per world"
        ),
        safety_argument=(
            "discharge postings are double-entry records compared field by "
            "field; only the derived digest is excluded"
        ),
    ),
    NormalizationRule(
        rule_id="request-digest-binding",
        field="request_digest",
        reason=(
            "the execution submission ledger pins the digest of each "
            "submitted effect request, whose spec embeds the environment-"
            "specific adapter identity"
        ),
        rule=(
            "exclude request_digest from the cross-environment byte "
            "comparison; the submitted requests themselves are compared as "
            "records after normalization, and the one-key-one-submission "
            "discipline is proven per world by the idempotency invariant"
        ),
        safety_argument=(
            "the request records (step, key, authorization, payload) are "
            "compared field-by-field; only the derived digest over "
            "environment-bound content is excluded"
        ),
    ),
    NormalizationRule(
        rule_id="composed-state-checkpoint-before",
        field="state_before",
        reason=(
            "the IG-002 stage journal records composed-state digests before "
            "and after every stage; the composed digest embeds the "
            "environment identity by construction"
        ),
        rule=(
            "exclude state_before/state_after digests from the "
            "cross-environment byte comparison; the stage TUPLES (stage, "
            "domain, command_id, requested_at, outcome) are compared, and "
            "the chaining + honesty of each journal is proven per world by "
            "the append-only invariant and the rebuild contract"
        ),
        safety_argument=(
            "the state-machine semantics are the compared stage tuples plus "
            "the compared record states; the checkpoint digests are derived "
            "values over the environment-bound composed state"
        ),
    ),
    NormalizationRule(
        rule_id="instruction-obligation-binding",
        field="obligation_digest",
        reason=(
            "settlement instructions pin the seal of their clearing "
            "obligation, and seals are environment-bound"
        ),
        rule=(
            "exclude obligation_digest from the cross-environment byte "
            "comparison; the instructions and the bound obligations are "
            "compared as records after normalization, and the instruction-"
            "pinning invariant runs per world"
        ),
        safety_argument=(
            "the obligation records are compared field-by-field; only the "
            "derived binding digest over environment-bound seals is excluded"
        ),
    ),
    NormalizationRule(
        rule_id="settlement-instructions-binding",
        field="instructions_digest",
        reason=(
            "settlements pin the digest of their instruction list, which "
            "covers the environment-bound obligation seals"
        ),
        rule=(
            "exclude instructions_digest from the cross-environment byte "
            "comparison; the instructions are compared as content after "
            "normalization"
        ),
        safety_argument=(
            "identical in kind to the obligation_digest rule: a derived "
            "digest over compared content"
        ),
    ),
    NormalizationRule(
        rule_id="finality-settlement-binding",
        field="settlement_digest",
        reason=(
            "finality certificates pin the digest of their settlement, "
            "which covers environment-bound instruction seals"
        ),
        rule=(
            "exclude settlement_digest from the cross-environment byte "
            "comparison; the settlement record itself is compared after "
            "normalization and the certificate-binding invariant runs per "
            "world"
        ),
        safety_argument=(
            "the certificate's claims and the settlement's legs are compared "
            "directly; only the derived binding digest is excluded"
        ),
    ),
    NormalizationRule(
        rule_id="reconciliation-observation-bindings",
        field="observation_digests",
        reason=(
            "settlement reconciliation entries pin the digests of their "
            "folded leg observations, whose records embed the environment "
            "identity and provider-issued references"
        ),
        rule=(
            "exclude every entry of the observation_digests list from the "
            "cross-environment byte comparison; the folded observations are "
            "execution-domain records compared in full after normalization"
        ),
        safety_argument=(
            "the plural list is exactly the leg-observation binding of the "
            "singular observation_digest rule; the observations themselves "
            "are compared"
        ),
    ),
    NormalizationRule(
        rule_id="generic-derived-digest-binding",
        field="digest",
        reason=(
            "several composed records carry a generic 'digest' field that "
            "pins derived content embedding environment-bound seals (the "
            "obligation resolution's discharge evidence digest, the netting "
            "statement digest)"
        ),
        rule=(
            "exclude the generic digest field from the cross-environment "
            "byte comparison; the covered content (discharge evidence, "
            "netting statement positions and pairs) is compared field-by-"
            "field after normalization, and the per-world batteries prove "
            "each binding points at exactly what it claims"
        ),
        safety_argument=(
            "conservative exclusion: the digest is a derived value over "
            "content that is either environment-bound (discharge evidence) "
            "or fully compared (netting statements); a semantic divergence "
            "in the content changes the compared fields, not just the digest"
        ),
    ),
    NormalizationRule(
        rule_id="composed-state-checkpoint-after",
        field="state_after",
        reason=(
            "the IG-002 stage journal records composed-state digests before "
            "and after every stage; the composed digest embeds the "
            "environment identity by construction"
        ),
        rule=(
            "exclude the state_after digests from the cross-environment byte "
            "comparison; the stage TUPLES are compared and the chaining + "
            "honesty of each journal is proven per world by the append-only "
            "invariant and the rebuild contract"
        ),
        safety_argument=(
            "identical to the state_before rule: derived checkpoints over "
            "environment-bound composed state, never compared semantics"
        ),
    ),
)


def validate_parity_gate_id(gate_id: object) -> str:
    """Fail closed unless ``gate_id`` names the simulation parity gate."""
    if not isinstance(gate_id, str) or gate_id not in KNOWN_PARITY_GATES:
        raise CoreValidationError(
            f"unknown parity gate {gate_id!r}; this package executes only "
            f"{sorted(KNOWN_PARITY_GATES)}"
        )
    return gate_id
