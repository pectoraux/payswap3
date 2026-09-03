"""IG-005 gate contracts: identity, vocabulary and boundary constants.

The external rail sandbox integration gate
(``spec/integration-gates.md`` row IG-005) exercises *canonical
interoperability over at least two rail-shaped adapters and the
exception/investigation paths* by composing ONLY already-merged
implementations: the WORK-007 canonical world-adapter contract and
status vocabulary, the WORK-014 typed execution adapter ports, the
WORK-016 settlement/finality authority, the WORK-023 federation-era
canonical lifecycle semantics and the WORK-027 IG-002 fulfillment
lifecycle harness over the real domain engines. This module declares
the gate's typed, versioned identity and freezes the vocabularies the
rail composition uses. It introduces no domain semantics of its own:
every behavioral authority stays with the consumed implementations.

Identity discipline:

* ``IG-005`` is the gate identifier listed in
  ``spec/integration-gates.md``; unknown gate ids fail closed
  everywhere. The IG-001/IG-002/IG-003 gate ids stay unknown HERE on
  purpose (one validator per gate, no shared mutation of the merged
  sibling gates' contract surfaces).
* The gate projects NO new protocol-visible name: every
  registry-listed object type and event namespace it touches belongs
  to the consumed domain engines.
* The two compared rail worlds are two distinct sandbox ENVIRONMENTS
  (one per external rail), each a full IG-002 lifecycle composition
  bound to exactly ONE typed adapter binding. The environments,
  domains and adapter identities all differ between the worlds by
  declaration; nothing else may.
* Rail classification (the work order's required vocabulary) is a
  first-class frozen enum: a real provider sandbox may never be
  silently counted as a local deterministic sandbox or vice versa.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from src.core.errors import CoreValidationError

#: The identifier of this gate (spec/integration-gates.md, IG-005 row).
RAILS_GATE_ID = "IG-005"

#: Typed, versioned public boundary version of the gate package.
RAILS_API_VERSION = "v0.1"

#: Schema version of the gate's canonical comparison-result record.
RAILS_SCHEMA_VERSION = 1

#: The gate identifiers this package knows how to execute.
KNOWN_RAILS_GATES = frozenset({RAILS_GATE_ID})

#: The only implementation roots the gate may import (AST-audited by
#: the contract suite). Anything else is a second authority or an
#: unmerged sibling and is forbidden. ``src.integration.lifecycle`` is
#: the merged WORK-027 public boundary (the composed lifecycle harness
#: AND the merged Stripe test-mode / local deterministic rail adapters
#: the gate reuses — imported, never forked).
CONSUMED_SURFACES = (
    "src.core",
    "src.transition",
    "src.evidence",
    "src.capability",
    "src.interoperability",
    "src.execution",
    "src.clearing",
    "src.settlement",
    "src.integration.lifecycle",
)

#: Rail A (the first external rail): Stripe test mode, reused from the
#: merged WORK-027 dogfooding rails (the declared adapter contract and
#: its id are the merged package's own).
RAIL_A_NAME = "rail_a"
RAIL_A_ADAPTER_ID = "interoperability/adapter/stripe-test"
RAIL_A_ENVIRONMENT_ID = "env/sandbox-ig005-rail-a"
RAIL_A_DOMAIN_ID = "domain/ig005-rail-a"
RAIL_A_CURRENCY = "USD"
RAIL_A_CAPABILITY_ID = "capability/stripe-test"

#: Rail B (the second external rail): the public Stellar testnet. No
#: credential exists or is required: the testnet is an open public
#: sandbox network addressed over the public Horizon API, and the
#: rail's test accounts are deterministic keypairs derived from PUBLIC
#: constants (documented as non-secret, testnet-only — they hold
#: testnet XLM only and are never used against any production
#: network).
RAIL_B_NAME = "rail_b"
RAIL_B_ADAPTER_ID = "interoperability/adapter/stellar-testnet"
RAIL_B_ENVIRONMENT_ID = "env/sandbox-ig005-rail-b"
RAIL_B_DOMAIN_ID = "domain/ig005-rail-b"
RAIL_B_CURRENCY = "USD"
RAIL_B_CAPABILITY_ID = "capability/stellar-testnet"

#: The local deterministic rail worlds (the merged WORK-027
#: ``LocalDeterministicRail``) drive the deterministic failure and
#: investigation battery (transport ambiguity, reconciliation
#: not-found, unexpected provider status). They are classified
#: ``LOCAL_DETERMINISTIC_SANDBOX`` and are NEVER counted as one of the
#: two external rails.
LOCAL_RAIL_A_NAME = "local_a"
LOCAL_RAIL_B_NAME = "local_b"
LOCAL_RAIL_A_ADAPTER_ID = "interoperability/adapter/ig005-local-a"
LOCAL_RAIL_B_ADAPTER_ID = "interoperability/adapter/ig005-local-b"
LOCAL_RAIL_A_ENVIRONMENT_ID = "env/sandbox-ig005-local-a"
LOCAL_RAIL_B_ENVIRONMENT_ID = "env/sandbox-ig005-local-b"
LOCAL_RAIL_A_DOMAIN_ID = "domain/ig005-local-a"
LOCAL_RAIL_B_DOMAIN_ID = "domain/ig005-local-b"
LOCAL_RAIL_CURRENCY = "USD"

#: The default gate actor and authorized actors of the composed
#: environments (mirroring the sibling gate conventions).
DEFAULT_RAILS_ACTOR = "principal/ig005-ops"
DEFAULT_AUTHORIZED_ACTORS = frozenset(
    {"principal/ig005-ops", "principal/payer-ig005"}
)

#: The canonical payer/payee of the rail scenarios (declared data).
RAILS_PAYER = "principal/payer-ig005"
RAILS_PAYEE = "principal/merchant-42"

#: The canonical scenario amount: 100 minor units at scale 2 = 1.00 of
#: the declared canonical asset (1.00 USD declared on BOTH real rails —
#: the work order's *equivalent declared economic inputs*: the same
#: declared value, scale and canonical asset; rail A settles usd
#: natively while rail B settles the declared amount natively on the
#: public testnet as the documented sandbox-conformance translation,
#: disclosed in the world reports and never a canonical value claim).
RAILS_AMOUNT_MINOR = 100

#: The declared canonical asset word of every IG-005 world (the merged
#: money authority's closed canonical vocabulary; both real rails and
#: the local pair declare it — see the declared-canonical-asset
#: normalization rule for the rails' native settlement representations).
RAILS_DECLARED_CURRENCY = "USD"

#: The rejection-scenario amount (2.50 of the declared asset).
RAILS_REJECTION_AMOUNT_MINOR = 250


class RailClass(StrEnum):
    """The frozen rail classification vocabulary of the work order.

    A REAL provider sandbox is an actual external provider's sandbox
    world (Stripe test mode, the public Stellar testnet). A local
    deterministic sandbox is an in-memory scripted rail. The two are
    never interchangeable: the classification is declared per world,
    validated against the bound rail's nature where observable, and
    reported in every verdict — a local rail may never claim
    ``REAL_PROVIDER_SANDBOX``.
    """

    REAL_PROVIDER_SANDBOX = "REAL_PROVIDER_SANDBOX"
    LOCAL_DETERMINISTIC_SANDBOX = "LOCAL_DETERMINISTIC_SANDBOX"

    @classmethod
    def parse(cls, value: object) -> "RailClass":
        if not isinstance(value, cls):
            raise CoreValidationError(
                f"rail class must be a RailClass member, got {value!r}"
            )
        return value


@dataclass(frozen=True, slots=True)
class NormalizationRule:
    """One declared normalization rule of the cross-rail comparison.

    A rule is field-bound (it names exactly one field name), documented
    for BOTH rails (the rail A representation and the rail B
    representation of the legitimate difference), reasoned (why the
    field legitimately differs), exact (the transformation rule) and
    justified (the safety argument: why the normalization cannot erase
    semantic differences). Broad "ignore field" strategies are
    forbidden; the forbidden fields (amount, currency, canonical
    outcome, failure class, idempotency result, economic effect,
    settlement status, finality status, evidence epistemic meaning)
    are pinned by the contract suite and can never appear in the
    registry.
    """

    rule_id: str
    field: str
    rail_a_representation: str
    rail_b_representation: str
    reason: str
    rule: str
    safety_argument: str

    def __post_init__(self) -> None:
        for name in (
            "rule_id",
            "field",
            "rail_a_representation",
            "rail_b_representation",
            "reason",
            "rule",
            "safety_argument",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise CoreValidationError(
                    f"normalization rule {self.rule_id!r} requires a "
                    f"non-empty {name}"
                )


#: The closed set of digest-valued field names excluded from the
#: cross-rail byte comparison because they are environment-bound
#: derived values: each one is a seal or digest computed OVER canonical
#: content that legitimately embeds the world's environment identity,
#: domain identity, adapter identity or provider-issued reference. The
#: excluded fields carry per-rule justifications below (one rule per
#: field). Their binding correctness is proven PER WORLD by the
#: composed WORK-027 invariant battery (re-run by this gate's battery
#: on both worlds), while the cross-rail comparison proves the semantic
#: CONTENT those digests cover is identical after normalization.
RAILS_ENV_BOUND_DIGEST_FIELDS = frozenset(
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

#: The frozen rail normalization registry: exactly the fields that may
#: differ legitimately between the two rail worlds' execution of the
#: SAME declared scenario, with per-field rules and BOTH rails'
#: representations. Every other difference at every other path is a
#: semantic divergence and fails the gate closed. The registry is
#: consumed by the projection layer and pinned by the contract suite
#: (a mutation of the registry is detectable by the discrimination
#: battery).
RAILS_NORMALIZATION_RULES: tuple[NormalizationRule, ...] = (
    NormalizationRule(
        rule_id="world-environment-identity",
        field="environment_id",
        rail_a_representation="env/sandbox-ig005-rail-a (Stripe test-mode world)",
        rail_b_representation=(
            "env/sandbox-ig005-rail-b (Stellar testnet world; the local "
            "pair declares env/sandbox-ig005-local-*)"
        ),
        reason=(
            "the two compared executions intentionally run in two "
            "distinct sandbox environments — one per external rail — and "
            "in distinct local environments for the deterministic pair"
        ),
        rule=(
            "wherever the field name environment_id appears at any depth, "
            "validate the value is exactly one of the two compared "
            "worlds' declared environment ids (fail closed on any foreign "
            "value) and replace it with the neutral token {ENVIRONMENT}"
        ),
        safety_argument=(
            "environment ids never enter amounts, states, transitions, "
            "authorization decisions or evidence classes; a foreign value "
            "fails closed instead of normalizing, and the per-world "
            "environment-isolation invariant proves every record of a "
            "world carries exactly that world's environment id"
        ),
    ),
    NormalizationRule(
        rule_id="world-domain-identity",
        field="domain_id",
        rail_a_representation="domain/ig005-rail-a (one engine domain per world)",
        rail_b_representation="domain/ig005-rail-b (and domain/ig005-local-*)",
        reason=(
            "each rail world binds its own per-engine domain (the "
            "sibling convention: clearing, settlement and execution "
            "objects never share a domain), so the domain identity is "
            "environment-scoped engine binding metadata"
        ),
        rule=(
            "wherever the field name domain_id appears, validate the value "
            "is exactly one of the two compared worlds' declared domain "
            "ids (fail closed on any foreign value) and replace it with "
            "the neutral token {DOMAIN}"
        ),
        safety_argument=(
            "domain ids carry no financial semantics; the domain-isolation "
            "invariant proves each world's engines and records carry only "
            "their own domain binding, so a cross-domain leak is a "
            "fail-closed divergence rather than a silent normalization"
        ),
    ),
    NormalizationRule(
        rule_id="rail-adapter-identity",
        field="adapter_id",
        rail_a_representation=(
            "interoperability/adapter/stripe-test (the merged WORK-027 "
            "Stripe test-mode adapter contract)"
        ),
        rail_b_representation=(
            "interoperability/adapter/stellar-testnet (the IG-005 Stellar "
            "testnet adapter contract over the same typed ports)"
        ),
        reason=(
            "each world binds its own declared rail adapter contract; the "
            "adapter identity is transport-level rail metadata"
        ),
        rule=(
            "wherever the field name adapter_id (or the plural binding "
            "list adapter_ids) appears, validate every entry is exactly "
            "one of the two compared worlds' declared adapter ids (fail "
            "closed on any foreign value) and replace it with the neutral "
            "token {RAIL_ADAPTER}"
        ),
        safety_argument=(
            "the adapter identity carries no lifecycle semantics; both "
            "adapters implement the identical merged typed port contract "
            "and the same canonical payment status vocabulary, which are "
            "compared as content"
        ),
    ),
    NormalizationRule(
        rule_id="provider-native-reference",
        field="native_reference",
        rail_a_representation=(
            "Stripe-issued PaymentIntent ids (pi_…) — provider-issued, "
            "idempotency-key-bound"
        ),
        rail_b_representation=(
            "Stellar transaction hashes (64 hex characters) and the local "
            "rails' ig002-local/<key> references"
        ),
        reason=(
            "provider-issued reference ids are rail-specific: each rail "
            "issues references from its own namespace for the same "
            "declared effect"
        ),
        rule=(
            "wherever the field name native_reference appears with a "
            "string value, validate the value matches the OWNING world's "
            "declared native-reference pattern (Stripe pi_ ids, Stellar "
            "64-hex transaction hashes, or the local ig002-local/<key> "
            "shape; fail closed on any other shape) and replace it with "
            "the neutral token {NATIVE_REFERENCE}; None values stay None"
        ),
        safety_argument=(
            "the key-binding of each reference (one idempotency key, one "
            "submission, one native reference) is proven PER WORLD by the "
            "idempotency invariant and the submission ledger; a mutated "
            "or foreign reference breaks the declared shape and fails "
            "closed instead of normalizing"
        ),
    ),
    NormalizationRule(
        rule_id="provider-native-status-wording",
        field="native_code",
        rail_a_representation=(
            "Stripe's native words (succeeded, processing, canceled…) "
            "recorded in the STATUS observation content"
        ),
        rail_b_representation=(
            "Stellar's native words (completed, pending, failed) and the "
            "local rails' ACSD/PDNG/UKWN/RJCT/STLD/FINL words"
        ),
        reason=(
            "each provider words its native status vocabulary "
            "differently; the canonical payment status the adapters map "
            "INTO (the merged WORK-007 vocabulary) is the compared "
            "semantics — the raw native word is the provider's wording of "
            "that same canonical classification"
        ),
        rule=(
            "wherever the field name native_code appears in a STATUS "
            "observation's content, validate the value is EXACTLY one of "
            "the owning world's declared adapter status-map native codes "
            "(fail closed on any other value — an undeclared word is the "
            "unexpected-provider-status path) and replace it with the "
            "neutral token {NATIVE_STATUS}; the content's canonical_status "
            "field is NEVER touched and is compared strictly"
        ),
        safety_argument=(
            "the canonical classification is authoritative and compared "
            "strictly; the native word is validated against the owning "
            "adapter's closed declared vocabulary (a fabricated or "
            "substituted word fails closed), and the mapping native-code "
            "-> canonical-status is proven by the status-map contract "
            "tests"
        ),
    ),
    NormalizationRule(
        rule_id="provider-timestamps-and-ledger-metadata",
        field="provider_metadata",
        rail_a_representation=(
            "Stripe's created_at/ledger metadata (HTTP response fields)"
        ),
        rail_b_representation=(
            "Stellar's created_at/ledger/fee_charged metadata (HTTP "
            "response fields)"
        ),
        reason=(
            "provider timestamps and ledger placement metadata are "
            "transport-layer facts of each sandbox world, not canonical "
            "protocol semantics"
        ),
        rule=(
            "provider timestamps and ledger metadata never enter the "
            "canonical semantic state: the canonical timeline of every "
            "compared record is the declared scenario instant carried by "
            "the stage journal and record provenance; native provider "
            "metadata is exposed per world through sanitized read "
            "accessors only"
        ),
        safety_argument=(
            "the compared state carries only declared instants; wall "
            "clock reads are forbidden by the contract suite, so a "
            "provider-time difference can never masquerade as (or hide) "
            "a semantic difference"
        ),
    ),
    NormalizationRule(
        rule_id="declared-canonical-asset",
        field="asset",
        rail_a_representation=(
            "asset/usd declared and settled natively (Stripe test mode "
            "settles usd)"
        ),
        rail_b_representation=(
            "asset/usd declared (the same canonical asset); the Stellar "
            "testnet rail settles the declared amount natively on the "
            "public testnet as a documented sandbox-conformance "
            "translation, disclosed in the world report and never a "
            "canonical value claim"
        ),
        reason=(
            "the merged money authority's canonical currency vocabulary is "
            "closed (ISO-4217 style fiat codes); the gate consumes it "
            "as-is, so BOTH real rails declare the SAME canonical asset "
            "over the declared amount — the rails' native settlement "
            "representations differ at the transport layer only"
        ),
        rule=(
            "wherever the field name asset (or the step payload's "
            "currency) appears, validate the value is EXACTLY the owning "
            "world's declared canonical asset (fail closed on any other "
            "value — a substituted asset is a divergence, never a "
            "normalization); the two worlds declare the SAME canonical "
            "asset, so the compared values are identical and strictly "
            "compared; the rails' native settlement representations stay "
            "rail-local diagnostic data, never canonical state"
        ),
        safety_argument=(
            "an asset substitution (asset/usd rendered as asset/gbp, or a "
            "rail leg silently re-denominated) breaks the exact-value "
            "validation and fails closed; the amount value and scale are "
            "compared strictly; the native settlement difference is "
            "transport-layer metadata disclosed per world, never a "
            "compared semantic field and never a canonical value claim"
        ),
    ),
    NormalizationRule(
        rule_id="step-payload-currency-wording",
        field="currency",
        rail_a_representation="USD (the step payload's declared canonical currency)",
        rail_b_representation="USD (and USD for the local pair)",
        reason=(
            "the execution step payload carries the declared canonical "
            "currency word of the world's declared asset — both real "
            "worlds declare the same canonical asset, so the compared "
            "values are identical"
        ),
        rule=(
            "wherever the field name currency appears in a step payload, "
            "validate the value is exactly the owning world's declared "
            "currency (fail closed on any other value) — the identical "
            "values are then compared strictly (no substitution is ever "
            "normalized)"
        ),
        safety_argument=(
            "exact-value validation with strict comparison: a substituted "
            "currency fails closed; amount value and scale are compared "
            "strictly"
        ),
    ),
    NormalizationRule(
        rule_id="envelope-seal",
        field="integrity_hash",
        rail_a_representation="seals over Stripe-world content (env/adapter/pi_-bound)",
        rail_b_representation="seals over Stellar-world content (env/adapter/hash-bound)",
        reason=(
            "every durable record's seal is computed by the single "
            "canonical hash authority over canonical content that embeds "
            "the world's environment, domain, adapter identity and "
            "provider-issued references, so the seal bytes legitimately "
            "differ between the rail worlds"
        ),
        rule=(
            "exclude the envelope integrity_hash value from the "
            "cross-rail byte comparison; seal integrity is proven per "
            "world (every consumed domain verifies seals on every trusted "
            "decode, and the composed invariant battery re-runs on both "
            "worlds), and the semantic content the seal covers is "
            "compared field-by-field after normalization"
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
        rail_a_representation="plan digest over the Stripe world's hop projections",
        rail_b_representation="plan digest over the Stellar world's hop projections",
        reason=(
            "the compiler's plan digest covers the compiled plan content, "
            "whose hop projections embed the world's environment identity"
        ),
        rule=(
            "exclude plan_digest from the cross-rail byte comparison; "
            "determinism of compilation is proven per world (the IG-002 "
            "replay contract recompiles and compares plan digests inside "
            "one environment) and the plan content is compared "
            "field-by-field after normalization"
        ),
        safety_argument=(
            "the plan's payments, routes, amounts and states are compared "
            "directly; only the derived digest over world-bound content "
            "is excluded"
        ),
    ),
    NormalizationRule(
        rule_id="source-seal-binding",
        field="source_digest",
        rail_a_representation="obligation/netting source seals (Stripe world)",
        rail_b_representation="obligation/netting source seals (Stellar world)",
        reason=(
            "obligation and netting records pin the seal of their sealed "
            "authority (execution evidence or netting statement), and "
            "seals are world-bound"
        ),
        rule=(
            "exclude source_digest from the cross-rail byte comparison; "
            "the authority-routing invariant (run per world) proves each "
            "binding points at exactly the sealed record of its declared "
            "kind, and the bound records' content is compared after "
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
        rail_a_representation="settled-leg observation seals (Stripe world)",
        rail_b_representation="settled-leg observation seals (Stellar world)",
        reason=(
            "settled legs pin the digest of their folded leg observation, "
            "whose record embeds the world identity and the "
            "provider-issued reference"
        ),
        rule=(
            "exclude observation_digest from the cross-rail byte "
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
        rail_a_representation="leg-observation instruction seals (Stripe world)",
        rail_b_representation="leg-observation instruction seals (Stellar world)",
        reason=(
            "leg observations pin the instruction digest of their "
            "settlement leg; the digest covers instruction content that "
            "transitively embeds world-bound seals"
        ),
        rule=(
            "exclude subject_request_digest from the cross-rail byte "
            "comparison; the instructions and the observations are "
            "compared as content after normalization"
        ),
        safety_argument=(
            "the instruction and leg records are compared directly; the "
            "binding is a derived digest over that same compared content"
        ),
    ),
    NormalizationRule(
        rule_id="discharge-evidence-binding",
        field="evidence_digest",
        rail_a_representation="discharge-evidence seals (Stripe world)",
        rail_b_representation="discharge-evidence seals (Stellar world)",
        reason=(
            "obligation resolution pins the settlement discharge evidence "
            "digest, which covers world-bound settlement records"
        ),
        rule=(
            "exclude evidence_digest from the cross-rail byte comparison; "
            "the discharge evidence and postings are compared as content "
            "after normalization, and the resolution invariant runs per "
            "world"
        ),
        safety_argument=(
            "discharge postings are double-entry records compared field "
            "by field; only the derived digest is excluded"
        ),
    ),
    NormalizationRule(
        rule_id="request-digest-binding",
        field="request_digest",
        rail_a_representation="submission-ledger request seals (Stripe world)",
        rail_b_representation="submission-ledger request seals (Stellar world)",
        reason=(
            "the execution submission ledger pins the digest of each "
            "submitted effect request, whose spec embeds the world's "
            "adapter identity"
        ),
        rule=(
            "exclude request_digest from the cross-rail byte comparison; "
            "the submitted requests themselves are compared as records "
            "after normalization, and the one-key-one-submission "
            "discipline is proven per world by the idempotency invariant"
        ),
        safety_argument=(
            "the request records (step, key, authorization, payload) are "
            "compared field-by-field; only the derived digest over "
            "world-bound content is excluded"
        ),
    ),
    NormalizationRule(
        rule_id="composed-state-checkpoint-before",
        field="state_before",
        rail_a_representation="stage-journal composed checkpoints (Stripe world)",
        rail_b_representation="stage-journal composed checkpoints (Stellar world)",
        reason=(
            "the IG-002 stage journal records composed-state digests "
            "before and after every stage; the composed digest embeds the "
            "world's environment identity by construction"
        ),
        rule=(
            "exclude state_before digests from the cross-rail byte "
            "comparison; the stage TUPLES (stage, domain, command_id, "
            "requested_at, outcome) are compared, and the chaining + "
            "honesty of each journal is proven per world by the "
            "append-only invariant and the rebuild contract"
        ),
        safety_argument=(
            "the state-machine semantics are the compared stage tuples "
            "plus the compared record states; the checkpoint digests are "
            "derived values over the world-bound composed state"
        ),
    ),
    NormalizationRule(
        rule_id="composed-state-checkpoint-after",
        field="state_after",
        rail_a_representation="stage-journal composed checkpoints (Stripe world)",
        rail_b_representation="stage-journal composed checkpoints (Stellar world)",
        reason=(
            "identical in kind to the state_before rule: derived "
            "checkpoints over world-bound composed state"
        ),
        rule=(
            "exclude state_after digests from the cross-rail byte "
            "comparison; the stage TUPLES are compared and the chaining + "
            "honesty of each journal is proven per world by the "
            "append-only invariant and the rebuild contract"
        ),
        safety_argument=(
            "derived checkpoints over world-bound composed state, never "
            "compared semantics"
        ),
    ),
    NormalizationRule(
        rule_id="instruction-obligation-binding",
        field="obligation_digest",
        rail_a_representation="instruction obligation seals (Stripe world)",
        rail_b_representation="instruction obligation seals (Stellar world)",
        reason=(
            "settlement instructions pin the seal of their clearing "
            "obligation, and seals are world-bound"
        ),
        rule=(
            "exclude obligation_digest from the cross-rail byte "
            "comparison; the instructions and the bound obligations are "
            "compared as records after normalization, and the "
            "instruction-pinning invariant runs per world"
        ),
        safety_argument=(
            "the obligation records are compared field-by-field; only the "
            "derived binding digest over world-bound seals is excluded"
        ),
    ),
    NormalizationRule(
        rule_id="settlement-instructions-binding",
        field="instructions_digest",
        rail_a_representation="settlement instruction-list seals (Stripe world)",
        rail_b_representation="settlement instruction-list seals (Stellar world)",
        reason=(
            "settlements pin the digest of their instruction list, which "
            "covers the world-bound obligation seals"
        ),
        rule=(
            "exclude instructions_digest from the cross-rail byte "
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
        rail_a_representation="finality-certificate settlement seals (Stripe world)",
        rail_b_representation="finality-certificate settlement seals (Stellar world)",
        reason=(
            "finality certificates pin the digest of their settlement, "
            "which covers world-bound instruction seals"
        ),
        rule=(
            "exclude settlement_digest from the cross-rail byte "
            "comparison; the settlement record itself is compared after "
            "normalization and the certificate-binding invariant runs per "
            "world"
        ),
        safety_argument=(
            "the certificate's claims and the settlement's legs are "
            "compared directly; only the derived binding digest is "
            "excluded"
        ),
    ),
    NormalizationRule(
        rule_id="reconciliation-observation-bindings",
        field="observation_digests",
        rail_a_representation="reconciliation entry seals (Stripe world)",
        rail_b_representation="reconciliation entry seals (Stellar world)",
        reason=(
            "settlement reconciliation entries pin the digests of their "
            "folded leg observations, whose records embed the world "
            "identity and provider-issued references"
        ),
        rule=(
            "exclude every entry of the observation_digests list from the "
            "cross-rail byte comparison; the folded observations are "
            "execution-domain records compared in full after normalization"
        ),
        safety_argument=(
            "the plural list is exactly the leg-observation binding of "
            "the singular observation_digest rule; the observations "
            "themselves are compared"
        ),
    ),
    NormalizationRule(
        rule_id="generic-derived-digest-binding",
        field="digest",
        rail_a_representation="generic derived digests (discharge evidence, netting)",
        rail_b_representation="generic derived digests (discharge evidence, netting)",
        reason=(
            "several composed records carry a generic 'digest' field that "
            "pins derived content embedding world-bound seals (the "
            "obligation resolution's discharge evidence digest, the "
            "netting statement digest)"
        ),
        rule=(
            "exclude the generic digest field from the cross-rail byte "
            "comparison; the covered content (discharge evidence, netting "
            "statement positions and pairs) is compared field-by-field "
            "after normalization, and the per-world batteries prove each "
            "binding points at exactly what it claims"
        ),
        safety_argument=(
            "conservative exclusion: the digest is a derived value over "
            "content that is either world-bound (discharge evidence) or "
            "fully compared (netting statements); a semantic divergence "
            "in the content changes the compared fields, not just the "
            "digest"
        ),
    ),
)


def validate_rails_gate_id(gate_id: object) -> str:
    """Fail closed unless ``gate_id`` names the external rail sandbox gate."""
    if not isinstance(gate_id, str) or gate_id not in KNOWN_RAILS_GATES:
        raise CoreValidationError(
            f"unknown rails gate {gate_id!r}; this package executes only "
            f"{sorted(KNOWN_RAILS_GATES)}"
        )
    return gate_id


__all__ = [
    "CONSUMED_SURFACES",
    "DEFAULT_AUTHORIZED_ACTORS",
    "DEFAULT_RAILS_ACTOR",
    "KNOWN_RAILS_GATES",
    "LOCAL_RAIL_A_ADAPTER_ID",
    "LOCAL_RAIL_A_DOMAIN_ID",
    "LOCAL_RAIL_A_ENVIRONMENT_ID",
    "LOCAL_RAIL_A_NAME",
    "LOCAL_RAIL_B_ADAPTER_ID",
    "LOCAL_RAIL_B_DOMAIN_ID",
    "LOCAL_RAIL_B_ENVIRONMENT_ID",
    "LOCAL_RAIL_B_NAME",
    "LOCAL_RAIL_CURRENCY",
    "NormalizationRule",
    "RAILS_AMOUNT_MINOR",
    "RAILS_API_VERSION",
    "RAILS_ENV_BOUND_DIGEST_FIELDS",
    "RAILS_GATE_ID",
    "RAILS_NORMALIZATION_RULES",
    "RAILS_DECLARED_CURRENCY",
    "RAILS_PAYEE",
    "RAILS_PAYER",
    "RAILS_REJECTION_AMOUNT_MINOR",
    "RAILS_SCHEMA_VERSION",
    "RAIL_A_ADAPTER_ID",
    "RAIL_A_CAPABILITY_ID",
    "RAIL_A_CURRENCY",
    "RAIL_A_DOMAIN_ID",
    "RAIL_A_ENVIRONMENT_ID",
    "RAIL_A_NAME",
    "RAIL_B_ADAPTER_ID",
    "RAIL_B_CAPABILITY_ID",
    "RAIL_B_CURRENCY",
    "RAIL_B_DOMAIN_ID",
    "RAIL_B_ENVIRONMENT_ID",
    "RAIL_B_NAME",
    "RailClass",
    "validate_rails_gate_id",
]
