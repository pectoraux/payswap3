"""State namespace separation (WORK-019).

Every environment has separate namespaces for protocol, value, trust,
economic and dependency state (``simulation.md`` "State separation").
The kernel owns one physical store — its atomic validate-all-then-apply
commit semantics are consumed, never reimplemented — and this module
adds the namespace layer: deterministic object-id classification,
provisioning contamination checks and per-namespace derived views and
digests.

Namespaces are logical separation with kernel-owned physical state: a
command may legitimately span namespaces (for example an intent
transition that also advances a value hold), but an object id belongs to
exactly one namespace forever, unclassifiable ids fail closed and an
object provisioned under the wrong namespace fails closed
(cross-namespace contamination).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from src.core.envelope import ObjectEnvelope
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.transition.store import MemoryStateStore

from ._validation import require_identifier, require_text, strict_fields
from .contracts import StateNamespace


@dataclass(frozen=True, slots=True)
class NamespaceRule:
    """One classification rule: object ids beginning with ``prefix``."""

    prefix: str
    namespace: StateNamespace

    def __post_init__(self) -> None:
        require_text("namespace rule prefix", self.prefix)
        if not self.prefix.endswith("/"):
            raise CoreValidationError(
                "namespace rule prefix must end with '/' (object family prefix)"
            )
        if not isinstance(self.namespace, StateNamespace):
            raise CoreValidationError(
                "namespace rule namespace must be a StateNamespace"
            )


_RULE_DIGEST_FIELDS = frozenset({"rules"})


class NamespaceRules:
    """Deterministic, strictly unambiguous namespace classification.

    Validation (fail closed):

    * every one of the five frozen namespaces must be covered;
    * prefixes are unique;
    * no prefix may be a proper prefix of another prefix, so exactly one
      rule matches any object id and classification is total and
      unambiguous;
    * ``classify`` fails closed on unclassifiable object ids.
    """

    def __init__(self, rules: Iterable[NamespaceRule]) -> None:
        if isinstance(rules, NamespaceRules):
            raise CoreValidationError("namespace rules must be an iterable of NamespaceRule")
        collected: list[NamespaceRule] = []
        for rule in rules:
            if not isinstance(rule, NamespaceRule):
                raise CoreValidationError("namespace rules must be NamespaceRule records")
            collected.append(rule)
        if not collected:
            raise CoreValidationError("namespace rules must not be empty")
        prefixes = [rule.prefix for rule in collected]
        if len(set(prefixes)) != len(prefixes):
            raise CoreValidationError("namespace rules contain duplicate prefixes")
        ordered = sorted(collected, key=lambda rule: rule.prefix)
        for first, second in zip(ordered, ordered[1:]):
            if second.prefix.startswith(first.prefix):
                raise CoreValidationError(
                    f"namespace prefixes are ambiguous: {first.prefix!r} and "
                    f"{second.prefix!r} overlap"
                )
        covered = {rule.namespace for rule in ordered}
        missing = set(StateNamespace) - covered
        if missing:
            raise CoreValidationError(
                "namespace rules must cover all five frozen namespaces; missing: "
                f"{sorted(namespace.value for namespace in missing)}"
            )
        self._rules: tuple[NamespaceRule, ...] = tuple(ordered)

    @property
    def rules(self) -> tuple[NamespaceRule, ...]:
        return self._rules

    def classify(self, object_id: str) -> StateNamespace:
        """Fail closed unless exactly one rule classifies the object id."""
        require_identifier("object_id", object_id)
        matches = [
            rule for rule in self._rules if object_id.startswith(rule.prefix)
        ]
        if len(matches) != 1:
            raise CoreValidationError(
                f"object id {object_id!r} is not classified into exactly one state "
                "namespace; the environment fails closed on unclassifiable state"
            )
        return matches[0].namespace

    def to_dict(self) -> dict[str, Any]:
        return {
            "rules": [
                {"prefix": rule.prefix, "namespace": rule.namespace.value}
                for rule in self._rules
            ]
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "NamespaceRules":
        if not isinstance(value, Mapping):
            raise CoreValidationError("namespace rules must be an object")
        strict_fields("namespace rules", value, _RULE_DIGEST_FIELDS)
        rules_raw = value["rules"]
        if not isinstance(rules_raw, list):
            raise CoreValidationError("namespace rules must deserialize from a list")
        rules = []
        for item in rules_raw:
            if not isinstance(item, Mapping):
                raise CoreValidationError("namespace rule must be an object")
            strict_fields("namespace rule", item, frozenset({"prefix", "namespace"}))
            rules.append(
                NamespaceRule(
                    prefix=item["prefix"],
                    namespace=StateNamespace.parse(item["namespace"]),
                )
            )
        return cls(rules)

    @property
    def digest(self) -> str:
        return canonical_sha256(self.to_dict())


#: The default namespace classification of the repository's object-id
#: families. Every environment must classify all five namespaces; custom
#: rules are accepted but must be total and unambiguous.
DEFAULT_NAMESPACE_RULES = NamespaceRules(
    (
        NamespaceRule("intent/", StateNamespace.PROTOCOL),
        NamespaceRule("fulfillment/", StateNamespace.PROTOCOL),
        NamespaceRule("execution/", StateNamespace.PROTOCOL),
        NamespaceRule("clearing/", StateNamespace.PROTOCOL),
        NamespaceRule("settlement/", StateNamespace.PROTOCOL),
        NamespaceRule("finality/", StateNamespace.PROTOCOL),
        NamespaceRule("obligation/", StateNamespace.PROTOCOL),
        NamespaceRule("netting/", StateNamespace.PROTOCOL),
        NamespaceRule("reservation/", StateNamespace.PROTOCOL),
        NamespaceRule("capability/", StateNamespace.PROTOCOL),
        NamespaceRule("market/", StateNamespace.PROTOCOL),
        NamespaceRule("quote/", StateNamespace.PROTOCOL),
        NamespaceRule("value/", StateNamespace.VALUE),
        NamespaceRule("ledger/", StateNamespace.VALUE),
        NamespaceRule("account/", StateNamespace.VALUE),
        NamespaceRule("hold/", StateNamespace.VALUE),
        NamespaceRule("asset/", StateNamespace.VALUE),
        NamespaceRule("posting/", StateNamespace.VALUE),
        NamespaceRule("trust/", StateNamespace.TRUST),
        NamespaceRule("principal/", StateNamespace.TRUST),
        NamespaceRule("credential/", StateNamespace.TRUST),
        NamespaceRule("mandate/", StateNamespace.TRUST),
        NamespaceRule("authority/", StateNamespace.TRUST),
        NamespaceRule("economic/", StateNamespace.ECONOMIC),
        NamespaceRule("fee/", StateNamespace.ECONOMIC),
        NamespaceRule("cost/", StateNamespace.ECONOMIC),
        NamespaceRule("dependency/", StateNamespace.DEPENDENCY),
        NamespaceRule("extension/", StateNamespace.DEPENDENCY),
        NamespaceRule("model/", StateNamespace.DEPENDENCY),
    )
)


class NamespacedStateStore:
    """Kernel ``StateStore`` implementation with namespace routing and gating.

    ``get`` routes every object id through classification (unclassifiable
    ids fail closed before the kernel can treat them as absent) and
    ``commit`` validates that every resulting envelope id classifies
    before delegating the batch to the kernel-owned
    :class:`~src.transition.store.MemoryStateStore`, whose atomic
    validate-all-then-apply semantics remain the single commit authority.
    A commit that raises leaves all namespace state byte-identical to its
    pre-commit state.
    """

    __slots__ = ("_rules", "_inner")

    def __init__(self, rules: NamespaceRules, inner: MemoryStateStore) -> None:
        if not isinstance(rules, NamespaceRules):
            raise CoreValidationError("namespaced store requires NamespaceRules")
        if not isinstance(inner, MemoryStateStore):
            raise CoreValidationError(
                "namespaced store requires the kernel-owned MemoryStateStore"
            )
        self._rules = rules
        self._inner = inner

    @property
    def inner(self) -> MemoryStateStore:
        return self._inner

    @property
    def rules(self) -> NamespaceRules:
        return self._rules

    def get(self, object_id: str) -> ObjectEnvelope | None:
        self._rules.classify(object_id)
        return self._inner.get(object_id)

    def commit(self, resulting: tuple[ObjectEnvelope, ...]) -> None:
        if not isinstance(resulting, tuple) or not resulting:
            raise CoreValidationError(
                "commit requires a non-empty tuple of resulting envelopes"
            )
        for envelope in resulting:
            self._rules.classify(envelope.object_id)
        self._inner.commit(resulting)

    def snapshot(self) -> tuple[ObjectEnvelope, ...]:
        return self._inner.snapshot()

    def namespace_state(self, namespace: StateNamespace) -> tuple[ObjectEnvelope, ...]:
        """Deterministic ordered view of one namespace's objects."""
        if not isinstance(namespace, StateNamespace):
            raise CoreValidationError("namespace must be a StateNamespace")
        return tuple(
            envelope
            for envelope in self._inner.snapshot()
            if self._rules.classify(envelope.object_id) == namespace
        )

    def namespace_digest(self, namespace: StateNamespace) -> str:
        return canonical_sha256(
            [envelope.to_dict() for envelope in self.namespace_state(namespace)]
        )


def provision_namespaced_state(
    rules: NamespaceRules,
    initial_state: Mapping[StateNamespace, Iterable[ObjectEnvelope]],
) -> tuple[MemoryStateStore, tuple[tuple[str, tuple[str, ...]], ...]]:
    """Validate and provision per-namespace initial state.

    Every envelope must belong to exactly the namespace it is provisioned
    under (cross-namespace contamination fails closed) and object ids
    must be unique across namespaces. Returns the kernel-owned store and
    the per-namespace object-id inventory (sorted, deterministic).
    """
    if not isinstance(initial_state, Mapping):
        raise CoreValidationError("initial state must be a mapping of namespaces")
    seen: dict[str, StateNamespace] = {}
    grouped: dict[StateNamespace, list[ObjectEnvelope]] = {}
    inventory: list[tuple[str, tuple[str, ...]]] = []
    for namespace, envelopes in initial_state.items():
        if not isinstance(namespace, StateNamespace):
            raise CoreValidationError(
                "initial state keys must be StateNamespace members"
            )
        if namespace in grouped:
            raise CoreValidationError(
                f"initial state declares namespace {namespace.value} twice"
            )
        bucket: list[ObjectEnvelope] = []
        for envelope in envelopes:
            if not isinstance(envelope, ObjectEnvelope):
                raise CoreValidationError(
                    "initial state entries must be ObjectEnvelope instances"
                )
            envelope.verify_integrity()
            classified = rules.classify(envelope.object_id)
            if classified != namespace:
                raise CoreValidationError(
                    f"cross-namespace contamination: object {envelope.object_id!r} "
                    f"classifies into the {classified.value} namespace but was "
                    f"provisioned under {namespace.value}"
                )
            previous = seen.get(envelope.object_id)
            if previous is not None:
                raise CoreValidationError(
                    f"initial state contains duplicate object id {envelope.object_id!r}"
                )
            seen[envelope.object_id] = namespace
            bucket.append(envelope)
        grouped[namespace] = bucket
        inventory.append(
            (namespace.value, tuple(sorted(item.object_id for item in bucket)))
        )
    for namespace in StateNamespace:
        grouped.setdefault(namespace, [])
    store = MemoryStateStore(
        envelope for bucket in grouped.values() for envelope in bucket
    )
    return store, tuple(sorted(inventory))
