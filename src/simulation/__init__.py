"""PaySwap simulation domain (WORK-019): one machine, many worlds.

The public boundary is typed and versioned:

- one executable protocol machine, many worlds: the
  :class:`~src.simulation.runtime.EnvironmentRuntime` wraps ONE real
  :class:`~src.transition.TransitionEngine` through a shared
  :class:`~src.simulation.runtime.ProtocolBinding` (the same business
  semantics run in every environment); environments differ only in
  world state and permitted external effects — never financial
  semantics (the frozen parity invariant, proven by
  :func:`~src.simulation.runtime.parity_projection` and
  :func:`~src.simulation.runtime.canonical_journal_diff`);
- the six frozen environment modes
  ``SIMULATION/REPLAY/FORECAST/COUNTERFACTUAL/SHADOW/PRODUCTION`` with
  the five separated state namespaces (protocol, value, trust,
  economic, dependency), fail-closed classification, provisioning
  contamination checks and per-namespace digests;
- the deterministic world adapter boundary: every world observation
  carries the frozen epistemic vocabulary (re-used from
  ``src.evidence`` — ``OBSERVED``/``ESTIMATED``/``PREDICTED``/
  ``SIMULATED``/``COUNTERFACTUAL``), an explicit ``as_of`` instant and
  a canonical value; mode/epistemic confusion fails closed at
  construction AND at every observation;
- the effect policy is the ONLY environment difference: simulated,
  replay, forecast and counterfactual environments record effects,
  shadow environments shadow them, and production requires an explicit
  typed :class:`~src.simulation.effects.EffectAuthorization` — and even
  then this package only emits authorized effect records: there is no
  out-of-environment execution path here (constitution invariant 14);
- snapshots, sealed checkpoints (version-chained, tamper-rejecting) and
  deterministic restore, which refuses every cross-boundary restore
  (wrong environment, wrong mode, wrong binding) — simulation state is
  never copied into production financial state;
- deterministic replay with per-entry divergence detection, and
  forecast/counterfactual branching from snapshots (branching into
  production fails closed; promotion is the only path into production
  and it carries digests and metadata only, never state);
- no second authority of any kind: the single canonical hash authority
  seals every object, the kernel's registry validates event types and
  authority classes, the epistemic vocabulary is owned by
  ``src.evidence`` and the single error authority is
  :class:`~src.core.errors.CoreValidationError` re-exported below;
- registry discipline: ``payswap/simulation/v1`` and the ``simulation``
  event namespace are already listed in the frozen protocol registry;
  every other simulation object kind follows the sibling convention and
  uses internal non-registry ``simulation/...`` formats — no new
  protocol-visible name is invented;
- determinism discipline: no wall-clock reads, no entropy sources, no
  generated identifiers — every instant is explicit declared ``as_of``
  data and every digest is canonical.

The domain consumes the merged dependency domains only:
``src.core`` (envelope, canonical serialization, error authority),
``src.transition`` (the real kernel) and ``src.evidence`` (the frozen
epistemic vocabulary). Unmerged sibling implementations are never
imported.
"""

from __future__ import annotations

from ..core.errors import CoreValidationError
from ..evidence.contracts import EpistemicType

from .contracts import (
    MODE_EPISTEMIC_TYPES,
    SIMULATION_API_VERSION,
    SIMULATION_CHECKPOINT_OBJECT_TYPE,
    SIMULATION_COMMANDS,
    SIMULATION_EVENT_NAMESPACE,
    SIMULATION_OBJECT_TYPE,
    SIMULATION_PROTOCOL_VERSION,
    SIMULATION_RESULT_OBJECT_TYPE,
    SIMULATION_RUN_STATES,
    SIMULATION_SCHEMA_VERSION,
    SIMULATION_TERMINAL_STATES,
    EffectDecision,
    EnvironmentMode,
    FaultKind,
    SimulationRunState,
    StateNamespace,
    mode_epistemic_type,
)
from .world import (
    EnvironmentClock,
    ScriptedWorld,
    WorldAdapter,
    WorldObservation,
    WorldView,
)
from .state import (
    DEFAULT_NAMESPACE_RULES,
    NamespaceRule,
    NamespaceRules,
    NamespacedStateStore,
    provision_namespaced_state,
)
from .effects import (
    EffectAuthorization,
    EffectIntent,
    EffectPolicy,
    EffectRecord,
    record_effects,
)
from .runtime import (
    CommandRegistration,
    EnvironmentSpec,
    EnvironmentTransition,
    EnvironmentRuntime,
    FaultInjection,
    ProtocolBinding,
    SimulationOperation,
    TransitionLog,
    WorldAwareHandler,
    canonical_journal_diff,
    parity_digest,
    parity_projection,
    raw_journal_digest,
)
from .snapshots import (
    EnvironmentSnapshot,
    SimulationCheckpoint,
    SimulationResult,
)
from .replay import (
    ReplayEntry,
    ReplayJournal,
    ReplayReport,
    replay,
)
from .branching import (
    BRANCH_PROVENANCE_ISSUER,
    ForecastError,
    branch,
    branch_from,
    forecast_errors,
)
from .promotion import (
    FreshValidation,
    PromotionAuthorization,
    PromotionRequest,
    PromotionVerdict,
    ValidationVerdict,
    decide_promotion_authorization,
    perform_fresh_validation,
    request_promotion,
)

__all__ = [
    # versioned public-boundary contracts
    "SIMULATION_API_VERSION",
    "SIMULATION_PROTOCOL_VERSION",
    "SIMULATION_SCHEMA_VERSION",
    "SIMULATION_OBJECT_TYPE",
    "SIMULATION_CHECKPOINT_OBJECT_TYPE",
    "SIMULATION_RESULT_OBJECT_TYPE",
    "SIMULATION_EVENT_NAMESPACE",
    "SIMULATION_COMMANDS",
    "SIMULATION_RUN_STATES",
    "SIMULATION_TERMINAL_STATES",
    "MODE_EPISTEMIC_TYPES",
    "BRANCH_PROVENANCE_ISSUER",
    # frozen vocabularies
    "EnvironmentMode",
    "StateNamespace",
    "SimulationRunState",
    "EffectDecision",
    "FaultKind",
    "EpistemicType",
    "mode_epistemic_type",
    # the deterministic world boundary
    "WorldAdapter",
    "WorldObservation",
    "WorldView",
    "ScriptedWorld",
    "EnvironmentClock",
    # state namespaces
    "NamespaceRule",
    "NamespaceRules",
    "NamespacedStateStore",
    "DEFAULT_NAMESPACE_RULES",
    "provision_namespaced_state",
    # the effect policy and authorization boundary
    "EffectIntent",
    "EffectAuthorization",
    "EffectPolicy",
    "EffectRecord",
    "record_effects",
    # the environment runtime over the real kernel
    "ProtocolBinding",
    "CommandRegistration",
    "WorldAwareHandler",
    "EnvironmentSpec",
    "EnvironmentRuntime",
    "EnvironmentTransition",
    "SimulationOperation",
    "FaultInjection",
    "TransitionLog",
    "parity_projection",
    "parity_digest",
    "canonical_journal_diff",
    "raw_journal_digest",
    # snapshots, checkpoints and results
    "EnvironmentSnapshot",
    "SimulationCheckpoint",
    "SimulationResult",
    # deterministic replay
    "ReplayJournal",
    "ReplayEntry",
    "ReplayReport",
    "replay",
    # forecast and counterfactual branching
    "branch",
    "branch_from",
    "ForecastError",
    "forecast_errors",
    # the promotion boundary
    "PromotionRequest",
    "FreshValidation",
    "PromotionAuthorization",
    "ValidationVerdict",
    "PromotionVerdict",
    "request_promotion",
    "perform_fresh_validation",
    "decide_promotion_authorization",
    # re-exported owning authorities (single sources: src.core, src.evidence)
    "CoreValidationError",
]
