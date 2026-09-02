"""Forecast and counterfactual state branching (WORK-019).

``COUNTERFACTUAL`` branches from a snapshot with changed assumptions and
``FORECAST`` explores generated future observations. Branching is the
one governed path along which environment state crosses an environment
identity: the branch is a NEW environment that inherits the parent's
protocol history (engine clock, processed-command records and
append-only journal, so duplicates of parent commands converge instead
of re-executing) and its object state re-bound to the branch
environment identity — object ids, version chains, states and
provenance stay exactly as the parent produced them.

Branching into ``PRODUCTION`` fails closed unconditionally (the frozen
promotion path is simulation → evidence → production decision → fresh
validation → production authorization; simulation state is never copied
into production financial state), and a branch must take a NEW
environment id.

This module also owns production feedback:
:func:`forecast_errors` compares predicted world observations with
observed ones through exact integer arithmetic
(:class:`ForecastError`) — predictions are scored, never resealed as
observations.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from src.core.envelope import ObjectEnvelope
from src.core.errors import CoreValidationError

from src.transition import EngineState

from ..evidence.contracts import EpistemicType

from ._validation import (
    require_identifier,
    require_int,
    require_text,
    require_utc_timestamp,
    strict_fields,
)
from .contracts import EnvironmentMode, StateNamespace
from .runtime import (
    EnvironmentRuntime,
    EnvironmentSpec,
    ProtocolBinding,
)
from .snapshots import EnvironmentSnapshot, SimulationCheckpoint
from .state import DEFAULT_NAMESPACE_RULES, NamespaceRules
from .world import WorldAdapter, WorldObservation

#: Default provenance issuer of branched runs.
BRANCH_PROVENANCE_ISSUER = "principal/simulation-operator"

_ERROR_FIELDS = frozenset(
    {
        "observation_key",
        "as_of",
        "predicted_value",
        "observed_value",
        "signed_error",
        "absolute_error",
    }
)


def _rebind(envelope: ObjectEnvelope, environment_id: str) -> ObjectEnvelope:
    """Re-issue one parent state object under the branch environment identity.

    Everything except the environment identity stays exactly as the
    parent produced it (object id, type, version chain, state,
    provenance, causation, correlation); the integrity seal is recomputed
    with the single canonical hash authority.
    """
    return ObjectEnvelope(
        object_id=envelope.object_id,
        object_type=envelope.object_type,
        object_version=envelope.object_version,
        environment_id=environment_id,
        domain_id=envelope.domain_id,
        schema_version=envelope.schema_version,
        protocol_version=envelope.protocol_version,
        state=envelope.state,
        provenance=envelope.provenance,
        causation_id=envelope.causation_id,
        correlation_id=envelope.correlation_id,
        previous_version=envelope.previous_version,
    ).with_integrity_hash()


def _require_branch_inputs(
    *,
    environment_id: str,
    mode: EnvironmentMode,
    world: WorldAdapter,
) -> None:
    require_identifier("branch environment_id", environment_id)
    if not isinstance(mode, EnvironmentMode):
        raise CoreValidationError("branch mode must be an EnvironmentMode")
    if not isinstance(world, WorldAdapter):
        raise CoreValidationError("branch requires a WorldAdapter")
    if mode is EnvironmentMode.PRODUCTION:
        raise CoreValidationError(
            "branching into production fails closed: simulation state is never "
            "copied into production financial state (promotion is the only "
            "path and it carries no state)"
        )


def _branch_runtime(
    snapshot: EnvironmentSnapshot,
    *,
    binding: ProtocolBinding,
    rules: NamespaceRules,
    at: str,
    environment_id: str,
    mode: EnvironmentMode,
    world: WorldAdapter,
    branched_from: str,
    provenance_issuer: str,
) -> EnvironmentRuntime:
    """Construct the branch environment from one sealed parent snapshot."""
    grouped: dict[StateNamespace, list[ObjectEnvelope]] = {}
    for item in snapshot.objects:
        envelope = ObjectEnvelope.from_dict(item)
        grouped.setdefault(rules.classify(envelope.object_id), []).append(
            _rebind(envelope, environment_id)
        )
    runtime = EnvironmentRuntime(
        spec=EnvironmentSpec(
            environment_id=environment_id,
            mode=mode,
            domain_id=snapshot.domain_id,
            as_of=at,
        ),
        binding=binding,
        world=world,
        namespace_rules=rules,
        initial_state=grouped,
        simulation_id=f"simulation/branch/{environment_id}",
        provenance_issuer=provenance_issuer,
        first_operation="simulation/branch",
        branched_from=branched_from,
    )
    runtime._adopt_engine_state(  # package-internal branching hook
        EngineState.from_dict(snapshot.engine_state), as_of=at
    )
    return runtime


def branch_from(
    parent: EnvironmentRuntime,
    *,
    at: str,
    environment_id: str,
    mode: EnvironmentMode,
    world: WorldAdapter,
    label: str = "",
    provenance_issuer: str = BRANCH_PROVENANCE_ISSUER,
) -> EnvironmentRuntime:
    """Branch a new environment from one live parent runtime.

    The parent is never mutated: a snapshot is captured (its journal,
    state and namespace digests are unchanged afterwards) and becomes the
    branch's inheritance. The branch must take a new environment id and
    a non-production mode; the world must satisfy the frozen
    mode/epistemic binding (counterfactual worlds carry ``COUNTERFACTUAL``
    observations, forecast worlds carry ``PREDICTED`` ones).
    """
    if not isinstance(parent, EnvironmentRuntime):
        raise CoreValidationError("branch_from requires an EnvironmentRuntime parent")
    require_utc_timestamp("branch at", at)
    require_text("branch provenance_issuer", provenance_issuer)
    _require_branch_inputs(
        environment_id=environment_id, mode=mode, world=world
    )
    if environment_id == parent.environment_id:
        raise CoreValidationError(
            "a branch requires a new environment id distinct from the parent "
            f"environment {parent.environment_id}"
        )
    snapshot = parent.snapshot(
        label=label if label else f"branch/{environment_id}", at=at
    )
    if snapshot.content_digest is None:  # pragma: no cover - snapshots self-seal
        raise CoreValidationError("branch source snapshot is not sealed")
    return _branch_runtime(
        snapshot,
        binding=parent.binding,
        rules=parent.namespace_rules,
        at=at,
        environment_id=environment_id,
        mode=mode,
        world=world,
        branched_from=snapshot.content_digest,
        provenance_issuer=provenance_issuer,
    )


def branch(
    checkpoint: SimulationCheckpoint,
    *,
    binding: ProtocolBinding,
    environment_id: str,
    mode: EnvironmentMode,
    world: WorldAdapter,
    provenance_issuer: str = BRANCH_PROVENANCE_ISSUER,
) -> EnvironmentRuntime:
    """Branch a new environment from one sealed checkpoint.

    The checkpoint must be sealed for the same binding (the same
    protocol machine) and the default namespace classification; its
    snapshot content digest is verified first. The branch's simulation
    envelope carries the checkpoint digest as its causation reference.
    """
    if not isinstance(checkpoint, SimulationCheckpoint):
        raise CoreValidationError("branch requires a SimulationCheckpoint")
    if not isinstance(binding, ProtocolBinding):
        raise CoreValidationError("branch requires a ProtocolBinding")
    require_text("branch provenance_issuer", provenance_issuer)
    _require_branch_inputs(
        environment_id=environment_id, mode=mode, world=world
    )
    snapshot = checkpoint.snapshot  # verifies the sealed snapshot content
    if environment_id == snapshot.environment_id:
        raise CoreValidationError(
            "a branch requires a new environment id distinct from the source "
            f"environment {snapshot.environment_id}"
        )
    if snapshot.binding_fingerprint != binding.fingerprint:
        raise CoreValidationError(
            "branch fails closed: the binding fingerprint does not match the "
            "checkpoint (the same protocol machine must reconstruct the state)"
        )
    if snapshot.namespace_rules_digest != DEFAULT_NAMESPACE_RULES.digest:
        raise CoreValidationError(
            "branch fails closed: the namespace rules digest does not match "
            "the default classification of this domain"
        )
    return _branch_runtime(
        snapshot,
        binding=binding,
        rules=DEFAULT_NAMESPACE_RULES,
        at=snapshot.recorded_at,
        environment_id=environment_id,
        mode=mode,
        world=world,
        branched_from=checkpoint.checkpoint_digest,
        provenance_issuer=provenance_issuer,
    )


@dataclass(frozen=True, slots=True)
class ForecastError:
    """One exact-integer prediction error.

    Production feedback compares predictions with observations; the
    arithmetic is exact integer arithmetic — no floating-point value is
    ever constructed — and the signed error is always
    ``observed - predicted``.
    """

    observation_key: str
    as_of: str
    predicted_value: int
    observed_value: int
    signed_error: int
    absolute_error: int

    def __post_init__(self) -> None:
        require_identifier("forecast error observation_key", self.observation_key)
        require_utc_timestamp("forecast error as_of", self.as_of)
        for name in (
            "predicted_value",
            "observed_value",
            "signed_error",
            "absolute_error",
        ):
            require_int(f"forecast error {name}", getattr(self, name))
        if self.signed_error != self.observed_value - self.predicted_value:
            raise CoreValidationError(
                "forecast error signed_error must be observed minus predicted"
            )
        if self.absolute_error != abs(self.signed_error):
            raise CoreValidationError(
                "forecast error absolute_error must be the absolute signed error"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "observation_key": self.observation_key,
            "as_of": self.as_of,
            "predicted_value": self.predicted_value,
            "observed_value": self.observed_value,
            "signed_error": self.signed_error,
            "absolute_error": self.absolute_error,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ForecastError":
        if not isinstance(value, Mapping):
            raise CoreValidationError("forecast error must be an object")
        strict_fields("forecast error", value, _ERROR_FIELDS)
        return cls(
            observation_key=value["observation_key"],
            as_of=value["as_of"],
            predicted_value=value["predicted_value"],
            observed_value=value["observed_value"],
            signed_error=value["signed_error"],
            absolute_error=value["absolute_error"],
        )


def forecast_errors(
    predicted: tuple[WorldObservation, ...],
    observed: tuple[WorldObservation, ...],
) -> tuple[ForecastError, ...]:
    """Score predictions against observations with exact integer arithmetic.

    Fail-closed contract:

    * every prediction must carry ``PREDICTED`` and every observation
      ``OBSERVED`` (epistemic confusion never crosses);
    * pairing is total and unambiguous by
      ``(observation_key, as_of)`` — duplicate pairs and gaps (a
      prediction without its observation, or an observation without its
      prediction) fail closed;
    * both values must be exact integers.

    Predictions are scored; they are never re-sealed as observations and
    never rewrite financial truth.
    """
    predicted_tuple = tuple(predicted)
    observed_tuple = tuple(observed)
    for observation in predicted_tuple:
        if not isinstance(observation, WorldObservation):
            raise CoreValidationError(
                "forecast comparisons consume WorldObservation records"
            )
        if observation.epistemic_type is not EpistemicType.PREDICTED:
            raise CoreValidationError(
                "epistemic-type confusion: forecast comparisons consume "
                "PREDICTED observations but "
                f"{observation.observation_key!r} carries "
                f"{observation.epistemic_type.value}"
            )
        if not isinstance(observation.value, int) or isinstance(
            observation.value, bool
        ):
            raise CoreValidationError(
                "forecast error arithmetic is exact integer arithmetic; "
                f"{observation.observation_key!r} carries a non-integer "
                "predicted value"
            )
    for observation in observed_tuple:
        if not isinstance(observation, WorldObservation):
            raise CoreValidationError(
                "forecast comparisons consume WorldObservation records"
            )
        if observation.epistemic_type is not EpistemicType.OBSERVED:
            raise CoreValidationError(
                "epistemic-type confusion: forecast comparisons consume "
                "OBSERVED observations but "
                f"{observation.observation_key!r} carries "
                f"{observation.epistemic_type.value}"
            )
        if not isinstance(observation.value, int) or isinstance(
            observation.value, bool
        ):
            raise CoreValidationError(
                "forecast error arithmetic is exact integer arithmetic; "
                f"{observation.observation_key!r} carries a non-integer "
                "observed value"
            )
    predicted_map = {
        (item.observation_key, item.as_of): item for item in predicted_tuple
    }
    observed_map = {
        (item.observation_key, item.as_of): item for item in observed_tuple
    }
    if len(predicted_map) != len(predicted_tuple) or len(observed_map) != len(
        observed_tuple
    ):
        raise CoreValidationError(
            "forecast comparisons fail closed on duplicate "
            "(observation_key, as_of) pairs"
        )
    if set(predicted_map) != set(observed_map):
        unobserved = sorted(set(predicted_map) - set(observed_map))
        unpredicted = sorted(set(observed_map) - set(predicted_map))
        raise CoreValidationError(
            "prediction/observation pairing is incomplete: predictions "
            f"without observations={unobserved}, observations without "
            f"predictions={unpredicted}"
        )
    errors: list[ForecastError] = []
    for key in sorted(predicted_map):
        prediction = predicted_map[key]
        observation = observed_map[key]
        signed = observation.value - prediction.value
        errors.append(
            ForecastError(
                observation_key=prediction.observation_key,
                as_of=prediction.as_of,
                predicted_value=prediction.value,
                observed_value=observation.value,
                signed_error=signed,
                absolute_error=abs(signed),
            )
        )
    return tuple(errors)
