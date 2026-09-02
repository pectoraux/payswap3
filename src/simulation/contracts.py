"""Frozen public-boundary contracts for the simulation domain (WORK-019).

This package owns the frozen v0.1 ``simulation.md`` environment runtime
abstraction: the six environment modes, the five state namespaces, the
``payswap/simulation/v1`` object identity, the ``simulation`` event
namespace and the frozen ``Simulation`` command family
``Create/Initialize/Run/Pause/Resume/Checkpoint/Step/InjectFault/Branch/
Complete/Fail/Cancel/Replay``.

Registry discipline: ``payswap/simulation/v1`` and the ``simulation``
event namespace are ALREADY listed in the frozen protocol registry; every
other simulation object kind below follows the sibling convention and
uses internal non-registry ``simulation/...`` formats. No new
protocol-visible name is invented here.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Mapping

from src.core.errors import CoreValidationError
from src.transition.registry import PROTOCOL_VERSION

from ._validation import parse_enum, require_text
from src.evidence.contracts import EpistemicType

# -- typed, versioned public boundary --------------------------------------

#: Version of this typed, versioned public boundary.
SIMULATION_API_VERSION = "v0.1"

#: Frozen protocol version consumed (owned by the transition kernel registry).
SIMULATION_PROTOCOL_VERSION = PROTOCOL_VERSION

#: Schema version of simulation-domain durable objects.
SIMULATION_SCHEMA_VERSION = 1

#: Registry-listed protocol object type of the simulation run identity.
SIMULATION_OBJECT_TYPE = "payswap/simulation/v1"

#: Internal (non-registry) object types of simulation-domain durable objects.
SIMULATION_CHECKPOINT_OBJECT_TYPE = "simulation/checkpoint/v1"
SIMULATION_RESULT_OBJECT_TYPE = "simulation/result/v1"

#: Registry-listed protocol event namespace owned by this domain.
SIMULATION_EVENT_NAMESPACE = "simulation"

#: The frozen ``Simulation`` command family (command-event-model.md).
SIMULATION_COMMANDS = frozenset(
    {
        "simulation/create",
        "simulation/initialize",
        "simulation/run",
        "simulation/pause",
        "simulation/resume",
        "simulation/checkpoint",
        "simulation/step",
        "simulation/inject-fault",
        "simulation/branch",
        "simulation/complete",
        "simulation/fail",
        "simulation/cancel",
        "simulation/replay",
    }
)


class EnvironmentMode(StrEnum):
    """Closed vocabulary of the frozen environment kinds (simulation.md).

    One executable protocol machine; the environment supplies protocol
    state, world observations, models, clocks, declared entropy sources
    and an effect policy. Environments differ in world state and
    permitted external effects — never financial semantics.
    """

    SIMULATION = "simulation"
    REPLAY = "replay"
    FORECAST = "forecast"
    COUNTERFACTUAL = "counterfactual"
    SHADOW = "shadow"
    PRODUCTION = "production"

    @classmethod
    def parse(cls, value: object) -> "EnvironmentMode":
        """Fail closed on unknown modes (implementation principle 6)."""
        return parse_enum("environment mode", value, cls)  # type: ignore[return-value]


class StateNamespace(StrEnum):
    """Closed vocabulary of the five separated state namespaces.

    Every environment has separate namespaces for protocol, value, trust,
    economic and dependency state. Simulation may contain a full ledger
    and simulated settlements, but they are not production financial
    effects.
    """

    PROTOCOL = "protocol"
    VALUE = "value"
    TRUST = "trust"
    ECONOMIC = "economic"
    DEPENDENCY = "dependency"

    @classmethod
    def parse(cls, value: object) -> "StateNamespace":
        return parse_enum("state namespace", value, cls)  # type: ignore[return-value]


class SimulationRunState(StrEnum):
    """Closed lifecycle vocabulary of one simulation run."""

    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


#: Terminal run states: history stays immutable after them.
SIMULATION_TERMINAL_STATES = frozenset(
    {
        SimulationRunState.COMPLETED,
        SimulationRunState.FAILED,
        SimulationRunState.CANCELLED,
    }
)

#: All lifecycle states.
SIMULATION_RUN_STATES = frozenset(
    {
        SimulationRunState.RUNNING,
        SimulationRunState.PAUSED,
        SimulationRunState.COMPLETED,
        SimulationRunState.FAILED,
        SimulationRunState.CANCELLED,
    }
)


#: Frozen binding of environment modes to the epistemic type of the world
#: observations they may consume (``simulation.md`` "Epistemic
#: separation", vocabulary owned by ``src.evidence``):
#: simulation consumes ``SIMULATED``, replay/shadow/production consume
#: ``OBSERVED``, forecast consumes ``PREDICTED`` and counterfactual
#: consumes ``COUNTERFACTUAL``. Mode/epistemic confusion fails closed.
MODE_EPISTEMIC_TYPES: Mapping[EnvironmentMode, EpistemicType] = {
    EnvironmentMode.SIMULATION: EpistemicType.SIMULATED,
    EnvironmentMode.REPLAY: EpistemicType.OBSERVED,
    EnvironmentMode.FORECAST: EpistemicType.PREDICTED,
    EnvironmentMode.COUNTERFACTUAL: EpistemicType.COUNTERFACTUAL,
    EnvironmentMode.SHADOW: EpistemicType.OBSERVED,
    EnvironmentMode.PRODUCTION: EpistemicType.OBSERVED,
}


def mode_epistemic_type(mode: EnvironmentMode) -> EpistemicType:
    """The frozen epistemic requirement of one environment mode."""
    if not isinstance(mode, EnvironmentMode):
        raise CoreValidationError("mode must be an EnvironmentMode")
    try:
        return MODE_EPISTEMIC_TYPES[mode]
    except KeyError as exc:
        raise CoreValidationError(
            f"environment mode {mode!r} has no epistemic requirement"
        ) from exc


class EffectDecision(StrEnum):
    """Closed vocabulary of effect policy outcomes.

    Every decision is a typed record — never an executed side effect.
    ``AUTHORIZED`` records authorize real execution that happens outside
    this package, behind the explicit authorization boundary.
    """

    RECORDED = "recorded"
    SHADOWED = "shadowed"
    AUTHORIZED = "authorized"


class FaultKind(StrEnum):
    """Closed vocabulary of debugger fault injections.

    Faults are injected over the REAL protocol machine's inputs — the
    world observations it consumes and the effects its transitions
    request — never over a simulation of the machine.
    """

    WORLD_OBSERVATION_UNAVAILABLE = "world.observation-unavailable"
    EFFECT_FAILURE = "effect.failure"


def validate_operation(operation: str) -> str:
    """Require an operation from the frozen simulation command family."""
    require_text("operation", operation)
    if operation not in SIMULATION_COMMANDS:
        raise CoreValidationError(
            f"operation {operation!r} is not part of the frozen simulation command family"
        )
    return operation
