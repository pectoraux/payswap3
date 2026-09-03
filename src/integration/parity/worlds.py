"""The two compared environment harnesses of the IG-003 parity gate.

Each world is one environment of the SAME protocol machine (the merged
IG-002 fulfillment lifecycle harness over the real domain engines):
the worlds differ ONLY in their environment binding — the environment
identity, the rail adapter identity, the declared rail fidelity class,
the world-observation epistemic class and the provider-issued reference
prefix — never in financial semantics (the frozen parity invariant).

The world-coupling of each rail is the merged WORK-019 public boundary:
every rail outcome is served by a deterministic
:class:`~src.simulation.ScriptedWorld` of
:class:`~src.simulation.WorldObservation` records addressed by
``(observation_key, as_of)`` with the frozen epistemic class required by
the world's environment mode (:func:`~src.simulation.mode_epistemic_type`
— SIMULATION consumes ``SIMULATED`` observations, PRODUCTION consumes
``OBSERVED``). The declared world-outcome VALUES are identical in both
worlds: given the same inputs and world observations, the protocol
transitions must be identical across environments.

The rails themselves implement the execution domain's typed ports
(:class:`~src.execution.adapters.EffectSubmissionPort` /
:class:`~src.execution.adapters.EffectReconciliationPort`) and are bound
through the canonical interoperability :class:`~src.interoperability.WorldAdapter`
contract with the declared fidelity class (SIMULATION for the simulation
rail, PRODUCTION for the production-compatible rail — both effect-capable
classes of the frozen fidelity vocabulary) and the declared native-status
map. Environment-specific transport details stay HERE, outside the
semantic comparison authority.
"""

from __future__ import annotations

from collections import namedtuple
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.evidence.contracts import EpistemicType
from src.execution.adapters import (
    AdapterBinding,
    AdapterQueryResult,
    AdapterSubmission,
    EffectReconciliationPort,
    EffectSubmissionPort,
)
from src.execution.contracts import QueryOutcome, SubmissionStatus
from src.interoperability import (
    AdapterStatusMap,
    CanonicalPaymentStatus,
    EffectInterface,
    FidelityClass,
    IdentifierScheme,
    ObservationInterface,
    StatusMapEntry,
    WorldAdapter,
)
from src.simulation import (
    EnvironmentMode,
    ScriptedWorld,
    WorldObservation,
    mode_epistemic_type,
)

from .contracts import (
    PARITY_DOMAIN_ID,
    PARITY_WORLD_OBSERVATION_AS_OF,
    PRODUCTION_ADAPTER_ID,
    PRODUCTION_COMPATIBLE_ENVIRONMENT_ID,
    PRODUCTION_NATIVE_PREFIX,
    SIMULATION_ADAPTER_ID,
    SIMULATION_ENVIRONMENT_ID,
    SIMULATION_NATIVE_PREFIX,
    WorldRole,
)

#: The declared native status vocabulary of both parity rails (the same
#: semantic interface; native words map through the adapter status map).
PARITY_STATUS_MAP = (
    StatusMapEntry("ACSD", CanonicalPaymentStatus.ACKNOWLEDGED),
    StatusMapEntry("PDNG", CanonicalPaymentStatus.PROCESSING),
    StatusMapEntry("UKWN", CanonicalPaymentStatus.UNKNOWN),
    StatusMapEntry("RJCT", CanonicalPaymentStatus.FAILED),
    StatusMapEntry("STLD", CanonicalPaymentStatus.SETTLED),
    StatusMapEntry("FINL", CanonicalPaymentStatus.FINAL),
)

_SUBMISSION_OUTCOMES = frozenset({"accept", "reject", "unknown"})
_QUERY_OUTCOMES = frozenset({"succeeded", "failed", "not-found", "unknown"})


@dataclass(frozen=True, slots=True)
class DeclaredRailScript:
    """The declared world-outcome script for one idempotency key.

    Environment-neutral declared data: the SAME script drives both
    worlds (the shared declared input). The rail-side native reference
    is NOT part of the script — each world's rail issues references
    from its own environment prefix plus the key.
    """

    idempotency_key: str
    submission: str
    query: str
    native_status: str | None
    finality_claim: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.idempotency_key, str) or not self.idempotency_key.strip():
            raise CoreValidationError("rail script requires an idempotency key")
        if self.submission not in _SUBMISSION_OUTCOMES:
            raise CoreValidationError(
                f"unknown submission outcome {self.submission!r}; the frozen "
                f"vocabulary is {sorted(_SUBMISSION_OUTCOMES)}"
            )
        if self.query not in _QUERY_OUTCOMES:
            raise CoreValidationError(
                f"unknown query outcome {self.query!r}; the frozen vocabulary "
                f"is {sorted(_QUERY_OUTCOMES)}"
            )
        for optional in (self.native_status, self.finality_claim):
            if optional is not None and (
                not isinstance(optional, str) or not optional.strip()
            ):
                raise CoreValidationError(
                    "optional rail script fields must be non-empty strings"
                )


class ParityRail(EffectSubmissionPort, EffectReconciliationPort):
    """One environment's rail over the WORK-019 deterministic world.

    Every port call observes the world source (a WORK-019
    ``ScriptedWorld``) at the declared ``(observation_key, as_of)`` and
    translates the declared world outcome into the typed adapter
    response. The rail deduplicates submissions on the idempotency key
    (a second call for a processed key returns the recorded submission —
    never a second rail-side effect) and issues native references from
    its environment's prefix. Unknown observations fail closed (the
    WORK-019 world-adapter contract).
    """

    def __init__(
        self,
        *,
        world_source: ScriptedWorld,
        epistemic_class: EpistemicType,
        observation_as_of: str,
        native_prefix: str,
    ) -> None:
        self._world_source = world_source
        self._epistemic_class = epistemic_class
        self._observation_as_of = observation_as_of
        self._native_prefix = native_prefix
        self._processed: dict[str, AdapterSubmission] = {}
        self._rejected: set[str] = set()
        self._native_status: dict[str, str] = {}
        self._consumed: list[WorldObservation] = []
        self.submit_call_count = 0
        self.query_call_count = 0

    # -- world-observation access (declared, deterministic) --------------

    def _observe(self, idempotency_key: str) -> WorldObservation:
        record = self._world_source.observe(
            f"rail/outcome/{idempotency_key}", self._observation_as_of
        )
        if record.epistemic_type is not self._epistemic_class:
            raise CoreValidationError(
                "parity rail world observation carries epistemic class "
                f"{record.epistemic_type.value} while its environment requires "
                f"{self._epistemic_class.value} (mode/epistemic confusion "
                "fails closed)"
            )
        if record not in self._consumed:
            self._consumed.append(record)
        return record

    def _script_value(self, idempotency_key: str) -> Mapping[str, Any]:
        from src.transition.payload import payload_to_json_value

        record = self._observe(idempotency_key)
        # The world-observation value is stored in the kernel's deeply
        # immutable payload form; project it back to the canonical JSON
        # form (the same trusted path the adapter payloads take).
        value = payload_to_json_value(record.value)
        if not isinstance(value, Mapping):
            raise CoreValidationError(
                "parity rail world observation values must be objects"
            )
        return value

    # -- the typed ports ---------------------------------------------------

    def submit_effect(self, request: Any) -> AdapterSubmission:
        self.submit_call_count += 1
        key = request.spec.idempotency_key
        recorded = self._processed.get(key)
        if recorded is not None:
            # Rail-side idempotency: the same key never causes a second
            # rail-side effect (constitution invariant 9).
            return recorded
        script = self._script_value(key)
        submission = script["submission"]
        if submission == "accept":
            result = AdapterSubmission(
                status=SubmissionStatus.ACCEPTED,
                native_reference=self.native_reference_for(key),
                reason=None,
            )
            self._processed[key] = result
        elif submission == "reject":
            result = AdapterSubmission(
                status=SubmissionStatus.REJECTED,
                native_reference=None,
                reason="rail rejected the effect (parity declared script)",
            )
            self._rejected.add(key)
            self._processed[key] = result
        else:
            # A transport failure means the rail never received the
            # submission: nothing is recorded, so reconciliation reports
            # NOT_FOUND (the retry-safe truth) until it resolves.
            result = AdapterSubmission(
                status=SubmissionStatus.UNKNOWN,
                native_reference=None,
                reason="transport failure: no definitive submission response",
            )
        return result

    def query_effect(self, request: Any) -> AdapterQueryResult:
        self.query_call_count += 1
        key = request.spec.idempotency_key
        processed = self._processed.get(key)
        if processed is None:
            # The rail never received this effect (or its submission
            # response was not definitive): NOT_FOUND is retry-safe truth.
            return AdapterQueryResult(
                outcome=QueryOutcome.NOT_FOUND,
                native_reference=None,
                detail="the rail never received or processed this effect",
            )
        script = self._script_value(key)
        outcome = script["query"]
        native_status = script.get("native_status")
        if outcome == "succeeded":
            if isinstance(native_status, str):
                self._native_status[key] = native_status
            return AdapterQueryResult(
                outcome=QueryOutcome.SUCCEEDED,
                native_reference=self.native_reference_for(key),
                detail=None,
            )
        if outcome == "failed":
            if isinstance(native_status, str):
                self._native_status[key] = native_status
            return AdapterQueryResult(
                outcome=QueryOutcome.FAILED,
                native_reference=self.native_reference_for(key),
                detail=None,
            )
        if outcome == "unknown":
            return AdapterQueryResult(
                outcome=QueryOutcome.UNKNOWN,
                native_reference=None,
                detail="rail reconciliation still open (parity declared script)",
            )
        return AdapterQueryResult(
            outcome=QueryOutcome.NOT_FOUND,
            native_reference=None,
            detail="the rail never received or processed this effect",
        )

    # -- deterministic read accessors ---------------------------------------

    def native_reference_for(self, idempotency_key: str) -> str:
        return f"{self._native_prefix}{idempotency_key}"

    def native_status_for(self, idempotency_key: str) -> str | None:
        return self._native_status.get(idempotency_key)

    def finality_claim_for(self, idempotency_key: str) -> str | None:
        return self._script_value(idempotency_key).get("finality_claim")

    def processed_keys(self) -> tuple[str, ...]:
        return tuple(sorted(self._processed))

    def consumed_observations(self) -> tuple[WorldObservation, ...]:
        return tuple(self._consumed)

    def consumed_observation_digest(self) -> str:
        return canonical_sha256(
            {
                "epistemic_class": self._epistemic_class.value,
                "observations": [
                    observation.to_dict() for observation in self._consumed
                ],
            }
        )


@dataclass(frozen=True)
class ParityWorld:
    """One declared environment of the parity comparison.

    ``role`` is the compared environment role; ``mode`` is the frozen
    WORK-019 environment mode the role binds to; ``epistemic_class`` is
    the frozen world-observation class required by that mode; the rail
    ports, the typed adapter binding and the world source (the WORK-019
    deterministic scripted world) complete the environment harness.
    """

    role: WorldRole
    environment_id: str
    domain_id: str
    adapter_id: str
    fidelity_class: str
    mode: EnvironmentMode
    epistemic_class: EpistemicType
    world_source: ScriptedWorld
    rail: ParityRail
    binding: AdapterBinding
    native_prefix: str
    observation_as_of: str
    world_source_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.role, WorldRole):
            raise CoreValidationError("parity world requires a WorldRole")
        if not isinstance(self.mode, EnvironmentMode):
            raise CoreValidationError("parity world requires an EnvironmentMode")
        if not isinstance(self.epistemic_class, EpistemicType):
            raise CoreValidationError("parity world requires an EpistemicType")
        # The frozen mode→epistemic binding is load-bearing: the declared
        # epistemic class must be exactly what the environment mode
        # requires (SIMULATION → SIMULATED, PRODUCTION → OBSERVED).
        required = mode_epistemic_type(self.mode)
        if self.epistemic_class is not required:
            raise CoreValidationError(
                f"parity world role {self.role.value} binds mode "
                f"{self.mode.value} which requires {required.value} world "
                f"observations, but the world declares "
                f"{self.epistemic_class.value} (mode/epistemic confusion "
                "fails closed)"
            )
        if not isinstance(self.world_source, ScriptedWorld):
            raise CoreValidationError("parity world requires a ScriptedWorld")
        if not isinstance(self.rail, ParityRail):
            raise CoreValidationError("parity world requires a ParityRail")
        if not isinstance(self.binding, AdapterBinding):
            raise CoreValidationError("parity world requires an AdapterBinding")
        if self.binding.adapter_id != self.adapter_id:
            raise CoreValidationError("parity world adapter ids must agree")
        if self.binding.world_adapter.fidelity_class.value != self.fidelity_class:
            raise CoreValidationError(
                "parity world fidelity class must match the declared adapter "
                "contract"
            )

    @property
    def environment_class(self) -> str:
        """The capability domain's frozen environment class of the env id."""
        from src.capability import classify_environment

        return classify_environment(self.environment_id)


#: The pair of the two compared environments (deterministic order).
EnvironmentPair = namedtuple("EnvironmentPair", ["simulation", "production"])


def _world_observations(
    scripts: Sequence[DeclaredRailScript],
    *,
    epistemic_type: EpistemicType,
    world_source_id: str,
    as_of: str,
) -> tuple[WorldObservation, ...]:
    observations = []
    for script in scripts:
        if not isinstance(script, DeclaredRailScript):
            raise CoreValidationError(
                "the declared rail scripts must be DeclaredRailScript records"
            )
        observations.append(
            WorldObservation(
                observation_key=f"rail/outcome/{script.idempotency_key}",
                epistemic_type=epistemic_type,
                as_of=as_of,
                value={
                    "submission": script.submission,
                    "query": script.query,
                    "native_status": script.native_status,
                    "finality_claim": script.finality_claim,
                },
                source=world_source_id,
            )
        )
    return tuple(observations)


def _make_world(
    *,
    role: WorldRole,
    mode: EnvironmentMode,
    environment_id: str,
    adapter_id: str,
    fidelity_class: FidelityClass,
    native_prefix: str,
    world_source_id: str,
    scripts: Sequence[DeclaredRailScript],
) -> ParityWorld:
    epistemic_class = mode_epistemic_type(mode)
    observations = _world_observations(
        scripts,
        epistemic_type=epistemic_class,
        world_source_id=world_source_id,
        as_of=PARITY_WORLD_OBSERVATION_AS_OF,
    )
    world_source = ScriptedWorld(
        observations=observations,
        epistemic_type=epistemic_class,
    )
    contract = WorldAdapter(
        adapter_id=adapter_id,
        capability_id=f"capability/{adapter_id.rpartition('/')[2]}",
        observation_interface=ObservationInterface(
            operations=("RESOLVE_ENDPOINT", "PAYMENT_STATUS", "FINALITY")
        ),
        effect_interface=EffectInterface(
            operations=("SUBMIT_PAYMENT",),
            destination_schemes=(IdentifierScheme.ALIAS,),
        ),
        fidelity_class=fidelity_class,
    )
    status_map = AdapterStatusMap(
        adapter_id=adapter_id, entries=PARITY_STATUS_MAP
    )
    rail = ParityRail(
        world_source=world_source,
        epistemic_class=epistemic_class,
        observation_as_of=PARITY_WORLD_OBSERVATION_AS_OF,
        native_prefix=native_prefix,
    )
    binding = AdapterBinding(
        adapter_id=adapter_id,
        submission_port=rail,
        reconciliation_port=rail,
        world_adapter=contract,
        status_map=status_map,
    )
    return ParityWorld(
        role=role,
        environment_id=environment_id,
        domain_id=PARITY_DOMAIN_ID,
        adapter_id=adapter_id,
        fidelity_class=fidelity_class.value,
        mode=mode,
        epistemic_class=epistemic_class,
        world_source=world_source,
        rail=rail,
        binding=binding,
        native_prefix=native_prefix,
        observation_as_of=PARITY_WORLD_OBSERVATION_AS_OF,
        world_source_id=world_source_id,
    )


def build_environment_pair(
    *,
    scripts: Iterable[DeclaredRailScript],
    simulation_environment_id: str = SIMULATION_ENVIRONMENT_ID,
    production_environment_id: str = PRODUCTION_COMPATIBLE_ENVIRONMENT_ID,
    domain_id: str = PARITY_DOMAIN_ID,
) -> EnvironmentPair:
    """Build the two compared environments from ONE declared script set.

    The same declared scripts (the shared declared input) build both
    worlds: identical world-outcome values, identical observation keys
    and instants — differing only in the environment binding (identity,
    mode, epistemic class, fidelity class, adapter identity, native
    reference prefix). Two calls with the same scripts build
    byte-identical environments.
    """
    del domain_id  # the shared domain binding is frozen in the contract
    script_list = tuple(scripts)
    if not script_list:
        raise CoreValidationError(
            "the parity pair requires at least one declared rail script"
        )
    simulation = _make_world(
        role=WorldRole.SIMULATION,
        mode=EnvironmentMode.SIMULATION,
        environment_id=simulation_environment_id,
        adapter_id=SIMULATION_ADAPTER_ID,
        fidelity_class=FidelityClass.SIMULATION,
        native_prefix=SIMULATION_NATIVE_PREFIX,
        world_source_id="world/ig003-simulation",
        scripts=script_list,
    )
    production = _make_world(
        role=WorldRole.PRODUCTION_COMPATIBLE,
        mode=EnvironmentMode.PRODUCTION,
        environment_id=production_environment_id,
        adapter_id=PRODUCTION_ADAPTER_ID,
        fidelity_class=FidelityClass.PRODUCTION,
        native_prefix=PRODUCTION_NATIVE_PREFIX,
        world_source_id="world/ig003-production-compatible",
        scripts=script_list,
    )
    return EnvironmentPair(simulation=simulation, production=production)
