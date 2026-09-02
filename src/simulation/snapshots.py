"""Snapshots, sealed checkpoints and simulation results (WORK-019).

An :class:`EnvironmentSnapshot` is the complete deterministic state of
one environment at one instant: kernel engine state (clock, idempotency
records, append-only journal), all namespaced object state, the world
observation journal, the effect journal, the operation journal and the
simulation run envelope — sealed with a content digest computed by the
single canonical hash authority.

A :class:`SimulationCheckpoint` wraps a snapshot in a durable sealed
composite (canonical core envelope + payload + domain seal) with a
checkpoint chain (sequence and parent digest), mirroring the
``SimulationCheckpoint`` object of the canonical object model. A
:class:`SimulationResult` is the sealed terminal outcome record of one
run.

Tampered or spliced composites fail closed on the trusted
deserialization path; no second hash authority is introduced.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256

from ._validation import (
    require_identifier,
    require_int,
    require_text,
    require_utc_timestamp,
    strict_fields,
)
from .contracts import (
    SIMULATION_CHECKPOINT_OBJECT_TYPE,
    SIMULATION_PROTOCOL_VERSION,
    SIMULATION_RESULT_OBJECT_TYPE,
    SIMULATION_SCHEMA_VERSION,
    EnvironmentMode,
    SimulationRunState,
)

_SNAPSHOT_FIELDS = frozenset(
    {
        "environment_id",
        "mode",
        "domain_id",
        "as_of",
        "clock",
        "label",
        "recorded_at",
        "binding_fingerprint",
        "namespace_rules_digest",
        "engine_state",
        "objects",
        "namespace_digests",
        "observation_journal",
        "effect_journal",
        "operation_journal",
        "transition_log",
        "active_faults",
        "simulation_envelope",
        "content_digest",
    }
)


def _require_digest(value: str) -> str:
    require_text("digest", value)
    if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise CoreValidationError("digest must be a canonical SHA-256 hex digest")
    return value


@dataclass(frozen=True, slots=True)
class EnvironmentSnapshot:
    """Complete deterministic environment state at one instant."""

    environment_id: str
    mode: EnvironmentMode
    domain_id: str
    as_of: str
    clock: int
    label: str
    recorded_at: str
    binding_fingerprint: str
    namespace_rules_digest: str
    engine_state: dict[str, Any]
    objects: tuple[dict[str, Any], ...]
    namespace_digests: tuple[tuple[str, str], ...]
    observation_journal: tuple[dict[str, Any], ...]
    effect_journal: tuple[dict[str, Any], ...]
    operation_journal: tuple[dict[str, Any], ...]
    transition_log: tuple[dict[str, Any], ...]
    active_faults: tuple[tuple[str, str, str], ...]
    simulation_envelope: dict[str, Any]
    content_digest: str | None = None

    def __post_init__(self) -> None:
        require_identifier("snapshot environment_id", self.environment_id)
        if not isinstance(self.mode, EnvironmentMode):
            raise CoreValidationError("snapshot mode must be an EnvironmentMode")
        require_identifier("snapshot domain_id", self.domain_id)
        require_utc_timestamp("snapshot as_of", self.as_of)
        require_int("snapshot clock", self.clock, minimum=0)
        require_text("snapshot label", self.label)
        require_utc_timestamp("snapshot recorded_at", self.recorded_at)
        _require_digest(self.binding_fingerprint)
        _require_digest(self.namespace_rules_digest)
        if not isinstance(self.engine_state, Mapping):
            raise CoreValidationError("snapshot engine_state must be an object")
        for name in (
            "objects",
            "observation_journal",
            "effect_journal",
            "operation_journal",
            "transition_log",
        ):
            if not isinstance(getattr(self, name), tuple):
                raise CoreValidationError(f"snapshot {name} must be a tuple")
        for item in self.objects:
            if not isinstance(item, Mapping):
                raise CoreValidationError("snapshot object entries must be objects")
        for pair in self.namespace_digests:
            if not isinstance(pair, tuple) or len(pair) != 2:
                raise CoreValidationError(
                    "snapshot namespace_digests entries must be (namespace, digest) tuples"
                )
        for fault in self.active_faults:
            if not isinstance(fault, tuple) or len(fault) != 3:
                raise CoreValidationError(
                    "snapshot active_faults entries must be (kind, target, reason) tuples"
                )
        if not isinstance(self.simulation_envelope, Mapping):
            raise CoreValidationError("snapshot simulation_envelope must be an object")
        expected = canonical_sha256(self._content())
        if self.content_digest is None:
            object.__setattr__(self, "content_digest", expected)
        elif self.content_digest != expected:
            raise CoreValidationError(
                "snapshot content digest mismatch; tampered snapshots fail closed"
            )

    def _content(self) -> dict[str, Any]:
        return {
            "environment_id": self.environment_id,
            "mode": self.mode.value,
            "domain_id": self.domain_id,
            "as_of": self.as_of,
            "clock": self.clock,
            "label": self.label,
            "recorded_at": self.recorded_at,
            "binding_fingerprint": self.binding_fingerprint,
            "namespace_rules_digest": self.namespace_rules_digest,
            "engine_state": self.engine_state,
            "objects": list(self.objects),
            "namespace_digests": [list(pair) for pair in self.namespace_digests],
            "observation_journal": list(self.observation_journal),
            "effect_journal": list(self.effect_journal),
            "operation_journal": list(self.operation_journal),
            "transition_log": list(self.transition_log),
            "active_faults": [list(fault) for fault in self.active_faults],
            "simulation_envelope": self.simulation_envelope,
        }

    def to_dict(self) -> dict[str, Any]:
        content = self._content()
        content["content_digest"] = self.content_digest
        return content

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EnvironmentSnapshot":
        if not isinstance(value, Mapping):
            raise CoreValidationError("environment snapshot must be an object")
        strict_fields("environment snapshot", value, _SNAPSHOT_FIELDS)
        namespace_digests = value["namespace_digests"]
        active_faults = value["active_faults"]
        if not isinstance(namespace_digests, list) or not isinstance(active_faults, list):
            raise CoreValidationError(
                "snapshot digest and fault inventories must deserialize from lists"
            )
        return cls(
            environment_id=value["environment_id"],
            mode=EnvironmentMode.parse(value["mode"]),
            domain_id=value["domain_id"],
            as_of=value["as_of"],
            clock=value["clock"],
            label=value["label"],
            recorded_at=value["recorded_at"],
            binding_fingerprint=value["binding_fingerprint"],
            namespace_rules_digest=value["namespace_rules_digest"],
            engine_state=value["engine_state"],
            objects=tuple(value["objects"]),
            namespace_digests=tuple(
                (pair[0], pair[1]) for pair in namespace_digests
            ),
            observation_journal=tuple(value["observation_journal"]),
            effect_journal=tuple(value["effect_journal"]),
            operation_journal=tuple(value["operation_journal"]),
            transition_log=tuple(value["transition_log"]),
            active_faults=tuple(
                (fault[0], fault[1], fault[2]) for fault in active_faults
            ),
            simulation_envelope=value["simulation_envelope"],
            content_digest=value["content_digest"],
        )

    def verify(self) -> None:
        """Fail closed unless the recorded content digest matches the content."""
        expected = canonical_sha256(self._content())
        if self.content_digest != expected:
            raise CoreValidationError(
                "snapshot content digest mismatch; tampered snapshots fail closed"
            )


def _seal_composite(envelope: ObjectEnvelope, payload_json: Any) -> str:
    return canonical_sha256({"envelope": envelope.to_dict(), "payload": payload_json})


@dataclass(frozen=True, slots=True)
class SimulationCheckpoint:
    """A sealed durable checkpoint: envelope + snapshot payload + domain seal."""

    envelope: ObjectEnvelope
    payload: Any
    integrity_hash: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("checkpoint envelope must be an ObjectEnvelope")
        if self.envelope.object_type != SIMULATION_CHECKPOINT_OBJECT_TYPE:
            raise CoreValidationError(
                "checkpoint envelope object_type must be "
                f"{SIMULATION_CHECKPOINT_OBJECT_TYPE}"
            )
        if self.envelope.protocol_version != SIMULATION_PROTOCOL_VERSION:
            raise CoreValidationError(
                "checkpoint envelope protocol version must be "
                f"{SIMULATION_PROTOCOL_VERSION}"
            )
        if self.envelope.schema_version != SIMULATION_SCHEMA_VERSION:
            raise CoreValidationError(
                "checkpoint envelope schema version must be "
                f"{SIMULATION_SCHEMA_VERSION}"
            )
        expected = _seal_composite(self.envelope, self._payload_json())
        if self.integrity_hash is None:
            object.__setattr__(self, "integrity_hash", expected)
        elif self.integrity_hash != expected:
            raise CoreValidationError(
                f"integrity hash mismatch for checkpoint {self.envelope.object_id}"
            )

    def _payload_json(self) -> Any:
        from src.transition.payload import payload_to_json_value

        return payload_to_json_value(self.payload)

    @property
    def sequence(self) -> int:
        from src.transition.payload import payload_to_json_value

        payload = payload_to_json_value(self.payload)
        return int(payload["sequence"])

    @property
    def parent_checkpoint_digest(self) -> str | None:
        from src.transition.payload import payload_to_json_value

        payload = payload_to_json_value(self.payload)
        return payload["parent_checkpoint_digest"]

    @property
    def snapshot(self) -> EnvironmentSnapshot:
        from src.transition.payload import payload_to_json_value

        payload = payload_to_json_value(self.payload)
        return EnvironmentSnapshot.from_dict(payload["snapshot"])

    @property
    def checkpoint_digest(self) -> str:
        if self.integrity_hash is None:  # pragma: no cover - post_init seals
            raise CoreValidationError("checkpoint is not sealed")
        return self.integrity_hash

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "payload": self._payload_json(),
            "integrity_hash": self.integrity_hash,
        }

    @classmethod
    def seal(
        cls,
        *,
        snapshot: EnvironmentSnapshot,
        sequence: int,
        parent_checkpoint_digest: str | None,
        provenance: Provenance,
        checkpoint_id: str,
    ) -> "SimulationCheckpoint":
        from src.transition.payload import normalize_payload

        require_int("checkpoint sequence", sequence, minimum=1)
        if parent_checkpoint_digest is not None:
            _require_digest(parent_checkpoint_digest)
        require_identifier("checkpoint id", checkpoint_id)
        envelope = ObjectEnvelope(
            object_id=checkpoint_id,
            object_type=SIMULATION_CHECKPOINT_OBJECT_TYPE,
            object_version=1,
            environment_id=snapshot.environment_id,
            domain_id=snapshot.domain_id,
            schema_version=SIMULATION_SCHEMA_VERSION,
            protocol_version=SIMULATION_PROTOCOL_VERSION,
            state="SEALED",
            provenance=provenance,
            causation_id=None,
            correlation_id=None,
            previous_version=None,
        ).with_integrity_hash()
        payload = normalize_payload(
            "checkpoint payload",
            {
                "snapshot": snapshot.to_dict(),
                "sequence": sequence,
                "parent_checkpoint_digest": parent_checkpoint_digest,
            },
        )
        return cls(envelope=envelope, payload=payload)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SimulationCheckpoint":
        from src.transition.payload import normalize_payload

        if not isinstance(value, Mapping):
            raise CoreValidationError("simulation checkpoint must be an object")
        strict_fields(
            "simulation checkpoint", value, frozenset({"envelope", "payload", "integrity_hash"})
        )
        envelope = ObjectEnvelope.from_dict(value["envelope"])
        if envelope.state != "SEALED":
            raise CoreValidationError("checkpoint envelope state must be SEALED")
        payload = normalize_payload("checkpoint payload", value["payload"])
        return cls(envelope=envelope, payload=payload, integrity_hash=value["integrity_hash"])


@dataclass(frozen=True, slots=True)
class SimulationResult:
    """The sealed terminal outcome record of one simulation run."""

    envelope: ObjectEnvelope
    payload: Any
    integrity_hash: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("result envelope must be an ObjectEnvelope")
        if self.envelope.object_type != SIMULATION_RESULT_OBJECT_TYPE:
            raise CoreValidationError(
                "result envelope object_type must be "
                f"{SIMULATION_RESULT_OBJECT_TYPE}"
            )
        if self.envelope.protocol_version != SIMULATION_PROTOCOL_VERSION:
            raise CoreValidationError(
                "result envelope protocol version must be "
                f"{SIMULATION_PROTOCOL_VERSION}"
            )
        if self.envelope.schema_version != SIMULATION_SCHEMA_VERSION:
            raise CoreValidationError(
                "result envelope schema version must be "
                f"{SIMULATION_SCHEMA_VERSION}"
            )
        try:
            SimulationRunState(self.envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"unknown simulation result state: {self.envelope.state!r}"
            ) from exc
        expected = _seal_composite(self.envelope, self._payload_json())
        if self.integrity_hash is None:
            object.__setattr__(self, "integrity_hash", expected)
        elif self.integrity_hash != expected:
            raise CoreValidationError(
                f"integrity hash mismatch for result {self.envelope.object_id}"
            )

    def _payload_json(self) -> Any:
        from src.transition.payload import payload_to_json_value

        return payload_to_json_value(self.payload)

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "payload": self._payload_json(),
            "integrity_hash": self.integrity_hash,
        }

    @classmethod
    def seal(
        cls,
        *,
        environment_id: str,
        domain_id: str,
        mode: EnvironmentMode,
        run_state: SimulationRunState,
        at: str,
        provenance: Provenance,
        result_id: str,
        journal_digest: str,
        state_digest: str,
        parity_digest: str,
        namespace_digests: Iterable[tuple[str, str]],
        transition_count: int,
        observation_count: int,
        effect_count: int,
        note: str,
    ) -> "SimulationResult":
        from src.transition.payload import normalize_payload

        require_identifier("result id", result_id)
        require_identifier("result environment_id", environment_id)
        require_identifier("result domain_id", domain_id)
        if not isinstance(mode, EnvironmentMode):
            raise CoreValidationError("result mode must be an EnvironmentMode")
        if not isinstance(run_state, SimulationRunState):
            raise CoreValidationError("result run_state must be a SimulationRunState")
        if run_state not in (
            SimulationRunState.COMPLETED,
            SimulationRunState.FAILED,
            SimulationRunState.CANCELLED,
        ):
            raise CoreValidationError(
                "simulation results are sealed only for terminal run states"
            )
        require_utc_timestamp("result at", at)
        require_text("result note", note)
        require_int("result transition_count", transition_count, minimum=0)
        require_int("result observation_count", observation_count, minimum=0)
        require_int("result effect_count", effect_count, minimum=0)
        envelope = ObjectEnvelope(
            object_id=result_id,
            object_type=SIMULATION_RESULT_OBJECT_TYPE,
            object_version=1,
            environment_id=environment_id,
            domain_id=domain_id,
            schema_version=SIMULATION_SCHEMA_VERSION,
            protocol_version=SIMULATION_PROTOCOL_VERSION,
            state=run_state.value,
            provenance=provenance,
            causation_id=None,
            correlation_id=None,
            previous_version=None,
        ).with_integrity_hash()
        payload = normalize_payload(
            "result payload",
            {
                "environment_id": environment_id,
                "mode": mode.value,
                "note": note,
                "journal_digest": journal_digest,
                "state_digest": state_digest,
                "parity_digest": parity_digest,
                "namespace_digests": [list(pair) for pair in namespace_digests],
                "transition_count": transition_count,
                "observation_count": observation_count,
                "effect_count": effect_count,
            },
        )
        return cls(envelope=envelope, payload=payload)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SimulationResult":
        from src.transition.payload import normalize_payload

        if not isinstance(value, Mapping):
            raise CoreValidationError("simulation result must be an object")
        strict_fields(
            "simulation result", value, frozenset({"envelope", "payload", "integrity_hash"})
        )
        envelope = ObjectEnvelope.from_dict(value["envelope"])
        try:
            SimulationRunState(envelope.state)
        except ValueError as exc:
            raise CoreValidationError(
                f"unknown simulation result state: {envelope.state!r}"
            ) from exc
        payload = normalize_payload("result payload", value["payload"])
        return cls(envelope=envelope, payload=payload, integrity_hash=value["integrity_hash"])
