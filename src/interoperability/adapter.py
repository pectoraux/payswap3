from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Iterable, Mapping

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_json, loads_canonical

from .identifiers import IdentifierScheme
from .message import CanonicalPaymentMessage
from .records import (
    _require_text,
    coerce_enum,
    require_adapter_id,
)
from .status import CanonicalPaymentStatus, coerce_payment_status

# Fidelity classes follow the one-machine/many-worlds modes of the frozen
# simulation contract: production and simulation adapters implement the same
# semantic interface and differ exactly in their world coupling. SHADOW, REPLAY
# and FORECAST adapters are pure observation and must not declare effects.
class FidelityClass(StrEnum):
    PRODUCTION = "PRODUCTION"
    SHADOW = "SHADOW"
    SIMULATION = "SIMULATION"
    REPLAY = "REPLAY"
    FORECAST = "FORECAST"
    COUNTERFACTUAL = "COUNTERFACTUAL"


EFFECT_CAPABLE_FIDELITY_CLASSES: frozenset[FidelityClass] = frozenset({
    FidelityClass.PRODUCTION,
    FidelityClass.SIMULATION,
    FidelityClass.COUNTERFACTUAL,
})


# Observation operations of the world adapter semantic interface, derived from
# the frozen external command surface (ResolveEndpoint / RecordStatus /
# RecordFinality).
class ObservationOperation(StrEnum):
    RESOLVE_ENDPOINT = "RESOLVE_ENDPOINT"
    PAYMENT_STATUS = "PAYMENT_STATUS"
    FINALITY = "FINALITY"


# Effect operations of the world adapter semantic interface, derived from the
# frozen external command surface (RequestEffect) and the recourse reversal
# commands. Reversal capability presupposes submission capability.
class EffectOperation(StrEnum):
    SUBMIT_PAYMENT = "SUBMIT_PAYMENT"
    REVERSE_PAYMENT = "REVERSE_PAYMENT"


_JURISDICTION = re.compile(r"[A-Z]{2}")
_MAX_SCALE = 18

_OBSERVATION_KEYS = frozenset({"operations"})
_EFFECT_KEYS = frozenset({"operations", "destination_schemes"})
_ADAPTER_KEYS = frozenset(
    {
        "adapter_id",
        "capability_id",
        "observation_interface",
        "effect_interface",
        "fidelity_class",
    }
)
_STATUS_ENTRY_KEYS = frozenset({"native_code", "canonical_status"})
_STATUS_MAP_KEYS = frozenset({"adapter_id", "entries"})
_DOMESTIC_KEYS = frozenset(
    {
        "adapter_id",
        "message_id",
        "end_to_end_id",
        "currency",
        "amount_value",
        "amount_scale",
        "destination_scheme",
        "destination_value",
        "destination_jurisdiction",
        "endpoint_id",
    }
)


def _coerce_operations(
    name: str,
    enum_cls: type[StrEnum],
    values: Any,
) -> tuple[Any, ...]:
    if not isinstance(values, tuple):
        raise CoreValidationError(f"{name} must be a tuple")
    operations = tuple(
        coerce_enum(f"{name}[{index}]", enum_cls, item)
        for index, item in enumerate(values)
    )
    if len(operations) != len(set(operations)):
        raise CoreValidationError(f"{name} declares duplicate operations")
    return operations


@dataclass(frozen=True, slots=True)
class ObservationInterface:
    """Declared observation surface of a world adapter."""

    operations: tuple[ObservationOperation, ...]

    def __post_init__(self) -> None:
        operations = _coerce_operations(
            "observation_interface.operations", ObservationOperation, self.operations
        )
        if not operations:
            raise CoreValidationError(
                "observation_interface must declare at least one operation"
            )
        object.__setattr__(self, "operations", operations)

    def to_dict(self) -> dict[str, Any]:
        return {"operations": [operation.value for operation in self.operations]}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ObservationInterface":
        if not isinstance(value, Mapping):
            raise CoreValidationError("observation interface must be an object")
        if set(value) != _OBSERVATION_KEYS:
            missing = sorted(_OBSERVATION_KEYS - set(value))
            extra = sorted(set(value) - _OBSERVATION_KEYS)
            raise CoreValidationError(
                f"non-canonical observation interface fields; missing={missing}, extra={extra}"
            )
        return cls(operations=tuple(value["operations"]))


@dataclass(frozen=True, slots=True)
class EffectInterface:
    """Declared effect surface of a world adapter.

    An effectful adapter must declare the destination identifier schemes it
    can address; a pure observation adapter declares neither effects nor
    schemes.
    """

    operations: tuple[EffectOperation, ...] = ()
    destination_schemes: tuple[IdentifierScheme, ...] = ()

    def __post_init__(self) -> None:
        operations = _coerce_operations(
            "effect_interface.operations", EffectOperation, self.operations
        )
        if not isinstance(self.destination_schemes, tuple):
            raise CoreValidationError("effect_interface.destination_schemes must be a tuple")
        schemes = tuple(
            coerce_enum(
                f"effect_interface.destination_schemes[{index}]",
                IdentifierScheme,
                item,
            )
            for index, item in enumerate(self.destination_schemes)
        )
        if len(schemes) != len(set(schemes)):
            raise CoreValidationError(
                "effect_interface.destination_schemes declares duplicate schemes"
            )
        if operations and not schemes:
            raise CoreValidationError(
                "an effectful adapter must declare the destination schemes it supports"
            )
        if schemes and not operations:
            raise CoreValidationError(
                "a pure observation adapter must not declare destination schemes"
            )
        if EffectOperation.REVERSE_PAYMENT in operations and (
            EffectOperation.SUBMIT_PAYMENT not in operations
        ):
            raise CoreValidationError(
                "REVERSE_PAYMENT requires the SUBMIT_PAYMENT effect operation"
            )
        object.__setattr__(self, "operations", operations)
        object.__setattr__(self, "destination_schemes", schemes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "operations": [operation.value for operation in self.operations],
            "destination_schemes": [scheme.value for scheme in self.destination_schemes],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EffectInterface":
        if not isinstance(value, Mapping):
            raise CoreValidationError("effect interface must be an object")
        if set(value) != _EFFECT_KEYS:
            missing = sorted(_EFFECT_KEYS - set(value))
            extra = sorted(set(value) - _EFFECT_KEYS)
            raise CoreValidationError(
                f"non-canonical effect interface fields; missing={missing}, extra={extra}"
            )
        return cls(
            operations=tuple(value["operations"]),
            destination_schemes=tuple(value["destination_schemes"]),
        )


@dataclass(frozen=True, slots=True)
class WorldAdapter:
    """Canonical world adapter contract of the frozen interoperability model.

    The contract shape is exactly the frozen WorldAdapter record
    (adapter_id, capability_id, observation_interface, effect_interface,
    fidelity_class). Adapters are canonical contracts and pure
    transformation declarations, never I/O: production and simulation
    adapters implement the same semantic interface and differ only in
    fidelity class.
    """

    adapter_id: str
    capability_id: str
    observation_interface: ObservationInterface
    effect_interface: EffectInterface
    fidelity_class: FidelityClass

    def __post_init__(self) -> None:
        require_adapter_id("adapter.adapter_id", self.adapter_id)
        _require_text("adapter.capability_id", self.capability_id)
        if not isinstance(self.observation_interface, ObservationInterface):
            raise CoreValidationError(
                "adapter.observation_interface must be an ObservationInterface"
            )
        if not isinstance(self.effect_interface, EffectInterface):
            raise CoreValidationError("adapter.effect_interface must be an EffectInterface")
        fidelity = coerce_enum("adapter.fidelity_class", FidelityClass, self.fidelity_class)
        if self.effect_interface.operations and (
            fidelity not in EFFECT_CAPABLE_FIDELITY_CLASSES
        ):
            raise CoreValidationError(
                f"adapter fidelity class {fidelity.value} must not declare effects; "
                "SHADOW, REPLAY and FORECAST adapters are pure observation"
            )
        object.__setattr__(self, "fidelity_class", fidelity)

    def to_dict(self) -> dict[str, Any]:
        return {
            "adapter_id": self.adapter_id,
            "capability_id": self.capability_id,
            "observation_interface": self.observation_interface.to_dict(),
            "effect_interface": self.effect_interface.to_dict(),
            "fidelity_class": self.fidelity_class.value,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "WorldAdapter":
        if not isinstance(value, Mapping):
            raise CoreValidationError("world adapter must be an object")
        if set(value) != _ADAPTER_KEYS:
            missing = sorted(_ADAPTER_KEYS - set(value))
            extra = sorted(set(value) - _ADAPTER_KEYS)
            raise CoreValidationError(
                f"non-canonical world adapter fields; missing={missing}, extra={extra}"
            )
        return cls(
            adapter_id=value["adapter_id"],
            capability_id=value["capability_id"],
            observation_interface=ObservationInterface.from_dict(
                value["observation_interface"]
            ),
            effect_interface=EffectInterface.from_dict(value["effect_interface"]),
            fidelity_class=value["fidelity_class"],
        )

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_json(cls, value: str) -> "WorldAdapter":
        decoded = loads_canonical(value)
        if not isinstance(decoded, dict):
            raise CoreValidationError("world adapter JSON must decode to an object")
        return cls.from_dict(decoded)


@dataclass(frozen=True, slots=True)
class StatusMapEntry:
    """One declared native-to-canonical status mapping."""

    native_code: str
    canonical_status: CanonicalPaymentStatus

    def __post_init__(self) -> None:
        _require_text("status entry.native_code", self.native_code)
        status = coerce_payment_status(self.canonical_status)
        object.__setattr__(self, "canonical_status", status)

    def to_dict(self) -> dict[str, Any]:
        return {
            "native_code": self.native_code,
            "canonical_status": self.canonical_status.value,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "StatusMapEntry":
        if not isinstance(value, Mapping):
            raise CoreValidationError("status map entry must be an object")
        if set(value) != _STATUS_ENTRY_KEYS:
            missing = sorted(_STATUS_ENTRY_KEYS - set(value))
            extra = sorted(set(value) - _STATUS_ENTRY_KEYS)
            raise CoreValidationError(
                f"non-canonical status entry fields; missing={missing}, extra={extra}"
            )
        return cls(
            native_code=value["native_code"],
            canonical_status=value["canonical_status"],
        )


@dataclass(frozen=True, slots=True)
class AdapterStatusMap:
    """The complete declared native status vocabulary of one adapter.

    Adapters map native status into the canonical payment lifecycle
    vocabulary; they never redefine it. The declared mapping must be complete
    over the adapter's native vocabulary: an undeclared native code fails
    closed instead of being silently guessed.
    """

    adapter_id: str
    entries: tuple[StatusMapEntry, ...]

    def __post_init__(self) -> None:
        require_adapter_id("status_map.adapter_id", self.adapter_id)
        if not isinstance(self.entries, tuple):
            raise CoreValidationError("status_map.entries must be a tuple")
        for index, entry in enumerate(self.entries):
            if not isinstance(entry, StatusMapEntry):
                raise CoreValidationError(f"status_map.entries[{index}] must be a StatusMapEntry")
        if not self.entries:
            raise CoreValidationError(
                "status_map must declare at least one native status entry"
            )
        native_codes = [entry.native_code for entry in self.entries]
        if len(native_codes) != len(set(native_codes)):
            raise CoreValidationError(
                "status_map declares duplicate native codes; the native vocabulary "
                "must be unambiguous"
            )

    @classmethod
    def for_adapter(
        cls,
        adapter: WorldAdapter,
        entries: Iterable[StatusMapEntry],
    ) -> "AdapterStatusMap":
        if not isinstance(adapter, WorldAdapter):
            raise CoreValidationError("status map binding requires a WorldAdapter")
        if ObservationOperation.PAYMENT_STATUS not in adapter.observation_interface.operations:
            raise CoreValidationError(
                f"adapter {adapter.adapter_id} does not declare the PAYMENT_STATUS "
                "observation operation required to own a status map"
            )
        return cls(adapter_id=adapter.adapter_id, entries=tuple(entries))

    def map_status(self, native_code: str) -> CanonicalPaymentStatus:
        _require_text("native_code", native_code)
        for entry in self.entries:
            if entry.native_code == native_code:
                return entry.canonical_status
        raise CoreValidationError(
            f"native status {native_code!r} is not declared in the status map of "
            f"adapter {self.adapter_id}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "adapter_id": self.adapter_id,
            "entries": [entry.to_dict() for entry in self.entries],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AdapterStatusMap":
        if not isinstance(value, Mapping):
            raise CoreValidationError("adapter status map must be an object")
        if set(value) != _STATUS_MAP_KEYS:
            missing = sorted(_STATUS_MAP_KEYS - set(value))
            extra = sorted(set(value) - _STATUS_MAP_KEYS)
            raise CoreValidationError(
                f"non-canonical status map fields; missing={missing}, extra={extra}"
            )
        return cls(
            adapter_id=value["adapter_id"],
            entries=tuple(StatusMapEntry.from_dict(item) for item in value["entries"]),
        )

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_json(cls, value: str) -> "AdapterStatusMap":
        decoded = loads_canonical(value)
        if not isinstance(decoded, dict):
            raise CoreValidationError("status map JSON must decode to an object")
        return cls.from_dict(decoded)


@dataclass(frozen=True, slots=True)
class DomesticInstruction:
    """Rail-shaped projection of a canonical payment message for one adapter.

    The instruction is the pure output of translating a canonical message
    through a world adapter contract; it is data, never an I/O request.
    """

    adapter_id: str
    message_id: str
    end_to_end_id: str
    currency: str
    amount_value: int
    amount_scale: int
    destination_scheme: str
    destination_value: str
    destination_jurisdiction: str | None
    endpoint_id: str

    def __post_init__(self) -> None:
        require_adapter_id("instruction.adapter_id", self.adapter_id)
        _require_text("instruction.message_id", self.message_id)
        _require_text("instruction.end_to_end_id", self.end_to_end_id)
        _require_text("instruction.currency", self.currency)
        if (
            not isinstance(self.amount_value, int)
            or isinstance(self.amount_value, bool)
            or self.amount_value < 0
        ):
            raise CoreValidationError(
                f"instruction.amount_value must be a non-negative integer, "
                f"got {self.amount_value!r}"
            )
        if (
            not isinstance(self.amount_scale, int)
            or isinstance(self.amount_scale, bool)
            or not 0 <= self.amount_scale <= _MAX_SCALE
        ):
            raise CoreValidationError(
                f"instruction.amount_scale must be an integer between 0 and "
                f"{_MAX_SCALE}, got {self.amount_scale!r}"
            )
        _require_text("instruction.destination_scheme", self.destination_scheme)
        _require_text("instruction.destination_value", self.destination_value)
        if self.destination_jurisdiction is not None:
            _require_text(
                "instruction.destination_jurisdiction", self.destination_jurisdiction
            )
            if not _JURISDICTION.fullmatch(self.destination_jurisdiction):
                raise CoreValidationError(
                    f"instruction.destination_jurisdiction must be an ISO 3166-1 "
                    f"alpha-2 code, got {self.destination_jurisdiction!r}"
                )
        _require_text("instruction.endpoint_id", self.endpoint_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "adapter_id": self.adapter_id,
            "message_id": self.message_id,
            "end_to_end_id": self.end_to_end_id,
            "currency": self.currency,
            "amount_value": self.amount_value,
            "amount_scale": self.amount_scale,
            "destination_scheme": self.destination_scheme,
            "destination_value": self.destination_value,
            "destination_jurisdiction": self.destination_jurisdiction,
            "endpoint_id": self.endpoint_id,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "DomesticInstruction":
        if not isinstance(value, Mapping):
            raise CoreValidationError("domestic instruction must be an object")
        if set(value) != _DOMESTIC_KEYS:
            missing = sorted(_DOMESTIC_KEYS - set(value))
            extra = sorted(set(value) - _DOMESTIC_KEYS)
            raise CoreValidationError(
                f"non-canonical domestic instruction fields; missing={missing}, extra={extra}"
            )
        return cls(
            adapter_id=value["adapter_id"],
            message_id=value["message_id"],
            end_to_end_id=value["end_to_end_id"],
            currency=value["currency"],
            amount_value=value["amount_value"],
            amount_scale=value["amount_scale"],
            destination_scheme=value["destination_scheme"],
            destination_value=value["destination_value"],
            destination_jurisdiction=value["destination_jurisdiction"],
            endpoint_id=value["endpoint_id"],
        )

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_json(cls, value: str) -> "DomesticInstruction":
        decoded = loads_canonical(value)
        if not isinstance(decoded, dict):
            raise CoreValidationError("domestic instruction JSON must decode to an object")
        return cls.from_dict(decoded)


def translate_to_domestic(
    message: CanonicalPaymentMessage,
    adapter: WorldAdapter,
) -> DomesticInstruction:
    """Project a canonical payment message into one adapter's domestic shape.

    Pure transformation: the adapter must declare the SUBMIT_PAYMENT effect
    operation and support the message's destination identifier scheme; both
    mismatches fail closed.
    """
    if not isinstance(message, CanonicalPaymentMessage):
        raise CoreValidationError("translation requires a CanonicalPaymentMessage")
    if not isinstance(adapter, WorldAdapter):
        raise CoreValidationError("translation requires a WorldAdapter")
    if EffectOperation.SUBMIT_PAYMENT not in adapter.effect_interface.operations:
        raise CoreValidationError(
            f"adapter {adapter.adapter_id} does not declare the SUBMIT_PAYMENT "
            "effect operation required for payment translation"
        )
    destination_scheme = message.destination.identifier.scheme
    if destination_scheme not in adapter.effect_interface.destination_schemes:
        raise CoreValidationError(
            f"adapter {adapter.adapter_id} does not support destination scheme "
            f"{destination_scheme.value} required by message {message.object_id}"
        )
    identifier = message.destination.identifier
    return DomesticInstruction(
        adapter_id=adapter.adapter_id,
        message_id=message.object_id,
        end_to_end_id=message.end_to_end_id,
        currency=message.instructed_amount.currency,
        amount_value=message.instructed_amount.value,
        amount_scale=message.instructed_amount.scale,
        destination_scheme=identifier.scheme.value,
        destination_value=identifier.value,
        destination_jurisdiction=identifier.jurisdiction,
        endpoint_id=message.destination.endpoint_id,
    )


def apply_status_observation(
    message: CanonicalPaymentMessage,
    status_map: AdapterStatusMap,
    native_code: str,
    *,
    provenance: Any,
) -> CanonicalPaymentMessage:
    """Fold one native status observation into the canonical message.

    The native code is mapped through the adapter's declared status map
    (failing closed on undeclared codes) and recorded as the next immutable
    version of the message. A mapping to UNKNOWN lands the message in the
    explicit ambiguous branch, which callers must reconcile before any retry.
    """
    from src.core import Provenance

    if not isinstance(message, CanonicalPaymentMessage):
        raise CoreValidationError("status observation requires a CanonicalPaymentMessage")
    if not isinstance(status_map, AdapterStatusMap):
        raise CoreValidationError("status observation requires an AdapterStatusMap")
    if not isinstance(provenance, Provenance):
        raise CoreValidationError("status observation requires a Provenance record")
    mapped_status = status_map.map_status(native_code)
    return message.with_status(mapped_status, provenance=provenance)


__all__ = [
    "AdapterStatusMap",
    "DomesticInstruction",
    "EFFECT_CAPABLE_FIDELITY_CLASSES",
    "EffectInterface",
    "EffectOperation",
    "FidelityClass",
    "ObservationInterface",
    "ObservationOperation",
    "StatusMapEntry",
    "WorldAdapter",
    "apply_status_observation",
    "translate_to_domestic",
]
