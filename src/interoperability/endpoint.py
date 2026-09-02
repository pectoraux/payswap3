from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Iterable, Mapping

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_json, loads_canonical

from .identifiers import EndpointIdentifier
from .records import (
    ADAPTER_ID_PREFIX,
    DOMAIN_PROTOCOL_VERSION,
    DOMAIN_SCHEMA_VERSION,
    OBJECT_TYPE_ENDPOINT,
    OBJECT_TYPE_ENDPOINT_RESOLUTION,
    RESOLUTION_STATE,
    _require_positive,
    _require_text,
    coerce_enum,
    decode_record,
    payload_binding_hash,
    require_adapter_id,
    require_identifier_tuple,
    require_object_identity,
    require_payload_keys,
    validate_timestamp,
    verify_payload_binding,
)

# Endpoint lifecycle states for the Register/Update/Suspend/Reactivate/Remove
# command family of the frozen command-event model; only ACTIVE endpoints are
# resolvable, and CLOSED is terminal.
class EndpointState(StrEnum):
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    CLOSED = "CLOSED"


class ResolutionMethod(StrEnum):
    CANONICAL = "CANONICAL"
    ADAPTER_ASSISTED = "ADAPTER_ASSISTED"


_ENDPOINT_PAYLOAD_KEYS = frozenset({"identifiers"})
_RESOLUTION_PAYLOAD_KEYS = frozenset(
    {
        "requested_identifier",
        "destination",
        "resolved_at",
        "resolution_method",
        "adapter_id",
    }
)
_DESTINATION_KEYS = frozenset(
    {"resolution_id", "endpoint_id", "endpoint_version", "identifier"}
)
_TRANSLATION_KEYS = frozenset({"source", "target"})
_DIRECTORY_KEYS = frozenset({"adapter_id", "translations"})


@dataclass(frozen=True, slots=True)
class Destination:
    """The resolved destination a canonical payment message addresses.

    Destination is a derived value object carried by the durable
    EndpointResolution record; it always cites the exact endpoint version it
    was resolved from.
    """

    resolution_id: str
    endpoint_id: str
    endpoint_version: int
    identifier: EndpointIdentifier

    def __post_init__(self) -> None:
        _require_text("destination.resolution_id", self.resolution_id)
        _require_text("destination.endpoint_id", self.endpoint_id)
        _require_positive("destination.endpoint_version", self.endpoint_version)
        if not isinstance(self.identifier, EndpointIdentifier):
            raise CoreValidationError("destination.identifier must be an EndpointIdentifier")

    def to_dict(self) -> dict[str, Any]:
        return {
            "resolution_id": self.resolution_id,
            "endpoint_id": self.endpoint_id,
            "endpoint_version": self.endpoint_version,
            "identifier": self.identifier.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Destination":
        if not isinstance(value, Mapping):
            raise CoreValidationError("destination must be an object")
        if set(value) != _DESTINATION_KEYS:
            missing = sorted(_DESTINATION_KEYS - set(value))
            extra = sorted(set(value) - _DESTINATION_KEYS)
            raise CoreValidationError(
                f"non-canonical destination fields; missing={missing}, extra={extra}"
            )
        return cls(
            resolution_id=value["resolution_id"],
            endpoint_id=value["endpoint_id"],
            endpoint_version=value["endpoint_version"],
            identifier=EndpointIdentifier.from_dict(value["identifier"]),
        )


@dataclass(frozen=True, slots=True)
class IdentifierTranslation:
    """A domestic identifier translation declared by a directory adapter."""

    source: EndpointIdentifier
    target: EndpointIdentifier

    def __post_init__(self) -> None:
        if not isinstance(self.source, EndpointIdentifier):
            raise CoreValidationError("translation.source must be an EndpointIdentifier")
        if not isinstance(self.target, EndpointIdentifier):
            raise CoreValidationError("translation.target must be an EndpointIdentifier")
        if self.source.identity_key() == self.target.identity_key():
            raise CoreValidationError(
                "identifier translation must change the identifier identity"
            )

    def to_dict(self) -> dict[str, Any]:
        return {"source": self.source.to_dict(), "target": self.target.to_dict()}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "IdentifierTranslation":
        if not isinstance(value, Mapping):
            raise CoreValidationError("identifier translation must be an object")
        if set(value) != _TRANSLATION_KEYS:
            missing = sorted(_TRANSLATION_KEYS - set(value))
            extra = sorted(set(value) - _TRANSLATION_KEYS)
            raise CoreValidationError(
                f"non-canonical translation fields; missing={missing}, extra={extra}"
            )
        return cls(
            source=EndpointIdentifier.from_dict(value["source"]),
            target=EndpointIdentifier.from_dict(value["target"]),
        )


@dataclass(frozen=True, slots=True)
class EndpointDirectory:
    """Pure domestic-adapter translation table for endpoint resolution.

    The directory is a canonical contract, never an I/O boundary: it declares
    how domestic-shaped identifiers translate into canonical identifiers for
    the resolution engine. A directory must be bound to a world adapter whose
    observation interface declares RESOLVE_ENDPOINT.
    """

    adapter_id: str
    translations: tuple[IdentifierTranslation, ...]

    def __post_init__(self) -> None:
        require_adapter_id("directory.adapter_id", self.adapter_id)
        if not isinstance(self.translations, tuple):
            raise CoreValidationError("directory.translations must be a tuple")
        if not self.translations:
            raise CoreValidationError("directory.translations must declare at least one translation")
        sources = [translation.source.identity_key() for translation in self.translations]
        if len(sources) != len(set(sources)):
            raise CoreValidationError(
                "directory declares duplicate source identifiers; sources must be unambiguous"
            )

    @classmethod
    def for_adapter(
        cls,
        adapter: Any,
        translations: Iterable[IdentifierTranslation],
    ) -> "EndpointDirectory":
        from .adapter import ObservationOperation, WorldAdapter

        if not isinstance(adapter, WorldAdapter):
            raise CoreValidationError("directory binding requires a WorldAdapter")
        if ObservationOperation.RESOLVE_ENDPOINT not in adapter.observation_interface.operations:
            raise CoreValidationError(
                f"adapter {adapter.adapter_id} does not declare the RESOLVE_ENDPOINT "
                "observation operation required to own an endpoint directory"
            )
        return cls(adapter_id=adapter.adapter_id, translations=tuple(translations))

    def to_dict(self) -> dict[str, Any]:
        return {
            "adapter_id": self.adapter_id,
            "translations": [translation.to_dict() for translation in self.translations],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EndpointDirectory":
        if not isinstance(value, Mapping):
            raise CoreValidationError("endpoint directory must be an object")
        if set(value) != _DIRECTORY_KEYS:
            missing = sorted(_DIRECTORY_KEYS - set(value))
            extra = sorted(set(value) - _DIRECTORY_KEYS)
            raise CoreValidationError(
                f"non-canonical directory fields; missing={missing}, extra={extra}"
            )
        return cls(
            adapter_id=value["adapter_id"],
            translations=tuple(
                IdentifierTranslation.from_dict(item) for item in value["translations"]
            ),
        )


@dataclass(frozen=True, slots=True)
class Endpoint:
    """A registered payment destination addressable by jurisdictional identifiers.

    Endpoint is a sealed envelope record in the internal (non-registry)
    interoperability object identity space. Registering, updating,
    suspending, reactivating and closing produce new immutable versions; a
    closed endpoint is terminal.
    """

    envelope: Any
    identifiers: tuple[EndpointIdentifier, ...]
    payload_hash: str

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def object_version(self) -> int:
        return self.envelope.object_version

    @property
    def state(self) -> EndpointState:
        return coerce_enum("endpoint.state", EndpointState, self.envelope.state)  # type: ignore[return-value]

    def payload_dict(self) -> dict[str, Any]:
        return {"identifiers": [identifier.to_dict() for identifier in self.identifiers]}

    def __post_init__(self) -> None:
        require_object_identity(self.envelope, OBJECT_TYPE_ENDPOINT)
        coerce_enum("endpoint.state", EndpointState, self.envelope.state)
        identifiers = require_identifier_tuple("endpoint.identifiers", self.identifiers)
        if not identifiers:
            raise CoreValidationError("endpoint.identifiers must declare at least one identifier")
        identity_keys = [identifier.identity_key() for identifier in identifiers]
        if len(identity_keys) != len(set(identity_keys)):
            raise CoreValidationError("endpoint declares duplicate identifiers")
        verify_payload_binding(self.envelope, self.payload_dict(), self.payload_hash)

    @classmethod
    def create(
        cls,
        *,
        endpoint_id: str,
        identifiers: Iterable[EndpointIdentifier],
        environment_id: str,
        domain_id: str,
        provenance: Any,
        causation_id: str | None = None,
        correlation_id: str | None = None,
        state: str = "ACTIVE",
    ) -> "Endpoint":
        from src.core import ObjectEnvelope

        endpoint_state = coerce_enum("endpoint.state", EndpointState, state)
        identifier_tuple = tuple(identifiers)
        envelope = ObjectEnvelope(
            object_id=endpoint_id,
            object_type=OBJECT_TYPE_ENDPOINT,
            object_version=1,
            environment_id=environment_id,
            domain_id=domain_id,
            schema_version=DOMAIN_SCHEMA_VERSION,
            protocol_version=DOMAIN_PROTOCOL_VERSION,
            state=endpoint_state.value,
            provenance=provenance,
            causation_id=causation_id,
            correlation_id=correlation_id,
        ).with_integrity_hash()
        return cls(
            envelope=envelope,
            identifiers=identifier_tuple,
            payload_hash=payload_binding_hash(
                envelope,
                {"identifiers": [identifier.to_dict() for identifier in identifier_tuple]},
            ),
        )

    def evolve(
        self,
        *,
        identifiers: Iterable[EndpointIdentifier] | None = None,
        state: Any = None,
        provenance: Any = None,
        causation_id: str | None = None,
        correlation_id: str | None = None,
        **unknown: Any,
    ) -> "Endpoint":
        """Apply an update/suspend/reactivate/close change as a new version."""
        if unknown:
            raise CoreValidationError(
                f"endpoint evolve does not accept fields {sorted(unknown)}; "
                "identity fields cannot change across object versions"
            )
        current = self.state
        if current is EndpointState.CLOSED:
            raise CoreValidationError(
                f"endpoint {self.object_id} is CLOSED; closed endpoints are terminal"
            )
        new_state = current if state is None else coerce_enum("endpoint.state", EndpointState, state)
        changes: dict[str, Any] = {"state": new_state.value}
        if provenance is not None:
            changes["provenance"] = provenance
        if causation_id is not None:
            changes["causation_id"] = causation_id
        if correlation_id is not None:
            changes["correlation_id"] = correlation_id
        envelope = self.envelope.next_version(**changes).with_integrity_hash()
        new_identifiers = self.identifiers if identifiers is None else tuple(identifiers)
        return Endpoint(
            envelope=envelope,
            identifiers=new_identifiers,
            payload_hash=payload_binding_hash(
                envelope,
                {"identifiers": [identifier.to_dict() for identifier in new_identifiers]},
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "payload": self.payload_dict(),
            "payload_hash": self.payload_hash,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Endpoint":
        envelope, payload, payload_hash = decode_record(value)
        require_payload_keys(payload, _ENDPOINT_PAYLOAD_KEYS)
        return cls(
            envelope=envelope,
            identifiers=tuple(
                EndpointIdentifier.from_dict(item) for item in payload["identifiers"]
            ),
            payload_hash=payload_hash,
        )

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_json(cls, value: str) -> "Endpoint":
        decoded = loads_canonical(value)
        if not isinstance(decoded, dict):
            raise CoreValidationError("endpoint JSON must decode to an object")
        return cls.from_dict(decoded)


@dataclass(frozen=True, slots=True)
class EndpointResolution:
    """Durable record of one endpoint resolution and its destination.

    Resolution records are immutable facts: re-resolution produces a new
    resolution object, never a mutation. The payload binding ties the
    requested identifier, destination, method and adapter provenance to one
    exact sealed envelope version.
    """

    envelope: Any
    requested_identifier: EndpointIdentifier
    destination: Destination
    resolved_at: str
    resolution_method: ResolutionMethod
    adapter_id: str | None
    payload_hash: str

    @property
    def object_id(self) -> str:
        return self.envelope.object_id

    @property
    def object_version(self) -> int:
        return self.envelope.object_version

    def payload_dict(self) -> dict[str, Any]:
        return {
            "requested_identifier": self.requested_identifier.to_dict(),
            "destination": self.destination.to_dict(),
            "resolved_at": self.resolved_at,
            "resolution_method": self.resolution_method.value,
            "adapter_id": self.adapter_id,
        }

    def __post_init__(self) -> None:
        require_object_identity(self.envelope, OBJECT_TYPE_ENDPOINT_RESOLUTION)
        if self.envelope.state != RESOLUTION_STATE:
            raise CoreValidationError(
                f"endpoint resolution state must be {RESOLUTION_STATE!r}, "
                f"got {self.envelope.state!r}"
            )
        if not isinstance(self.requested_identifier, EndpointIdentifier):
            raise CoreValidationError(
                "resolution.requested_identifier must be an EndpointIdentifier"
            )
        if not isinstance(self.destination, Destination):
            raise CoreValidationError("resolution.destination must be a Destination")
        if self.destination.resolution_id != self.envelope.object_id:
            raise CoreValidationError(
                "resolution.destination must be bound to this resolution record"
            )
        validate_timestamp("resolution.resolved_at", self.resolved_at)
        method = coerce_enum(
            "resolution.resolution_method", ResolutionMethod, self.resolution_method
        )
        object.__setattr__(self, "resolution_method", method)
        if method is ResolutionMethod.CANONICAL:
            if self.adapter_id is not None:
                raise CoreValidationError(
                    "canonical resolution must not cite an adapter"
                )
        else:
            require_adapter_id("resolution.adapter_id", self.adapter_id or "")
        verify_payload_binding(self.envelope, self.payload_dict(), self.payload_hash)

    @classmethod
    def create(
        cls,
        *,
        resolution_id: str,
        environment_id: str,
        domain_id: str,
        provenance: Any,
        requested_identifier: EndpointIdentifier,
        destination: Destination,
        resolved_at: str,
        resolution_method: Any,
        adapter_id: str | None,
        causation_id: str | None = None,
        correlation_id: str | None = None,
    ) -> "EndpointResolution":
        from src.core import ObjectEnvelope

        method = coerce_enum(
            "resolution.resolution_method", ResolutionMethod, resolution_method
        )
        envelope = ObjectEnvelope(
            object_id=resolution_id,
            object_type=OBJECT_TYPE_ENDPOINT_RESOLUTION,
            object_version=1,
            environment_id=environment_id,
            domain_id=domain_id,
            schema_version=DOMAIN_SCHEMA_VERSION,
            protocol_version=DOMAIN_PROTOCOL_VERSION,
            state=RESOLUTION_STATE,
            provenance=provenance,
            causation_id=causation_id,
            correlation_id=correlation_id,
        ).with_integrity_hash()
        return cls(
            envelope=envelope,
            requested_identifier=requested_identifier,
            destination=destination,
            resolved_at=resolved_at,
            resolution_method=method,
            adapter_id=adapter_id,
            payload_hash=payload_binding_hash(
                envelope,
                {
                    "requested_identifier": requested_identifier.to_dict(),
                    "destination": destination.to_dict(),
                    "resolved_at": resolved_at,
                    "resolution_method": method.value,
                    "adapter_id": adapter_id,
                },
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "payload": self.payload_dict(),
            "payload_hash": self.payload_hash,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EndpointResolution":
        envelope, payload, payload_hash = decode_record(value)
        require_payload_keys(payload, _RESOLUTION_PAYLOAD_KEYS)
        return cls(
            envelope=envelope,
            requested_identifier=EndpointIdentifier.from_dict(
                payload["requested_identifier"]
            ),
            destination=Destination.from_dict(payload["destination"]),
            resolved_at=payload["resolved_at"],
            resolution_method=payload["resolution_method"],
            adapter_id=payload["adapter_id"],
            payload_hash=payload_hash,
        )

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_json(cls, value: str) -> "EndpointResolution":
        decoded = loads_canonical(value)
        if not isinstance(decoded, dict):
            raise CoreValidationError("endpoint resolution JSON must decode to an object")
        return cls.from_dict(decoded)


def _matching_identifier(
    endpoint_record: Endpoint, identifier: EndpointIdentifier
) -> EndpointIdentifier | None:
    for candidate in endpoint_record.identifiers:
        if candidate.identity_key() == identifier.identity_key():
            return candidate
    return None


def resolve_endpoint(
    requested: EndpointIdentifier,
    endpoints: Iterable[Endpoint],
    *,
    resolution_id: str,
    environment_id: str,
    domain_id: str,
    provenance: Any,
    resolved_at: str,
    directories: Iterable[EndpointDirectory] = (),
    correlation_id: str | None = None,
) -> EndpointResolution:
    """Resolve an identifier to a destination through canonical and adapter paths.

    The engine is a pure function over the supplied endpoint registry and
    domestic directories; it performs no I/O and mutates nothing. Direct
    canonical matches take precedence; otherwise directories may translate a
    domestic-shaped identifier into a canonical one. Ambiguity, conflicting
    translations, suspended/closed endpoints and unresolved identifiers all
    fail closed with descriptive errors.
    """
    if not isinstance(requested, EndpointIdentifier):
        raise CoreValidationError("requested must be an EndpointIdentifier")
    endpoint_tuple = tuple(endpoints)
    for index, candidate in enumerate(endpoint_tuple):
        if not isinstance(candidate, Endpoint):
            raise CoreValidationError(f"endpoints[{index}] must be an Endpoint")
    directory_tuple = tuple(directories)
    for index, directory in enumerate(directory_tuple):
        if not isinstance(directory, EndpointDirectory):
            raise CoreValidationError(f"directories[{index}] must be an EndpointDirectory")

    active = [
        candidate
        for candidate in endpoint_tuple
        if candidate.state is EndpointState.ACTIVE
    ]

    direct_matches = [
        candidate
        for candidate in active
        if _matching_identifier(candidate, requested) is not None
    ]
    if len(direct_matches) > 1:
        ids = sorted(candidate.object_id for candidate in direct_matches)
        raise CoreValidationError(
            f"endpoint resolution is ambiguous: {len(direct_matches)} active endpoints "
            f"match identifier {requested.scheme.value} {requested.value!r}: {ids}"
        )
    if direct_matches:
        matched = direct_matches[0]
        identifier = _matching_identifier(matched, requested)
        destination = Destination(
            resolution_id=resolution_id,
            endpoint_id=matched.object_id,
            endpoint_version=matched.object_version,
            identifier=identifier if identifier is not None else requested,
        )
        return EndpointResolution.create(
            resolution_id=resolution_id,
            environment_id=environment_id,
            domain_id=domain_id,
            provenance=provenance,
            requested_identifier=requested,
            destination=destination,
            resolved_at=resolved_at,
            resolution_method=ResolutionMethod.CANONICAL,
            adapter_id=None,
            correlation_id=correlation_id,
        )

    directory_matches: list[tuple[EndpointDirectory, EndpointIdentifier]] = []
    for directory in directory_tuple:
        for translation in directory.translations:
            if translation.source.identity_key() == requested.identity_key():
                directory_matches.append((directory, translation.target))
    distinct_targets = {
        target.identity_key() for _, target in directory_matches
    }
    if len(distinct_targets) > 1:
        targets = sorted(
            f"{target.scheme.value} {target.value!r}" for _, target in directory_matches
        )
        raise CoreValidationError(
            f"conflicting directory translations for identifier "
            f"{requested.scheme.value} {requested.value!r}: {targets}"
        )
    if directory_matches:
        directory, target = directory_matches[0]
        translated_matches = [
            candidate for candidate in active if _matching_identifier(candidate, target)
        ]
        if len(translated_matches) > 1:
            ids = sorted(candidate.object_id for candidate in translated_matches)
            raise CoreValidationError(
                f"endpoint resolution is ambiguous: {len(translated_matches)} active "
                f"endpoints match translated identifier {target.scheme.value} "
                f"{target.value!r}: {ids}"
            )
        if translated_matches:
            matched = translated_matches[0]
            identifier = _matching_identifier(matched, target)
            destination = Destination(
                resolution_id=resolution_id,
                endpoint_id=matched.object_id,
                endpoint_version=matched.object_version,
                identifier=identifier if identifier is not None else target,
            )
            return EndpointResolution.create(
                resolution_id=resolution_id,
                environment_id=environment_id,
                domain_id=domain_id,
                provenance=provenance,
                requested_identifier=requested,
                destination=destination,
                resolved_at=resolved_at,
                resolution_method=ResolutionMethod.ADAPTER_ASSISTED,
                adapter_id=directory.adapter_id,
                correlation_id=correlation_id,
            )
        raise CoreValidationError(
            f"endpoint resolution failed: no active endpoint matches the directory "
            f"translation {target.scheme.value} {target.value!r} of identifier "
            f"{requested.scheme.value} {requested.value!r}"
        )

    raise CoreValidationError(
        f"endpoint resolution failed: no active endpoint matches identifier "
        f"{requested.scheme.value} {requested.value!r}"
    )


__all__ = [
    "ADAPTER_ID_PREFIX",
    "Destination",
    "Endpoint",
    "EndpointDirectory",
    "EndpointResolution",
    "EndpointState",
    "IdentifierTranslation",
    "ResolutionMethod",
    "resolve_endpoint",
]
