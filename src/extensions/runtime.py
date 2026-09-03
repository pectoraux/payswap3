"""The sandboxed invocation runtime core (extensions.md "Security").

Extensions are bounded capability providers. An invocation is a pure,
deterministic function evaluation inside a closed sandbox:

* the sandbox context (:class:`SandboxContext`) exposes EXACTLY the frozen
  declared-data fields — the invocation identity, the extension identity,
  the requested capability, the declared typed input artifacts, the
  declared resource views, the declared ``as_of`` instant, the environment
  mode and the invocation effect mode. There is no store, engine, view,
  ledger or kernel handle: extensions receive no ambient authority
  (constitution §5).
* every requested capability, input artifact kind and resource view must
  be declared by the manifest; anything undeclared fails closed;
* handler outputs must be typed artifacts of declared output kinds, with
  the producer bound to the invoked extension, schema versions declared
  by the manifest, artifact ids that never collide with input ids, and
  total artifact bytes bounded by the manifest's resource requirements;
* handler exceptions fail closed without partial state;
* this domain never produces production effects: invocations either
  produce candidate typed artifacts for the protocol to consume through
  its own authoritative paths (``RECORDED``) or are recorded as pure
  observation (``SHADOWED`` — live observation, non-production effects).

The code a manifest may execute is resolved from a
:class:`CodeRepository` by the declared ``code_hash`` — the runtime never
loads undeclared code.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Callable, Mapping

from src.core.envelope import ObjectEnvelope
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_json
from src.simulation import EnvironmentMode

from ._validation import (
    compare_timestamps,
    require_bool,
    require_int,
    require_internal_id,
    require_text,
    unique_entries,
    validate_timestamp,
)
from .contracts import (
    CREDIT_PER_BYTE,
    EXTENSION_INVOCATION_OBJECT_TYPE,
    EXTENSIONS_PROTOCOL_VERSION,
    EXTENSIONS_SCHEMA_VERSION,
    INVOCATION_BASE_CREDIT,
    ExtensionArtifactKind,
    ExtensionCapability,
    InvocationEffectMode,
    ResourceCredits,
)
from .artifacts import ExtensionArtifact
from .manifest import ExtensionManifest

#: The closed set of sandbox-context fields (frozen; no ambient authority).
SANDBOX_CONTEXT_FIELDS = (
    "invocation_id",
    "extension_id",
    "capability",
    "inputs",
    "resources",
    "as_of",
    "environment_mode",
    "effect_mode",
)

#: Handler signature: one pure function of the declared sandbox context.
SandboxHandler = Callable[["SandboxContext"], tuple[ExtensionArtifact, ...]]


@dataclass(frozen=True, slots=True)
class SandboxContext:
    """The closed world one invocation sees.

    Exactly the frozen declared-data fields; constructing it with any
    ambient-authority argument (store, engine, view, ledger, kernel)
    fails immediately because the frozen field set admits no such
    parameter.
    """

    invocation_id: str
    extension_id: str
    capability: ExtensionCapability
    inputs: tuple[ExtensionArtifact, ...]
    resources: tuple[tuple[str, tuple[tuple[str, Any], ...]], ...]
    as_of: str
    environment_mode: EnvironmentMode
    effect_mode: InvocationEffectMode

    def resource_value(self, name: str) -> dict[str, Any]:
        """Read-only view of one declared resource's payload pairs."""
        for resource_name, pairs in self.resources:
            if resource_name == name:
                return dict(pairs)
        raise CoreValidationError(
            f"sandbox context does not carry the declared resource {name!r}"
        )


@dataclass(frozen=True, slots=True)
class InvocationRequest:
    """One sandboxed invocation request as declared data (fail closed).

    ``resources`` is a tuple of ``(permission_name, payload_pairs)``
    entries; each entry requests one declared permission's read view.
    """

    invocation_id: str
    capability: ExtensionCapability
    inputs: tuple[ExtensionArtifact, ...]
    resources: tuple[tuple[str, tuple[tuple[str, Any], ...]], ...]
    as_of: str

    def __post_init__(self) -> None:
        require_internal_id("request.invocation_id", self.invocation_id)
        if not isinstance(self.capability, ExtensionCapability):
            object.__setattr__(
                self, "capability", ExtensionCapability.parse(self.capability)
            )
        if not isinstance(self.inputs, tuple) or not self.inputs:
            raise CoreValidationError(
                "request.inputs must be a non-empty tuple of artifacts"
            )
        for artifact in self.inputs:
            if not isinstance(artifact, ExtensionArtifact):
                raise CoreValidationError(
                    "request.inputs entries must be ExtensionArtifact values"
                )
        unique_entries(
            "request.inputs",
            tuple(artifact.artifact_id for artifact in self.inputs),
        )
        if not isinstance(self.resources, tuple):
            raise CoreValidationError("request.resources must be a tuple")
        names: list[str] = []
        for entry in self.resources:
            if not isinstance(entry, tuple) or len(entry) != 2:
                raise CoreValidationError(
                    "request.resources entries must be (name, pairs) tuples"
                )
            name, pairs = entry
            require_text("request.resources name", name)
            if not isinstance(pairs, tuple):
                raise CoreValidationError(
                    "request.resources payloads must be canonical pair tuples"
                )
            for pair in pairs:
                if not isinstance(pair, tuple) or len(pair) != 2:
                    raise CoreValidationError(
                        "request.resources payload entries must be (key, value) pairs"
                    )
                if not isinstance(pair[0], str):
                    raise CoreValidationError(
                        "request.resources payload keys must be strings"
                    )
            names.append(name)
        if len(set(names)) != len(names):
            raise CoreValidationError("request.resources contains duplicate names")
        validate_timestamp("request.as_of", self.as_of)


class CodeRepository:
    """Deterministic code registry: ``code_hash`` -> handler function.

    The marketplace publishes extension code by content digest; the
    runtime resolves the declared digest and fails closed on unknown
    code. Handlers are ordinary deterministic callables supplied by the
    deployment (in-repo test extensions, vetted packages) — the manifest
    binds the identity of the code, the repository binds the code itself.
    """

    __slots__ = ("_handlers",)

    def __init__(self) -> None:
        self._handlers: dict[str, SandboxHandler] = {}

    def register(self, code_hash: str, handler: SandboxHandler) -> None:
        from ._validation import require_digest

        require_digest("code repository code_hash", code_hash)
        if not callable(handler):
            raise CoreValidationError("code repository handler must be callable")
        if code_hash in self._handlers:
            raise CoreValidationError(
                f"code {code_hash} is already registered in the code repository"
            )
        self._handlers[code_hash] = handler

    def resolve(self, code_hash: str) -> SandboxHandler:
        from ._validation import require_digest

        require_digest("code repository code_hash", code_hash)
        handler = self._handlers.get(code_hash)
        if handler is None:
            raise CoreValidationError(
                f"extension code {code_hash} is not registered in the code repository; "
                "the runtime never executes undeclared code"
            )
        return handler

    def known_hashes(self) -> tuple[str, ...]:
        return tuple(sorted(self._handlers))


@dataclass(frozen=True, slots=True)
class ExtensionInvocation:
    """One completed sandboxed invocation record (immutable, kernel-bound).

    The record is the protocol-visible evidence of one bounded capability
    evaluation: typed outputs, metered resource credits, the effect mode
    (recorded candidate artifacts vs. pure shadow observation) and the
    covering grant that authorized it. Invocation records never reference
    stores, engines, views, ledgers or kernels.
    """

    invocation_id: str
    target_id: str
    extension_id: str
    capability: ExtensionCapability
    input_artifact_ids: tuple[str, ...]
    output_artifacts: tuple[ExtensionArtifact, ...]
    status: str
    effect_mode: InvocationEffectMode
    environment_mode: EnvironmentMode
    shadowed: bool
    covering_grant_id: str | None
    resource_credits: ResourceCredits
    artifact_bytes: int
    as_of: str
    envelope: ObjectEnvelope | None = None

    def __post_init__(self) -> None:
        require_internal_id("invocation.invocation_id", self.invocation_id)
        require_internal_id("invocation.target_id", self.target_id)
        require_internal_id("invocation.extension_id", self.extension_id)
        if not isinstance(self.capability, ExtensionCapability):
            object.__setattr__(
                self, "capability", ExtensionCapability.parse(self.capability)
            )
        if not isinstance(self.input_artifact_ids, tuple):
            raise CoreValidationError("invocation.input_artifact_ids must be a tuple")
        for ref in self.input_artifact_ids:
            require_text("invocation.input_artifact_id", ref)
        if not isinstance(self.output_artifacts, tuple) or not self.output_artifacts:
            raise CoreValidationError(
                "invocation.output_artifacts must be a non-empty tuple"
            )
        for artifact in self.output_artifacts:
            if not isinstance(artifact, ExtensionArtifact):
                raise CoreValidationError(
                    "invocation.output_artifacts entries must be ExtensionArtifact values"
                )
        if not isinstance(self.status, str) or not self.status.strip():
            raise CoreValidationError("invocation.status must be a non-empty string")
        if not isinstance(self.effect_mode, InvocationEffectMode):
            object.__setattr__(
                self, "effect_mode", InvocationEffectMode.parse(self.effect_mode)
            )
        if not isinstance(self.environment_mode, EnvironmentMode):
            object.__setattr__(
                self, "environment_mode", EnvironmentMode.parse(self.environment_mode)
            )
        require_bool("invocation.shadowed", self.shadowed)
        if self.covering_grant_id is not None:
            require_internal_id("invocation.covering_grant_id", self.covering_grant_id)
        if not isinstance(self.resource_credits, ResourceCredits):
            if isinstance(self.resource_credits, int):
                object.__setattr__(
                    self, "resource_credits", ResourceCredits(credits=self.resource_credits)
                )
            else:
                raise CoreValidationError(
                    "invocation.resource_credits must be ResourceCredits"
                )
        require_int("invocation.artifact_bytes", self.artifact_bytes, minimum=0)
        validate_timestamp("invocation.as_of", self.as_of)
        if self.envelope is not None and not isinstance(self.envelope, ObjectEnvelope):
            raise CoreValidationError("invocation envelope must be an ObjectEnvelope")

    # -- envelope binding ---------------------------------------------------

    @property
    def state(self) -> str:
        if self.envelope is None:
            raise CoreValidationError(
                "invocation state requires the bound kernel envelope"
            )
        return self.envelope.state

    def bind_envelope(self, envelope: ObjectEnvelope) -> "ExtensionInvocation":
        if not isinstance(envelope, ObjectEnvelope):
            raise CoreValidationError("invocation envelope must be an ObjectEnvelope")
        if envelope.integrity_hash is None:
            raise CoreValidationError(
                "invocation envelope must be sealed with with_integrity_hash()"
            )
        if envelope.object_id != self.invocation_id:
            raise CoreValidationError(
                "invocation envelope object_id must equal invocation_id"
            )
        if envelope.object_type != EXTENSION_INVOCATION_OBJECT_TYPE:
            raise CoreValidationError(
                "invocation envelope object_type must be exactly "
                f"{EXTENSION_INVOCATION_OBJECT_TYPE}"
            )
        if envelope.protocol_version != EXTENSIONS_PROTOCOL_VERSION:
            raise CoreValidationError(
                "invocation envelope protocol_version must be "
                f"{EXTENSIONS_PROTOCOL_VERSION}"
            )
        if envelope.schema_version != EXTENSIONS_SCHEMA_VERSION:
            raise CoreValidationError(
                "invocation envelope schema_version must be the domain schema version"
            )
        if envelope.state != self.status:
            raise CoreValidationError(
                "invocation envelope state must equal the invocation status"
            )
        return replace(self, envelope=envelope)

    # -- target binding -------------------------------------------------------

    def with_target(
        self, *, target_id: str, covering_grant_id: str | None
    ) -> "ExtensionInvocation":
        """Re-bind the concrete invocation target and covering grant.

        Only the kernel runtime (engine.py) uses this: it binds the target
        object the command addressed (a SANDBOX-state manifest or an
        installed instance) and the grant that authorized the capability.
        """
        require_internal_id("invocation target_id", target_id)
        if covering_grant_id is not None:
            require_internal_id("invocation covering_grant_id", covering_grant_id)
        return replace(self, target_id=target_id, covering_grant_id=covering_grant_id)

    # -- canonical serialization -------------------------------------------

    def to_record_dict(self) -> dict[str, Any]:
        return {
            "invocation_id": self.invocation_id,
            "target_id": self.target_id,
            "extension_id": self.extension_id,
            "capability": self.capability.value,
            "input_artifact_ids": list(self.input_artifact_ids),
            "output_artifacts": [artifact.to_dict() for artifact in self.output_artifacts],
            "status": self.status,
            "effect_mode": self.effect_mode.value,
            "environment_mode": self.environment_mode.value,
            "shadowed": self.shadowed,
            "covering_grant_id": self.covering_grant_id,
            "resource_credits": self.resource_credits.credits,
            "artifact_bytes": self.artifact_bytes,
            "as_of": self.as_of,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict() if self.envelope is not None else None,
            "record": self.to_record_dict(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ExtensionInvocation":
        if not isinstance(value, Mapping):
            raise CoreValidationError("invocation must be an object")
        from ._validation import exact_fields

        exact_fields("invocation", value, {"envelope", "record"})
        record = value["record"]
        if not isinstance(record, Mapping):
            raise CoreValidationError("invocation record must be an object")
        exact_fields(
            "invocation record",
            record,
            {
                "invocation_id",
                "target_id",
                "extension_id",
                "capability",
                "input_artifact_ids",
                "output_artifacts",
                "status",
                "effect_mode",
                "environment_mode",
                "shadowed",
                "covering_grant_id",
                "resource_credits",
                "artifact_bytes",
                "as_of",
            },
        )
        outputs = record["output_artifacts"]
        if not isinstance(outputs, list):
            raise CoreValidationError(
                "invocation.output_artifacts must deserialize from a list"
            )
        invocation = cls(
            invocation_id=record["invocation_id"],
            target_id=record["target_id"],
            extension_id=record["extension_id"],
            capability=record["capability"],
            input_artifact_ids=tuple(record["input_artifact_ids"]),
            output_artifacts=tuple(
                ExtensionArtifact.from_dict(item) for item in outputs
            ),
            status=record["status"],
            effect_mode=record["effect_mode"],
            environment_mode=record["environment_mode"],
            shadowed=record["shadowed"],
            covering_grant_id=record["covering_grant_id"],
            resource_credits=record["resource_credits"],
            artifact_bytes=record["artifact_bytes"],
            as_of=record["as_of"],
        )
        if value["envelope"] is None:
            return invocation
        return invocation.bind_envelope(ObjectEnvelope.from_dict(value["envelope"]))


def _artifact_bytes(artifact: ExtensionArtifact) -> int:
    """Canonical byte length of one artifact's sealed form."""
    return len(canonical_json(artifact.to_dict()).encode("utf-8"))


def execute_sandboxed_invocation(
    *,
    manifest: ExtensionManifest,
    handler: SandboxHandler,
    request: InvocationRequest,
    environment_mode: EnvironmentMode,
    shadowed: bool,
) -> ExtensionInvocation:
    """Run one sandboxed invocation and return the sealed record.

    The full frozen security model is enforced here, fail closed at every
    boundary: declared capability, declared input kinds, unexpired input
    artifacts, declared resource views, declared output kinds, producer
    binding, declared schema versions, input/output id disjointness, and
    the manifest's artifact-byte resource requirement. Handler exceptions
    fail closed without partial state.
    """
    if not isinstance(manifest, ExtensionManifest):
        raise CoreValidationError("sandbox invocation requires an ExtensionManifest")
    if not callable(handler):
        raise CoreValidationError("sandbox invocation requires a callable handler")
    if not isinstance(request, InvocationRequest):
        raise CoreValidationError("sandbox invocation requires an InvocationRequest")
    if not isinstance(environment_mode, EnvironmentMode):
        environment_mode = EnvironmentMode.parse(environment_mode)
    require_bool("sandbox invocation shadowed", shadowed)

    # -- capability boundary ------------------------------------------------
    if request.capability not in manifest.capabilities_provided:
        raise CoreValidationError(
            f"undeclared capability {request.capability.value!r}: manifest "
            f"{manifest.extension_id} provides only "
            f"{sorted(item.value for item in manifest.capabilities_provided)}"
        )

    # -- input boundary -----------------------------------------------------
    for artifact in request.inputs:
        if artifact.kind not in manifest.inputs:
            raise CoreValidationError(
                f"undeclared input kind {artifact.kind.value!r}: manifest "
                f"{manifest.extension_id} declares inputs "
                f"{sorted(item.value for item in manifest.inputs)}"
            )
        if compare_timestamps(request.as_of, artifact.expires_at) >= 0:
            raise CoreValidationError(
                f"input artifact {artifact.artifact_id!r} is expired at the "
                f"declared as_of {request.as_of} (expires {artifact.expires_at})"
            )

    # -- resource boundary --------------------------------------------------
    for name, _pairs in request.resources:
        if name not in {permission.value for permission in manifest.permissions}:
            raise CoreValidationError(
                f"undeclared resource {name!r}: manifest {manifest.extension_id} "
                "declares no such permission; extensions cannot access "
                "undeclared resources"
            )

    effect_mode = (
        InvocationEffectMode.SHADOWED if shadowed else InvocationEffectMode.RECORDED
    )

    # -- the closed sandbox -------------------------------------------------
    context = SandboxContext(
        invocation_id=request.invocation_id,
        extension_id=manifest.extension_id,
        capability=request.capability,
        inputs=request.inputs,
        resources=request.resources,
        as_of=request.as_of,
        environment_mode=environment_mode,
        effect_mode=effect_mode,
    )
    try:
        outputs = handler(context)
    except CoreValidationError:
        raise
    except Exception as exc:  # handler code fails closed, no partial state
        raise CoreValidationError(
            f"sandboxed handler for {manifest.extension_id} failed: {exc}"
        ) from exc

    # -- output boundary ----------------------------------------------------
    if not isinstance(outputs, tuple) or not outputs:
        raise CoreValidationError(
            "sandboxed handlers must return a non-empty tuple of artifacts"
        )
    for artifact in outputs:
        if not isinstance(artifact, ExtensionArtifact):
            raise CoreValidationError(
                "sandboxed handler outputs must be ExtensionArtifact values"
            )
        if artifact.kind not in manifest.outputs:
            raise CoreValidationError(
                f"undeclared output kind {artifact.kind.value!r}: manifest "
                f"{manifest.extension_id} declares outputs "
                f"{sorted(item.value for item in manifest.outputs)}"
            )
        if artifact.producer != manifest.extension_id:
            raise CoreValidationError(
                f"output artifact {artifact.artifact_id!r} producer must be the "
                f"invoked extension {manifest.extension_id}, declared "
                f"{artifact.producer!r}"
            )
        if artifact.schema_version not in manifest.schema_versions:
            raise CoreValidationError(
                f"output artifact {artifact.artifact_id!r} schema version "
                f"{artifact.schema_version} is not declared by the manifest"
            )
    output_ids = tuple(artifact.artifact_id for artifact in outputs)
    if len(set(output_ids)) != len(output_ids):
        raise CoreValidationError("sandboxed outputs contain duplicate artifact ids")
    input_ids = {artifact.artifact_id for artifact in request.inputs}
    for artifact_id in output_ids:
        if artifact_id in input_ids:
            raise CoreValidationError(
                f"output artifact id {artifact_id!r} must not collide with an "
                "input artifact id"
            )

    total_bytes = sum(_artifact_bytes(artifact) for artifact in outputs)
    if total_bytes > manifest.resource_requirements.max_artifact_bytes:
        raise CoreValidationError(
            f"artifact bytes {total_bytes} exceed the manifest's declared "
            f"max_artifact_bytes {manifest.resource_requirements.max_artifact_bytes}"
        )

    credits = INVOCATION_BASE_CREDIT + CREDIT_PER_BYTE * total_bytes

    return ExtensionInvocation(
        invocation_id=request.invocation_id,
        # The pure sandbox binds the extension identity as the default
        # target (a SANDBOX-phase manifest target: its object id IS the
        # extension id); the kernel runtime re-binds the concrete target
        # object and covering grant when the invocation runs against an
        # installed instance.
        target_id=manifest.extension_id,
        extension_id=manifest.extension_id,
        capability=request.capability,
        input_artifact_ids=tuple(artifact.artifact_id for artifact in request.inputs),
        output_artifacts=tuple(outputs),
        status="COMPLETED",
        effect_mode=effect_mode,
        environment_mode=environment_mode,
        shadowed=shadowed,
        covering_grant_id=None,
        resource_credits=ResourceCredits(credits=credits),
        artifact_bytes=total_bytes,
        as_of=request.as_of,
    )
