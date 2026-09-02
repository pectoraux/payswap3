"""The kernel-bound extension runtime: the marketplace state machine.

:class:`ExtensionRuntime` binds the extension domain to the real
transition kernel (:class:`src.transition.TransitionEngine`) — there is
no second state machine. Every lifecycle mutation is a kernel command
with an immutable ``extension/...`` event; every durable object is a
sealed kernel envelope; rejections never mutate state; duplicates
converge to the original decision.

Command types are internal free-form strings (the frozen 12-verb
``Extension`` family of command-event-model.md plus the documented
internal triggers ``certify``/``shadow``/``invoke``/``measure``);
events use the registry-listed ``extension`` namespace; the manifest
object uses the registry-listed ``payswap/extension-manifest/v1`` type
while instances, grants, invocations and contributions use internal
non-registry ``extension/...`` types (sibling convention).

The domain projection (manifests, instances, grants, invocations,
contributions, invocation quota counters) is a pure function of the
kernel journal: :meth:`ExtensionRuntime.rebuild_from_journal` replays
the sealed journal into a fresh runtime and reproduces the canonical
domain-state digest byte-identically.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.simulation import EnvironmentMode

from src.transition import (
    AuthorizationDecision,
    Command,
    MemoryStateStore,
    Outcome,
    RejectionReason,
    TransitionApplication,
    TransitionEngine,
    TransitionResult,
    payload_to_json_value,
)

from ._validation import (
    require_bool,
    require_internal_id,
    require_jurisdictions,
    require_text,
    validate_timestamp,
)
from .contracts import (
    CAPABILITY_GRANT_OBJECT_TYPE,
    CERTIFY_MIN_SANDBOX_INVOCATIONS,
    CONTRIBUTION_METRICS,
    DEFAULT_AUTHORIZED_ACTORS,
    EXTENSION_COMMAND_TYPES,
    EXTENSION_CONTRIBUTION_OBJECT_TYPE,
    EXTENSION_INSTANCE_OBJECT_TYPE,
    EXTENSION_INVOCATION_OBJECT_TYPE,
    EXTENSION_MANIFEST_OBJECT_TYPE,
    EXTENSIONS_PROTOCOL_VERSION,
    EXTENSIONS_SCHEMA_VERSION,
    ExtensionCapability,
    ExtensionLifecycleState,
    InvocationEffectMode,
)
from .artifacts import ExtensionArtifact
from .contribution import ExtensionContribution, OutcomeMeasurement, measure_contribution
from .dag import require_acyclic
from .grants import CapabilityGrant, ExtensionInstance
from .lifecycle import (
    require_instance_state,
    require_manifest_state,
    resolve_lifecycle_transition,
)
from .manifest import ExtensionManifest, parse_version, version_in_bounds
from .runtime import (
    CodeRepository,
    ExtensionInvocation,
    InvocationRequest,
    execute_sandboxed_invocation,
)

#: Registry-listed authority class exercising extension command authority
#: (A1 mirrors the kernel dogfooding and the IG-001 integration-gate
#: precedent for command-driving actors).
RUNTIME_AUTHORITY_CLASS = "A1"

#: Provenance source stamp for every object the runtime creates.
RUNTIME_PROVENANCE_SOURCE = "extensions/runtime"

#: Command type -> registry-listed event type (the ``extension`` namespace).
EXTENSION_EVENT_TYPES: Mapping[str, str] = {
    "extension/register": "extension/registered",
    "extension/submit": "extension/submitted",
    "extension/certify": "extension/certified",
    "extension/approve": "extension/approved",
    "extension/reject": "extension/rejected",
    "extension/publish": "extension/published",
    "extension/install": "extension/installed",
    "extension/activate": "extension/activated",
    "extension/shadow": "extension/shadowed",
    "extension/invoke": "extension/invoked",
    "extension/measure": "extension/measured",
    "extension/degrade": "extension/degraded",
    "extension/suspend": "extension/suspended",
    "extension/resume": "extension/resumed",
    "extension/deprecate": "extension/deprecated",
    "extension/archive": "extension/archived",
}

#: Manifest-lifecycle command verbs (targets the manifest object family).
_MANIFEST_VERBS = frozenset(
    {"submit", "certify", "approve", "reject", "publish"}
)

#: Instance-lifecycle command verbs (targets the instance object family).
_INSTANCE_VERBS = frozenset({"activate", "degrade", "suspend", "resume"})

#: Family-agnostic terminal verbs (valid for manifests and instances).
_DUAL_VERBS = frozenset({"deprecate", "archive"})

#: Sandbox invocation window key (the manifest SANDBOX certification phase).
SANDBOX_WINDOW_KEY = "sandbox"

_PAYLOAD_KEYS = frozenset(
    {"envelopes", "manifests", "instances", "grants", "invocations", "contributions"}
)


def _invocation_window_key(invocation: ExtensionInvocation) -> tuple[str, str]:
    """Deterministic quota-window key of one invocation record."""
    if invocation.covering_grant_id is None:
        return (invocation.target_id, SANDBOX_WINDOW_KEY)
    return (invocation.target_id, f"grant:{invocation.covering_grant_id}")


class ExtensionRuntime:
    """One extension marketplace bound to one kernel environment.

    Wraps ONE :class:`TransitionEngine` (the only state machine) plus the
    domain projection rebuilt from its journal. The runtime enforces the
    frozen extension security model end to end: manifests validate their
    authority-tier requirements at registration, sandboxed invocations
    see exactly their declared world, grants scope every capability
    exercise, quotas bound invocation volume, and contribution
    measurement only ever rewards verified incremental value.
    """

    def __init__(
        self,
        *,
        environment_id: str,
        domain_id: str,
        environment_mode: EnvironmentMode,
        authorized_actors: Iterable[str] = DEFAULT_AUTHORIZED_ACTORS,
        code_repository: CodeRepository,
    ) -> None:
        require_text("runtime.environment_id", environment_id)
        require_text("runtime.domain_id", domain_id)
        if not isinstance(environment_mode, EnvironmentMode):
            environment_mode = EnvironmentMode.parse(environment_mode)
        actors = frozenset(authorized_actors)
        if not actors:
            raise CoreValidationError(
                "the extension runtime requires at least one authorized actor"
            )
        for actor in actors:
            require_text("runtime.authorized_actor", actor)
        if not isinstance(code_repository, CodeRepository):
            raise CoreValidationError(
                "the extension runtime requires a CodeRepository"
            )
        self._environment_id = environment_id
        self._domain_id = domain_id
        self._environment_mode = environment_mode
        self._authorized_actors = actors
        self._code_repository = code_repository

        self._store = MemoryStateStore()
        self._engine = TransitionEngine(
            environment_id=environment_id,
            authorization=self._authorize,
            store=self._store,
        )
        for command_type, event_type in EXTENSION_EVENT_TYPES.items():
            self._engine.register(
                command_type, event_type, self._handler_for(command_type)
            )

        self._manifests: dict[str, ExtensionManifest] = {}
        self._instances: dict[str, ExtensionInstance] = {}
        self._grants: dict[str, CapabilityGrant] = {}
        self._invocations: dict[str, ExtensionInvocation] = {}
        self._contributions: dict[str, ExtensionContribution] = {}
        self._invocation_counts: dict[tuple[str, str], int] = {}

    # -- read-only surface ---------------------------------------------------

    @property
    def environment_id(self) -> str:
        return self._environment_id

    @property
    def domain_id(self) -> str:
        return self._domain_id

    @property
    def environment_mode(self) -> EnvironmentMode:
        return self._environment_mode

    @property
    def engine(self) -> TransitionEngine:
        return self._engine

    @property
    def store(self):
        return self._store

    @property
    def code_repository(self) -> CodeRepository:
        return self._code_repository

    def manifest(self, extension_id: str) -> ExtensionManifest:
        manifest = self._manifests.get(extension_id)
        if manifest is None:
            raise CoreValidationError(f"unknown extension manifest {extension_id!r}")
        return manifest

    def instance(self, instance_id: str) -> ExtensionInstance:
        instance = self._instances.get(instance_id)
        if instance is None:
            raise CoreValidationError(f"unknown extension instance {instance_id!r}")
        return instance

    def grant(self, grant_id: str) -> CapabilityGrant:
        grant = self._grants.get(grant_id)
        if grant is None:
            raise CoreValidationError(f"unknown capability grant {grant_id!r}")
        return grant

    def invocation(self, invocation_id: str) -> ExtensionInvocation:
        invocation = self._invocations.get(invocation_id)
        if invocation is None:
            raise CoreValidationError(f"unknown extension invocation {invocation_id!r}")
        return invocation

    def contribution(self, contribution_id: str) -> ExtensionContribution:
        contribution = self._contributions.get(contribution_id)
        if contribution is None:
            raise CoreValidationError(
                f"unknown extension contribution {contribution_id!r}"
            )
        return contribution

    def invocation_count(self, target_id: str, window_key: str) -> int:
        return self._invocation_counts.get((target_id, window_key), 0)

    # -- command submission --------------------------------------------------

    def submit(self, command: Command) -> TransitionResult:
        """Process one extension command through the real kernel.

        Handler-level fail-closed validation raises
        ``CoreValidationError``; the runtime converts it into an explicit
        ``POLICY_REJECTED`` result after asserting the domain state is
        byte-identical to its pre-command form (rejections never mutate
        state). Accepted commands advance the immutable journal and the
        domain projection.
        """
        if not isinstance(command, Command):
            raise CoreValidationError("submit expects a Command envelope")
        journal_before = self._engine.journal
        snapshot_before = self._store.snapshot()
        try:
            result = self._engine.process(command)
        except CoreValidationError as exc:
            if self._engine.journal != journal_before or (
                self._store.snapshot() != snapshot_before
            ):
                raise CoreValidationError(
                    f"command {command.command_id} failed closed after mutating "
                    "state; failing closed on divergence"
                ) from exc
            return TransitionResult(
                command_id=command.command_id,
                idempotency_key=command.idempotency_key,
                outcome=Outcome.REJECTED,
                reason=RejectionReason.POLICY_REJECTED,
                detail=str(exc),
                event=None,
                payload=None,
                resulting_envelopes=(),
            )
        if result.outcome is Outcome.REJECTED:
            if self._engine.journal != journal_before or (
                self._store.snapshot() != snapshot_before
            ):
                raise CoreValidationError(
                    f"kernel rejected command {command.command_id} but the domain "
                    "state mutated; failing closed on divergence"
                )
            return result
        if result.outcome is Outcome.ACCEPTED:
            self._apply_projection(result)
        return result

    # -- projection and digests ---------------------------------------------

    def domain_state_digest(self) -> str:
        """Canonical digest of the whole domain projection.

        A pure function of the accepted command history: the sealed
        envelopes plus the domain records of every manifest, instance,
        grant, invocation and contribution, deterministically ordered.
        """
        state: list[tuple[str, Any]] = []
        for extension_id in sorted(self._manifests):
            state.append(("manifest", self._manifests[extension_id].to_dict()))
        for instance_id in sorted(self._instances):
            state.append(("instance", self._instances[instance_id].to_dict()))
        for grant_id in sorted(self._grants):
            state.append(("grant", self._grants[grant_id].to_dict()))
        for invocation_id in sorted(self._invocations):
            state.append(("invocation", self._invocations[invocation_id].to_dict()))
        for contribution_id in sorted(self._contributions):
            state.append(
                ("contribution", self._contributions[contribution_id].to_dict())
            )
        return canonical_sha256(state)

    def rebuild_from_journal(self) -> str:
        """Replay the sealed journal into a fresh runtime; return its digest.

        Proves the domain projection is reproducible from the immutable
        journal alone: envelopes are re-committed in order and the
        records (including invocation quota counters) are re-applied
        deterministically.
        """
        fresh = ExtensionRuntime(
            environment_id=self._environment_id,
            domain_id=self._domain_id,
            environment_mode=self._environment_mode,
            authorized_actors=self._authorized_actors,
            code_repository=self._code_repository,
        )
        for entry in self._engine.journal:
            decoded = payload_to_json_value(entry.payload)
            self._require_payload_shape(decoded, "journal entry")
            envelopes = tuple(
                ObjectEnvelope.from_dict(item) for item in decoded["envelopes"]
            )
            fresh._store.commit(envelopes)
            fresh._apply_decoded(decoded)
        return fresh.domain_state_digest()

    def _apply_projection(self, result: TransitionResult) -> None:
        decoded = payload_to_json_value(result.payload)
        self._require_payload_shape(decoded, "transition result")
        self._apply_decoded(decoded)

    @staticmethod
    def _require_payload_shape(decoded: object, name: str) -> None:
        if not isinstance(decoded, Mapping) or set(decoded) != _PAYLOAD_KEYS:
            raise CoreValidationError(
                f"{name} payload is not the canonical extension projection payload"
            )

    def _apply_decoded(self, decoded: Mapping[str, Any]) -> None:
        envelopes: dict[str, ObjectEnvelope] = {}
        for item in decoded["envelopes"]:
            envelope = ObjectEnvelope.from_dict(item)
            if envelope.object_id in envelopes:
                raise CoreValidationError(
                    "projection payload contains duplicate envelopes"
                )
            envelopes[envelope.object_id] = envelope

        for record in decoded["manifests"]:
            manifest = ExtensionManifest.from_dict({"envelope": None, "record": record})
            envelope = envelopes.get(manifest.extension_id)
            if envelope is None:
                raise CoreValidationError(
                    "projection payload manifest record has no matching envelope"
                )
            self._manifests[manifest.extension_id] = manifest.bind_envelope(envelope)

        for record in decoded["instances"]:
            instance = ExtensionInstance.from_dict({"envelope": None, "record": record})
            envelope = envelopes.get(instance.instance_id)
            if envelope is None:
                raise CoreValidationError(
                    "projection payload instance record has no matching envelope"
                )
            self._instances[instance.instance_id] = instance.bind_envelope(envelope)

        for record in decoded["grants"]:
            grant = CapabilityGrant.from_dict({"envelope": None, "record": record})
            envelope = envelopes.get(grant.grant_id)
            if envelope is None:
                raise CoreValidationError(
                    "projection payload grant record has no matching envelope"
                )
            self._grants[grant.grant_id] = grant.bind_envelope(envelope)

        for record in decoded["invocations"]:
            invocation = ExtensionInvocation.from_dict(
                {"envelope": None, "record": record}
            )
            envelope = envelopes.get(invocation.invocation_id)
            if envelope is None:
                raise CoreValidationError(
                    "projection payload invocation record has no matching envelope"
                )
            bound = invocation.bind_envelope(envelope)
            self._invocations[invocation.invocation_id] = bound
            key = _invocation_window_key(bound)
            self._invocation_counts[key] = self._invocation_counts.get(key, 0) + 1

        for record in decoded["contributions"]:
            contribution = ExtensionContribution.from_dict(
                {"envelope": None, "record": record}
            )
            envelope = envelopes.get(contribution.contribution_id)
            if envelope is None:
                raise CoreValidationError(
                    "projection payload contribution record has no matching envelope"
                )
            self._contributions[contribution.contribution_id] = (
                contribution.bind_envelope(envelope)
            )

    # -- kernel plumbing -----------------------------------------------------

    def _authorize(self, command: Command, view) -> AuthorizationDecision:
        if command.actor in self._authorized_actors:
            return AuthorizationDecision(
                granted=True, authority=RUNTIME_AUTHORITY_CLASS, reason=None
            )
        return AuthorizationDecision(
            granted=False,
            authority=None,
            reason=(
                f"actor {command.actor} is not authorized to drive extension "
                f"commands in environment {self._environment_id}"
            ),
        )

    def _handler_for(self, command_type: str):
        verb = command_type.partition("/")[2]

        def handler(command: Command, view) -> TransitionApplication:
            return self._dispatch(verb, command)

        return handler

    def _dispatch(self, verb: str, command: Command) -> TransitionApplication:
        if f"extension/{verb}" not in EXTENSION_COMMAND_TYPES:
            raise CoreValidationError(f"unknown extension command verb {verb!r}")
        if verb == "register":
            return self._handle_register(command)
        if verb == "install":
            return self._handle_install(command)
        if verb == "invoke":
            return self._handle_invoke(command)
        if verb == "measure":
            return self._handle_measure(command)
        if verb == "shadow":
            return self._handle_shadow(command)
        if verb in _MANIFEST_VERBS:
            return self._handle_state_advance(command, verb, manifest_only=True)
        if verb in _INSTANCE_VERBS:
            return self._handle_state_advance(command, verb, manifest_only=False)
        if verb in _DUAL_VERBS:
            return self._handle_state_advance(command, verb, manifest_only=None)
        raise CoreValidationError(f"unhandled extension command verb {verb!r}")

    # -- shared helpers ------------------------------------------------------

    @staticmethod
    def _payload_dict(command: Command) -> dict[str, Any]:
        decoded = payload_to_json_value(command.payload)
        if not isinstance(decoded, dict):
            raise CoreValidationError(
                f"extension command {command.command_id} payload must be an object"
            )
        return decoded

    def _provenance(self, command: Command) -> Provenance:
        return Provenance(
            issuer=command.actor,
            source=RUNTIME_PROVENANCE_SOURCE,
            recorded_at=command.requested_at,
        )

    def _new_envelope(
        self, *, object_id: str, object_type: str, state: str, command: Command
    ) -> ObjectEnvelope:
        return (
            ObjectEnvelope(
                object_id=object_id,
                object_type=object_type,
                object_version=1,
                environment_id=command.environment_id,
                domain_id=command.domain_id,
                schema_version=EXTENSIONS_SCHEMA_VERSION,
                protocol_version=EXTENSIONS_PROTOCOL_VERSION,
                state=state,
                provenance=self._provenance(command),
                causation_id=command.command_id,
                correlation_id=command.correlation_id,
                previous_version=None,
            )
            .with_integrity_hash()
        )

    def _next_envelope(
        self, current: ObjectEnvelope, *, state: str, command: Command
    ) -> ObjectEnvelope:
        return (
            current.next_version(
                state=state,
                provenance=self._provenance(command),
                causation_id=command.command_id,
                correlation_id=command.correlation_id,
            )
            .with_integrity_hash()
        )

    @staticmethod
    def _application_payload(
        *,
        envelopes: tuple[ObjectEnvelope, ...],
        manifests: tuple[dict[str, Any], ...] = (),
        instances: tuple[dict[str, Any], ...] = (),
        grants: tuple[dict[str, Any], ...] = (),
        invocations: tuple[dict[str, Any], ...] = (),
        contributions: tuple[dict[str, Any], ...] = (),
    ) -> dict[str, Any]:
        return {
            "envelopes": [envelope.to_dict() for envelope in envelopes],
            "manifests": list(manifests),
            "instances": list(instances),
            "grants": list(grants),
            "invocations": list(invocations),
            "contributions": list(contributions),
        }

    def _single_target(self, command: Command) -> str:
        if len(command.target_refs) != 1:
            raise CoreValidationError(
                f"extension command {command.command_id} must declare exactly one "
                f"target object (declared {list(command.target_refs)})"
            )
        return command.target_refs[0]

    def _target_envelope(self, command: Command, object_ref: str) -> ObjectEnvelope:
        envelope = self._store.get(object_ref)
        if envelope is None:
            raise CoreValidationError(
                f"extension object {object_ref!r} does not exist in environment "
                f"{self._environment_id}"
            )
        if envelope.environment_id != command.environment_id or (
            envelope.domain_id != command.domain_id
        ):
            raise CoreValidationError(
                f"extension object {object_ref!r} does not belong to the command "
                f"environment/domain"
            )
        return envelope

    def _require_envelope_object_type(self, envelope: ObjectEnvelope, object_type: str) -> None:
        if envelope.object_type != object_type:
            raise CoreValidationError(
                f"extension object {envelope.object_id!r} must be of type "
                f"{object_type!r} but is {envelope.object_type!r}"
            )

    def _parse_state(self, envelope: ObjectEnvelope) -> ExtensionLifecycleState:
        from .lifecycle import parse_lifecycle_state

        return parse_lifecycle_state(envelope.state)

    # -- register ------------------------------------------------------------

    def _handle_register(self, command: Command) -> TransitionApplication:
        payload = self._payload_dict(command)
        if set(payload) != {"manifest"}:
            raise CoreValidationError(
                "extension/register payload must carry exactly the 'manifest' record"
            )
        manifest = ExtensionManifest.from_record_dict(payload["manifest"])
        target = self._single_target(command)
        if target != manifest.extension_id:
            raise CoreValidationError(
                "extension/register must target the manifest extension_id "
                f"{manifest.extension_id!r}"
            )
        if self._store.get(manifest.extension_id) is not None:
            raise CoreValidationError(
                f"extension manifest {manifest.extension_id!r} is already registered"
            )
        # The declared code must exist in the repository (never execute
        # undeclared code).
        self._code_repository.resolve(manifest.code_hash)
        # Dependency cycles fail closed at registration (missing
        # dependencies are resolved later, at install/activation time).
        candidates = dict(self._manifests)
        candidates[manifest.extension_id] = manifest
        require_acyclic(candidates)

        envelope = self._new_envelope(
            object_id=manifest.extension_id,
            object_type=EXTENSION_MANIFEST_OBJECT_TYPE,
            state=ExtensionLifecycleState.DRAFT.value,
            command=command,
        )
        bound = manifest.bind_envelope(envelope)
        return TransitionApplication(
            resulting_envelopes=(envelope,),
            payload=self._application_payload(
                envelopes=(envelope,), manifests=(bound.to_record_dict(),)
            ),
        )

    # -- lifecycle state advancement -----------------------------------------

    def _handle_state_advance(
        self, command: Command, verb: str, *, manifest_only: bool | None
    ) -> TransitionApplication:
        if verb == "reject":
            payload = self._payload_dict(command)
            if set(payload) != {"reason"}:
                raise CoreValidationError(
                    "extension/reject payload must carry exactly a 'reason'"
                )
            require_text("extension/reject reason", payload["reason"])
        else:
            payload = self._payload_dict(command)
            if payload:
                raise CoreValidationError(
                    f"extension/{verb} payload must be empty"
                )
        object_ref = self._single_target(command)
        envelope = self._target_envelope(command, object_ref)
        current_state = self._parse_state(envelope)

        if envelope.object_type == EXTENSION_MANIFEST_OBJECT_TYPE:
            if manifest_only is False:
                raise CoreValidationError(
                    f"extension/{verb} targets an instance object, but "
                    f"{object_ref!r} is a manifest"
                )
            require_manifest_state(current_state)
        elif envelope.object_type == EXTENSION_INSTANCE_OBJECT_TYPE:
            if manifest_only is True:
                raise CoreValidationError(
                    f"extension/{verb} targets a manifest object, but "
                    f"{object_ref!r} is an instance"
                )
            require_instance_state(current_state)
        else:
            raise CoreValidationError(
                f"extension/{verb} target {object_ref!r} is neither an extension "
                "manifest nor an extension instance"
            )

        if verb == "certify":
            sandbox_evidence = sum(
                1
                for invocation in self._invocations.values()
                if invocation.target_id == object_ref
                and invocation.covering_grant_id is None
            )
            if sandbox_evidence < CERTIFY_MIN_SANDBOX_INVOCATIONS:
                raise CoreValidationError(
                    f"certification of {object_ref!r} requires at least "
                    f"{CERTIFY_MIN_SANDBOX_INVOCATIONS} completed sandbox "
                    f"invocation(s) as evidence; recorded {sandbox_evidence}"
                )

        if verb == "activate":
            # Activation readiness: every declared dependency must be
            # backed by an ACTIVE instance within the declared bounds.
            instance = self.instance(object_ref)
            manifest = self.manifest(instance.manifest_id)
            for spec in manifest.dependencies:
                active = self._active_instance_of(spec.extension_id)
                if active is None:
                    raise CoreValidationError(
                        f"activation of {object_ref!r} requires an ACTIVE instance "
                        f"of dependency {spec.extension_id} in this environment"
                    )
                if not version_in_bounds(active.version, spec):
                    raise CoreValidationError(
                        f"dependency {spec.extension_id} instance version "
                        f"{active.version} is outside the declared bounds of "
                        f"{manifest.extension_id}"
                    )

        target_state = resolve_lifecycle_transition(verb, current_state)
        if envelope.object_type == EXTENSION_MANIFEST_OBJECT_TYPE:
            require_manifest_state(target_state)
        else:
            require_instance_state(target_state)

        new_envelope = self._next_envelope(
            envelope, state=target_state.value, command=command
        )
        if envelope.object_type == EXTENSION_MANIFEST_OBJECT_TYPE:
            record = self.manifest(object_ref).to_record_dict()
            return TransitionApplication(
                resulting_envelopes=(new_envelope,),
                payload=self._application_payload(
                    envelopes=(new_envelope,), manifests=(record,)
                ),
            )
        record = self.instance(object_ref).to_record_dict()
        return TransitionApplication(
            resulting_envelopes=(new_envelope,),
            payload=self._application_payload(
                envelopes=(new_envelope,), instances=(record,)
            ),
        )

    # -- install -------------------------------------------------------------

    def _handle_install(self, command: Command) -> TransitionApplication:
        payload = self._payload_dict(command)
        if set(payload) != {"instance_id", "manifest_id", "version", "jurisdictions", "grants"}:
            raise CoreValidationError(
                "extension/install payload must carry exactly instance_id, "
                "manifest_id, version, jurisdictions and grants"
            )
        instance_id = require_internal_id("install.instance_id", payload["instance_id"])
        manifest_id = require_internal_id("install.manifest_id", payload["manifest_id"])
        require_text("install.version", payload["version"])
        jurisdictions = require_jurisdictions("install.jurisdictions", payload["jurisdictions"])
        manifest = self.manifest(manifest_id)
        manifest_envelope = self._target_envelope(command, manifest_id)
        self._require_envelope_object_type(
            manifest_envelope, EXTENSION_MANIFEST_OBJECT_TYPE
        )
        # Dependency resolution comes first: a missing dependency is a
        # structural defect regardless of the target's own state.
        closure = self._dependency_closure(manifest)
        for extension_id in sorted(closure):
            if extension_id == manifest.extension_id:
                continue
            dependency_envelope = self._store.get(extension_id)
            if dependency_envelope is None:
                raise CoreValidationError(
                    f"missing dependency: {manifest_id} depends on {extension_id} "
                    "which is not registered"
                )
            if dependency_envelope.state != ExtensionLifecycleState.PUBLISHED.value:
                raise CoreValidationError(
                    f"install requires dependency {extension_id!r} to be published "
                    f"(state {dependency_envelope.state})"
                )
        if self._parse_state(manifest_envelope) is not ExtensionLifecycleState.PUBLISHED:
            raise CoreValidationError(
                f"install requires manifest {manifest_id!r} to be published "
                f"(state {manifest_envelope.state})"
            )
        if payload["version"] != manifest.version:
            raise CoreValidationError(
                f"install version {payload['version']!r} must equal the published "
                f"manifest version {manifest.version!r}"
            )
        if self._store.get(instance_id) is not None:
            raise CoreValidationError(
                f"extension instance {instance_id!r} already exists"
            )
        # Environment-class support gate.
        if self._environment_mode == EnvironmentMode.PRODUCTION:
            if not manifest.production_support:
                raise CoreValidationError(
                    f"manifest {manifest_id!r} does not declare production support; "
                    "installing into a production environment fails closed"
                )
        elif not manifest.simulation_support:
            raise CoreValidationError(
                f"manifest {manifest_id!r} does not declare simulation support; "
                "installing into a non-production environment fails closed"
            )
        for jurisdiction in jurisdictions:
            if jurisdiction not in manifest.jurisdictions:
                raise CoreValidationError(
                    f"install jurisdiction {jurisdiction!r} is outside the "
                    f"manifest jurisdictions {list(manifest.jurisdictions)}"
                )
        # Version bounds across the dependency closure (fail closed).
        from .dag import DependencyGraph

        DependencyGraph.build(closure)

        grants_payload = payload["grants"]
        if not isinstance(grants_payload, list) or not grants_payload:
            raise CoreValidationError(
                "extension/install requires at least one capability grant"
            )
        grants: list[CapabilityGrant] = []
        for entry in grants_payload:
            grants.append(self._parse_grant(entry, instance_id, manifest))
        declared = {instance_id} | {grant.grant_id for grant in grants}
        if set(command.target_refs) != declared:
            raise CoreValidationError(
                "extension/install must declare exactly the instance and its "
                f"grants in target_refs (declared {list(command.target_refs)})"
            )

        instance = ExtensionInstance(
            instance_id=instance_id,
            manifest_id=manifest_id,
            extension_id=manifest.extension_id,
            version=manifest.version,
            environment_mode=self._environment_mode,
            shadow=False,
            jurisdictions=jurisdictions,
        )
        instance_envelope = self._new_envelope(
            object_id=instance_id,
            object_type=EXTENSION_INSTANCE_OBJECT_TYPE,
            state=ExtensionLifecycleState.INSTALLED.value,
            command=command,
        )
        bound_instance = instance.bind_envelope(instance_envelope)
        grant_envelopes: list[ObjectEnvelope] = []
        bound_grants: list[CapabilityGrant] = []
        for grant in grants:
            grant_envelope = self._new_envelope(
                object_id=grant.grant_id,
                object_type=CAPABILITY_GRANT_OBJECT_TYPE,
                state="ACTIVE",
                command=command,
            )
            grant_envelopes.append(grant_envelope)
            bound_grants.append(grant.bind_envelope(grant_envelope))

        envelopes = (instance_envelope, *tuple(grant_envelopes))
        return TransitionApplication(
            resulting_envelopes=envelopes,
            payload=self._application_payload(
                envelopes=envelopes,
                instances=(bound_instance.to_record_dict(),),
                grants=tuple(grant.to_record_dict() for grant in bound_grants),
            ),
        )

    def _parse_grant(
        self, entry: object, instance_id: str, manifest: ExtensionManifest
    ) -> CapabilityGrant:
        if not isinstance(entry, Mapping):
            raise CoreValidationError("install grants must be objects")
        if set(entry) != {
            "grant_id",
            "capability",
            "granted_by",
            "valid_from",
            "valid_until",
            "jurisdictions",
            "budget",
        }:
            raise CoreValidationError(
                "install grant payloads must carry exactly grant_id, capability, "
                "granted_by, valid_from, valid_until, jurisdictions and budget"
            )
        grant_id = require_internal_id("grant.grant_id", entry["grant_id"])
        capability = ExtensionCapability.parse(entry["capability"])
        if capability not in manifest.capabilities_provided:
            raise CoreValidationError(
                f"grant {grant_id!r} claims capability {capability.value!r} which "
                f"manifest {manifest.extension_id} does not provide; grants for "
                "undeclared capabilities fail closed"
            )
        if entry["granted_by"] not in self._authorized_actors:
            raise CoreValidationError(
                f"grant {grant_id!r} must be granted by an authorized marketplace "
                "actor"
            )
        if self._store.get(grant_id) is not None:
            raise CoreValidationError(
                f"capability grant {grant_id!r} already exists"
            )
        return CapabilityGrant(
            grant_id=grant_id,
            instance_id=instance_id,
            extension_id=manifest.extension_id,
            capability=capability,
            granted_by=entry["granted_by"],
            valid_from=entry["valid_from"],
            valid_until=entry["valid_until"],
            jurisdictions=entry["jurisdictions"],
            budget=entry["budget"],
        )

    def _active_instance_of(self, extension_id: str) -> ExtensionInstance | None:
        """The ACTIVE instance of one extension in this environment, if any."""
        candidates = sorted(
            (
                instance
                for instance in self._instances.values()
                if instance.extension_id == extension_id
                and instance.state is ExtensionLifecycleState.ACTIVE
            ),
            key=lambda instance: instance.instance_id,
        )
        return candidates[0] if candidates else None

    def _dependency_closure(
        self, manifest: ExtensionManifest
    ) -> dict[str, ExtensionManifest]:
        closure: dict[str, ExtensionManifest] = {manifest.extension_id: manifest}
        pending = [manifest]
        while pending:
            current = pending.pop()
            for spec in current.dependencies:
                if spec.extension_id in closure:
                    continue
                dependency = self._manifests.get(spec.extension_id)
                if dependency is None:
                    raise CoreValidationError(
                        f"missing dependency: {manifest.extension_id} depends on "
                        f"{spec.extension_id} which is not registered"
                    )
                closure[spec.extension_id] = dependency
                pending.append(dependency)
        return closure

    # -- shadow ---------------------------------------------------------------

    def _handle_shadow(self, command: Command) -> TransitionApplication:
        payload = self._payload_dict(command)
        if set(payload) != {"shadow"}:
            raise CoreValidationError(
                "extension/shadow payload must carry exactly a boolean 'shadow' flag"
            )
        shadow = require_bool("extension/shadow flag", payload["shadow"])
        instance_id = self._single_target(command)
        envelope = self._target_envelope(command, instance_id)
        self._require_envelope_object_type(envelope, EXTENSION_INSTANCE_OBJECT_TYPE)
        if self._parse_state(envelope) is not ExtensionLifecycleState.ACTIVE:
            raise CoreValidationError(
                f"shadow requires an ACTIVE instance; {instance_id!r} is in state "
                f"{envelope.state}"
            )
        instance = self.instance(instance_id)
        updated = ExtensionInstance(
            instance_id=instance.instance_id,
            manifest_id=instance.manifest_id,
            extension_id=instance.extension_id,
            version=instance.version,
            environment_mode=instance.environment_mode,
            shadow=shadow,
            jurisdictions=instance.jurisdictions,
        )
        new_envelope = self._next_envelope(
            envelope, state=ExtensionLifecycleState.ACTIVE.value, command=command
        )
        return TransitionApplication(
            resulting_envelopes=(new_envelope,),
            payload=self._application_payload(
                envelopes=(new_envelope,),
                instances=(updated.bind_envelope(new_envelope).to_record_dict(),),
            ),
        )

    # -- invoke ---------------------------------------------------------------

    def _handle_invoke(self, command: Command) -> TransitionApplication:
        payload = self._payload_dict(command)
        if set(payload) != {
            "invocation_id",
            "capability",
            "inputs",
            "resources",
            "as_of",
            "jurisdiction",
        }:
            raise CoreValidationError(
                "extension/invoke payload must carry exactly invocation_id, "
                "capability, inputs, resources, as_of and jurisdiction"
            )
        invocation_id = require_internal_id(
            "invoke.invocation_id", payload["invocation_id"]
        )
        target = self._single_target(command)
        if target != invocation_id:
            raise CoreValidationError(
                "extension/invoke must target the invocation id being created"
            )
        expected_refs = [
            expected.object_ref
            for expected in command.expected_versions
            if expected.object_ref != invocation_id
        ]
        if len(expected_refs) != 1:
            raise CoreValidationError(
                "extension/invoke must declare exactly one invoked target object "
                "besides the invocation id (expected_versions)"
            )
        target_ref = expected_refs[0]
        target_envelope = self._target_envelope(command, target_ref)

        if not isinstance(payload["inputs"], list) or not payload["inputs"]:
            raise CoreValidationError("invoke inputs must be a non-empty list")
        inputs = tuple(
            ExtensionArtifact.from_dict(item) for item in payload["inputs"]
        )
        resources_payload = payload["resources"]
        if not isinstance(resources_payload, Mapping):
            raise CoreValidationError("invoke resources must be an object")
        resources = tuple(
            (
                require_text("invoke resource name", name),
                tuple(sorted((key, value) for key, value in view.items())),
            )
            for name, view in sorted(resources_payload.items())
        )
        request = InvocationRequest(
            invocation_id=invocation_id,
            capability=payload["capability"],
            inputs=inputs,
            resources=resources,
            as_of=payload["as_of"],
        )
        jurisdiction = require_text("invoke jurisdiction", payload["jurisdiction"])
        validate_timestamp("invoke as_of", payload["as_of"])

        if target_envelope.object_type == EXTENSION_MANIFEST_OBJECT_TYPE:
            return self._invoke_sandbox(
                command, target_ref, target_envelope, request
            )
        if target_envelope.object_type == EXTENSION_INSTANCE_OBJECT_TYPE:
            return self._invoke_instance(
                command, target_ref, target_envelope, request, jurisdiction
            )
        raise CoreValidationError(
            f"extension/invoke target {target_ref!r} is neither a manifest nor an "
            "instance object"
        )

    def _invoke_sandbox(
        self,
        command: Command,
        target_ref: str,
        target_envelope: ObjectEnvelope,
        request: InvocationRequest,
    ) -> TransitionApplication:
        if self._parse_state(target_envelope) is not ExtensionLifecycleState.SANDBOX:
            raise CoreValidationError(
                f"sandbox invocations require the SANDBOX lifecycle state; manifest "
                f"{target_ref!r} is in state {target_envelope.state}"
            )
        manifest = self.manifest(target_ref)
        window_key = (target_ref, SANDBOX_WINDOW_KEY)
        count = self._invocation_counts.get(window_key, 0)
        if count >= manifest.resource_requirements.max_invocations_per_window:
            raise CoreValidationError(
                f"resource quota exhausted: manifest {target_ref!r} allows at most "
                f"{manifest.resource_requirements.max_invocations_per_window} "
                f"invocations per window; recorded {count}"
            )
        shadowed = self._environment_mode == EnvironmentMode.SHADOW
        bound = self._execute_invocation(
            command=command,
            manifest=manifest,
            request=request,
            shadowed=shadowed,
            target_id=target_ref,
            covering_grant_id=None,
        )
        return TransitionApplication(
            resulting_envelopes=(bound.envelope,),
            payload=self._application_payload(
                envelopes=(bound.envelope,),
                invocations=(bound.to_record_dict(),),
            ),
        )

    def _invoke_instance(
        self,
        command: Command,
        target_ref: str,
        target_envelope: ObjectEnvelope,
        request: InvocationRequest,
        jurisdiction: str,
    ) -> TransitionApplication:
        if self._parse_state(target_envelope) is not ExtensionLifecycleState.ACTIVE:
            raise CoreValidationError(
                f"invocation requires an ACTIVE instance; {target_ref!r} is in "
                f"state {target_envelope.state}"
            )
        instance = self.instance(target_ref)
        manifest = self.manifest(instance.manifest_id)
        grant = self._covering_grant(instance, request, jurisdiction)
        window_key = (target_ref, f"grant:{grant.grant_id}")
        count = self._invocation_counts.get(window_key, 0)
        if count >= manifest.resource_requirements.max_invocations_per_window:
            raise CoreValidationError(
                f"resource quota exhausted: manifest {manifest.extension_id!r} "
                f"allows at most "
                f"{manifest.resource_requirements.max_invocations_per_window} "
                f"invocations per window; recorded {count}"
            )
        if count >= grant.budget.max_invocations:
            raise CoreValidationError(
                f"grant budget quota exhausted: grant {grant.grant_id!r} allows at "
                f"most {grant.budget.max_invocations} invocations in its budget "
                f"window; recorded {count}"
            )
        shadowed = instance.shadow or self._environment_mode == EnvironmentMode.SHADOW
        bound = self._execute_invocation(
            command=command,
            manifest=manifest,
            request=request,
            shadowed=shadowed,
            target_id=target_ref,
            covering_grant_id=grant.grant_id,
        )
        return TransitionApplication(
            resulting_envelopes=(bound.envelope,),
            payload=self._application_payload(
                envelopes=(bound.envelope,),
                invocations=(bound.to_record_dict(),),
            ),
        )

    def _covering_grant(
        self, instance: ExtensionInstance, request: InvocationRequest, jurisdiction: str
    ) -> CapabilityGrant:
        candidates = sorted(
            (
                grant
                for grant in self._grants.values()
                if grant.instance_id == instance.instance_id
                and grant.capability is request.capability
            ),
            key=lambda grant: grant.grant_id,
        )
        if not candidates:
            raise CoreValidationError(
                f"no covering capability grant: instance {instance.instance_id!r} "
                f"has no grant for capability {request.capability.value!r}"
            )
        scoped = [
            grant for grant in candidates if jurisdiction in grant.jurisdictions
        ]
        if not scoped:
            raise CoreValidationError(
                f"grant jurisdiction scope: no grant of capability "
                f"{request.capability.value!r} covers jurisdiction "
                f"{jurisdiction!r} for instance {instance.instance_id!r}"
            )
        for grant in scoped:
            if not grant.covers(as_of=_invocation_as_of(request), jurisdiction=jurisdiction):
                continue
            if not grant.budget.contains(_invocation_as_of(request)):
                continue
            return grant
        raise CoreValidationError(
            f"grant window: no grant of capability {request.capability.value!r} "
            f"covers the declared as_of {_invocation_as_of(request)} for instance "
            f"{instance.instance_id!r} (validity or budget window exhausted)"
        )

    def _execute_invocation(
        self,
        *,
        command: Command,
        manifest: ExtensionManifest,
        request: InvocationRequest,
        shadowed: bool,
        target_id: str,
        covering_grant_id: str | None,
    ) -> ExtensionInvocation:
        """Compute the sealed invocation record WITHOUT mutating state.

        The handler is validate-and-compute only: the resulting envelope
        and record are journaled by the kernel and applied to the domain
        projection exclusively by :meth:`_apply_decoded` after the commit.
        A rejection therefore leaves the projection untouched.
        """
        handler = self._code_repository.resolve(manifest.code_hash)
        invocation = execute_sandboxed_invocation(
            manifest=manifest,
            handler=handler,
            request=request,
            environment_mode=self._environment_mode,
            shadowed=shadowed,
        )
        invocation = invocation.with_target(
            target_id=target_id, covering_grant_id=covering_grant_id
        )
        envelope = self._new_envelope(
            object_id=invocation.invocation_id,
            object_type=EXTENSION_INVOCATION_OBJECT_TYPE,
            state=invocation.status,
            command=command,
        )
        return invocation.bind_envelope(envelope)

    # -- measure ---------------------------------------------------------------

    def _handle_measure(self, command: Command) -> TransitionApplication:
        payload = self._payload_dict(command)
        if set(payload) != {"contribution_id", "baseline", "treatment"}:
            raise CoreValidationError(
                "extension/measure payload must carry exactly contribution_id, "
                "baseline and treatment"
            )
        contribution_id = require_internal_id(
            "measure.contribution_id", payload["contribution_id"]
        )
        target = self._single_target(command)
        if target != contribution_id:
            raise CoreValidationError(
                "extension/measure must target the contribution id being created"
            )
        if self._store.get(contribution_id) is not None:
            raise CoreValidationError(
                f"extension contribution {contribution_id!r} already exists"
            )
        for arm in ("baseline", "treatment"):
            arm_payload = payload[arm]
            if isinstance(arm_payload, Mapping):
                metric = arm_payload.get("metric")
                if not isinstance(metric, str) or metric not in CONTRIBUTION_METRICS:
                    raise CoreValidationError(
                        f"contribution metric {metric!r} is not in the closed "
                        "vocabulary; activity volume alone is not a valid "
                        "contribution measure"
                    )
        baseline = OutcomeMeasurement.from_dict(payload["baseline"])
        treatment = OutcomeMeasurement.from_dict(payload["treatment"])

        # The extension's declared marketplace pricing governs the reward.
        manifest = self.manifest(treatment.extension_id)

        # Verified evidence resolution: every treatment evidence reference
        # must resolve to a recorded invocation of the same extension;
        # only RECORDED (applied) invocations count — shadowed
        # observation never adds applied invocations or earnings.
        applied: list[ExtensionInvocation] = []
        for reference in treatment.evidence_refs:
            invocation = self._invocations.get(reference)
            if invocation is None:
                raise CoreValidationError(
                    f"treatment evidence reference {reference!r} does not resolve "
                    "to a recorded invocation; unbacked measurements fail closed"
                )
            if invocation.extension_id != treatment.extension_id:
                raise CoreValidationError(
                    f"treatment evidence reference {reference!r} belongs to "
                    f"extension {invocation.extension_id!r}, not "
                    f"{treatment.extension_id!r}"
                )
            if invocation.effect_mode is InvocationEffectMode.RECORDED:
                applied.append(invocation)
        applied_invocations = len(applied)
        resource_credits = sum(
            invocation.resource_credits.credits for invocation in applied
        )

        contribution = measure_contribution(
            contribution_id=contribution_id,
            baseline=baseline,
            treatment=treatment,
            pricing=manifest.pricing,
            applied_invocations=applied_invocations,
            resource_credits=resource_credits,
            as_of=command.requested_at,
        )
        envelope = self._new_envelope(
            object_id=contribution_id,
            object_type=EXTENSION_CONTRIBUTION_OBJECT_TYPE,
            state="MEASURED",
            command=command,
        )
        bound = contribution.bind_envelope(envelope)
        return TransitionApplication(
            resulting_envelopes=(envelope,),
            payload=self._application_payload(
                envelopes=(envelope,),
                contributions=(bound.to_record_dict(),),
            ),
        )


def _invocation_as_of(request: InvocationRequest) -> str:
    return request.as_of
