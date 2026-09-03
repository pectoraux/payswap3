"""The fulfillment compiler service bound to the transition kernel.

``FulfillmentCompiler`` owns exactly one real
:class:`~src.transition.engine.TransitionEngine` and one real
:class:`~src.transition.store.MemoryStateStore` per environment/domain and
registers the frozen ``Fulfillment`` command family
(``Compile/Recompile/Accept/Reject/Invalidate``) as internal
``compiler/fulfillment.<verb>`` command types (the W026 sibling convention:
command types are internal free-form strings):

```text
compiler/fulfillment.compile    → intent/fulfillment-compiled
compiler/fulfillment.recompile  → intent/fulfillment-recompiled
compiler/fulfillment.accept     → intent/fulfillment-accepted
compiler/fulfillment.reject     → intent/fulfillment-rejected
compiler/fulfillment.invalidate → intent/fulfillment-invalidated
```

Event types live in the frozen registry's ``intent`` namespace (there is no
``fulfillment`` namespace; fulfillment compiles an intent into a plan, so
``intent/fulfillment-*`` is the semantically correct protocol-visible
projection — documented in :mod:`src.compiler.contracts`).

Discipline (mirrors the IG-001 gate pattern):

* the kernel owns the protocol object lifecycle: the
  registry-listed ``payswap/fulfillment-plan/v1`` envelope, its version
  chain, the immutable event journal, idempotency convergence and the
  authorization decision (stage-4, exercised under the declared
  ``COMPILER_AUTHORITY_CLASS`` authority class);
* the compiler NEVER executes or posts anything: accepting a plan only
  advances the lifecycle state; the plan is a proposal (constitution
  invariants 3, 14, 18 — no second authority);
* every handler validates its whole step BEFORE the first mutation
  (validate-then-apply): a rejected or failed command leaves the kernel
  store, the journal and the tracked plans byte-identical;
* lifecycle command payloads carry the current sealed plan payload; the
  handler re-derives it through the trusted deserialization path (spec
  digest self-check + composite seal against the STORE envelope + pinned
  content equality with the tracked plan), so forged or spliced payloads
  fail closed inside the handler;
* compile/recompile payloads carry the full
  :class:`~src.compiler.inputs.CompilationInput`, re-verified through its
  trusted path (embedded intent/policy/slack envelope integrity) before
  any routing decision;
* determinism: no clock reads, no entropy; every instant is the
  command's declared ``requested_at`` / the request's declared ``as_of``.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from src.core.envelope import Provenance
from src.core.errors import CoreValidationError
from src.transition import (
    AuthorizationDecision,
    Command,
    ExpectedVersion,
    TransitionApplication,
    TransitionEngine,
)
from src.transition.engine import TransitionResult
from src.transition.payload import payload_to_json_value
from src.transition.store import MemoryStateStore

from .compile import compile_fulfillment
from .contracts import (
    COMPILER_ACCEPT_COMMAND,
    COMPILER_AUTHORITY_CLASS,
    COMPILER_COMPILE_COMMAND,
    COMPILER_EVENTS_BY_COMMAND,
    COMPILER_INVALIDATE_COMMAND,
    COMPILER_RECOMPILE_COMMAND,
    COMPILER_REJECT_COMMAND,
    FULFILLMENT_PLAN_OBJECT_TYPE,
)
from .inputs import CompilationInput, CompilationRequest, RouteHopOffer
from .plan import FulfillmentPlan, FulfillmentPlanSpec
from .seal import seal_composite

#: Provenance source of every compiler transition: the internal command
#: type itself (deterministic, no clock, no entropy).
COMPILER_PROVENANCE_SOURCE = "compiler/fulfillment"

_LIFECYCLE_PAYLOAD_FIELDS = frozenset({"plan", "integrity_hash", "reason"})
_COMPILE_PAYLOAD_FIELDS = frozenset({"type", "request", "intent", "policy", "slack", "hop_offers"})

#: Lifecycle commands that require an explicit non-empty reason.
_COMMANDS_REQUIRING_REASON = frozenset(
    {COMPILER_REJECT_COMMAND, COMPILER_INVALIDATE_COMMAND}
)


def _require_text(name: str, value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CoreValidationError(f"{name} must be a non-empty string")
    return value


def _payload_dict(command: Command) -> dict[str, Any]:
    decoded = payload_to_json_value(command.payload)
    if not isinstance(decoded, dict):
        raise CoreValidationError("compiler command payloads must be objects")
    return decoded


class FulfillmentCompiler:
    """One compiler environment: the real transition kernel plus the
    compiler's plan registry (the in-memory projection of sealed plans).

    The kernel store owns the durable ``payswap/fulfillment-plan/v1``
    envelopes (single envelope authority); the plan registry holds the
    sealed payloads side by side — the same split the IG-001 gate uses for
    the ledger. The compiler proposes plans only: no external effect and
    no ledger mutation ever happens here.
    """

    def __init__(
        self,
        *,
        environment_id: str,
        domain_id: str,
        authorized_actors: Iterable[str],
    ) -> None:
        self._environment_id = _require_text("compiler.environment_id", environment_id)
        self._domain_id = _require_text("compiler.domain_id", domain_id)
        actors = frozenset(authorized_actors)
        if not actors:
            raise CoreValidationError("the compiler requires at least one authorized actor")
        for actor in actors:
            _require_text("compiler.authorized_actor", actor)
        self._authorized_actors = actors
        self._store = MemoryStateStore()
        self._plans: dict[str, FulfillmentPlan] = {}
        self._engine = self._build_engine()

    # ------------------------------------------------------------------
    # read-only access to the real composed implementations
    # ------------------------------------------------------------------

    @property
    def environment_id(self) -> str:
        return self._environment_id

    @property
    def domain_id(self) -> str:
        return self._domain_id

    @property
    def authorized_actors(self) -> frozenset[str]:
        return self._authorized_actors

    @property
    def engine(self) -> TransitionEngine:
        """The real transition kernel driving this compiler."""
        return self._engine

    @property
    def store(self) -> MemoryStateStore:
        """The kernel's authoritative object store."""
        return self._store

    # ------------------------------------------------------------------
    # the frozen Fulfillment command family
    # ------------------------------------------------------------------

    def compile(
        self,
        *,
        plan_id: str,
        request: CompilationRequest,
        intent,
        policy,
        slack,
        hop_offers: Iterable[RouteHopOffer],
        command_id: str,
        idempotency_key: str,
        nonce: str,
        actor: str,
        requested_at: str | None = None,
    ) -> TransitionResult:
        """Compile an authorized intent into a new fulfillment plan.

        The command carries the absence precondition on the plan object
        (optimistic concurrency): compiling over an existing plan fails
        closed. All heavy validation runs inside the handler BEFORE any
        mutation, so a failed compile leaves zero kernel state.
        """
        payload = CompilationInput(
            request=request,
            intent=intent,
            policy=policy,
            slack=slack,
            hop_offers=tuple(hop_offers),
        )
        command = self._build_command(
            command_type=COMPILER_COMPILE_COMMAND,
            plan_id=plan_id,
            payload=payload.to_dict(),
            command_id=command_id,
            idempotency_key=idempotency_key,
            nonce=nonce,
            actor=actor,
            requested_at=requested_at if requested_at is not None else request.as_of,
            expected_versions=(ExpectedVersion(plan_id, 0),),
        )
        return self._engine.process(command)

    def recompile(
        self,
        *,
        plan_id: str,
        request: CompilationRequest,
        intent,
        policy,
        slack,
        hop_offers: Iterable[RouteHopOffer],
        command_id: str,
        idempotency_key: str,
        nonce: str,
        actor: str,
        requested_at: str | None = None,
        expected_version: int | None = None,
    ) -> TransitionResult:
        """Recompile an existing plan from a fresh compilation input.

        Without an explicit ``expected_version`` the command pins the
        plan's CURRENT store version (expected-version discipline); an
        explicit value is honored verbatim so stale recompiles fail
        closed with the kernel's ``version_conflict``.
        """
        current = self._require_plan(plan_id)
        if expected_version is None:
            expected_version = current.envelope.object_version
        if (
            not isinstance(expected_version, int)
            or isinstance(expected_version, bool)
            or expected_version < 1
        ):
            raise CoreValidationError(
                "expected_version must be a positive integer (0 is creation-only)"
            )
        payload = CompilationInput(
            request=request,
            intent=intent,
            policy=policy,
            slack=slack,
            hop_offers=tuple(hop_offers),
        )
        command = self._build_command(
            command_type=COMPILER_RECOMPILE_COMMAND,
            plan_id=plan_id,
            payload=payload.to_dict(),
            command_id=command_id,
            idempotency_key=idempotency_key,
            nonce=nonce,
            actor=actor,
            requested_at=requested_at if requested_at is not None else request.as_of,
            expected_versions=(ExpectedVersion(plan_id, expected_version),),
        )
        return self._engine.process(command)

    def accept_plan(
        self,
        *,
        plan_id: str,
        command_id: str,
        idempotency_key: str,
        nonce: str,
        actor: str,
        as_of: str,
    ) -> TransitionResult:
        """Accept a COMPILED plan (hands it to the execution domain).

        Accepting never executes anything and never posts to any ledger.
        """
        return self._lifecycle(
            command_type=COMPILER_ACCEPT_COMMAND,
            plan_id=plan_id,
            reason=None,
            command_id=command_id,
            idempotency_key=idempotency_key,
            nonce=nonce,
            actor=actor,
            as_of=as_of,
        )

    def reject_plan(
        self,
        *,
        plan_id: str,
        reason: str,
        command_id: str,
        idempotency_key: str,
        nonce: str,
        actor: str,
        as_of: str,
    ) -> TransitionResult:
        """Reject a COMPILED plan with an explicit reason (terminal)."""
        return self._lifecycle(
            command_type=COMPILER_REJECT_COMMAND,
            plan_id=plan_id,
            reason=reason,
            command_id=command_id,
            idempotency_key=idempotency_key,
            nonce=nonce,
            actor=actor,
            as_of=as_of,
        )

    def invalidate_plan(
        self,
        *,
        plan_id: str,
        reason: str,
        command_id: str,
        idempotency_key: str,
        nonce: str,
        actor: str,
        as_of: str,
    ) -> TransitionResult:
        """Invalidate a COMPILED or ACCEPTED plan (terminal)."""
        return self._lifecycle(
            command_type=COMPILER_INVALIDATE_COMMAND,
            plan_id=plan_id,
            reason=reason,
            command_id=command_id,
            idempotency_key=idempotency_key,
            nonce=nonce,
            actor=actor,
            as_of=as_of,
        )

    def plan(self, plan_id: str) -> FulfillmentPlan:
        """Rebuild the current fulfillment plan from the kernel state.

        The envelope comes from the kernel store (the single envelope
        authority); the sealed payload comes from the compiler's plan
        registry. The constructor re-verifies both integrities, so a
        divergent pair fails closed.
        """
        _require_text("plan_id", plan_id)
        envelope = self._store.get(plan_id)
        if envelope is None:
            raise CoreValidationError(f"no fulfillment plan {plan_id!r} exists in this compiler")
        tracked = self._plans.get(plan_id)
        if tracked is None:
            raise CoreValidationError(
                f"fulfillment plan {plan_id!r} has no tracked sealed payload; "
                "failing closed on registry divergence"
            )
        return FulfillmentPlan(
            envelope=envelope,
            spec=tracked.spec,
            integrity_hash=tracked.integrity_hash,
        )

    def current_version(self, plan_id: str) -> int:
        """Kernel-store version of one plan (0 when absent)."""
        _require_text("plan_id", plan_id)
        envelope = self._store.get(plan_id)
        return 0 if envelope is None else envelope.object_version

    # ------------------------------------------------------------------
    # kernel construction and shared plumbing
    # ------------------------------------------------------------------

    def _build_engine(self) -> TransitionEngine:
        engine = TransitionEngine(
            environment_id=self._environment_id,
            authorization=self._authorize,
            store=self._store,
        )
        engine.register(
            COMPILER_COMPILE_COMMAND, self._event_of(COMPILER_COMPILE_COMMAND),
            self._compile_handler,
        )
        engine.register(
            COMPILER_RECOMPILE_COMMAND, self._event_of(COMPILER_RECOMPILE_COMMAND),
            self._recompile_handler,
        )
        engine.register(
            COMPILER_ACCEPT_COMMAND, self._event_of(COMPILER_ACCEPT_COMMAND),
            self._lifecycle_handler(COMPILER_ACCEPT_COMMAND),
        )
        engine.register(
            COMPILER_REJECT_COMMAND, self._event_of(COMPILER_REJECT_COMMAND),
            self._lifecycle_handler(COMPILER_REJECT_COMMAND),
        )
        engine.register(
            COMPILER_INVALIDATE_COMMAND, self._event_of(COMPILER_INVALIDATE_COMMAND),
            self._lifecycle_handler(COMPILER_INVALIDATE_COMMAND),
        )
        return engine

    @staticmethod
    def _event_of(command_type: str) -> str:
        return COMPILER_EVENTS_BY_COMMAND[command_type]

    def _authorize(self, command: Command, view) -> AuthorizationDecision:
        if command.actor in self._authorized_actors:
            return AuthorizationDecision(
                granted=True, authority=COMPILER_AUTHORITY_CLASS, reason=None
            )
        return AuthorizationDecision(
            granted=False,
            authority=None,
            reason=f"actor {command.actor} is not authorized to compile in environment "
            f"{self._environment_id}",
        )

    def _build_command(
        self,
        *,
        command_type: str,
        plan_id: str,
        payload: Mapping[str, Any],
        command_id: str,
        idempotency_key: str,
        nonce: str,
        actor: str,
        requested_at: str,
        expected_versions: tuple[ExpectedVersion, ...],
    ) -> Command:
        return Command.build(
            command_id=command_id,
            command_type=command_type,
            actor=actor,
            target_refs=(plan_id,),
            payload=dict(payload),
            environment_id=self._environment_id,
            domain_id=self._domain_id,
            expected_versions=expected_versions,
            idempotency_key=idempotency_key,
            nonce=nonce,
            requested_at=requested_at,
        )

    def _provenance(self, command: Command) -> Provenance:
        return Provenance(
            issuer=command.actor,
            source=COMPILER_PROVENANCE_SOURCE,
            recorded_at=command.requested_at,
        )

    def _require_plan(self, plan_id: str) -> FulfillmentPlan:
        _require_text("plan_id", plan_id)
        tracked = self._plans.get(plan_id)
        if tracked is None:
            raise CoreValidationError(f"no fulfillment plan {plan_id!r} exists in this compiler")
        return tracked

    # ------------------------------------------------------------------
    # transition handlers (validate-then-apply; failures leave zero state)
    # ------------------------------------------------------------------

    def _compile_handler(self, command: Command, view) -> TransitionApplication:
        plan_id = self._single_target(command)
        if view.get(plan_id) is not None:
            raise CoreValidationError(
                f"plan object {plan_id} already exists; compile requires its absence "
                "(use the recompile command to replace a plan)"
            )
        payload = _payload_dict(command)
        if set(payload) != _COMPILE_PAYLOAD_FIELDS:
            raise CoreValidationError(
                "compile payloads must be a canonical compilation input object"
            )
        compilation_input = CompilationInput.from_dict(payload)
        spec = compile_fulfillment(
            request=compilation_input.request,
            intent=compilation_input.intent,
            policy=compilation_input.policy,
            slack=compilation_input.slack,
            hop_offers=compilation_input.hop_offers,
        )
        plan = FulfillmentPlan.build(
            object_id=plan_id,
            environment_id=command.environment_id,
            domain_id=command.domain_id,
            spec=spec,
            provenance=self._provenance(command),
            causation_id=command.command_id,
            correlation_id=command.correlation_id,
        )
        self._plans[plan_id] = plan
        return self._application(plan, reason=None)

    def _recompile_handler(self, command: Command, view) -> TransitionApplication:
        plan_id = self._single_target(command)
        envelope = view.get(plan_id)
        if envelope is None:
            raise CoreValidationError(
                f"recompile requires an existing plan; {plan_id!r} does not exist"
            )
        if envelope.object_type != FULFILLMENT_PLAN_OBJECT_TYPE:
            raise CoreValidationError(
                f"recompile target {plan_id!r} is not a {FULFILLMENT_PLAN_OBJECT_TYPE}"
            )
        payload = _payload_dict(command)
        if set(payload) != _COMPILE_PAYLOAD_FIELDS:
            raise CoreValidationError(
                "recompile payloads must be a canonical compilation input object"
            )
        compilation_input = CompilationInput.from_dict(payload)
        spec = compile_fulfillment(
            request=compilation_input.request,
            intent=compilation_input.intent,
            policy=compilation_input.policy,
            slack=compilation_input.slack,
            hop_offers=compilation_input.hop_offers,
        )
        plan = FulfillmentPlan.advance_version(
            envelope,
            spec,
            command="recompile",
            provenance=self._provenance(command),
        )
        self._plans[plan_id] = plan
        return self._application(plan, reason=None)

    def _lifecycle_handler(self, command_type: str):
        command_name = command_type.rpartition(".")[2]

        def handler(command: Command, view) -> TransitionApplication:
            plan_id = self._single_target(command)
            envelope = view.get(plan_id)
            if envelope is None:
                raise CoreValidationError(
                    f"{command_name} requires an existing plan; {plan_id!r} does not exist"
                )
            if envelope.object_type != FULFILLMENT_PLAN_OBJECT_TYPE:
                raise CoreValidationError(
                    f"{command_name} target {plan_id!r} is not a "
                    f"{FULFILLMENT_PLAN_OBJECT_TYPE}"
                )
            payload = _payload_dict(command)
            if set(payload) != _LIFECYCLE_PAYLOAD_FIELDS:
                raise CoreValidationError(
                    f"{command_name} payload fields must be canonical "
                    f"{sorted(_LIFECYCLE_PAYLOAD_FIELDS)}"
                )
            reason = payload["reason"]
            if command_type in _COMMANDS_REQUIRING_REASON:
                _require_text(f"{command_name} reason", reason)
            elif reason is not None:
                _require_text(f"{command_name} reason", reason)
            spec = FulfillmentPlanSpec.from_dict(payload["plan"])
            # The composite seal must bind the payload spec to the STORE
            # envelope at its current version (integrity_hash is the
            # compiler domain seal, not transport metadata).
            expected_seal = seal_composite(envelope, spec)
            if payload["integrity_hash"] != expected_seal:
                raise CoreValidationError(
                    f"{command_name} payload integrity hash does not seal the plan "
                    f"{plan_id} against its current envelope version "
                    f"{envelope.object_version}; failing closed on a forged payload"
                )
            # The lifecycle commands never change plan content: the payload
            # spec must be exactly the tracked current spec (pinned
            # content; the seal alone cannot detect a swapped-but-sealed
            # payload).
            tracked = self._plans.get(plan_id)
            if tracked is None:
                raise CoreValidationError(
                    f"{command_name} requires a tracked plan payload for {plan_id!r}; "
                    "failing closed on registry divergence"
                )
            if payload["plan"] != tracked.spec.to_dict():
                raise CoreValidationError(
                    f"{command_name} cannot replace the plan content; lifecycle "
                    "commands advance state only (use recompile to change the spec)"
                )
            plan = FulfillmentPlan.advance_version(
                envelope,
                spec,
                command=command_name,
                provenance=self._provenance(command),
            )
            self._plans[plan_id] = plan
            return self._application(plan, reason=reason)

        return handler

    def _application(
        self, plan: FulfillmentPlan, *, reason: str | None
    ) -> TransitionApplication:
        return TransitionApplication(
            resulting_envelopes=(plan.envelope,),
            payload={
                "plan": plan.spec.to_dict(),
                "integrity_hash": plan.integrity_hash,
                "reason": reason,
            },
        )

    def _single_target(self, command: Command) -> str:
        if len(command.target_refs) != 1:
            raise CoreValidationError(
                "compiler commands must target exactly one fulfillment plan object"
            )
        return command.target_refs[0]

    # ------------------------------------------------------------------
    # convenience path used by the lifecycle wrappers
    # ------------------------------------------------------------------

    def _lifecycle(
        self,
        *,
        command_type: str,
        plan_id: str,
        reason: str | None,
        command_id: str,
        idempotency_key: str,
        nonce: str,
        actor: str,
        as_of: str,
    ) -> TransitionResult:
        plan = self._require_plan(plan_id)
        command = self._build_command(
            command_type=command_type,
            plan_id=plan_id,
            payload={
                "plan": plan.spec.to_dict(),
                "integrity_hash": plan.integrity_hash,
                "reason": reason,
            },
            command_id=command_id,
            idempotency_key=idempotency_key,
            nonce=nonce,
            actor=actor,
            requested_at=as_of,
            expected_versions=(),
        )
        return self._engine.process(command)
