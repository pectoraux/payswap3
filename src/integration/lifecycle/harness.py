"""The IG-002 composition harness: the fulfillment lifecycle gate.

:class:`FulfillmentLifecycleGate` binds the REAL merged engines of the
canonical financial chain — the fulfillment compiler (WORK-013), the
execution engine with its typed adapter ports (WORK-014), the clearing
engine (WORK-015) and the settlement engine (WORK-016) — into ONE
environment and drives the frozen lifecycle through their public
command APIs only:

```text
intent (real intent-domain records)
  → fulfillment compilation        (real FulfillmentCompiler kernel)
  → execution plan                 (real ExecutionEngine kernel)
  → external effect request        (typed idempotency + authorization + HELD hold)
  → external effect submission     (the single rail port call, in-transition)
  → rail acknowledgment / result   (real rails through the typed ports)
  → clearing recognition           (facts derived from the sealed result)
  → obligation validation / due    (real clearing lifecycle)
  → netting                        (real statement + net obligations)
  → settlement batch               (real settlement lifecycle)
  → reconciliation                 (leg-bound OBSERVED rail evidence)
  → finality certificate           (FINALITY-class claims only, SETTLED legs only)
  → obligation resolution          (digest-bound discharge evidence)
```

Composition discipline (fail closed, one authority per concept):

* every stage runs through the OWNING domain engine's public command
  surface; the gate owns only the cross-domain translation (step →
  payment-leg evidence, execution observation → settlement leg
  observation, discharge evidence → clearing resolution);
* every stage snapshot-digests the composed state before and after:
  a rejected or duplicate stage must leave the composed state
  byte-identical (the gate fails closed on divergence), and an accepted
  stage is followed by the full cross-domain invariant battery;
* the stage journal is append-only and chained (``state_after`` of one
  entry equals ``state_before`` of the next);
* adapter rails are injected as :class:`src.execution.adapters.AdapterBinding`
  mappings — the gate itself is rail-agnostic and never touches a
  provider directly.
"""

from __future__ import annotations

from typing import Any, Callable, Iterable, Mapping

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.execution import ExecutionEngine
from src.clearing import ClearingEngine
from src.compiler import FulfillmentCompiler
from src.settlement import SettlementEngine

from .contracts import (
    CLEARING_DOMAIN_SUFFIX,
    COMPILER_DOMAIN_SUFFIX,
    DEFAULT_AUTHORIZED_ACTORS,
    DEFAULT_GATE_ACTOR,
    DEFAULT_STEP_MAX_ATTEMPTS,
    EXECUTION_DOMAIN_SUFFIX,
    GATE_AUTHORITY_CLASS,
    GATE_PROVENANCE_SOURCE,
    PAYMENT_SUBMIT_EFFECT_TYPE,
    SETTLEMENT_DOMAIN_SUFFIX,
    validate_lifecycle_gate_id,
)
from .invariants import verify_lifecycle_invariants
from .world import LifecycleWorld, build_declared_world  # noqa: F401 (re-export)


def _require_text(name: str, value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CoreValidationError(f"{name} must be a non-empty string")
    return value


class FulfillmentLifecycleGate:
    """One IG-002 composed environment: compiler + execution + clearing
    + settlement, over one environment id and derived per-domain ids."""

    def __init__(
        self,
        *,
        environment_id: str,
        domain_id: str,
        bindings: Mapping[str, Any],
        gate_id: str = "IG-002",
        authorized_actors: Iterable[str] = DEFAULT_AUTHORIZED_ACTORS,
        actor: str = DEFAULT_GATE_ACTOR,
    ) -> None:
        validate_lifecycle_gate_id(gate_id)
        self._gate_id = gate_id
        self._environment_id = _require_text("gate.environment_id", environment_id)
        self._domain_id = _require_text("gate.domain_id", domain_id)
        self._actor = _require_text("gate.actor", actor)
        actors = frozenset(authorized_actors) | {actor}
        for gate_actor in actors:
            _require_text("gate.authorized_actor", gate_actor)
        self._authorized_actors = actors
        if not isinstance(bindings, Mapping) or not bindings:
            raise CoreValidationError(
                "the lifecycle gate requires at least one typed adapter binding"
            )
        self._bindings = dict(bindings)
        self._compiler = FulfillmentCompiler(
            environment_id=self._environment_id,
            domain_id=f"{self._domain_id}/{COMPILER_DOMAIN_SUFFIX}",
            authorized_actors=actors,
        )
        self._execution = ExecutionEngine(
            environment_id=self._environment_id,
            domain_id=f"{self._domain_id}/{EXECUTION_DOMAIN_SUFFIX}",
            bindings=self._bindings,
            actor=actor,
            authorized_actors=actors,
        )
        self._clearing = ClearingEngine(
            environment_id=self._environment_id,
            domain_id=f"{self._domain_id}/{CLEARING_DOMAIN_SUFFIX}",
        )
        self._settlement = SettlementEngine(
            environment_id=self._environment_id,
            domain_id=f"{self._domain_id}/{SETTLEMENT_DOMAIN_SUFFIX}",
        )
        self._world: LifecycleWorld | None = None
        self._worlds: list[LifecycleWorld] = []
        self._plans: list[Any] = []
        self._plan_hops: dict[str, list[dict[str, Any]]] = {}
        self._execution_plans: list[str] = []
        self._stage_journal: list[dict[str, Any]] = []
        self._last_invariant_checks: tuple[str, ...] = ()

    # ------------------------------------------------------------------
    # read-only access to the real composed implementations
    # ------------------------------------------------------------------

    @property
    def gate_id(self) -> str:
        return self._gate_id

    @property
    def environment_id(self) -> str:
        return self._environment_id

    @property
    def domain_id(self) -> str:
        return self._domain_id

    @property
    def actor(self) -> str:
        return self._actor

    @property
    def authorized_actors(self) -> frozenset[str]:
        return self._authorized_actors

    @property
    def compiler(self) -> FulfillmentCompiler:
        return self._compiler

    @property
    def execution(self) -> ExecutionEngine:
        return self._execution

    @property
    def clearing(self) -> ClearingEngine:
        return self._clearing

    @property
    def settlement(self) -> SettlementEngine:
        return self._settlement

    @property
    def world(self) -> LifecycleWorld:
        if self._world is None:
            raise CoreValidationError(
                "no world has been compiled in this gate yet"
            )
        return self._world

    @property
    def worlds(self) -> tuple[LifecycleWorld, ...]:
        return tuple(self._worlds)

    @property
    def plans(self) -> tuple[Any, ...]:
        return tuple(self._plans)

    @property
    def execution_plans(self) -> tuple[str, ...]:
        return tuple(self._execution_plans)

    @property
    def stage_journal(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._stage_journal)

    @property
    def bindings(self) -> Mapping[str, Any]:
        """The typed adapter bindings this gate composes (read-only)."""
        return dict(self._bindings)

    @property
    def last_invariant_checks(self) -> tuple[str, ...]:
        """The checks of the most recent invariant verification."""
        return tuple(self._last_invariant_checks)

    # ------------------------------------------------------------------
    # composed state projection
    # ------------------------------------------------------------------

    def _composed_state(self) -> dict[str, Any]:
        return {
            "compiler": [plan.to_dict() for plan in self._plans],
            "execution": _committed_snapshot(self._execution),
            "clearing": _committed_snapshot(self._clearing),
            "settlement": _committed_snapshot(self._settlement),
        }

    def composed_digest(self) -> str:
        """Digest over the whole composed lifecycle state."""
        return canonical_sha256(
            {
                "gate_id": self._gate_id,
                "environment_id": self._environment_id,
                "domain_id": self._domain_id,
                "state": self._composed_state(),
            }
        )

    def snapshot(self) -> dict[str, Any]:
        """Canonical, byte-stable snapshot of the composed gate state."""
        return {
            "schema_version": 1,
            "gate_id": self._gate_id,
            "environment_id": self._environment_id,
            "domain_id": self._domain_id,
            "actor": self._actor,
            "authorized_actors": sorted(self._authorized_actors),
            "adapter_ids": sorted(self._bindings),
            "worlds": [world.to_dict() for world in self._worlds],
            "plans": [plan.to_dict() for plan in self._plans],
            "execution_plans": list(self._execution_plans),
            "plan_hops": dict(self._plan_hops),
            "stage_journal": [dict(entry) for entry in self._stage_journal],
            "execution_journal": [
                _journal_entry_to_dict(entry) for entry in self._execution.journal()
            ],
            "clearing_journal": [
                _journal_entry_to_dict(entry) for entry in self._clearing.journal
            ],
            "settlement_journal": [
                _journal_entry_to_dict(entry) for entry in self._settlement.journal
            ],
            "composed_digest": self.composed_digest(),
        }

    # ------------------------------------------------------------------
    # the stage driver: invariant verification + no-mutation guard
    # ------------------------------------------------------------------

    def _drive(
        self,
        *,
        domain: str,
        stage: str,
        command_id: str,
        requested_at: str,
        driver: Callable[[], Any],
        post_accept: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        before = self.composed_digest()
        entry = {
            "stage": stage,
            "domain": domain,
            "command_id": command_id,
            "requested_at": requested_at,
            "outcome": "accepted",
            "state_before": before,
            "state_after": before,
        }
        try:
            transition = driver()
        except CoreValidationError:
            after = self.composed_digest()
            if after != before:
                entry["state_after"] = after
                self._stage_journal.append(entry)
                raise CoreValidationError(
                    f"stage {stage} ({command_id}) failed closed but the composed "
                    "state mutated; failing on composed-state divergence"
                )
            entry["outcome"] = "rejected"
            self._stage_journal.append(entry)
            raise
        outcome = _transition_outcome(transition)
        if outcome == "accepted" and post_accept is not None:
            # Gate-level bookkeeping mutates INSIDE the stage window, so
            # the recorded state_after digest reflects the full post-stage
            # composed state (the journal stays chained).
            post_accept()
        after = self.composed_digest()
        entry["state_after"] = after
        entry["outcome"] = outcome
        if outcome == "accepted":
            self._last_invariant_checks = tuple(
                verify_lifecycle_invariants(self)
            )
        else:
            if after != before:
                self._stage_journal.append(entry)
                raise CoreValidationError(
                    f"stage {stage} ({command_id}) returned {outcome} but the "
                    "composed state mutated; failing on composed-state divergence"
                )
        self._stage_journal.append(entry)
        return entry

    # ------------------------------------------------------------------
    # lifecycle stages
    # ------------------------------------------------------------------

    def stage_compile(
        self,
        world: LifecycleWorld,
        *,
        plan_id: str,
        command_id: str,
        idempotency_key: str,
        nonce: str,
        requested_at: str | None = None,
    ) -> dict[str, Any]:
        """Compile one declared world into a fulfillment plan (real kernel)."""
        from src.compiler import CompilationRequest

        request = CompilationRequest(
            environment_id=world.environment_id,
            domain_id=world.domain_id,
            as_of=world.as_of,
            required_jurisdiction=world.jurisdiction,
            minimum_authority_tier=world.minimum_authority_tier,
        )

        def driver() -> Any:
            return self._compiler.compile(
                plan_id=plan_id,
                request=request,
                intent=world.intent,
                policy=world.policy,
                slack=world.slack,
                hop_offers=world.hops,
                command_id=command_id,
                idempotency_key=idempotency_key,
                nonce=nonce,
                actor=self._actor,
                requested_at=requested_at,
            )

        def post_accept() -> None:
            self._world = world
            self._worlds.append(world)
            self._plans.append(self._compiler.plan(plan_id))

        return self._drive(
            domain="compiler",
            stage="compile",
            command_id=command_id,
            requested_at=requested_at or request.as_of,
            driver=driver,
            post_accept=post_accept,
        )

    def stage_accept_plan(
        self, plan_id: str, *, command_id: str, idempotency_key: str, nonce: str, as_of: str
    ) -> dict[str, Any]:
        """Accept the compiled plan (the compiler's handoff boundary)."""

        def driver() -> Any:
            return self._compiler.accept_plan(
                plan_id=plan_id,
                command_id=command_id,
                idempotency_key=idempotency_key,
                nonce=nonce,
                actor=self._actor,
                as_of=as_of,
            )

        def post_accept() -> None:
            self._plans[-1] = self._compiler.plan(plan_id)

        return self._drive(
            domain="compiler",
            stage="accept-plan",
            command_id=command_id,
            requested_at=as_of,
            driver=driver,
            post_accept=post_accept,
        )

    def _plan_steps(self, plan: Any) -> list[dict[str, Any]]:
        """Derive the execution steps from a compiled plan's payments."""
        steps: list[dict[str, Any]] = []
        hop_records: list[dict[str, Any]] = []
        world = self.world
        plan_id = plan.envelope.object_id
        execution_plan_id = f"execution/{plan_id}"
        position = 0
        for payment in plan.spec.payments:
            for hop in payment.route_hops:
                position += 1
                step_id = f"{execution_plan_id}/step/{position}"
                currency = hop.source_asset[len("asset/"):]
                steps.append(
                    {
                        "step_id": step_id,
                        "adapter_id": _adapter_for_step(self._bindings, hop),
                        "effect_type": PAYMENT_SUBMIT_EFFECT_TYPE,
                        "payload": {
                            "currency": currency,
                            "amount_value": hop.input_value,
                            "amount_scale": hop.source_scale,
                            "destination": world.destination,
                        },
                        "reservation_ref": hop.reservation_id,
                        "max_attempts": DEFAULT_STEP_MAX_ATTEMPTS,
                    }
                )
                hop_records.append(
                    {
                        "step_id": step_id,
                        "hop_id": hop.hop_id,
                        "payment_leg": dict(world.payment_legs[hop.hop_id]),
                    }
                )
        if not steps:
            raise CoreValidationError(
                f"plan {plan_id} compiled without routable payments"
            )
        return steps, hop_records, execution_plan_id

    def stage_create_execution_plan(
        self, plan_id: str, *, command_id: str, requested_at: str
    ) -> dict[str, Any]:
        """Create the execution plan (steps derived from the plan's hops)."""
        plan = self._compiler.plan(plan_id)
        steps, hop_records, execution_plan_id = self._plan_steps(plan)

        def driver() -> Any:
            return self._execution.create_plan(
                command_id=command_id,
                requested_at=requested_at,
                plan_id=execution_plan_id,
                steps=steps,
                source_ref=plan_id,
                summary=f"IG-002 execution of {plan_id}",
            )

        def post_accept() -> None:
            self._execution_plans.append(execution_plan_id)
            self._plan_hops[execution_plan_id] = hop_records

        return self._drive(
            domain="execution",
            stage="create-execution-plan",
            command_id=command_id,
            requested_at=requested_at,
            driver=driver,
            post_accept=post_accept,
        )

    def stage_authorize_execution_plan(
        self, execution_plan_id: str, *, command_id: str, requested_at: str
    ) -> dict[str, Any]:
        """Authorize the execution plan with the world's real safety gates."""
        hop_records = self._plan_hops[execution_plan_id]
        first_hop_id = hop_records[0]["hop_id"]
        world = self.world

        def driver() -> Any:
            return self._execution.authorize_plan(
                command_id=command_id,
                requested_at=requested_at,
                plan_id=execution_plan_id,
                authority_class=GATE_AUTHORITY_CLASS,
                fraud_decision=world.fraud_gates[first_hop_id],
                compliance_assessment=world.compliance_gates[first_hop_id],
            )

        return self._drive(
            domain="execution",
            stage="authorize-execution-plan",
            command_id=command_id,
            requested_at=requested_at,
            driver=driver,
        )

    def stage_start_execution_plan(
        self, execution_plan_id: str, *, command_id: str, requested_at: str
    ) -> dict[str, Any]:
        def driver() -> Any:
            return self._execution.start_plan(
                command_id=command_id,
                requested_at=requested_at,
                plan_id=execution_plan_id,
            )

        return self._drive(
            domain="execution",
            stage="start-execution-plan",
            command_id=command_id,
            requested_at=requested_at,
            driver=driver,
        )

    def stage_request_effect(
        self,
        step_id: str,
        *,
        idempotency_key: str,
        command_id: str,
        requested_at: str,
        world: LifecycleWorld | None = None,
    ) -> dict[str, Any]:
        """Declare the idempotent external effect request (typed gates)."""
        from src.execution import EffectAuthorization

        source_world = world if world is not None else self.world
        authorization = EffectAuthorization(
            authorizer=source_world.authorization["authorizer"],
            authority_class=source_world.authorization["authority_class"],
            authorized_types=frozenset(
                source_world.authorization["authorized_types"]
            ),
            valid_from=source_world.authorization["valid_from"],
            valid_until=source_world.authorization["valid_until"],
        )
        step = self._execution.step(step_id)
        hold = source_world.hold_gate_for(step.spec.reservation_ref)

        def driver() -> Any:
            return self._execution.request_effect(
                command_id=command_id,
                requested_at=requested_at,
                step_id=step_id,
                idempotency_key=idempotency_key,
                authorization=authorization,
                hold=hold,
            )

        return self._drive(
            domain="execution",
            stage="request-effect",
            command_id=command_id,
            requested_at=requested_at,
            driver=driver,
        )

    def stage_submit_effect(
        self, step_id: str, *, command_id: str, requested_at: str
    ) -> dict[str, Any]:
        """Submit the effect to the rail — the single real port call."""

        def driver() -> Any:
            return self._execution.submit_step(
                command_id=command_id,
                requested_at=requested_at,
                step_id=step_id,
            )

        return self._drive(
            domain="execution",
            stage="submit-effect",
            command_id=command_id,
            requested_at=requested_at,
            driver=driver,
        )

    def stage_acknowledge_effect(
        self, step_id: str, *, native_reference: str, command_id: str, requested_at: str
    ) -> dict[str, Any]:
        def driver() -> Any:
            return self._execution.acknowledge_step(
                command_id=command_id,
                requested_at=requested_at,
                step_id=step_id,
                native_reference=native_reference,
            )

        return self._drive(
            domain="execution",
            stage="acknowledge-effect",
            command_id=command_id,
            requested_at=requested_at,
            driver=driver,
        )

    def stage_observe_effect_result(
        self,
        step_id: str,
        *,
        outcome: str,
        native_reference: str | None,
        observed_at: str,
        command_id: str,
        payment_leg: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Record the rail's outcome with the canonical payment-leg evidence."""
        leg = dict(payment_leg) if payment_leg is not None else self._payment_leg(step_id)

        def driver() -> Any:
            return self._execution.record_effect_result(
                command_id=command_id,
                requested_at=observed_at,
                step_id=step_id,
                outcome=outcome,
                native_reference=native_reference,
                observed_at=observed_at,
                detail=leg,
            )

        return self._drive(
            domain="execution",
            stage="observe-effect-result",
            command_id=command_id,
            requested_at=observed_at,
            driver=driver,
        )

    def stage_complete_step(
        self, step_id: str, *, command_id: str, requested_at: str
    ) -> dict[str, Any]:
        def driver() -> Any:
            return self._execution.complete_step(
                command_id=command_id,
                requested_at=requested_at,
                step_id=step_id,
            )

        return self._drive(
            domain="execution",
            stage="complete-step",
            command_id=command_id,
            requested_at=requested_at,
            driver=driver,
        )

    def stage_fail_step(
        self, step_id: str, *, reason: str, command_id: str, requested_at: str
    ) -> dict[str, Any]:
        def driver() -> Any:
            return self._execution.fail_step(
                command_id=command_id,
                requested_at=requested_at,
                step_id=step_id,
                reason=reason,
            )

        return self._drive(
            domain="execution",
            stage="fail-step",
            command_id=command_id,
            requested_at=requested_at,
            driver=driver,
        )

    def stage_reconcile_effect(
        self, step_id: str, *, command_id: str, requested_at: str
    ) -> dict[str, Any]:
        """Query the rail through the public reconciliation port."""

        def driver() -> Any:
            return self._execution.reconcile_step(
                command_id=command_id,
                requested_at=requested_at,
                step_id=step_id,
            )

        return self._drive(
            domain="execution",
            stage="reconcile-effect",
            command_id=command_id,
            requested_at=requested_at,
            driver=driver,
        )

    def stage_retry_step(
        self, step_id: str, *, reason: str, command_id: str, requested_at: str
    ) -> dict[str, Any]:
        def driver() -> Any:
            return self._execution.retry_step(
                command_id=command_id,
                requested_at=requested_at,
                step_id=step_id,
                reason=reason,
            )

        return self._drive(
            domain="execution",
            stage="retry-step",
            command_id=command_id,
            requested_at=requested_at,
            driver=driver,
        )

    def stage_record_payment_status(
        self, step_id: str, *, native_code: str, command_id: str, requested_at: str
    ) -> dict[str, Any]:
        """Record the canonical payment status through the status map."""

        def driver() -> Any:
            return self._execution.record_status(
                command_id=command_id,
                requested_at=requested_at,
                step_id=step_id,
                native_code=native_code,
            )

        return self._drive(
            domain="execution",
            stage="record-payment-status",
            command_id=command_id,
            requested_at=requested_at,
            driver=driver,
        )

    def stage_record_finality_claim(
        self, step_id: str, *, claim: str, native_reference: str, command_id: str, requested_at: str
    ) -> dict[str, Any]:
        """Record the rail's finality CLAIM (evidence only — never truth)."""

        def driver() -> Any:
            return self._execution.record_finality(
                command_id=command_id,
                requested_at=requested_at,
                step_id=step_id,
                claim=claim,
                native_reference=native_reference,
            )

        return self._drive(
            domain="execution",
            stage="record-finality-claim",
            command_id=command_id,
            requested_at=requested_at,
            driver=driver,
        )

    # -- clearing stretch ------------------------------------------------

    def stage_open_clearing_cycle(
        self, cycle_id: str, *, opens_at: str, closes_at: str, command_id: str, requested_at: str, description: str = ""
    ) -> dict[str, Any]:
        def driver() -> Any:
            return self._clearing.create_cycle(
                command_id=command_id,
                requested_at=requested_at,
                cycle_id=cycle_id,
                opens_at=opens_at,
                closes_at=closes_at,
                description=description,
            )

        return self._drive(
            domain="clearing",
            stage="open-clearing-cycle",
            command_id=command_id,
            requested_at=requested_at,
            driver=driver,
        )

    def step_effect_result(self, step_id: str) -> Any:
        """The step's recorded effect result (fail closed when absent)."""
        from src.execution import EffectResult

        results = [
            record
            for record in self._execution.objects()
            if isinstance(record, EffectResult)
            and record.spec.step_id == step_id
        ]
        if not results:
            raise CoreValidationError(
                f"step {step_id} has no recorded effect result; obligations are "
                "recognized only from recorded execution evidence"
            )
        return results[-1]

    def stage_recognize_obligation(
        self,
        *,
        cycle_id: str,
        step_id: str,
        due_from: str,
        due_until: str,
        command_id: str,
        requested_at: str,
    ) -> dict[str, Any]:
        """Recognize the obligation from the step's sealed execution evidence."""
        record = self.step_effect_result(step_id)
        if record.spec.outcome.value != "SUCCEEDED":
            raise CoreValidationError(
                f"step {step_id}'s effect result outcome is "
                f"{record.spec.outcome.value}; obligations are recognized only "
                "from SUCCEEDED execution evidence"
            )
        effect_result = record.to_dict()

        def driver() -> Any:
            return self._clearing.recognize_obligation(
                command_id=command_id,
                requested_at=requested_at,
                cycle_id=cycle_id,
                effect_result=effect_result,
                due_from=due_from,
                due_until=due_until,
            )

        return self._drive(
            domain="clearing",
            stage="recognize-obligation",
            command_id=command_id,
            requested_at=requested_at,
            driver=driver,
        )

    def stage_validate_obligation(
        self, obligation_id: str, *, command_id: str, requested_at: str
    ) -> dict[str, Any]:
        def driver() -> Any:
            return self._clearing.validate_obligation(
                command_id=command_id,
                requested_at=requested_at,
                obligation_id=obligation_id,
            )

        return self._drive(
            domain="clearing",
            stage="validate-obligation",
            command_id=command_id,
            requested_at=requested_at,
            driver=driver,
        )

    def stage_mark_due_obligation(
        self, obligation_id: str, *, command_id: str, requested_at: str
    ) -> dict[str, Any]:
        def driver() -> Any:
            return self._clearing.mark_due_obligation(
                command_id=command_id,
                requested_at=requested_at,
                obligation_id=obligation_id,
            )

        return self._drive(
            domain="clearing",
            stage="mark-due-obligation",
            command_id=command_id,
            requested_at=requested_at,
            driver=driver,
        )

    def stage_validate_cycle(
        self, cycle_id: str, *, command_id: str, requested_at: str
    ) -> dict[str, Any]:
        def driver() -> Any:
            return self._clearing.validate_cycle(
                command_id=command_id,
                requested_at=requested_at,
                cycle_id=cycle_id,
            )

        return self._drive(
            domain="clearing",
            stage="validate-cycle",
            command_id=command_id,
            requested_at=requested_at,
            driver=driver,
        )

    def stage_finalize_cycle(
        self, cycle_id: str, *, command_id: str, requested_at: str
    ) -> dict[str, Any]:
        def driver() -> Any:
            return self._clearing.finalize_cycle(
                command_id=command_id,
                requested_at=requested_at,
                cycle_id=cycle_id,
            )

        return self._drive(
            domain="clearing",
            stage="finalize-cycle",
            command_id=command_id,
            requested_at=requested_at,
            driver=driver,
        )

    def stage_net_obligations(
        self,
        netting_id: str,
        obligation_ids: Iterable[str],
        *,
        mode: str = "BILATERAL",
        due_from: str,
        due_until: str,
        command_prefix: str,
        requested_at: str,
    ) -> dict[str, Any]:
        """Create, calculate and finalize one netting cycle over the members."""
        entries: list[dict[str, Any]] = []

        def create() -> Any:
            return self._clearing.create_netting(
                command_id=f"{command_prefix}-create",
                requested_at=requested_at,
                netting_id=netting_id,
                mode=mode,
                due_from=due_from,
                due_until=due_until,
            )

        entries.append(
            self._drive(
                domain="clearing",
                stage="netting-create",
                command_id=f"{command_prefix}-create",
                requested_at=requested_at,
                driver=create,
            )
        )
        for index, obligation_id in enumerate(obligation_ids, start=1):
            def add(obligation_id: str = obligation_id, index: int = index) -> Any:
                return self._clearing.add_netting_member(
                    command_id=f"{command_prefix}-add-{index}",
                    requested_at=requested_at,
                    netting_id=netting_id,
                    obligation_id=obligation_id,
                )

            entries.append(
                self._drive(
                    domain="clearing",
                    stage="netting-add",
                    command_id=f"{command_prefix}-add-{index}",
                    requested_at=requested_at,
                    driver=add,
                )
            )

        def calculate() -> Any:
            return self._clearing.calculate_netting(
                command_id=f"{command_prefix}-calculate",
                requested_at=requested_at,
                netting_id=netting_id,
            )

        entries.append(
            self._drive(
                domain="clearing",
                stage="netting-calculate",
                command_id=f"{command_prefix}-calculate",
                requested_at=requested_at,
                driver=calculate,
            )
        )

        def finalize() -> Any:
            return self._clearing.finalize_netting(
                command_id=f"{command_prefix}-finalize",
                requested_at=requested_at,
                netting_id=netting_id,
            )

        entries.append(
            self._drive(
                domain="clearing",
                stage="netting-finalize",
                command_id=f"{command_prefix}-finalize",
                requested_at=requested_at,
                driver=finalize,
            )
        )
        return {"stage": "net-obligations", "entries": entries}

    # -- settlement stretch ----------------------------------------------

    def stage_settle(
        self,
        settlement_id: str,
        obligation_ids: Iterable[str],
        *,
        submit_by: str,
        settle_by: str,
        command_prefix: str,
        requested_at: str,
    ) -> dict[str, Any]:
        """Create, authorize and submit one settlement batch."""
        obligations = [
            self._clearing.obligation(obligation_id).to_dict()
            for obligation_id in obligation_ids
        ]

        def create() -> Any:
            return self._settlement.create_settlement(
                command_id=f"{command_prefix}-create",
                requested_at=requested_at,
                settlement_id=settlement_id,
                obligations=obligations,
                submit_by=submit_by,
                settle_by=settle_by,
            )

        self._drive(
            domain="settlement",
            stage="settlement-create",
            command_id=f"{command_prefix}-create",
            requested_at=requested_at,
            driver=create,
        )

        def authorize() -> Any:
            return self._settlement.authorize_settlement(
                command_id=f"{command_prefix}-authorize",
                requested_at=requested_at,
                settlement_id=settlement_id,
            )

        self._drive(
            domain="settlement",
            stage="settlement-authorize",
            command_id=f"{command_prefix}-authorize",
            requested_at=requested_at,
            driver=authorize,
        )

        def submit() -> Any:
            return self._settlement.submit_settlement(
                command_id=f"{command_prefix}-submit",
                requested_at=requested_at,
                settlement_id=settlement_id,
            )

        self._drive(
            domain="settlement",
            stage="settlement-submit",
            command_id=f"{command_prefix}-submit",
            requested_at=requested_at,
            driver=submit,
        )
        return {"stage": "settle", "settlement_id": settlement_id}

    def _latest_request(self, step_id: str) -> Any | None:
        from src.execution import EffectRequest

        requests = [
            record
            for record in self._execution.objects()
            if isinstance(record, EffectRequest)
            and record.spec.step_id == step_id
        ]
        return requests[-1] if requests else None

    def _step_observations(self, step_id: str, kind: str) -> list[Any]:
        request = self._latest_request(step_id)
        if request is None:
            return []
        subject = request.object_id
        found = []
        for observation in self._execution.observations():
            if observation.spec.subject_ref == subject and observation.spec.kind.value == kind:
                found.append(observation)
        return found

    def _payment_leg(self, step_id: str) -> dict[str, Any]:
        for records in self._plan_hops.values():
            for record in records:
                if record["step_id"] == step_id:
                    return dict(record["payment_leg"])
        raise CoreValidationError(
            f"step {step_id} is not part of a compiled execution plan in this gate"
        )

    def _build_leg_observation(
        self,
        *,
        observation_id: str,
        step_id: str,
        instruction: Any,
    ) -> dict[str, Any]:
        """Translate one REAL execution observation into a leg-bound one.

        The content (native code, canonical status, claim, native
        reference) is copied verbatim from the execution domain's
        recorded OBSERVED evidence — the gate never re-derives rail
        outcomes — and re-bound to the settlement leg through the
        execution domain's own public record factory with the leg's
        instruction digest (splice protection).
        """
        from src.core.envelope import Provenance
        from src.evidence.contracts import EpistemicType
        from src.execution.contracts import ObservationKind
        from src.execution.effects import (
            ExternalObservationSpec,
            make_observation_record,
        )

        status_observations = self._step_observations(step_id, "STATUS")
        if not status_observations:
            raise CoreValidationError(
                f"step {step_id} carries no recorded payment status observation; "
                "settlement reconciliation consumes recorded rail evidence only"
            )
        recorded = status_observations[-1]
        step = self._execution.step(step_id)
        spec = ExternalObservationSpec(
            observation_id=observation_id,
            kind=ObservationKind.STATUS,
            subject_ref=instruction.instruction_id,
            adapter_id=step.spec.adapter_id,
            epistemic=EpistemicType.OBSERVED,
            observed_at=recorded.spec.observed_at,
            content=dict(recorded.spec.content),
            subject_request_digest=instruction.instruction_digest(),
        )
        record = make_observation_record(
            spec=spec,
            environment_id=self._environment_id,
            domain_id=self._execution.domain_id,
            provenance=Provenance(
                issuer=self._actor,
                source=GATE_PROVENANCE_SOURCE,
                recorded_at=recorded.spec.observed_at,
            ),
        )
        return record.to_dict()

    def _build_claim_observation(
        self,
        *,
        observation_id: str,
        step_id: str,
        instruction: Any,
    ) -> dict[str, Any]:
        from src.core.envelope import Provenance
        from src.evidence.contracts import EpistemicType
        from src.execution.contracts import ObservationKind
        from src.execution.effects import (
            ExternalObservationSpec,
            make_observation_record,
        )

        claim_observations = self._step_observations(step_id, "FINALITY")
        if not claim_observations:
            raise CoreValidationError(
                f"step {step_id} carries no recorded finality claim; finality "
                "certificates validate recorded FINALITY evidence only"
            )
        recorded = claim_observations[-1]
        step = self._execution.step(step_id)
        spec = ExternalObservationSpec(
            observation_id=observation_id,
            kind=ObservationKind.FINALITY,
            subject_ref=instruction.instruction_id,
            adapter_id=step.spec.adapter_id,
            epistemic=EpistemicType.OBSERVED,
            observed_at=recorded.spec.observed_at,
            content=dict(recorded.spec.content),
            subject_request_digest=instruction.instruction_digest(),
        )
        record = make_observation_record(
            spec=spec,
            environment_id=self._environment_id,
            domain_id=self._execution.domain_id,
            provenance=Provenance(
                issuer=self._actor,
                source=GATE_PROVENANCE_SOURCE,
                recorded_at=recorded.spec.observed_at,
            ),
        )
        return record.to_dict()

    def stage_fold_rail_evidence(
        self,
        settlement_id: str,
        steps: Mapping[str, str],
        *,
        command_id: str,
        requested_at: str,
    ) -> dict[str, Any]:
        """Fold the recorded rail evidence into the settlement's legs."""
        settlement = self._settlement.settlement(settlement_id)
        observations = []
        for index, (instruction_id, step_id) in enumerate(steps.items(), start=1):
            instruction = self._instruction_of(settlement, instruction_id)
            observations.append(
                self._build_leg_observation(
                    observation_id=f"execution/ig002/{settlement_id.rpartition('/')[2]}/leg-status-{index}",
                    step_id=step_id,
                    instruction=instruction,
                )
            )

        def driver() -> Any:
            return self._settlement.reconcile_settlement(
                command_id=command_id,
                requested_at=requested_at,
                settlement_id=settlement_id,
                as_of=requested_at,
                observations=observations,
            )

        return self._drive(
            domain="settlement",
            stage="fold-rail-evidence",
            command_id=command_id,
            requested_at=requested_at,
            driver=driver,
        )

    def stage_validate_finality_certificate(
        self,
        finality_id: str,
        settlement_id: str,
        steps: Mapping[str, str],
        *,
        command_prefix: str,
        requested_at: str,
    ) -> dict[str, Any]:
        """Validate the rail's FINALITY claims into the certificate."""
        settlement = self._settlement.settlement(settlement_id)
        for index, (instruction_id, step_id) in enumerate(steps.items(), start=1):
            instruction = self._instruction_of(settlement, instruction_id)
            observation = self._build_claim_observation(
                observation_id=f"execution/ig002/{settlement_id.rpartition('/')[2]}/leg-claim-{index}",
                step_id=step_id,
                instruction=instruction,
            )

            def validate(
                observation: dict[str, Any] = observation,
                instruction_id: str = instruction_id,
            ) -> Any:
                return self._settlement.validate_finality_claim(
                    command_id=f"{command_prefix}-{index}",
                    requested_at=requested_at,
                    finality_id=finality_id,
                    settlement_id=settlement_id,
                    observation=observation,
                )

            self._drive(
                domain="settlement",
                stage="validate-finality-claim",
                command_id=f"{command_prefix}-{index}",
                requested_at=requested_at,
                driver=validate,
            )
        return {"stage": "validate-finality-certificate", "finality_id": finality_id}

    def stage_establish_finality(
        self, finality_id: str, *, command_id: str, requested_at: str
    ) -> dict[str, Any]:
        def driver() -> Any:
            return self._settlement.establish_finality(
                command_id=command_id,
                requested_at=requested_at,
                finality_id=finality_id,
            )

        return self._drive(
            domain="settlement",
            stage="establish-finality",
            command_id=command_id,
            requested_at=requested_at,
            driver=driver,
        )

    def stage_resolve_settled_obligations(
        self, settlement_id: str, *, command_prefix: str, requested_at: str
    ) -> dict[str, Any]:
        """Resolve the cleared obligations with digest-bound discharge evidence."""
        evidence = self._settlement.discharge_evidence(settlement_id)
        resolved: list[str] = []
        for index, binding in enumerate(evidence, start=1):
            obligation_id = binding["obligation_id"]

            def resolve(
                obligation_id: str = obligation_id, binding: dict = binding
            ) -> Any:
                return self._clearing.resolve_obligation(
                    command_id=f"{command_prefix}-{index}",
                    requested_at=requested_at,
                    obligation_id=obligation_id,
                    evidence_ref=binding["evidence_ref"],
                    evidence_digest=binding["evidence_digest"],
                    reason=f"IG-002 discharge of {settlement_id}",
                )

            self._drive(
                domain="clearing",
                stage="resolve-obligation",
                command_id=f"{command_prefix}-{index}",
                requested_at=requested_at,
                driver=resolve,
            )
            resolved.append(obligation_id)
        return {"stage": "resolve-settled-obligations", "resolved": resolved}

    def _instruction_of(self, settlement: Any, instruction_id: str) -> Any:
        for instruction in settlement.spec.instructions:
            if instruction.instruction_id == instruction_id:
                return instruction
        raise CoreValidationError(
            f"settlement {settlement.object_id} has no leg {instruction_id!r}"
        )


def _transition_outcome(transition: Any) -> str:
    if transition is None:
        return "accepted"
    outcome = getattr(transition, "outcome", None)
    if outcome is None:
        return "accepted"
    return outcome.value


def _adapter_for_step(bindings: Mapping[str, Any], hop: Any) -> str:
    """Pick the typed adapter binding for one planned hop.

    The composed scenarios bind exactly ONE rail per gate (the rail the
    scenario drives); a multi-rail gate would need a per-hop binding
    declaration, which the frozen v0.1 plan spec does not carry — so the
    gate fails closed rather than guessing an adapter.
    """
    if len(bindings) != 1:
        raise CoreValidationError(
            "the lifecycle gate requires exactly one typed adapter binding for "
            f"hop {hop.hop_id}; a multi-rail composition needs a declared "
            "per-hop adapter source, which the frozen plan spec does not carry"
        )
    return next(iter(bindings))


def _committed_snapshot(engine: Any) -> dict[str, Any]:
    """The engine snapshot with kernel REJECTION records excluded.

    The kernel's idempotency ledger records REJECTED commands so a retry
    converges to the original verdict; those records are retry
    bookkeeping, not committed state (the IG-001 committed-state
    discipline). A fail-closed rejection must therefore leave the
    composed state byte-identical — the gate's no-mutation guard
    depends on it. The full kernel state (including rejection records)
    stays observable through each engine's own ``snapshot_state``.
    """
    snapshot = engine.snapshot_state()
    state = snapshot["engine"]
    records = state.get("records", ())
    committed = [
        record
        for record in records
        if record.get("result", {}).get("outcome") != "rejected"
    ]
    if len(committed) == len(records):
        return snapshot
    projected = dict(snapshot)
    projected["engine"] = {
        "logical_time": state["logical_time"],
        "records": committed,
        "journal": state["journal"],
    }
    return projected


def _journal_entry_to_dict(entry: Any) -> dict[str, Any]:
    """Canonical projection of one kernel journal entry."""
    return {
        "event": entry.event.to_dict(),
        "payload": _payload_value(entry.payload),
    }


def _payload_value(payload: Any) -> Any:
    from src.transition.payload import payload_to_json_value

    return payload_to_json_value(payload)
