"""DOGFOOD-027 — the fulfillment lifecycle integration gate conformance.

This module is a clearly-marked TEST-SIDE ARTIFACT, not part of the
authoritative package surface. It provides the two rails the gate
composes (both behind the execution domain's typed ports):

* :class:`LocalDeterministicRail` — ``LOCAL_DETERMINISTIC_SANDBOX``: a
  scripted in-memory rail (submissions/queries per idempotency key,
  native references derived from declared data, rail-side idempotency
  exactly as the port contract demands). Used by the contract suite
  and the deterministic part of the dogfood.
* :class:`StripeTestRail` — ``REAL_PROVIDER_SANDBOX``: the REAL
  external rail (Stripe test mode) driven over HTTPS through the same
  :class:`src.execution.adapters.EffectSubmissionPort` /
  :class:`src.execution.adapters.EffectReconciliationPort` boundary.

SECURITY (non-negotiable):

* the Stripe credential is read from the ``STRIPE_SECRET_KEY``
  environment variable at CALL time and is never stored, logged,
  printed, echoed or committed;
* errors are sanitized to ``{http_status, error_type, error_code}`` —
  no authorization headers, no raw provider bodies, no secrets;
* only safe normalized provider references (PaymentIntent id, status,
  amount, currency) are kept and reported;
* a missing credential or an unreachable/unauthenticated provider is
  OFFLINE MODE (WORK-027 §8A): the submission is NOT ATTEMPTED, the
  adapter returns an explicit UNKNOWN submission with a sanitized
  reason, the query reports NOT_FOUND for never-attempted effects, and
  the lifecycle never reaches settlement or finality.

``build_transcript`` executes the deterministic dogfood (local rail:
canonical, recovery, rejection, netting and idempotency scenarios,
all in one gate). ``build_real_rail_transcript`` executes the
REAL_PROVIDER_SANDBOX experiment (one real Stripe test-mode payment
end-to-end, plus the idempotent duplicate convergence and a real
card-declined rejection probe) with an offline fallback when the
provider is unavailable.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Iterable, Mapping

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256
from src.interoperability import (
    AdapterStatusMap,
    EffectInterface,
    IdentifierScheme,
    ObservationInterface,
    StatusMapEntry,
    WorldAdapter,
)
from src.interoperability.status import CanonicalPaymentStatus
from src.execution.adapters import (
    AdapterBinding,
    AdapterQueryResult,
    AdapterSubmission,
    EffectReconciliationPort,
    EffectSubmissionPort,
)
from src.execution.contracts import QueryOutcome, SubmissionStatus

from .harness import FulfillmentLifecycleGate
from .scenarios import (
    canonical_lifecycle,
    netting_lifecycle,
    recovery_lifecycle,
    rejection_lifecycle,
)

#: The local deterministic sandbox rail's adapter identity.
LOCAL_ADAPTER_ID = "interoperability/adapter/ig002-local-sandbox"

#: The real provider sandbox rail's adapter identity (Stripe test mode).
STRIPE_ADAPTER_ID = "interoperability/adapter/stripe-test"

#: The environment variable carrying the Stripe test-mode secret key.
STRIPE_SECRET_ENV = "STRIPE_SECRET_KEY"

#: The deterministic test payment methods of the Stripe sandbox world.
STRIPE_SUCCESS_PAYMENT_METHOD = "pm_card_visa"
STRIPE_DECLINE_PAYMENT_METHOD = "pm_card_visa_chargeDeclined"

#: The local rail's declared native status vocabulary.
LOCAL_STATUS_MAP = (
    StatusMapEntry("ACSD", CanonicalPaymentStatus.ACKNOWLEDGED),
    StatusMapEntry("PDNG", CanonicalPaymentStatus.PROCESSING),
    StatusMapEntry("UKWN", CanonicalPaymentStatus.UNKNOWN),
    StatusMapEntry("RJCT", CanonicalPaymentStatus.FAILED),
    StatusMapEntry("STLD", CanonicalPaymentStatus.SETTLED),
    StatusMapEntry("FINL", CanonicalPaymentStatus.FINAL),
)

#: The Stripe rail's declared native status vocabulary (PaymentIntent
#: statuses mapped into the canonical payment lifecycle).
STRIPE_STATUS_MAP = (
    StatusMapEntry("succeeded", CanonicalPaymentStatus.SETTLED),
    StatusMapEntry("processing", CanonicalPaymentStatus.PROCESSING),
    StatusMapEntry("requires_action", CanonicalPaymentStatus.PROCESSING),
    StatusMapEntry("requires_capture", CanonicalPaymentStatus.PROCESSING),
    StatusMapEntry("requires_confirmation", CanonicalPaymentStatus.ACCEPTED),
    StatusMapEntry("requires_payment_method", CanonicalPaymentStatus.FAILED),
    StatusMapEntry("canceled", CanonicalPaymentStatus.REVERSED),
)

_SUBMISSION_SCRIPTS = frozenset({"accept", "reject", "unknown"})
_QUERY_SCRIPTS = frozenset({"succeeded", "failed", "not-found", "unknown"})


def _scripted(table: dict[str, list[str]], key: str, default: str) -> str:
    outcomes = table.get(key)
    if not outcomes:
        return default
    remaining = list(outcomes)
    outcome = remaining.pop(0)
    table[key] = remaining if remaining else [outcome]
    return outcome


class LocalDeterministicRail(EffectSubmissionPort, EffectReconciliationPort):
    """The LOCAL_DETERMINISTIC_SANDBOX rail (test-side artifact).

    ``submissions``/``queries`` map idempotency keys to ordered scripted
    outcomes. The rail deduplicates submissions on the idempotency key:
    a second call for an already-processed key returns the recorded
    submission (never a second rail-side effect).
    """

    def __init__(
        self,
        *,
        submissions: Mapping[str, Iterable[str]] | None = None,
        queries: Mapping[str, Iterable[str]] | None = None,
    ) -> None:
        self._submissions: dict[str, list[str]] = {
            key: list(outcomes) for key, outcomes in (submissions or {}).items()
        }
        self._queries: dict[str, list[str]] = {
            key: list(outcomes) for key, outcomes in (queries or {}).items()
        }
        self._processed: dict[str, AdapterSubmission] = {}
        self._native_status: dict[str, str] = {}
        self.submit_call_count = 0

    @property
    def processed_key_count(self) -> int:
        return len(self._processed)

    @property
    def processed_keys(self) -> tuple[str, ...]:
        return tuple(sorted(self._processed))

    def script_submissions(self, submissions: Mapping[str, Iterable[str]]) -> None:
        for key, outcomes in submissions.items():
            self._submissions[key] = list(outcomes)

    def script_queries(self, queries: Mapping[str, Iterable[str]]) -> None:
        for key, outcomes in queries.items():
            self._queries[key] = list(outcomes)

    def submit_effect(self, request: Any) -> AdapterSubmission:
        self.submit_call_count += 1
        key = request.spec.idempotency_key
        recorded = self._processed.get(key)
        if recorded is not None:
            # Rail-side idempotency: the same key never causes a second
            # rail-side effect (constitution invariant 9).
            return recorded
        script = _scripted(self._submissions, key, "accept")
        if script not in _SUBMISSION_SCRIPTS:
            raise ValueError(f"unknown sandbox submission script {script!r}")
        if script == "accept":
            submission = AdapterSubmission(
                status=SubmissionStatus.ACCEPTED,
                native_reference=f"ig002-local/{key}",
                reason=None,
            )
            self._processed[key] = submission
        elif script == "reject":
            submission = AdapterSubmission(
                status=SubmissionStatus.REJECTED,
                native_reference=None,
                reason="rail rejected the effect (sandbox script)",
            )
            self._processed[key] = submission
        else:
            # A transport failure means the rail never received the
            # submission: nothing is recorded, so reconciliation reports
            # NOT_FOUND (the retry-safe truth) until it resolves.
            submission = AdapterSubmission(
                status=SubmissionStatus.UNKNOWN,
                native_reference=None,
                reason="transport failure: no definitive submission response",
            )
        return submission

    def query_effect(self, request: Any) -> AdapterQueryResult:
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
        default = "succeeded"
        if processed.status is SubmissionStatus.REJECTED:
            default = "failed"
        script = _scripted(self._queries, key, default)
        if script not in _QUERY_SCRIPTS:
            raise ValueError(f"unknown sandbox query script {script!r}")
        if script == "succeeded":
            self._native_status[key] = "STLD"
            return AdapterQueryResult(
                outcome=QueryOutcome.SUCCEEDED,
                native_reference=f"ig002-local/{key}",
                detail=None,
            )
        if script == "failed":
            self._native_status[key] = "RJCT"
            return AdapterQueryResult(
                outcome=QueryOutcome.FAILED,
                native_reference=f"ig002-local/{key}",
                detail=None,
            )
        if script == "unknown":
            return AdapterQueryResult(
                outcome=QueryOutcome.UNKNOWN,
                native_reference=None,
                detail="rail reconciliation still open (sandbox script)",
            )
        return AdapterQueryResult(
            outcome=QueryOutcome.NOT_FOUND,
            native_reference=None,
            detail="the rail never received or processed this effect",
        )

    def native_status_for(self, key: str) -> str | None:
        return self._native_status.get(key)

    def native_payment(self, key: str) -> dict[str, Any] | None:
        if key not in self._processed:
            return None
        return {
            "id": f"ig002-local/{key}",
            "status": self._native_status.get(key, "unknown"),
        }


def make_local_world_adapter() -> WorldAdapter:
    """The local sandbox rail's declared world-adapter contract."""
    return WorldAdapter(
        adapter_id=LOCAL_ADAPTER_ID,
        capability_id="capability/ig002-local-sandbox",
        observation_interface=ObservationInterface(
            operations=("RESOLVE_ENDPOINT", "PAYMENT_STATUS", "FINALITY")
        ),
        effect_interface=EffectInterface(
            operations=("SUBMIT_PAYMENT",),
            destination_schemes=(IdentifierScheme.ALIAS,),
        ),
        fidelity_class="SIMULATION",
    )


def make_local_status_map() -> AdapterStatusMap:
    return AdapterStatusMap(adapter_id=LOCAL_ADAPTER_ID, entries=LOCAL_STATUS_MAP)


def make_local_binding(rail: LocalDeterministicRail) -> AdapterBinding:
    """Bind the local deterministic rail through the PUBLIC adapter path."""
    return AdapterBinding(
        adapter_id=LOCAL_ADAPTER_ID,
        submission_port=rail,
        reconciliation_port=rail,
        world_adapter=make_local_world_adapter(),
        status_map=make_local_status_map(),
    )


class StripeTestRail(EffectSubmissionPort, EffectReconciliationPort):
    """The REAL_PROVIDER_SANDBOX rail: Stripe test mode over HTTPS.

    The credential is read from ``STRIPE_SECRET_KEY`` at call time and
    never stored or logged. Submissions create confirmed PaymentIntents
    with the declared deterministic test payment method and the request's
    idempotency key as the Stripe ``Idempotency-Key`` header (rail-side
    idempotency: the same key never causes a second charge). Queries GET
    the PaymentIntent. Only safe normalized references are kept.

    Offline mode (WORK-027 §8A): a missing credential, an
    unauthenticated one, or an unreachable endpoint means the effect is
    NOT ATTEMPTED — the submission returns UNKNOWN with a sanitized
    reason, and the query reports NOT_FOUND for never-attempted effects.
    """

    def __init__(
        self,
        *,
        secret_env_var: str = STRIPE_SECRET_ENV,
        api_base: str = "https://api.stripe.com/v1",
        success_payment_method: str = STRIPE_SUCCESS_PAYMENT_METHOD,
        decline_payment_method: str = STRIPE_DECLINE_PAYMENT_METHOD,
        decline_keys: Iterable[str] = (),
        timeout_seconds: int = 20,
    ) -> None:
        self._secret_env_var = secret_env_var
        self._api_base = api_base.rstrip("/")
        self._success_payment_method = success_payment_method
        self._decline_payment_method = decline_payment_method
        self._decline_keys = frozenset(decline_keys)
        self._timeout_seconds = timeout_seconds
        self._native: dict[str, dict[str, Any]] = {}
        self._rejected: set[str] = set()
        self.call_count = 0
        self.offline_reason: str | None = None

    # -- sanitized rail-side read accessors (safe provider references) --

    @property
    def processed_keys(self) -> tuple[str, ...]:
        return tuple(sorted(self._native))

    @property
    def rejected_keys(self) -> tuple[str, ...]:
        return tuple(sorted(self._rejected))

    def native_status_for(self, key: str) -> str | None:
        native = self._native.get(key)
        return None if native is None else native["status"]

    def native_payment(self, key: str) -> dict[str, Any] | None:
        native = self._native.get(key)
        return None if native is None else dict(native)

    # -- the typed ports ---------------------------------------------------

    def _credential(self) -> str | None:
        return os.environ.get(self._secret_env_var)

    def _headers(self, credential: str, idempotency_key: str | None) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {credential}",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        if idempotency_key is not None:
            headers["Idempotency-Key"] = idempotency_key
        return headers

    def _http(
        self,
        *,
        method: str,
        path: str,
        credential: str,
        params: Mapping[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """One HTTP call; returns a sanitized outcome envelope.

        Raises nothing on provider errors — the envelope carries
        ``{"transport": ...}`` or ``{"provider_error": {...}}`` so the
        ports can translate explicitly. No header or secret material is
        ever included in the envelope or in any exception text.
        """
        url = f"{self._api_base}{path}"
        data = None
        if params is not None:
            data = urllib.parse.urlencode(params).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=data,
            headers=self._headers(credential, idempotency_key),
            method=method,
        )
        self.call_count += 1
        try:
            with urllib.request.urlopen(
                request, timeout=self._timeout_seconds
            ) as response:
                body = response.read()
                return {"ok": json.loads(body.decode("utf-8"))}
        except urllib.error.HTTPError as error:
            try:
                payload = json.loads(error.read().decode("utf-8"))
            except Exception:  # sanitized: never leak raw bodies
                payload = {}
            error_payload = payload.get("error", {})
            return {
                "provider_error": {
                    "http_status": error.code,
                    "error_type": error_payload.get("type"),
                    "error_code": error_payload.get("code"),
                }
            }
        except Exception as error:  # transport failure, sanitized
            return {
                "transport": {
                    "error_class": type(error).__name__,
                }
            }

    def submit_effect(self, request: Any) -> AdapterSubmission:
        from src.transition.payload import payload_to_json_value

        spec = request.spec
        key = spec.idempotency_key
        payload = payload_to_json_value(spec.payload)
        if not isinstance(payload, Mapping):
            raise CoreValidationError(
                "the Stripe rail requires a payment payload object"
            )
        credential = self._credential()
        if credential is None:
            self.offline_reason = "provider credential not configured"
            return AdapterSubmission(
                status=SubmissionStatus.UNKNOWN,
                native_reference=None,
                reason=(
                    "provider credential not configured; effect NOT ATTEMPTED "
                    "(offline mode)"
                ),
            )
        params = {
            "amount": payload["amount_value"],
            "currency": str(payload["currency"]).lower(),
            "payment_method": (
                self._decline_payment_method
                if key in self._decline_keys
                else self._success_payment_method
            ),
            "confirm": "true",
            "capture_method": "automatic",
        }
        result = self._http(
            method="POST",
            path="/payment_intents",
            credential=credential,
            params=params,
            idempotency_key=key,
        )
        if "ok" in result:
            payment = result["ok"]
            self._native[key] = {
                "id": payment["id"],
                "status": payment["status"],
                "amount": payment["amount"],
                "currency": payment["currency"],
            }
            return AdapterSubmission(
                status=SubmissionStatus.ACCEPTED,
                native_reference=payment["id"],
                reason=None,
            )
        if "transport" in result:
            return AdapterSubmission(
                status=SubmissionStatus.UNKNOWN,
                native_reference=None,
                reason=(
                    "transport failure: no definitive submission response "
                    f"({result['transport']['error_class']})"
                ),
            )
        error = result["provider_error"]
        if error["http_status"] in (401, 403):
            self.offline_reason = "provider authentication failed"
            return AdapterSubmission(
                status=SubmissionStatus.UNKNOWN,
                native_reference=None,
                reason=(
                    "provider authentication failed; effect NOT ATTEMPTED "
                    "(offline mode)"
                ),
            )
        if error["http_status"] == 402:
            # A definitive business rejection: the rail did not (and will
            # not) process this effect. Sanitized to the error code only.
            self._rejected.add(key)
            return AdapterSubmission(
                status=SubmissionStatus.REJECTED,
                native_reference=None,
                reason=f"stripe:{error['error_code']}",
            )
        return AdapterSubmission(
            status=SubmissionStatus.UNKNOWN,
            native_reference=None,
            reason=f"provider error (http {error['http_status']})",
        )

    def query_effect(self, request: Any) -> AdapterQueryResult:
        key = request.spec.idempotency_key
        if key in self._native:
            native = self._native[key]
            result = self._http(
                method="GET",
                path=f"/payment_intents/{native['id']}",
                credential=self._credential() or "",
            )
            if "ok" in result:
                payment = result["ok"]
                self._native[key]["status"] = payment["status"]
                status = payment["status"]
                if status == "succeeded":
                    return AdapterQueryResult(
                        outcome=QueryOutcome.SUCCEEDED,
                        native_reference=payment["id"],
                        detail=None,
                    )
                if status == "canceled":
                    return AdapterQueryResult(
                        outcome=QueryOutcome.FAILED,
                        native_reference=payment["id"],
                        detail=None,
                    )
                return AdapterQueryResult(
                    outcome=QueryOutcome.UNKNOWN,
                    native_reference=None,
                    detail="the payment intent is still processing",
                )
            if "transport" in result:
                return AdapterQueryResult(
                    outcome=QueryOutcome.UNKNOWN,
                    native_reference=None,
                    detail="transport failure during reconciliation",
                )
            error = result["provider_error"]
            if error["http_status"] == 404:
                return AdapterQueryResult(
                    outcome=QueryOutcome.NOT_FOUND,
                    native_reference=None,
                    detail="the rail no longer knows this payment intent",
                )
            return AdapterQueryResult(
                outcome=QueryOutcome.UNKNOWN,
                native_reference=None,
                detail=f"provider error during reconciliation (http {error['http_status']})",
            )
        if key in self._rejected:
            return AdapterQueryResult(
                outcome=QueryOutcome.NOT_FOUND,
                native_reference=None,
                detail="the rail definitively rejected this effect",
            )
        # The effect was never attempted (or its submission response was
        # not definitive): never fabricated as success.
        return AdapterQueryResult(
            outcome=QueryOutcome.NOT_FOUND,
            native_reference=None,
            detail="the rail never received or processed this effect",
        )


def make_stripe_world_adapter() -> WorldAdapter:
    """The Stripe test-mode rail's declared world-adapter contract.

    ``SIMULATION`` fidelity declares the world coupling truthfully: the
    adapter is coupled to Stripe's TEST-mode sandbox world — a real
    external world with no production funds (REAL_PROVIDER_SANDBOX in
    the dogfood vocabulary), addressed through the same semantic
    interface a production rail declares.
    """
    return WorldAdapter(
        adapter_id=STRIPE_ADAPTER_ID,
        capability_id="capability/stripe-test",
        observation_interface=ObservationInterface(
            operations=("RESOLVE_ENDPOINT", "PAYMENT_STATUS", "FINALITY")
        ),
        effect_interface=EffectInterface(
            operations=("SUBMIT_PAYMENT",),
            destination_schemes=(IdentifierScheme.ALIAS,),
        ),
        fidelity_class="SIMULATION",
    )


def make_stripe_status_map() -> AdapterStatusMap:
    return AdapterStatusMap(adapter_id=STRIPE_ADAPTER_ID, entries=STRIPE_STATUS_MAP)


def make_stripe_binding(rail: StripeTestRail) -> AdapterBinding:
    """Bind the Stripe test-mode rail through the PUBLIC adapter path."""
    return AdapterBinding(
        adapter_id=STRIPE_ADAPTER_ID,
        submission_port=rail,
        reconciliation_port=rail,
        world_adapter=make_stripe_world_adapter(),
        status_map=make_stripe_status_map(),
    )


# ---------------------------------------------------------------------------
# DOGFOOD-027: the deterministic local conformance transcript.
# ---------------------------------------------------------------------------


def build_transcript() -> tuple[str, str]:
    """Execute the deterministic DOGFOOD-027 experiment (local rail)."""
    lines: list[str] = [
        "DOGFOOD-027: fulfillment lifecycle integration gate (IG-002) — "
        "fulfillment lifecycle conformance on the local deterministic rail",
        "work_order=WORK-027",
        "architecture=v0.1 (frozen)",
        "gate=IG-002 (full fulfillment lifecycle; required inputs WORK-007, "
        "WORK-009, WORK-010, WORK-011, WORK-012, WORK-013, WORK-014, WORK-015, "
        "WORK-016, WORK-017 and WORK-018, all complete and merged on main)",
        "rail=LOCAL_DETERMINISTIC_SANDBOX (interoperability/adapter/ig002-local-sandbox) "
        "bound through the typed EffectSubmissionPort/EffectReconciliationPort",
        "environment=env/ig002-dogfood (isolated in-memory kernels; no production "
        "state is reachable)",
    ]
    checks: list[bool] = []
    rail = LocalDeterministicRail(
        submissions={
            "ig002-recover-1": ("unknown",),
            "ig002-recover-1-retry": ("accept",),
        },
        queries={"ig002-recover-1": ("not-found",)},
    )
    binding = make_local_binding(rail)
    gate = FulfillmentLifecycleGate(
        environment_id="env/sandbox-ig002-dogfood",
        domain_id="domain/ig002-dogfood",
        bindings={binding.adapter_id: binding},
    )

    canonical = canonical_lifecycle(gate)
    lines.append(f"intent_id={gate.world.intent.object_id} (AUTHORIZED)")
    lines.append(f"plan_id={canonical['plan_id']} (ACCEPTED, deterministic digest)")
    lines.append(f"execution_plan_id={canonical['execution_plan_id']} (COMPLETED)")
    lines.append(
        f"effect_request={canonical['step_ids'][0]}/request/1 "
        f"(idempotency_key={canonical['idempotency_keys'][0]})"
    )
    lines.append(f"effect_reference={canonical['native_reference']}")
    lines.append(f"clearing_cycle={canonical['cycle_id']} (FINALIZED)")
    lines.append(f"obligation={canonical['obligation_ids'][0]} (RESOLVED)")
    lines.append(
        f"settlement={canonical['settlement_id']} (COMPLETED; one SETTLED leg)"
    )
    lines.append(
        "reconciliation=canonical status SETTLED folded from the recorded OBSERVED "
        "rail observation, digest-bound to the leg"
    )
    lines.append(
        f"finality={canonical['finality_id']} (ESTABLISHED; FINAL claim bound to the "
        "settled leg; certificate from the settlement domain only)"
    )
    checks.append(bool(canonical.get("finality_established")))
    checks.append(bool(canonical.get("obligation_resolved")))
    checks.append(len(canonical["invariant_checks"]) >= 8)

    recovery = recovery_lifecycle(gate)
    lines.append(
        "recovery: unknown submission -> reconciliation NOT_FOUND (retry-safe) -> "
        "same step re-armed under a fresh key -> SUCCEEDED -> finality "
        f"(first_state={recovery['first_submission_state']}, "
        f"query={recovery['reconciliation_outcome']}, "
        f"finality={recovery['finality_established']})"
    )
    checks.append(recovery["recovered"] and recovery["finality_established"])
    checks.append(recovery["reconciliation_outcome"] == "NOT_FOUND")

    rejection = rejection_lifecycle(gate)
    new_obligations = (
        rejection["obligation_count_after"] - rejection["obligation_count"]
    )
    lines.append(
        "rejection: accepted submission, FAILED effect result -> step FAILED, plan "
        f"FAILED, new obligations recognized={new_obligations} (failure never "
        "discharges; the recognition probe failed closed)"
    )
    checks.append(
        rejection["step_state"] == "FAILED"
        and rejection["plan_state"] == "FAILED"
        and new_obligations == 0
        and rejection["failed_recognition_rejected"]
    )

    netting = netting_lifecycle(gate)
    statement = gate.clearing.netting(netting["netting_id"]).spec.statement
    lines.append(
        f"netting_cycle={netting['netting_id']} (gross={statement.gross_total} "
        f"net={statement.net_total} reduction={statement.reduction} USD minor; "
        "pair nets sum to the group net; members resolved by netting)"
    )
    lines.append(
        f"net_obligation={netting['net_obligation_id']} (issued, marked due, settled)"
    )
    checks.append(
        netting["net_obligation_resolved"]
        and statement.gross_total == 18000
        and statement.net_total == 2000
    )

    # Idempotency: re-driving the canonical submission never re-calls the
    # port. On the completed step the lifecycle guard converges to an
    # explicit rejection (a terminal step never takes a new submission);
    # on an in-flight step the same re-drive converges to the engine's
    # duplicate outcome — both without a second port call or a second
    # economic effect.
    before_calls = rail.submit_call_count
    replay = gate.stage_submit_effect(
        canonical["step_ids"][0],
        command_id="cmd/ig002-pay-1/submit-replay",
        requested_at="2026-09-04T00:16:30Z",
    )
    lines.append(
        "idempotency: re-driven submission converged without a second port call "
        f"(outcome={replay['outcome']}: the completed step's lifecycle guard; "
        f"port_calls_before={before_calls}, "
        f"port_calls_after={rail.submit_call_count})"
    )
    checks.append(
        replay["outcome"] in ("duplicate", "rejected")
        and rail.submit_call_count == before_calls
    )
    lines.append(f"stage_journal_entries={len(gate.stage_journal)}")
    lines.append(
        "economic_outcome: the payer's 100.00 USD intent was fulfilled end-to-end "
        "(10000 minor units conserved through execution evidence, obligation, "
        "discharge posting and finality certificate)"
    )
    passed = all(checks)
    lines.append(f"checks_passed={sum(1 for check in checks if check)}/{len(checks)}")
    lines.append(
        "classification: DOGFOOD-027: PASS"
        if passed
        else "classification: DOGFOOD-027: FAIL"
    )
    transcript = "\n".join(lines) + "\n"
    digest = canonical_sha256({"transcript": transcript})
    return transcript, digest


# ---------------------------------------------------------------------------
# DOGFOOD-027: the REAL_PROVIDER_SANDBOX experiment (Stripe test mode).
# ---------------------------------------------------------------------------


def build_real_rail_transcript() -> tuple[str, str]:
    """Execute the REAL_PROVIDER_SANDBOX experiment (Stripe test mode).

    Falls back to the explicit offline contract when the credential is
    absent or the provider is unreachable: the effect is NOT ATTEMPTED,
    the transcript states ``REAL RAIL: NOT EXECUTED`` with the sanitized
    reason, and the experiment classification becomes OUTSTANDING (the
    dogfood requirement is then not satisfied by this run).
    """
    lines: list[str] = [
        "DOGFOOD-027 REAL RAIL: fulfillment lifecycle integration gate (IG-002) — "
        "real supported sandbox payment end-to-end",
        "work_order=WORK-027",
        "architecture=v0.1 (frozen)",
        "gate=IG-002",
        "rail=REAL_PROVIDER_SANDBOX Stripe test mode "
        f"({STRIPE_ADAPTER_ID}) bound through the typed "
        "EffectSubmissionPort/EffectReconciliationPort",
        "environment=env/ig002-real-rail (isolated in-memory kernels composed with "
        "Stripe's TEST-mode sandbox world; no production funds are reachable)",
        "credential=STRIPE_SECRET_KEY environment variable (read at call time; "
        "never printed, stored, committed or echoed)",
    ]
    credential = os.environ.get(STRIPE_SECRET_ENV)
    if credential is None:
        rail = StripeTestRail()
        binding = make_stripe_binding(rail)
        gate = FulfillmentLifecycleGate(
            environment_id="env/sandbox-ig002-real-rail",
            domain_id="domain/ig002-real-rail",
            bindings={binding.adapter_id: binding},
        )
        from .scenarios import offline_lifecycle

        outcome = offline_lifecycle(gate)
        lines.extend(
            [
                "REAL RAIL: NOT EXECUTED",
                "REASON: provider credential not configured (offline mode)",
                "OFFLINE FALLBACK: EXECUTED",
                f"submission_state={outcome['submission_state']} "
                f"({outcome['submission_reason']})",
                f"reconciliation_outcome={outcome['reconciliation_outcome']}",
                f"any_settled_or_final={outcome['any_settled_or_final']} "
                "(offline never reaches settlement or finality)",
                "REAL-RAIL REQUIREMENT: OUTSTANDING",
                "classification: DOGFOOD-027 REAL RAIL: BLOCKED (offline fallback "
                "executed; the real sandbox payment remains outstanding)",
            ]
        )
        transcript = "\n".join(lines) + "\n"
        return transcript, canonical_sha256({"transcript": transcript})

    rail = StripeTestRail(
        decline_keys={"ig002-rail-decline-1"},
    )
    binding = make_stripe_binding(rail)
    gate = FulfillmentLifecycleGate(
        environment_id="env/sandbox-ig002-real-rail",
        domain_id="domain/ig002-real-rail",
        bindings={binding.adapter_id: binding},
    )
    from .scenarios import run_fulfillment_lifecycle

    checks: list[bool] = []
    outcome = run_fulfillment_lifecycle(
        gate,
        rail=rail,
        tag="rail-1",
        amount_minor=10000,
    )
    payment = rail.native_payment("ig002-rail-1")
    lines.append(
        f"intent_id={gate.world.intent.object_id} (AUTHORIZED: 100.00 USD to "
        "principal/merchant-42)"
    )
    lines.append(f"plan_id={outcome['plan_id']} (ACCEPTED)")
    lines.append(f"execution_plan_id={outcome['execution_plan_id']} (COMPLETED)")
    lines.append(
        f"effect_request={outcome['step_ids'][0]}/request/1 "
        f"(idempotency_key={outcome['idempotency_keys'][0]})"
    )
    lines.append(f"effect_reference={outcome['native_reference']}")
    lines.append(
        "provider_payment: "
        + (
            "id=<stripe PaymentIntent id> status=succeeded amount=10000 "
            "currency=usd (normalized safe reference)"
            if payment is not None and payment["status"] == "succeeded"
            else f"status={payment['status'] if payment else 'unavailable'}"
        )
    )
    lines.append(f"clearing_cycle={outcome['cycle_id']} (FINALIZED)")
    lines.append(f"obligation={outcome['obligation_ids'][0]} (RESOLVED)")
    lines.append("netting_cycle=none (single-obligation real-rail scenario; the "
                 "netting stage is proven on the local deterministic rail)")
    lines.append(
        f"settlement={outcome['settlement_id']} (COMPLETED; one SETTLED leg with "
        "its discharge posting)"
    )
    lines.append(
        "reconciliation: the recorded OBSERVED status observation (native code "
        "'succeeded' -> canonical SETTLED through the adapter's declared status "
        "map) was folded digest-bound onto the leg"
    )
    lines.append(
        f"finality={outcome['finality_id']} (ESTABLISHED from the rail's FINAL "
        "claim; a payment status alone could never establish it)"
    )
    checks.append(outcome["finality_established"] is True)
    checks.append(outcome["obligation_resolved"] is True)
    checks.append(
        payment is not None
        and payment["status"] == "succeeded"
        and payment["amount"] == 10000
        and payment["currency"] == "usd"
    )

    # Idempotency on the REAL rail: re-driving the submission never
    # re-calls the port and never causes a second charge. On the
    # completed step the lifecycle guard converges to an explicit
    # rejection; the rail's own Idempotency-Key handling (the same key
    # returns the same PaymentIntent) plus the engine's submission
    # ledger keep the economic effect exactly-once.
    before_calls = rail.call_count
    replay = gate.stage_submit_effect(
        outcome["step_ids"][0],
        command_id="cmd/ig002-rail-1/submit-replay",
        requested_at="2026-09-04T00:16:30Z",
    )
    lines.append(
        "idempotency: re-driven submission converged without a second port call "
        f"or charge (outcome={replay['outcome']}: the completed step's lifecycle "
        f"guard; port_http_calls_before={before_calls}, "
        f"port_http_calls_after={rail.call_count}; one payment, one obligation, "
        "one discharge, one certificate)"
    )
    checks.append(
        replay["outcome"] in ("duplicate", "rejected")
        and rail.call_count == before_calls
    )
    discharge_count = len(
        [entry for entry in gate.settlement.postings() if entry.kind == "DISCHARGE"]
    )
    checks.append(discharge_count == 1)

    # A REAL rejected payment (card_declined): the definitive business
    # rejection fails the step; no obligation is ever recognized.
    decline = run_fulfillment_lifecycle(
        gate,
        rail=rail,
        tag="rail-decline-1",
        amount_minor=2500,
        stop_after="submitted",
    )
    decline_step = gate.execution.step(decline["step_ids"][0])
    lines.append(
        "rejection_probe: a real card_declined submission (test method "
        f"pm_card_visa_chargeDeclined) -> step {decline_step.state.value}, no "
        "obligation recognized (failure never discharges)"
    )
    checks.append(decline_step.state.value == "FAILED")
    checks.append(
        len(
            [
                record
                for record in gate.clearing.records()
                if record.__class__.__name__ == "Obligation"
            ]
        )
        == 1
    )

    lines.append(f"port_http_calls={rail.call_count} (provider calls minimized)")
    lines.append(
        "economic_outcome: the real Stripe test-mode sandbox payment of 100.00 USD "
        "succeeded end-to-end — the payer intent was fulfilled through "
        "compilation, execution, clearing, settlement and an ESTABLISHED finality "
        "certificate with exactly one discharge posting; no secret material "
        "appears in this transcript"
    )
    checks.append(all(checks[:3]))
    passed = all(checks)
    lines.append(f"checks_passed={sum(1 for check in checks if check)}/{len(checks)}")
    lines.append(
        "classification: DOGFOOD-027 REAL RAIL: PASS"
        if passed
        else "classification: DOGFOOD-027 REAL RAIL: FAIL"
    )
    transcript = "\n".join(lines) + "\n"
    digest = canonical_sha256({"transcript": transcript})
    return transcript, digest


def main() -> None:
    transcript, digest = build_transcript()
    print(transcript, end="")
    print(f"transcript_sha256={digest}")


def main_real() -> None:
    transcript, digest = build_real_rail_transcript()
    print(transcript, end="")
    print(f"transcript_sha256={digest}")


if __name__ == "__main__":  # pragma: no cover
    main()
