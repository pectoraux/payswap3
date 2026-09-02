"""Typed adapter ports — ports over providers (WORK-014).

Implementation principle 4: the execution domain defines TYPED PORTS
(abstract adapter interfaces); concrete rails are external and remain
replaceable. This module owns:

* :class:`EffectSubmissionPort` — the abstract submission boundary
  through which ONE effect request is handed to a rail adapter;
* :class:`EffectReconciliationPort` — the abstract reconciliation
  boundary through which the outcome of an in-flight (possibly
  unknown) submission is queried — the recovery-discipline driver;
* :class:`AdapterBinding` — the typed binding of a port pair to the
  canonical world adapter contract owned by the interoperability domain
  (merged mainline, ``src.interoperability.WorldAdapter``): the contract
  must declare an effect-capable fidelity class and a non-empty effect
  interface; the binding optionally carries the adapter's declared
  native-status map for canonical status observations.

The local deterministic sandbox rail used by tests and dogfooding lives
in ``dogfooding.py`` and is a clearly-marked test-side artifact, NOT
part of the authoritative package surface. Production rails implement
these ports behind their own adapters.

Adapter contract (enforced on every port implementation's inputs):

* ``submit_effect`` MUST be idempotent on the request's idempotency key
  (a rail that processes the same key twice is a broken rail);
* ``query_effect`` MUST return the rail's authoritative statement about
  the submitted effect — ``NOT_FOUND`` means the effect never arrived
  or was never processed (the only retry-safe reconciliation outcome).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Mapping

from src.core.errors import CoreValidationError
from src.interoperability import (
    EFFECT_CAPABLE_FIDELITY_CLASSES,
    AdapterStatusMap,
    WorldAdapter,
)

from ._validation import require_identifier, require_text
from .contracts import ADAPTER_PORT_API_VERSION, QueryOutcome, SubmissionStatus
from .effects import EffectRequest


@dataclass(frozen=True, slots=True)
class AdapterSubmission:
    """Typed response of one adapter submission.

    ``ACCEPTED`` requires the native reference the rail issued;
    ``REJECTED`` (the effect definitively did not happen) and ``UNKNOWN``
    (no definitive submission response — transport failure) both require
    an explicit reason: every failure path is explicit.
    """

    status: SubmissionStatus
    native_reference: str | None
    reason: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.status, SubmissionStatus):
            raise CoreValidationError("submission status must be a SubmissionStatus")
        if self.status is SubmissionStatus.ACCEPTED:
            if not isinstance(self.native_reference, str) or not self.native_reference.strip():
                raise CoreValidationError(
                    "an ACCEPTED submission must carry the rail's native reference"
                )
            if self.reason is not None:
                require_text("submission reason", self.reason)
        else:
            if not isinstance(self.reason, str) or not self.reason.strip():
                raise CoreValidationError(
                    f"a {self.status.value} submission must state an explicit reason"
                )
            if self.native_reference is not None:
                require_text("submission native_reference", self.native_reference)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "native_reference": self.native_reference,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AdapterSubmission":
        if not isinstance(value, Mapping):
            raise CoreValidationError("adapter submission must be an object")
        if set(value) != {"status", "native_reference", "reason"}:
            raise CoreValidationError("adapter submission fields are not canonical")
        return cls(
            status=SubmissionStatus(value["status"]),
            native_reference=value["native_reference"],
            reason=value["reason"],
        )


@dataclass(frozen=True, slots=True)
class AdapterQueryResult:
    """Typed response of one adapter reconciliation query.

    ``SUCCEEDED``/``FAILED`` are definitive outcomes and require the
    rail's native reference; ``NOT_FOUND`` (the effect never happened —
    retry-safe) and ``UNKNOWN`` (reconciliation still open) carry an
    optional detail.
    """

    outcome: QueryOutcome
    native_reference: str | None
    detail: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, QueryOutcome):
            raise CoreValidationError("query outcome must be a QueryOutcome")
        if self.outcome in (QueryOutcome.SUCCEEDED, QueryOutcome.FAILED):
            if not isinstance(self.native_reference, str) or not self.native_reference.strip():
                raise CoreValidationError(
                    f"a {self.outcome.value} query outcome must carry the rail's "
                    "native reference"
                )
        if self.native_reference is not None:
            require_text("query native_reference", self.native_reference)
        if self.detail is not None:
            require_text("query detail", self.detail)

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "native_reference": self.native_reference,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AdapterQueryResult":
        if not isinstance(value, Mapping):
            raise CoreValidationError("adapter query result must be an object")
        if set(value) != {"outcome", "native_reference", "detail"}:
            raise CoreValidationError("adapter query result fields are not canonical")
        return cls(
            outcome=QueryOutcome(value["outcome"]),
            native_reference=value["native_reference"],
            detail=value["detail"],
        )


class EffectSubmissionPort(ABC):
    """The abstract submission port of one rail adapter.

    Implementations hand one typed :class:`EffectRequest` to their rail
    and return the typed :class:`AdapterSubmission`. They MUST
    deduplicate on the request's idempotency key: submitting the same
    key with identical content twice returns the same submission
    response and never causes a second rail-side effect (constitution
    invariant 9). Failures are explicit typed outcomes, never
    exceptions-as-ambiguity.
    """

    __slots__ = ()

    @abstractmethod
    def submit_effect(self, request: EffectRequest) -> AdapterSubmission:
        """Submit one effect request to the rail."""
        raise NotImplementedError


class EffectReconciliationPort(ABC):
    """The abstract reconciliation port of one rail adapter.

    Implementations query their rail for the authoritative outcome of a
    submitted effect request and return the typed
    :class:`AdapterQueryResult`. ``NOT_FOUND`` is the rail's statement
    that the effect never arrived or was never processed — the only
    outcome that makes a retry safe (implementation principle 8:
    external effects are idempotent where possible and reconciled
    before unsafe retry).
    """

    __slots__ = ()

    @abstractmethod
    def query_effect(self, request: EffectRequest) -> AdapterQueryResult:
        """Query the rail for the outcome of one submitted effect request."""
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class AdapterBinding:
    """Typed binding of one rail adapter's ports to its declared contract.

    The canonical world adapter contract is owned by the interoperability
    domain (WORK-007, merged mainline) and is consumed here — never
    redefined. The declared contract must:

    * carry the same adapter id as the binding;
    * declare a non-empty effect interface (pure observation adapters
      cannot be execution submission targets);
    * declare an effect-capable fidelity class (SHADOW/REPLAY/FORECAST
      adapters are pure observation by the frozen contract and are
      rejected here exactly as they are there).

    The optional status map is the adapter's declared native-to-canonical
    status vocabulary (also owned by the interoperability domain); a
    binding without one cannot record canonical status observations.
    """

    adapter_id: str
    submission_port: EffectSubmissionPort
    reconciliation_port: EffectReconciliationPort
    world_adapter: WorldAdapter
    status_map: AdapterStatusMap | None = None

    def __post_init__(self) -> None:
        require_identifier("binding adapter_id", self.adapter_id)
        if not isinstance(self.submission_port, EffectSubmissionPort):
            raise CoreValidationError(
                "binding submission_port must implement EffectSubmissionPort"
            )
        if not isinstance(self.reconciliation_port, EffectReconciliationPort):
            raise CoreValidationError(
                "binding reconciliation_port must implement EffectReconciliationPort"
            )
        if not isinstance(self.world_adapter, WorldAdapter):
            raise CoreValidationError(
                "binding world_adapter must be an interoperability WorldAdapter"
            )
        if self.world_adapter.adapter_id != self.adapter_id:
            raise CoreValidationError(
                f"binding adapter_id {self.adapter_id!r} does not match the declared "
                f"contract adapter_id {self.world_adapter.adapter_id!r}"
            )
        if not self.world_adapter.effect_interface.operations:
            raise CoreValidationError(
                f"adapter {self.adapter_id} declares a pure observation contract; "
                "execution submission requires an effect-capable adapter"
            )
        if self.world_adapter.fidelity_class not in EFFECT_CAPABLE_FIDELITY_CLASSES:
            raise CoreValidationError(
                f"adapter {self.adapter_id} declares fidelity class "
                f"{self.world_adapter.fidelity_class.value}, which is not "
                "effect-capable; execution submission fails closed"
            )
        if self.status_map is not None:
            if not isinstance(self.status_map, AdapterStatusMap):
                raise CoreValidationError("binding status_map must be an AdapterStatusMap")
            if self.status_map.adapter_id != self.adapter_id:
                raise CoreValidationError(
                    f"binding status_map adapter_id {self.status_map.adapter_id!r} "
                    f"does not match binding adapter_id {self.adapter_id!r}"
                )

    def submit(self, request: EffectRequest) -> AdapterSubmission:
        if not isinstance(request, EffectRequest):
            raise CoreValidationError("adapter submission requires an EffectRequest")
        if request.spec.adapter_id != self.adapter_id:
            raise CoreValidationError(
                f"effect request {request.spec.request_id} targets adapter "
                f"{request.spec.adapter_id!r}, not {self.adapter_id!r}"
            )
        submission = self.submission_port.submit_effect(request)
        if not isinstance(submission, AdapterSubmission):
            raise CoreValidationError(
                "submission ports must return AdapterSubmission records"
            )
        return submission

    def query(self, request: EffectRequest) -> AdapterQueryResult:
        if not isinstance(request, EffectRequest):
            raise CoreValidationError("adapter query requires an EffectRequest")
        if request.spec.adapter_id != self.adapter_id:
            raise CoreValidationError(
                f"effect request {request.spec.request_id} targets adapter "
                f"{request.spec.adapter_id!r}, not {self.adapter_id!r}"
            )
        result = self.reconciliation_port.query_effect(request)
        if not isinstance(result, AdapterQueryResult):
            raise CoreValidationError(
                "reconciliation ports must return AdapterQueryResult records"
            )
        return result

    def map_status(self, native_code: str) -> str:
        """Map one native status code to the canonical payment status."""
        if self.status_map is None:
            raise CoreValidationError(
                f"adapter {self.adapter_id} declares no status map; canonical "
                "status observations are unavailable on this binding"
            )
        return self.status_map.map_status(native_code).value


__all__ = [
    "ADAPTER_PORT_API_VERSION",
    "AdapterBinding",
    "AdapterQueryResult",
    "AdapterSubmission",
    "EffectReconciliationPort",
    "EffectSubmissionPort",
]
