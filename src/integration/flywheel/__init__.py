"""The IG-006 merchant/global end-to-end dogfood gate (WORK-031).

Public boundary of the flywheel integration package. The package
composes ONLY already-merged implementations (see
``contracts.CONSUMED_SURFACES``) and introduces no domain semantics of
its own: the merchant delay/credit condition, the fulfillment
lifecycle, the resilience orchestration and the evidence records all
belong to their consumed authorities.
"""

from __future__ import annotations

from src.core.errors import CoreValidationError

from .contracts import (
    CONSUMED_SURFACES,
    CONTAINMENT_PROBES,
    CREDIT_LIMIT_MINOR,
    FLYWHEEL_API_VERSION,
    FLYWHEEL_ENVIRONMENT_ID,
    FLYWHEEL_GATE_ID,
    FLYWHEEL_SCHEMA_VERSION,
    JOURNEY_AMOUNT_MINOR,
    JOURNEY_ASSET_CODE,
    JOURNEY_SCALE,
    JOURNEY_STAGE_TOKENS,
    JOURNEY_EVIDENCE_ID,
    OUTCOME_OBSERVATION_ID,
    KNOWN_FLYWHEEL_GATES,
    JourneyOutcome,
    JourneyStage,
    validate_flywheel_gate_id,
)
from .harness import FlywheelGate
from .invariants import verify_flywheel_invariants
from .scenarios import (
    journey_quality_attributes,
    run_containment_battery,
    run_merchant_journey,
)
from .worlds import FlywheelWorld, build_flywheel_world

__all__ = [
    "CONSUMED_SURFACES",
    "CONTAINMENT_PROBES",
    "CREDIT_LIMIT_MINOR",
    "CoreValidationError",
    "FLYWHEEL_API_VERSION",
    "FLYWHEEL_ENVIRONMENT_ID",
    "FLYWHEEL_GATE_ID",
    "FLYWHEEL_SCHEMA_VERSION",
    "FlywheelGate",
    "FlywheelWorld",
    "JOURNEY_AMOUNT_MINOR",
    "JOURNEY_ASSET_CODE",
    "JOURNEY_EVIDENCE_ID",
    "JOURNEY_SCALE",
    "JOURNEY_STAGE_TOKENS",
    "JourneyOutcome",
    "JourneyStage",
    "KNOWN_FLYWHEEL_GATES",
    "OUTCOME_OBSERVATION_ID",
    "build_flywheel_world",
    "journey_quality_attributes",
    "run_containment_battery",
    "run_merchant_journey",
    "validate_flywheel_gate_id",
    "verify_flywheel_invariants",
]
