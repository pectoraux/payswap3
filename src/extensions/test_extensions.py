"""WORK-020 contract and discrimination suite (red-first).

This suite was authored BEFORE the implementation and captures the frozen
contract of the extension runtime and capability marketplace domain
(``spec/architecture/v0.1/extensions.md`` + WORK-020):

- the frozen manifest contract: every frozen field
  (extension_id, developer, version, code_hash, capabilities_provided,
  capabilities_required, permissions, dependencies, inputs, outputs,
  pricing, resource_requirements, authority_class, risk_class,
  jurisdictions, protocol_versions, schema_versions, simulation_support,
  production_support) plus the typed authority-tier requirements
  (verification, collateral, monitoring, risk limits — fail closed when
  missing for the declared R0-R5 tier);
- the registry-listed protocol-visible manifest object type
  ``payswap/extension-manifest/v1`` (the ONLY registry-listed extension
  object); instances, grants, invocations and contributions follow the
  sibling convention and use internal non-registry ``extension/...``
  formats; events use the registered ``extension`` namespace; command
  types are internal free-form strings (frozen 12-verb Extension family
  plus the documented internal triggers certify/shadow/invoke/measure);
- the frozen 13-state lifecycle
  DRAFT→SANDBOX→TESTED→SUBMITTED→SECURITY_REVIEW→POLICY_REVIEW→
  PUBLISHED→INSTALLED→ACTIVE→DEGRADED→SUSPENDED→DEPRECATED→ARCHIVED
  with explicit fail-closed edges and reject paths back to the sandbox;
- typed composition artifacts (DemandSignal, RouteProposal, QuoteSet,
  RiskAssessment, ComplianceProof, Attestation, ExecutionAdapter,
  SettlementInstruction) carrying schema version, producer, provenance,
  expiry, confidence, dependencies and risk;
- the sandboxed invocation runtime: declared inputs/outputs only,
  capability grants, resource quotas, no ambient authority (the sandbox
  context exposes exactly the frozen declared-data fields — never a
  store, engine or view), undeclared capability/resource/output access
  fails closed, and this package never produces production effects;
- the dependency DAG: version bounds, fail-closed cycle detection,
  missing-dependency and activation-readiness checks;
- contribution measurement: verified incremental contribution against a
  counterfactual baseline/treatment comparison, distinct typed economic
  quantities (resource credits vs real economic earnings vs financial
  collateral), and activity volume never counting as contribution;
- the real transition kernel is the ONLY state machine (no second
  authority): every lifecycle mutation is a kernel command with an
  immutable ``extension/...`` event; ``CoreValidationError`` is the
  single error authority;
- the import boundary: domain modules import only the stdlib, the
  canonical core and the declared dependency surfaces actually consumed
  (``src.transition``, ``src.capability``, ``src.safety``,
  ``src.evidence``, ``src.simulation`` public contracts) — never ledger,
  finality, authority or unmerged sibling surfaces;
- determinism: no wall-clock reads, no entropy, no generated identifiers
  in domain code — every instant is explicit declared ``as_of`` data.
"""

from __future__ import annotations

import ast
import dataclasses
import subprocess
import sys
import time
import unittest
from pathlib import Path

from src.core.envelope import ObjectEnvelope, Provenance
from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256

from src.transition import (
    Command,
    ExpectedVersion,
    Outcome,
    RejectionReason,
    validate_event_type,
)

from src.capability import CapabilityKind
from src.safety.contracts import RiskBand
from src.evidence.contracts import EpistemicType
from src.simulation import EnvironmentMode

from src.extensions import (
    CAPABILITY_DOMAIN_MIRROR,
    CAPABILITY_GRANT_OBJECT_TYPE,
    CONSUMED_SURFACES,
    CONTRIBUTION_METRICS,
    CodeRepository,
    ContributionMetric,
    DependencyGraph,
    DependencySpec,
    EconomicEarnings,
    ExtensionArtifact,
    ExtensionArtifactKind,
    ExtensionCapability,
    ExtensionContribution,
    ExtensionInstance,
    ExtensionInvocation,
    ExtensionLifecycleState,
    ExtensionManifest,
    ExtensionPermission,
    ExtensionRuntime,
    EXTENSION_CONTRIBUTION_OBJECT_TYPE,
    EXTENSION_INSTANCE_OBJECT_TYPE,
    EXTENSION_INVOCATION_OBJECT_TYPE,
    EXTENSION_MANIFEST_OBJECT_TYPE,
    EXTENSION_COMMAND_TYPES,
    EXTENSIONS_API_VERSION,
    EXTENSIONS_EVENT_NAMESPACE,
    EXTENSIONS_PROTOCOL_VERSION,
    EXTENSIONS_SCHEMA_VERSION,
    FROZEN_EXTENSION_COMMAND_VERBS,
    FinancialCollateral,
    FORBIDDEN_PERMISSIONS,
    InvocationEffectMode,
    InvocationRequest,
    INSTANCE_LIFECYCLE_STATES,
    LIFECYCLE_TRANSITIONS,
    MANIFEST_LIFECYCLE_STATES,
    MonitoringLevel,
    OutcomeMeasurement,
    PricingModel,
    PricingSpec,
    ResourceBudget,
    ResourceCredits,
    ResourceRequirements,
    RiskControls,
    SANDBOX_CONTEXT_FIELDS,
    SandboxContext,
    TIER_MAXIMUM_EXPOSURE_MINOR,
    TIER_MINIMUM_COLLATERAL_MINOR,
    TIER_MINIMUM_MONITORING,
    VerificationEvidence,
    execute_sandboxed_invocation,
    measure_contribution,
    parse_version,
    resolve_lifecycle_transition,
    version_in_bounds,
)
from src.extensions import CoreValidationError as ExtensionsCoreValidationError

# ---------------------------------------------------------------------------
# shared deterministic fixtures
# ---------------------------------------------------------------------------

T0 = "2026-09-02T00:00:00Z"
T1 = "2026-09-02T00:01:00Z"
T2 = "2026-09-02T00:30:00Z"
T3 = "2026-09-02T01:00:00Z"
T4 = "2026-09-02T06:00:00Z"
T_EXPIRY = "2026-09-03T00:00:00Z"

ENV_SIM = "env/test-extensions-simulation"
ENV_PROD = "env/test-extensions-production"
DOMAIN = "domain/extensions-test"

ALPHA_HASH = "a" * 64
BETA_HASH = "b" * 64


def make_provenance(recorded_at: str = T1) -> Provenance:
    return Provenance(
        issuer="principal/test-harness",
        source="extensions/test",
        recorded_at=recorded_at,
    )


def make_pricing(**overrides) -> PricingSpec:
    values = {
        "model": PricingModel.REVENUE_SHARE,
        "amount_minor": 0,
        "asset": "USD",
        "share_bps": 1000,
    }
    values.update(overrides)
    return PricingSpec(**values)


def make_requirements(**overrides) -> ResourceRequirements:
    values = {
        "max_invocations_per_window": 5,
        "max_artifact_bytes": 4096,
    }
    values.update(overrides)
    return ResourceRequirements(**values)


def make_controls(**overrides) -> RiskControls:
    values = RiskControls(
        collateral=FinancialCollateral(amount_minor=25_000_000, asset="USD"),
        monitoring_level=MonitoringLevel.INTENSIVE,
        risk_limits={"max_single_exposure_minor": 1_000_000},
    )
    if overrides:
        return RiskControls(**{**values.to_dict(), **overrides})
    return values


def make_manifest(
    extension_id: str = "extension/alpha-route",
    code_hash: str = ALPHA_HASH,
    authority_class: str = "R2",
    risk_class: RiskBand = RiskBand.MEDIUM,
    **overrides,
):
    """Deterministic valid manifest carrying the full frozen field set."""
    fields = {
        "extension_id": extension_id,
        "developer": "principal/developer-alpha",
        "version": "1.0.0",
        "code_hash": code_hash,
        "capabilities_provided": (ExtensionCapability.ROUTE_PROPOSAL,),
        "capabilities_required": (),
        "permissions": (ExtensionPermission.READ_MARKET_DATA,),
        "dependencies": (),
        "inputs": (ExtensionArtifactKind.DEMAND_SIGNAL,),
        "outputs": (ExtensionArtifactKind.ROUTE_PROPOSAL,),
        "pricing": make_pricing(),
        "resource_requirements": make_requirements(),
        "authority_class": authority_class,
        "risk_class": risk_class,
        "jurisdictions": ("US", "GH"),
        "protocol_versions": ("v0.1",),
        "schema_versions": (1,),
        "simulation_support": True,
        "production_support": True,
        "verification": VerificationEvidence(
            method="third-party-audit",
            evidence_refs=("evidence/audit-alpha",),
            review_digest="c" * 64,
        ),
        "risk_controls": make_controls(),
    }
    fields.update(overrides)
    return ExtensionManifest(**fields)


def make_demand_artifact(
    artifact_id: str = "extension-artifact/demand-1",
    volume_minor: int = 5_000_000,
    producer: str = "extension/network-demand-source",
    payload: tuple | None = None,
    expires_at: str = T_EXPIRY,
    confidence_bps: int = 9000,
) -> ExtensionArtifact:
    return ExtensionArtifact(
        artifact_id=artifact_id,
        kind=ExtensionArtifactKind.DEMAND_SIGNAL,
        schema_version=1,
        producer=producer,
        payload=(("corridor", "US->GH"), ("volume_minor", volume_minor))
        if payload is None
        else payload,
        provenance=make_provenance(),
        expires_at=expires_at,
        confidence_bps=confidence_bps,
        dependencies=(),
        risk_band=RiskBand.LOW,
    )


def alpha_handler(context: SandboxContext):
    """A concrete in-repo test extension (route-proposal provider)."""
    demand = context.inputs[0]
    payload = dict(demand.payload)
    savings = payload["volume_minor"] // 20
    return (
        ExtensionArtifact(
            artifact_id=f"extension-artifact/{context.invocation_id}/proposal",
            kind=ExtensionArtifactKind.ROUTE_PROPOSAL,
            schema_version=1,
            producer=context.extension_id,
            payload=(
                ("corridor", payload["corridor"]),
                ("cost_savings_minor", savings),
                ("quality_bps", 9000),
            ),
            provenance=make_provenance(),
            expires_at=T_EXPIRY,
            confidence_bps=8500,
            dependencies=(demand.artifact_id,),
            risk_band=RiskBand.LOW,
        ),
    )


def make_runtime(
    environment_id: str = ENV_SIM,
    mode: EnvironmentMode = EnvironmentMode.SIMULATION,
    authorized_actors=frozenset({"principal/marketplace-operator"}),
) -> ExtensionRuntime:
    repository = CodeRepository()
    repository.register(ALPHA_HASH, alpha_handler)
    repository.register(BETA_HASH, alpha_handler)
    return ExtensionRuntime(
        environment_id=environment_id,
        domain_id=DOMAIN,
        environment_mode=mode,
        authorized_actors=authorized_actors,
        code_repository=repository,
    )


def cmd(
    command_id: str,
    command_type: str,
    target_refs: tuple[str, ...],
    payload: dict,
    *,
    requested_at: str = T1,
    environment_id: str = ENV_SIM,
    expected_versions: tuple[tuple[str, int], ...] = (),
    actor: str = "principal/marketplace-operator",
) -> Command:
    return Command.build(
        command_id=command_id,
        command_type=command_type,
        actor=actor,
        authority_refs=("authority/ops",),
        target_refs=tuple(target_refs),
        payload=payload,
        environment_id=environment_id,
        domain_id=DOMAIN,
        expected_versions=tuple(
            ExpectedVersion(object_ref=ref, object_version=version)
            for ref, version in expected_versions
        ),
        idempotency_key=f"key/{command_id}",
        nonce="1",
        requested_at=requested_at,
    )


def register_manifest(
    runtime: ExtensionRuntime, manifest=None, *, command_id="cmd/register-1"
) -> str:
    manifest = manifest or make_manifest()
    result = runtime.submit(
        cmd(
            command_id,
            "extension/register",
            (manifest.extension_id,),
            {"manifest": manifest.to_record_dict()},
            environment_id=runtime.environment_id,
            expected_versions=((manifest.extension_id, 0),),
        )
    )
    assert result.outcome is Outcome.ACCEPTED, result.detail
    return manifest.extension_id


def sandbox_invoke_once(
    runtime: ExtensionRuntime,
    manifest_id: str,
    invocation_id: str,
    *,
    requested_at: str = T2,
    environment_id: str = ENV_SIM,
    resources: dict | None = None,
):
    """One sandbox-phase invocation targeting the SANDBOX-state manifest."""
    current = runtime.store.get(manifest_id)
    version = current.object_version if current is not None else 0
    payload = {
        "invocation_id": invocation_id,
        "capability": "route_proposal",
        "inputs": [make_demand_artifact().to_dict()],
        "resources": resources or {},
        "as_of": requested_at,
        "jurisdiction": "US",
    }
    return runtime.submit(
        cmd(
            f"cmd/{invocation_id}",
            "extension/invoke",
            (invocation_id,),
            payload,
            requested_at=requested_at,
            environment_id=environment_id,
            expected_versions=((invocation_id, 0), (manifest_id, version)),
        )
    )


def drive_to_published(runtime: ExtensionRuntime, manifest_id: str, *, base_id="cmd") -> None:
    """submit → sandbox invoke → certify → submit → approve → approve → publish."""
    environment_id = runtime.environment_id
    runtime.submit(
        cmd(
            f"{base_id}-submit",
            "extension/submit",
            (manifest_id,),
            {},
            environment_id=environment_id,
        )
    )
    sandbox_invoke_once(
        runtime,
        manifest_id,
        f"extension-invocation/{base_id}-sandbox-1",
        environment_id=environment_id,
    )
    runtime.submit(
        cmd(
            f"{base_id}-certify",
            "extension/certify",
            (manifest_id,),
            {},
            environment_id=environment_id,
        )
    )
    runtime.submit(
        cmd(
            f"{base_id}-submit2",
            "extension/submit",
            (manifest_id,),
            {},
            environment_id=environment_id,
        )
    )
    for suffix, command_type in (
        ("approve1", "extension/approve"),
        ("approve2", "extension/approve"),
        ("publish", "extension/publish"),
    ):
        result = runtime.submit(
            cmd(
                f"{base_id}-{suffix}",
                command_type,
                (manifest_id,),
                {},
                environment_id=environment_id,
            )
        )
        assert result.outcome is Outcome.ACCEPTED, (command_type, result.detail)


def grant_payload(
    grant_id: str = "extension-grant/alpha-route-route",
    capability: str = "route_proposal",
    budget_max_invocations: int = 5,
) -> dict:
    return {
        "grant_id": grant_id,
        "capability": capability,
        "granted_by": "principal/marketplace-operator",
        "valid_from": T0,
        "valid_until": T4,
        "jurisdictions": ("US", "GH"),
        "budget": {
            "max_invocations": budget_max_invocations,
            "window_start": T0,
            "window_end": T4,
        },
    }


def install_command(
    instance_id: str = "extension-instance/alpha-route@sim",
    manifest_id: str = "extension/alpha-route",
    grants: tuple[dict, ...] | None = None,
    *,
    command_id="cmd/install-1",
    environment_id: str = ENV_SIM,
) -> Command:
    grants = grants if grants is not None else (grant_payload(),)
    return cmd(
        command_id,
        "extension/install",
        (instance_id,) + tuple(grant["grant_id"] for grant in grants),
        {
            "instance_id": instance_id,
            "manifest_id": manifest_id,
            "version": "1.0.0",
            "jurisdictions": ("US", "GH"),
            "grants": list(grants),
        },
        environment_id=environment_id,
        expected_versions=((instance_id, 0),)
        + tuple((grant["grant_id"], 0) for grant in grants),
    )


def install_instance(
    runtime: ExtensionRuntime,
    manifest_id: str = "extension/alpha-route",
    instance_id: str = "extension-instance/alpha-route@sim",
    *,
    command_id="cmd/install-1",
    grants: tuple[dict, ...] | None = None,
) -> str:
    result = runtime.submit(
        install_command(instance_id, manifest_id, grants, command_id=command_id)
    )
    assert result.outcome is Outcome.ACCEPTED, result.detail
    return instance_id


def activate_instance(
    runtime: ExtensionRuntime,
    instance_id: str,
    *,
    command_id="cmd/activate-1",
):
    current = runtime.store.get(instance_id)
    return runtime.submit(
        cmd(
            command_id,
            "extension/activate",
            (instance_id,),
            {},
            expected_versions=((instance_id, current.object_version),),
        )
    )


def invoke_once(
    runtime: ExtensionRuntime,
    target_id: str,
    invocation_id: str,
    *,
    resources: dict | None = None,
    requested_at: str = T2,
    capability: str = "route_proposal",
    jurisdiction: str = "US",
    environment_id: str = ENV_SIM,
):
    """One invocation command targeting an instance (or SANDBOX manifest)."""
    current = runtime.store.get(target_id)
    version = current.object_version if current is not None else 0
    payload = {
        "invocation_id": invocation_id,
        "capability": capability,
        "inputs": [make_demand_artifact().to_dict()],
        "resources": resources or {},
        "as_of": requested_at,
        "jurisdiction": jurisdiction,
    }
    return runtime.submit(
        cmd(
            f"cmd/{invocation_id}",
            "extension/invoke",
            (invocation_id,),
            payload,
            requested_at=requested_at,
            environment_id=environment_id,
            expected_versions=((invocation_id, 0), (target_id, version)),
        )
    )


# ---------------------------------------------------------------------------
# 1. static boundary
# ---------------------------------------------------------------------------

DOMAIN_PACKAGE = Path(__file__).parent
DOMAIN_SOURCES = sorted(
    source for source in DOMAIN_PACKAGE.glob("*.py") if source.name != "test_extensions.py"
)


class StaticBoundaryTests(unittest.TestCase):
    """The typed, versioned public boundary and the import firewall."""

    def test_version_constants_are_frozen(self) -> None:
        self.assertEqual(EXTENSIONS_API_VERSION, "v0.1")
        self.assertEqual(EXTENSIONS_PROTOCOL_VERSION, "v0.1")
        self.assertEqual(EXTENSIONS_SCHEMA_VERSION, 1)

    def test_manifest_object_type_is_the_registry_listed_one(self) -> None:
        self.assertEqual(EXTENSION_MANIFEST_OBJECT_TYPE, "payswap/extension-manifest/v1")

    def test_internal_object_types_are_non_registry(self) -> None:
        for object_type in (
            EXTENSION_INSTANCE_OBJECT_TYPE,
            CAPABILITY_GRANT_OBJECT_TYPE,
            EXTENSION_INVOCATION_OBJECT_TYPE,
            EXTENSION_CONTRIBUTION_OBJECT_TYPE,
        ):
            self.assertTrue(object_type.startswith("extension/"))
            self.assertNotIn("payswap/", object_type)

    def test_event_namespace_is_registered(self) -> None:
        self.assertEqual(EXTENSIONS_EVENT_NAMESPACE, "extension")
        validate_event_type("test", "extension/registered")
        validate_event_type("test", "extension/invoked")

    def test_command_types_cover_the_frozen_family_plus_internal_triggers(self) -> None:
        self.assertEqual(
            FROZEN_EXTENSION_COMMAND_VERBS,
            frozenset(
                {
                    "register",
                    "submit",
                    "approve",
                    "reject",
                    "publish",
                    "install",
                    "activate",
                    "degrade",
                    "suspend",
                    "resume",
                    "deprecate",
                    "archive",
                }
            ),
        )
        self.assertEqual(
            EXTENSION_COMMAND_TYPES,
            frozenset(
                {
                    "extension/register",
                    "extension/submit",
                    "extension/certify",
                    "extension/approve",
                    "extension/reject",
                    "extension/publish",
                    "extension/install",
                    "extension/activate",
                    "extension/shadow",
                    "extension/invoke",
                    "extension/measure",
                    "extension/degrade",
                    "extension/suspend",
                    "extension/resume",
                    "extension/deprecate",
                    "extension/archive",
                }
            ),
        )

    def test_public_boundary_all_is_explicit_and_frozen(self) -> None:
        import src.extensions as package

        self.assertEqual(sorted(package.__all__), sorted(set(package.__all__)))
        for name in package.__all__:
            self.assertTrue(hasattr(package, name), name)

    def test_domain_modules_import_only_consumed_surfaces(self) -> None:
        consumed = set()
        for source in DOMAIN_SOURCES:
            tree = ast.parse(source.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    if node.level == 0 and node.module and node.module.startswith("src."):
                        consumed.add(node.module.split(".")[1])
                    elif node.level > 1 and node.module:
                        consumed.add(node.module.split(".")[0])
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.startswith("src."):
                            consumed.add(alias.name.split(".")[1])
        self.assertEqual(consumed, set(CONSUMED_SURFACES))
        self.assertEqual(
            CONSUMED_SURFACES,
            frozenset({"core", "transition", "capability", "safety", "evidence", "simulation"}),
        )

    def test_ledger_finality_authority_surfaces_are_never_imported(self) -> None:
        forbidden = {
            "value",
            "money",
            "intent",
            "market",
            "liquidity",
            "reservation",
            "trust",
            "interoperability",
            "integration",
            "compiler",
            "execution",
            "agents",
            "data",
        }
        for source in DOMAIN_SOURCES:
            tree = ast.parse(source.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("src."):
                    self.assertNotIn(node.module.split(".")[1], forbidden, source.name)
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.startswith("src."):
                            self.assertNotIn(alias.name.split(".")[1], forbidden, source.name)

    def test_domain_code_has_no_wall_clock_or_entropy(self) -> None:
        for source in DOMAIN_SOURCES:
            text = source.read_text(encoding="utf-8")
            for forbidden in (
                "time.time",
                "time.monotonic",
                "datetime.now",
                "utcnow",
                "random",
                "uuid",
                "secrets",
                "time.sleep",
            ):
                self.assertNotIn(forbidden, text, f"{source.name} references {forbidden}")

    def test_domain_sources_contain_no_float_literals(self) -> None:
        for source in DOMAIN_SOURCES:
            tree = ast.parse(source.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, float):
                    self.fail(f"{source.name} contains the float literal {node.value}")

    def test_error_authority_is_core(self) -> None:
        self.assertIs(ExtensionsCoreValidationError, CoreValidationError)
        with self.assertRaises(CoreValidationError):
            ExtensionPermission.parse("ledger_write")

    def test_capability_vocabulary_mirrors_the_capability_domain(self) -> None:
        for capability, kind in CAPABILITY_DOMAIN_MIRROR.items():
            self.assertEqual(capability.value, kind.value)
        mirrored = {kind.value for kind in CapabilityKind}
        self.assertEqual(
            {capability.value for capability in CAPABILITY_DOMAIN_MIRROR}, mirrored
        )

    def test_loaded_modules_never_include_forbidden_surfaces(self) -> None:
        # money and trust load transitively through the DECLARED merged
        # dependencies (src.safety risk classes are typed money-domain
        # amounts; src.evidence attestations bind trust principals) —
        # that is the approved WORK-017/WORK-018 design, and DIRECT
        # imports of those roots remain forbidden by the AST boundary
        # test. What must never load here are the authoritative ledger
        # surface and the unmerged wave-5 sibling surfaces.
        #
        # The check runs in an ISOLATED SUBPROCESS so it measures the
        # extension domain's own transitive import closure, never the
        # residue of whatever sibling suites ran earlier in this process
        # (order-robust by construction).
        probe = (
            "import sys\n"
            "from src.extensions import ExtensionRuntime, CodeRepository\n"
            "runtime = ExtensionRuntime(\n"
            "    environment_id='env/probe',\n"
            "    domain_id='domain/extensions',\n"
            "    environment_mode='simulation',\n"
            "    code_repository=CodeRepository(),\n"
            ")\n"
            "roots = sorted({name.split('.')[1] for name in sys.modules"
            " if name.startswith('src.')})\n"
            "print(','.join(roots))\n"
        )
        completed = subprocess.run(
            [sys.executable, "-c", probe],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).resolve().parents[2]),
            check=True,
        )
        loaded = set(completed.stdout.strip().split(","))
        self.assertNotIn("", loaded)
        self.assertIn("extensions", loaded)
        # money and trust load transitively through the declared
        # dependency contracts (src.safety risk classes carry typed money
        # amounts; src.evidence attestations bind trust principals) — the
        # approved WORK-017/WORK-018 design.
        self.assertEqual(
            loaded,
            {
                "core",
                "extensions",
                "transition",
                "capability",
                "safety",
                "evidence",
                "simulation",
                "money",
                "trust",
            },
        )
        for root in (
            "value",
            "intent",
            "market",
            "liquidity",
            "reservation",
            "interoperability",
            "integration",
            "compiler",
            "execution",
            "agents",
            "data",
        ):
            self.assertNotIn(root, loaded)


# ---------------------------------------------------------------------------
# 2. versions and dependency bounds
# ---------------------------------------------------------------------------


class VersionBoundTests(unittest.TestCase):
    def test_parse_version_accepts_triplets(self) -> None:
        self.assertEqual(parse_version("1.2.3"), (1, 2, 3))
        self.assertEqual(parse_version("0.0.1"), (0, 0, 1))

    def test_parse_version_fails_closed_on_malformed_values(self) -> None:
        for bad in ("1.2", "1.2.3.4", "v1.2.3", "1.2.x", "", "01.2.3", "1..3"):
            with self.assertRaises(CoreValidationError):
                parse_version(bad)

    def test_version_in_bounds_is_inclusive(self) -> None:
        spec = DependencySpec(
            extension_id="extension/dep", min_version="1.0.0", max_version="2.0.0"
        )
        self.assertTrue(version_in_bounds("1.0.0", spec))
        self.assertTrue(version_in_bounds("2.0.0", spec))
        self.assertTrue(version_in_bounds("1.5.0", spec))
        self.assertFalse(version_in_bounds("0.9.9", spec))
        self.assertFalse(version_in_bounds("2.0.1", spec))

    def test_version_bounds_may_be_one_sided(self) -> None:
        min_only = DependencySpec(
            extension_id="extension/dep", min_version="1.0.0", max_version=None
        )
        max_only = DependencySpec(
            extension_id="extension/dep", min_version=None, max_version="2.0.0"
        )
        self.assertTrue(version_in_bounds("9.9.9", min_only))
        self.assertTrue(version_in_bounds("0.0.1", max_only))
        self.assertFalse(version_in_bounds("0.9.0", min_only))

    def test_dependency_spec_rejects_malformed_bounds(self) -> None:
        with self.assertRaises(CoreValidationError):
            DependencySpec(extension_id="extension/dep", min_version="1.2", max_version=None)
        with self.assertRaises(CoreValidationError):
            DependencySpec(extension_id="extension/dep", min_version=None, max_version="x")
        with self.assertRaises(CoreValidationError):
            DependencySpec(extension_id="extension/", min_version=None, max_version=None)

    def test_dependency_bound_inversion_fails_closed(self) -> None:
        with self.assertRaises(CoreValidationError):
            DependencySpec(
                extension_id="extension/dep", min_version="2.0.0", max_version="1.0.0"
            )


# ---------------------------------------------------------------------------
# 3. manifest contract
# ---------------------------------------------------------------------------


class ManifestContractTests(unittest.TestCase):
    def test_valid_manifest_round_trips_canonically(self) -> None:
        manifest = make_manifest()
        decoded = ExtensionManifest.from_dict(manifest.to_dict())
        self.assertEqual(decoded, manifest)
        self.assertEqual(
            canonical_sha256(decoded.to_record_dict()),
            canonical_sha256(manifest.to_record_dict()),
        )

    def test_manifest_record_dict_carries_every_frozen_field(self) -> None:
        record = make_manifest().to_record_dict()
        self.assertEqual(
            set(record),
            {
                "extension_id",
                "developer",
                "version",
                "code_hash",
                "capabilities_provided",
                "capabilities_required",
                "permissions",
                "dependencies",
                "inputs",
                "outputs",
                "pricing",
                "resource_requirements",
                "authority_class",
                "risk_class",
                "jurisdictions",
                "protocol_versions",
                "schema_versions",
                "simulation_support",
                "production_support",
                "verification",
                "risk_controls",
            },
        )

    def test_manifest_from_dict_rejects_unknown_fields(self) -> None:
        wrapped = make_manifest().to_dict()
        wrapped["record"]["surprise"] = 1
        with self.assertRaises(CoreValidationError):
            ExtensionManifest.from_dict(wrapped)

    def test_manifest_identity_fields_fail_closed(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_manifest(extension_id="payswap/alpha")
        with self.assertRaises(CoreValidationError):
            make_manifest(extension_id="")
        with self.assertRaises(CoreValidationError):
            make_manifest(developer="")
        with self.assertRaises(CoreValidationError):
            make_manifest(version="1.2")
        with self.assertRaises(CoreValidationError):
            make_manifest(code_hash="zz")

    def test_manifest_capabilities_use_the_closed_vocabulary(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_manifest(capabilities_provided=("teleportation",))
        with self.assertRaises(CoreValidationError):
            make_manifest(capabilities_provided=())
        with self.assertRaises(CoreValidationError):
            make_manifest(capabilities_required=("nope",))

    def test_manifest_permissions_fail_closed_on_unknown_values(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_manifest(permissions=("root_access",))

    def test_manifest_rejects_architecture_forbidden_permissions(self) -> None:
        for forbidden in FORBIDDEN_PERMISSIONS:
            with self.assertRaises(CoreValidationError):
                make_manifest(permissions=(forbidden,))
        self.assertEqual(
            FORBIDDEN_PERMISSIONS,
            frozenset(
                {
                    "ledger_write",
                    "finality_modify",
                    "authority_grant",
                    "compliance_bypass",
                    "undeclared_resource_access",
                }
            ),
        )

    def test_manifest_authority_class_must_be_an_extension_tier(self) -> None:
        for tier in ("R0", "R1", "R2", "R3", "R4", "R5"):
            manifest = make_manifest(authority_class=tier)
            self.assertEqual(manifest.authority_class, tier)
        with self.assertRaises(CoreValidationError):
            make_manifest(authority_class="A2")
        with self.assertRaises(CoreValidationError):
            make_manifest(authority_class="R6")

    def test_manifest_risk_class_uses_the_safety_vocabulary(self) -> None:
        self.assertEqual(make_manifest().risk_class, RiskBand.MEDIUM)
        with self.assertRaises(CoreValidationError):
            make_manifest(risk_class="EXTREME")

    def test_manifest_jurisdictions_are_iso_alpha2(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_manifest(jurisdictions=("usa",))
        with self.assertRaises(CoreValidationError):
            make_manifest(jurisdictions=())

    def test_manifest_protocol_versions_must_include_the_frozen_protocol(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_manifest(protocol_versions=("v0.2",))

    def test_manifest_schema_versions_must_include_the_domain_schema(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_manifest(schema_versions=(2,))

    def test_manifest_must_support_at_least_one_environment_class(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_manifest(simulation_support=False, production_support=False)

    def test_manifest_inputs_outputs_use_the_frozen_artifact_kinds(self) -> None:
        self.assertEqual(
            {kind.value for kind in ExtensionArtifactKind},
            {
                "demand_signal",
                "route_proposal",
                "quote_set",
                "risk_assessment",
                "compliance_proof",
                "attestation",
                "execution_adapter",
                "settlement_instruction",
            },
        )
        with self.assertRaises(CoreValidationError):
            make_manifest(inputs=("wish",))
        with self.assertRaises(CoreValidationError):
            make_manifest(outputs=())

    def test_manifest_pricing_models_are_validated(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_manifest(
                pricing=PricingSpec(
                    model=PricingModel.REVENUE_SHARE,
                    amount_minor=5,
                    asset="USD",
                    share_bps=1000,
                )
            )
        with self.assertRaises(CoreValidationError):
            make_manifest(
                pricing=PricingSpec(
                    model=PricingModel.REVENUE_SHARE,
                    amount_minor=0,
                    asset="USD",
                    share_bps=10001,
                )
            )
        with self.assertRaises(CoreValidationError):
            make_manifest(
                pricing=PricingSpec(
                    model=PricingModel.FIXED,
                    amount_minor=10,
                    asset="USD",
                    share_bps=1,
                )
            )
        with self.assertRaises(CoreValidationError):
            make_manifest(
                pricing=PricingSpec(
                    model=PricingModel.FIXED,
                    amount_minor=-1,
                    asset="USD",
                    share_bps=0,
                )
            )

    def test_manifest_resource_requirements_are_positive(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_manifest(resource_requirements=ResourceRequirements(0, 1024))
        with self.assertRaises(CoreValidationError):
            make_manifest(resource_requirements=ResourceRequirements(5, 0))

    def test_manifest_tier_gate_requires_verification_above_r0(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_manifest(authority_class="R1", verification=None)

    def test_manifest_tier_gate_requires_collateral_for_reserve_tiers(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_manifest(
                authority_class="R3",
                risk_controls=RiskControls(
                    collateral=None,
                    monitoring_level=MonitoringLevel.STANDARD,
                    risk_limits={"max_single_exposure_minor": 1_000},
                ),
            )

    def test_manifest_tier_gate_enforces_the_minimum_collateral_schedule(self) -> None:
        self.assertEqual(
            TIER_MINIMUM_COLLATERAL_MINOR,
            {"R0": 0, "R1": 0, "R2": 0, "R3": 1_000_000, "R4": 5_000_000, "R5": 25_000_000},
        )
        with self.assertRaises(CoreValidationError):
            make_manifest(
                authority_class="R4",
                risk_controls=RiskControls(
                    collateral=FinancialCollateral(amount_minor=4_999_999, asset="USD"),
                    monitoring_level=MonitoringLevel.ENHANCED,
                    risk_limits={"max_single_exposure_minor": 1_000},
                ),
            )

    def test_manifest_tier_gate_enforces_the_monitoring_schedule(self) -> None:
        self.assertEqual(TIER_MINIMUM_MONITORING["R5"], MonitoringLevel.INTENSIVE)
        with self.assertRaises(CoreValidationError):
            make_manifest(
                authority_class="R5",
                risk_controls=RiskControls(
                    collateral=FinancialCollateral(amount_minor=25_000_000, asset="USD"),
                    monitoring_level=MonitoringLevel.ENHANCED,
                    risk_limits={"max_single_exposure_minor": 1_000},
                ),
            )

    def test_manifest_tier_gate_caps_declared_risk_limits(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_manifest(
                authority_class="R3",
                risk_controls=RiskControls(
                    collateral=FinancialCollateral(amount_minor=1_000_000, asset="USD"),
                    monitoring_level=MonitoringLevel.STANDARD,
                    risk_limits={
                        "max_single_exposure_minor": TIER_MAXIMUM_EXPOSURE_MINOR["R3"] + 1
                    },
                ),
            )

    def test_manifest_high_tier_accepts_the_full_control_package(self) -> None:
        manifest = make_manifest(authority_class="R5")
        self.assertEqual(manifest.authority_class, "R5")

    def test_manifest_envelope_binding(self) -> None:
        manifest = make_manifest()
        envelope = ObjectEnvelope(
            object_id=manifest.extension_id,
            object_type=EXTENSION_MANIFEST_OBJECT_TYPE,
            object_version=1,
            environment_id=ENV_SIM,
            domain_id=DOMAIN,
            schema_version=1,
            protocol_version="v0.1",
            state=ExtensionLifecycleState.DRAFT.value,
            provenance=make_provenance(),
        ).with_integrity_hash()
        bound = manifest.bind_envelope(envelope)
        self.assertEqual(bound.state, ExtensionLifecycleState.DRAFT)
        with self.assertRaises(CoreValidationError):
            manifest.bind_envelope(
                ObjectEnvelope(
                    object_id="extension/other",
                    object_type=EXTENSION_MANIFEST_OBJECT_TYPE,
                    object_version=1,
                    environment_id=ENV_SIM,
                    domain_id=DOMAIN,
                    schema_version=1,
                    protocol_version="v0.1",
                    state="DRAFT",
                    provenance=make_provenance(),
                ).with_integrity_hash()
            )


# ---------------------------------------------------------------------------
# 4. composition artifacts
# ---------------------------------------------------------------------------


class ArtifactTests(unittest.TestCase):
    def test_artifact_round_trips_canonically(self) -> None:
        artifact = make_demand_artifact()
        decoded = ExtensionArtifact.from_dict(artifact.to_dict())
        self.assertEqual(decoded, artifact)

    def test_artifact_digest_is_deterministic(self) -> None:
        self.assertEqual(make_demand_artifact().digest, make_demand_artifact().digest)
        self.assertNotEqual(
            make_demand_artifact(volume_minor=6_000_000).digest,
            make_demand_artifact().digest,
        )

    def test_artifact_rejects_unknown_kinds_and_bad_values(self) -> None:
        with self.assertRaises(CoreValidationError):
            ExtensionArtifact(
                artifact_id="x",
                kind="wish",
                schema_version=1,
                producer="extension/p",
                payload=(),
                provenance=make_provenance(),
                expires_at=T_EXPIRY,
                confidence_bps=1,
                dependencies=(),
                risk_band=RiskBand.LOW,
            )
        with self.assertRaises(CoreValidationError):
            make_demand_artifact(confidence_bps=10001)
        with self.assertRaises(CoreValidationError):
            make_demand_artifact(artifact_id="")
        with self.assertRaises(CoreValidationError):
            make_demand_artifact(producer="")
        with self.assertRaises(CoreValidationError):
            make_demand_artifact(expires_at="not-a-time")

    def test_artifact_payload_must_be_canonical(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_demand_artifact(payload=(("volume", 1.5),))

    def test_artifact_from_dict_rejects_unknown_fields(self) -> None:
        record = make_demand_artifact().to_dict()
        record["extra"] = 1
        with self.assertRaises(CoreValidationError):
            ExtensionArtifact.from_dict(record)


# ---------------------------------------------------------------------------
# 5. lifecycle machine
# ---------------------------------------------------------------------------


class LifecycleMachineTests(unittest.TestCase):
    def test_lifecycle_table_covers_exactly_the_frozen_states(self) -> None:
        self.assertEqual(len(ExtensionLifecycleState), 13)
        self.assertEqual(
            [state.value for state in ExtensionLifecycleState],
            [
                "DRAFT",
                "SANDBOX",
                "TESTED",
                "SUBMITTED",
                "SECURITY_REVIEW",
                "POLICY_REVIEW",
                "PUBLISHED",
                "INSTALLED",
                "ACTIVE",
                "DEGRADED",
                "SUSPENDED",
                "DEPRECATED",
                "ARCHIVED",
            ],
        )
        self.assertEqual(set(LIFECYCLE_TRANSITIONS), set(ExtensionLifecycleState))

    def test_the_frozen_chain_is_walkable(self) -> None:
        chain = [state.value for state in ExtensionLifecycleState]
        for before, after in zip(chain, chain[1:]):
            self.assertIn(
                after,
                {s.value for s in LIFECYCLE_TRANSITIONS[ExtensionLifecycleState(before)]},
            )

    def test_manifest_and_instance_state_sets_partition_the_lifecycle(self) -> None:
        self.assertEqual(
            MANIFEST_LIFECYCLE_STATES,
            frozenset(
                {
                    ExtensionLifecycleState.DRAFT,
                    ExtensionLifecycleState.SANDBOX,
                    ExtensionLifecycleState.TESTED,
                    ExtensionLifecycleState.SUBMITTED,
                    ExtensionLifecycleState.SECURITY_REVIEW,
                    ExtensionLifecycleState.POLICY_REVIEW,
                    ExtensionLifecycleState.PUBLISHED,
                    ExtensionLifecycleState.DEPRECATED,
                    ExtensionLifecycleState.ARCHIVED,
                }
            ),
        )
        self.assertEqual(
            INSTANCE_LIFECYCLE_STATES,
            frozenset(
                {
                    ExtensionLifecycleState.INSTALLED,
                    ExtensionLifecycleState.ACTIVE,
                    ExtensionLifecycleState.DEGRADED,
                    ExtensionLifecycleState.SUSPENDED,
                    ExtensionLifecycleState.DEPRECATED,
                    ExtensionLifecycleState.ARCHIVED,
                }
            ),
        )
        self.assertEqual(
            MANIFEST_LIFECYCLE_STATES | INSTANCE_LIFECYCLE_STATES,
            set(ExtensionLifecycleState),
        )

    def test_resolve_transition_fails_closed_on_unknown_edges(self) -> None:
        with self.assertRaises(CoreValidationError):
            resolve_lifecycle_transition("activate", ExtensionLifecycleState.DRAFT)
        with self.assertRaises(CoreValidationError):
            resolve_lifecycle_transition("publish", ExtensionLifecycleState.DRAFT)
        with self.assertRaises(CoreValidationError):
            resolve_lifecycle_transition("resume", ExtensionLifecycleState.DRAFT)
        with self.assertRaises(CoreValidationError):
            resolve_lifecycle_transition("deprecate", ExtensionLifecycleState.ARCHIVED)
        with self.assertRaises(CoreValidationError):
            resolve_lifecycle_transition("archive", ExtensionLifecycleState.ARCHIVED)

    def test_resolve_transition_knows_the_review_pipeline(self) -> None:
        self.assertEqual(
            resolve_lifecycle_transition("submit", ExtensionLifecycleState.DRAFT),
            ExtensionLifecycleState.SANDBOX,
        )
        self.assertEqual(
            resolve_lifecycle_transition("certify", ExtensionLifecycleState.SANDBOX),
            ExtensionLifecycleState.TESTED,
        )
        self.assertEqual(
            resolve_lifecycle_transition("submit", ExtensionLifecycleState.TESTED),
            ExtensionLifecycleState.SUBMITTED,
        )
        self.assertEqual(
            resolve_lifecycle_transition("approve", ExtensionLifecycleState.SUBMITTED),
            ExtensionLifecycleState.SECURITY_REVIEW,
        )
        self.assertEqual(
            resolve_lifecycle_transition("approve", ExtensionLifecycleState.SECURITY_REVIEW),
            ExtensionLifecycleState.POLICY_REVIEW,
        )
        self.assertEqual(
            resolve_lifecycle_transition("reject", ExtensionLifecycleState.POLICY_REVIEW),
            ExtensionLifecycleState.SANDBOX,
        )
        self.assertEqual(
            resolve_lifecycle_transition("publish", ExtensionLifecycleState.POLICY_REVIEW),
            ExtensionLifecycleState.PUBLISHED,
        )


# ---------------------------------------------------------------------------
# 6. dependency DAG
# ---------------------------------------------------------------------------


class DependencyGraphTests(unittest.TestCase):
    def _manifests(self):
        base = make_manifest(extension_id="extension/base", code_hash=BETA_HASH)
        middle = make_manifest(
            extension_id="extension/middle",
            code_hash=BETA_HASH,
            dependencies=(DependencySpec("extension/base", "1.0.0", "1.9.9"),),
        )
        top = make_manifest(
            extension_id="extension/top",
            dependencies=(
                DependencySpec("extension/middle", "1.0.0", None),
                DependencySpec("extension/base", None, "2.0.0"),
            ),
        )
        return {"extension/base": base, "extension/middle": middle, "extension/top": top}

    def test_linear_graph_builds_with_deterministic_install_order(self) -> None:
        graph = DependencyGraph.build(self._manifests())
        order = graph.install_order()
        self.assertEqual(order, ("extension/base", "extension/middle", "extension/top"))
        self.assertEqual(DependencyGraph.build(self._manifests()).install_order(), order)

    def test_missing_dependency_fails_closed(self) -> None:
        manifests = self._manifests()
        del manifests["extension/base"]
        with self.assertRaises(CoreValidationError) as raised:
            DependencyGraph.build(manifests)
        self.assertIn("missing", str(raised.exception))

    def test_cycle_detection_fails_closed(self) -> None:
        a = make_manifest(
            extension_id="extension/cyc-a",
            dependencies=(DependencySpec("extension/cyc-b", None, None),),
        )
        b = make_manifest(
            extension_id="extension/cyc-b",
            dependencies=(DependencySpec("extension/cyc-a", None, None),),
        )
        with self.assertRaises(CoreValidationError) as raised:
            DependencyGraph.build({"extension/cyc-a": a, "extension/cyc-b": b})
        self.assertIn("cycle", str(raised.exception))

    def test_self_dependency_fails_closed(self) -> None:
        manifest = make_manifest(
            dependencies=(DependencySpec("extension/alpha-route", None, None),)
        )
        with self.assertRaises(CoreValidationError):
            DependencyGraph.build({"extension/alpha-route": manifest})

    def test_version_out_of_bounds_fails_closed(self) -> None:
        manifests = self._manifests()
        manifests["extension/base"] = make_manifest(
            extension_id="extension/base", version="2.0.0", code_hash=BETA_HASH
        )
        with self.assertRaises(CoreValidationError) as raised:
            DependencyGraph.build(manifests)
        self.assertIn("bound", str(raised.exception).lower())

    def test_duplicate_manifest_identity_fails_closed(self) -> None:
        manifests = self._manifests()
        # A second registration of the same extension identity under a
        # different graph key: the identity/key mismatch (a duplicate or
        # inconsistent manifest identity) fails closed.
        manifests["extension/top-duplicate"] = make_manifest(
            extension_id="extension/top"
        )
        with self.assertRaises(CoreValidationError):
            DependencyGraph.build(manifests)

    def test_activation_readiness_requires_active_dependencies(self) -> None:
        graph = DependencyGraph.build(self._manifests())
        graph.require_activation_ready(
            "extension/top",
            {
                "extension/base": parse_version("1.0.0"),
                "extension/middle": parse_version("1.0.0"),
            },
        )
        with self.assertRaises(CoreValidationError):
            graph.require_activation_ready(
                "extension/top", {"extension/base": parse_version("1.0.0")}
            )
        with self.assertRaises(CoreValidationError):
            graph.require_activation_ready(
                "extension/top",
                {
                    "extension/base": parse_version("2.0.0"),
                    "extension/middle": parse_version("1.0.0"),
                },
            )


# ---------------------------------------------------------------------------
# 7. sandbox invocation runtime (pure core)
# ---------------------------------------------------------------------------


class SandboxInvocationTests(unittest.TestCase):
    def _request(self, **overrides) -> InvocationRequest:
        values = {
            "invocation_id": "extension-invocation/alpha-1",
            "capability": ExtensionCapability.ROUTE_PROPOSAL,
            "inputs": (make_demand_artifact(),),
            "resources": (("read_market_data", (("spread_bps", 12),)),),
            "as_of": T2,
        }
        values.update(overrides)
        return InvocationRequest(**values)

    def test_happy_path_invocation_produces_sealed_typed_outputs(self) -> None:
        invocation = execute_sandboxed_invocation(
            manifest=make_manifest(),
            handler=alpha_handler,
            request=self._request(),
            environment_mode=EnvironmentMode.SIMULATION,
            shadowed=False,
        )
        self.assertEqual(invocation.effect_mode, InvocationEffectMode.RECORDED)
        self.assertEqual(invocation.status, "COMPLETED")
        self.assertEqual(len(invocation.output_artifacts), 1)
        self.assertEqual(invocation.output_artifacts[0].kind, ExtensionArtifactKind.ROUTE_PROPOSAL)
        self.assertEqual(invocation.output_artifacts[0].producer, "extension/alpha-route")
        self.assertGreaterEqual(invocation.resource_credits.credits, 1)

    def test_invocation_in_shadow_mode_records_shadowed_outputs(self) -> None:
        invocation = execute_sandboxed_invocation(
            manifest=make_manifest(),
            handler=alpha_handler,
            request=self._request(),
            environment_mode=EnvironmentMode.SHADOW,
            shadowed=True,
        )
        self.assertEqual(invocation.effect_mode, InvocationEffectMode.SHADOWED)

    def test_undeclared_capability_fails_closed(self) -> None:
        with self.assertRaises(CoreValidationError) as raised:
            execute_sandboxed_invocation(
                manifest=make_manifest(),
                handler=alpha_handler,
                request=self._request(capability=ExtensionCapability.QUOTE_PROVISION),
                environment_mode=EnvironmentMode.SIMULATION,
                shadowed=False,
            )
        self.assertIn("undeclared capability", str(raised.exception))

    def test_undeclared_input_kind_fails_closed(self) -> None:
        with self.assertRaises(CoreValidationError):
            execute_sandboxed_invocation(
                manifest=make_manifest(inputs=(ExtensionArtifactKind.QUOTE_SET,)),
                handler=alpha_handler,
                request=self._request(),
                environment_mode=EnvironmentMode.SIMULATION,
                shadowed=False,
            )

    def test_undeclared_output_kind_fails_closed(self) -> None:
        def bad_handler(context: SandboxContext):
            return (
                ExtensionArtifact(
                    artifact_id="extension-artifact/bad",
                    kind=ExtensionArtifactKind.SETTLEMENT_INSTRUCTION,
                    schema_version=1,
                    producer=context.extension_id,
                    payload=(("oops", 1),),
                    provenance=make_provenance(),
                    expires_at=T_EXPIRY,
                    confidence_bps=100,
                    dependencies=(),
                    risk_band=RiskBand.LOW,
                ),
            )

        with self.assertRaises(CoreValidationError) as raised:
            execute_sandboxed_invocation(
                manifest=make_manifest(),
                handler=bad_handler,
                request=self._request(),
                environment_mode=EnvironmentMode.SIMULATION,
                shadowed=False,
            )
        self.assertIn("undeclared output", str(raised.exception))

    def test_output_producer_must_be_the_invoked_extension(self) -> None:
        def impostor_handler(context: SandboxContext):
            return (
                ExtensionArtifact(
                    artifact_id="extension-artifact/impostor",
                    kind=ExtensionArtifactKind.ROUTE_PROPOSAL,
                    schema_version=1,
                    producer="extension/someone-else",
                    payload=(("corridor", "US->GH"),),
                    provenance=make_provenance(),
                    expires_at=T_EXPIRY,
                    confidence_bps=100,
                    dependencies=(),
                    risk_band=RiskBand.LOW,
                ),
            )

        with self.assertRaises(CoreValidationError):
            execute_sandboxed_invocation(
                manifest=make_manifest(),
                handler=impostor_handler,
                request=self._request(),
                environment_mode=EnvironmentMode.SIMULATION,
                shadowed=False,
            )

    def test_output_schema_version_must_be_declared_by_the_manifest(self) -> None:
        def stale_handler(context: SandboxContext):
            return (
                ExtensionArtifact(
                    artifact_id="extension-artifact/stale",
                    kind=ExtensionArtifactKind.ROUTE_PROPOSAL,
                    schema_version=7,
                    producer=context.extension_id,
                    payload=(("corridor", "US->GH"),),
                    provenance=make_provenance(),
                    expires_at=T_EXPIRY,
                    confidence_bps=100,
                    dependencies=(),
                    risk_band=RiskBand.LOW,
                ),
            )

        with self.assertRaises(CoreValidationError):
            execute_sandboxed_invocation(
                manifest=make_manifest(),
                handler=stale_handler,
                request=self._request(),
                environment_mode=EnvironmentMode.SIMULATION,
                shadowed=False,
            )

    def test_expired_input_artifact_fails_closed(self) -> None:
        expired = make_demand_artifact(expires_at="2026-09-02T00:00:01Z")
        with self.assertRaises(CoreValidationError) as raised:
            execute_sandboxed_invocation(
                manifest=make_manifest(),
                handler=alpha_handler,
                request=self._request(inputs=(expired,)),
                environment_mode=EnvironmentMode.SIMULATION,
                shadowed=False,
            )
        self.assertIn("expired", str(raised.exception))

    def test_undeclared_resource_access_fails_closed(self) -> None:
        with self.assertRaises(CoreValidationError) as raised:
            execute_sandboxed_invocation(
                manifest=make_manifest(),
                handler=alpha_handler,
                request=self._request(
                    resources=(("observe_protocol_state", (("peek", 1),)),)
                ),
                environment_mode=EnvironmentMode.SIMULATION,
                shadowed=False,
            )
        self.assertIn("undeclared resource", str(raised.exception))

    def test_output_artifact_bytes_are_bounded_by_resource_requirements(self) -> None:
        manifest = make_manifest(resource_requirements=ResourceRequirements(5, 8))
        with self.assertRaises(CoreValidationError) as raised:
            execute_sandboxed_invocation(
                manifest=manifest,
                handler=alpha_handler,
                request=self._request(),
                environment_mode=EnvironmentMode.SIMULATION,
                shadowed=False,
            )
        self.assertIn("artifact bytes", str(raised.exception))

    def test_output_ids_may_not_collide_with_input_ids(self) -> None:
        def colliding_handler(context: SandboxContext):
            source = context.inputs[0]
            return (
                ExtensionArtifact(
                    artifact_id=source.artifact_id,
                    kind=ExtensionArtifactKind.ROUTE_PROPOSAL,
                    schema_version=1,
                    producer=context.extension_id,
                    payload=(("corridor", "US->GH"),),
                    provenance=make_provenance(),
                    expires_at=T_EXPIRY,
                    confidence_bps=100,
                    dependencies=(),
                    risk_band=RiskBand.LOW,
                ),
            )

        with self.assertRaises(CoreValidationError) as raised:
            execute_sandboxed_invocation(
                manifest=make_manifest(),
                handler=colliding_handler,
                request=self._request(),
                environment_mode=EnvironmentMode.SIMULATION,
                shadowed=False,
            )
        self.assertIn("collide", str(raised.exception))

    def test_sandbox_context_exposes_exactly_the_frozen_declared_fields(self) -> None:
        field_names = tuple(field.name for field in dataclasses.fields(SandboxContext))
        self.assertEqual(field_names, SANDBOX_CONTEXT_FIELDS)
        self.assertEqual(
            SANDBOX_CONTEXT_FIELDS,
            (
                "invocation_id",
                "extension_id",
                "capability",
                "inputs",
                "resources",
                "as_of",
                "environment_mode",
                "effect_mode",
            ),
        )
        for forbidden_attribute in ("store", "engine", "view", "ledger", "kernel"):
            self.assertNotIn(forbidden_attribute, field_names)

    def test_sandbox_context_rejects_ambient_authority_arguments(self) -> None:
        with self.assertRaises(TypeError):
            SandboxContext(
                invocation_id="i",
                extension_id="extension/alpha-route",
                capability=ExtensionCapability.ROUTE_PROPOSAL,
                inputs=(),
                resources=(),
                as_of=T2,
                environment_mode=EnvironmentMode.SIMULATION,
                effect_mode=InvocationEffectMode.RECORDED,
                store=object(),
            )

    def test_handler_exceptions_fail_closed_without_partial_state(self) -> None:
        def failing_handler(context: SandboxContext):
            raise CoreValidationError("extension code failed deterministically")

        with self.assertRaises(CoreValidationError):
            execute_sandboxed_invocation(
                manifest=make_manifest(),
                handler=failing_handler,
                request=self._request(),
                environment_mode=EnvironmentMode.SIMULATION,
                shadowed=False,
            )

    def test_empty_output_fails_closed(self) -> None:
        with self.assertRaises(CoreValidationError):
            execute_sandboxed_invocation(
                manifest=make_manifest(),
                handler=lambda context: (),
                request=self._request(),
                environment_mode=EnvironmentMode.SIMULATION,
                shadowed=False,
            )

    def test_duplicate_input_artifact_ids_fail_closed(self) -> None:
        duplicate = make_demand_artifact()
        with self.assertRaises(CoreValidationError):
            execute_sandboxed_invocation(
                manifest=make_manifest(),
                handler=alpha_handler,
                request=self._request(inputs=(duplicate, duplicate)),
                environment_mode=EnvironmentMode.SIMULATION,
                shadowed=False,
            )


# ---------------------------------------------------------------------------
# 8. kernel-bound runtime: manifest lifecycle
# ---------------------------------------------------------------------------


class KernelManifestLifecycleTests(unittest.TestCase):
    def test_full_marketplace_pipeline_through_the_kernel(self) -> None:
        runtime = make_runtime()
        manifest_id = register_manifest(runtime)
        drive_to_published(runtime, manifest_id)
        envelope = runtime.store.get(manifest_id)
        self.assertEqual(envelope.state, "PUBLISHED")
        self.assertEqual(envelope.object_type, EXTENSION_MANIFEST_OBJECT_TYPE)
        events = [entry.event.event_type for entry in runtime.engine.journal]
        self.assertEqual(
            events,
            [
                "extension/registered",
                "extension/submitted",
                "extension/invoked",
                "extension/certified",
                "extension/submitted",
                "extension/approved",
                "extension/approved",
                "extension/published",
            ],
        )

    def test_register_requires_a_valid_manifest(self) -> None:
        runtime = make_runtime()
        manifest = make_manifest()
        record = manifest.to_record_dict()
        record.pop("permissions")
        result = runtime.submit(
            cmd(
                "cmd/bad-register",
                "extension/register",
                (manifest.extension_id,),
                {"manifest": record},
                expected_versions=((manifest.extension_id, 0),),
            )
        )
        self.assertIs(result.outcome, Outcome.REJECTED)
        self.assertIs(result.reason, RejectionReason.POLICY_REJECTED)

    def test_register_fails_closed_on_code_not_in_the_repository(self) -> None:
        runtime = make_runtime()
        manifest = make_manifest(code_hash="d" * 64)
        result = runtime.submit(
            cmd(
                "cmd/unknown-code",
                "extension/register",
                (manifest.extension_id,),
                {"manifest": manifest.to_record_dict()},
                expected_versions=((manifest.extension_id, 0),),
            )
        )
        self.assertIs(result.outcome, Outcome.REJECTED)
        self.assertIn("code", (result.detail or "").lower())

    def test_register_fails_closed_on_cyclic_dependencies(self) -> None:
        runtime = make_runtime()
        first = make_manifest(
            extension_id="extension/cyc-1",
            dependencies=(DependencySpec("extension/cyc-2", None, None),),
        )
        register_manifest(runtime, first)
        second = make_manifest(
            extension_id="extension/cyc-2",
            dependencies=(DependencySpec("extension/cyc-1", None, None),),
        )
        result = runtime.submit(
            cmd(
                "cmd/register-cyc-2",
                "extension/register",
                (second.extension_id,),
                {"manifest": second.to_record_dict()},
                expected_versions=((second.extension_id, 0),),
            )
        )
        self.assertIs(result.outcome, Outcome.REJECTED)
        self.assertIn("cycle", (result.detail or ""))

    def test_invalid_lifecycle_edge_fails_closed(self) -> None:
        runtime = make_runtime()
        manifest_id = register_manifest(runtime)
        result = runtime.submit(
            cmd("cmd/premature-publish", "extension/publish", (manifest_id,), {})
        )
        self.assertIs(result.outcome, Outcome.REJECTED)
        self.assertIn("publish", (result.detail or ""))

    def test_reject_path_returns_a_reviewed_manifest_to_the_sandbox(self) -> None:
        runtime = make_runtime()
        manifest_id = register_manifest(runtime)
        drive_to_published(runtime, manifest_id)
        # PUBLISHED manifests cannot be rejected back (they are past review).
        result = runtime.submit(
            cmd("cmd/reject-published", "extension/reject", (manifest_id,), {"reason": "x"})
        )
        self.assertIs(result.outcome, Outcome.REJECTED)
        # a fresh manifest driven into POLICY_REVIEW and rejected there
        manifest_id2 = register_manifest(
            runtime,
            make_manifest(extension_id="extension/beta-route", code_hash=BETA_HASH),
            command_id="cmd/register-beta",
        )
        runtime.submit(cmd("cmd/beta-submit", "extension/submit", (manifest_id2,), {}))
        sandbox_invoke_once(runtime, manifest_id2, "extension-invocation/beta-sandbox-1")
        runtime.submit(cmd("cmd/beta-certify", "extension/certify", (manifest_id2,), {}))
        runtime.submit(cmd("cmd/beta-submit2", "extension/submit", (manifest_id2,), {}))
        runtime.submit(cmd("cmd/beta-approve1", "extension/approve", (manifest_id2,), {}))
        runtime.submit(cmd("cmd/beta-approve2", "extension/approve", (manifest_id2,), {}))
        result = runtime.submit(
            cmd("cmd/beta-reject", "extension/reject", (manifest_id2,), {"reason": "policy gap"})
        )
        self.assertIs(result.outcome, Outcome.ACCEPTED)
        self.assertEqual(runtime.store.get(manifest_id2).state, "SANDBOX")

    def test_reject_requires_an_explicit_reason(self) -> None:
        runtime = make_runtime()
        manifest_id = register_manifest(runtime)
        runtime.submit(cmd("cmd/r-submit", "extension/submit", (manifest_id,), {}))
        result = runtime.submit(cmd("cmd/r-reject", "extension/reject", (manifest_id,), {}))
        self.assertIs(result.outcome, Outcome.REJECTED)

    def test_certify_requires_sandbox_invocation_evidence(self) -> None:
        runtime = make_runtime()
        manifest_id = register_manifest(runtime)
        runtime.submit(cmd("cmd/submit-1", "extension/submit", (manifest_id,), {}))
        result = runtime.submit(cmd("cmd/certify-1", "extension/certify", (manifest_id,), {}))
        self.assertIs(result.outcome, Outcome.REJECTED)
        self.assertIn("evidence", (result.detail or "").lower())
        sandbox_invoke_once(runtime, manifest_id, "extension-invocation/sandbox-1")
        result = runtime.submit(cmd("cmd/certify-2", "extension/certify", (manifest_id,), {}))
        self.assertIs(result.outcome, Outcome.ACCEPTED)
        self.assertEqual(runtime.store.get(manifest_id).state, "TESTED")

    def test_deprecate_and_archive_terminal_paths(self) -> None:
        runtime = make_runtime()
        manifest_id = register_manifest(runtime)
        runtime.submit(cmd("cmd/dep-1", "extension/deprecate", (manifest_id,), {}))
        self.assertEqual(runtime.store.get(manifest_id).state, "DEPRECATED")
        runtime.submit(cmd("cmd/arch-1", "extension/archive", (manifest_id,), {}))
        self.assertEqual(runtime.store.get(manifest_id).state, "ARCHIVED")
        result = runtime.submit(cmd("cmd/arch-2", "extension/archive", (manifest_id,), {}))
        self.assertIs(result.outcome, Outcome.REJECTED)


class KernelDisciplineTests(unittest.TestCase):
    def test_unknown_command_type_fails_closed(self) -> None:
        runtime = make_runtime()
        manifest_id = register_manifest(runtime)
        result = runtime.submit(cmd("cmd/unknown", "extension/teleport", (manifest_id,), {}))
        self.assertIs(result.outcome, Outcome.REJECTED)
        self.assertIs(result.reason, RejectionReason.UNKNOWN_COMMAND_TYPE)

    def test_environment_mismatch_is_rejected(self) -> None:
        runtime = make_runtime()
        manifest = make_manifest()
        result = runtime.submit(
            cmd(
                "cmd/other-env",
                "extension/register",
                (manifest.extension_id,),
                {"manifest": manifest.to_record_dict()},
                environment_id="env/other",
                expected_versions=((manifest.extension_id, 0),),
            )
        )
        self.assertIs(result.outcome, Outcome.REJECTED)
        self.assertIs(result.reason, RejectionReason.ENVIRONMENT_MISMATCH)

    def test_unauthorized_actor_is_rejected(self) -> None:
        runtime = make_runtime()
        manifest = make_manifest()
        result = runtime.submit(
            cmd(
                "cmd/intruder",
                "extension/register",
                (manifest.extension_id,),
                {"manifest": manifest.to_record_dict()},
                actor="principal/intruder",
                expected_versions=((manifest.extension_id, 0),),
            )
        )
        self.assertIs(result.outcome, Outcome.REJECTED)
        self.assertIs(result.reason, RejectionReason.UNAUTHORIZED)

    def test_expected_version_conflict_is_rejected(self) -> None:
        runtime = make_runtime()
        manifest_id = register_manifest(runtime)
        result = runtime.submit(
            cmd(
                "cmd/stale",
                "extension/submit",
                (manifest_id,),
                {},
                expected_versions=((manifest_id, 5),),
            )
        )
        self.assertIs(result.outcome, Outcome.REJECTED)
        self.assertIs(result.reason, RejectionReason.VERSION_CONFLICT)

    def test_duplicate_commands_converge(self) -> None:
        runtime = make_runtime()
        manifest = make_manifest()
        first = runtime.submit(
            cmd(
                "cmd/dup-1",
                "extension/register",
                (manifest.extension_id,),
                {"manifest": manifest.to_record_dict()},
                expected_versions=((manifest.extension_id, 0),),
            )
        )
        second = runtime.submit(
            cmd(
                "cmd/dup-1",
                "extension/register",
                (manifest.extension_id,),
                {"manifest": manifest.to_record_dict()},
                expected_versions=((manifest.extension_id, 0),),
            )
        )
        self.assertIs(first.outcome, Outcome.ACCEPTED)
        self.assertIs(second.outcome, Outcome.DUPLICATE)
        self.assertEqual(second.event, first.event)

    def test_rejected_commands_leave_the_domain_state_byte_identical(self) -> None:
        runtime = make_runtime()
        manifest_id = register_manifest(runtime)
        drive_to_published(runtime, manifest_id)
        before = runtime.domain_state_digest()
        runtime.submit(cmd("cmd/bad-1", "extension/teleport", (manifest_id,), {}))
        runtime.submit(cmd("cmd/bad-2", "extension/publish", (manifest_id,), {}))
        runtime.submit(
            cmd("cmd/bad-3", "extension/reject", (manifest_id,), {"reason": "x"})
        )
        after = runtime.domain_state_digest()
        self.assertEqual(before, after)

    def test_every_accepted_command_advances_the_immutable_journal(self) -> None:
        runtime = make_runtime()
        manifest_id = register_manifest(runtime)
        drive_to_published(runtime, manifest_id)
        journal = runtime.engine.journal
        self.assertEqual(len(journal), 8)
        for entry in journal:
            self.assertEqual(entry.event.environment_id, ENV_SIM)
            self.assertTrue(entry.event.event_type.startswith("extension/"))

    def test_domain_projection_is_reproducible_from_the_journal(self) -> None:
        runtime = make_runtime()
        manifest_id = register_manifest(runtime)
        drive_to_published(runtime, manifest_id)
        instance_id = install_instance(runtime, manifest_id)
        activate_instance(runtime, instance_id)
        invoke_once(runtime, instance_id, "extension-invocation/live-1")
        live = runtime.domain_state_digest()
        rebuilt = runtime.rebuild_from_journal()
        self.assertEqual(rebuilt, live)


# ---------------------------------------------------------------------------
# 9. grants, installation and activation
# ---------------------------------------------------------------------------


class InstallationGrantTests(unittest.TestCase):
    def _published_runtime(self) -> tuple[ExtensionRuntime, str]:
        runtime = make_runtime()
        manifest_id = register_manifest(runtime)
        drive_to_published(runtime, manifest_id)
        return runtime, manifest_id

    def test_install_creates_instance_and_grant_objects(self) -> None:
        runtime, manifest_id = self._published_runtime()
        instance_id = install_instance(runtime, manifest_id)
        instance = runtime.instance(instance_id)
        self.assertEqual(instance.state, ExtensionLifecycleState.INSTALLED)
        self.assertEqual(instance.manifest_id, manifest_id)
        self.assertEqual(instance.extension_id, "extension/alpha-route")
        self.assertFalse(instance.shadow)
        self.assertEqual(instance.envelope.object_type, EXTENSION_INSTANCE_OBJECT_TYPE)
        grant = runtime.grant("extension-grant/alpha-route-route")
        self.assertEqual(grant.capability, ExtensionCapability.ROUTE_PROPOSAL)
        self.assertEqual(grant.instance_id, instance_id)
        self.assertEqual(grant.envelope.object_type, CAPABILITY_GRANT_OBJECT_TYPE)
        self.assertEqual(grant.budget.max_invocations, 5)

    def test_install_requires_support_for_the_runtime_environment_class(self) -> None:
        production = make_runtime(
            environment_id=ENV_PROD, mode=EnvironmentMode.PRODUCTION
        )
        manifest = make_manifest(production_support=False)
        manifest_id = register_manifest(
            production, manifest, command_id="cmd/p-register"
        )
        drive_to_published(production, manifest_id, base_id="cmd/p")
        result = production.submit(
            install_command(
                "extension-instance/alpha-route@prod",
                manifest_id,
                environment_id=ENV_PROD,
                command_id="cmd/p-install",
            )
        )
        self.assertIs(result.outcome, Outcome.REJECTED)
        self.assertIn("production", (result.detail or ""))

    def test_install_requires_resolved_published_dependencies(self) -> None:
        runtime = make_runtime()
        dependent = make_manifest(
            extension_id="extension/dependent",
            dependencies=(DependencySpec("extension/missing", "1.0.0", None),),
        )
        register_manifest(runtime, dependent)
        result = runtime.submit(
            install_command(
                "extension-instance/dependent@sim",
                "extension/dependent",
                (grant_payload(grant_id="extension-grant/dependent-route"),),
                command_id="cmd/install-dep",
            )
        )
        self.assertIs(result.outcome, Outcome.REJECTED)
        self.assertIn("missing", (result.detail or ""))

    def test_install_requires_the_dependency_to_be_published(self) -> None:
        runtime = make_runtime()
        register_manifest(runtime, make_manifest(extension_id="extension/base", code_hash=BETA_HASH))
        # base stays in DRAFT: the dependency is registered but not published
        dependent = make_manifest(
            extension_id="extension/dependent",
            dependencies=(DependencySpec("extension/base", "1.0.0", None),),
        )
        register_manifest(runtime, dependent, command_id="cmd/register-dep")
        drive_to_published(runtime, "extension/dependent", base_id="cmd/dep")
        result = runtime.submit(
            install_command(
                "extension-instance/dependent@sim",
                "extension/dependent",
                (grant_payload(grant_id="extension-grant/dependent-route"),),
                command_id="cmd/install-dep",
            )
        )
        self.assertIs(result.outcome, Outcome.REJECTED)
        self.assertIn("published", (result.detail or ""))

    def test_install_rejects_grants_for_undeclared_capabilities(self) -> None:
        runtime, manifest_id = self._published_runtime()
        result = runtime.submit(
            install_command(
                "extension-instance/x@sim",
                manifest_id,
                (grant_payload(capability="attestation"),),
                command_id="cmd/install-bad-grant",
            )
        )
        self.assertIs(result.outcome, Outcome.REJECTED)

    def test_install_requires_at_least_one_grant(self) -> None:
        runtime, manifest_id = self._published_runtime()
        result = runtime.submit(
            install_command(
                "extension-instance/y@sim", manifest_id, (), command_id="cmd/install-no-grants"
            )
        )
        self.assertIs(result.outcome, Outcome.REJECTED)

    def test_grant_payload_validation_fails_closed(self) -> None:
        runtime, manifest_id = self._published_runtime()
        bad_grant = grant_payload()
        bad_grant["budget"] = {"max_invocations": 0, "window_start": T0, "window_end": T4}
        result = runtime.submit(
            install_command(
                "extension-instance/z@sim",
                manifest_id,
                (bad_grant,),
                command_id="cmd/install-zero-budget",
            )
        )
        self.assertIs(result.outcome, Outcome.REJECTED)

    def test_activation_requires_active_dependencies(self) -> None:
        runtime = make_runtime()
        register_manifest(
            runtime, make_manifest(extension_id="extension/base", code_hash=BETA_HASH)
        )
        drive_to_published(runtime, "extension/base", base_id="cmd/base")
        dependent = make_manifest(
            extension_id="extension/dependent",
            dependencies=(DependencySpec("extension/base", "1.0.0", None),),
        )
        register_manifest(runtime, dependent, command_id="cmd/register-dependent")
        drive_to_published(runtime, "extension/dependent", base_id="cmd/dep")
        install_instance(
            runtime,
            "extension/dependent",
            "extension-instance/dependent@sim",
            command_id="cmd/install-dependent",
            grants=(grant_payload(grant_id="extension-grant/dependent-route"),),
        )
        result = activate_instance(
            runtime,
            "extension-instance/dependent@sim",
            command_id="cmd/activate-dependent",
        )
        self.assertIs(result.outcome, Outcome.REJECTED)
        self.assertIn("dependency", (result.detail or ""))


# ---------------------------------------------------------------------------
# 10. instance lifecycle and invocation through the kernel
# ---------------------------------------------------------------------------


class KernelInvocationTests(unittest.TestCase):
    def _active_runtime(self) -> tuple[ExtensionRuntime, str, str]:
        runtime = make_runtime()
        manifest_id = register_manifest(runtime)
        drive_to_published(runtime, manifest_id)
        instance_id = install_instance(runtime, manifest_id)
        activate_instance(runtime, instance_id)
        return runtime, manifest_id, instance_id

    def test_activated_instance_is_active_and_invocable(self) -> None:
        runtime, manifest_id, instance_id = self._active_runtime()
        self.assertEqual(runtime.instance(instance_id).state, ExtensionLifecycleState.ACTIVE)
        result = invoke_once(runtime, instance_id, "extension-invocation/live-1")
        self.assertIs(result.outcome, Outcome.ACCEPTED)
        invocation = runtime.invocation("extension-invocation/live-1")
        self.assertEqual(invocation.status, "COMPLETED")
        self.assertEqual(invocation.effect_mode, InvocationEffectMode.RECORDED)
        self.assertEqual(invocation.environment_mode, EnvironmentMode.SIMULATION)
        self.assertEqual(invocation.target_id, instance_id)
        self.assertEqual(
            invocation.envelope.object_type, EXTENSION_INVOCATION_OBJECT_TYPE
        )

    def test_invocation_requires_an_active_instance(self) -> None:
        runtime = make_runtime()
        manifest_id = register_manifest(runtime)
        drive_to_published(runtime, manifest_id)
        instance_id = install_instance(runtime, manifest_id)  # INSTALLED, not ACTIVE
        result = invoke_once(runtime, instance_id, "extension-invocation/too-early")
        self.assertIs(result.outcome, Outcome.REJECTED)
        self.assertIn("active", (result.detail or "").lower())

    def test_suspended_instance_invocation_fails_closed(self) -> None:
        runtime, _, instance_id = self._active_runtime()
        runtime.submit(cmd("cmd/suspend-1", "extension/suspend", (instance_id,), {}))
        self.assertEqual(runtime.store.get(instance_id).state, "SUSPENDED")
        result = invoke_once(runtime, instance_id, "extension-invocation/while-suspended")
        self.assertIs(result.outcome, Outcome.REJECTED)

    def test_instance_lifecycle_walks_the_frozen_tail(self) -> None:
        runtime, _, instance_id = self._active_runtime()
        runtime.submit(cmd("cmd/d1", "extension/degrade", (instance_id,), {}))
        self.assertEqual(runtime.store.get(instance_id).state, "DEGRADED")
        runtime.submit(cmd("cmd/r1", "extension/resume", (instance_id,), {}))
        self.assertEqual(runtime.store.get(instance_id).state, "ACTIVE")
        runtime.submit(cmd("cmd/s1", "extension/suspend", (instance_id,), {}))
        self.assertEqual(runtime.store.get(instance_id).state, "SUSPENDED")
        runtime.submit(cmd("cmd/r2", "extension/resume", (instance_id,), {}))
        self.assertEqual(runtime.store.get(instance_id).state, "ACTIVE")
        runtime.submit(cmd("cmd/d2", "extension/deprecate", (instance_id,), {}))
        self.assertEqual(runtime.store.get(instance_id).state, "DEPRECATED")
        runtime.submit(cmd("cmd/a1", "extension/archive", (instance_id,), {}))
        self.assertEqual(runtime.store.get(instance_id).state, "ARCHIVED")

    def test_invocation_enforces_the_grant_window(self) -> None:
        runtime, _, instance_id = self._active_runtime()
        result = invoke_once(
            runtime,
            instance_id,
            "extension-invocation/late",
            requested_at="2026-12-01T00:00:00Z",
        )
        self.assertIs(result.outcome, Outcome.REJECTED)
        self.assertIn("window", (result.detail or ""))

    def test_invocation_enforces_the_grant_jurisdiction_scope(self) -> None:
        runtime, _, instance_id = self._active_runtime()
        result = invoke_once(
            runtime, instance_id, "extension-invocation/elsewhere", jurisdiction="FR"
        )
        self.assertIs(result.outcome, Outcome.REJECTED)
        self.assertIn("jurisdiction", (result.detail or ""))

    def test_invocation_quota_exhaustion_fails_closed(self) -> None:
        runtime = make_runtime()
        manifest_id = register_manifest(runtime)
        drive_to_published(runtime, manifest_id)
        instance_id = install_instance(runtime, manifest_id)
        activate_instance(runtime, instance_id)
        for index in range(5):
            result = invoke_once(
                runtime, instance_id, f"extension-invocation/quota-{index}"
            )
            self.assertIs(result.outcome, Outcome.ACCEPTED)
        result = invoke_once(runtime, instance_id, "extension-invocation/quota-overflow")
        self.assertIs(result.outcome, Outcome.REJECTED)
        self.assertIn("quota", (result.detail or ""))

    def test_grant_budget_quota_exhaustion_fails_closed(self) -> None:
        # Distinct from the manifest's per-window quota: the covering
        # grant's own budget bounds invocation volume independently, so a
        # generous manifest quota must NOT mask an exhausted grant budget.
        runtime = make_runtime()
        manifest_id = register_manifest(
            runtime,
            make_manifest(
                resource_requirements=make_requirements(
                    max_invocations_per_window=50, max_artifact_bytes=4096
                )
            ),
        )
        drive_to_published(runtime, manifest_id)
        instance_id = install_instance(
            runtime,
            manifest_id,
            grants=(grant_payload(budget_max_invocations=2),),
        )
        activate_instance(runtime, instance_id)
        for index in range(2):
            result = invoke_once(
                runtime, instance_id, f"extension-invocation/budget-{index}"
            )
            self.assertIs(result.outcome, Outcome.ACCEPTED)
        result = invoke_once(
            runtime, instance_id, "extension-invocation/budget-overflow"
        )
        self.assertIs(result.outcome, Outcome.REJECTED)
        self.assertIn("grant budget quota", (result.detail or ""))

    def test_invocation_without_covering_grant_fails_closed(self) -> None:
        runtime = make_runtime()
        manifest = make_manifest(
            capabilities_provided=(
                ExtensionCapability.ROUTE_PROPOSAL,
                ExtensionCapability.QUOTE_PROVISION,
            ),
            outputs=(ExtensionArtifactKind.ROUTE_PROPOSAL, ExtensionArtifactKind.QUOTE_SET),
        )
        manifest_id = register_manifest(runtime, manifest)
        drive_to_published(runtime, manifest_id)
        instance_id = install_instance(runtime, manifest_id)  # route grant only
        activate_instance(runtime, instance_id)
        result = invoke_once(
            runtime, instance_id, "extension-invocation/ungranted", capability="quote_provision"
        )
        self.assertIs(result.outcome, Outcome.REJECTED)
        self.assertIn("grant", (result.detail or ""))

    def test_shadow_command_records_shadow_mode_invocations(self) -> None:
        runtime, _, instance_id = self._active_runtime()
        result = runtime.submit(
            cmd(
                "cmd/shadow-on",
                "extension/shadow",
                (instance_id,),
                {"shadow": True},
                expected_versions=((instance_id, runtime.store.get(instance_id).object_version),),
            )
        )
        self.assertIs(result.outcome, Outcome.ACCEPTED)
        self.assertTrue(runtime.instance(instance_id).shadow)
        result = invoke_once(runtime, instance_id, "extension-invocation/shadow-1")
        self.assertIs(result.outcome, Outcome.ACCEPTED)
        invocation = runtime.invocation("extension-invocation/shadow-1")
        self.assertEqual(invocation.effect_mode, InvocationEffectMode.SHADOWED)
        runtime.submit(
            cmd(
                "cmd/shadow-off",
                "extension/shadow",
                (instance_id,),
                {"shadow": False},
                expected_versions=((instance_id, runtime.store.get(instance_id).object_version),),
            )
        )
        self.assertFalse(runtime.instance(instance_id).shadow)

    def test_shadow_requires_an_active_instance(self) -> None:
        runtime = make_runtime()
        manifest_id = register_manifest(runtime)
        drive_to_published(runtime, manifest_id)
        instance_id = install_instance(runtime, manifest_id)
        result = runtime.submit(
            cmd("cmd/shadow-installed", "extension/shadow", (instance_id,), {"shadow": True})
        )
        self.assertIs(result.outcome, Outcome.REJECTED)

    def test_sandbox_invocations_do_not_version_the_manifest(self) -> None:
        runtime = make_runtime()
        manifest_id = register_manifest(runtime)
        runtime.submit(cmd("cmd/sb-submit", "extension/submit", (manifest_id,), {}))
        before = runtime.store.get(manifest_id).object_version
        sandbox_invoke_once(runtime, manifest_id, "extension-invocation/sb-1")
        after = runtime.store.get(manifest_id).object_version
        self.assertEqual(before, after)
        invocation = runtime.invocation("extension-invocation/sb-1")
        self.assertEqual(invocation.target_id, manifest_id)


# ---------------------------------------------------------------------------
# 11. contribution measurement and economics
# ---------------------------------------------------------------------------


def make_measurement(
    extension_id: str = "extension/alpha-route",
    metric=ContributionMetric.COST_SAVINGS_MINOR,
    value: int = 250_000,
    as_of: str = T3,
    epistemic_type=EpistemicType.SIMULATED,
    evidence_refs=("extension-invocation/live-1",),
) -> OutcomeMeasurement:
    return OutcomeMeasurement(
        extension_id=extension_id,
        metric=metric,
        value=value,
        as_of=as_of,
        epistemic_type=epistemic_type,
        evidence_refs=evidence_refs,
    )


class ContributionMeasurementTests(unittest.TestCase):
    def test_verified_incremental_contribution_over_a_counterfactual_baseline(self) -> None:
        baseline = make_measurement(
            value=0,
            epistemic_type=EpistemicType.COUNTERFACTUAL,
            evidence_refs=("counterfactual/default-route",),
        )
        treatment = make_measurement(value=250_000)
        contribution = measure_contribution(
            contribution_id="extension-contribution/alpha-1",
            baseline=baseline,
            treatment=treatment,
            pricing=make_pricing(),
            applied_invocations=3,
            resource_credits=12,
            as_of=T3,
        )
        self.assertEqual(contribution.incremental, 250_000)
        self.assertTrue(contribution.verified)
        self.assertEqual(contribution.earnings, EconomicEarnings(amount_minor=25_000, asset="USD"))
        self.assertEqual(contribution.resource_credits, ResourceCredits(credits=12))
        self.assertEqual(contribution.applied_invocations, 3)

    def test_zero_contribution_when_treatment_does_not_beat_the_baseline(self) -> None:
        baseline = make_measurement(
            value=250_000,
            epistemic_type=EpistemicType.COUNTERFACTUAL,
            evidence_refs=("x",),
        )
        treatment = make_measurement(value=250_000)
        contribution = measure_contribution(
            contribution_id="extension-contribution/alpha-2",
            baseline=baseline,
            treatment=treatment,
            pricing=make_pricing(),
            applied_invocations=99,
            resource_credits=99,
            as_of=T3,
        )
        self.assertEqual(contribution.incremental, 0)
        self.assertFalse(contribution.verified)
        self.assertEqual(contribution.earnings, EconomicEarnings(amount_minor=0, asset="USD"))

    def test_activity_volume_is_not_a_contribution_metric(self) -> None:
        self.assertEqual(
            CONTRIBUTION_METRICS,
            frozenset(
                {
                    "fulfillment_quality",
                    "cost_savings_minor",
                    "latency_improvement_ms",
                    "risk_reduction_bps",
                }
            ),
        )
        self.assertNotIn("activity_volume", CONTRIBUTION_METRICS)
        self.assertNotIn("invocation_count", CONTRIBUTION_METRICS)
        with self.assertRaises(CoreValidationError) as raised:
            make_measurement(metric="activity_volume")
        self.assertIn("closed vocabulary", str(raised.exception))
        with self.assertRaises(CoreValidationError):
            make_measurement(metric="invocation_count")

    def test_volume_alone_cannot_manufacture_earnings(self) -> None:
        baseline = make_measurement(
            value=0, epistemic_type=EpistemicType.COUNTERFACTUAL, evidence_refs=("x",)
        )
        treatment = make_measurement(value=0)
        contribution = measure_contribution(
            contribution_id="extension-contribution/alpha-3",
            baseline=baseline,
            treatment=treatment,
            pricing=make_pricing(),
            applied_invocations=1_000_000,
            resource_credits=1_000_000,
            as_of=T3,
        )
        self.assertEqual(contribution.earnings, EconomicEarnings(amount_minor=0, asset="USD"))
        self.assertEqual(contribution.resource_credits, ResourceCredits(credits=1_000_000))

    def test_metric_mismatch_between_baseline_and_treatment_fails_closed(self) -> None:
        baseline = make_measurement(
            metric=ContributionMetric.FULFILLMENT_QUALITY,
            epistemic_type=EpistemicType.COUNTERFACTUAL,
            evidence_refs=("x",),
        )
        with self.assertRaises(CoreValidationError):
            measure_contribution(
                contribution_id="extension-contribution/alpha-4",
                baseline=baseline,
                treatment=make_measurement(),
                pricing=make_pricing(),
                applied_invocations=1,
                resource_credits=1,
                as_of=T3,
            )

    def test_counterfactual_treatment_fails_closed(self) -> None:
        with self.assertRaises(CoreValidationError):
            measure_contribution(
                contribution_id="extension-contribution/alpha-5",
                baseline=make_measurement(
                    epistemic_type=EpistemicType.COUNTERFACTUAL, evidence_refs=("x",)
                ),
                treatment=make_measurement(epistemic_type=EpistemicType.COUNTERFACTUAL),
                pricing=make_pricing(),
                applied_invocations=1,
                resource_credits=1,
                as_of=T3,
            )

    def test_simulated_baselines_fail_closed(self) -> None:
        with self.assertRaises(CoreValidationError):
            measure_contribution(
                contribution_id="extension-contribution/alpha-6",
                baseline=make_measurement(
                    epistemic_type=EpistemicType.SIMULATED, evidence_refs=("x",)
                ),
                treatment=make_measurement(),
                pricing=make_pricing(),
                applied_invocations=1,
                resource_credits=1,
                as_of=T3,
            )

    def test_unbacked_treatment_is_not_verified(self) -> None:
        baseline = make_measurement(
            value=0, epistemic_type=EpistemicType.COUNTERFACTUAL, evidence_refs=("x",)
        )
        treatment = make_measurement(value=100, evidence_refs=())
        contribution = measure_contribution(
            contribution_id="extension-contribution/alpha-7",
            baseline=baseline,
            treatment=treatment,
            pricing=make_pricing(),
            applied_invocations=1,
            resource_credits=1,
            as_of=T3,
        )
        self.assertFalse(contribution.verified)
        self.assertEqual(contribution.earnings, EconomicEarnings(amount_minor=0, asset="USD"))

    def test_fixed_pricing_earnings_require_verification(self) -> None:
        baseline = make_measurement(
            value=0, epistemic_type=EpistemicType.COUNTERFACTUAL, evidence_refs=("x",)
        )
        treatment = make_measurement(value=100)
        verified = measure_contribution(
            contribution_id="extension-contribution/alpha-8",
            baseline=baseline,
            treatment=treatment,
            pricing=make_pricing(
                model=PricingModel.FIXED, amount_minor=500, asset="USD", share_bps=0
            ),
            applied_invocations=1,
            resource_credits=1,
            as_of=T3,
        )
        self.assertEqual(verified.earnings, EconomicEarnings(amount_minor=500, asset="USD"))
        flat = measure_contribution(
            contribution_id="extension-contribution/alpha-9",
            baseline=baseline,
            treatment=make_measurement(value=0),
            pricing=make_pricing(
                model=PricingModel.FIXED, amount_minor=500, asset="USD", share_bps=0
            ),
            applied_invocations=1,
            resource_credits=1,
            as_of=T3,
        )
        self.assertEqual(flat.earnings, EconomicEarnings(amount_minor=0, asset="USD"))

    def test_revenue_share_earnings_use_exact_integer_arithmetic(self) -> None:
        baseline = make_measurement(
            value=0, epistemic_type=EpistemicType.COUNTERFACTUAL, evidence_refs=("x",)
        )
        treatment = make_measurement(value=999)
        contribution = measure_contribution(
            contribution_id="extension-contribution/alpha-10",
            baseline=baseline,
            treatment=treatment,
            pricing=make_pricing(share_bps=3333),
            applied_invocations=1,
            resource_credits=1,
            as_of=T3,
        )
        self.assertEqual(
            contribution.earnings,
            EconomicEarnings(amount_minor=(3333 * 999) // 10000, asset="USD"),
        )

    def test_per_invocation_pricing_is_price_accounting_not_contribution(self) -> None:
        baseline = make_measurement(
            value=10, epistemic_type=EpistemicType.COUNTERFACTUAL, evidence_refs=("x",)
        )
        treatment = make_measurement(value=5)  # worse than the baseline
        contribution = measure_contribution(
            contribution_id="extension-contribution/alpha-11",
            baseline=baseline,
            treatment=treatment,
            pricing=make_pricing(
                model=PricingModel.PER_INVOCATION, amount_minor=7, asset="USD", share_bps=0
            ),
            applied_invocations=4,
            resource_credits=4,
            as_of=T3,
        )
        self.assertEqual(contribution.incremental, 0)
        self.assertFalse(contribution.verified)
        # price accounting records the caller-billed amount...
        self.assertEqual(contribution.billed_minor, 28)
        # ...but rewards stay zero: volume is not contribution
        self.assertEqual(contribution.earnings, EconomicEarnings(amount_minor=0, asset="USD"))

    def test_economic_quantities_are_distinct_typed_values(self) -> None:
        credits = ResourceCredits(credits=5)
        earnings = EconomicEarnings(amount_minor=5, asset="USD")
        collateral = FinancialCollateral(amount_minor=5, asset="USD")
        self.assertNotEqual(type(credits), type(earnings))
        self.assertNotEqual(type(earnings), type(collateral))
        self.assertNotEqual(credits, earnings)
        self.assertNotEqual(earnings, collateral)
        self.assertEqual(set(credits.to_dict()), {"resource_credits"})
        self.assertEqual(set(earnings.to_dict()), {"earnings_minor", "asset"})
        self.assertEqual(set(collateral.to_dict()), {"collateral_minor", "asset"})
        with self.assertRaises(CoreValidationError):
            ResourceCredits(credits=-1)
        with self.assertRaises(CoreValidationError):
            EconomicEarnings(amount_minor=-1, asset="USD")
        with self.assertRaises(CoreValidationError):
            FinancialCollateral(amount_minor=-1, asset="USD")

    def test_contribution_record_round_trips_and_tampering_fails(self) -> None:
        baseline = make_measurement(
            value=0, epistemic_type=EpistemicType.COUNTERFACTUAL, evidence_refs=("x",)
        )
        contribution = measure_contribution(
            contribution_id="extension-contribution/alpha-12",
            baseline=baseline,
            treatment=make_measurement(value=250_000),
            pricing=make_pricing(),
            applied_invocations=3,
            resource_credits=12,
            as_of=T3,
        )
        decoded = ExtensionContribution.from_dict(contribution.to_dict())
        self.assertEqual(decoded, contribution)
        tampered = contribution.to_dict()
        tampered["record"]["incremental"] = 999_999
        with self.assertRaises(CoreValidationError):
            ExtensionContribution.from_dict(tampered)

    def test_measurement_validation_fails_closed(self) -> None:
        with self.assertRaises(CoreValidationError):
            make_measurement(value=-1)
        with self.assertRaises(CoreValidationError):
            make_measurement(epistemic_type="GUESSED")

    def test_measure_command_creates_a_kernel_contribution_object(self) -> None:
        runtime = make_runtime()
        manifest_id = register_manifest(runtime)
        drive_to_published(runtime, manifest_id)
        instance_id = install_instance(runtime, manifest_id)
        activate_instance(runtime, instance_id)
        invoke_once(runtime, instance_id, "extension-invocation/treat-1")
        invoke_once(runtime, instance_id, "extension-invocation/treat-2")
        result = runtime.submit(
            cmd(
                "cmd/measure-1",
                "extension/measure",
                ("extension-contribution/alpha-1",),
                {
                    "contribution_id": "extension-contribution/alpha-1",
                    "baseline": make_measurement(
                        value=0,
                        epistemic_type=EpistemicType.COUNTERFACTUAL,
                        evidence_refs=("counterfactual/default-route",),
                    ).to_dict(),
                    "treatment": make_measurement(
                        value=500_000,
                        evidence_refs=(
                            "extension-invocation/treat-1",
                            "extension-invocation/treat-2",
                        ),
                    ).to_dict(),
                },
                expected_versions=(("extension-contribution/alpha-1", 0),),
            )
        )
        self.assertIs(result.outcome, Outcome.ACCEPTED)
        contribution = runtime.contribution("extension-contribution/alpha-1")
        self.assertEqual(contribution.incremental, 500_000)
        self.assertTrue(contribution.verified)
        self.assertEqual(contribution.applied_invocations, 2)
        self.assertEqual(contribution.envelope.object_type, EXTENSION_CONTRIBUTION_OBJECT_TYPE)

    def test_measure_command_rejects_activity_volume_metrics(self) -> None:
        runtime = make_runtime()
        manifest_id = register_manifest(runtime)
        drive_to_published(runtime, manifest_id)
        instance_id = install_instance(runtime, manifest_id)
        activate_instance(runtime, instance_id)
        invoke_once(runtime, instance_id, "extension-invocation/volume-1")
        result = runtime.submit(
            cmd(
                "cmd/measure-volume",
                "extension/measure",
                ("extension-contribution/volume",),
                {
                    "contribution_id": "extension-contribution/volume",
                    "baseline": {
                        "extension_id": "extension/alpha-route",
                        "metric": "activity_volume",
                        "value": 0,
                        "as_of": T3,
                        "epistemic_type": "COUNTERFACTUAL",
                        "evidence_refs": ["x"],
                    },
                    "treatment": {
                        "extension_id": "extension/alpha-route",
                        "metric": "activity_volume",
                        "value": 9,
                        "as_of": T3,
                        "epistemic_type": "SIMULATED",
                        "evidence_refs": ["y"],
                    },
                },
                expected_versions=(("extension-contribution/volume", 0),),
            )
        )
        self.assertIs(result.outcome, Outcome.REJECTED)
        self.assertIn("activity volume", (result.detail or ""))


# ---------------------------------------------------------------------------
# 12. security model: authority boundaries
# ---------------------------------------------------------------------------


class SecurityBoundaryTests(unittest.TestCase):
    def test_extensions_cannot_declare_ledger_or_authority_powers(self) -> None:
        for forbidden in (
            "ledger_write",
            "finality_modify",
            "authority_grant",
            "compliance_bypass",
            "undeclared_resource_access",
        ):
            with self.assertRaises(CoreValidationError):
                make_manifest(permissions=(forbidden,))

    def test_invocation_records_carry_no_kernel_references(self) -> None:
        runtime = make_runtime()
        manifest_id = register_manifest(runtime)
        drive_to_published(runtime, manifest_id)
        instance_id = install_instance(runtime, manifest_id)
        activate_instance(runtime, instance_id)
        invoke_once(runtime, instance_id, "extension-invocation/inspect-1")
        record = runtime.invocation("extension-invocation/inspect-1").to_dict()["record"]
        for forbidden in ("store", "engine", "view", "ledger", "kernel"):
            self.assertNotIn(forbidden, set(record))

    def test_the_runtime_never_writes_non_extension_object_types(self) -> None:
        runtime = make_runtime()
        manifest_id = register_manifest(runtime)
        drive_to_published(runtime, manifest_id)
        instance_id = install_instance(runtime, manifest_id)
        activate_instance(runtime, instance_id)
        invoke_once(runtime, instance_id, "extension-invocation/typecheck-1")
        for envelope in runtime.store.snapshot():
            self.assertTrue(
                envelope.object_type == EXTENSION_MANIFEST_OBJECT_TYPE
                or envelope.object_type.startswith("extension/")
            )

    def test_resource_payloads_are_declared_data_only(self) -> None:
        runtime = make_runtime()
        manifest_id = register_manifest(runtime)
        drive_to_published(runtime, manifest_id)
        instance_id = install_instance(runtime, manifest_id)
        activate_instance(runtime, instance_id)
        result = invoke_once(
            runtime,
            instance_id,
            "extension-invocation/undeclared-resource",
            resources={"observe_protocol_state": {"peek": 1}},
        )
        self.assertIs(result.outcome, Outcome.REJECTED)
        self.assertIn("undeclared resource", (result.detail or ""))

    def test_invocations_never_touch_authoritative_value_state(self) -> None:
        # The store only ever holds extension-domain objects; there is no
        # ledger path from an invocation (constitution invariant 6/16).
        runtime = make_runtime()
        manifest_id = register_manifest(runtime)
        drive_to_published(runtime, manifest_id)
        instance_id = install_instance(runtime, manifest_id)
        activate_instance(runtime, instance_id)
        before = runtime.domain_state_digest()
        invoke_once(runtime, instance_id, "extension-invocation/valuecheck-1")
        after = runtime.domain_state_digest()
        self.assertNotEqual(before, after)  # the invocation record IS recorded
        for envelope in runtime.store.snapshot():
            self.assertNotIn("value/", envelope.object_id)
            self.assertNotIn("settlement", envelope.object_type)


# ---------------------------------------------------------------------------
# 13. dogfooding conformance (DOGFOOD-020)
# ---------------------------------------------------------------------------


class DogfoodingConformanceTests(unittest.TestCase):
    def test_transcript_is_deterministic_within_and_across_builds(self) -> None:
        from src.extensions.dogfooding import build_transcript

        transcript_a, digest_a = build_transcript()
        transcript_b, digest_b = build_transcript()
        self.assertEqual(transcript_a, transcript_b)
        self.assertEqual(digest_a, digest_b)

    def test_transcript_reports_the_mandated_sequence_and_passes(self) -> None:
        from src.extensions.dogfooding import build_transcript

        transcript, digest = build_transcript()
        self.assertIn("DOGFOOD-020: PASS", transcript)
        self.assertIn("install", transcript)
        self.assertIn("contribution", transcript)
        self.assertIn("shadow", transcript)
        self.assertEqual(len(digest), 64)

    def test_shadow_activity_adds_no_earnings(self) -> None:
        from src.extensions.dogfooding import build_transcript

        transcript, _ = build_transcript()
        self.assertIn("shadow.earnings_delta_minor=0", transcript)
        self.assertIn("shadow.applied_invocations_delta=0", transcript)


# ---------------------------------------------------------------------------
# 14. quality-attribute measurements
# ---------------------------------------------------------------------------


class QualityAttributeTests(unittest.TestCase):
    def _active_runtime_with_manifest(self):
        runtime = make_runtime()
        manifest_id = register_manifest(
            runtime,
            make_manifest(resource_requirements=ResourceRequirements(10_000, 1_048_576)),
        )
        drive_to_published(runtime, manifest_id)
        instance_id = install_instance(
            runtime,
            manifest_id,
            grants=(
                grant_payload(
                    grant_id="extension-grant/alpha-route-route",
                    budget_max_invocations=10_000,
                ),
            ),
        )
        activate_instance(runtime, instance_id)
        return runtime, instance_id

    def test_invocation_throughput_at_scale_is_measured_and_deterministic(self) -> None:
        runtime, instance_id = self._active_runtime_with_manifest()
        count = 200
        started = time.process_time()
        for index in range(count):
            result = invoke_once(
                runtime, instance_id, f"extension-invocation/bench-{index}"
            )
            self.assertIs(result.outcome, Outcome.ACCEPTED)
        elapsed = time.process_time() - started
        self.assertGreater(elapsed, 0)
        self.assertLess(elapsed, 120.0)
        digest_one = runtime.domain_state_digest()
        runtime2, instance2 = self._active_runtime_with_manifest()
        for index in range(count):
            invoke_once(runtime2, instance2, f"extension-invocation/bench-{index}")
        self.assertEqual(digest_one, runtime2.domain_state_digest())

    def test_dag_validation_cost_at_scale(self) -> None:
        manifests = {}
        for index in range(60):
            extension_id = f"extension/dag-{index:03d}"
            dependencies = (
                (DependencySpec(f"extension/dag-{index - 1:03d}", "1.0.0", None),)
                if index
                else ()
            )
            manifests[extension_id] = make_manifest(
                extension_id=extension_id,
                code_hash=f"{index:064d}"[-64:],
                dependencies=dependencies,
            )
        started = time.process_time()
        graph = DependencyGraph.build(manifests)
        graph.install_order()
        elapsed = time.process_time() - started
        self.assertGreater(elapsed, 0)
        self.assertEqual(len(graph.install_order()), 60)

    def test_contribution_measurement_cost_at_scale(self) -> None:
        baseline = make_measurement(
            value=0, epistemic_type=EpistemicType.COUNTERFACTUAL, evidence_refs=("x",)
        )
        started = time.process_time()
        for index in range(300):
            measure_contribution(
                contribution_id=f"extension-contribution/bench-{index}",
                baseline=baseline,
                treatment=make_measurement(value=index % 1000),
                pricing=make_pricing(),
                applied_invocations=3,
                resource_credits=9,
                as_of=T3,
            )
        elapsed = time.process_time() - started
        self.assertGreater(elapsed, 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
