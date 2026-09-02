"""The extension dependency DAG with version bounds and cycle detection.

Every manifest declares its dependencies with inclusive version bounds.
The DAG fails closed on missing dependencies, out-of-bound versions,
self-dependencies, duplicate identities and cycles; it also answers the
activation-readiness question (every dependency must have an ACTIVE
instance within the declared bounds before a dependent may activate).

The graph is a pure function of the registered manifest records — no
state machine of its own; ordering is deterministic (lexicographic
topological order).
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from src.core.errors import CoreValidationError

from .contracts import ExtensionLifecycleState, MANIFEST_LIFECYCLE_STATES
from .manifest import DependencySpec, ExtensionManifest, parse_version, version_in_bounds
from ._validation import parse_enum, require_internal_id, require_text


def require_acyclic(manifests: Mapping[str, ExtensionManifest]) -> None:
    """Cycle-only check over registered manifests (registration gate).

    Unlike :meth:`DependencyGraph.build`, unresolved dependencies are
    permitted here — a manifest may be registered before its dependencies
    (they are resolved and version-checked at install/activation time).
    A dependency cycle is a structural defect and fails closed immediately
    at registration, deterministically reporting the lexicographically
    first cycle found.
    """
    if not isinstance(manifests, Mapping):
        raise CoreValidationError("cycle check must run over a mapping of manifests")
    WHITE, GRAY, BLACK = 0, 1, 2
    color: dict[str, int] = {key: WHITE for key in manifests}
    stack: list[str] = []

    def visit(node: str) -> None:
        color[node] = GRAY
        stack.append(node)
        for spec in manifests[node].dependencies:
            target = spec.extension_id
            if target not in manifests:
                continue  # unresolved dependencies are legal at registration
            if color[target] == GRAY:
                cycle = stack[stack.index(target):] + [target]
                raise CoreValidationError(
                    "dependency cycle detected: " + " -> ".join(cycle)
                )
            if color[target] == WHITE:
                visit(target)
        stack.pop()
        color[node] = BLACK

    for node in sorted(manifests):
        if color[node] == WHITE:
            visit(node)


class DependencyGraph:
    """Deterministic dependency graph over registered manifests.

    Built from :meth:`build`, which validates the whole set fail-closed:
    every dependency resolves to a registered manifest whose concrete
    version satisfies the declared inclusive bounds; no cycles exist.
    """

    def __init__(self, manifests: Mapping[str, ExtensionManifest]) -> None:
        self._manifests: dict[str, ExtensionManifest] = dict(manifests)
        self._order = self._topological_order()

    # -- construction -------------------------------------------------------

    @classmethod
    def build(cls, manifests: Mapping[str, ExtensionManifest]) -> "DependencyGraph":
        if not isinstance(manifests, Mapping):
            raise CoreValidationError("dependency graph must build from a mapping")
        for extension_id, manifest in manifests.items():
            if extension_id != manifest.extension_id:
                raise CoreValidationError(
                    f"dependency graph key {extension_id!r} must equal the manifest "
                    "extension_id (duplicate or inconsistent manifest identity)"
                )
        graph = cls(manifests)
        graph._require_resolved()
        graph._require_acyclic()
        return graph

    # -- queries ------------------------------------------------------------

    def install_order(self) -> tuple[str, ...]:
        """Deterministic lexicographic topological order for installation."""
        return self._order

    def dependencies_of(self, extension_id: str) -> tuple[DependencySpec, ...]:
        self._require_known(extension_id)
        return self._manifests[extension_id].dependencies

    def require_installable(self, extension_id: str) -> None:
        """Fail closed unless the manifest and all its dependencies are PUBLISHED."""
        manifest = self._require_known(extension_id)
        self._require_state(manifest, ExtensionLifecycleState.PUBLISHED)
        for spec in manifest.dependencies:
            dependency = self._require_resolved_spec(extension_id, spec)
            self._require_state(dependency, ExtensionLifecycleState.PUBLISHED)

    def require_activation_ready(
        self, extension_id: str, active_versions: Mapping[str, tuple[int, int, int]]
    ) -> None:
        """Fail closed unless the whole dependency closure is active in bounds.

        Activation readiness is transitive: every manifest in the target's
        dependency closure must have every one of its declared
        dependencies backed by an ACTIVE instance whose version satisfies
        the declared inclusive bounds. The target itself must not appear
        among the active versions.
        """
        manifest = self._require_known(extension_id)
        if manifest.extension_id in active_versions:
            # An extension's own instance must not satisfy its dependencies.
            raise CoreValidationError(
                f"activation readiness of {extension_id} must not list itself"
            )
        for declared_id, declared in active_versions.items():
            if not isinstance(declared, tuple) or len(declared) != 3:
                raise CoreValidationError(
                    "activation readiness versions must be parsed version tuples"
                )
        closure: dict[str, ExtensionManifest] = {manifest.extension_id: manifest}
        pending = [manifest]
        while pending:
            current = pending.pop()
            for spec in current.dependencies:
                if spec.extension_id in closure:
                    continue
                dependency = self._require_resolved_spec(extension_id, spec)
                closure[spec.extension_id] = dependency
                pending.append(dependency)
        for node_id in sorted(closure):
            for spec in closure[node_id].dependencies:
                if spec.extension_id not in active_versions:
                    raise CoreValidationError(
                        f"activation of {extension_id} requires an ACTIVE instance "
                        f"of dependency {spec.extension_id} (required by "
                        f"{node_id}) in this environment"
                    )
                declared = active_versions[spec.extension_id]
                if not version_in_bounds(
                    ".".join(str(part) for part in declared), spec
                ):
                    raise CoreValidationError(
                        f"dependency {spec.extension_id} instance version "
                        f"{'.'.join(str(part) for part in declared)} is outside the "
                        f"declared bounds of {node_id}"
                    )

    # -- internals ----------------------------------------------------------

    def _require_known(self, extension_id: str) -> ExtensionManifest:
        require_text("dependency extension_id", extension_id)
        manifest = self._manifests.get(extension_id)
        if manifest is None:
            raise CoreValidationError(
                f"unknown manifest {extension_id!r} in the dependency graph"
            )
        return manifest

    def _require_resolved_spec(
        self, extension_id: str, spec: DependencySpec
    ) -> ExtensionManifest:
        dependency = self._manifests.get(spec.extension_id)
        if dependency is None:
            raise CoreValidationError(
                f"missing dependency: {extension_id} depends on {spec.extension_id} "
                "which is not registered"
            )
        if not version_in_bounds(dependency.version, spec):
            raise CoreValidationError(
                f"dependency version bound violation: {extension_id} requires "
                f"{spec.extension_id} within "
                f"[{spec.min_version or 'any'}, {spec.max_version or 'any'}] but the "
                f"registered version is {dependency.version}"
            )
        return dependency

    def _require_state(
        self, manifest: ExtensionManifest, state: ExtensionLifecycleState
    ) -> None:
        if manifest.envelope is None:
            raise CoreValidationError(
                f"manifest {manifest.extension_id} has no lifecycle state "
                "(not registered through the kernel)"
            )
        current = parse_enum(
            "manifest state", ExtensionLifecycleState, manifest.envelope.state
        )
        if current not in MANIFEST_LIFECYCLE_STATES:
            raise CoreValidationError(
                f"manifest {manifest.extension_id} holds an invalid state"
            )
        if current is not state:
            raise CoreValidationError(
                f"manifest {manifest.extension_id} must be {state.value} but is "
                f"{current.value}"
            )

    def _require_resolved(self) -> None:
        for extension_id, manifest in self._manifests.items():
            for spec in manifest.dependencies:
                self._require_resolved_spec(extension_id, spec)

    def _require_acyclic(self) -> None:
        WHITE, GRAY, BLACK = 0, 1, 2
        color: dict[str, int] = {key: WHITE for key in self._manifests}
        stack: list[str] = []

        def visit(node: str) -> None:
            color[node] = GRAY
            stack.append(node)
            for spec in self._manifests[node].dependencies:
                target = spec.extension_id
                if target not in self._manifests:
                    continue  # reported by _require_resolved
                if color[target] == GRAY:
                    cycle = stack[stack.index(target):] + [target]
                    raise CoreValidationError(
                        "dependency cycle detected: " + " -> ".join(cycle)
                    )
                if color[target] == WHITE:
                    visit(target)
            stack.pop()
            color[node] = BLACK

        for node in sorted(self._manifests):
            if color[node] == WHITE:
                visit(node)

    def _topological_order(self) -> tuple[str, ...]:
        remaining = set(self._manifests)
        order: list[str] = []
        while remaining:
            ready = sorted(
                node
                for node in remaining
                if all(
                    spec.extension_id not in remaining
                    for spec in self._manifests[node].dependencies
                )
            )
            if not ready:
                raise CoreValidationError(
                    "dependency cycle detected: "
                    + " -> ".join(sorted(remaining))
                )
            for node in ready:
                order.append(node)
                remaining.discard(node)
        return tuple(order)
