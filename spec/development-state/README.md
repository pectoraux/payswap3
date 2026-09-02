# Development State

This directory is the repository-native control plane.

## Authority classes

- `governance-model.json` — authoritative governance model.
- `program-state.json` — authoritative operational state for activated/in-flight work.
- `dependency-state.json` — derived dependency projection.
- `frontier-state.json` — derived eligibility/frontier projection.
- `checkpoint-state.json` — derived checkpoint projection.
- `future-roadmap.json` — planned sequence and parallel waves; never activation authority.

The first Architect can reconstruct the program from this directory without conversation history.

## Bootstrap state

The repository starts with no active implementation Work Order. `WORK-001` is the first eligible item and must be activated explicitly by the Architect.
