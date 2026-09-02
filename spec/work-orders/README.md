# Work Orders

Each `WORK-NNN.md` is one bounded implementation unit.

A Work Order owns one protected surface and declares:

- objective;
- hard dependencies and their type;
- owned surfaces;
- forbidden surfaces;
- acceptance criteria;
- proof classes;
- dogfooding/conformance experiment;
- definition of done.

Workers must not broaden a Work Order while implementing it. Cross-cutting composition belongs to an `IG-*` Work Order.

## Activation

All Work Orders begin `planned`. The Architect moves exactly the authorized Work Order(s) into `program-state.json` as `in_flight`.

## Parallel work

Parallel Work Orders must start from the same stable main revision and cannot consume unmerged sibling implementations.
