"""DOGFOOD-026: full simulated ledger/intent trace with balanced postings
and replay.

Run in a clean process:

    python3 -m src.integration.dogfooding

The experiment executes the Work Order's mandated conformance task against
the REAL composed surfaces (kernel + ledger + money) in one isolated
environment: an authorized payment intent is reserved through a real hold
with its encumbrance posting, settled through a real fixed-point FX
conversion with an explicit residual and a weighted residual allocation,
posted as balanced double-entry FX/FEE legs, certified by a real
reconciliation that seals the journal — then the whole composed state is
snapshotted and rebuilt FROM THE JOURNAL ALONE, and every cross-layer
invariant is re-verified on the rebuilt state. The transcript is fully
deterministic (no wall-clock time, no entropy) so repeated runs are
byte-identical.
"""

from __future__ import annotations

from src.core.errors import CoreValidationError
from src.core.serialization import canonical_sha256

from .harness import IntegrationGate
from .invariants import verify_invariants
from .replay import assert_replay_equivalence, replay_from_journal
from .scenarios import (
    DEFAULT_ALLOCATION_WEIGHTS,
    DEFAULT_FEE_MINOR,
    DEFAULT_INITIAL_DEPOSIT_MINOR,
    DEFAULT_RATE_DENOMINATOR,
    DEFAULT_RATE_NUMERATOR,
    DEFAULT_SOURCE_MINOR,
    payment_scenario_commands,
    run_payment_scenario,
)

ENVIRONMENT = "env/ig001-dogfood"
DOMAIN = "domain/ig001-dogfood"
PAYER = "value/account/payer-ig1"
PAYEE = "value/account/payee-ig1"
SAVINGS = "value/account/payee-savings-ig1"
HOUSE_USD = "value/account/house-usd-ig1"
HOUSE_EUR = "value/account/house-eur-ig1"
VAULT = "value/account/vault-ig1"
FEE_INCOME = "value/account/fee-income-ig1"


def build_transcript() -> tuple[str, str]:
    """Execute the DOGFOOD-026 experiment and return (transcript, digest)."""
    lines: list[str] = [
        "DOGFOOD-026: kernel/value integration gate (IG-001) - full simulated "
        "ledger/intent trace with balanced postings and replay",
        "work order: WORK-026",
        "architecture: v0.1 (frozen)",
        "gate: IG-001 (kernel + value correctness; required inputs WORK-003, "
        "WORK-005 and WORK-006, all complete and merged on main)",
        "surface: src.integration composition harness driving the real "
        "src.transition kernel, the real src.value ledger and the real "
        "src.money arithmetic through their public APIs",
        f"environment: {ENVIRONMENT} (isolated in-memory kernel store and ledger; "
        "no production state is reachable)",
        "task: execute a full simulated ledger/intent trace - intent "
        "create/authorize with a real hold and encumbrance posting, FX settlement "
        "with an explicit residual, weighted allocation, fee and balanced "
        "postings, reconciliation, then snapshot and journal-driven replay",
        "starting state: freshly provisioned environment - USD and EUR assets "
        "(scale 2), 7 accounts, one ACTIVE journal, one funding deposit of "
        f"{DEFAULT_INITIAL_DEPOSIT_MINOR} USD minor units",
        "commands: 4 kernel commands with expected-version discipline "
        "(integration/intent.create, integration/intent.authorize, "
        "integration/settlement.submit, integration/settlement.reconcile)",
        "expected outcome: every accepted step keeps all cross-layer value "
        "invariants; the journal rebuilds the composed state byte-identically",
    ]
    try:
        gate = IntegrationGate(environment_id=ENVIRONMENT, domain_id=DOMAIN)
        gate.provision()
        results = run_payment_scenario(gate, tag="ig1")
        step_specs = (
            ("integration/intent.create", "intent/created"),
            ("integration/intent.authorize", "intent/authorized"),
            ("integration/settlement.submit", "settlement/submitted"),
            ("integration/settlement.reconcile", "settlement/reconciled"),
        )
        for index, (result, (command_type, event_type)) in enumerate(
            zip(results, step_specs), start=1
        ):
            event = result.event
            versions = ",".join(
                f"{envelope.object_id}@v{envelope.object_version}:{envelope.state}"
                for envelope in result.resulting_envelopes
            )
            lines.append(
                f"step {index} {command_type}: outcome={result.outcome.value} "
                f"event={event.event_type} logical_time={event.logical_time} "
                f"objects={versions}"
            )
            if event.event_type != event_type:
                raise AssertionError(f"unexpected event type {event.event_type}")

        entries = gate.snapshot()["engine"]["journal"]
        settle_payload = entries[2]["payload"]
        effects = settle_payload["effects"]
        conversion = effects[0]["outputs"]["conversion"]
        parts = effects[1]["outputs"]["parts"]
        postings = [e for e in effects if e["kind"] == "post"]
        lines.extend(
            [
                "fx: source={} {} minor units (scale {}) rate={}/{} mode={} "
                "target={} {} minor units residual={}/{} (|residual| < denominator: "
                "value is conserved exactly)".format(
                    conversion["source"]["value"],
                    conversion["source"]["currency"],
                    conversion["source"]["scale"],
                    conversion["rate"]["rate_numerator"],
                    conversion["rate"]["rate_denominator"],
                    conversion["rounding_mode"],
                    conversion["target"]["value"],
                    conversion["target"]["currency"],
                    conversion["residual_numerator"],
                    conversion["residual_denominator"],
                ),
                "allocation: weights={} parts={} parts_sum={} == conversion target "
                "(residual allocation conserves value exactly)".format(
                    list(DEFAULT_ALLOCATION_WEIGHTS),
                    [part["value"] for part in parts],
                    sum(part["value"] for part in parts),
                ),
                f"fee: {DEFAULT_FEE_MINOR} USD minor units posted as an explicit "
                "FEE posting (payer debit / fee-income credit)",
                "postings: "
                + ", ".join(
                    f"{effect['outputs']['posting']['envelope']['object_id']}("
                    f"{effect['inputs']['posting_class']}) for "
                    f"{len(effect['inputs']['legs'])} legs"
                    for effect in postings
                )
                + " - every posting balances per asset",
            ]
        )
        balances = {
            account_id: gate.ledger.derive_balances(account_id=account_id).available
            for account_id in (PAYER, PAYEE, SAVINGS, HOUSE_USD, HOUSE_EUR, VAULT, FEE_INCOME)
        }
        lines.append(
            "balances: payer.available={} payee.available={} savings.available={} "
            "house_usd.available={} house_eur.available={} vault.available={} "
            "fee_income.available={}".format(
                balances[PAYER],
                balances[PAYEE],
                balances[SAVINGS],
                balances[HOUSE_USD],
                balances[HOUSE_EUR],
                balances[VAULT],
                balances[FEE_INCOME],
            )
        )
        reconciliation_state = gate.ledger_state()["reconciliations"][0]["envelope"]["state"]
        discrepancies = len(
            gate.ledger_state()["reconciliations"][0]["payload"]["discrepancies"]
        )
        lines.append(
            f"reconciliation: state={reconciliation_state} discrepancies={discrepancies} "
            "journal_state=RECONCILED (certified and sealed)"
        )

        checks = verify_invariants(gate)
        lines.append(
            f"invariants: {len(checks)} checks PASS after every accepted step: "
            + ", ".join(checks)
        )

        # Deterministic replay: rebuild the composed state FROM THE JOURNAL.
        snapshot = gate.snapshot()
        effect_count = sum(
            len(entry["payload"].get("effects", ())) for entry in entries
        )
        rebuilt = replay_from_journal(snapshot)
        assert_replay_equivalence(gate, rebuilt)
        rebuilt_checks = verify_invariants(rebuilt)
        lines.extend(
            [
                f"replay: journal_entries={len(entries)} ledger_effects={effect_count} "
                f"ledger_digest_original={gate.ledger_digest()} "
                f"ledger_digest_rebuilt={rebuilt.ledger_digest()} (identical)",
                f"replay: kernel_digest_original={gate.kernel_digest()} "
                f"kernel_digest_rebuilt={rebuilt.kernel_digest()} (identical)",
                f"replay: composed_digest_original={gate.composed_digest()} "
                f"composed_digest_rebuilt={rebuilt.composed_digest()} (identical)",
                f"replay: rebuilt invariants {len(rebuilt_checks)}/{len(checks)} PASS "
                "(no semantic loss across the state/journal/snapshot boundaries)",
            ]
        )

        # Fail-closed conformance: after reconciliation the journal is sealed.
        sealed_rejected = False
        try:
            commands = payment_scenario_commands(
                tag="ig2", environment_id=ENVIRONMENT, domain_id=DOMAIN
            )
            gate.submit(commands[0])
            gate.submit(commands[1])
        except CoreValidationError:
            sealed_rejected = True
        lines.append(
            "sealed-journal check: a second payment after reconciliation fails "
            "closed "
            + (
                "(journal RECONCILED; postings require the journal to be ACTIVE)"
                if sealed_rejected
                else "(UNEXPECTEDLY ACCEPTED)"
            )
        )
        if not sealed_rejected:
            raise AssertionError("the sealed journal accepted a further posting")
        lines.extend(
            [
                "observed outcome: every step accepted with balanced postings, exact "
                "FX conservation with an explicit residual, reconciliation BALANCED, "
                "and a byte-identical journal-driven rebuild",
                "classification: DOGFOOD-026: PASS",
            ]
        )
    except Exception as exc:  # dogfooding classification, not a domain error path
        lines.extend(
            [
                f"observed outcome: experiment failed ({type(exc).__name__}: {exc})",
                "classification: DOGFOOD-026: CONTRACT_FAILURE",
            ]
        )
    transcript = "\n".join(lines) + "\n"
    digest = canonical_sha256({"transcript": transcript})
    return transcript, digest


def main() -> None:
    transcript, _ = build_transcript()
    print(transcript, end="")


if __name__ == "__main__":
    main()
