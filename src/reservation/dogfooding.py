"""DOGFOOD-012: a two-actor real-PostgreSQL race on keyed reservations.

The dogfooding/conformance contract of WORK-012: two REAL actors — two
separate psycopg2 connections to a real PostgreSQL server — race on the
reservation domain's concurrency contracts, and the harness prints a
deterministic transcript proving:

- **Experiment A (single winner on one key).** Two actors race to create
  and then hold a reservation on the SAME resource key. The race is real:
  the loser's insert genuinely contends with the winner's uncommitted
  unique-index entry (the server decides it with a ``UniqueViolation``),
  and the loser's hold update contends with the winner's
  ``SELECT ... FOR UPDATE`` row lock (a NOWAIT probe proves the lock is
  held; the losing update sees a stale version after the winner commits).
  Exactly ONE winner commits; the loser path records explicit provenance
  (which actor, which precedence rule decided it, deterministic reason).
- **Experiment B (keyed-not-global).** While actor alpha holds key one's
  row lock, actor beta commits a reservation on key two. Interleaved
  commits prove there is no global serialization: the interleaving is
  proven by lock state (beta's NOWAIT probe on key one fails immediately
  before beta's commit on key two succeeds), never by timing.
- **Deterministic schedule.** The outcome schedule is decided by the
  domain's explicit precedence rule (earliest ``requested_at``, then
  command id, then actor) through
  :func:`~src.reservation.resolve_precedence` plus issued/commit event
  ordering — no clock reads, no sleeps — so two clean-process runs are
  byte-identical with the same SHA-256 digests.

The experiment table is dropped and recreated per run under a FIXED
name, and the PostgreSQL datadir lives OUTSIDE the repository worktree.
The pgserver/psycopg2 imports appear ONLY in this harness: the domain
modules stay stdlib-only, and the unittest suite never requires
PostgreSQL.
"""

from __future__ import annotations

import threading

import pgserver
import psycopg2
import psycopg2.errors

from src.core.serialization import canonical_sha256

from . import (
    Amount,
    ConditionKind,
    ConditionSpec,
    CoreValidationError,
    ExpectedVersion,
    OperatingWindow,
    Provenance,
    ReservationStore,
    WriterClaim,
    commit_reservation,
    create_reservation,
    hold_reservation,
    resolve_precedence,
)

#: Fixed user-space PostgreSQL datadir of the dogfooding server. The
#: server and its data live outside the repository worktree, always.
DATADIR = "/home/z/pgdata-w012"

#: Fixed experiment table name, dropped and recreated per run.
TABLE = "reservation_race_w012"

ENV = "env/test"
DOMAIN = "domain/demo"
STAMP = "2026-09-02T00:00:00Z"
ASSET = "asset/USD"
OPENS_AT = "2026-09-03T00:00:00Z"
CLOSES_AT = "2026-09-03T02:00:00Z"
HOLD_AT = "2026-09-03T00:40:00Z"
COMMIT_AT = "2026-09-03T00:50:00Z"

KEY_ONE = "resource/provider-alpha/asset-USD/slot-7"
KEY_TWO = "resource/provider-beta/asset-USD/slot-8"

RESERVATION_A = "reservation/dogfood-a"
RESERVATION_B = "reservation/dogfood-b"
RESERVATION_B2 = "reservation/dogfood-b2"

HOLD_REF_ALPHA = "value/hold/dogfood-1"
HOLD_REF_BETA = "value/hold/dogfood-2"
FUNDING_REF = "value/funding-source/wallet-7"

#: The two actors' writer claims. Precedence resolves actor/alpha first
#: (earliest requested_at): the deterministic schedule of the race.
CLAIM_ALPHA = WriterClaim(
    actor="actor/alpha",
    requested_at="2026-09-03T00:00:01Z",
    command_id="command/w-012-dogfood-alpha",
)
CLAIM_BETA = WriterClaim(
    actor="actor/beta",
    requested_at="2026-09-03T00:00:02Z",
    command_id="command/w-012-dogfood-beta",
)


def _prov(source: str) -> Provenance:
    return Provenance(
        issuer="principal/reservation-operator",
        source=source,
        recorded_at=STAMP,
        evidence_refs=("evidence/work-012-dogfooding",),
    )


def _conditions() -> tuple[ConditionSpec, ...]:
    return (
        ConditionSpec(
            condition_key="cond/encumbrance",
            kind=ConditionKind.ENCUMBRANCE,
            ref=HOLD_REF_ALPHA,
        ),
        ConditionSpec(
            condition_key="cond/funding",
            kind=ConditionKind.FUNDING,
            ref=FUNDING_REF,
        ),
    )


def _create(reservation_id: str, resource_key: str, provider: str, conditions=()):
    return create_reservation(
        reservation_id=reservation_id,
        resource_key=resource_key,
        provider=provider,
        beneficiary="principal/merchant-42",
        asset=ASSET,
        amount=Amount(value=25000, scale=2, asset=ASSET),
        window=OperatingWindow(opens_at=OPENS_AT, closes_at=CLOSES_AT),
        conditions=conditions,
        funding_refs=(FUNDING_REF,),
        environment_id=ENV,
        domain_id=DOMAIN,
        provenance=_prov(f"reservation/dogfooding/create/{reservation_id}"),
        correlation_id="corr/w-012-dogfooding",
    )


def _reset_table(conn) -> None:
    """Create the experiment table fresh for this run (fixed name)."""
    with conn.cursor() as cur:
        cur.execute(f"DROP TABLE IF EXISTS {TABLE}")
        cur.execute(
            f"CREATE TABLE {TABLE} ("
            "resource_key TEXT PRIMARY KEY, "
            "reservation_id TEXT NOT NULL, "
            "state TEXT NOT NULL, "
            "object_version INTEGER NOT NULL)"
        )
    conn.commit()


def _experiment_a_create_race(conn_alpha, conn_beta, store, lines) -> None:
    """Two actors race to create a reservation on the SAME resource key."""
    record_alpha = _create(RESERVATION_A, KEY_ONE, "provider/alpha", _conditions())
    record_beta = _create(RESERVATION_B, KEY_ONE, "provider/alpha")
    first, second = resolve_precedence((CLAIM_BETA, CLAIM_ALPHA))
    assert (first.actor, second.actor) == ("actor/alpha", "actor/beta")
    lines.append("exp=A same-key create race (unique constraint)")
    lines.append("precedence=actor/alpha first (rule: earliest requested_at)")

    # The precedence winner inserts first and leaves the row uncommitted.
    with conn_alpha.cursor() as cur:
        cur.execute(
            f"INSERT INTO {TABLE} (resource_key, reservation_id, state, object_version)"
            " VALUES (%s, %s, %s, %s)",
            (KEY_ONE, RESERVATION_A, "RESERVED", 1),
        )
    lines.append(f"a.insert {KEY_ONE} {RESERVATION_A} (uncommitted)")

    # The loser races on the same key from its own connection: its insert
    # contends with the winner's uncommitted unique-index entry and is
    # decided by the server (UniqueViolation once the winner commits).
    issued = threading.Event()
    finished = threading.Event()
    outcome: dict[str, str] = {}

    def beta_insert() -> None:
        issued.set()
        try:
            with conn_beta.cursor() as cur:
                cur.execute(
                    f"INSERT INTO {TABLE} (resource_key, reservation_id, state, object_version)"
                    " VALUES (%s, %s, %s, %s)",
                    (KEY_ONE, RESERVATION_B, "RESERVED", 1),
                )
            outcome["insert"] = "applied"
        except psycopg2.errors.UniqueViolation:
            outcome["insert"] = "UniqueViolation"
        except Exception as exc:  # pragma: no cover - harness plumbing
            outcome["insert"] = f"unexpected:{type(exc).__name__}"
        finally:
            conn_beta.rollback()
            finished.set()

    thread = threading.Thread(target=beta_insert)
    thread.start()
    assert issued.wait(timeout=60)
    lines.append(f"b.insert {KEY_ONE} {RESERVATION_B} (issued while a uncommitted)")
    conn_alpha.commit()
    lines.append("a.commit")
    assert finished.wait(timeout=60)
    thread.join(timeout=60)
    assert not thread.is_alive()
    assert outcome["insert"] == "UniqueViolation", outcome
    lines.append("b.error=UniqueViolation")
    lines.append("b.rollback")

    lines.append(f"winner=actor/alpha {RESERVATION_A}")
    lines.append(f"loser=actor/beta {RESERVATION_B}")
    lines.append("loser.reason=resource key admits at most one live reservation")
    lines.append(
        "loser.provenance=precedence requested_at "
        f"{CLAIM_ALPHA.requested_at} < {CLAIM_BETA.requested_at}"
    )

    # Domain mirror: the store must leave the same single winner.
    store.apply(
        (record_alpha,),
        expected_versions=(ExpectedVersion(RESERVATION_A, 0),),
        writer=CLAIM_ALPHA,
    )
    lines.append(f"domain.winner_applied={RESERVATION_A}")
    try:
        store.apply(
            (record_beta,),
            expected_versions=(ExpectedVersion(RESERVATION_B, 0),),
            writer=CLAIM_BETA,
        )
        raise AssertionError("domain mirror: the second live creation must be denied")
    except CoreValidationError as exc:
        assert "at most one live reservation" in str(exc), exc
    lines.append("domain.loser_denied_by=live_key_exclusivity")

    with conn_alpha.cursor() as cur:
        cur.execute(f"SELECT count(*) FROM {TABLE} WHERE resource_key = %s", (KEY_ONE,))
        live_rows = cur.fetchone()[0]
    conn_alpha.commit()
    assert live_rows == 1, live_rows
    lines.append(f"pg.live_rows_on_key={live_rows}")


def _experiment_a_hold_race(conn_alpha, conn_beta, store, lines) -> None:
    """The two actors then race to hold the winner's reservation."""
    lines.append("exp=A same-key hold race (row-level locking)")
    stored = store.get(RESERVATION_A)
    hold_alpha = hold_reservation(
        stored,
        as_of=HOLD_AT,
        hold_ref=HOLD_REF_ALPHA,
        provenance=_prov("reservation/dogfooding/hold-alpha"),
    )
    hold_beta = hold_reservation(
        stored,
        as_of=HOLD_AT,
        hold_ref=HOLD_REF_BETA,
        provenance=_prov("reservation/dogfooding/hold-beta"),
    )

    # The winner takes the row lock and holds it uncommitted.
    with conn_alpha.cursor() as cur:
        cur.execute(
            f"SELECT reservation_id FROM {TABLE} WHERE resource_key = %s FOR UPDATE",
            (KEY_ONE,),
        )
        assert cur.fetchone() == (RESERVATION_A,)
    lines.append(f"a.lock {KEY_ONE} (SELECT FOR UPDATE, uncommitted)")

    # The loser proves the row lock is really held: NOWAIT fails.
    try:
        with conn_beta.cursor() as cur:
            cur.execute(
                f"SELECT reservation_id FROM {TABLE}"
                " WHERE resource_key = %s FOR UPDATE NOWAIT",
                (KEY_ONE,),
            )
        raise AssertionError("NOWAIT must fail while alpha holds the row lock")
    except psycopg2.errors.LockNotAvailable:
        pass
    conn_beta.rollback()
    lines.append("b.nowait=LockNotAvailable (row lock held by actor/alpha)")

    # The loser's hold update races on the row lock with a stale expected
    # version (1): it can only complete after the winner commits v2, and
    # then the version predicate matches zero rows.
    issued = threading.Event()
    finished = threading.Event()
    outcome: dict[str, int] = {}

    def beta_update() -> None:
        issued.set()
        try:
            with conn_beta.cursor() as cur:
                cur.execute(
                    f"UPDATE {TABLE} SET state = %s, object_version = 2"
                    " WHERE resource_key = %s AND object_version = 1",
                    ("HELD", KEY_ONE),
                )
                outcome["rows"] = cur.rowcount
        except Exception as exc:  # pragma: no cover - harness plumbing
            outcome["rows"] = -1
            outcome["error"] = type(exc).__name__
        finally:
            conn_beta.rollback()
            finished.set()

    thread = threading.Thread(target=beta_update)
    thread.start()
    assert issued.wait(timeout=60)
    lines.append(
        f"b.update {KEY_ONE} (issued while a holds the row lock, expected version 1)"
    )

    # The winner performs the hold transition and commits.
    with conn_alpha.cursor() as cur:
        cur.execute(
            f"UPDATE {TABLE} SET state = %s, object_version = 2"
            " WHERE resource_key = %s AND object_version = 1",
            ("HELD", KEY_ONE),
        )
        assert cur.rowcount == 1
    lines.append("a.update state=HELD version=2")
    conn_alpha.commit()
    lines.append("a.commit")
    assert finished.wait(timeout=60)
    thread.join(timeout=60)
    assert not thread.is_alive()
    assert outcome["rows"] == 0, outcome
    lines.append(f"b.rows_updated={outcome['rows']}")
    lines.append("b.reason=expected-version conflict (writer expected 1, store holds 2)")
    lines.append("b.rollback")

    # Domain mirror: the same hold race through the versioned store.
    store.apply(
        (hold_alpha,),
        expected_versions=(ExpectedVersion(RESERVATION_A, 1),),
        writer=CLAIM_ALPHA,
    )
    try:
        store.apply(
            (hold_beta,),
            expected_versions=(ExpectedVersion(RESERVATION_A, 1),),
            writer=CLAIM_BETA,
        )
        raise AssertionError("domain mirror: the stale hold must be denied")
    except CoreValidationError as exc:
        assert "expected-version conflict" in str(exc), exc
    lines.append("domain.hold_loser_denied_by=expected_version")

    # PostgreSQL and the domain agree on the outcome.
    with conn_alpha.cursor() as cur:
        cur.execute(
            f"SELECT state, object_version FROM {TABLE} WHERE resource_key = %s",
            (KEY_ONE,),
        )
        row = cur.fetchone()
    conn_alpha.commit()
    held = store.get(RESERVATION_A)
    assert row == ("HELD", 2), row
    assert (held.state.value, held.envelope.object_version) == ("HELD", 2)
    lines.append(f"pg.hold_state={row[0]} v{row[1]}")
    lines.append(f"domain.hold_state={held.state.value} v{held.envelope.object_version}")


def _experiment_b(conn_alpha, conn_beta, store, lines) -> None:
    """Keyed-not-global: beta commits key two while alpha holds key one."""
    lines.append("exp=B keyed-not-global concurrency")

    # Alpha re-acquires key one's row lock and holds it uncommitted.
    with conn_alpha.cursor() as cur:
        cur.execute(
            f"SELECT reservation_id FROM {TABLE} WHERE resource_key = %s FOR UPDATE",
            (KEY_ONE,),
        )
        assert cur.fetchone() == (RESERVATION_A,)
    lines.append(f"a.lock {KEY_ONE} (uncommitted)")

    # Beta proves the lock is still held, then commits a DIFFERENT key.
    try:
        with conn_beta.cursor() as cur:
            cur.execute(
                f"SELECT reservation_id FROM {TABLE}"
                " WHERE resource_key = %s FOR UPDATE NOWAIT",
                (KEY_ONE,),
            )
        raise AssertionError("NOWAIT must fail while alpha holds the row lock")
    except psycopg2.errors.LockNotAvailable:
        pass
    conn_beta.rollback()
    lines.append("b.nowait=LockNotAvailable (key one row lock still held)")
    with conn_beta.cursor() as cur:
        cur.execute(
            f"INSERT INTO {TABLE} (resource_key, reservation_id, state, object_version)"
            " VALUES (%s, %s, %s, %s)",
            (KEY_TWO, RESERVATION_B2, "RESERVED", 1),
        )
        assert cur.rowcount == 1
        cur.execute(
            f"UPDATE {TABLE} SET state = %s, object_version = 2"
            " WHERE resource_key = %s AND object_version = 1",
            ("COMMITTED", KEY_TWO),
        )
        assert cur.rowcount == 1
    conn_beta.commit()
    lines.append(f"b.insert {KEY_TWO} {RESERVATION_B2} (different key)")
    lines.append("b.update state=COMMITTED version=2 (condition-free commit)")
    lines.append("b.commit=ok (key two committed while key one lock held)")

    # Alpha then conditionally commits key one (version 3).
    with conn_alpha.cursor() as cur:
        cur.execute(
            f"UPDATE {TABLE} SET state = %s, object_version = 3"
            " WHERE resource_key = %s AND object_version = 2",
            ("COMMITTED", KEY_ONE),
        )
        assert cur.rowcount == 1
    lines.append("a.update state=COMMITTED version=3 (conditional commit)")
    conn_alpha.commit()
    lines.append("a.commit=ok")
    lines.append("interleaved=beta committed before alpha (no global serialization)")

    # Domain mirror: while alpha's domain gate on key one is held, beta's
    # commit on key two succeeds — keyed, never global.
    record_beta2 = _create(RESERVATION_B2, KEY_TWO, "provider/beta")
    store.apply(
        (record_beta2,),
        expected_versions=(ExpectedVersion(RESERVATION_B2, 0),),
        writer=CLAIM_BETA,
    )
    commit_beta = commit_reservation(
        store.get(RESERVATION_B2),
        as_of=COMMIT_AT,
        provenance=_prov("reservation/dogfooding/commit-beta"),
    )
    commit_alpha = commit_reservation(
        store.get(RESERVATION_A),
        as_of=COMMIT_AT,
        satisfied_conditions=("cond/encumbrance", "cond/funding"),
        evidence_refs=("evidence/work-012-dogfooding",),
        provenance=_prov("reservation/dogfooding/commit-alpha"),
    )
    with store.locks().locked(KEY_ONE, claim=CLAIM_ALPHA):
        store.apply(
            (commit_beta,),
            expected_versions=(ExpectedVersion(RESERVATION_B2, 1),),
            writer=CLAIM_BETA,
        )
        lines.append(
            "domain.b_cross_key_apply=ok (key two committed while key one gate held)"
        )
    store.apply(
        (commit_alpha,),
        expected_versions=(ExpectedVersion(RESERVATION_A, 2),),
        writer=CLAIM_ALPHA,
    )
    lines.append("domain.a_apply=ok (conditional commit with satisfied conditions)")

    # Final agreement between PostgreSQL and the domain.
    with conn_alpha.cursor() as cur:
        cur.execute(
            f"SELECT resource_key, reservation_id, state, object_version FROM {TABLE}"
            " ORDER BY resource_key"
        )
        rows = cur.fetchall()
        cur.execute(
            f"SELECT resource_key, count(*) FROM {TABLE}"
            " GROUP BY resource_key ORDER BY resource_key"
        )
        grouped = cur.fetchall()
    conn_alpha.commit()
    assert rows == [
        (KEY_ONE, RESERVATION_A, "COMMITTED", 3),
        (KEY_TWO, RESERVATION_B2, "COMMITTED", 2),
    ], rows
    assert grouped == [(KEY_ONE, 1), (KEY_TWO, 1)], grouped
    for row in rows:
        lines.append(f"pg.row {row[0]} {row[1]} {row[2]} v{row[3]}")
    lines.append("pg.live_per_key=1")
    lines.append(f"pg.row_count={len(rows)}")
    final_alpha = store.get(RESERVATION_A)
    final_beta = store.get(RESERVATION_B2)
    assert (final_alpha.state.value, final_alpha.envelope.object_version) == (
        "COMMITTED",
        3,
    )
    assert (final_beta.state.value, final_beta.envelope.object_version) == (
        "COMMITTED",
        2,
    )
    lines.append(f"domain.snapshot_digest={store.snapshot_digest()}")


def build_transcript() -> tuple[str, str]:
    """Build the deterministic DOGFOOD-012 transcript and its digest.

    Two real separate connections (two actors) race on the fixed
    experiment table; every invariant is verified before it is printed,
    so a printed PASS transcript is a proven one.
    """
    server = pgserver.get_server(DATADIR)
    conn_alpha = psycopg2.connect(server.get_uri())
    conn_beta = psycopg2.connect(server.get_uri())
    try:
        with conn_alpha.cursor() as cur:
            cur.execute("SHOW server_version")
            server_version = cur.fetchone()[0]
        conn_alpha.commit()
        _reset_table(conn_alpha)
        lines = [
            "DOGFOOD-012: two-actor real-PostgreSQL race on keyed reservations",
            f"server=PostgreSQL/{server_version}",
            f"table={TABLE}",
            "actors=actor/alpha+actor/beta (two separate connections)",
            "schedule=domain precedence rule and issued/commit event ordering (no clock reads)",
        ]
        store = ReservationStore()
        _experiment_a_create_race(conn_alpha, conn_beta, store, lines)
        _experiment_a_hold_race(conn_alpha, conn_beta, store, lines)
        _experiment_b(conn_alpha, conn_beta, store, lines)
        transcript = "\n".join(lines)
        digest = canonical_sha256({"transcript": transcript})
        return transcript, digest
    finally:
        conn_alpha.close()
        conn_beta.close()


def main() -> str:
    """Run DOGFOOD-012, print the transcript and return its digest."""
    transcript, digest = build_transcript()
    print(transcript)
    print(f"digest={digest}")
    print("DOGFOOD-012: PASS")
    return digest


if __name__ == "__main__":  # pragma: no cover - manual conformance run
    main()
