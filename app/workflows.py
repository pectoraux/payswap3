from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TASK_STATES = ("DRAFT", "OPTIONS", "NEEDS_DECISION", "IN_PROGRESS", "WAITING", "COMPLETED", "NEEDS_ATTENTION")
TASK_KINDS = {"pay": "Pay someone", "checkout": "Create a checkout"}


def _db_path() -> Path:
    return Path(os.getenv("PAYSWAP_AUTH_DB", "app/data/auth.sqlite3"))


def _connect() -> sqlite3.Connection:
    path = _db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE IF NOT EXISTS product_tasks (id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL, owner_role TEXT NOT NULL, kind TEXT NOT NULL, state TEXT NOT NULL, title TEXT NOT NULL, payload_json TEXT NOT NULL, selected_option TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, protocol_binding_json TEXT, protocol_binding_created_at TEXT, execution_handoff_json TEXT, execution_handoff_created_at TEXT, execution_runtime_json TEXT, execution_runtime_created_at TEXT)")
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(product_tasks)")}
    if "protocol_binding_json" not in columns:
        conn.execute("ALTER TABLE product_tasks ADD COLUMN protocol_binding_json TEXT")
    if "protocol_binding_created_at" not in columns:
        conn.execute("ALTER TABLE product_tasks ADD COLUMN protocol_binding_created_at TEXT")
    if "execution_handoff_json" not in columns:
        conn.execute("ALTER TABLE product_tasks ADD COLUMN execution_handoff_json TEXT")
    if "execution_handoff_created_at" not in columns:
        conn.execute("ALTER TABLE product_tasks ADD COLUMN execution_handoff_created_at TEXT")
    if "execution_runtime_json" not in columns:
        conn.execute("ALTER TABLE product_tasks ADD COLUMN execution_runtime_json TEXT")
    if "execution_runtime_created_at" not in columns:
        conn.execute("ALTER TABLE product_tasks ADD COLUMN execution_runtime_created_at TEXT")
    conn.commit()
    return conn


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def create_task(*, owner_id: int, owner_role: str, kind: str, payload: dict[str, Any]) -> int:
    if kind not in TASK_KINDS:
        raise ValueError("unsupported workflow")
    now = _now()
    conn = _connect()
    try:
        cur = conn.execute("INSERT INTO product_tasks(owner_id,owner_role,kind,state,title,payload_json,selected_option,created_at,updated_at,protocol_binding_json,protocol_binding_created_at,execution_handoff_json,execution_handoff_created_at,execution_runtime_json,execution_runtime_created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (owner_id, owner_role, kind, "DRAFT", payload.get("title") or TASK_KINDS[kind], json.dumps(payload, sort_keys=True), None, now, now, None, None, None, None, None, None))
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def get_task(task_id: int, *, owner_id: int) -> sqlite3.Row | None:
    conn = _connect()
    try:
        return conn.execute("SELECT * FROM product_tasks WHERE id=? AND owner_id=?", (task_id, owner_id)).fetchone()
    finally:
        conn.close()


def list_tasks(*, owner_id: int) -> list[sqlite3.Row]:
    conn = _connect()
    try:
        return conn.execute("SELECT * FROM product_tasks WHERE owner_id=? ORDER BY id DESC", (owner_id,)).fetchall()
    finally:
        conn.close()


def advance_task(task_id: int, *, owner_id: int, state: str, selected_option: str | None = None) -> bool:
    if state not in TASK_STATES:
        raise ValueError("unsupported task state")
    conn = _connect()
    try:
        cur = conn.execute("UPDATE product_tasks SET state=?, selected_option=COALESCE(?,selected_option), updated_at=? WHERE id=? AND owner_id=?", (state, selected_option, _now(), task_id, owner_id))
        conn.commit()
        return cur.rowcount == 1
    finally:
        conn.close()


def save_protocol_binding(task_id: int, *, owner_id: int, binding: dict[str, Any]) -> bool:
    now = _now()
    encoded = json.dumps(binding, sort_keys=True)
    conn = _connect()
    try:
        cur = conn.execute("UPDATE product_tasks SET protocol_binding_json=?, protocol_binding_created_at=?, updated_at=? WHERE id=? AND owner_id=? AND protocol_binding_json IS NULL", (encoded, now, now, task_id, owner_id))
        conn.commit()
        return cur.rowcount == 1
    finally:
        conn.close()


def save_execution_handoff(task_id: int, *, owner_id: int, handoff: dict[str, Any]) -> bool:
    now = _now()
    encoded = json.dumps(handoff, sort_keys=True)
    conn = _connect()
    try:
        cur = conn.execute("UPDATE product_tasks SET execution_handoff_json=?, execution_handoff_created_at=?, updated_at=? WHERE id=? AND owner_id=? AND execution_handoff_json IS NULL", (encoded, now, now, task_id, owner_id))
        conn.commit()
        return cur.rowcount == 1
    finally:
        conn.close()


def save_execution_runtime(task_id: int, *, owner_id: int, runtime: dict[str, Any]) -> bool:
    now = _now()
    encoded = json.dumps(runtime, sort_keys=True)
    conn = _connect()
    try:
        cur = conn.execute("UPDATE product_tasks SET execution_runtime_json=?, execution_runtime_created_at=?, updated_at=? WHERE id=? AND owner_id=? AND execution_runtime_json IS NULL", (encoded, now, now, task_id, owner_id))
        conn.commit()
        return cur.rowcount == 1
    finally:
        conn.close()


def decode_payload(row: sqlite3.Row) -> dict[str, Any]:
    return json.loads(row["payload_json"])


def decode_protocol_binding(row: sqlite3.Row) -> dict[str, Any] | None:
    value = row["protocol_binding_json"]
    return None if value is None else json.loads(value)


def decode_execution_handoff(row: sqlite3.Row) -> dict[str, Any] | None:
    value = row["execution_handoff_json"]
    return None if value is None else json.loads(value)


def decode_execution_runtime(row: sqlite3.Row) -> dict[str, Any] | None:
    value = row["execution_runtime_json"]
    return None if value is None else json.loads(value)


def route_options(row: sqlite3.Row) -> list[dict[str, str]]:
    if row["kind"] == "pay":
        return [
            {"id": "balanced", "name": "Balanced route", "summary": "Balances timing, reliability, and cost for this sandbox request."},
            {"id": "fast", "name": "Fast route", "summary": "Prioritizes the requested completion time in the sandbox."},
            {"id": "conservative", "name": "Conservative route", "summary": "Prioritizes reliability and lower operational risk in the sandbox."},
        ]
    return [
        {"id": "balanced", "name": "Balanced checkout", "summary": "Optimizes completion reliability while keeping the buyer experience simple."},
        {"id": "fast", "name": "Fast checkout", "summary": "Optimizes for quick confirmation and a short fulfillment path."},
        {"id": "resilient", "name": "Resilient checkout", "summary": "Adds recovery flexibility around temporary route failures."},
    ]


def _validate_amount(amount: str) -> None:
    text = amount.strip()
    if not text or any(ch not in "0123456789." for ch in text) or text.count(".") > 1:
        raise ValueError("Enter a valid positive amount.")
    whole, dot, fraction = text.partition(".")
    if not whole or (dot and not fraction) or (not dot and not whole):
        raise ValueError("Enter a valid positive amount.")
    if len(fraction) > 18:
        raise ValueError("Use no more than 18 decimal places.")
    digits = (whole + fraction).lstrip("0") or "0"
    if int(digits) <= 0:
        raise ValueError("Enter a valid positive amount.")


def validate_pay(recipient: str, amount: str, asset: str, deadline: str) -> dict[str, str]:
    recipient, amount, asset, deadline = recipient.strip(), amount.strip(), asset.strip().upper(), deadline.strip()
    if not recipient or len(recipient) > 200:
        raise ValueError("Enter a recipient.")
    _validate_amount(amount)
    if not asset or len(asset) > 20:
        raise ValueError("Enter an asset symbol.")
    if not deadline:
        raise ValueError("Choose when the payment should arrive.")
    return {"title": f"Pay {recipient}", "recipient": recipient, "amount": amount, "asset": asset, "deadline": deadline}


def validate_checkout(customer: str, amount: str, asset: str, reference: str, deadline: str) -> dict[str, str]:
    customer, amount, asset, reference, deadline = customer.strip(), amount.strip(), asset.strip().upper(), reference.strip(), deadline.strip()
    if not customer or len(customer) > 200:
        raise ValueError("Enter a customer.")
    _validate_amount(amount)
    if not asset or len(asset) > 20:
        raise ValueError("Enter an asset symbol.")
    if not reference or len(reference) > 120:
        raise ValueError("Enter a checkout reference.")
    if not deadline:
        raise ValueError("Choose when the checkout should settle.")
    return {"title": f"Checkout for {customer}", "customer": customer, "amount": amount, "asset": asset, "reference": reference, "deadline": deadline}
