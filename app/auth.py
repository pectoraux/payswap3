from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import sqlite3
from pathlib import Path
from typing import Any

ROLES = (
    ("customer", "Customer", "Pay for things, track promises, receipts, and recourse."),
    ("merchant", "Merchant", "Create demand, get paid, manage fulfilment and exceptions."),
    ("provider", "Financial / Service Provider", "Offer rails, capabilities, quotes, and execution."),
    ("liquidity", "Liquidity Provider", "Supply liquidity, credit, collateral, and pricing."),
    ("developer", "Capability Developer", "Build, test, publish, and measure extensions."),
    ("agent", "Agent / Mediator", "Propose routes, compare outcomes, and coordinate safely."),
    ("operator", "Network Operations", "Monitor reliability, investigate cases, and recover incidents."),
    ("admin", "Administrator", "Manage access, participants, governance, and platform operations."),
)

ROLE_LABELS = {key: label for key, label, _ in ROLES}
DEMO_USERS = [
    ("demo-customer", "customer", "Maya Customer"),
    ("demo-merchant", "merchant", "Noah Merchant"),
    ("demo-provider", "provider", "Ari Provider"),
    ("demo-liquidity", "liquidity", "Sam Liquidity"),
    ("demo-developer", "developer", "Kai Developer"),
    ("demo-agent", "agent", "Ava Agent"),
    ("demo-operator", "operator", "Owen Operations"),
    ("demo-admin", "admin", "Alex Admin"),
]

DEFAULT_ADMIN_USERNAME = "ekontetevi@gmail"
DEFAULT_ADMIN_PASSWORD_HASH = "scrypt$15$8$1$pL1bkAUVQzmHqcshWJrZxQ==$_TR4n2WU1rKcGEPyCWSbnrYjrZeESa1jxtvwqRAaBaM="

SCHEMA = """
CREATE TABLE IF NOT EXISTS waitlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    role TEXT NOT NULL,
    organization TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'waiting',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    role TEXT NOT NULL,
    password_hash TEXT,
    is_demo INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


def _db_path() -> Path:
    return Path(os.getenv("PAYSWAP_AUTH_DB", "app/data/auth.sqlite3"))


def _connect() -> sqlite3.Connection:
    p = _db_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(p)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=2**15,
        r=8,
        p=1,
        dklen=32,
        maxmem=1024 * 1024 * 1024,
    )
    return "scrypt$15$8$1$" + base64.urlsafe_b64encode(salt).decode() + "$" + base64.urlsafe_b64encode(digest).decode()


def verify_password(password: str, encoded: str) -> bool:
    try:
        _, logn, r, p, salt_b64, digest_b64 = encoded.split("$")
        salt = base64.urlsafe_b64decode(salt_b64.encode())
        expected = base64.urlsafe_b64decode(digest_b64.encode())
        actual = hashlib.scrypt(
            password.encode(),
            salt=salt,
            n=2**int(logn),
            r=int(r),
            p=int(p),
            dklen=32,
            maxmem=1024 * 1024 * 1024,
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def ensure_demo_users() -> None:
    conn = _connect()
    for username, role, name in DEMO_USERS:
        conn.execute(
            "INSERT OR IGNORE INTO users(username,name,role,is_demo) VALUES(?,?,?,1)",
            (username, name, role),
        )
    conn.commit()
    conn.close()


def ensure_default_admin() -> bool:
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT id FROM users WHERE username=?",
            (DEFAULT_ADMIN_USERNAME,),
        ).fetchone()
        if row:
            conn.execute(
                "UPDATE users SET role='admin', is_demo=0 WHERE username=?",
                (DEFAULT_ADMIN_USERNAME,),
            )
        else:
            conn.execute(
                "INSERT INTO users(username,name,role,password_hash,is_demo) VALUES(?,?,?,?,0)",
                (
                    DEFAULT_ADMIN_USERNAME,
                    "Ekontetevi Admin",
                    "admin",
                    DEFAULT_ADMIN_PASSWORD_HASH,
                ),
            )
        conn.commit()
        return True
    finally:
        conn.close()


def bootstrap_admin_from_env() -> bool:
    email = os.getenv("PAYSWAP_ADMIN_EMAIL", "").strip().lower()
    password = os.getenv("PAYSWAP_ADMIN_PASSWORD", "")
    if not email or not password:
        return False
    conn = _connect()
    row = conn.execute("SELECT id FROM users WHERE username=?", (email,)).fetchone()
    encoded = hash_password(password)
    if row:
        conn.execute(
            "UPDATE users SET role='admin',password_hash=?,is_demo=0 WHERE username=?",
            (encoded, email),
        )
    else:
        conn.execute(
            "INSERT INTO users(username,name,role,password_hash,is_demo) VALUES(?,?,?,?,0)",
            (email, email.split("@")[0].replace(".", " ").title(), "admin", encoded),
        )
    conn.commit()
    conn.close()
    return True


def authenticate(username: str, password: str) -> sqlite3.Row | None:
    conn = _connect()
    row = conn.execute(
        "SELECT * FROM users WHERE lower(username)=lower(?) AND is_demo=0",
        (username.strip(),),
    ).fetchone()
    conn.close()
    return row if row and row["password_hash"] and verify_password(password, row["password_hash"]) else None


def get_demo(username: str) -> sqlite3.Row | None:
    conn = _connect()
    row = conn.execute(
        "SELECT * FROM users WHERE username=? AND is_demo=1",
        (username,),
    ).fetchone()
    conn.close()
    return row


def join_waitlist(name: str, email: str, role: str, organization: str) -> tuple[bool, str]:
    if not name.strip() or not email.strip() or "@" not in email:
        return False, "Please enter your name and a valid email."
    role = role if role in ROLE_LABELS else "customer"
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO waitlist(email,name,role,organization) VALUES(?,?,?,?)",
            (email.strip().lower(), name.strip(), role, organization.strip()),
        )
        conn.commit()
        return True, "You're on the list."
    except sqlite3.IntegrityError:
        return False, "That email is already on the waitlist."
    finally:
        conn.close()


def list_waitlist() -> list[sqlite3.Row]:
    conn = _connect()
    rows = conn.execute("SELECT * FROM waitlist ORDER BY id DESC").fetchall()
    conn.close()
    return rows


def create_user_from_waitlist(
    waitlist_id: int,
    username: str,
    name: str,
    role: str,
    password: str,
) -> tuple[bool, str]:
    role = role if role in ROLE_LABELS and role != "admin" else "customer"
    if len(password) < 10:
        return False, "Use a temporary password of at least 10 characters."
    username = username.strip().lower()
    name = name.strip()
    if not username or not name:
        return False, "Username and name are required."
    conn = _connect()
    try:
        item = conn.execute("SELECT * FROM waitlist WHERE id=?", (waitlist_id,)).fetchone()
        if not item:
            return False, "Waitlist entry not found."
        conn.execute(
            "INSERT INTO users(username,name,role,password_hash,is_demo) VALUES(?,?,?,?,0)",
            (username, name, role, hash_password(password)),
        )
        conn.execute("UPDATE waitlist SET status='account_created' WHERE id=?", (waitlist_id,))
        conn.commit()
        return True, "Account created."
    except sqlite3.IntegrityError:
        return False, "That username already exists."
    finally:
        conn.close()


def demo_role_cards() -> list[dict[str, Any]]:
    return [
        {"username": u, "role": role, "label": ROLE_LABELS[role]}
        for u, role, _ in DEMO_USERS
    ]
