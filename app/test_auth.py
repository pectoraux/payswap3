from __future__ import annotations

import os
import tempfile
import unittest

os.environ["PAYSWAP_DEMO_MODE"] = "true"

from app.auth import (
    DEFAULT_ADMIN_USERNAME,
    _connect,
    authenticate,
    create_user_from_waitlist,
    ensure_default_admin,
    ensure_demo_users,
    join_waitlist,
)
from app.workflows import get_task


class AuthShellTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["PAYSWAP_AUTH_DB"] = os.path.join(self.tmp.name, "auth.sqlite3")
        ensure_demo_users()
        ensure_default_admin()
        from app.server import create_app
        self.app = create_app()
        self.client = self.app.test_client()

    def tearDown(self) -> None:
        self.tmp.cleanup()
        os.environ.pop("PAYSWAP_AUTH_DB", None)

    def csrf(self, path: str = "/login") -> str:
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200)
        with self.client.session_transaction() as state:
            token = state.get("_csrf_token")
        self.assertIsNotNone(token)
        return token

    def sign_in_demo(self, username: str) -> str:
        response = self.client.get(f"/demo/{username}", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        with self.client.session_transaction() as state:
            token = state.get("_csrf_token")
        self.assertIsNotNone(token)
        return token

    def test_seeded_admin_is_real_not_demo(self) -> None:
        row = authenticate(DEFAULT_ADMIN_USERNAME, "Payswap123456")
        self.assertIsNotNone(row)
        assert row is not None
        self.assertEqual(row["role"], "admin")
        self.assertEqual(row["is_demo"], 0)

    def test_demo_accounts_are_present_for_all_roles(self) -> None:
        conn = _connect()
        rows = conn.execute("SELECT COUNT(*) AS count FROM users WHERE is_demo=1").fetchone()
        conn.close()
        self.assertEqual(rows["count"], 8)

    def test_demo_admin_cannot_open_real_access_control(self) -> None:
        response = self.client.get("/demo/demo-admin")
        self.assertEqual(response.status_code, 302)
        response = self.client.get("/admin")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/app", response.headers["Location"])

    def test_protected_post_requires_csrf(self) -> None:
        response = self.client.post("/waitlist", data={"name": "No Token", "email": "no-token@example.com"})
        self.assertEqual(response.status_code, 302)
        conn = _connect()
        row = conn.execute("SELECT id FROM waitlist WHERE email=?", ("no-token@example.com",)).fetchone()
        conn.close()
        self.assertIsNone(row)

    def test_customer_can_complete_sandbox_pay_workflow(self) -> None:
        token = self.sign_in_demo("demo-customer")
        response = self.client.post(
            "/app/pay",
            data={"csrf_token": token, "recipient": "Supplier Co", "amount": "8450.00", "asset": "USD", "deadline": "2030-01-02T12:00"},
        )
        self.assertEqual(response.status_code, 302)
        task_id = int(response.headers["Location"].rsplit("/", 1)[1])
        task = get_task(task_id, owner_id=1)
        self.assertIsNotNone(task)
        assert task is not None
        self.assertEqual(task["state"], "DRAFT")
        self.client.get(response.headers["Location"])
        with self.client.session_transaction() as state:
            token = state["_csrf_token"]
        self.client.post(f"/app/task/{task_id}/options", data={"csrf_token": token})
        self.client.post(f"/app/task/{task_id}/choose", data={"csrf_token": token, "option": "balanced"})
        self.client.post(f"/app/task/{task_id}/simulate", data={"csrf_token": token})
        task = get_task(task_id, owner_id=1)
        self.assertEqual(task["state"], "COMPLETED")
        self.assertEqual(task["selected_option"], "balanced")

    def test_merchant_can_create_checkout_and_customer_cannot(self) -> None:
        token = self.sign_in_demo("demo-merchant")
        response = self.client.post(
            "/app/checkout",
            data={"csrf_token": token, "customer": "Customer One", "amount": "250.00", "asset": "USD", "reference": "ORDER-1042"},
        )
        self.assertEqual(response.status_code, 302)
        self.client.get(response.headers["Location"])
        with self.client.session_transaction() as state:
            state["user"] = {"id": 1, "username": "demo-customer", "name": "Maya Customer", "role": "customer", "demo": True}
        response = self.client.get("/app/checkout")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/app", response.headers["Location"])

    def test_task_data_is_owner_scoped(self) -> None:
        token = self.sign_in_demo("demo-customer")
        response = self.client.post("/app/pay", data={"csrf_token": token, "recipient": "Private Co", "amount": "10", "asset": "USD", "deadline": "2030-01-02T12:00"})
        self.assertEqual(response.status_code, 302)
        task_id = int(response.headers["Location"].rsplit("/", 1)[1])
        self.assertIsNotNone(get_task(task_id, owner_id=1))
        self.assertIsNone(get_task(task_id, owner_id=999999))

    def test_waitlist_then_admin_account_creation(self) -> None:
        token = self.csrf("/waitlist")
        ok, message = join_waitlist("Test User", "test@example.com", "merchant", "Example Co")
        self.assertTrue(ok, message)
        conn = _connect()
        item = conn.execute("SELECT id FROM waitlist WHERE email=?", ("test@example.com",)).fetchone()
        conn.close()
        self.assertIsNotNone(item)
        assert item is not None
        with self.client.session_transaction() as state:
            state["user"] = {"id": 1, "username": DEFAULT_ADMIN_USERNAME, "name": "Ekontetevi Admin", "role": "admin", "demo": False}
            state["_csrf_token"] = token
        response = self.client.post(
            "/admin/create-account",
            data={
                "csrf_token": token,
                "waitlist_id": str(item["id"]),
                "username": "test@example.com",
                "name": "Test User",
                "role": "merchant",
                "password": "temporary-password-123",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertIsNotNone(authenticate("test@example.com", "temporary-password-123"))


if __name__ == "__main__":
    unittest.main()
