from __future__ import annotations

import hmac
import os
import secrets
from functools import wraps
from urllib.parse import urlparse

from flask import Flask, flash, redirect, render_template, request, session, url_for

from .auth import ROLE_LABELS, ROLES, authenticate, bootstrap_admin_from_env, create_user_from_waitlist, demo_role_cards, ensure_default_admin, ensure_demo_users, get_demo, join_waitlist, list_waitlist
from .workflows import advance_task, create_task, decode_payload, get_task, list_tasks, route_options, validate_checkout, validate_pay


def _safe_next(value: str | None) -> str:
    if not value:
        return url_for("dashboard")
    parsed = urlparse(value)
    if parsed.scheme or parsed.netloc or not value.startswith("/"):
        return url_for("dashboard")
    return value


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.secret_key = os.getenv("PAYSWAP_SESSION_SECRET", secrets.token_hex(32))
    app.config.update(
        DEMO_MODE=os.getenv("PAYSWAP_DEMO_MODE", "true").lower() == "true",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.getenv("PAYSWAP_COOKIE_SECURE", "false").lower() == "true",
    )
    ensure_demo_users()
    ensure_default_admin()
    bootstrap_admin_from_env()

    def current_user():
        return session.get("user")

    def csrf_token() -> str:
        token = session.get("_csrf_token")
        if not token:
            token = secrets.token_urlsafe(32)
            session["_csrf_token"] = token
        return token

    def csrf_protected(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            expected = session.get("_csrf_token")
            supplied = request.form.get("csrf_token", "")
            if not expected or not supplied or not hmac.compare_digest(expected, supplied):
                flash("Your session expired. Please try again.", "error")
                return redirect(url_for("login"))
            return fn(*args, **kwargs)
        return wrapper

    def login_required(role=None):
        def decorator(fn):
            @wraps(fn)
            def wrapper(*args, **kwargs):
                user = current_user()
                if not user:
                    return redirect(url_for("login", next=request.path))
                if role and user.get("role") != role:
                    flash("That area is restricted to administrators.", "error")
                    return redirect(url_for("dashboard"))
                if role == "admin" and user.get("demo"):
                    flash("Demo administrator access is view-only.", "error")
                    return redirect(url_for("dashboard"))
                return fn(*args, **kwargs)
            return wrapper
        return decorator

    def owner_id() -> int:
        return int(current_user()["id"])

    def task_or_404(task_id: int):
        task = get_task(task_id, owner_id=owner_id())
        if not task:
            from flask import abort
            abort(404)
        return task

    @app.context_processor
    def inject():
        return {
            "current_user": current_user(),
            "roles": ROLES,
            "role_labels": ROLE_LABELS,
            "demo_mode": app.config["DEMO_MODE"],
            "csrf_token": csrf_token,
        }

    @app.get("/")
    def index():
        if current_user():
            return redirect(url_for("dashboard"))
        return render_template("landing.html", demo_cards=demo_role_cards())

    @app.get("/login")
    def login():
        if current_user():
            return redirect(url_for("dashboard"))
        return render_template("login.html", demo_cards=demo_role_cards(), next_url=_safe_next(request.args.get("next")))

    @app.post("/login")
    @csrf_protected
    def do_login():
        user = authenticate(request.form.get("username", ""), request.form.get("password", ""))
        if not user:
            flash("The email or password didn't match.", "error")
            return redirect(url_for("login"))
        session.clear()
        session["user"] = {"id": user["id"], "username": user["username"], "name": user["name"], "role": user["role"], "demo": False}
        return redirect(_safe_next(request.form.get("next")))

    @app.get("/demo/<username>")
    def demo_login(username: str):
        if not app.config["DEMO_MODE"]:
            flash("Demo access is disabled.", "error")
            return redirect(url_for("login"))
        user = get_demo(username)
        if not user:
            flash("Demo account not found.", "error")
            return redirect(url_for("login"))
        session.clear()
        session["user"] = {"id": user["id"], "username": user["username"], "name": user["name"], "role": user["role"], "demo": True}
        return redirect(url_for("dashboard"))

    @app.post("/logout")
    @csrf_protected
    def logout():
        session.clear()
        return redirect(url_for("index"))

    @app.get("/waitlist")
    def waitlist():
        return render_template("waitlist.html")

    @app.post("/waitlist")
    @csrf_protected
    def submit_waitlist():
        ok, message = join_waitlist(request.form.get("name", ""), request.form.get("email", ""), request.form.get("role", "customer"), request.form.get("organization", ""))
        flash(message, "success" if ok else "error")
        return redirect(url_for("waitlist"))

    @app.get("/app")
    @login_required()
    def dashboard():
        return render_template("dashboard.html", tasks=list_tasks(owner_id=owner_id()))

    def role_required(expected_role: str):
        return login_required(expected_role)

    @app.get("/app/pay")
    @role_required("customer")
    def pay():
        return render_template("workflow_form.html", kind="pay", eyebrow="CUSTOMER WORKSPACE", heading="Pay someone", description="Describe the outcome. PaySwap will show a small number of meaningful sandbox choices before you decide.")

    @app.post("/app/pay")
    @role_required("customer")
    @csrf_protected
    def submit_pay():
        try:
            payload = validate_pay(request.form.get("recipient", ""), request.form.get("amount", ""), request.form.get("asset", ""), request.form.get("deadline", ""))
            task_id = create_task(owner_id=owner_id(), owner_role="customer", kind="pay", payload=payload)
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("pay"))
        return redirect(url_for("task_detail", task_id=task_id))

    @app.get("/app/checkout")
    @role_required("merchant")
    def checkout():
        return render_template("workflow_form.html", kind="checkout", eyebrow="MERCHANT WORKSPACE", heading="Create a checkout", description="Turn a customer request into a clear payment outcome without exposing network internals.")

    @app.post("/app/checkout")
    @role_required("merchant")
    @csrf_protected
    def submit_checkout():
        try:
            payload = validate_checkout(request.form.get("customer", ""), request.form.get("amount", ""), request.form.get("asset", ""), request.form.get("reference", ""))
            task_id = create_task(owner_id=owner_id(), owner_role="merchant", kind="checkout", payload=payload)
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("checkout"))
        return redirect(url_for("task_detail", task_id=task_id))

    @app.get("/app/task/<int:task_id>")
    @login_required()
    def task_detail(task_id: int):
        task = task_or_404(task_id)
        state_labels = {"DRAFT": "Draft", "OPTIONS": "Options ready", "NEEDS_DECISION": "Needs your decision", "IN_PROGRESS": "In progress", "WAITING": "Waiting", "COMPLETED": "Completed", "NEEDS_ATTENTION": "Needs attention"}
        return render_template("workflow_task.html", task=task, payload=decode_payload(task), options=route_options(task), state_label=state_labels[task["state"]])

    @app.post("/app/task/<int:task_id>/options")
    @login_required()
    @csrf_protected
    def show_task_options(task_id: int):
        task_or_404(task_id)
        advance_task(task_id, owner_id=owner_id(), state="OPTIONS")
        return redirect(url_for("task_detail", task_id=task_id))

    @app.post("/app/task/<int:task_id>/choose")
    @login_required()
    @csrf_protected
    def choose_task_option(task_id: int):
        task = task_or_404(task_id)
        chosen = request.form.get("option", "")
        valid = {option["id"] for option in route_options(task)}
        if chosen not in valid:
            flash("Choose one of the presented options.", "error")
            return redirect(url_for("task_detail", task_id=task_id))
        advance_task(task_id, owner_id=owner_id(), state="IN_PROGRESS", selected_option=chosen)
        return redirect(url_for("task_detail", task_id=task_id))

    @app.post("/app/task/<int:task_id>/simulate")
    @login_required()
    @csrf_protected
    def simulate_task(task_id: int):
        task_or_404(task_id)
        advance_task(task_id, owner_id=owner_id(), state="COMPLETED")
        return redirect(url_for("task_detail", task_id=task_id))

    @app.get("/admin")
    @login_required("admin")
    def admin():
        return render_template("admin.html", waitlist=list_waitlist())

    @app.post("/admin/create-account")
    @login_required("admin")
    @csrf_protected
    def admin_create_account():
        try:
            waitlist_id = int(request.form.get("waitlist_id", "0"))
        except ValueError:
            waitlist_id = 0
        ok, message = create_user_from_waitlist(waitlist_id, request.form.get("username", ""), request.form.get("name", ""), request.form.get("role", "customer"), request.form.get("password", ""))
        flash(message, "success" if ok else "error")
        return redirect(url_for("admin"))

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "5000")), debug=os.getenv("DEBUG", "false").lower() == "true")
