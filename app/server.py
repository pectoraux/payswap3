from __future__ import annotations

import os
import secrets
from functools import wraps

from flask import Flask, flash, redirect, render_template, request, session, url_for

from .auth import ROLE_LABELS, ROLES, authenticate, bootstrap_admin_from_env, create_user_from_waitlist, demo_role_cards, ensure_demo_users, get_demo, join_waitlist, list_waitlist


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
    bootstrap_admin_from_env()

    def current_user():
        return session.get("user")

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
                return fn(*args, **kwargs)
            return wrapper
        return decorator

    @app.context_processor
    def inject():
        return {"current_user": current_user(), "roles": ROLES, "role_labels": ROLE_LABELS, "demo_mode": app.config["DEMO_MODE"]}

    @app.get("/")
    def index():
        if current_user():
            return redirect(url_for("dashboard"))
        return render_template("landing.html", demo_cards=demo_role_cards())

    @app.get("/login")
    def login():
        if current_user():
            return redirect(url_for("dashboard"))
        return render_template("login.html", demo_cards=demo_role_cards())

    @app.post("/login")
    def do_login():
        user = authenticate(request.form.get("username", ""), request.form.get("password", ""))
        if not user:
            flash("The email or password didn't match.", "error")
            return redirect(url_for("login"))
        session["user"] = {"id": user["id"], "username": user["username"], "name": user["name"], "role": user["role"], "demo": False}
        return redirect(request.args.get("next") or url_for("dashboard"))

    @app.get("/demo/<username>")
    def demo_login(username: str):
        if not app.config["DEMO_MODE"]:
            flash("Demo access is disabled.", "error")
            return redirect(url_for("login"))
        user = get_demo(username)
        if not user:
            flash("Demo account not found.", "error")
            return redirect(url_for("login"))
        session["user"] = {"id": user["id"], "username": user["username"], "name": user["name"], "role": user["role"], "demo": True}
        return redirect(url_for("dashboard"))

    @app.get("/logout")
    def logout():
        session.clear()
        return redirect(url_for("index"))

    @app.get("/waitlist")
    def waitlist():
        return render_template("waitlist.html")

    @app.post("/waitlist")
    def submit_waitlist():
        ok, message = join_waitlist(request.form.get("name", ""), request.form.get("email", ""), request.form.get("role", "customer"), request.form.get("organization", ""))
        flash(message, "success" if ok else "error")
        return redirect(url_for("waitlist"))

    @app.get("/app")
    @login_required()
    def dashboard():
        return render_template("dashboard.html")

    @app.get("/admin")
    @login_required("admin")
    def admin():
        return render_template("admin.html", waitlist=list_waitlist())

    @app.post("/admin/create-account")
    @login_required("admin")
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
