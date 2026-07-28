#!/usr/bin/env python3
"""Authenticated, stateless web front end for the SCA consolidator."""

from __future__ import annotations

import csv
import hashlib
import io
import os
import re
import secrets
import sqlite3
import threading
import zipfile
from contextlib import contextmanager
from datetime import timedelta
from functools import wraps
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Callable, Iterator
from urllib.parse import urlparse

import click
from flask import Flask, Response, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

from checkmarx_sca_consolidator_v2 import (
    BUILTIN_GROUP_RULES,
    EXPORT_BASENAME,
    OUTPUT_COLUMNS,
    SUMMARY_COLUMNS,
    ReportError,
    build_html_report,
    build_xlsx_bytes,
    env_int,
    load_report,
    make_rows,
    make_summary,
    spreadsheet_safe,
)
from security import AlbOidcVerifier, AuthenticationError, SlidingWindowLimiter


THEMES = ("midnight", "light", "blueprint")
ALLOWED_OUTPUTS = {"preview", "csv", "html", "xlsx"}

# Audit records are emitted as space-separated key=value pairs, so any value that
# can carry attacker-controlled text is reduced to characters that cannot forge a
# new field. Header values cannot contain raw newlines, but they can contain
# spaces and '=' signs, which is enough to fake a second `outcome=` in the line.
LOG_UNSAFE_RE = re.compile(r"[^A-Za-z0-9._:/=+-]")


def log_safe(value: str, limit: int = 128) -> str:
    return LOG_UNSAFE_RE.sub("_", value)[:limit] or "-"


def env_bool(name: str, default: bool = False, overrides: dict[str, Any] | None = None) -> bool:
    raw = (overrides or {}).get(name, os.environ.get(name, default))
    if isinstance(raw, bool):
        return raw
    value = str(raw).strip().lower()
    if value not in {"true", "false"}:
        raise RuntimeError(f"{name} must be true or false (got {raw!r}).")
    return value == "true"


def validate_https_url(value: str, setting: str) -> None:
    if not value:
        return
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise RuntimeError(f"{setting} must be an absolute HTTPS URL.")


def csv_payload(rows: list[dict[str, str]], max_bytes: int) -> bytes:
    """Serialize rows to CSV, abandoning the write once the cap is passed.

    The size check happens while writing rather than afterwards so an
    oversized export never fully materializes in the worker.
    """
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=OUTPUT_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for index, row in enumerate(rows, start=1):
        writer.writerow({key: spreadsheet_safe(value) for key, value in row.items()})
        if index % 256 == 0 and output.tell() > max_bytes:
            abort(413)
    payload = ("﻿" + output.getvalue()).encode("utf-8")
    if len(payload) > max_bytes:
        abort(413)
    return payload


def attachment(payload: bytes, mimetype: str, filename: str, max_bytes: int, **headers: str) -> Response:
    if len(payload) > max_bytes:
        abort(413)
    return Response(
        payload,
        mimetype=mimetype,
        headers={"Content-Disposition": f"attachment; filename={filename}", **headers},
    )


def export_response(
    output_format: str,
    rows: list[dict[str, str]],
    summary: list[dict[str, str]],
    unmapped: list[dict[str, str]],
    diagnostics: dict[str, Any],
    max_bytes: int,
    max_preview_rows: int,
) -> Any:
    """Serialize a consolidated report in the requested format."""
    if output_format == "csv":
        return attachment(csv_payload(rows, max_bytes), "text/csv", f"{EXPORT_BASENAME}.csv", max_bytes)

    if output_format == "html":
        return attachment(
            build_html_report(rows).encode("utf-8"),
            "text/html",
            f"{EXPORT_BASENAME}.html",
            max_bytes,
            **{
                "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; "
                "base-uri 'none'; form-action 'none'; sandbox"
            },
        )

    if output_format == "xlsx":
        payload = build_xlsx_bytes(
            {
                "Consolidated": (rows, OUTPUT_COLUMNS),
                "Summary": (summary, SUMMARY_COLUMNS),
                "Unmapped": (unmapped, OUTPUT_COLUMNS),
                "Diagnostics": (
                    [{key: str(value) for key, value in diagnostics.items()}],
                    list(diagnostics.keys()),
                ),
            }
        )
        if payload is None:
            flash("Excel export is not available because XlsxWriter is not installed.")
            return redirect(url_for("index"))
        return attachment(
            payload,
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            f"{EXPORT_BASENAME}.xlsx",
            max_bytes,
        )

    # The preview is rendered into a single HTML response, so it needs its own
    # bound: the byte cap above only applies to the attachment formats, and
    # MAX_REPORT_ROWS alone would allow a multi-hundred-megabyte page. The
    # grouped summary is always complete; only the detail table is truncated.
    visible = rows[:max_preview_rows]
    return render_template(
        "report.html",
        rows=visible,
        summary=summary,
        diagnostics=diagnostics,
        unmapped=len(unmapped),
        truncated=len(rows) - len(visible),
        total_rows=len(rows),
    )


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    test_config = test_config or {}
    app = Flask(__name__)
    app_env = str(test_config.get("APP_ENV", os.environ.get("APP_ENV", "development"))).lower()
    auth_mode = str(test_config.get("AUTH_MODE", os.environ.get("AUTH_MODE", "local"))).lower()
    cookie_secure = env_bool("COOKIE_SECURE", False, test_config)
    trusted_hosts = [host.strip() for host in os.environ.get("TRUSTED_HOSTS", "").split(",") if host.strip()]

    app.config.update(
        APP_ENV=app_env,
        AUTH_MODE=auth_mode,
        SECRET_KEY=os.environ.get("SECRET_KEY"),
        DATABASE=os.environ.get("DATABASE_PATH", "/data/users.db"),
        MAX_CONTENT_LENGTH=env_int("MAX_UPLOAD_BYTES", 25 * 1024 * 1024, 1024, 100 * 1024 * 1024, test_config),
        MAX_FORM_MEMORY_SIZE=512 * 1024,
        MAX_FORM_PARTS=20,
        MAX_JSON_DEPTH=env_int("MAX_JSON_DEPTH", 64, 8, 256, test_config),
        # Counts every JSON value including scalars, so the ceiling is well
        # above the old container-only figure.
        MAX_JSON_NODES=env_int("MAX_JSON_NODES", 2_000_000, 1_000, 20_000_000, test_config),
        MAX_ZIP_MEMBERS=env_int("MAX_ZIP_MEMBERS", 10_000, 1, 200_000, test_config),
        MAX_REPORT_CONTENT_CHARS=env_int(
            "MAX_REPORT_CONTENT_CHARS", 64_000_000, 100_000, 512_000_000, test_config
        ),
        MAX_REPORT_PACKAGES=env_int("MAX_REPORT_PACKAGES", 100_000, 1, 500_000, test_config),
        MAX_REPORT_ROWS=env_int("MAX_REPORT_ROWS", 50_000, 1, 250_000, test_config),
        MAX_PREVIEW_ROWS=env_int("MAX_PREVIEW_ROWS", 2_000, 10, 50_000, test_config),
        MAX_EXPORT_BYTES=env_int("MAX_EXPORT_BYTES", 100 * 1024 * 1024, 1024, 250 * 1024 * 1024, test_config),
        REPORTS_PER_MINUTE=env_int("REPORTS_PER_MINUTE", 6, 1, 120, test_config),
        TRUST_PROXY_HOPS=env_int("TRUST_PROXY_HOPS", 0, 0, 8, test_config),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=cookie_secure,
        SESSION_COOKIE_NAME="__Host-sca_stitcher_session" if app_env == "production" else "sca_stitcher_session",
        PERMANENT_SESSION_LIFETIME=timedelta(
            minutes=env_int("SESSION_LIFETIME_MINUTES", 30, 5, 12 * 60, test_config)
        ),
        PREFERRED_URL_SCHEME="https" if app_env == "production" else "http",
        TRUSTED_HOSTS=trusted_hosts or None,
        ALB_ARN=os.environ.get("ALB_ARN", ""),
        ALB_CLIENT_ID=os.environ.get("ALB_CLIENT_ID", ""),
        ALB_ISSUER=os.environ.get("ALB_ISSUER", ""),
        ALB_LOGOUT_URL=os.environ.get("ALB_LOGOUT_URL", ""),
        ALB_SESSION_COOKIE_NAME=os.environ.get("ALB_SESSION_COOKIE_NAME", "AWSELBAuthSessionCookie"),
    )
    app.config.update(test_config)

    if app.config["AUTH_MODE"] not in {"local", "alb_oidc"}:
        raise RuntimeError("AUTH_MODE must be local or alb_oidc.")
    if not app.config.get("TESTING") and not app.config.get("SECRET_KEY"):
        raise RuntimeError("Set SECRET_KEY to a long random value before starting the web app.")
    if app.config["APP_ENV"] == "production":
        secret = str(app.config.get("SECRET_KEY", "")).encode("utf-8")
        if len(secret) < 32:
            raise RuntimeError("Production SECRET_KEY must contain at least 32 bytes of random data.")
        if app.config["AUTH_MODE"] != "alb_oidc":
            raise RuntimeError("Production deployments must use AUTH_MODE=alb_oidc.")
        if not app.config["SESSION_COOKIE_SECURE"]:
            raise RuntimeError("Production deployments must set COOKIE_SECURE=true.")
        if not app.config["TRUSTED_HOSTS"]:
            raise RuntimeError("Production deployments must set TRUSTED_HOSTS.")
        for setting in ("ALB_ARN", "ALB_CLIENT_ID", "ALB_ISSUER", "ALB_LOGOUT_URL"):
            if not app.config[setting]:
                raise RuntimeError(f"Production deployments must set {setting}.")
        validate_https_url(app.config["ALB_ISSUER"], "ALB_ISSUER")
        validate_https_url(app.config["ALB_LOGOUT_URL"], "ALB_LOGOUT_URL")

    # Forwarded headers are honoured only when the operator states how many
    # proxies sit in front. Trusting them unconditionally would let any client
    # that can reach the socket directly spoof its own audit address and
    # rate-limit key, so the default of 0 ignores them entirely.
    proxy_hops = app.config["TRUST_PROXY_HOPS"]
    if proxy_hops:
        app.wsgi_app = ProxyFix(  # type: ignore[method-assign]
            app.wsgi_app, x_for=proxy_hops, x_proto=proxy_hops, x_host=proxy_hops
        )
    elif app.config["APP_ENV"] == "production":
        app.logger.warning(
            "security_event=startup outcome=degraded detail=%s",
            "TRUST_PROXY_HOPS=0_behind_a_load_balancer_records_the_proxy_address_in_audit_events",
        )

    alb_verifier: AlbOidcVerifier | Any | None = app.config.get("ALB_VERIFIER")
    if app.config["AUTH_MODE"] == "alb_oidc" and alb_verifier is None:
        alb_verifier = AlbOidcVerifier(
            app.config["ALB_ARN"],
            app.config["ALB_CLIENT_ID"],
            issuer=app.config["ALB_ISSUER"],
        )

    login_ip_limiter = SlidingWindowLimiter()
    login_account_limiter = SlidingWindowLimiter()
    report_limiter = SlidingWindowLimiter()
    report_slot = threading.BoundedSemaphore(value=1)
    dummy_password_hash = generate_password_hash(secrets.token_urlsafe(32))

    @contextmanager
    def db() -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(app.config["DATABASE"], timeout=5)
        connection.row_factory = sqlite3.Row
        # The image runs multiple gunicorn workers against one database file, so
        # a blocked writer must wait rather than fail immediately.
        connection.execute("PRAGMA busy_timeout = 5000")
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def init_db() -> None:
        """Create and migrate the schema once at startup.

        This deliberately does not run per request: issuing DDL from concurrent
        request threads is both wasteful and unsafe.
        """
        path = Path(app.config["DATABASE"])
        path.parent.mkdir(parents=True, exist_ok=True)
        with db() as connection:
            # WAL lets readers proceed during a write, which matters because the
            # admin pages read the user list while another worker may be
            # updating a role.
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS users "
                "(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, "
                "is_admin INTEGER NOT NULL DEFAULT 0, must_change_password INTEGER NOT NULL DEFAULT 0)"
            )
            columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(users)").fetchall()
            }
            if "is_admin" not in columns:
                connection.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")
                # Accounts created before roles existed were all provisioned by create-admin.
                connection.execute("UPDATE users SET is_admin = 1")
            if "must_change_password" not in columns:
                connection.execute(
                    "ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0"
                )
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS users_username_nocase "
                "ON users(lower(username))"
            )

    if app.config["AUTH_MODE"] == "local":
        init_db()

    def csrf_token() -> str:
        return session.setdefault("csrf_token", secrets.token_urlsafe(32))

    def valid_csrf() -> bool:
        expected = session.get("csrf_token", "")
        return bool(expected and secrets.compare_digest(expected, request.form.get("csrf_token", "")))

    def validate_username(username: str) -> None:
        if not 3 <= len(username) <= 128:
            raise ValueError("Username must contain 3-128 characters.")

    def validate_password(password: str) -> None:
        if not 12 <= len(password) <= 256:
            raise ValueError("Password must contain 12-256 characters.")

    def validate_local_credentials(username: str, password: str) -> None:
        validate_username(username)
        validate_password(password)

    def principal_fingerprint(value: str) -> str:
        return hashlib.sha256(value.lower().encode("utf-8", errors="replace")).hexdigest()[:16]

    def current_principal() -> str:
        """One stable identity per user, shared by every audit event.

        Without this, a login recorded the username while a report recorded the
        numeric row id, so no two event types could be correlated to the same
        person.
        """
        if app.config["AUTH_MODE"] == "local":
            return str(session.get("username", "") or getattr(g, "auth_display", ""))
        return str(getattr(g, "auth_subject", ""))

    def audit(event: str, outcome: str, target: str = "", **extra: str) -> None:
        """Record a security event.

        ``target`` is the account an action was performed *on*; the actor is
        always resolved from the request so a privileged change can be traced
        back to the administrator who made it.
        """
        actor = current_principal()
        app.logger.info(
            'security_event=%s outcome=%s actor=%s target=%s remote=%s request_id="%s"%s',
            event,
            outcome,
            principal_fingerprint(actor) if actor else "-",
            principal_fingerprint(target) if target else "-",
            request.remote_addr or "-",
            log_safe(request.headers.get("X-Amzn-Trace-Id", "")),
            "".join(f" {key}={log_safe(str(value))}" for key, value in extra.items()),
        )

    def authenticate_request() -> bool:
        if app.config["AUTH_MODE"] == "local":
            if "user_id" not in session:
                return False
            with db() as connection:
                user = connection.execute(
                    "SELECT id, username, is_admin, must_change_password "
                    "FROM users WHERE id = ?",
                    (session["user_id"],),
                ).fetchone()
            if not user:
                session.clear()
                return False
            session["username"] = user["username"]
            g.auth_subject = str(user["id"])
            g.auth_display = str(user["username"])
            g.is_admin = bool(user["is_admin"])
            g.must_change_password = bool(user["must_change_password"])
            return True
        if getattr(g, "auth_subject", None):
            return True
        token = request.headers.get("X-Amzn-Oidc-Data", "")
        asserted_identity = request.headers.get("X-Amzn-Oidc-Identity", "")
        try:
            claims = alb_verifier.verify(token, asserted_identity)
        except AuthenticationError:
            audit("alb_authentication", "rejected")
            return False
        g.auth_subject = asserted_identity
        g.auth_display = str(claims.get("name") or claims.get("email") or asserted_identity)
        return True

    def login_required(view: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(view)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            if not authenticate_request():
                if app.config["AUTH_MODE"] == "local":
                    return redirect(url_for("login"))
                abort(401)
            if (
                app.config["AUTH_MODE"] == "local"
                and getattr(g, "must_change_password", False)
                and view.__name__ not in {"change_password", "logout"}
            ):
                return redirect(url_for("change_password"))
            return view(*args, **kwargs)

        return wrapped

    def admin_required(view: Callable[..., Any]) -> Callable[..., Any]:
        @login_required
        @wraps(view)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            if app.config["AUTH_MODE"] != "local":
                abort(404)
            if not getattr(g, "is_admin", False):
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    def csrf_protected(view: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(view)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            if not valid_csrf():
                abort(400)
            return view(*args, **kwargs)

        return wrapped

    def survives_db_contention(view: Callable[..., Any]) -> Callable[..., Any]:
        """Turn a lock timeout on a user mutation into a retry prompt, not a 500."""

        @wraps(view)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            try:
                return view(*args, **kwargs)
            except sqlite3.OperationalError:
                audit(view.__name__, "deferred", reason="database_busy")
                flash("The user database was busy. Try that change again.")
                return redirect(url_for("admin"))

        return wrapped

    def require_user(connection: sqlite3.Connection, user_id: int) -> sqlite3.Row:
        user = connection.execute(
            "SELECT id, username, is_admin, must_change_password FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if not user:
            abort(404)
        return user

    def current_user() -> str:
        return str(getattr(g, "auth_display", "") or session.get("username", ""))

    def current_user_is_admin() -> bool:
        return app.config["AUTH_MODE"] == "local" and bool(getattr(g, "is_admin", False))

    app.jinja_env.globals.update(
        csrf_token=csrf_token,
        themes=THEMES,
        max_upload_mb=max(1, round(app.config["MAX_CONTENT_LENGTH"] / (1024 * 1024))),
        current_user=current_user,
        current_user_is_admin=current_user_is_admin,
        auth_mode=app.config["AUTH_MODE"],
        logout_enabled=app.config["AUTH_MODE"] == "local" or bool(app.config["ALB_LOGOUT_URL"]),
    )

    @app.after_request
    def security_headers(response: Response) -> Response:
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; "
            "base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
        )
        if app.config["APP_ENV"] == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    @app.cli.command("create-admin")
    @click.option("--username", prompt=True)
    @click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
    def create_admin(username: str, password: str) -> None:
        """Create a local-development administrator without exposing an HTTP bootstrap route."""
        if app.config["AUTH_MODE"] != "local":
            raise click.ClickException("Local users are disabled when AUTH_MODE is not local.")
        username = username.strip()
        try:
            validate_local_credentials(username, password)
        except ValueError as exc:
            raise click.ClickException(str(exc)) from exc
        try:
            with db() as connection:
                connection.execute(
                    "INSERT INTO users(username, password_hash, is_admin) VALUES (?, ?, 1)",
                    (username, generate_password_hash(password)),
                )
        except sqlite3.IntegrityError as exc:
            raise click.ClickException("That username already exists.") from exc
        click.echo("Local administrator created.")

    @app.cli.command("reset-password")
    @click.option("--username", prompt=True)
    @click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True)
    @click.option(
        "--grant-admin",
        is_flag=True,
        help="Also restore administrator access, for recovering from a full lockout.",
    )
    def reset_password(username: str, password: str, grant_admin: bool) -> None:
        """Reset a local password and require the user to replace it after signing in."""
        if app.config["AUTH_MODE"] != "local":
            raise click.ClickException("Local users are disabled when AUTH_MODE is not local.")
        username = username.strip()
        try:
            validate_password(password)
        except ValueError as exc:
            raise click.ClickException(str(exc)) from exc
        # Two whole statements rather than a concatenated fragment: nothing here
        # is user-controlled either way, but assembling SQL from a flag is a
        # pattern worth not having in an auth path at all.
        statement = (
            "UPDATE users SET password_hash = ?, must_change_password = 1, is_admin = 1 "
            "WHERE lower(username) = lower(?)"
            if grant_admin
            else "UPDATE users SET password_hash = ?, must_change_password = 1 "
            "WHERE lower(username) = lower(?)"
        )
        with db() as connection:
            result = connection.execute(statement, (generate_password_hash(password), username))
            if result.rowcount != 1:
                raise click.ClickException("No matching local user exists.")
        click.echo("Password reset. The user must choose a new password after signing in.")
        if grant_admin:
            click.echo("Administrator access restored.")

    @app.cli.command("list-admins")
    def list_admins() -> None:
        """Show which local accounts currently hold administrator access."""
        if app.config["AUTH_MODE"] != "local":
            raise click.ClickException("Local users are disabled when AUTH_MODE is not local.")
        with db() as connection:
            admins = connection.execute(
                "SELECT username FROM users WHERE is_admin = 1 ORDER BY lower(username)"
            ).fetchall()
        if not admins:
            click.echo("No administrators exist. Recover one with:")
            click.echo("  flask --app web_app reset-password --grant-admin")
            return
        for row in admins:
            click.echo(row["username"])

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/")
    @login_required
    def index() -> str:
        return render_template("index.html")

    @app.post("/theme")
    @login_required
    @csrf_protected
    def theme() -> Any:
        selected = request.form.get("theme", "")
        if selected not in THEMES:
            flash("That theme is not available.")
            return redirect(url_for("index"))
        session["theme"] = selected
        return redirect(url_for("index"))

    @app.route("/login", methods=["GET", "POST"])
    def login() -> Any:
        if app.config["AUTH_MODE"] != "local":
            return redirect(url_for("index"))
        with db() as connection:
            provisioned = connection.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None
        if not provisioned:
            return render_template("login.html", needs_admin=True), 503
        if request.method != "POST":
            return render_template("login.html")

        if not valid_csrf():
            abort(400)
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not 1 <= len(username) <= 128 or len(password) > 256:
            audit("login", "rejected", target=username, reason="malformed_credentials")
            flash("Invalid username or password.")
            return render_template("login.html"), 401

        remote = request.remote_addr or "unknown"
        retry_after = max(
            login_ip_limiter.check(f"ip:{remote}", limit=10, window_seconds=300),
            login_account_limiter.check(
                f"account:{principal_fingerprint(username)}", limit=5, window_seconds=300
            ),
        )
        if retry_after:
            audit("login_rate_limit", "blocked", target=username)
            response = Response(
                render_template("login.html", rate_limited=True),
                status=429,
                mimetype="text/html",
            )
            response.headers["Retry-After"] = str(retry_after)
            return response

        # The connection is released before hashing, which is deliberately slow.
        with db() as connection:
            user = connection.execute(
                "SELECT id, username, password_hash FROM users WHERE lower(username) = lower(?)",
                (username,),
            ).fetchone()
        password_ok = check_password_hash(user["password_hash"] if user else dummy_password_hash, password)
        if user and password_ok:
            selected_theme = session.get("theme")
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            if selected_theme in THEMES:
                session["theme"] = selected_theme
            session.permanent = True
            login_account_limiter.clear(f"account:{principal_fingerprint(username)}")
            audit("login", "succeeded", target=user["username"])
            return redirect(url_for("index"))
        audit("login", "rejected", target=username, reason="bad_credentials")
        flash("Invalid username or password.")
        return render_template("login.html"), 401

    @app.get("/recovery")
    def recovery() -> Any:
        if app.config["AUTH_MODE"] != "local":
            return redirect(url_for("index"))
        return render_template("recovery.html")

    @app.route("/change-password", methods=["GET", "POST"])
    @login_required
    def change_password() -> Any:
        if app.config["AUTH_MODE"] != "local":
            abort(404)
        if request.method == "POST":
            if not valid_csrf():
                abort(400)
            current_password = request.form.get("current_password", "")
            new_password = request.form.get("new_password", "")
            confirmation = request.form.get("confirm_password", "")
            with db() as connection:
                user = connection.execute(
                    "SELECT id, username, password_hash FROM users WHERE id = ?",
                    (session["user_id"],),
                ).fetchone()
                password_ok = bool(
                    user and check_password_hash(user["password_hash"], current_password)
                )
                if not password_ok:
                    audit("password_change", "rejected", reason="wrong_current_password")
                    flash("The current password is incorrect.")
                    return render_template("change_password.html"), 400
                if new_password != confirmation:
                    flash("The new passwords do not match.")
                    return render_template("change_password.html"), 400
                try:
                    validate_password(new_password)
                except ValueError as exc:
                    flash(str(exc))
                    return render_template("change_password.html"), 400
                if check_password_hash(user["password_hash"], new_password):
                    flash("Choose a password different from the temporary or current password.")
                    return render_template("change_password.html"), 400
                connection.execute(
                    "UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?",
                    (generate_password_hash(new_password), user["id"]),
                )
            username = str(user["username"])
            user_id = int(user["id"])
            selected_theme = session.get("theme")
            session.clear()
            session["user_id"] = user_id
            session["username"] = username
            if selected_theme in THEMES:
                session["theme"] = selected_theme
            session.permanent = True
            audit("password_change", "succeeded")
            flash("Password updated.")
            return redirect(url_for("index"))
        return render_template("change_password.html")

    @app.get("/admin")
    @admin_required
    def admin() -> Any:
        with db() as connection:
            users = connection.execute(
                "SELECT id, username, is_admin, must_change_password "
                "FROM users ORDER BY lower(username)"
            ).fetchall()
        return render_template("admin.html", users=users)

    @app.post("/admin/users")
    @admin_required
    @csrf_protected
    @survives_db_contention
    def admin_create_user() -> Any:
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirmation = request.form.get("confirm_password", "")
        if password != confirmation:
            flash("The temporary passwords do not match.")
            return redirect(url_for("admin"))
        try:
            validate_local_credentials(username, password)
        except ValueError as exc:
            flash(str(exc))
            return redirect(url_for("admin"))
        is_admin = 1 if request.form.get("is_admin") == "1" else 0
        try:
            with db() as connection:
                connection.execute(
                    "INSERT INTO users("
                    "username, password_hash, is_admin, must_change_password"
                    ") VALUES (?, ?, ?, 1)",
                    (username, generate_password_hash(password), is_admin),
                )
        except sqlite3.IntegrityError:
            flash("That username already exists.")
            return redirect(url_for("admin"))
        audit(
            "admin_user_create",
            "succeeded",
            target=username,
            role="admin" if is_admin else "user",
        )
        flash(f"Created {username}. A password change is required at first sign-in.")
        return redirect(url_for("admin"))

    @app.post("/admin/users/<int:user_id>/reset-password")
    @admin_required
    @csrf_protected
    @survives_db_contention
    def admin_reset_password(user_id: int) -> Any:
        password = request.form.get("password", "")
        confirmation = request.form.get("confirm_password", "")
        if password != confirmation:
            flash("The temporary passwords do not match.")
            return redirect(url_for("admin"))
        try:
            validate_password(password)
        except ValueError as exc:
            flash(str(exc))
            return redirect(url_for("admin"))
        with db() as connection:
            user = require_user(connection, user_id)
            connection.execute(
                "UPDATE users SET password_hash = ?, must_change_password = 1 WHERE id = ?",
                (generate_password_hash(password), user_id),
            )
        audit("admin_password_reset", "succeeded", target=user["username"])
        flash(f"Password reset for {user['username']}. A change is required at next sign-in.")
        return redirect(url_for("admin"))

    @app.post("/admin/users/<int:user_id>/role")
    @admin_required
    @csrf_protected
    @survives_db_contention
    def admin_change_role(user_id: int) -> Any:
        make_admin = request.form.get("is_admin") == "1"
        with db() as connection:
            user = require_user(connection, user_id)
            if user_id == int(session["user_id"]) and not make_admin:
                flash("You cannot remove your own administrator access.")
                return redirect(url_for("admin"))
            if make_admin:
                connection.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (user_id,))
            else:
                # The remaining-admin count is evaluated inside the same statement
                # so two concurrent demotions cannot both observe a stale count and
                # leave the deployment with no administrator at all.
                demoted = connection.execute(
                    "UPDATE users SET is_admin = 0 "
                    "WHERE id = ? AND is_admin = 1 "
                    "  AND (SELECT count(*) FROM users WHERE is_admin = 1) > 1",
                    (user_id,),
                )
                if demoted.rowcount != 1 and user["is_admin"]:
                    flash("At least one administrator must remain.")
                    return redirect(url_for("admin"))
        audit(
            "admin_role_change",
            "succeeded",
            target=user["username"],
            new_role="admin" if make_admin else "user",
        )
        flash(f"Updated the role for {user['username']}.")
        return redirect(url_for("admin"))

    @app.post("/admin/users/<int:user_id>/delete")
    @admin_required
    @csrf_protected
    @survives_db_contention
    def admin_delete_user(user_id: int) -> Any:
        with db() as connection:
            user = require_user(connection, user_id)
            if user_id == int(session["user_id"]):
                flash("You cannot delete your own signed-in account.")
                return redirect(url_for("admin"))
            # Same single-statement guard as the demotion path above.
            deleted = connection.execute(
                "DELETE FROM users "
                "WHERE id = ? "
                "  AND (is_admin = 0 OR (SELECT count(*) FROM users WHERE is_admin = 1) > 1)",
                (user_id,),
            )
            if deleted.rowcount != 1:
                flash("At least one administrator must remain.")
                return redirect(url_for("admin"))
        audit("admin_user_delete", "succeeded", target=user["username"])
        flash(f"Deleted {user['username']}.")
        return redirect(url_for("admin"))

    @app.post("/logout")
    @login_required
    @csrf_protected
    def logout() -> Any:
        # g.auth_display survives session.clear(), so audit() still resolves the
        # actor for the record below.
        session.clear()
        audit("logout", "succeeded")
        if app.config["AUTH_MODE"] == "local":
            return redirect(url_for("login"))
        if not app.config["ALB_LOGOUT_URL"]:
            abort(501)
        response = redirect(app.config["ALB_LOGOUT_URL"])
        cookie_name = app.config["ALB_SESSION_COOKIE_NAME"]
        for suffix in ("", "-0", "-1", "-2", "-3"):
            response.delete_cookie(cookie_name + suffix, path="/", secure=True, samesite="None")
        return response

    @app.post("/report")
    @login_required
    @csrf_protected
    def report() -> Any:
        output_format = request.form.get("format") or "preview"
        if output_format not in ALLOWED_OUTPUTS:
            flash("Choose a supported output format.")
            return redirect(url_for("index"))

        retry_after = report_limiter.check(
            f"report:{g.auth_subject}",
            limit=app.config["REPORTS_PER_MINUTE"],
            window_seconds=60,
        )
        if retry_after:
            audit("report_rate_limit", "blocked")
            response = Response("Too many report requests. Try again shortly.", status=429, mimetype="text/plain")
            response.headers["Retry-After"] = str(retry_after)
            return response

        upload = request.files.get("report")
        if not upload or not upload.filename:
            flash("Choose a Checkmarx JSON or ZIP report.")
            return redirect(url_for("index"))
        suffix = Path(upload.filename).suffix.lower()
        if suffix not in {".json", ".zip"}:
            flash("Only .json and .zip files are accepted.")
            return redirect(url_for("index"))
        if not report_slot.acquire(blocking=False):
            audit("report_concurrency", "blocked")
            response = Response(
                "The report worker is busy. Try again shortly.", status=503, mimetype="text/plain"
            )
            response.headers["Retry-After"] = "30"
            return response

        try:
            try:
                with TemporaryDirectory() as tmpdir:
                    source_path = Path(tmpdir) / f"report{suffix}"
                    upload.save(source_path)
                    source = load_report(
                        source_path,
                        max_json_bytes=app.config["MAX_CONTENT_LENGTH"],
                        max_depth=app.config["MAX_JSON_DEPTH"],
                        max_nodes=app.config["MAX_JSON_NODES"],
                        max_zip_members=app.config["MAX_ZIP_MEMBERS"],
                    )
                    rows, unmapped, diagnostics = make_rows(
                        source,
                        BUILTIN_GROUP_RULES,
                        max_packages=app.config["MAX_REPORT_PACKAGES"],
                        max_rows=app.config["MAX_REPORT_ROWS"],
                        max_depth=app.config["MAX_JSON_DEPTH"],
                        max_nodes=app.config["MAX_JSON_NODES"],
                        max_content_chars=app.config["MAX_REPORT_CONTENT_CHARS"],
                    )
            # OSError is deliberately absent here. A full disk, a permission
            # problem, or a failure writing the temporary upload is an
            # operational fault, not bad input, and must reach the logged 500
            # path below so it is visible to monitoring.
            except (ReportError, zipfile.BadZipFile) as exc:
                audit("report_processing", "rejected", error_type=type(exc).__name__)
                flash("Could not process the report because it is invalid or exceeds a safety limit.")
                return redirect(url_for("index"))
            except Exception as exc:
                # A bug in the consolidator or an operational failure, not bad
                # input. Log the traceback so it is not silently misreported to
                # the user as an invalid report.
                audit("report_processing", "error", error_type=type(exc).__name__)
                app.logger.exception("Unhandled failure while consolidating a report.")
                abort(500)

            if not rows:
                flash("No reportable findings were found.")
                return redirect(url_for("index"))
            summary = make_summary(rows)
            audit("report_processing", "succeeded", output_format=output_format, rows=str(len(rows)))

            return export_response(
                output_format,
                rows,
                summary,
                unmapped,
                diagnostics,
                app.config["MAX_EXPORT_BYTES"],
                app.config["MAX_PREVIEW_ROWS"],
            )
        finally:
            report_slot.release()

    return app


def __getattr__(name: str) -> Any:
    """Build the WSGI app lazily so importing this module never validates config.

    ``gunicorn web_app:app`` and ``flask --app web_app`` both resolve ``app``
    through this hook; tests and tooling can import the module without needing a
    SECRET_KEY in the environment.
    """
    if name == "app":
        return create_app()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


if __name__ == "__main__":
    # Deliberate LAN bind for local use; production runs behind the authenticated ALB.
    create_app().run(host=os.environ.get("WEB_HOST", "0.0.0.0"), port=8080)  # nosec B104
