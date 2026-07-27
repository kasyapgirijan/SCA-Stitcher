#!/usr/bin/env python3
"""Authenticated, stateless web front end for the SCA consolidator."""

from __future__ import annotations

import csv
import hashlib
import io
import os
import secrets
import sqlite3
import threading
from contextlib import contextmanager
from datetime import timedelta
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Iterator
from urllib.parse import urlparse

import click
from flask import Flask, Response, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from checkmarx_sca_consolidator_v2 import (
    BUILTIN_GROUP_RULES,
    OUTPUT_COLUMNS,
    SUMMARY_COLUMNS,
    build_html_report,
    build_xlsx_bytes,
    load_report,
    make_rows,
    make_summary,
    spreadsheet_safe,
)
from security import AlbOidcVerifier, AuthenticationError, SlidingWindowLimiter


THEMES = ("midnight", "light", "blueprint")
ALLOWED_OUTPUTS = {"preview", "csv", "html", "xlsx"}


def env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer.") from exc
    if not minimum <= value <= maximum:
        raise RuntimeError(f"{name} must be between {minimum} and {maximum}.")
    return value


def env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name, str(default)).strip().lower()
    if value not in {"true", "false"}:
        raise RuntimeError(f"{name} must be true or false.")
    return value == "true"


def validate_https_url(value: str, setting: str) -> None:
    if not value:
        return
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise RuntimeError(f"{setting} must be an absolute HTTPS URL.")


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    test_config = test_config or {}
    app = Flask(__name__)
    app_env = str(test_config.get("APP_ENV", os.environ.get("APP_ENV", "development"))).lower()
    auth_mode = str(test_config.get("AUTH_MODE", os.environ.get("AUTH_MODE", "local"))).lower()
    configured_secret = os.environ.get("SECRET_KEY") or test_config.get("SECRET_KEY")
    cookie_secure = env_bool("COOKIE_SECURE", False)
    trusted_hosts = [host.strip() for host in os.environ.get("TRUSTED_HOSTS", "").split(",") if host.strip()]

    app.config.update(
        APP_ENV=app_env,
        AUTH_MODE=auth_mode,
        SECRET_KEY=configured_secret,
        DATABASE=os.environ.get("DATABASE_PATH", "/data/users.db"),
        MAX_CONTENT_LENGTH=env_int("MAX_UPLOAD_BYTES", 25 * 1024 * 1024, 1024, 100 * 1024 * 1024),
        MAX_FORM_MEMORY_SIZE=512 * 1024,
        MAX_FORM_PARTS=20,
        MAX_JSON_DEPTH=env_int("MAX_JSON_DEPTH", 64, 8, 256),
        MAX_JSON_NODES=env_int("MAX_JSON_NODES", 250_000, 1_000, 2_000_000),
        MAX_REPORT_PACKAGES=env_int("MAX_REPORT_PACKAGES", 100_000, 1, 500_000),
        MAX_REPORT_ROWS=env_int("MAX_REPORT_ROWS", 50_000, 1, 250_000),
        MAX_EXPORT_BYTES=env_int("MAX_EXPORT_BYTES", 100 * 1024 * 1024, 1024, 250 * 1024 * 1024),
        REPORTS_PER_MINUTE=env_int("REPORTS_PER_MINUTE", 6, 1, 120),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=cookie_secure,
        SESSION_COOKIE_NAME="__Host-checkmarkx_session" if app_env == "production" else "checkmarkx_session",
        PERMANENT_SESSION_LIFETIME=timedelta(
            minutes=env_int("SESSION_LIFETIME_MINUTES", 30, 5, 12 * 60)
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
        path = Path(app.config["DATABASE"])
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(path, timeout=5)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS users "
                "(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL)"
            )
            yield connection
            connection.commit()
        finally:
            connection.close()

    def csrf_token() -> str:
        return session.setdefault("csrf_token", secrets.token_urlsafe(32))

    def valid_csrf() -> bool:
        expected = session.get("csrf_token", "")
        return bool(expected and secrets.compare_digest(expected, request.form.get("csrf_token", "")))

    def principal_fingerprint(value: str) -> str:
        return hashlib.sha256(value.lower().encode("utf-8", errors="replace")).hexdigest()[:16]

    def audit(event: str, outcome: str, principal: str = "") -> None:
        request_id = request.headers.get("X-Amzn-Trace-Id", "")[:128]
        app.logger.info(
            "security_event=%s outcome=%s principal=%s remote=%s request_id=%s",
            event,
            outcome,
            principal_fingerprint(principal) if principal else "-",
            request.remote_addr or "-",
            request_id or "-",
        )

    def authenticate_request() -> bool:
        if app.config["AUTH_MODE"] == "local":
            if "user_id" not in session:
                return False
            g.auth_subject = str(session["user_id"])
            g.auth_display = str(session.get("username", "Signed-in user"))
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
            return view(*args, **kwargs)

        return wrapped

    def current_user() -> str:
        return str(getattr(g, "auth_display", "") or session.get("username", ""))

    app.jinja_env.globals.update(
        csrf_token=csrf_token,
        themes=THEMES,
        max_upload_mb=max(1, round(app.config["MAX_CONTENT_LENGTH"] / (1024 * 1024))),
        current_user=current_user,
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
        if not 3 <= len(username) <= 128 or not 12 <= len(password) <= 256:
            raise click.ClickException("Username must be 3-128 characters and password 12-256 characters.")
        try:
            with db() as connection:
                connection.execute(
                    "INSERT INTO users(username, password_hash) VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )
        except sqlite3.IntegrityError as exc:
            raise click.ClickException("That username already exists.") from exc
        click.echo("Local administrator created.")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/")
    @login_required
    def index() -> str:
        return render_template("index.html")

    @app.post("/theme")
    @login_required
    def theme() -> Any:
        if not valid_csrf():
            abort(400)
        selected = request.form.get("theme", "")
        if selected in THEMES:
            session["theme"] = selected
        return redirect(url_for("index"))

    @app.route("/login", methods=["GET", "POST"])
    def login() -> Any:
        if app.config["AUTH_MODE"] != "local":
            return redirect(url_for("index"))
        with db() as connection:
            if not connection.execute("SELECT 1 FROM users LIMIT 1").fetchone():
                return render_template("login.html", needs_admin=True), 503
            if request.method == "POST":
                if not valid_csrf():
                    abort(400)
                username = request.form.get("username", "").strip()
                password = request.form.get("password", "")
                if not 1 <= len(username) <= 128 or len(password) > 256:
                    audit("login", "rejected", username)
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
                    audit("login_rate_limit", "blocked", username)
                    response = Response(
                        render_template("login.html", rate_limited=True),
                        status=429,
                        mimetype="text/html",
                    )
                    response.headers["Retry-After"] = str(retry_after)
                    return response

                user = connection.execute(
                    "SELECT id, username, password_hash FROM users WHERE username = ?",
                    (username,),
                ).fetchone()
                password_ok = check_password_hash(user["password_hash"] if user else dummy_password_hash, password)
                if user and password_ok:
                    session.clear()
                    session["user_id"] = user["id"]
                    session["username"] = user["username"]
                    session.permanent = True
                    login_account_limiter.clear(f"account:{principal_fingerprint(username)}")
                    audit("login", "succeeded", username)
                    return redirect(url_for("index"))
                audit("login", "rejected", username)
                flash("Invalid username or password.")
                return render_template("login.html"), 401
        return render_template("login.html")

    @app.post("/logout")
    @login_required
    def logout() -> Any:
        if not valid_csrf():
            abort(400)
        principal = current_user()
        session.clear()
        audit("logout", "succeeded", principal)
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
    def report() -> Any:
        if not valid_csrf():
            abort(400)
        output_format = request.form.get("format") or request.form.get("action") or "preview"
        if output_format not in ALLOWED_OUTPUTS:
            flash("Choose a supported output format.")
            return redirect(url_for("index"))

        principal = str(g.auth_subject)
        retry_after = report_limiter.check(
            f"report:{principal}",
            limit=app.config["REPORTS_PER_MINUTE"],
            window_seconds=60,
        )
        if retry_after:
            audit("report_rate_limit", "blocked", principal)
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
            audit("report_concurrency", "blocked", principal)
            abort(503)

        from tempfile import TemporaryDirectory

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
                    )
                    rows, unmapped, diagnostics = make_rows(
                        source,
                        BUILTIN_GROUP_RULES,
                        max_packages=app.config["MAX_REPORT_PACKAGES"],
                        max_rows=app.config["MAX_REPORT_ROWS"],
                    )
            except (ValueError, OSError, KeyError, TypeError, AttributeError, sqlite3.Error, SystemExit) as exc:
                app.logger.warning(
                    "security_event=report_processing outcome=rejected principal=%s error_type=%s",
                    principal_fingerprint(principal),
                    type(exc).__name__,
                )
                flash("Could not process the report because it is invalid or exceeds a safety limit.")
                return redirect(url_for("index"))

            if not rows:
                flash("No reportable findings were found.")
                return redirect(url_for("index"))
            summary = make_summary(rows)
            audit("report_processing", "succeeded", principal)

            if output_format == "csv":
                output = io.StringIO()
                writer = csv.DictWriter(output, fieldnames=OUTPUT_COLUMNS, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(
                    {key: spreadsheet_safe(value) for key, value in row.items()}
                    for row in rows
                )
                payload = ("\ufeff" + output.getvalue()).encode("utf-8")
                if len(payload) > app.config["MAX_EXPORT_BYTES"]:
                    abort(413)
                return Response(
                    payload,
                    mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=checkmarx_sca_consolidated.csv"},
                )
            if output_format == "html":
                payload = build_html_report(rows).encode("utf-8")
                if len(payload) > app.config["MAX_EXPORT_BYTES"]:
                    abort(413)
                return Response(
                    payload,
                    mimetype="text/html",
                    headers={
                        "Content-Disposition": "attachment; filename=checkmarx_sca_consolidated.html",
                        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; "
                        "base-uri 'none'; form-action 'none'; sandbox",
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
                if len(payload) > app.config["MAX_EXPORT_BYTES"]:
                    abort(413)
                return Response(
                    payload,
                    mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": "attachment; filename=checkmarx_sca_consolidated.xlsx"},
                )
            return render_template(
                "report.html",
                rows=rows,
                summary=summary,
                diagnostics=diagnostics,
                unmapped=len(unmapped),
            )
        finally:
            report_slot.release()

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host=os.environ.get("WEB_HOST", "0.0.0.0"), port=8080)
