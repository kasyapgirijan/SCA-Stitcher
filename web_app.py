#!/usr/bin/env python3
"""Authenticated, stateless web front end for the SCA consolidator."""

from __future__ import annotations

import csv
import io
import os
import secrets
import sqlite3
from functools import wraps
from pathlib import Path
from typing import Any, Callable

from flask import Flask, Response, abort, flash, redirect, render_template, request, session, url_for
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
)


DATABASE = Path(os.environ.get("DATABASE_PATH", "/data/users.db"))
MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", str(25 * 1024 * 1024)))
THEMES = ("midnight", "light", "blueprint")


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    app = Flask(__name__)
    configured_secret = os.environ.get("SECRET_KEY") or (test_config or {}).get("SECRET_KEY")
    app.config.update(
        SECRET_KEY=configured_secret or secrets.token_hex(32),
        MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES,
        DATABASE=str(DATABASE),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "false").lower() == "true",
    )
    if test_config:
        app.config.update(test_config)
    if not app.config.get("TESTING") and not os.environ.get("SECRET_KEY"):
        raise RuntimeError("Set SECRET_KEY to a long random value before starting the web app.")

    def db() -> sqlite3.Connection:
        path = Path(app.config["DATABASE"])
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(path)
        connection.row_factory = sqlite3.Row
        connection.execute(
            "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL)"
        )
        return connection

    def csrf_token() -> str:
        return session.setdefault("csrf_token", secrets.token_urlsafe(32))

    app.jinja_env.globals["csrf_token"] = csrf_token
    app.jinja_env.globals["themes"] = THEMES
    app.jinja_env.globals["max_upload_mb"] = max(1, round(app.config["MAX_CONTENT_LENGTH"] / (1024 * 1024)))

    def valid_csrf() -> bool:
        expected = session.get("csrf_token", "")
        return bool(expected and secrets.compare_digest(expected, request.form.get("csrf_token", "")))

    def login_required(view: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(view)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            if "user_id" not in session:
                return redirect(url_for("login"))
            return view(*args, **kwargs)

        return wrapped

    @app.after_request
    def security_headers(response: Response) -> Response:
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'"
        return response

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
        return redirect(request.referrer or url_for("index"))

    @app.route("/setup", methods=["GET", "POST"])
    def setup() -> Any:
        with db() as connection:
            if connection.execute("SELECT 1 FROM users LIMIT 1").fetchone():
                return redirect(url_for("login"))
            if request.method == "POST":
                if not valid_csrf():
                    abort(400)
                username = request.form.get("username", "").strip()
                password = request.form.get("password", "")
                if len(username) < 3 or len(password) < 12:
                    flash("Use a username of 3+ characters and a password of 12+ characters.")
                else:
                    connection.execute(
                        "INSERT INTO users(username, password_hash) VALUES (?, ?)",
                        (username, generate_password_hash(password)),
                    )
                    connection.commit()
                    return redirect(url_for("login"))
        return render_template("setup.html")

    @app.route("/login", methods=["GET", "POST"])
    def login() -> Any:
        with db() as connection:
            if not connection.execute("SELECT 1 FROM users LIMIT 1").fetchone():
                return redirect(url_for("setup"))
            if request.method == "POST":
                if not valid_csrf():
                    abort(400)
                user = connection.execute(
                    "SELECT id, username, password_hash FROM users WHERE username = ?", (request.form.get("username", "").strip(),)
                ).fetchone()
                if user and check_password_hash(user["password_hash"], request.form.get("password", "")):
                    session.clear()
                    session["user_id"] = user["id"]
                    session["username"] = user["username"]
                    return redirect(url_for("index"))
                flash("Invalid username or password.")
        return render_template("login.html")

    @app.post("/logout")
    @login_required
    def logout() -> Any:
        if not valid_csrf():
            abort(400)
        session.clear()
        return redirect(url_for("login"))

    @app.post("/report")
    @login_required
    def report() -> Any:
        if not valid_csrf():
            abort(400)
        upload = request.files.get("report")
        if not upload or not upload.filename:
            flash("Choose a Checkmarx JSON or ZIP report.")
            return redirect(url_for("index"))
        suffix = Path(upload.filename).suffix.lower()
        if suffix not in {".json", ".zip"}:
            flash("Only .json and .zip files are accepted.")
            return redirect(url_for("index"))

        # A temporary file is parsed and discarded before this request ends.
        from tempfile import TemporaryDirectory

        try:
            with TemporaryDirectory() as tmpdir:
                source_path = Path(tmpdir) / f"report{suffix}"
                upload.save(source_path)
                rows, unmapped, diagnostics = make_rows(load_report(source_path, max_json_bytes=MAX_UPLOAD_BYTES), BUILTIN_GROUP_RULES)
        except (ValueError, OSError, KeyError, sqlite3.Error, SystemExit) as exc:
            flash(f"Could not process report: {exc}")
            return redirect(url_for("index"))
        if not rows:
            flash("No reportable findings were found.")
            return redirect(url_for("index"))

        output_format = request.form.get("format") or request.form.get("action") or "preview"
        if output_format not in {"preview", "csv", "html", "xlsx"}:
            flash("Choose a supported output format.")
            return redirect(url_for("index"))

        summary = make_summary(rows)

        if output_format == "csv":
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=OUTPUT_COLUMNS, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
            return Response(
                "\ufeff" + output.getvalue(),
                mimetype="text/csv",
                headers={"Content-Disposition": "attachment; filename=checkmarx_sca_consolidated.csv"},
            )
        if output_format == "html":
            return Response(
                build_html_report(rows),
                mimetype="text/html",
                headers={"Content-Disposition": "attachment; filename=checkmarx_sca_consolidated.html"},
            )
        if output_format == "xlsx":
            payload = build_xlsx_bytes(
                {
                    "Consolidated": (rows, OUTPUT_COLUMNS),
                    "Summary": (summary, SUMMARY_COLUMNS),
                    "Unmapped": (unmapped, OUTPUT_COLUMNS),
                    "Diagnostics": ([{k: str(v) for k, v in diagnostics.items()}], list(diagnostics.keys())),
                }
            )
            if payload is None:
                flash("Excel export is not available because XlsxWriter is not installed.")
                return redirect(url_for("index"))
            return Response(
                payload,
                mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                headers={"Content-Disposition": "attachment; filename=checkmarx_sca_consolidated.xlsx"},
            )
        return render_template("report.html", rows=rows, summary=summary, diagnostics=diagnostics, unmapped=len(unmapped))

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
