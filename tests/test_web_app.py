import io
import json
import os
import zipfile

import pytest

os.environ.setdefault("SECRET_KEY", "test-import-secret")

from checkmarx_sca_consolidator_v2 import BUILTIN_GROUP_RULES, load_report, make_rows
from web_app import create_app


@pytest.fixture()
def client(tmp_path):
    app = create_app({"TESTING": True, "SECRET_KEY": "test-secret", "DATABASE": str(tmp_path / "users.db")})
    return app.test_client()


def token(response):
    marker = b'name="csrf_token" value="'
    return response.data.split(marker, 1)[1].split(b'"', 1)[0].decode()


def register_and_login(client):
    response = client.get("/setup")
    client.post("/setup", data={"csrf_token": token(response), "username": "reviewer", "password": "a-secure-password"})
    response = client.get("/login")
    client.post("/login", data={"csrf_token": token(response), "username": "reviewer", "password": "a-secure-password"})


def sample_report():
    return {
        "RiskReportSummary": {"ProjectName": "Demo"},
        "Packages": [{
            "Id": "npm-demo-1.0", "Name": "demo", "Version": "1.0", "IsDirectDependency": True,
            "VulnerabilityCount": 1, "HighVulnerabilityCount": 1,
            "Vulnerabilities": [{"CVE": "CVE-2026-1234", "CVSS": 8.1}],
        }],
    }


def test_auth_and_ephemeral_preview(client, tmp_path):
    assert client.get("/").status_code == 302
    register_and_login(client)
    response = client.get("/")
    response = client.post(
        "/report",
        data={"csrf_token": token(response), "action": "preview", "report": (io.BytesIO(json.dumps(sample_report()).encode()), "scan.json")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    assert b"CVE-2026-1234" in response.data
    assert response.headers["Cache-Control"] == "no-store"
    assert not list(tmp_path.glob("*.json"))


def test_workspace_ui_exposes_formats_and_strict_styles(client):
    register_and_login(client)
    response = client.get("/")

    assert response.status_code == 200
    for output_format in (b"preview", b"xlsx", b"csv", b"html"):
        assert b'name="format" value="' + output_format + b'"' in response.data
    assert b"Reports are not retained." in response.data
    assert b"/static/styles.css" in response.data
    assert "style-src 'self'" in response.headers["Content-Security-Policy"]
    assert "'unsafe-inline'" not in response.headers["Content-Security-Policy"]


def test_csv_download(client):
    register_and_login(client)
    response = client.get("/")
    response = client.post(
        "/report",
        data={"csrf_token": token(response), "format": "csv", "report": (io.BytesIO(json.dumps(sample_report()).encode()), "scan.json")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    assert response.mimetype == "text/csv"
    assert "attachment" in response.headers["Content-Disposition"]


def test_html_download(client):
    register_and_login(client)
    response = client.get("/")
    response = client.post(
        "/report",
        data={"csrf_token": token(response), "format": "html", "report": (io.BytesIO(json.dumps(sample_report()).encode()), "scan.json")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    assert response.mimetype == "text/html"
    assert "attachment" in response.headers["Content-Disposition"]
    assert b"Checkmarx SCA Consolidated Output" in response.data


def test_xlsx_download(client):
    register_and_login(client)
    response = client.get("/")
    response = client.post(
        "/report",
        data={"csrf_token": token(response), "format": "xlsx", "report": (io.BytesIO(json.dumps(sample_report()).encode()), "scan.json")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    assert response.mimetype == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    assert response.data.startswith(b"PK")


def test_string_vulnerability_counts_are_reportable():
    report = {
        "RiskReportSummary": {"ProjectName": "Demo"},
        "Packages": [{
            "Id": "npm-demo-1.0", "Name": "demo", "Version": "1.0", "IsDirectDependency": True,
            "VulnerabilityCount": "1", "HighVulnerabilityCount": "1",
        }],
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


def test_secret_key_is_required_for_non_test_startup(monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError):
        create_app()
