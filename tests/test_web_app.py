import io
import json

import pytest

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


def test_csv_download(client):
    register_and_login(client)
    response = client.get("/")
    response = client.post(
        "/report",
        data={"csrf_token": token(response), "action": "csv", "report": (io.BytesIO(json.dumps(sample_report()).encode()), "scan.json")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    assert response.mimetype == "text/csv"
    assert "attachment" in response.headers["Content-Disposition"]
