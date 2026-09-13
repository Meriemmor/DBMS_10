import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Allow imports from backend/
BACKEND_DIR = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND_DIR))

# main.py requires API_KEY when it is imported
os.environ["API_KEY"] = "test-api-key"

import main


client = TestClient(main.app)


def test_root():
    response = client.get("/")

    assert response.status_code == 200
    assert response.json() == {
        "message": "Vulnerability Tracker API is running"
    }


def test_create_finding_without_api_key_is_rejected():
    response = client.post(
        "/findings",
        json={
            "asset_id": 1,
            "vulnerability_id": 1,
            "status": "Open",
            "discovered_on": "2026-09-13",
            "due_date": "2026-09-20",
            "resolved_on": None,
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or missing API key"


def test_create_finding_with_invalid_api_key_is_rejected():
    response = client.post(
        "/findings",
        headers={"X-API-Key": "wrong-key"},
        json={
            "asset_id": 1,
            "vulnerability_id": 1,
            "status": "Open",
            "discovered_on": "2026-09-13",
            "due_date": "2026-09-20",
            "resolved_on": None,
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or missing API key"


def test_invalid_status_is_rejected():
    response = client.post(
        "/findings",
        headers={"X-API-Key": "test-api-key"},
        json={
            "asset_id": 1,
            "vulnerability_id": 1,
            "status": "Definitely Not A Status",
            "discovered_on": "2026-09-13",
            "due_date": "2026-09-20",
            "resolved_on": None,
        },
    )

    assert response.status_code == 422


def test_findings_join_returns_related_data(monkeypatch):
    class FakeCursor:
        def execute(self, query, params=None):
            pass

        def fetchall(self):
            return [
                (
                    1,
                    "web-01",
                    "Platform",
                    "CVE-2026-1234",
                    "Critical",
                    "Open",
                    "2026-07-16",
                    "2026-07-30",
                    None,
                )
            ]

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    class FakeConnection:
        def cursor(self):
            return FakeCursor()

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    monkeypatch.setattr(main, "get_connection", lambda: FakeConnection())

    response = client.get("/findings")

    assert response.status_code == 200

    finding = response.json()["findings"][0]

    assert finding["asset"] == "web-01"
    assert finding["team"] == "Platform"
    assert finding["cve_id"] == "CVE-2026-1234"
    assert finding["severity"] == "Critical"


def test_summary_aggregation(monkeypatch):
    class FakeCursor:
        def execute(self, query, params=None):
            pass

        def fetchall(self):
            return [
                ("Critical", 3),
                ("High", 2),
            ]

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    class FakeConnection:
        def cursor(self):
            return FakeCursor()

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    monkeypatch.setattr(main, "get_connection", lambda: FakeConnection())

    response = client.get("/summary")

    assert response.status_code == 200
    assert response.json() == {
        "summary": {
            "Critical": 3,
            "High": 2,
            "Medium": 0,
            "Low": 0,
        }
    }


def test_create_finding_with_valid_api_key(monkeypatch):
    class FakeCursor:
        def execute(self, query, params=None):
            pass

        def fetchone(self):
            return (42,)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    class FakeConnection:
        def cursor(self):
            return FakeCursor()

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    monkeypatch.setattr(main, "get_connection", lambda: FakeConnection())

    response = client.post(
        "/findings",
        headers={"X-API-Key": "test-api-key"},
        json={
            "asset_id": 1,
            "vulnerability_id": 2,
            "status": "Open",
            "discovered_on": "2026-09-13",
            "due_date": "2026-09-20",
            "resolved_on": None,
        },
    )

    assert response.status_code == 201
    assert response.json() == {
        "message": "Finding created",
        "id": 42,
    }
