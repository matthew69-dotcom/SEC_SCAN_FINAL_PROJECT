"""Smoke tests for Week 1 — verifies the app boots, validation works, and the
mock /api/scan returns the right shape."""
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_scan_mock_ok():
    r = client.post("/api/scan", json={"domain": "example.com"})
    assert r.status_code == 200
    data = r.json()
    assert data["domain"] == "example.com"
    assert 0 <= data["score"] <= 100
    assert data["grade"] in {"A+", "A", "B", "C", "D", "F"}
    assert isinstance(data["findings"], list)


def test_scan_rejects_bad_domain():
    r = client.post("/api/scan", json={"domain": "not a domain"})
    assert r.status_code == 422


def test_scan_strips_protocol():
    r = client.post("/api/scan", json={"domain": "https://Example.COM/"})
    assert r.status_code == 200
    assert r.json()["domain"] == "example.com"
