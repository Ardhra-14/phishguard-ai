"""
Phase 0 tests — verify the FastAPI skeleton works before any ML code.
Run with:  pytest tests/test_phase0.py -v
"""
import pytest
from httpx import AsyncClient, ASGITransport
from main import app


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


async def test_health_check(client):
    """GET /health should return 200 with status ok."""
    response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["version"] == "1.0.0"
    assert data["service"] == "PhishGuard AI"


async def test_scan_phishing_domain(client):
    """POST /api/v1/scan with a suspicious domain should return a score."""
    response = await client.post(
        "/api/v1/scan",
        json={"url": "secure-sbi-login.xyz"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "score" in data
    assert "verdict" in data
    assert "domain" in data
    assert data["score"] >= 0
    assert data["score"] <= 100
    assert data["verdict"] in ("PHISHING", "SUSPICIOUS", "SAFE")


async def test_scan_legitimate_domain(client):
    """POST /api/v1/scan with a clearly legitimate domain should score low."""
    response = await client.post(
        "/api/v1/scan",
        json={"url": "https://google.com"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["score"] < 50


async def test_scan_adds_scheme(client):
    """Domains without a scheme should be accepted and auto-prefixed."""
    response = await client.post(
        "/api/v1/scan",
        json={"url": "hdfc-verify-login.tk"},
    )
    assert response.status_code == 200


async def test_scan_empty_url_rejected(client):
    """Empty URL should return 422 validation error."""
    response = await client.post("/api/v1/scan", json={"url": ""})
    assert response.status_code == 422


async def test_scan_returns_duration_header(client):
    """Response must include X-Scan-Duration header."""
    response = await client.post(
        "/api/v1/scan",
        json={"url": "payupi-verify.co.in"},
    )
    assert "x-scan-duration" in response.headers


async def test_feed_endpoint(client):
    """GET /api/v1/feed should return items list."""
    response = await client.get("/api/v1/feed")
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert isinstance(data["items"], list)


async def test_stats_endpoint(client):
    """GET /api/v1/stats should return all metric keys."""
    response = await client.get("/api/v1/stats")
    assert response.status_code == 200
    data = response.json()
    assert "threats_today" in data
    assert "avg_confidence" in data
    assert "zero_day_count" in data
