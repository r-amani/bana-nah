"""
Unit and integration tests for Scans Router (POST /api/scans, GET /api/scans, etc.).
"""
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.models.scan import ScanStatus, ModuleStatus


@pytest.mark.anyio
async def test_list_scans_empty():
    mock_db = MagicMock()
    mock_db.scans.find.return_value.sort.return_value.skip.return_value.limit.return_value.to_list = AsyncMock(return_value=[])

    with patch("app.routers.scans.get_db", return_value=mock_db):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/scans?limit=6")
            assert resp.status_code == 200
            assert resp.json() == []


@pytest.mark.anyio
async def test_list_scans_with_records():
    mock_db = MagicMock()
    sample_scan = {
        "scan_id": "scan-12345",
        "target_url": "https://example-phish.com",
        "hostname": "example-phish.com",
        "status": "completed",
        "created_at": "2026-11-07T12:00:00",
        "completed_at": "2026-11-07T12:00:01",
        "duration_ms": 120.5,
        "risk_score": 65.0,
        "risk_level": "high",
        "module_results": [],
        "summary": "Completed test scan",
    }
    mock_db.scans.find.return_value.sort.return_value.skip.return_value.limit.return_value.to_list = AsyncMock(return_value=[sample_scan])

    with patch("app.routers.scans.get_db", return_value=mock_db):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/scans?limit=10")
            assert resp.status_code == 200
            data = resp.json()
            assert len(data) == 1
            assert data[0]["scan_id"] == "scan-12345"
            assert data[0]["hostname"] == "example-phish.com"
            assert data[0]["risk_score"] == 65.0


@pytest.mark.anyio
async def test_create_scan_standard_payload():
    mock_result = {
        "scan_id": "scan-created-1",
        "target_url": "https://suspicious-site.xyz",
        "hostname": "suspicious-site.xyz",
        "status": "completed",
        "created_at": datetime.utcnow(),
        "completed_at": datetime.utcnow(),
        "duration_ms": 250.0,
        "risk_score": 75.0,
        "risk_level": "critical",
        "module_results": [],
        "summary": "High risk detected",
    }

    with patch("app.routers.scans.orchestrator.run_scan", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = mock_result
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/scans",
                json={"url": "https://suspicious-site.xyz", "modules": ["url_detection"]},
            )
            assert resp.status_code == 201
            data = resp.json()
            assert data["scan_id"] == "scan-created-1"
            assert data["hostname"] == "suspicious-site.xyz"
            mock_run.assert_called_once_with(
                target_url="https://suspicious-site.xyz",
                requested_modules=["url_detection"],
                request_ip="127.0.0.1",
            )


@pytest.mark.anyio
async def test_create_scan_alias_payload():
    mock_result = {
        "scan_id": "scan-created-2",
        "target_url": "https://alias-test.xyz",
        "hostname": "alias-test.xyz",
        "status": "completed",
        "created_at": datetime.utcnow(),
        "completed_at": datetime.utcnow(),
        "duration_ms": 300.0,
        "risk_score": 10.0,
        "risk_level": "low",
        "module_results": [],
        "summary": "Low risk scan",
    }

    with patch("app.routers.scans.orchestrator.run_scan", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = mock_result
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/scans",
                json={"target_url": "https://alias-test.xyz", "requested_modules": ["tls_validation"]},
            )
            assert resp.status_code == 201
            data = resp.json()
            assert data["scan_id"] == "scan-created-2"
            mock_run.assert_called_once_with(
                target_url="https://alias-test.xyz",
                requested_modules=["tls_validation"],
                request_ip="127.0.0.1",
            )


@pytest.mark.anyio
async def test_create_scan_validation_error_empty_url():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/scans",
            json={"url": "   "},
        )
        assert resp.status_code == 422
        data = resp.json()
        assert "detail" in data
        assert any("Target URL cannot be empty" in str(d) for d in data["detail"])
