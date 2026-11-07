"""
Integration tests for the complete PHANTOM scan pipeline, graph router, and domain history.
"""
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from app.scanner.orchestrator import ScanOrchestrator
from app.scanner.modules.placeholder import PlaceholderModule
from app.scanner.modules.url_detection import UrlDetectionModule
from app.scanner.modules.risk_scoring import RiskScoringModule
from app.scanner.modules.community_intelligence import CommunityIntelligenceModule
from app.scanner.modules.flight_recorder import FlightRecorderModule
from app.scanner.modules.attack_fingerprint import AttackFingerprintModule
from app.scanner.modules.graph_enrichment import GraphEnrichmentModule


@pytest.mark.anyio
async def test_full_scan_pipeline_orchestration():
    orch = ScanOrchestrator()
    orch.register_module(PlaceholderModule())
    orch.register_module(UrlDetectionModule())
    orch.register_module(RiskScoringModule())
    orch.register_module(CommunityIntelligenceModule())
    orch.register_module(FlightRecorderModule())
    orch.register_module(AttackFingerprintModule())
    orch.register_module(GraphEnrichmentModule())

    # Mock database and network operations
    mock_db = MagicMock()
    mock_db.scans.insert_one = AsyncMock(return_value=MagicMock())
    mock_db.scans.update_one = AsyncMock(return_value=MagicMock())
    mock_db.scans.find_one = AsyncMock(return_value=None)
    mock_db.reports.find.return_value.to_list = AsyncMock(return_value=[])
    mock_db.flight_recorder.insert_one = AsyncMock(return_value=MagicMock())
    mock_db.flight_recorder.find_one = AsyncMock(return_value=None)
    mock_db.entities.find.return_value.limit.return_value.to_list = AsyncMock(return_value=[])
    mock_db.entities.update_one = AsyncMock(return_value=MagicMock())
    mock_db.findings.insert_many = AsyncMock(return_value=MagicMock())
    mock_db.relationships.insert_many = AsyncMock(return_value=MagicMock())

    with patch("app.scanner.orchestrator.get_db", return_value=mock_db), \
         patch("app.scanner.modules.community_intelligence.get_db", return_value=mock_db), \
         patch("app.scanner.modules.flight_recorder.get_db", return_value=mock_db), \
         patch("app.scanner.modules.attack_fingerprint.get_db", return_value=mock_db), \
         patch("app.security.url_validator.validate_resolved_ip", return_value="93.184.216.34"), \
         patch("dns.resolver.Resolver"):

        scan_result = await orch.run_scan("https://paypa1-update.xyz/login")

        assert scan_result["status"] in ("completed", "partial")
        assert scan_result["hostname"] == "paypa1-update.xyz"
        assert scan_result["risk_score"] > 0
        assert scan_result["risk_level"] in ("low", "medium", "high", "critical")

        # Verify all modules ran
        module_names = [m["module"] for m in scan_result["module_results"]]
        assert "url_detection" in module_names
        assert "risk_scoring" in module_names
        assert "community_intelligence" in module_names
        assert "flight_recorder" in module_names
        assert "attack_fingerprint" in module_names
        assert "graph_enrichment" in module_names


@pytest.mark.anyio
async def test_graph_api_returns_evidence_and_relationships():
    from app.routers.graph import get_graph

    mock_db = MagicMock()
    mock_entities = [
        {"entity_id": "domain:test.xyz", "type": "domain", "value": "test.xyz", "metadata": {}, "first_seen": datetime.utcnow(), "last_seen": datetime.utcnow(), "scan_ids": ["scan-1"]},
        {"entity_id": "ip:198.51.100.1", "type": "ip_address", "value": "198.51.100.1", "metadata": {}, "first_seen": datetime.utcnow(), "last_seen": datetime.utcnow(), "scan_ids": ["scan-1"]},
    ]
    mock_relationships = [
        {
            "relationship_id": "rel-1",
            "source_entity_id": "domain:test.xyz",
            "target_entity_id": "ip:198.51.100.1",
            "type": "resolves_to",
            "confidence": 1.0,
            "metadata": {"evidence": "DNS A Record resolved"},
            "scan_id": "scan-1",
            "created_at": datetime.utcnow(),
        }
    ]

    mock_db.entities.find.return_value.limit.return_value.to_list = AsyncMock(return_value=mock_entities)
    mock_db.relationships.find.return_value.to_list = AsyncMock(return_value=mock_relationships)

    with patch("app.routers.graph.get_db", return_value=mock_db):
        resp = await get_graph(hostname="test.xyz", max_nodes=100)

        assert len(resp.nodes) == 2
        assert len(resp.edges) == 1
        edge = resp.edges[0]
        assert edge.source_entity_id == "domain:test.xyz"
        assert edge.target_entity_id == "ip:198.51.100.1"
        assert edge.type == "resolves_to"
        assert edge.confidence == 1.0
