"""
Unit tests for Investigation Graph Enrichment Module.
"""
from datetime import datetime
import pytest

from app.scanner.modules.graph_enrichment import GraphEnrichmentModule
from app.models.entity import EntityType, RelationshipType


def test_standardize_nodes_deduplication():
    mod = GraphEnrichmentModule()
    raw_entities = [
        {"type": "domain", "value": "test.com", "metadata": {"registrar": "GoDaddy"}},
        {"type": "ip_address", "value": "1.2.3.4", "metadata": {"country": "US"}},
        {"type": "ip_address", "value": "1.2.3.4", "metadata": {"asn": "AS12345"}},  # Duplicate IP
        {"type": "certificate", "value": "cert-fp-1", "metadata": {"issuer": "Let's Encrypt"}},
    ]
    findings = []

    nodes = mod._standardize_nodes("https://test.com/login", "test.com", "scan-ge-1", raw_entities, findings)

    node_ids = [n["entity_id"] for n in nodes]
    assert "url:https://test.com/login" in node_ids
    assert "domain:test.com" in node_ids
    assert "ip_address:1.2.3.4" in node_ids
    assert "certificate:cert-fp-1" in node_ids

    # IP address should appear exactly once
    ip_nodes = [n for n in nodes if n["value"] == "1.2.3.4"]
    assert len(ip_nodes) == 1
    # Merged metadata
    assert ip_nodes[0]["metadata"]["country"] == "US"
    assert ip_nodes[0]["metadata"]["asn"] == "AS12345"


def test_harmonize_relationships_and_prevent_duplicates():
    mod = GraphEnrichmentModule()
    nodes = [
        {"entity_id": "url:https://test.com/login", "type": "url", "value": "https://test.com/login"},
        {"entity_id": "domain:test.com", "type": "domain", "value": "test.com"},
        {"entity_id": "ip_address:1.2.3.4", "type": "ip_address", "value": "1.2.3.4"},
    ]

    raw_relationships = [
        {
            "source_entity_id": "domain:test.com",
            "target_entity_id": "ip_address:1.2.3.4",
            "type": "resolves_to",
            "confidence": 1.0,
            "metadata": {"dns_type": "A"},
        },
        {
            "source_entity_id": "domain:test.com",
            "target_entity_id": "ip_address:1.2.3.4",
            "type": "resolves_to",
            "confidence": 1.0,
            "metadata": {"dns_type": "A"},  # Duplicate
        },
    ]

    edges = mod._harmonize_relationships("https://test.com/login", "test.com", "scan-ge-2", raw_relationships, nodes)

    # Should have base edge (hosted_on) + 1 unique resolves_to edge
    assert len(edges) == 2
    types = [e["type"] for e in edges]
    assert "hosted_on" in types
    assert "resolves_to" in types

    resolves_edges = [e for e in edges if e["type"] == "resolves_to"]
    assert len(resolves_edges) == 1
    assert resolves_edges[0]["source_entity_id"] == "domain:test.com"
    assert resolves_edges[0]["target_entity_id"] == "ip_address:1.2.3.4"


@pytest.mark.anyio
async def test_graph_enrichment_execute():
    mod = GraphEnrichmentModule()
    input_entities = [
        {"type": "ip_address", "value": "93.184.216.34", "metadata": {}},
    ]
    input_relationships = [
        {"source_entity_id": "domain:example.com", "target_entity_id": "ip_address:93.184.216.34", "type": "resolves_to"},
    ]

    res = await mod.execute(
        "https://example.com", "example.com", "scan-ge-3",
        entities=input_entities, relationships=input_relationships, findings=[]
    )

    assert "data" in res
    assert res["data"]["total_nodes"] >= 3  # url, domain, ip
    assert res["data"]["total_edges"] >= 2  # hosted_on, resolves_to
    assert len(res["findings"]) == 0
