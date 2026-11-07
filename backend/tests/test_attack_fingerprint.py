"""
Unit tests for Attack Family Fingerprinting Module.
"""
from datetime import datetime
import pytest

from app.scanner.modules.attack_fingerprint import AttackFingerprintModule
from app.models.entity import RelationshipType


def test_similar_hostname_and_shared_brand():
    mod = AttackFingerprintModule()
    findings = []
    entities = []
    relationships = []

    indicators = {
        "hostname": "paypal-update-security.xyz",
        "ips": ["198.51.100.22"],
        "nameservers": ["ns1.phishhost.top"],
        "cert_sha256": "cert-hash-999",
        "target_brands": ["paypal"],
    }

    historical_pool = [
        {
            "domain": "paypal-security-login.xyz",
            "metadata": {},
            "relationships": [
                {
                    "type": "resolves_to",
                    "source_entity_id": "domain:paypal-security-login.xyz",
                    "target_entity_id": "ip:198.51.100.22",
                },
                {
                    "type": "has_certificate",
                    "source_entity_id": "domain:paypal-security-login.xyz",
                    "target_entity_id": "cert:cert-hash-999",
                },
            ],
        }
    ]

    clusters = mod._cluster_indicators(
        "paypal-update-security.xyz", indicators, historical_pool, "scan-fp-1", findings, entities, relationships
    )

    assert len(clusters) == 1
    cluster = clusters[0]
    assert cluster["related_domain"] == "paypal-security-login.xyz"
    assert cluster["confidence"] >= 0.70
    assert cluster["classification"] == "Shared observable infrastructure"
    assert any("Shared IP address" in ev for ev in cluster["supporting_evidence"])
    assert any("Identical TLS Certificate" in ev for ev in cluster["supporting_evidence"])

    # Verify structured relationship generated
    assert len(relationships) == 1
    rel = relationships[0]
    assert rel["type"] == RelationshipType.POTENTIALLY_RELATED_TO.value
    assert rel["source_entity_id"] == "domain:paypal-update-security.xyz"
    assert rel["target_entity_id"] == "domain:paypal-security-login.xyz"
    assert rel["metadata"]["classification"] == "Potentially related domains"

    # Verify finding generated for strong cluster
    assert len(findings) == 1
    assert "Attack Fingerprinting" in findings[0]["title"]


def test_unrelated_domains_no_association():
    mod = AttackFingerprintModule()
    findings = []
    entities = []
    relationships = []

    indicators = {
        "hostname": "clean-example.com",
        "ips": ["93.184.216.34"],
        "nameservers": ["a.iana-servers.net"],
        "cert_sha256": "iana-cert-123",
        "target_brands": [],
    }

    historical_pool = [
        {
            "domain": "totally-different-random.net",
            "metadata": {},
            "relationships": [
                {
                    "type": "resolves_to",
                    "source_entity_id": "domain:totally-different-random.net",
                    "target_entity_id": "ip:192.0.2.1",
                }
            ],
        }
    ]

    clusters = mod._cluster_indicators(
        "clean-example.com", indicators, historical_pool, "scan-fp-2", findings, entities, relationships
    )

    assert len(clusters) == 0
    assert len(relationships) == 0
    assert len(findings) == 0


def test_lexical_similarity_detection():
    mod = AttackFingerprintModule()
    findings = []
    entities = []
    relationships = []

    indicators = {
        "hostname": "chase-secure-account.com",
        "ips": ["203.0.113.50"],
        "nameservers": [],
        "cert_sha256": None,
        "target_brands": ["chase"],
    }

    historical_pool = [
        {
            "domain": "chase-secure-account.net",
            "metadata": {},
            "relationships": [
                {
                    "type": "resolves_to",
                    "source_entity_id": "domain:chase-secure-account.net",
                    "target_entity_id": "ip:203.0.113.50",
                }
            ],
        }
    ]

    clusters = mod._cluster_indicators(
        "chase-secure-account.com", indicators, historical_pool, "scan-fp-3", findings, entities, relationships
    )

    assert len(clusters) == 1
    cluster = clusters[0]
    assert cluster["related_domain"] == "chase-secure-account.net"
    assert cluster["confidence"] >= 0.60
