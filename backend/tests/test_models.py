"""
Tests for Pydantic models and schemas.
"""
from datetime import datetime
from app.models.scan import ScanDocument, ScanStatus, ModuleResult, ModuleStatus, ScanRequest
from app.models.finding import FindingDocument, Severity, FindingCategory
from app.models.report import ReportDocument, ReportCategory, ReportStatus
from app.models.entity import EntityDocument, RelationshipDocument, EntityType, RelationshipType


def test_scan_document():
    doc = ScanDocument(
        target_url="https://phishing-site.xyz/login",
        hostname="phishing-site.xyz",
        status=ScanStatus.COMPLETED,
        risk_score=85.0,
        risk_level="critical",
    )
    assert doc.scan_id is not None
    assert doc.status == ScanStatus.COMPLETED
    assert doc.risk_score == 85.0
    assert doc.risk_level == "critical"
    dump = doc.model_dump()
    assert dump["hostname"] == "phishing-site.xyz"


def test_finding_document():
    finding = FindingDocument(
        scan_id="test-scan-123",
        module="url_detection",
        category=FindingCategory.URL_ANALYSIS,
        title="Suspicious Typosquatting Detected",
        description="Domain typosquats paypal.com",
        severity=Severity.HIGH,
        confidence=0.9,
    )
    assert finding.severity == Severity.HIGH
    assert finding.confidence == 0.9


def test_report_document():
    report = ReportDocument(
        url="https://fake-login.com",
        hostname="fake-login.com",
        category=ReportCategory.PHISHING,
        description="Fake credential harvester mimicking internal portal.",
        status=ReportStatus.PENDING,
    )
    assert report.status == ReportStatus.PENDING
    assert report.category == ReportCategory.PHISHING


def test_entity_and_relationship():
    entity_url = EntityDocument(
        type=EntityType.URL,
        value="https://bad.com/page",
    )
    entity_ip = EntityDocument(
        type=EntityType.IP_ADDRESS,
        value="1.2.3.4",
    )
    rel = RelationshipDocument(
        source_entity_id=entity_url.entity_id,
        target_entity_id=entity_ip.entity_id,
        type=RelationshipType.RESOLVES_TO,
        scan_id="scan-xyz",
    )
    assert rel.type == RelationshipType.RESOLVES_TO


def test_scan_request_normalization():
    # Standard format
    req1 = ScanRequest(url="https://valid.com", modules=["url_detection"])
    assert req1.url == "https://valid.com"
    assert req1.modules == ["url_detection"]

    # Alias format from legacy frontend
    req2 = ScanRequest.model_validate({
        "target_url": "https://aliased.com",
        "requested_modules": ["tls_validation"],
    })
    assert req2.url == "https://aliased.com"
    assert req2.modules == ["tls_validation"]


def test_scan_request_validation():
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        ScanRequest.model_validate({"url": "  "})

    with pytest.raises(ValidationError):
        ScanRequest.model_validate({})
