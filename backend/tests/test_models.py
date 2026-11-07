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
