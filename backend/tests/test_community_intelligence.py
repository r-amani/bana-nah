"""
Unit tests for Community Intelligence Module.
"""
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch
import httpx
import pytest

from app.scanner.modules.community_intelligence import CommunityIntelligenceModule
from app.models.finding import Severity, FindingCategory


def test_analyze_reports_empty():
    mod = CommunityIntelligenceModule()
    findings = []
    entities = []
    relationships = []

    res = mod._analyze_community_reports([], "safe-domain.org", "scan-ci-1", findings, entities, relationships)

    assert res["total_reports"] == 0
    assert res["independent_reporters"] == 0
    assert res["duplicate_reports"] == 0
    assert res["corroborated_threat_signal"] is False
    assert len(findings) == 0


def test_analyze_duplicate_reports_handling():
    mod = CommunityIntelligenceModule()
    findings = []
    entities = []
    relationships = []

    # 3 submissions with identical reporter_ip and description
    duplicate_reports = [
        {
            "report_id": "rep-1",
            "url": "https://phish.xyz/login",
            "hostname": "phish.xyz",
            "category": "phishing",
            "description": "Stole my login credentials",
            "reporter_ip": "203.0.113.195",
            "status": "pending",
        },
        {
            "report_id": "rep-2",
            "url": "https://phish.xyz/login",
            "hostname": "phish.xyz",
            "category": "phishing",
            "description": "Stole my login credentials",
            "reporter_ip": "203.0.113.195",
            "status": "pending",
        },
        {
            "report_id": "rep-3",
            "url": "https://phish.xyz/login",
            "hostname": "phish.xyz",
            "category": "phishing",
            "description": "Stole my login credentials",
            "reporter_ip": "203.0.113.195",
            "status": "pending",
        },
    ]

    res = mod._analyze_community_reports(duplicate_reports, "phish.xyz", "scan-ci-2", findings, entities, relationships)

    assert res["total_reports"] == 3
    assert res["duplicate_reports"] == 2
    assert res["independent_reporters"] == 1
    assert res["status_breakdown"]["pending"] == 3
    assert any("Pending Review" in f["title"] for f in findings)


def test_analyze_corroborated_reports_generates_high_severity():
    mod = CommunityIntelligenceModule()
    findings = []
    entities = []
    relationships = []

    corroborated_reports = [
        {
            "report_id": "rep-10",
            "url": "https://evil-bank.xyz",
            "hostname": "evil-bank.xyz",
            "category": "phishing",
            "description": "Credential harvesting form impersonating Chase bank",
            "reporter_contact": "analyst1@security.org",
            "status": "verified",
        },
        {
            "report_id": "rep-11",
            "url": "https://evil-bank.xyz",
            "hostname": "evil-bank.xyz",
            "category": "phishing",
            "description": "Phishing kit targeting credit card numbers",
            "reporter_contact": "analyst2@cert.gov",
            "status": "corroborated",
        },
    ]

    res = mod._analyze_community_reports(corroborated_reports, "evil-bank.xyz", "scan-ci-3", findings, entities, relationships)

    assert res["corroborated_threat_signal"] is True
    assert res["status_breakdown"]["corroborated"] == 2
    assert len(findings) == 1
    finding = findings[0]
    assert finding["severity"] in (Severity.HIGH.value, Severity.CRITICAL.value)
    assert "Corroborated Community Threat Reports" in finding["title"]
    assert finding["confidence"] >= 0.80
    assert any(r["type"] == "reported_by" for r in relationships)


def test_analyze_rejected_reports_dismissed():
    mod = CommunityIntelligenceModule()
    findings = []
    entities = []
    relationships = []

    rejected_reports = [
        {
            "report_id": "rep-99",
            "url": "https://innocent.com",
            "hostname": "innocent.com",
            "category": "scam",
            "description": "False alarm disputed and cleared",
            "status": "rejected",
        }
    ]

    res = mod._analyze_community_reports(rejected_reports, "innocent.com", "scan-ci-4", findings, entities, relationships)

    assert res["status_breakdown"]["rejected"] == 1
    # Rejected reports must not trigger malicious threat findings
    assert len(findings) == 0


@pytest.mark.anyio
async def test_external_intel_unconfigured_default():
    mod = CommunityIntelligenceModule()
    mod.settings.virustotal_api_key = ""
    mod.settings.abuseipdb_api_key = ""
    mod.settings.shodan_api_key = ""

    findings = []
    res = await mod._fetch_optional_external_intel("test.com", "1.1.1.1", "scan-ci-5", findings)

    assert res["virustotal"]["status"] == "not_configured"
    assert res["abuseipdb"]["status"] == "not_configured"
    assert res["shodan"]["status"] == "not_configured"
    assert len(findings) == 0


@pytest.mark.anyio
async def test_external_intel_provider_unavailable_does_not_crash():
    mod = CommunityIntelligenceModule()
    mod.settings.virustotal_api_key = "dummy_token"

    findings = []
    with patch("httpx.AsyncClient.get", side_effect=httpx.ConnectTimeout("Connection timeout")):
        res = await mod._fetch_optional_external_intel("unreachable.com", "1.1.1.1", "scan-ci-6", findings)

        assert res["virustotal"]["status"] == "unavailable"
        assert len(findings) == 0
