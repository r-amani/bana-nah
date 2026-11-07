"""
Unit tests for Explainable Risk Scoring Engine.
"""
import pytest
from app.scanner.modules.risk_scoring import RiskScoringModule, calculate_explainable_risk
from app.models.finding import FindingDocument, Severity, FindingCategory


def test_calculate_risk_empty_findings():
    res = calculate_explainable_risk([])
    assert res["risk_score"] == 0.0
    assert res["risk_level"] == "none"
    assert res["findings_count"] == 0
    assert len(res["top_risk_factors"]) == 0


def test_calculate_risk_weights_and_breakdown():
    findings = [
        {
            "title": "Brand Typosquatting",
            "severity": "critical",
            "confidence": 1.0,
            "category": "phishing_indicator",
            "recommendation": "Block domain access.",
        },
        {
            "title": "Self-Signed Certificate",
            "severity": "high",
            "confidence": 0.9,
            "category": "tls_certificate",
            "recommendation": "Install trusted CA cert.",
        },
        {
            "title": "Missing HSTS Header",
            "severity": "medium",
            "confidence": 1.0,
            "category": "security_headers",
            "recommendation": "Enable HSTS header.",
        },
    ]

    # critical: 25 * 1.0 = 25
    # high: 15 * 0.9 = 13.5
    # medium: 8 * 1.0 = 8.0
    # raw sum: 46.5 -> round: 46.5
    res = calculate_explainable_risk(findings)

    assert res["risk_score"] == 46.5
    assert res["risk_level"] == "medium"
    assert res["factor_breakdown"]["url_threats"] == 25.0
    assert res["factor_breakdown"]["tls_vulnerabilities"] == 13.5
    assert res["factor_breakdown"]["content_and_headers"] == 8.0
    assert len(res["top_risk_factors"]) == 3
    assert len(res["recommendations"]) == 3


def test_calculate_risk_critical_cap():
    findings = [
        {"title": f"Critical Issue {i}", "severity": "critical", "confidence": 1.0, "category": "url_analysis"}
        for i in range(10)
    ]
    # 10 * 25 = 250 -> capped at 100.0
    res = calculate_explainable_risk(findings)
    assert res["risk_score"] == 100.0
    assert res["risk_level"] == "critical"


@pytest.mark.anyio
async def test_risk_scoring_module_execute():
    mod = RiskScoringModule()
    findings = [
        {"title": "Punycode Homograph", "severity": "critical", "confidence": 1.0, "category": "phishing_indicator"}
    ]

    res = await mod.execute("https://xn--pple-43d.com", "xn--pple-43d.com", "scan-risk-1", findings=findings)

    assert "data" in res
    assert res["data"]["risk_score"] == 25.0
    assert res["data"]["risk_level"] == "medium"
