"""
Tests for scan orchestrator module registration and risk score computation.
"""
from app.scanner.orchestrator import ScanOrchestrator, ModuleInterface
from app.models.finding import FindingDocument, Severity, FindingCategory
from app.scanner.modules.placeholder import PlaceholderModule
from app.scanner.modules.url_detection import UrlDetectionModule
from app.scanner.modules.tls_validation import TlsValidationModule
from app.scanner.modules.security_assessment import SecurityAssessmentModule
from app.scanner.modules.risk_scoring import RiskScoringModule


def test_orchestrator_module_registration():
    orch = ScanOrchestrator()
    placeholder = PlaceholderModule()
    orch.register_module(placeholder)

    modules = orch.list_modules()
    assert len(modules) == 1
    assert modules[0]["name"] == "placeholder"

    orch.unregister_module("placeholder")
    assert len(orch.list_modules()) == 0


def test_orchestrator_all_modules_registered():
    orch = ScanOrchestrator()
    orch.register_module(PlaceholderModule())
    orch.register_module(UrlDetectionModule())
    orch.register_module(TlsValidationModule())
    orch.register_module(SecurityAssessmentModule())
    orch.register_module(RiskScoringModule())

    registered = [m["name"] for m in orch.list_modules()]
    assert "placeholder" in registered
    assert "url_detection" in registered
    assert "tls_validation" in registered
    assert "security_assessment" in registered
    assert "risk_scoring" in registered
    assert len(registered) == 5


def test_basic_risk_score_calculation():
    orch = ScanOrchestrator()
    findings = [
        {"severity": "critical", "confidence": 1.0},
        {"severity": "high", "confidence": 0.8},
        {"severity": "medium", "confidence": 0.5},
    ]
    # critical: 25 * 1.0 = 25
    # high: 15 * 0.8 = 12
    # medium: 8 * 0.5 = 4
    # total = 41.0
    score = orch._compute_basic_risk_score(findings)
    assert score == 41.0
    assert orch._risk_level(score) == "medium"
