"""
Tests for scan orchestrator module registration and risk score computation.
"""
from app.scanner.orchestrator import ScanOrchestrator, ModuleInterface
from app.models.finding import FindingDocument, Severity, FindingCategory
from app.scanner.modules.placeholder import PlaceholderModule


def test_orchestrator_module_registration():
    orch = ScanOrchestrator()
    placeholder = PlaceholderModule()
    orch.register_module(placeholder)

    modules = orch.list_modules()
    assert len(modules) == 1
    assert modules[0]["name"] == "placeholder"

    orch.unregister_module("placeholder")
    assert len(orch.list_modules()) == 0


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
