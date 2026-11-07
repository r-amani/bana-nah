"""
PHANTOM Scan Modules
"""
from app.scanner.modules.placeholder import PlaceholderModule
from app.scanner.modules.url_detection import UrlDetectionModule
from app.scanner.modules.tls_validation import TlsValidationModule
from app.scanner.modules.security_assessment import SecurityAssessmentModule
from app.scanner.modules.risk_scoring import RiskScoringModule

__all__ = [
    "PlaceholderModule",
    "UrlDetectionModule",
    "TlsValidationModule",
    "SecurityAssessmentModule",
    "RiskScoringModule",
]
