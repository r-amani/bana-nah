"""
PHANTOM Finding Models
Findings are individual detection results from scan modules.
"""
from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field
import uuid


class Severity(str, Enum):
    """Finding severity levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingCategory(str, Enum):
    """Categories of findings."""
    URL_ANALYSIS = "url_analysis"
    TLS_CERTIFICATE = "tls_certificate"
    SECURITY_HEADERS = "security_headers"
    CONTENT_ANALYSIS = "content_analysis"
    DNS_ANALYSIS = "dns_analysis"
    REPUTATION = "reputation"
    PHISHING_INDICATOR = "phishing_indicator"
    MALWARE_INDICATOR = "malware_indicator"
    INFRASTRUCTURE = "infrastructure"
    BEHAVIORAL = "behavioral"


class FindingDocument(BaseModel):
    """MongoDB document schema for findings."""
    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str = Field(..., description="Associated scan ID")
    module: str = Field(..., description="Module that generated this finding")
    category: FindingCategory
    title: str = Field(..., description="Short finding title")
    description: str = Field(..., description="Detailed description")
    severity: Severity = Severity.INFO
    confidence: float = Field(default=0.5, ge=0.0, le=1.0, description="Confidence score 0-1")
    evidence: Optional[dict] = Field(default=None, description="Supporting evidence data")
    recommendation: Optional[str] = Field(default=None, description="Remediation guidance")
    created_at: datetime = Field(default_factory=datetime.utcnow)


class FindingResponse(BaseModel):
    """API response model for findings."""
    finding_id: str
    scan_id: str
    module: str
    category: str
    title: str
    description: str
    severity: str
    confidence: float
    evidence: Optional[dict] = None
    recommendation: Optional[str] = None
    created_at: datetime

    model_config = {"extra": "ignore"}
