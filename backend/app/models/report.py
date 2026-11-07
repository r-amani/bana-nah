"""
PHANTOM Community Report Models
Community-submitted threat intelligence reports.
"""
from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field
import uuid


class ReportStatus(str, Enum):
    """Report review status."""
    PENDING = "pending"
    VERIFIED = "verified"
    REJECTED = "rejected"
    UNDER_REVIEW = "under_review"


class ReportCategory(str, Enum):
    """Report threat categories."""
    PHISHING = "phishing"
    MALWARE = "malware"
    SCAM = "scam"
    SPAM = "spam"
    DEFACEMENT = "defacement"
    C2_SERVER = "c2_server"
    DATA_EXFILTRATION = "data_exfiltration"
    OTHER = "other"


class ReportRequest(BaseModel):
    """Request body for submitting a community report."""
    url: str = Field(..., description="Reported URL")
    category: ReportCategory = Field(..., description="Threat category")
    description: str = Field(..., min_length=10, max_length=2000, description="Description of the threat")
    reporter_contact: Optional[str] = Field(default=None, max_length=200, description="Optional contact info")


class ReportPatchRequest(BaseModel):
    """Request body for updating a report's status."""
    status: ReportStatus = Field(..., description="New report status")
    reviewer_notes: Optional[str] = Field(default=None, max_length=1000, description="Reviewer notes")


class ReportDocument(BaseModel):
    """MongoDB document schema for community reports."""
    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    url: str
    hostname: str
    category: ReportCategory
    description: str
    reporter_contact: Optional[str] = None
    reporter_ip: Optional[str] = None
    status: ReportStatus = ReportStatus.PENDING
    reviewer_notes: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = None


class ReportResponse(BaseModel):
    """API response model for reports."""
    report_id: str
    url: str
    hostname: str
    category: str
    description: str
    status: str
    reviewer_notes: Optional[str] = None
    created_at: datetime
    updated_at: Optional[datetime] = None
