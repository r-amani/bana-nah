"""
PHANTOM Scan Models
Pydantic models for scan requests, responses, and database documents.
"""
from datetime import datetime
from enum import Enum
from typing import Optional, Any
from pydantic import BaseModel, Field, HttpUrl, model_validator, field_validator
import uuid


class ScanStatus(str, Enum):
    """Scan lifecycle states."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"  # Some modules succeeded, some failed


class ModuleStatus(str, Enum):
    """Individual module execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    UNAVAILABLE = "unavailable"


class ScanRequest(BaseModel):
    """Request body for initiating a new scan."""
    url: str = Field(..., description="Target URL to scan", examples=["https://example.com"])
    modules: Optional[list[str]] = Field(
        default=None,
        description="Specific modules to run. If None, runs all available modules.",
        examples=[["url_detection", "tls_validation", "security_assessment"]],
    )

    model_config = {"extra": "ignore"}

    @model_validator(mode="before")
    @classmethod
    def normalize_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # Accept target_url if url is not provided
            if "url" not in data and "target_url" in data:
                data = {**data, "url": data["target_url"]}
            # Accept requested_modules if modules is not provided
            if "modules" not in data and "requested_modules" in data:
                data = {**data, "modules": data["requested_modules"]}
        return data

    @field_validator("url")
    @classmethod
    def validate_url_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Target URL cannot be empty")
        return v.strip()


class ModuleResult(BaseModel):
    """Result from a single scan module."""
    module: str = Field(..., description="Module identifier")
    status: ModuleStatus = Field(..., description="Module execution status")
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_ms: Optional[float] = None
    data: Optional[dict] = Field(default=None, description="Module-specific result data")
    error: Optional[str] = Field(default=None, description="Error message if module failed")

    model_config = {"extra": "ignore"}


class ScanResponse(BaseModel):
    """Response model for a scan."""
    scan_id: str = Field(..., description="Unique scan identifier")
    target_url: str = Field(..., description="The scanned URL")
    hostname: str = Field(..., description="Extracted hostname")
    status: ScanStatus = Field(..., description="Overall scan status")
    created_at: datetime
    completed_at: Optional[datetime] = None
    duration_ms: Optional[float] = None
    risk_score: Optional[float] = Field(default=None, ge=0.0, le=100.0, description="Overall risk score 0-100")
    risk_level: Optional[str] = Field(default=None, description="Risk level: low, medium, high, critical")
    module_results: list[ModuleResult] = Field(default_factory=list)
    summary: Optional[str] = Field(default=None, description="Human-readable scan summary")

    model_config = {"extra": "ignore"}


class ScanDocument(BaseModel):
    """MongoDB document schema for scans."""
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_url: str
    hostname: str
    status: ScanStatus = ScanStatus.PENDING
    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    duration_ms: Optional[float] = None
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    module_results: list[dict] = Field(default_factory=list)
    summary: Optional[str] = None
    request_ip: Optional[str] = None

    model_config = {"extra": "ignore"}
