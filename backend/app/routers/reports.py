"""
PHANTOM Community Reports Router
Endpoints for submitting and managing community threat reports.
"""
import logging
from datetime import datetime
from fastapi import APIRouter, HTTPException, Request, Query

from app.database import get_db
from app.models.report import (
    ReportRequest,
    ReportPatchRequest,
    ReportDocument,
    ReportResponse,
    ReportStatus,
)
from app.security.url_validator import validate_url, extract_hostname, URLValidationError

logger = logging.getLogger("phantom.routers.reports")

router = APIRouter()


@router.post("/reports", response_model=ReportResponse, status_code=201, summary="Submit a community report")
async def create_report(report_request: ReportRequest, request: Request):
    """Submit a community threat report for a URL."""
    # Validate URL
    try:
        validated_url = validate_url(report_request.url)
        hostname = extract_hostname(validated_url)
    except URLValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        db = get_db()
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Database is not available")

    report_doc = ReportDocument(
        url=validated_url,
        hostname=hostname,
        category=report_request.category,
        description=report_request.description,
        reporter_contact=report_request.reporter_contact,
        reporter_ip=request.client.host if request.client else None,
    )

    await db.reports.insert_one(report_doc.model_dump())
    logger.info("Community report %s submitted for %s", report_doc.report_id, hostname)

    return ReportResponse(**report_doc.model_dump())


@router.get("/reports", response_model=list[ReportResponse], summary="List community reports")
async def list_reports(
    hostname: str = Query(default=None, description="Filter by hostname"),
    status: str = Query(default=None, description="Filter by status"),
    limit: int = Query(default=50, ge=1, le=200, description="Max results"),
    offset: int = Query(default=0, ge=0, description="Offset for pagination"),
):
    """List community reports with optional filters."""
    try:
        db = get_db()
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Database is not available")

    query = {}
    if hostname:
        query["hostname"] = hostname
    if status:
        query["status"] = status

    reports = await (
        db.reports.find(query, {"_id": 0})
        .sort("created_at", -1)
        .skip(offset)
        .limit(limit)
        .to_list(length=limit)
    )

    return [ReportResponse(**r) for r in reports]


@router.patch("/reports/{report_id}", response_model=ReportResponse, summary="Update report status")
async def update_report(report_id: str, patch: ReportPatchRequest):
    """Update the status of a community report (e.g., verify or reject)."""
    try:
        db = get_db()
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Database is not available")

    update_data = {
        "status": patch.status.value,
        "updated_at": datetime.utcnow(),
    }
    if patch.reviewer_notes is not None:
        update_data["reviewer_notes"] = patch.reviewer_notes

    result = await db.reports.find_one_and_update(
        {"report_id": report_id},
        {"$set": update_data},
        return_document=True,
    )

    if not result:
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found")

    result.pop("_id", None)
    return ReportResponse(**result)
