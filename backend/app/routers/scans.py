"""
PHANTOM Scans Router
Endpoints for initiating and retrieving scans.
"""
import logging
from fastapi import APIRouter, HTTPException, Request, Query
from app.models.scan import ScanRequest, ScanResponse
from app.models.finding import FindingResponse
from app.database import get_db
from app.scanner.orchestrator import orchestrator
from app.security.url_validator import URLValidationError

logger = logging.getLogger("phantom.routers.scans")

router = APIRouter()


@router.post("/scans", response_model=ScanResponse, status_code=201, summary="Initiate a new scan")
async def create_scan(scan_request: ScanRequest, request: Request):
    """
    Start a new scan against a URL.
    The scan runs all registered modules (or a subset if specified)
    and returns the aggregated results.
    """
    try:
        result = await orchestrator.run_scan(
            target_url=scan_request.url,
            requested_modules=scan_request.modules,
            request_ip=request.client.host if request.client else None,
        )
        return ScanResponse(**result)
    except URLValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except RuntimeError as e:
        if "Database not connected" in str(e):
            raise HTTPException(status_code=503, detail="Database is not available")
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.exception("Scan failed: %s", e)
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.get("/scans", response_model=list[ScanResponse], summary="List recent scans")
async def list_scans(
    limit: int = Query(default=10, ge=1, le=100, description="Max results to return"),
    offset: int = Query(default=0, ge=0, description="Offset for pagination"),
):
    """
    Retrieve persisted scan records sorted by creation timestamp descending.
    Supports limit and offset query parameters.
    """
    try:
        db = get_db()
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Database is not available")

    scans = await (
        db.scans.find({}, {"_id": 0})
        .sort("created_at", -1)
        .skip(offset)
        .limit(limit)
        .to_list(length=limit)
    )
    return [ScanResponse(**s) for s in scans]


@router.get("/scans/{scan_id}", response_model=ScanResponse, summary="Get scan details")
async def get_scan(scan_id: str):
    """Retrieve a scan by its ID."""
    try:
        db = get_db()
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Database is not available")

    doc = await db.scans.find_one({"scan_id": scan_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
    return ScanResponse(**doc)


@router.get("/scans/{scan_id}/findings", response_model=list[FindingResponse], summary="Get scan findings")
async def get_scan_findings(scan_id: str):
    """Retrieve all findings for a scan."""
    try:
        db = get_db()
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Database is not available")

    # Verify scan exists
    scan = await db.scans.find_one({"scan_id": scan_id}, {"_id": 0, "scan_id": 1})
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")

    findings = await db.findings.find({"scan_id": scan_id}, {"_id": 0}).to_list(length=1000)
    return [FindingResponse(**f) for f in findings]
