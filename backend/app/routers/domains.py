"""
PHANTOM Domains Router
Endpoints for domain history and comparison.
"""
import logging
from fastapi import APIRouter, HTTPException, Query

from app.database import get_db

logger = logging.getLogger("phantom.routers.domains")

router = APIRouter()


@router.get("/domains/{hostname}/history", summary="Get domain scan history")
async def get_domain_history(
    hostname: str,
    limit: int = Query(default=20, ge=1, le=100, description="Max results"),
    offset: int = Query(default=0, ge=0, description="Offset for pagination"),
):
    """Retrieve scan history for a specific domain/hostname."""
    try:
        db = get_db()
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Database is not available")

    total = await db.scans.count_documents({"hostname": hostname})
    scans = await (
        db.scans.find({"hostname": hostname}, {"_id": 0})
        .sort("created_at", -1)
        .skip(offset)
        .limit(limit)
        .to_list(length=limit)
    )

    return {
        "hostname": hostname,
        "total": total,
        "offset": offset,
        "limit": limit,
        "scans": scans,
    }


@router.get("/domains/{hostname}/compare", summary="Compare domain scans over time")
async def compare_domain_scans(
    hostname: str,
    limit: int = Query(default=5, ge=2, le=20, description="Number of recent scans to compare"),
):
    """Compare the most recent scans for a hostname to identify changes."""
    try:
        db = get_db()
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Database is not available")

    scans = await (
        db.scans.find({"hostname": hostname}, {"_id": 0})
        .sort("created_at", -1)
        .limit(limit)
        .to_list(length=limit)
    )

    if len(scans) < 2:
        raise HTTPException(
            status_code=404,
            detail=f"Need at least 2 scans for comparison. Found {len(scans)} for '{hostname}'.",
        )

    # Build comparison data
    comparison = {
        "hostname": hostname,
        "scan_count": len(scans),
        "scans": [],
        "risk_trend": [],
    }

    for scan in scans:
        comparison["scans"].append({
            "scan_id": scan.get("scan_id"),
            "created_at": scan.get("created_at"),
            "status": scan.get("status"),
            "risk_score": scan.get("risk_score"),
            "risk_level": scan.get("risk_level"),
            "module_count": len(scan.get("module_results", [])),
        })
        if scan.get("risk_score") is not None:
            comparison["risk_trend"].append({
                "date": scan.get("created_at"),
                "score": scan.get("risk_score"),
            })

    return comparison
