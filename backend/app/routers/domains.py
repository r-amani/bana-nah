"""
PHANTOM Domains Router
Endpoints for domain scan history, timeline, and Flight Recorder comparison.
"""
import logging
from typing import Optional
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
    """Retrieve scan history and timeline for a specific domain/hostname."""
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

    # Fetch snapshots from Flight Recorder collection if available
    snapshots = await (
        db.flight_recorder.find({"hostname": hostname}, {"_id": 0})
        .sort("scan_timestamp", -1)
        .limit(limit)
        .to_list(length=limit)
    )

    return {
        "hostname": hostname,
        "total": total,
        "offset": offset,
        "limit": limit,
        "scans": scans,
        "snapshots": snapshots,
    }


@router.get("/domains/{hostname}/compare", summary="Compare domain scans over time (Flight Recorder)")
async def compare_domain_scans(
    hostname: str,
    limit: int = Query(default=5, ge=2, le=20, description="Number of recent scans to compare"),
):
    """
    Compare the most recent scans for a hostname using genuine Flight Recorder snapshots.
    Identifies risk deltas, certificate alterations, security header changes, and new findings.
    """
    try:
        db = get_db()
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Database is not available")

    # Fetch recent scans
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

    # Fetch Flight Recorder snapshots for these scans
    scan_ids = [s.get("scan_id") for s in scans if s.get("scan_id")]
    snapshots = await (
        db.flight_recorder.find({"scan_id": {"$in": scan_ids}}, {"_id": 0})
        .sort("scan_timestamp", -1)
        .to_list(length=limit)
    )
    snap_by_scan = {s["scan_id"]: s for s in snapshots if "scan_id" in s}

    # Pairwise comparisons between consecutive scans
    comparison_pairs = []
    for i in range(len(scans) - 1):
        latest = scans[i]
        prior = scans[i + 1]

        latest_snap = snap_by_scan.get(latest.get("scan_id"), {})
        prior_snap = snap_by_scan.get(prior.get("scan_id"), {})

        score_curr = float(latest.get("risk_score") or 0.0)
        score_prev = float(prior.get("risk_score") or 0.0)
        score_delta = round(score_curr - score_prev, 1)

        # Finding differences
        curr_findings = set(latest_snap.get("finding_titles", []))
        prev_findings = set(prior_snap.get("finding_titles", []))
        new_findings = sorted(list(curr_findings - prev_findings))
        resolved_findings = sorted(list(prev_findings - curr_findings))

        # TLS changes
        tls_curr = latest_snap.get("tls", {})
        tls_prev = prior_snap.get("tls", {})
        tls_changed = (tls_curr.get("sha256_fingerprint") != tls_prev.get("sha256_fingerprint")) if tls_curr and tls_prev else False

        # Header changes
        headers_curr = latest_snap.get("security_headers", {})
        headers_prev = prior_snap.get("security_headers", {})
        headers_removed = [h for h, val in headers_prev.items() if val and not headers_curr.get(h)]
        headers_added = [h for h, val in headers_curr.items() if val and not headers_prev.get(h)]

        comparison_pairs.append({
            "latest_scan_id": latest.get("scan_id"),
            "previous_scan_id": prior.get("scan_id"),
            "latest_timestamp": latest.get("created_at"),
            "previous_timestamp": prior.get("created_at"),
            "risk_score_delta": score_delta,
            "risk_trend": "escalated" if score_delta > 0 else "improved" if score_delta < 0 else "stable",
            "new_findings": new_findings,
            "resolved_findings": resolved_findings,
            "tls_changed": tls_changed,
            "headers_added": headers_added,
            "headers_removed": headers_removed,
        })

    # Summary
    trend = []
    for scan in reversed(scans):
        if scan.get("risk_score") is not None:
            trend.append({
                "scan_id": scan.get("scan_id"),
                "date": scan.get("created_at"),
                "score": scan.get("risk_score"),
                "level": scan.get("risk_level"),
            })

    return {
        "hostname": hostname,
        "scan_count": len(scans),
        "snapshots_recorded": len(snapshots),
        "risk_trend": trend,
        "consecutive_comparisons": comparison_pairs,
        "scans": [
            {
                "scan_id": s.get("scan_id"),
                "created_at": s.get("created_at"),
                "status": s.get("status"),
                "risk_score": s.get("risk_score"),
                "risk_level": s.get("risk_level"),
                "module_count": len(s.get("module_results", [])),
            }
            for s in scans
        ],
    }
