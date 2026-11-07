"""
PHANTOM Explainable Risk Scoring Engine
Aggregates security findings across all scan modules into a transparent,
multi-factor risk score with clear risk drivers and remediation recommendations.
"""
import logging
from datetime import datetime
from typing import Optional, Union
import uuid

from app.models.finding import FindingCategory, FindingDocument, Severity
from app.scanner.orchestrator import ModuleInterface

logger = logging.getLogger("phantom.scanner.modules.risk_scoring")

# Severity scoring weights
SEVERITY_WEIGHTS = {
    "critical": 25.0,
    "high": 15.0,
    "medium": 8.0,
    "low": 3.0,
    "info": 0.5,
}


def calculate_explainable_risk(findings: list[Union[dict, FindingDocument]]) -> dict:
    """
    Computes a normalized, explainable risk assessment from a list of findings.

    Returns:
    {
        "risk_score": float (0.0 to 100.0),
        "risk_level": "none" | "low" | "medium" | "high" | "critical",
        "factor_breakdown": {
            "url_threats": float,
            "tls_vulnerabilities": float,
            "content_and_headers": float,
            "other": float,
        },
        "top_risk_factors": list[str],
        "recommendations": list[str],
        "findings_count": int,
    }
    """
    if not findings:
        return {
            "risk_score": 0.0,
            "risk_level": "none",
            "factor_breakdown": {
                "url_threats": 0.0,
                "tls_vulnerabilities": 0.0,
                "content_and_headers": 0.0,
                "other": 0.0,
            },
            "top_risk_factors": [],
            "recommendations": ["No significant security threats or anomalies detected."],
            "findings_count": 0,
        }

    raw_score = 0.0
    url_points = 0.0
    tls_points = 0.0
    content_points = 0.0
    other_points = 0.0

    scored_findings = []

    for item in findings:
        f = item.model_dump() if isinstance(item, FindingDocument) else item
        sev_str = str(f.get("severity", "info")).lower()
        if hasattr(sev_str, "value"):
            sev_str = sev_str.value
        conf = float(f.get("confidence", 0.5))
        category = str(f.get("category", "")).lower()

        weight = SEVERITY_WEIGHTS.get(sev_str, 0.5)
        points = weight * conf
        raw_score += points

        # Group by security domain
        if category in ("url_analysis", "phishing_indicator", "dns_analysis"):
            url_points += points
        elif category in ("tls_certificate",):
            tls_points += points
        elif category in ("security_headers", "content_analysis"):
            content_points += points
        else:
            other_points += points

        scored_findings.append({
            "title": f.get("title", "Unknown"),
            "severity": sev_str,
            "points": points,
            "recommendation": f.get("recommendation"),
        })

    # Normalized score capped at 100.0
    normalized_score = round(min(raw_score, 100.0), 1)

    # Determine risk level
    if normalized_score >= 75.0:
        risk_level = "critical"
    elif normalized_score >= 50.0:
        risk_level = "high"
    elif normalized_score >= 25.0:
        risk_level = "medium"
    elif normalized_score > 0.0:
        risk_level = "low"
    else:
        risk_level = "none"

    # Sort findings by contributed points to identify top risk factors
    scored_findings.sort(key=lambda x: x["points"], reverse=True)
    top_factors = [
        f"[{f['severity'].upper()}] {f['title']}"
        for f in scored_findings
        if f["points"] > 1.0
    ][:5]

    # Deduplicated recommendations
    recommendations = []
    seen_recs = set()
    for f in scored_findings:
        rec = f.get("recommendation")
        if rec and rec not in seen_recs:
            seen_recs.add(rec)
            recommendations.append(rec)
        if len(recommendations) >= 5:
            break

    return {
        "risk_score": normalized_score,
        "risk_level": risk_level,
        "factor_breakdown": {
            "url_threats": round(url_points, 1),
            "tls_vulnerabilities": round(tls_points, 1),
            "content_and_headers": round(content_points, 1),
            "other": round(other_points, 1),
        },
        "top_risk_factors": top_factors,
        "recommendations": recommendations,
        "findings_count": len(findings),
    }


class RiskScoringModule(ModuleInterface):
    """
    Explainable Risk Scoring Module.
    Calculates composite risk scores and produces explainable reporting.
    """

    name = "risk_scoring"
    description = "Explainable multi-factor risk scoring engine with domain breakdowns"
    version = "1.0.0"

    async def execute(self, target_url: str, hostname: str, scan_id: str, **kwargs) -> dict:
        logger.info("Executing risk scoring evaluation for %s (scan %s)", hostname, scan_id)

        # Context findings passed in kwargs (if any)
        context_findings = kwargs.get("findings", [])
        risk_data = calculate_explainable_risk(context_findings)

        findings = []
        if risk_data["risk_level"] in ("high", "critical"):
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "module": self.name,
                "category": FindingCategory.PHISHING_INDICATOR.value,
                "title": f"Elevated Threat Level Assigned: {risk_data['risk_level'].upper()}",
                "description": f"Target exhibits severe threat indicators across multiple vectors with composite risk score {risk_data['risk_score']}/100.",
                "severity": Severity.HIGH.value if risk_data["risk_level"] == "high" else Severity.CRITICAL.value,
                "confidence": 0.95,
                "evidence": risk_data["factor_breakdown"],
                "recommendation": "Review high and critical findings immediately before trusting this destination.",
                "created_at": datetime.utcnow(),
            })

        return {
            "data": risk_data,
            "findings": findings,
            "entities": [],
            "relationships": [],
        }
