"""
PHANTOM Phishing Flight Recorder Module
Preserves timestamped security snapshots across scans and performs
delta comparison to detect infrastructure drift, certificate changes, and risk escalations.
"""
import copy
import logging
from datetime import datetime
from typing import Optional
import uuid

from app.database import get_db
from app.models.finding import FindingCategory, Severity
from app.scanner.orchestrator import ModuleInterface

logger = logging.getLogger("phantom.scanner.modules.flight_recorder")


def _add_finding(findings: list, scan_id: str, title: str, desc: str, severity: Severity, conf: float, evidence: dict, rec: str, cat: FindingCategory = FindingCategory.BEHAVIORAL):
    findings.append({
        "finding_id": str(uuid.uuid4()), "scan_id": scan_id, "module": "flight_recorder",
        "category": cat.value if hasattr(cat, "value") else cat,
        "title": title, "description": desc,
        "severity": severity.value if hasattr(severity, "value") else severity,
        "confidence": conf, "evidence": evidence, "recommendation": rec,
        "created_at": datetime.utcnow(),
    })


class FlightRecorderModule(ModuleInterface):
    name = "flight_recorder"
    description = "Preserves historical observation snapshots and tracks infrastructure drift"
    version = "1.0.0"

    async def execute(self, target_url: str, hostname: str, scan_id: str, **kwargs) -> dict:
        logger.info("Executing Flight Recorder observation for %s (scan %s)", hostname, scan_id)
        findings = []

        current_snapshot = self._build_snapshot(
            target_url, hostname, scan_id, kwargs.get("findings", []),
            kwargs.get("module_results", []), kwargs.get("risk_score", 0.0),
            kwargs.get("risk_level", "none"), kwargs
        )
        previous_snapshot = await self._fetch_latest_previous_snapshot(hostname, scan_id)

        if previous_snapshot:
            comparison = self._compare_snapshots(current_snapshot, previous_snapshot, scan_id, findings)
            has_history = True
        else:
            comparison = {"has_history": False, "message": f"First recorded Flight Recorder observation for {hostname}. No prior snapshot exists for comparison.", "delta": None}
            has_history = False

        await self._persist_snapshot(current_snapshot)
        return {
            "data": {"hostname": hostname, "scan_id": scan_id, "has_history": has_history, "current_snapshot": current_snapshot, "previous_snapshot": previous_snapshot, "comparison": comparison},
            "findings": findings, "entities": [], "relationships": [],
        }

    def _build_snapshot(self, target_url: str, hostname: str, scan_id: str, findings: list, module_results: list, risk_score: float, risk_level: str, extra_data: dict) -> dict:
        tls_data = extra_data.get("tls_data") or {}
        headers_data = extra_data.get("security_headers_data") or {}
        redirects_data = extra_data.get("redirects_data") or {}

        for mod in module_results:
            m_name, m_data = mod.get("module"), mod.get("data") or {}
            if m_name == "tls_validation" and not tls_data:
                tls_data = m_data
            elif m_name == "security_assessment":
                if not headers_data:
                    headers_data = m_data.get("security_headers") or {}
                if not redirects_data:
                    redirects_data = m_data.get("redirects") or {}

        unavailable = [m.get("module") for m in module_results if m.get("status") in ("unavailable", "failed")]
        finding_titles = [f.get("title") for f in findings if f.get("title")]
        finding_categories = list(set([str(f.get("category")) for f in findings if f.get("category")]))

        return {
            "snapshot_id": str(uuid.uuid4()), "scan_id": scan_id, "hostname": hostname, "submitted_url": target_url,
            "scan_timestamp": datetime.utcnow().isoformat(), "risk_score": float(risk_score), "risk_level": risk_level,
            "confidence_level": 0.85 if findings else 0.50, "findings_count": len(findings),
            "finding_titles": sorted(finding_titles), "finding_categories": sorted(finding_categories),
            "tls": {
                "issuer": tls_data.get("issuer"), "common_name": tls_data.get("common_name"),
                "sha256_fingerprint": tls_data.get("sha256_fingerprint"), "is_expired": tls_data.get("is_expired"),
                "is_self_signed": tls_data.get("is_self_signed"), "not_after": str(tls_data.get("not_after")) if tls_data.get("not_after") else None,
            },
            "security_headers": {
                "hsts": headers_data.get("hsts", False), "csp": headers_data.get("csp", False),
                "x_frame_options": headers_data.get("x_frame_options", False), "x_content_type_options": headers_data.get("x_content_type_options", False),
            },
            "redirects": {"hop_count": redirects_data.get("hop_count", 0), "final_url": redirects_data.get("final_url", target_url), "destinations": redirects_data.get("destinations", [])},
            "unavailable_checks": unavailable,
        }

    async def _fetch_latest_previous_snapshot(self, hostname: str, current_scan_id: str) -> Optional[dict]:
        try:
            db = get_db()
            prior = await db.flight_recorder.find_one({"hostname": hostname, "scan_id": {"$ne": current_scan_id}}, {"_id": 0}, sort=[("scan_timestamp", -1)])
            if prior:
                return prior
            prior_scan = await db.scans.find_one({"hostname": hostname, "scan_id": {"$ne": current_scan_id}}, {"_id": 0}, sort=[("created_at", -1)])
            if prior_scan:
                return {
                    "snapshot_id": f"scan-{prior_scan.get('scan_id')}", "scan_id": prior_scan.get("scan_id"), "hostname": hostname,
                    "submitted_url": prior_scan.get("target_url"), "scan_timestamp": str(prior_scan.get("created_at")),
                    "risk_score": prior_scan.get("risk_score", 0.0), "risk_level": prior_scan.get("risk_level", "none"),
                    "confidence_level": 0.80, "findings_count": len(prior_scan.get("module_results", [])),
                    "finding_titles": [], "finding_categories": [], "tls": {}, "security_headers": {}, "redirects": {}, "unavailable_checks": [],
                }
            return None
        except Exception as e:
            logger.warning("Could not query previous snapshots: %s", e)
            return None

    def _compare_snapshots(self, current: dict, previous: dict, scan_id: str, findings: list, entities: list = None, relationships: list = None) -> dict:
        curr_titles, prev_titles = set(current.get("finding_titles", [])), set(previous.get("finding_titles", []))
        new_findings, resolved_findings = sorted(list(curr_titles - prev_titles)), sorted(list(prev_titles - curr_titles))

        prev_score, curr_score = float(previous.get("risk_score") or 0.0), float(current.get("risk_score") or 0.0)
        score_delta = round(curr_score - prev_score, 1)

        curr_tls, prev_tls = current.get("tls") or {}, previous.get("tls") or {}
        tls_changed, tls_differences = False, []

        if curr_tls.get("sha256_fingerprint") and prev_tls.get("sha256_fingerprint") and curr_tls["sha256_fingerprint"] != prev_tls["sha256_fingerprint"]:
            tls_changed = True
            tls_differences.append("Certificate fingerprint replaced")
        if curr_tls.get("issuer") != prev_tls.get("issuer") and curr_tls.get("issuer"):
            tls_changed = True
            tls_differences.append(f"Issuer changed: {prev_tls.get('issuer')} -> {curr_tls.get('issuer')}")
        if curr_tls.get("is_self_signed") != prev_tls.get("is_self_signed"):
            tls_changed = True
            tls_differences.append(f"Self-signed status flipped to {curr_tls.get('is_self_signed')}")

        curr_h, prev_h = current.get("security_headers") or {}, previous.get("security_headers") or {}
        headers_added = [h for h, st in curr_h.items() if st and not prev_h.get(h, False)]
        headers_removed = [h for h, st in curr_h.items() if not st and prev_h.get(h, False)]

        curr_redir, prev_redir = current.get("redirects") or {}, previous.get("redirects") or {}
        redirect_changed = (curr_redir.get("final_url") != prev_redir.get("final_url"))
        newly_unavailable = list(set(current.get("unavailable_checks", [])) - set(previous.get("unavailable_checks", [])))

        delta = {
            "has_history": True, "previous_scan_id": previous.get("scan_id"), "previous_timestamp": previous.get("scan_timestamp"),
            "risk_score_delta": score_delta, "risk_level_shift": f"{previous.get('risk_level')} -> {current.get('risk_level')}",
            "new_findings": new_findings, "resolved_findings": resolved_findings, "tls_changed": tls_changed,
            "tls_differences": tls_differences, "headers_added": headers_added, "headers_removed": headers_removed,
            "redirect_changed": redirect_changed, "newly_unavailable_checks": newly_unavailable,
        }

        if score_delta >= 15.0:
            _add_finding(findings, scan_id, f"Flight Recorder: Risk Score Escalated by +{score_delta} Points", f"Target demonstrated significant security degradation compared to previous scan ({previous.get('scan_id')}). Score escalated from {prev_score} to {curr_score}.", Severity.HIGH if score_delta >= 25.0 else Severity.MEDIUM, 0.90, {"previous_score": prev_score, "current_score": curr_score, "delta": score_delta, "new_findings": new_findings}, "Review recently detected vulnerabilities and structural modifications.", FindingCategory.BEHAVIORAL)

        if tls_changed:
            _add_finding(findings, scan_id, "Flight Recorder: TLS Certificate Infrastructure Shift Observed", f"The TLS certificate presented by {current.get('hostname')} has changed since previous observation. Differences: {', '.join(tls_differences)}.", Severity.MEDIUM, 0.85, {"differences": tls_differences, "previous_fingerprint": prev_tls.get("sha256_fingerprint"), "current_fingerprint": curr_tls.get("sha256_fingerprint")}, "Verify whether certificate rotation was scheduled or indicates MITM/impersonation.", FindingCategory.TLS_CERTIFICATE)

        if headers_removed:
            _add_finding(findings, scan_id, f"Flight Recorder: Security Headers Stripped ({', '.join(headers_removed)})", f"Target previously enforced security headers ({', '.join(headers_removed)}) that are no longer present in current response.", Severity.LOW, 0.80, {"removed_headers": headers_removed}, "Restore missing security headers to maintain defense-in-depth.", FindingCategory.SECURITY_HEADERS)

        return delta

    async def _persist_snapshot(self, snapshot: dict) -> None:
        try:
            db = get_db()
            await db.flight_recorder.insert_one(copy.deepcopy(snapshot))
            logger.info("Flight Recorder snapshot persisted for %s (scan %s)", snapshot["hostname"], snapshot["scan_id"])
        except Exception as e:
            logger.warning("Could not persist Flight Recorder snapshot: %s", e)
