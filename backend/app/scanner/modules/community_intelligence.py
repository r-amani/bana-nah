"""
PHANTOM Community Intelligence Module
Retrieves, de-duplicates, and evaluates community threat reports and optional
external intelligence feeds (VirusTotal, AbuseIPDB, Shodan) without hardcoded keys.
"""
import asyncio
import hashlib
import logging
from datetime import datetime
from typing import Optional
import uuid

import httpx
from app.config import get_settings
from app.database import get_db
from app.models.entity import EntityType, RelationshipType
from app.models.finding import FindingCategory, Severity
from app.scanner.orchestrator import ModuleInterface

logger = logging.getLogger("phantom.scanner.modules.community_intelligence")


def _add_finding(findings: list, scan_id: str, title: str, desc: str, severity: Severity, conf: float, evidence: dict, rec: str, cat: FindingCategory = FindingCategory.REPUTATION):
    findings.append({
        "finding_id": str(uuid.uuid4()), "scan_id": scan_id, "module": "community_intelligence",
        "category": cat.value if hasattr(cat, "value") else cat,
        "title": title, "description": desc,
        "severity": severity.value if hasattr(severity, "value") else severity,
        "confidence": conf, "evidence": evidence, "recommendation": rec,
        "created_at": datetime.utcnow(),
    })


class CommunityIntelligenceModule(ModuleInterface):
    name = "community_intelligence"
    description = "Community threat reporting and optional multi-source intelligence integration"
    version = "1.0.0"

    def __init__(self):
        self.settings = get_settings()

    async def execute(self, target_url: str, hostname: str, scan_id: str, **kwargs) -> dict:
        logger.info("Executing community intelligence analysis for %s (scan %s)", hostname, scan_id)
        findings, entities, relationships = [], [], []

        raw_reports = await self._fetch_reports_for_domain(hostname)
        report_metrics = self._analyze_community_reports(raw_reports, hostname, scan_id, findings, entities, relationships)

        resolved_ip = kwargs.get("resolved_ip")
        if not resolved_ip:
            for ent in kwargs.get("entities", []):
                ent_type = ent.get("type") if isinstance(ent, dict) else getattr(ent, "type", None)
                if ent_type in (EntityType.IP_ADDRESS, "ip_address"):
                    resolved_ip = ent.get("value") if isinstance(ent, dict) else getattr(ent, "value", None)
                    break

        external_intel = await self._fetch_optional_external_intel(hostname, resolved_ip, scan_id, findings)
        return {
            "data": {"hostname": hostname, "community_reports": report_metrics, "external_intelligence": external_intel},
            "findings": findings, "entities": entities, "relationships": relationships,
        }

    async def _fetch_reports_for_domain(self, hostname: str) -> list[dict]:
        try:
            db = get_db()
            return await db.reports.find({"hostname": hostname}, {"_id": 0}).to_list(length=500)
        except Exception as e:
            logger.warning("Could not fetch reports from database: %s", e)
            return []

    def _analyze_community_reports(self, reports: list[dict], hostname: str, scan_id: str, findings: list[dict], entities: list[dict], relationships: list[dict]) -> dict:
        status_breakdown = {"pending": 0, "corroborated": 0, "disputed": 0, "rejected": 0, "under_review": 0}
        categories, seen_fps, unique_reps, dup_count, valid_reports = {}, set(), set(), 0, []

        for r in reports:
            raw_st = str(r.get("status", "pending")).lower()
            st_key = "corroborated" if raw_st in ("verified", "corroborated") else (raw_st if raw_st in status_breakdown else "pending")
            status_breakdown[st_key] += 1

            cat = str(r.get("category", "other")).lower()
            categories[cat] = categories.get(cat, 0) + 1

            rep_id = r.get("reporter_contact") or r.get("reporter_ip") or "anonymous"
            desc = (r.get("description") or "").strip().lower()
            fp = hashlib.sha256(f"{rep_id}|{desc}".encode("utf-8")).hexdigest()

            if fp in seen_fps and rep_id != "anonymous":
                dup_count += 1
            else:
                seen_fps.add(fp)
                if rep_id != "anonymous":
                    unique_reps.add(rep_id)
                valid_reports.append(r)

        indep_reporters = len(unique_reps) if unique_reps else (len(valid_reports) - dup_count)
        indep_reporters = max(1, indep_reporters) if valid_reports else 0
        corroborated_count, pending_count = status_breakdown["corroborated"], status_breakdown["pending"]

        if corroborated_count > 0:
            sev = Severity.CRITICAL if corroborated_count >= 3 else Severity.HIGH
            conf = min(0.95, 0.70 + (corroborated_count * 0.08))
            _add_finding(findings, scan_id, f"Corroborated Community Threat Reports ({corroborated_count} Verified)", f"Domain has {corroborated_count} independently verified community threat reports flagging it for malicious activity ({', '.join(categories.keys())}).", sev, round(conf, 2), {"corroborated_reports": corroborated_count, "independent_reporters": indep_reporters, "categories": categories, "status_breakdown": status_breakdown}, "Treat destination as an active threat. Avoid interacting with credentials or downloads.")
        elif pending_count > 0:
            _add_finding(findings, scan_id, f"Unverified Community Reports Submitted ({pending_count} Pending Review)", f"Domain has {pending_count} community report(s) pending verification. Early signals do not represent verified compromise.", Severity.LOW if pending_count < 3 else Severity.MEDIUM, 0.40, {"pending_reports": pending_count, "categories": categories, "duplicate_reports_identified": dup_count}, "Review community reports for context while awaiting moderation review.")

        domain_ent_id = f"domain:{hostname}"
        entities.append({"entity_id": domain_ent_id, "type": EntityType.DOMAIN.value, "value": hostname, "metadata": {"community_reports_count": len(reports), "corroborated_count": corroborated_count}, "first_seen": datetime.utcnow(), "last_seen": datetime.utcnow(), "scan_ids": [scan_id]})

        if corroborated_count > 0:
            for rep in valid_reports:
                if str(rep.get("status", "")).lower() in ("verified", "corroborated"):
                    rep_id = rep.get("report_id", str(uuid.uuid4()))
                    relationships.append({"relationship_id": str(uuid.uuid4()), "source_entity_id": domain_ent_id, "target_entity_id": f"report:{rep_id}", "type": RelationshipType.REPORTED_BY.value, "scan_id": scan_id, "confidence": 0.90, "metadata": {"category": rep.get("category"), "status": rep.get("status"), "reported_at": str(rep.get("created_at"))}, "created_at": datetime.utcnow()})

        return {
            "total_reports": len(reports), "independent_reporters": indep_reporters, "duplicate_reports": dup_count,
            "status_breakdown": status_breakdown, "categories": categories, "corroborated_threat_signal": corroborated_count > 0,
        }

    async def _fetch_optional_external_intel(self, hostname: str, resolved_ip: Optional[str], scan_id: str, findings: list[dict]) -> dict:
        results = {"virustotal": {"status": "not_configured", "data": None}, "abuseipdb": {"status": "not_configured", "data": None}, "shodan": {"status": "not_configured", "data": None}}

        vt_key = self.settings.virustotal_api_key
        if vt_key:
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.get(f"https://www.virustotal.com/api/v3/domains/{hostname}", headers={"x-apikey": vt_key})
                    if resp.status_code == 200:
                        vt_data = resp.json().get("data", {}).get("attributes", {})
                        stats = vt_data.get("last_analysis_stats", {})
                        malicious = stats.get("malicious", 0)
                        results["virustotal"] = {"status": "available", "data": {"malicious_count": malicious, "suspicious_count": stats.get("suspicious", 0), "harmless_count": stats.get("harmless", 0), "reputation": vt_data.get("reputation", 0)}}
                        if malicious >= 3:
                            _add_finding(findings, scan_id, f"VirusTotal Detection: {malicious} Security Vendors Flagged Domain", f"VirusTotal threat intelligence aggregates {malicious} engine detections for {hostname}.", Severity.HIGH if malicious < 10 else Severity.CRITICAL, 0.90, {"stats": stats}, "Block network traffic to this destination based on vendor consensus.")
                    elif resp.status_code == 404:
                        results["virustotal"] = {"status": "inconclusive", "data": "Domain unknown to VirusTotal"}
                    else:
                        results["virustotal"] = {"status": "unavailable", "data": f"HTTP {resp.status_code}"}
            except Exception as e:
                logger.warning("VirusTotal check failed: %s", e)
                results["virustotal"] = {"status": "unavailable", "data": str(e)}

        abuse_key = self.settings.abuseipdb_api_key
        if abuse_key and resolved_ip:
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": resolved_ip, "maxAgeInDays": "90"}, headers={"Key": abuse_key, "Accept": "application/json"})
                    if resp.status_code == 200:
                        abuse_data = resp.json().get("data", {})
                        score = abuse_data.get("abuseConfidenceScore", 0)
                        results["abuseipdb"] = {"status": "available", "data": {"ip": resolved_ip, "abuse_confidence_score": score, "total_reports": abuse_data.get("totalReports", 0), "country_code": abuse_data.get("countryCode"), "isp": abuse_data.get("isp")}}
                        if score >= 50:
                            _add_finding(findings, scan_id, f"AbuseIPDB Flagged Hosting IP ({score}% Abuse Confidence)", f"Resolved hosting IP {resolved_ip} has recorded abuse history with {score}% confidence score.", Severity.HIGH if score >= 80 else Severity.MEDIUM, score / 100.0, {"ip": resolved_ip, "score": score}, "Inspect server IP reputation and related hosted sites.", FindingCategory.INFRASTRUCTURE)
                    else:
                        results["abuseipdb"] = {"status": "unavailable", "data": f"HTTP {resp.status_code}"}
            except Exception as e:
                logger.warning("AbuseIPDB check failed: %s", e)
                results["abuseipdb"] = {"status": "unavailable", "data": str(e)}

        shodan_key = self.settings.shodan_api_key
        if shodan_key and resolved_ip:
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.get(f"https://api.shodan.io/shodan/host/{resolved_ip}", params={"key": shodan_key})
                    if resp.status_code == 200:
                        sh_data = resp.json()
                        results["shodan"] = {"status": "available", "data": {"ports": sh_data.get("ports", []), "org": sh_data.get("org"), "os": sh_data.get("os"), "vulns": list(sh_data.get("vulns", {}).keys())}}
                    elif resp.status_code == 404:
                        results["shodan"] = {"status": "inconclusive", "data": "No open ports indexed"}
                    else:
                        results["shodan"] = {"status": "unavailable", "data": f"HTTP {resp.status_code}"}
            except Exception as e:
                logger.warning("Shodan check failed: %s", e)
                results["shodan"] = {"status": "unavailable", "data": str(e)}

        return results
