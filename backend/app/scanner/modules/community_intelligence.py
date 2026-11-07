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
from app.models.entity import EntityDocument, EntityType, RelationshipDocument, RelationshipType
from app.models.finding import FindingCategory, FindingDocument, Severity
from app.scanner.orchestrator import ModuleInterface

logger = logging.getLogger("phantom.scanner.modules.community_intelligence")


class CommunityIntelligenceModule(ModuleInterface):
    """
    Community Intelligence Module.
    Aggregates community reports and external intelligence signals into evidence-backed findings.
    """

    name = "community_intelligence"
    description = "Community threat reporting and optional multi-source intelligence integration"
    version = "1.0.0"

    def __init__(self):
        self.settings = get_settings()

    async def execute(self, target_url: str, hostname: str, scan_id: str, **kwargs) -> dict:
        """
        Execute community intelligence analysis.
        Retrieves database reports, de-duplicates them, checks status, and checks optional APIs.
        """
        logger.info("Executing community intelligence analysis for %s (scan %s)", hostname, scan_id)

        findings = []
        entities = []
        relationships = []

        # 1. Fetch community reports from database
        raw_reports = await self._fetch_reports_for_domain(hostname)

        # 2. Analyze, group, and deduplicate reports
        report_metrics = self._analyze_community_reports(raw_reports, hostname, scan_id, findings, entities, relationships)

        # 3. Optional external threat intelligence feeds (VirusTotal, AbuseIPDB, Shodan)
        # Context entities or resolved IP may be supplied in kwargs
        resolved_ip = kwargs.get("resolved_ip")
        if not resolved_ip:
            # Check context entities for resolved IP
            for ent in kwargs.get("entities", []):
                ent_type = ent.get("type") if isinstance(ent, dict) else getattr(ent, "type", None)
                if ent_type in (EntityType.IP_ADDRESS, "ip_address"):
                    resolved_ip = ent.get("value") if isinstance(ent, dict) else getattr(ent, "value", None)
                    break

        external_intel = await self._fetch_optional_external_intel(hostname, resolved_ip, scan_id, findings)

        data = {
            "hostname": hostname,
            "community_reports": report_metrics,
            "external_intelligence": external_intel,
        }

        return {
            "data": data,
            "findings": findings,
            "entities": entities,
            "relationships": relationships,
        }

    async def _fetch_reports_for_domain(self, hostname: str) -> list[dict]:
        """Fetch community reports from MongoDB with safe fallback."""
        try:
            db = get_db()
            cursor = db.reports.find({"hostname": hostname}, {"_id": 0})
            return await cursor.to_list(length=500)
        except Exception as e:
            logger.warning("Could not fetch reports from database (degraded mode): %s", e)
            return []

    def _analyze_community_reports(
        self,
        reports: list[dict],
        hostname: str,
        scan_id: str,
        findings: list[dict],
        entities: list[dict],
        relationships: list[dict],
    ) -> dict:
        """
        De-duplicates reports, checks review statuses, counts independent corroborations,
        and generates evidence-backed findings.
        """
        if not reports:
            return {
                "total_reports": 0,
                "independent_reporters": 0,
                "duplicate_reports": 0,
                "status_breakdown": {
                    "pending": 0,
                    "corroborated": 0,
                    "disputed": 0,
                    "rejected": 0,
                    "under_review": 0,
                },
                "categories": {},
                "corroborated_threat_signal": False,
            }

        status_breakdown = {
            "pending": 0,
            "corroborated": 0,
            "disputed": 0,
            "rejected": 0,
            "under_review": 0,
        }
        categories = {}

        # De-duplication structures
        seen_fingerprints = set()
        unique_reporters = set()
        duplicate_count = 0
        valid_reports = []

        for r in reports:
            raw_status = str(r.get("status", "pending")).lower()
            if raw_status in ("verified", "corroborated"):
                status_key = "corroborated"
            elif raw_status in status_breakdown:
                status_key = raw_status
            else:
                status_key = "pending"
            status_breakdown[status_key] += 1

            cat = str(r.get("category", "other")).lower()
            categories[cat] = categories.get(cat, 0) + 1

            # Identify reporter identifier
            reporter_id = r.get("reporter_contact") or r.get("reporter_ip") or "anonymous"
            desc = (r.get("description") or "").strip().lower()
            # Fingerprint combines reporter identifier or text hash with target
            fp = hashlib.sha256(f"{reporter_id}|{desc}".encode("utf-8")).hexdigest()

            if fp in seen_fingerprints and reporter_id != "anonymous":
                duplicate_count += 1
            else:
                seen_fingerprints.add(fp)
                if reporter_id != "anonymous":
                    unique_reporters.add(reporter_id)
                valid_reports.append(r)

        independent_reporters_count = len(unique_reporters) if unique_reporters else (len(valid_reports) - duplicate_count)
        independent_reporters_count = max(1, independent_reporters_count) if valid_reports else 0

        # Evaluate Corroborated Reports
        corroborated_count = status_breakdown["corroborated"]
        pending_count = status_breakdown["pending"]
        rejected_count = status_breakdown["rejected"]

        # Rejected reports are dismissed and must not generate threat findings
        # Only active reports count
        if corroborated_count > 0:
            severity = Severity.CRITICAL if corroborated_count >= 3 else Severity.HIGH
            confidence = min(0.95, 0.70 + (corroborated_count * 0.08))
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "module": self.name,
                "category": FindingCategory.REPUTATION.value,
                "title": f"Corroborated Community Threat Reports ({corroborated_count} Verified)",
                "description": (
                    f"Domain has {corroborated_count} independently verified community threat reports "
                    f"flagging it for malicious activity ({', '.join(categories.keys())})."
                ),
                "severity": severity.value,
                "confidence": round(confidence, 2),
                "evidence": {
                    "corroborated_reports": corroborated_count,
                    "independent_reporters": independent_reporters_count,
                    "categories": categories,
                    "status_breakdown": status_breakdown,
                },
                "recommendation": "Treat destination as an active threat. Avoid interacting with credentials or downloads.",
                "created_at": datetime.utcnow(),
            })

        elif pending_count > 0:
            # Signals only, not proof
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "module": self.name,
                "category": FindingCategory.REPUTATION.value,
                "title": f"Unverified Community Reports Submitted ({pending_count} Pending Review)",
                "description": (
                    f"Domain has {pending_count} community report(s) pending verification. "
                    "Community reports are early signals and do not represent verified compromise."
                ),
                "severity": Severity.LOW.value if pending_count < 3 else Severity.MEDIUM.value,
                "confidence": 0.40,
                "evidence": {
                    "pending_reports": pending_count,
                    "categories": categories,
                    "duplicate_reports_identified": duplicate_count,
                },
                "recommendation": "Review community reports for context while awaiting moderation review.",
                "created_at": datetime.utcnow(),
            })

        # Add domain entity and reporter relationship if corroborated
        domain_ent_id = f"domain:{hostname}"
        entities.append({
            "entity_id": domain_ent_id,
            "type": EntityType.DOMAIN.value,
            "value": hostname,
            "metadata": {
                "community_reports_count": len(reports),
                "corroborated_count": corroborated_count,
            },
            "first_seen": datetime.utcnow(),
            "last_seen": datetime.utcnow(),
            "scan_ids": [scan_id],
        })

        if corroborated_count > 0:
            for rep in valid_reports:
                if str(rep.get("status", "")).lower() in ("verified", "corroborated"):
                    rep_id = rep.get("report_id", str(uuid.uuid4()))
                    relationships.append({
                        "relationship_id": str(uuid.uuid4()),
                        "source_entity_id": domain_ent_id,
                        "target_entity_id": f"report:{rep_id}",
                        "type": RelationshipType.REPORTED_BY.value,
                        "scan_id": scan_id,
                        "confidence": 0.90,
                        "metadata": {
                            "category": rep.get("category"),
                            "status": rep.get("status"),
                            "reported_at": str(rep.get("created_at")),
                        },
                        "created_at": datetime.utcnow(),
                    })

        return {
            "total_reports": len(reports),
            "independent_reporters": independent_reporters_count,
            "duplicate_reports": duplicate_count,
            "status_breakdown": status_breakdown,
            "categories": categories,
            "corroborated_threat_signal": corroborated_count > 0,
        }

    async def _fetch_optional_external_intel(
        self, hostname: str, resolved_ip: Optional[str], scan_id: str, findings: list[dict]
    ) -> dict:
        """
        Query optional external providers (VirusTotal, AbuseIPDB, Shodan) safely.
        If no API key is set, returns status: 'not_configured'.
        If request fails, returns status: 'unavailable'.
        Never crashes the scan pipeline.
        """
        intel_results = {
            "virustotal": {"status": "not_configured", "data": None},
            "abuseipdb": {"status": "not_configured", "data": None},
            "shodan": {"status": "not_configured", "data": None},
        }

        # 1. VirusTotal Domain Check
        vt_key = self.settings.virustotal_api_key
        if vt_key:
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.get(
                        f"https://www.virustotal.com/api/v3/domains/{hostname}",
                        headers={"x-apikey": vt_key},
                    )
                    if resp.status_code == 200:
                        vt_data = resp.json().get("data", {}).get("attributes", {})
                        stats = vt_data.get("last_analysis_stats", {})
                        malicious = stats.get("malicious", 0)
                        suspicious = stats.get("suspicious", 0)
                        intel_results["virustotal"] = {
                            "status": "available",
                            "data": {
                                "malicious_count": malicious,
                                "suspicious_count": suspicious,
                                "harmless_count": stats.get("harmless", 0),
                                "reputation": vt_data.get("reputation", 0),
                            },
                        }
                        if malicious >= 3:
                            findings.append({
                                "finding_id": str(uuid.uuid4()),
                                "scan_id": scan_id,
                                "module": self.name,
                                "category": FindingCategory.REPUTATION.value,
                                "title": f"VirusTotal Detection: {malicious} Security Vendors Flagged Domain",
                                "description": f"VirusTotal threat intelligence aggregates {malicious} engine detections for {hostname}.",
                                "severity": Severity.HIGH.value if malicious < 10 else Severity.CRITICAL.value,
                                "confidence": 0.90,
                                "evidence": {"stats": stats},
                                "recommendation": "Block network traffic to this destination based on global vendor consensus.",
                                "created_at": datetime.utcnow(),
                            })
                    elif resp.status_code == 404:
                        intel_results["virustotal"] = {"status": "inconclusive", "data": "Domain unknown to VirusTotal"}
                    else:
                        intel_results["virustotal"] = {"status": "unavailable", "data": f"HTTP {resp.status_code}"}
            except Exception as e:
                logger.warning("VirusTotal intelligence check failed: %s", e)
                intel_results["virustotal"] = {"status": "unavailable", "data": str(e)}

        # 2. AbuseIPDB IP Check (if IP available)
        abuse_key = self.settings.abuseipdb_api_key
        if abuse_key and resolved_ip:
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.get(
                        "https://api.abuseipdb.com/api/v2/check",
                        params={"ipAddress": resolved_ip, "maxAgeInDays": "90"},
                        headers={"Key": abuse_key, "Accept": "application/json"},
                    )
                    if resp.status_code == 200:
                        abuse_data = resp.json().get("data", {})
                        score = abuse_data.get("abuseConfidenceScore", 0)
                        intel_results["abuseipdb"] = {
                            "status": "available",
                            "data": {
                                "ip": resolved_ip,
                                "abuse_confidence_score": score,
                                "total_reports": abuse_data.get("totalReports", 0),
                                "country_code": abuse_data.get("countryCode"),
                                "isp": abuse_data.get("isp"),
                            },
                        }
                        if score >= 50:
                            findings.append({
                                "finding_id": str(uuid.uuid4()),
                                "scan_id": scan_id,
                                "module": self.name,
                                "category": FindingCategory.INFRASTRUCTURE.value,
                                "title": f"AbuseIPDB Flagged Hosting IP ({score}% Abuse Confidence)",
                                "description": f"Resolved hosting IP {resolved_ip} has recorded abuse history with {score}% confidence score.",
                                "severity": Severity.HIGH.value if score >= 80 else Severity.MEDIUM.value,
                                "confidence": score / 100.0,
                                "evidence": {"ip": resolved_ip, "score": score},
                                "recommendation": "Inspect server IP reputation and related hosted sites.",
                                "created_at": datetime.utcnow(),
                            })
                    else:
                        intel_results["abuseipdb"] = {"status": "unavailable", "data": f"HTTP {resp.status_code}"}
            except Exception as e:
                logger.warning("AbuseIPDB intelligence check failed: %s", e)
                intel_results["abuseipdb"] = {"status": "unavailable", "data": str(e)}

        # 3. Shodan Host Check (if IP available)
        shodan_key = self.settings.shodan_api_key
        if shodan_key and resolved_ip:
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.get(
                        f"https://api.shodan.io/shodan/host/{resolved_ip}",
                        params={"key": shodan_key},
                    )
                    if resp.status_code == 200:
                        sh_data = resp.json()
                        ports = sh_data.get("ports", [])
                        intel_results["shodan"] = {
                            "status": "available",
                            "data": {
                                "ports": ports,
                                "org": sh_data.get("org"),
                                "os": sh_data.get("os"),
                                "vulns": list(sh_data.get("vulns", {}).keys()),
                            },
                        }
                    elif resp.status_code == 404:
                        intel_results["shodan"] = {"status": "inconclusive", "data": "No open ports indexed"}
                    else:
                        intel_results["shodan"] = {"status": "unavailable", "data": f"HTTP {resp.status_code}"}
            except Exception as e:
                logger.warning("Shodan intelligence check failed: %s", e)
                intel_results["shodan"] = {"status": "unavailable", "data": str(e)}

        return intel_results
