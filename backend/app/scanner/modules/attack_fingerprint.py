"""
PHANTOM Attack Family Fingerprinting Module
Identifies potentially related phishing domains and infrastructure clusters
using observable technical indicators (shared IPs, certificates, nameservers, lexical patterns).
"""
import logging
from datetime import datetime
from typing import Optional
import uuid

from app.database import get_db
from app.models.entity import EntityType, RelationshipType
from app.models.finding import FindingCategory, Severity
from app.scanner.modules.url_detection import levenshtein_distance, TARGET_BRANDS
from app.scanner.orchestrator import ModuleInterface

logger = logging.getLogger("phantom.scanner.modules.attack_fingerprint")


class AttackFingerprintModule(ModuleInterface):
    """
    Attack Family Fingerprinting Module.
    Discovers potentially related domains based on observable technical infrastructure.
    """

    name = "attack_fingerprint"
    description = "Evidence-driven attack campaign and infrastructure clustering engine"
    version = "1.0.0"

    async def execute(self, target_url: str, hostname: str, scan_id: str, **kwargs) -> dict:
        """
        Execute attack family fingerprinting analysis.
        """
        logger.info("Executing attack fingerprinting for %s (scan %s)", hostname, scan_id)

        findings = []
        entities = []
        relationships = []

        # 1. Extract target observables from current scan context
        current_indicators = self._extract_current_indicators(target_url, hostname, kwargs)

        # 2. Query historical infrastructure from database for correlation
        historical_pool = await self._fetch_historical_infrastructure(hostname)

        # 3. Correlate indicators and compute evidence-driven associations
        clusters = self._cluster_indicators(
            hostname=hostname,
            indicators=current_indicators,
            historical_pool=historical_pool,
            scan_id=scan_id,
            findings=findings,
            entities=entities,
            relationships=relationships,
        )

        data = {
            "hostname": hostname,
            "target_indicators": current_indicators,
            "associated_clusters_count": len(clusters),
            "clusters": clusters,
        }

        return {
            "data": data,
            "findings": findings,
            "entities": entities,
            "relationships": relationships,
        }

    def _extract_current_indicators(self, target_url: str, hostname: str, kwargs: dict) -> dict:
        """Extract all observable indicators from current execution context."""
        indicators = {
            "hostname": hostname,
            "ips": set(),
            "nameservers": set(),
            "cert_sha256": None,
            "cert_issuer": None,
            "target_brands": set(),
            "redirect_destination": None,
        }

        # Identify brand keywords in hostname
        for brand in TARGET_BRANDS:
            if brand in hostname.lower():
                indicators["target_brands"].add(brand)

        # Look in kwargs for entities
        for ent in kwargs.get("entities", []):
            etype = ent.get("type") if isinstance(ent, dict) else getattr(ent, "type", None)
            evalue = ent.get("value") if isinstance(ent, dict) else getattr(ent, "value", None)
            if not evalue:
                continue

            if etype in (EntityType.IP_ADDRESS, "ip_address"):
                indicators["ips"].add(evalue)
            elif etype in (EntityType.NAMESERVER, "nameserver"):
                indicators["nameservers"].add(evalue)
            elif etype in (EntityType.CERTIFICATE, "certificate"):
                meta = ent.get("metadata", {}) if isinstance(ent, dict) else getattr(ent, "metadata", {})
                indicators["cert_sha256"] = meta.get("sha256")
                indicators["cert_issuer"] = meta.get("issuer")

        # Convert sets to lists for JSON serialization
        indicators["ips"] = list(indicators["ips"])
        indicators["nameservers"] = list(indicators["nameservers"])
        indicators["target_brands"] = list(indicators["target_brands"])
        return indicators

    async def _fetch_historical_infrastructure(self, current_hostname: str) -> list[dict]:
        """Fetch previously observed domains and infrastructure from MongoDB."""
        try:
            db = get_db()
            # Find entities of other domains
            domain_cursor = db.entities.find(
                {"type": "domain", "value": {"$ne": current_hostname}},
                {"_id": 0},
            ).limit(200)
            domains = await domain_cursor.to_list(length=200)

            # Find relationships for these domains
            pool = []
            for d in domains:
                dom_name = d["value"]
                # Fetch resolved IPs or certs for this domain
                dom_rels = await db.relationships.find(
                    {"$or": [{"source_entity_id": f"domain:{dom_name}"}, {"source_entity_id": dom_name}]},
                    {"_id": 0},
                ).limit(50).to_list(length=50)

                pool.append({
                    "domain": dom_name,
                    "metadata": d.get("metadata", {}),
                    "relationships": dom_rels,
                })
            return pool
        except Exception as e:
            logger.warning("Could not fetch historical infrastructure for fingerprinting: %s", e)
            return []

    def _cluster_indicators(
        self,
        hostname: str,
        indicators: dict,
        historical_pool: list[dict],
        scan_id: str,
        findings: list[dict],
        entities: list[dict],
        relationships: list[dict],
    ) -> list[dict]:
        """
        Calculates evidence-backed association scores with historical domains.
        Applies strict, defensible terminology.
        """
        clusters = []
        source_id = f"domain:{hostname}"

        curr_ips = set(indicators.get("ips", []))
        curr_brands = set(indicators.get("target_brands", []))
        curr_cert = indicators.get("cert_sha256")

        for item in historical_pool:
            other_domain = item["domain"]
            other_rels = item.get("relationships", [])

            # Extract other domain indicators from relationships
            other_ips = set()
            other_certs = set()
            for r in other_rels:
                rtype = r.get("type")
                target = r.get("target_entity_id", "")
                if rtype in ("resolves_to", RelationshipType.RESOLVES_TO):
                    other_ips.add(target.replace("ip:", ""))
                elif rtype in ("has_certificate", RelationshipType.HAS_CERTIFICATE):
                    other_certs.add(target.replace("cert:", ""))

            # Calculate match factors
            matching_factors = []
            confidence_score = 0.0

            # 1. Shared IP Address
            shared_ips = list(curr_ips.intersection(other_ips))
            if shared_ips:
                matching_factors.append(f"Shared IP address ({', '.join(shared_ips)})")
                confidence_score += 0.40

            # 2. Shared Certificate
            if curr_cert and curr_cert in other_certs:
                matching_factors.append("Identical TLS Certificate SHA-256 fingerprint")
                confidence_score += 0.50

            # 3. Brand Typosquatting / Pattern alignment
            other_brands = {b for b in TARGET_BRANDS if b in other_domain.lower()}
            shared_brand = curr_brands.intersection(other_brands)
            if shared_brand:
                matching_factors.append(f"Impersonates identical brand ({', '.join(shared_brand)})")
                confidence_score += 0.25

            # 4. Lexical distance on domain strings
            dist = levenshtein_distance(hostname, other_domain)
            if dist <= 3 and len(hostname) > 6:
                matching_factors.append(f"High domain lexical similarity (edit distance: {dist})")
                confidence_score += 0.30

            # Threshold for genuine relationship (requires non-trivial evidence)
            if matching_factors and confidence_score >= 0.40:
                final_confidence = min(0.95, round(confidence_score, 2))
                explanation = (
                    f"Domain {hostname} shares observable infrastructure ({'; '.join(matching_factors)}) "
                    f"with previously analyzed domain {other_domain}."
                )

                cluster_entry = {
                    "related_domain": other_domain,
                    "confidence": final_confidence,
                    "classification": "Shared observable infrastructure",
                    "supporting_evidence": matching_factors,
                    "explanation": explanation,
                }
                clusters.append(cluster_entry)

                target_id = f"domain:{other_domain}"

                # Ensure related domain entity exists
                entities.append({
                    "entity_id": target_id,
                    "type": EntityType.DOMAIN.value,
                    "value": other_domain,
                    "metadata": {"discovered_via_fingerprint": True},
                    "first_seen": datetime.utcnow(),
                    "last_seen": datetime.utcnow(),
                    "scan_ids": [scan_id],
                })

                # Create structured relationship
                relationships.append({
                    "relationship_id": str(uuid.uuid4()),
                    "source_entity_id": source_id,
                    "target_entity_id": target_id,
                    "type": RelationshipType.POTENTIALLY_RELATED_TO.value,
                    "scan_id": scan_id,
                    "confidence": final_confidence,
                    "metadata": {
                        "classification": "Potentially related domains",
                        "supporting_evidence": matching_factors,
                        "evidence_source": "Technical indicator and lexical correlation",
                        "explanation": explanation,
                        "timestamp": datetime.utcnow().isoformat(),
                    },
                    "created_at": datetime.utcnow(),
                })

        # Generate finding if strong cluster detected
        strong_clusters = [c for c in clusters if c["confidence"] >= 0.65]
        if strong_clusters:
            related_names = [c["related_domain"] for c in strong_clusters[:3]]
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "module": self.name,
                "category": FindingCategory.INFRASTRUCTURE.value,
                "title": f"Attack Fingerprinting: Shared Observable Infrastructure ({len(strong_clusters)} Related Domains)",
                "description": (
                    f"Evidence-based analysis identified {len(strong_clusters)} potentially related domain(s) "
                    f"({', '.join(related_names)}) exhibiting shared technical indicators (IPs, certificates, or lexical patterns)."
                ),
                "severity": Severity.HIGH.value if len(strong_clusters) >= 2 else Severity.MEDIUM.value,
                "confidence": max(c["confidence"] for c in strong_clusters),
                "evidence": {
                    "cluster_count": len(strong_clusters),
                    "clusters": strong_clusters,
                },
                "recommendation": "Investigate shared IP and certificate infrastructure for broader coordinated phishing campaigns.",
                "created_at": datetime.utcnow(),
            })

        return clusters
