"""
PHANTOM URL Threat Detection Module
Performs lexical analysis, brand typosquatting/homograph detection,
suspicious TLD classification, and DNS infrastructure resolution.
"""
import asyncio
import logging
import math
import re
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse
import uuid

import dns.resolver
from app.models.entity import EntityType, RelationshipType
from app.models.finding import FindingCategory, Severity
from app.scanner.orchestrator import ModuleInterface

logger = logging.getLogger("phantom.scanner.modules.url_detection")

# High-risk / frequently abused TLDs in phishing campaigns
SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "work", "click",
    "loan", "fit", "rest", "country", "kim", "science", "gdn", "mom",
    "surf", "racing", "date", "faith", "review", "party", "accountant",
}

# Top high-value targeted brand names for impersonation/typosquatting
TARGET_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "facebook",
    "instagram", "netflix", "chase", "wellsfargo", "bankofamerica",
    "binance", "coinbase", "twitter", "dropbox", "github", "linkedin",
    "whatsapp", "outlook", "citibank", "barclays", "steam",
]

# Keywords frequently found in phishing subdomains and paths
PHISHING_KEYWORDS = {
    "login", "signin", "verify", "verification", "account", "secure",
    "banking", "update", "wallet", "confirm", "security", "recovery",
    "support", "billing", "authenticate", "portal", "checkpoint",
}


def compute_entropy(text: str) -> float:
    """Calculate Shannon entropy for string randomness detection."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in prob)


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute the Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


class UrlDetectionModule(ModuleInterface):
    """
    URL Threat Detection module for lexical, homograph, and DNS analysis.
    """

    name = "url_detection"
    description = "URL lexical heuristics, brand typosquatting, homoglyph detection, and DNS analysis"
    version = "1.0.0"

    async def execute(self, target_url: str, hostname: str, scan_id: str, **kwargs) -> dict:
        logger.info("Executing URL detection for %s (scan %s)", hostname, scan_id)

        findings = []
        entities = []
        relationships = []

        parsed = urlparse(target_url)
        path = parsed.path or ""
        query = parsed.query or ""
        lower_host = hostname.lower()

        # 1. Base Entity: URL & Domain
        url_entity_id = str(uuid.uuid4())
        domain_entity_id = str(uuid.uuid4())

        entities.append({
            "entity_id": url_entity_id,
            "type": EntityType.URL.value,
            "value": target_url,
            "metadata": {"scheme": parsed.scheme, "path": path},
            "first_seen": datetime.utcnow(),
            "last_seen": datetime.utcnow(),
            "scan_ids": [scan_id],
        })

        entities.append({
            "entity_id": domain_entity_id,
            "type": EntityType.DOMAIN.value,
            "value": hostname,
            "metadata": {"hostname": hostname},
            "first_seen": datetime.utcnow(),
            "last_seen": datetime.utcnow(),
            "scan_ids": [scan_id],
        })

        relationships.append({
            "relationship_id": str(uuid.uuid4()),
            "source_entity_id": url_entity_id,
            "target_entity_id": domain_entity_id,
            "type": RelationshipType.RESOLVES_TO.value,
            "scan_id": scan_id,
            "confidence": 1.0,
            "metadata": {"relation": "url_to_domain"},
            "created_at": datetime.utcnow(),
        })

        # 2. Lexical & Structural Heuristics
        lexical_data = self._analyze_lexical(target_url, lower_host, path, query, scan_id, findings)

        # 3. Homograph & Typosquatting Analysis
        typo_data = self._analyze_typosquatting(lower_host, scan_id, findings)

        # 4. DNS Resolution Analysis
        dns_data = await asyncio.to_thread(self._resolve_dns, lower_host, scan_id, domain_entity_id, entities, relationships, findings)

        data = {
            "target_url": target_url,
            "hostname": hostname,
            "lexical_analysis": lexical_data,
            "typosquatting_analysis": typo_data,
            "dns_analysis": dns_data,
        }

        return {
            "data": data,
            "findings": findings,
            "entities": entities,
            "relationships": relationships,
        }

    def _analyze_lexical(self, target_url: str, hostname: str, path: str, query: str, scan_id: str, findings: list) -> dict:
        """Evaluate structural and lexical risk indicators."""
        entropy = compute_entropy(hostname)
        dot_count = hostname.count(".")
        hyphen_count = hostname.count("-")
        has_at_symbol = "@" in target_url
        is_ip_host = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname))

        # Check TLD
        parts = hostname.split(".")
        tld = parts[-1] if len(parts) > 1 else ""
        is_suspicious_tld = tld in SUSPICIOUS_TLDS

        # Check Phishing Keywords in subdomain or path
        found_keywords = [kw for kw in PHISHING_KEYWORDS if kw in path.lower() or kw in hostname]

        # Finding: IP Address Hostname
        if is_ip_host:
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "module": self.name,
                "category": FindingCategory.URL_ANALYSIS.value,
                "title": "Raw IP Address Used as Hostname",
                "description": f"URL uses raw IP '{hostname}' instead of a domain name, a hallmark of malicious campaigns.",
                "severity": Severity.HIGH.value,
                "confidence": 0.95,
                "evidence": {"hostname": hostname, "target_url": target_url},
                "recommendation": "Avoid interacting with services using raw IP addresses for consumer-facing portals.",
                "created_at": datetime.utcnow(),
            })

        # Finding: Embedded @ Symbol (Credential / URL Injection)
        if has_at_symbol:
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "module": self.name,
                "category": FindingCategory.URL_ANALYSIS.value,
                "title": "Embedded '@' Symbol in URL",
                "description": "The URL contains an '@' symbol, which can mislead users regarding the actual destination host.",
                "severity": Severity.HIGH.value,
                "confidence": 0.90,
                "evidence": {"target_url": target_url},
                "recommendation": "Treat URLs containing '@' symbols as suspicious phishing or obfuscation attempts.",
                "created_at": datetime.utcnow(),
            })

        # Finding: High Entropy Hostname (DGA / Obfuscation)
        if entropy > 3.8 and len(hostname) > 12:
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "module": self.name,
                "category": FindingCategory.URL_ANALYSIS.value,
                "title": "High Entropy Hostname (Possible DGA)",
                "description": f"The hostname exhibits high Shannon entropy ({entropy:.2f}), indicative of algorithmically generated domains.",
                "severity": Severity.MEDIUM.value,
                "confidence": 0.75,
                "evidence": {"entropy": round(entropy, 2), "hostname": hostname},
                "recommendation": "Investigate domain creation source and associated DNS reputation.",
                "created_at": datetime.utcnow(),
            })

        # Finding: Excessive Subdomains
        if dot_count > 3:
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "module": self.name,
                "category": FindingCategory.URL_ANALYSIS.value,
                "title": "Excessive Subdomain Nesting",
                "description": f"The domain contains {dot_count} dots, suggesting deep nesting often used to hide the true apex domain.",
                "severity": Severity.LOW.value,
                "confidence": 0.70,
                "evidence": {"dot_count": dot_count, "hostname": hostname},
                "recommendation": "Verify whether the apex domain matches the expected service provider.",
                "created_at": datetime.utcnow(),
            })

        # Finding: Suspicious TLD
        if is_suspicious_tld:
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "module": self.name,
                "category": FindingCategory.URL_ANALYSIS.value,
                "title": f"High-Abuse Top-Level Domain (.{tld})",
                "description": f"The TLD '.{tld}' has an elevated statistical incidence of phishing and abuse.",
                "severity": Severity.MEDIUM.value,
                "confidence": 0.65,
                "evidence": {"tld": tld, "hostname": hostname},
                "recommendation": "Exercise caution before inputting credentials on domains under high-abuse TLDs.",
                "created_at": datetime.utcnow(),
            })

        # Finding: Phishing Keywords in Path or Host
        if found_keywords:
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "module": self.name,
                "category": FindingCategory.PHISHING_INDICATOR.value,
                "title": "Phishing-Related Keywords Detected",
                "description": f"URL contains keywords commonly targeted in credential harvesting: {', '.join(found_keywords)}",
                "severity": Severity.MEDIUM.value,
                "confidence": 0.60,
                "evidence": {"keywords": found_keywords, "url": target_url},
                "recommendation": "Ensure domain matches genuine organization before supplying account credentials.",
                "created_at": datetime.utcnow(),
            })

        return {
            "entropy": round(entropy, 3),
            "dot_count": dot_count,
            "hyphen_count": hyphen_count,
            "is_ip_host": is_ip_host,
            "tld": tld,
            "is_suspicious_tld": is_suspicious_tld,
            "detected_keywords": found_keywords,
        }

    def _analyze_typosquatting(self, hostname: str, scan_id: str, findings: list) -> dict:
        """Detect Punycode / IDN homograph and brand typosquatting."""
        # 1. Punycode check
        is_punycode = "xn--" in hostname
        if is_punycode:
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "module": self.name,
                "category": FindingCategory.PHISHING_INDICATOR.value,
                "title": "Punycode / Internationalized Domain Detected",
                "description": f"Hostname '{hostname}' uses Punycode encoding, a common vector for visual homograph spoofing.",
                "severity": Severity.HIGH.value,
                "confidence": 0.85,
                "evidence": {"hostname": hostname},
                "recommendation": "Inspect decoded internationalized representation for character substitutions.",
                "created_at": datetime.utcnow(),
            })

        # 2. Typosquatting against popular brands
        # Extract the primary label (e.g. 'paypal-update' from 'paypal-update.com')
        parts = hostname.split(".")
        main_label = parts[0] if len(parts) <= 2 else parts[-2]

        matched_brand = None
        min_dist = 999

        for brand in TARGET_BRANDS:
            # Skip if domain is exact legitimate brand apex (e.g. google.com or paypal.com)
            if hostname == f"{brand}.com" or hostname.endswith(f".{brand}.com"):
                continue

            dist = levenshtein_distance(main_label, brand)
            if dist in (1, 2) and dist < min_dist:
                min_dist = dist
                matched_brand = brand
            elif brand in main_label and main_label != brand:
                matched_brand = brand
                min_dist = 0

        if matched_brand:
            severity = Severity.CRITICAL.value if min_dist in (0, 1) else Severity.HIGH.value
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "module": self.name,
                "category": FindingCategory.PHISHING_INDICATOR.value,
                "title": f"Brand Typosquatting Detected ({matched_brand})",
                "description": f"Domain '{hostname}' closely mimics legitimate brand '{matched_brand}' (edit distance: {min_dist}).",
                "severity": severity,
                "confidence": 0.90,
                "evidence": {
                    "target_brand": matched_brand,
                    "edit_distance": min_dist,
                    "domain_label": main_label,
                    "hostname": hostname,
                },
                "recommendation": f"Verify whether this domain is officially authorized by {matched_brand}.",
                "created_at": datetime.utcnow(),
            })

        return {
            "is_punycode": is_punycode,
            "targeted_brand": matched_brand,
            "edit_distance": min_dist if matched_brand else None,
        }

    def _resolve_dns(self, hostname: str, scan_id: str, domain_entity_id: str, entities: list, relationships: list, findings: list) -> dict:
        """Resolve DNS records and construct network graph entities."""
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 4.0

        records = {"a": [], "cname": [], "mx": [], "ns": []}

        # Query A records
        try:
            a_answers = resolver.resolve(hostname, "A")
            for rdata in a_answers:
                ip_str = rdata.to_text()
                records["a"].append(ip_str)

                # Entity & Relationship for IP
                ip_entity_id = str(uuid.uuid4())
                entities.append({
                    "entity_id": ip_entity_id,
                    "type": EntityType.IP_ADDRESS.value,
                    "value": ip_str,
                    "metadata": {"record_type": "A", "hostname": hostname},
                    "first_seen": datetime.utcnow(),
                    "last_seen": datetime.utcnow(),
                    "scan_ids": [scan_id],
                })
                relationships.append({
                    "relationship_id": str(uuid.uuid4()),
                    "source_entity_id": domain_entity_id,
                    "target_entity_id": ip_entity_id,
                    "type": RelationshipType.RESOLVES_TO.value,
                    "scan_id": scan_id,
                    "confidence": 1.0,
                    "metadata": {"record_type": "A"},
                    "created_at": datetime.utcnow(),
                })
        except Exception as e:
            logger.debug("DNS A query for %s failed: %s", hostname, e)

        # Query NS records
        try:
            ns_answers = resolver.resolve(hostname, "NS")
            for rdata in ns_answers:
                ns_str = rdata.to_text().rstrip(".")
                records["ns"].append(ns_str)

                # Entity & Relationship for Nameserver
                ns_entity_id = str(uuid.uuid4())
                entities.append({
                    "entity_id": ns_entity_id,
                    "type": EntityType.NAMESERVER.value,
                    "value": ns_str,
                    "metadata": {"domain": hostname},
                    "first_seen": datetime.utcnow(),
                    "last_seen": datetime.utcnow(),
                    "scan_ids": [scan_id],
                })
                relationships.append({
                    "relationship_id": str(uuid.uuid4()),
                    "source_entity_id": domain_entity_id,
                    "target_entity_id": ns_entity_id,
                    "type": RelationshipType.USES_NAMESERVER.value,
                    "scan_id": scan_id,
                    "confidence": 1.0,
                    "metadata": {"record_type": "NS"},
                    "created_at": datetime.utcnow(),
                })
        except Exception as e:
            logger.debug("DNS NS query for %s failed: %s", hostname, e)

        # Query MX records
        try:
            mx_answers = resolver.resolve(hostname, "MX")
            for rdata in mx_answers:
                records["mx"].append({
                    "exchange": rdata.exchange.to_text().rstrip("."),
                    "preference": rdata.preference,
                })
        except Exception as e:
            logger.debug("DNS MX query for %s failed: %s", hostname, e)

        # Finding if domain has no A records
        if not records["a"]:
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "module": self.name,
                "category": FindingCategory.DNS_ANALYSIS.value,
                "title": "No DNS A Records Resolved",
                "description": f"Domain '{hostname}' did not resolve to any active IPv4 addresses.",
                "severity": Severity.LOW.value,
                "confidence": 0.80,
                "evidence": {"hostname": hostname},
                "recommendation": "Check whether the domain is newly registered or inactive.",
                "created_at": datetime.utcnow(),
            })

        return records
