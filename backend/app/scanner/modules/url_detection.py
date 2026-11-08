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

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "work", "click",
    "loan", "fit", "rest", "country", "kim", "science", "gdn", "mom",
    "surf", "racing", "date", "faith", "review", "party", "accountant",
}

TARGET_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "facebook",
    "instagram", "netflix", "chase", "wellsfargo", "bankofamerica",
    "binance", "coinbase", "twitter", "dropbox", "github", "linkedin",
    "whatsapp", "outlook", "citibank", "barclays", "steam",
]

PHISHING_KEYWORDS = {
    "login", "signin", "verify", "verification", "account", "secure",
    "banking", "update", "wallet", "confirm", "security", "recovery",
    "support", "billing", "authenticate", "portal", "checkpoint",
}


def compute_entropy(text: str) -> float:
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in prob)


def levenshtein_distance(s1: str, s2: str) -> int:
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


def _add_finding(findings: list, scan_id: str, title: str, desc: str, severity: Severity, conf: float, evidence: dict, rec: str, cat: FindingCategory = FindingCategory.URL_ANALYSIS):
    findings.append({
        "finding_id": str(uuid.uuid4()), "scan_id": scan_id, "module": "url_detection",
        "category": cat.value if hasattr(cat, "value") else cat,
        "title": title, "description": desc,
        "severity": severity.value if hasattr(severity, "value") else severity,
        "confidence": conf, "evidence": evidence, "recommendation": rec,
        "created_at": datetime.utcnow(),
    })


def _add_dns_node(entities: list, relationships: list, scan_id: str, source_id: str, ent_type: EntityType, val: str, rel_type: RelationshipType, meta: dict):
    e_id = str(uuid.uuid4())
    now = datetime.utcnow()
    entities.append({"entity_id": e_id, "type": ent_type.value, "value": val, "metadata": meta, "first_seen": now, "last_seen": now, "scan_ids": [scan_id]})
    relationships.append({"relationship_id": str(uuid.uuid4()), "source_entity_id": source_id, "target_entity_id": e_id, "type": rel_type.value, "scan_id": scan_id, "confidence": 1.0, "metadata": meta, "created_at": now})


class UrlDetectionModule(ModuleInterface):
    name = "url_detection"
    description = "URL lexical heuristics, brand typosquatting, homoglyph detection, and DNS analysis"
    version = "1.0.0"

    async def execute(self, target_url: str, hostname: str, scan_id: str, **kwargs) -> dict:
        logger.info("Executing URL detection for %s (scan %s)", hostname, scan_id)
        findings, entities, relationships = [], [], []
        parsed = urlparse(target_url)
        path, query, lower_host = parsed.path or "", parsed.query or "", hostname.lower()

        url_entity_id, domain_entity_id = str(uuid.uuid4()), str(uuid.uuid4())
        now = datetime.utcnow()
        entities.append({"entity_id": url_entity_id, "type": EntityType.URL.value, "value": target_url, "metadata": {"scheme": parsed.scheme, "path": path}, "first_seen": now, "last_seen": now, "scan_ids": [scan_id]})
        entities.append({"entity_id": domain_entity_id, "type": EntityType.DOMAIN.value, "value": hostname, "metadata": {"hostname": hostname}, "first_seen": now, "last_seen": now, "scan_ids": [scan_id]})
        relationships.append({"relationship_id": str(uuid.uuid4()), "source_entity_id": url_entity_id, "target_entity_id": domain_entity_id, "type": RelationshipType.RESOLVES_TO.value, "scan_id": scan_id, "confidence": 1.0, "metadata": {"relation": "url_to_domain"}, "created_at": now})

        lexical_data = self._analyze_lexical(target_url, lower_host, path, query, scan_id, findings)
        typo_data = self._analyze_typosquatting(lower_host, scan_id, findings)
        dns_data = await asyncio.to_thread(self._resolve_dns, lower_host, scan_id, domain_entity_id, entities, relationships, findings)

        return {
            "data": {"target_url": target_url, "hostname": hostname, "lexical_analysis": lexical_data, "typosquatting_analysis": typo_data, "dns_analysis": dns_data},
            "findings": findings, "entities": entities, "relationships": relationships,
        }

    def _analyze_lexical(self, target_url: str, hostname: str, path: str, query: str, scan_id: str, findings: list) -> dict:
        entropy = compute_entropy(hostname)
        dot_count, hyphen_count = hostname.count("."), hostname.count("-")
        has_at_symbol = "@" in target_url
        is_ip_host = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname))

        parts = hostname.split(".")
        tld = parts[-1] if len(parts) > 1 else ""
        is_suspicious_tld = tld in SUSPICIOUS_TLDS
        found_keywords = [kw for kw in PHISHING_KEYWORDS if kw in path.lower() or kw in hostname]

        if is_ip_host:
            _add_finding(findings, scan_id, "Raw IP Address Used as Hostname", f"URL uses raw IP '{hostname}' instead of a domain name, a hallmark of malicious campaigns.", Severity.HIGH, 0.95, {"hostname": hostname, "target_url": target_url}, "Avoid interacting with services using raw IP addresses for consumer-facing portals.")
        if has_at_symbol:
            _add_finding(findings, scan_id, "Embedded '@' Symbol in URL", "The URL contains an '@' symbol, which can mislead users regarding the actual destination host.", Severity.HIGH, 0.90, {"target_url": target_url}, "Treat URLs containing '@' symbols as suspicious phishing or obfuscation attempts.")
        if entropy > 3.8 and len(hostname) > 12:
            _add_finding(findings, scan_id, "High Entropy Hostname (Possible DGA)", f"The hostname exhibits high Shannon entropy ({entropy:.2f}), indicative of algorithmically generated domains.", Severity.MEDIUM, 0.75, {"entropy": round(entropy, 2), "hostname": hostname}, "Investigate domain creation source and associated DNS reputation.")
        if dot_count > 3:
            _add_finding(findings, scan_id, "Excessive Subdomain Nesting", f"The domain contains {dot_count} dots, suggesting deep nesting often used to hide the true apex domain.", Severity.LOW, 0.70, {"dot_count": dot_count, "hostname": hostname}, "Verify whether the apex domain matches the expected service provider.")
        if is_suspicious_tld:
            _add_finding(findings, scan_id, f"High-Abuse Top-Level Domain (.{tld})", f"The TLD '.{tld}' has an elevated statistical incidence of phishing and abuse.", Severity.MEDIUM, 0.65, {"tld": tld, "hostname": hostname}, "Exercise caution before inputting credentials on domains under high-abuse TLDs.")
        if found_keywords:
            _add_finding(findings, scan_id, "Phishing-Related Keywords Detected", f"URL contains keywords commonly targeted in credential harvesting: {', '.join(found_keywords)}", Severity.MEDIUM, 0.60, {"keywords": found_keywords, "url": target_url}, "Ensure domain matches genuine organization before supplying account credentials.", FindingCategory.PHISHING_INDICATOR)

        return {"entropy": round(entropy, 3), "dot_count": dot_count, "hyphen_count": hyphen_count, "is_ip_host": is_ip_host, "tld": tld, "is_suspicious_tld": is_suspicious_tld, "detected_keywords": found_keywords}

    def _analyze_typosquatting(self, hostname: str, scan_id: str, findings: list) -> dict:
        is_punycode = "xn--" in hostname
        if is_punycode:
            _add_finding(findings, scan_id, "Punycode / Internationalized Domain Detected", f"Hostname '{hostname}' uses Punycode encoding, a common vector for visual homograph spoofing.", Severity.HIGH, 0.85, {"hostname": hostname}, "Inspect decoded internationalized representation for character substitutions.", FindingCategory.PHISHING_INDICATOR)

        parts = hostname.split(".")
        main_label = parts[0] if len(parts) <= 2 else parts[-2]
        tokens = list(set([main_label] + main_label.split("-")))
        matched_brand, min_dist = None, 999

        for brand in TARGET_BRANDS:
            if hostname == f"{brand}.com" or hostname.endswith(f".{brand}.com"):
                continue
            for token in tokens:
                dist = levenshtein_distance(token, brand)
                if dist in (1, 2) and dist < min_dist:
                    min_dist, matched_brand = dist, brand
                elif brand in token and token != brand:
                    min_dist, matched_brand = 0, brand

        if matched_brand:
            severity = Severity.CRITICAL if min_dist in (0, 1) else Severity.HIGH
            _add_finding(
                findings, scan_id, f"Brand Typosquatting Detected ({matched_brand})",
                f"Domain '{hostname}' closely mimics legitimate brand '{matched_brand}' (edit distance: {min_dist}).",
                severity, 0.90, {"target_brand": matched_brand, "edit_distance": min_dist, "domain_label": main_label, "hostname": hostname},
                f"Verify whether this domain is officially authorized by {matched_brand}.",
                FindingCategory.PHISHING_INDICATOR
            )

        return {"is_punycode": is_punycode, "targeted_brand": matched_brand, "edit_distance": min_dist if matched_brand else None}

    def _resolve_dns(self, hostname: str, scan_id: str, domain_entity_id: str, entities: list, relationships: list, findings: list) -> dict:
        resolver = dns.resolver.Resolver()
        resolver.timeout, resolver.lifetime = 3.0, 4.0
        records = {"a": [], "cname": [], "mx": [], "ns": []}

        try:
            for rdata in resolver.resolve(hostname, "A"):
                ip_str = rdata.to_text()
                records["a"].append(ip_str)
                _add_dns_node(entities, relationships, scan_id, domain_entity_id, EntityType.IP_ADDRESS, ip_str, RelationshipType.RESOLVES_TO, {"record_type": "A", "hostname": hostname})
        except Exception as e:
            logger.debug("DNS A query for %s failed: %s", hostname, e)

        try:
            for rdata in resolver.resolve(hostname, "NS"):
                ns_str = rdata.to_text().rstrip(".")
                records["ns"].append(ns_str)
                _add_dns_node(entities, relationships, scan_id, domain_entity_id, EntityType.NAMESERVER, ns_str, RelationshipType.USES_NAMESERVER, {"domain": hostname, "record_type": "NS"})
        except Exception as e:
            logger.debug("DNS NS query for %s failed: %s", hostname, e)

        try:
            for rdata in resolver.resolve(hostname, "MX"):
                records["mx"].append({"exchange": rdata.exchange.to_text().rstrip("."), "preference": rdata.preference})
        except Exception as e:
            logger.debug("DNS MX query for %s failed: %s", hostname, e)

        if not records["a"]:
            _add_finding(findings, scan_id, "No DNS A Records Resolved", f"Domain '{hostname}' did not resolve to any active IPv4 addresses.", Severity.LOW, 0.80, {"hostname": hostname}, "Check whether the domain is newly registered or inactive.", FindingCategory.DNS_ANALYSIS)

        return records
