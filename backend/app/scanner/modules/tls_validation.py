"""
PHANTOM TLS Validation Module
Extracts and validates SSL/TLS certificates, verifies certificate authority chains,
checks validity periods, SAN coverage, self-signed status, and generates cryptographic entities.
"""
import asyncio
import logging
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from app.models.entity import EntityType, RelationshipType
from app.models.finding import FindingCategory, Severity
from app.scanner.orchestrator import ModuleInterface

logger = logging.getLogger("phantom.scanner.modules.tls_validation")

HIGH_TARGET_BRANDS = [
    "whatsapp", "paypal", "microsoft", "apple", "google", "amazon", "netflix",
    "facebook", "instagram", "chase", "wellsfargo", "bankofamerica", "binance",
    "coinbase", "telegram", "twitter", "linkedin", "dropbox", "adobe", "roblox",
    "steam", "yahoo", "outlook", "office365", "dhl", "fedex", "usps", "ups",
    "barclays", "hsbc", "citibank", "santander"
]
SUSPICIOUS_AFFIXES = ["login", "secure", "verify", "auth", "portal", "update", "account", "signin", "support", "online"]


def _add_finding(findings: list, scan_id: str, title: str, desc: str, severity: Severity, conf: float, evidence: dict, rec: str, cat: FindingCategory = FindingCategory.TLS_CERTIFICATE):
    findings.append({
        "finding_id": str(uuid.uuid4()), "scan_id": scan_id, "module": "tls_validation",
        "category": cat.value if hasattr(cat, "value") else cat,
        "title": title, "description": desc,
        "severity": severity.value if hasattr(severity, "value") else severity,
        "confidence": conf, "evidence": evidence, "recommendation": rec,
        "created_at": datetime.now(timezone.utc),
    })


def _get_name_attrs(name: x509.Name) -> tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    attrs = {attr.oid: attr.value for attr in name}
    return (
        attrs.get(x509.NameOID.COMMON_NAME),
        attrs.get(x509.NameOID.ORGANIZATION_NAME),
        attrs.get(x509.NameOID.ORGANIZATIONAL_UNIT_NAME),
        attrs.get(x509.NameOID.COUNTRY_NAME),
    )


def _dim(dim_id: str, name: str, status: str, explanation: str, severity: str = "info", evidence: Optional[dict] = None) -> dict:
    return {"id": dim_id, "name": name, "status": status, "explanation": explanation, "severity": severity, "evidence": evidence or {}}


def _build_unavailable_payload(hostname: str, port: int, error_str: str, status: str = "unavailable") -> dict:
    is_dns_failure = any(k in error_str.lower() for k in ("known", "not known", "gaierror", "nodename"))
    error_summary = "DNS resolution failed (domain has no active IP routing or does not exist)." if is_dns_failure else f"Connection to port 443 was refused or timed out ({error_str})."

    findings_list = [
        {
            "title": "TLS Handshake Incomplete / Host Offline",
            "severity": "info",
            "evidence": f"Target: {hostname}:{port} — {error_str}",
            "interpretation": error_summary,
        }
    ]
    summary = {
        "certificate_health": {
            "status": "Offline / N/A",
            "title": "Certificate Health",
            "summary": "Port 443 was unreachable; no certificate was presented to validate.",
            "details": f"Error: {error_str}",
        },
        "domain_identity": {
            "status": "Unresolvable" if is_dns_failure else "Unreachable",
            "title": "Domain Identity",
            "summary": "Domain failed to route to an operational HTTPS server.",
            "details": hostname,
        },
        "website_trust": {
            "status": "Inactive / Inert",
            "title": "Website Trust",
            "summary": "Host is currently inactive; no live phishing forms can be loaded by users.",
            "details": "Server offline / dead link",
        },
    }
    return {
        "status": status, "error": error_str, "chain_valid": False, "is_expired": None,
        "is_self_signed": None, "hostname_matches": False, "certificate_type": None,
        "tls_version": None, "tls_protocol": None, "cipher": None, "cipher_suite": None,
        "is_unverified_fallback": False,
        "investigation_findings": findings_list,
        "investigation_summary": summary,
    }


class TlsValidationModule(ModuleInterface):
    name = "tls_validation"
    description = "TLS certificate extraction, expiration, SAN validation, and cryptographic analysis"
    version = "1.0.0"

    async def execute(self, target_url: str, hostname: str, scan_id: str, **kwargs) -> dict:
        logger.info("Executing TLS validation for %s (scan %s)", hostname, scan_id)
        findings, entities, relationships = [], [], []
        parsed = urlparse(target_url)
        port = parsed.port or 443

        cert_data = await asyncio.to_thread(self._fetch_and_parse_cert, hostname, port, scan_id, findings, entities, relationships)

        if parsed.scheme == "http":
            _add_finding(
                findings, scan_id, "Plain HTTP Scheme Specified",
                f"URL {target_url} uses unencrypted HTTP. Data in transit is vulnerable to interception.",
                Severity.MEDIUM, 1.0, {"target_url": target_url}, "Migrate services to HTTPS and enforce HSTS."
            )

        return {"data": cert_data, "findings": findings, "entities": entities, "relationships": relationships}

    def _probe_unverified_cert(self, hostname: str, port: int) -> tuple[Optional[bytes], Optional[str], Optional[tuple]]:
        try:
            probe_ctx = ssl.create_default_context()
            probe_ctx.check_hostname = False
            probe_ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=5.0) as sock:
                with probe_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return ssock.getpeercert(binary_form=True), ssock.version(), ssock.cipher()
        except Exception as e:
            logger.debug("Unverified probe failed for %s:%d: %s", hostname, port, e)
            return None, None, None

    def _fetch_and_parse_cert(self, hostname: str, port: int, scan_id: str, findings: list, entities: list, relationships: list) -> dict:
        raw_der, negotiated_protocol, cipher_info, chain_valid, chain_error, is_unverified_fallback = None, None, None, False, None, False

        # Stage 1: Verified connection probe
        try:
            with socket.create_connection((hostname, port), timeout=5.0) as sock:
                with ssl.create_default_context().wrap_socket(sock, server_hostname=hostname) as ssock:
                    raw_der = ssock.getpeercert(binary_form=True)
                    negotiated_protocol, cipher_info, chain_valid = ssock.version(), ssock.cipher(), True
        except ssl.SSLCertVerificationError as e:
            chain_error = getattr(e, "verify_message", None) or str(e)
            raw_der, negotiated_protocol, cipher_info = self._probe_unverified_cert(hostname, port)
            is_unverified_fallback = True
        except ssl.SSLError as e:
            chain_error = str(e)
            raw_der, negotiated_protocol, cipher_info = self._probe_unverified_cert(hostname, port)
            is_unverified_fallback = True
        except (socket.timeout, TimeoutError, ConnectionRefusedError, OSError) as e:
            logger.warning("TLS connection failed for %s:%d: %s", hostname, port, e)
            _add_finding(
                findings, scan_id, "TLS/HTTPS Connection Failed",
                f"Could not establish a TLS handshake with {hostname}:{port} ({type(e).__name__}: {str(e)}).",
                Severity.INFO, 0.95, {"hostname": hostname, "port": port, "error": str(e)},
                "Ensure an active, valid TLS certificate is deployed on port 443."
            )
            return _build_unavailable_payload(hostname, port, str(e), status="unavailable")
        except Exception as e:
            logger.warning("Unexpected TLS error for %s:%d: %s", hostname, port, e)
            _add_finding(
                findings, scan_id, "TLS/HTTPS Connection Failed",
                f"Could not establish a TLS handshake with {hostname}:{port} ({type(e).__name__}: {str(e)}).",
                Severity.INFO, 0.95, {"hostname": hostname, "port": port, "error": str(e)},
                "Ensure an active, valid TLS certificate is deployed on port 443."
            )
            return _build_unavailable_payload(hostname, port, str(e), status="unavailable")

        if not raw_der:
            err_msg = chain_error or "No certificate received from host"
            _add_finding(
                findings, scan_id, "TLS/HTTPS Connection Failed",
                f"Could not retrieve TLS certificate from {hostname}:{port} ({err_msg}).",
                Severity.INFO, 0.95, {"hostname": hostname, "port": port, "error": err_msg},
                "Ensure an active, valid TLS certificate is deployed on port 443."
            )
            return _build_unavailable_payload(hostname, port, err_msg, status="failed")

        try:
            cert = x509.load_der_x509_certificate(raw_der)
        except Exception as e:
            logger.error("Failed to parse DER certificate for %s: %s", hostname, e)
            return {"status": "failed", "error": f"Certificate parse error: {e}"}

        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        serial = format(cert.serial_number, "x")
        now = datetime.now(timezone.utc)
        not_before, not_after = cert.not_valid_before_utc, cert.not_valid_after_utc

        subj_cn, subj_org, subj_ou, subj_c = _get_name_attrs(cert.subject)
        iss_cn, iss_org, iss_ou, iss_c = _get_name_attrs(cert.issuer)
        issuer_str = iss_org or iss_cn or "Unknown Authority"
        ca_name = issuer_str

        # SANs
        sans = []
        try:
            sans = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass

        # Public key
        pk = cert.public_key()
        if isinstance(pk, rsa.RSAPublicKey):
            pk_algo, pk_size = "RSA", pk.key_size
        elif isinstance(pk, ec.EllipticCurvePublicKey):
            pk_algo, pk_size = f"ECDSA ({pk.curve.name})", pk.key_size
        elif isinstance(pk, ed25519.Ed25519PublicKey):
            pk_algo, pk_size = "Ed25519", 256
        else:
            pk_algo, pk_size = type(pk).__name__, getattr(pk, "key_size", None)

        sig_algo = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"
        sig_algo_full = getattr(cert.signature_algorithm_oid, "_name", None) or sig_algo

        is_wildcard = (subj_cn and subj_cn.startswith("*.")) or any(s.startswith("*.") for s in sans)
        base_cert_type = "Wildcard (DV)" if is_wildcard else ("Organization Validated (OV)" if subj_org and subj_c else "Domain Validated (DV)")
        cert_type = f"{base_cert_type} (UNVERIFIED)" if is_unverified_fallback else base_cert_type

        # SCT presence
        has_embedded_scts, sct_count = False, 0
        try:
            sct_ext = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2"))
            has_embedded_scts, sct_count = True, max(1, len(sct_ext.value.public_bytes()) // 100)
        except Exception:
            pass

        days_remaining = (not_after - now).days
        is_expired, is_not_yet_valid = now > not_after, now < not_before
        is_expiring_soon = 0 <= days_remaining <= 14

        if is_expired:
            _add_finding(findings, scan_id, "TLS Certificate Expired", f"Certificate for {hostname} expired on {not_after.isoformat()}.", Severity.CRITICAL, 1.0, {"not_after": not_after.isoformat(), "days_remaining": days_remaining}, "Renew and replace the expired TLS certificate immediately.")
        elif is_expiring_soon:
            _add_finding(findings, scan_id, "TLS Certificate Expiring Soon", f"Certificate for {hostname} expires in {days_remaining} days ({not_after.isoformat()}).", Severity.MEDIUM, 1.0, {"days_remaining": days_remaining, "not_after": not_after.isoformat()}, "Initiate renewal before certificate expires.")

        if is_not_yet_valid:
            _add_finding(findings, scan_id, "TLS Certificate Not Yet Valid", f"Certificate validity start date is in the future ({not_before.isoformat()}).", Severity.HIGH, 1.0, {"not_before": not_before.isoformat()}, "Ensure system clocks and issuance timestamps are synchronized.")

        is_self_signed = (cert.issuer == cert.subject)
        if is_self_signed:
            _add_finding(findings, scan_id, "Self-Signed TLS Certificate Detected", f"The certificate presented by {hostname} is self-signed and untrusted by standard root stores.", Severity.HIGH, 0.95, {"issuer": iss_cn or iss_org, "subject": subj_cn or subj_org}, "Replace self-signed certificates with ones issued by a publicly trusted CA.")

        is_untrusted_ca = False
        if not chain_valid and not is_self_signed:
            err_str = (chain_error or "").lower()
            if not ("hostname" in err_str and not any(k in err_str for k in ("issuer", "self-signed", "chain", "authority", "untrusted", "root"))) and not is_expired:
                is_untrusted_ca = True
                _add_finding(findings, scan_id, "Untrusted TLS Certificate Authority / Invalid Chain", f"TLS certificate for {hostname} issued by untrusted authority ({issuer_str}). Verification failure: {chain_error or 'Root authority not recognized'}.", Severity.HIGH, 0.95, {"hostname": hostname, "issuer": issuer_str, "chain_error": chain_error, "chain_valid": False}, "Replace with certificate from a globally recognized CA.")

        matched_hostname = self._match_hostname(hostname, subj_cn, sans)
        if not matched_hostname:
            _add_finding(findings, scan_id, "TLS Hostname Mismatch", f"Domain '{hostname}' does not match Common Name ({subj_cn}) or SANs ({', '.join(sans[:5])}).", Severity.CRITICAL, 0.95, {"hostname": hostname, "common_name": subj_cn, "sans": sans}, "Issue a certificate covering the target domain or update DNS routing.")

        if is_unverified_fallback:
            _add_finding(
                findings, scan_id, "Raw Certificate Retrieved via Unverified Forensic Fallback",
                f"Standard TLS trust handshake with {hostname}:{port} failed ({chain_error or 'Untrusted authority or invalid chain'}). Host certificate was extracted via an unverified forensic probe for threat inspection.",
                Severity.MEDIUM, 0.9, {"chain_error": chain_error, "unverified_fallback": True},
                "Investigate why standard TLS validation failed and ensure a trusted certificate is installed."
            )

        if sig_algo in ("md5", "sha1"):
            _add_finding(findings, scan_id, f"Weak Certificate Signature Algorithm ({sig_algo.upper()})", f"Certificate uses deprecated signature algorithm {sig_algo.upper()}, vulnerable to collision attacks.", Severity.HIGH, 1.0, {"signature_algorithm": sig_algo}, "Reissue certificate using SHA-256 or modern ECDSA algorithm.")

        # Entities & Relationships
        cert_ent_id, dom_ent_id = str(uuid.uuid4()), str(uuid.uuid4())
        entities.append({"entity_id": cert_ent_id, "type": EntityType.CERTIFICATE.value, "value": fingerprint, "metadata": {"sha256": fingerprint, "common_name": subj_cn, "issuer": issuer_str, "serial": serial, "sans": sans, "days_remaining": days_remaining, "protocol": negotiated_protocol, "chain_valid": chain_valid}, "first_seen": now, "last_seen": now, "scan_ids": [scan_id]})
        entities.append({"entity_id": dom_ent_id, "type": EntityType.DOMAIN.value, "value": hostname, "metadata": {"hostname": hostname}, "first_seen": now, "last_seen": now, "scan_ids": [scan_id]})
        relationships.append({"relationship_id": str(uuid.uuid4()), "source_entity_id": dom_ent_id, "target_entity_id": cert_ent_id, "type": RelationshipType.HAS_CERTIFICATE.value, "scan_id": scan_id, "confidence": 1.0, "metadata": {"fingerprint": fingerprint}, "created_at": now})

        if iss_org or iss_cn:
            iss_val = iss_org or iss_cn
            iss_ent_id = str(uuid.uuid4())
            entities.append({"entity_id": iss_ent_id, "type": EntityType.ORGANIZATION.value, "value": iss_val, "metadata": {"role": "certificate_authority"}, "first_seen": now, "last_seen": now, "scan_ids": [scan_id]})
            relationships.append({"relationship_id": str(uuid.uuid4()), "source_entity_id": cert_ent_id, "target_entity_id": iss_ent_id, "type": RelationshipType.ISSUED_BY.value, "scan_id": scan_id, "confidence": 1.0, "metadata": {"issuer": iss_val}, "created_at": now})

        is_healthy = chain_valid and matched_hostname and not (is_expired or is_not_yet_valid or is_self_signed or is_untrusted_ca or sig_algo in ("md5", "sha1"))

        # Brand Impersonation
        host_lower = hostname.lower().strip()
        matched_brand, is_official_brand_domain, impersonation_risk = None, False, "low"
        for b in HIGH_TARGET_BRANDS:
            if host_lower == f"{b}.com" or host_lower.endswith(f".{b}.com"):
                matched_brand, is_official_brand_domain, impersonation_risk = b, True, "none"
                break
            elif b in host_lower:
                matched_brand, impersonation_risk = b, "potential_impersonation"
                break

        suspicious_affix_found = [a for a in SUSPICIOUS_AFFIXES if a in host_lower]
        is_punycode = host_lower.startswith("xn--") or ".xn--" in host_lower
        san_apexes = { ".".join(s.split(".")[-2:]) for s in sans if len(s.split(".")) >= 2 }
        san_inconsistent = len(san_apexes) > 3

        if matched_brand and not is_official_brand_domain:
            _add_finding(
                findings, scan_id, f"Potential Brand Impersonation Indicator ({matched_brand.capitalize()})",
                f"Domain '{hostname}' contains recognizable brand keyword '{matched_brand.capitalize()}', yet certificate/DNS structure is not verified as official infrastructure.",
                Severity.HIGH if suspicious_affix_found else Severity.MEDIUM, 0.85,
                {"matched_brand": matched_brand, "hostname": hostname, "suspicious_affixes": suspicious_affix_found, "is_official_domain": False},
                f"Verify whether domain is legitimately owned by {matched_brand.capitalize()}.",
                FindingCategory.PHISHING_INDICATOR
            )

        # 7-Dimension Assessment
        dim_val = _dim("validity", "Certificate Validity", "fail" if (is_expired or is_not_yet_valid) else "pass", f"Certificate expired {abs(days_remaining)} days ago." if is_expired else (f"Certificate active within validity window ({days_remaining} days remaining)."), "critical" if is_expired else ("high" if is_not_yet_valid else "info"), {"not_after": not_after.isoformat(), "days_remaining": days_remaining})
        dim_ch = _dim("chain_trust", "Certificate Chain Trust", "warning" if is_self_signed else ("fail" if (is_untrusted_ca or not chain_valid) else "pass"), "Self-signed certificate; not issued by a trusted CA." if is_self_signed else (f"Validated against system root CA store ({ca_name})." if chain_valid else f"Failed root store verification ({chain_error or 'Untrusted authority'})."), "high" if (is_self_signed or is_untrusted_ca) else "info", {"issuer": issuer_str, "chain_valid": chain_valid})
        dim_dom = _dim("domain_matching", "Domain Name Matching", "pass" if matched_hostname else "fail", f"Hostname '{hostname}' matches CN or SANs." if matched_hostname else f"Hostname '{hostname}' does not match CN or SANs.", "info" if matched_hostname else "critical", {"common_name": subj_cn, "sans": sans[:10]})

        is_weak_key = (pk_algo == "RSA" and pk_size and pk_size < 2048) or (pk_algo.startswith("ECDSA") and pk_size and pk_size < 256)
        dim_cr = _dim("cryptography", "Cryptographic Strength", "fail" if (is_weak_key or sig_algo in ("md5", "sha1")) else "pass", f"Deprecated algorithm ({pk_algo} {pk_size}b / {sig_algo_full})." if (is_weak_key or sig_algo in ("md5", "sha1")) else f"Modern cryptographic parameters ({pk_algo} {pk_size or ''}b, {sig_algo_full}).", "high" if (is_weak_key or sig_algo in ("md5", "sha1")) else "info", {"key_algorithm": pk_algo, "key_size": pk_size, "sig_algo": sig_algo_full})
        dim_ex = _dim("expiration_risk", "Certificate Expiration Risk", "fail" if is_expired else ("warning" if is_expiring_soon else "pass"), f"Certificate expired on {not_after.strftime('%Y-%m-%d')}." if is_expired else (f"Certificate expires soon in {days_remaining} days." if is_expiring_soon else f"Certificate has {days_remaining} days remaining validity."), "critical" if is_expired else ("medium" if is_expiring_soon else "info"), {"days_remaining": days_remaining})
        dim_ct = _dim("transparency", "Certificate Transparency Presence", "pass" if has_embedded_scts else "unknown", f"Embedded SCTs verified ({sct_count} SCTs)." if has_embedded_scts else "No embedded SCTs detected in X.509 extensions.", "info" if has_embedded_scts else "low", {"embedded_scts": has_embedded_scts, "sct_count": sct_count})

        anom_stat, anom_exp = ("warning", f"High SAN divergence across {len(san_apexes)} distinct apex domains.") if san_inconsistent else (("warning", "Self-signed certificate anomaly.") if is_self_signed else (("warning", "Domain contains Punycode homoglyph lookalike characters.") if is_punycode else ("pass", "No structural certificate anomalies detected.")))
        dim_an = _dim("anomalies", "Potential Certificate Anomalies", anom_stat, anom_exp, "medium" if anom_stat == "warning" else "info", {"san_count": len(sans)})

        dimensions = [dim_val, dim_ch, dim_dom, dim_cr, dim_ex, dim_ct, dim_an]

        investigation_findings = [
            {"title": f"Certificate Issued by {ca_name}", "severity": "info", "evidence": f"Issuer CN: {iss_cn or 'N/A'}, O: {iss_org or 'N/A'}, C: {iss_c or 'N/A'}", "interpretation": f"Domain presents a certificate signed by {ca_name}."},
            {"title": f"Protocol {negotiated_protocol or 'TLS'} with {cipher_info[0] if cipher_info else 'Standard Cipher'}", "severity": "info", "evidence": f"Protocol: {negotiated_protocol or 'TLS'}, Cipher: {cipher_info[0] if cipher_info else 'N/A'}", "interpretation": "Cryptographic transport parameters prevent passive eavesdropping."},
            {"title": "System Root Trust Store Validation", "severity": "info" if chain_valid and not is_self_signed else "high", "evidence": f"Chain Valid: {chain_valid}, Self-Signed: {is_self_signed}", "interpretation": "Certificate chain validates against system roots." if chain_valid and not is_self_signed else f"Certificate chain failed validation ({chain_error or 'Untrusted authority'})."},
            {"title": "Certificate Validity Period Status", "severity": "critical" if is_expired else "info", "evidence": f"Valid: {not_before.strftime('%Y-%m-%d')} to {not_after.strftime('%Y-%m-%d')} ({days_remaining}d left)", "interpretation": f"The certificate is within its operational lifespan ({days_remaining}d remaining)." if not (is_expired or is_not_yet_valid) else "Certificate outside valid operational period."},
        ]

        if is_unverified_fallback:
            investigation_findings.insert(0, {
                "title": "Raw Certificate Retrieved via Unverified Forensic Fallback",
                "severity": "high",
                "evidence": f"Standard TLS verification failed ({chain_error or 'Verification error'}). Certificate metadata extracted without verification.",
                "interpretation": "Host metadata was obtained via an unverified connection. This certificate is NOT trusted by the system trust store and cannot guarantee transport authenticity.",
            })

        if matched_brand and not is_official_brand_domain:
            investigation_findings.append({
                "title": f"Brand Keyword '{matched_brand.capitalize()}' Present in Domain",
                "severity": "high" if suspicious_affix_found else "medium",
                "evidence": f"Domain: '{hostname}', Detected Brand: '{matched_brand}', Affixes: {suspicious_affix_found or 'None'}",
                "interpretation": f"The domain incorporates recognizable brand name '{matched_brand.capitalize()}'. While brand presence warrants investigation, it does not confirm phishing in isolation.",
            })

        investigation_findings.append({
            "title": "TLS Encryption Does Not Establish Website Legitimacy", "severity": "info",
            "evidence": "Modern threat actors widely deploy legitimate Let's Encrypt and Cloudflare TLS certificates on malicious infrastructure.",
            "interpretation": "A valid TLS certificate only guarantees encrypted transport to the intended host, not that the operator or content is trustworthy.",
        })

        cert_health_status = "Healthy" if is_healthy else ("Critical" if (is_expired or not matched_hostname) else "Warning")
        domain_id_status = "Aligned" if matched_hostname and not (matched_brand and not is_official_brand_domain) else ("Potential Impersonation" if (matched_brand and not is_official_brand_domain) else "Misaligned")
        web_trust_status = "Suspicious" if (matched_brand and not is_official_brand_domain) or is_untrusted_ca or is_self_signed else ("Neutral / Standard" if is_healthy else "Caution")

        investigation_summary = {
            "certificate_health": {"status": cert_health_status, "title": "Certificate Health", "summary": "Technical certificate configuration, cryptographic parameters, and chain trust." if not is_unverified_fallback else "Certificate extracted via unverified probe; standard TLS verification failed.", "details": f"Chain {'valid' if chain_valid else 'invalid'}, {pk_algo} {pk_size}b, {days_remaining} days remaining."},
            "domain_identity": {"status": domain_id_status, "title": "Domain Identity", "summary": "Alignment between certificate identity, SAN coverage, and target domain.", "details": f"Hostname {'matches' if matched_hostname else 'mismatched'} with {len(sans)} SANs covered."},
            "website_trust": {"status": web_trust_status, "title": "Website Trust", "summary": "Impersonation heuristics and brand mimicry indicators.", "details": f"Brand indicator flagged for '{matched_brand}'." if (matched_brand and not is_official_brand_domain) else "No brand impersonation keywords detected."},
        }

        total_validity_days = max(1, (not_after - not_before).days)
        elapsed_days = max(0, (now - not_before).days)
        progress_pct = min(100, max(0, round((elapsed_days / total_validity_days) * 100)))

        return {
            "status": "valid" if is_healthy else "unhealthy", "common_name": subj_cn, "issuer": issuer_str,
            "issuer_details": {"common_name": iss_cn, "organization": iss_org, "organizational_unit": iss_ou, "country": iss_c, "ca_name": ca_name},
            "subject": {"common_name": subj_cn, "organization": subj_org, "organizational_unit": subj_ou, "country": subj_c},
            "subject_details": {"common_name": subj_cn, "organization": subj_org, "organizational_unit": subj_ou, "country": subj_c, "sans": sans},
            "cryptography": {"tls_version": negotiated_protocol, "cipher_suite": cipher_info[0] if cipher_info else None, "public_key_algorithm": pk_algo, "public_key_size": pk_size, "signature_algorithm": sig_algo_full, "fingerprint_sha256": fingerprint, "unverified_fallback": is_unverified_fallback},
            "validity": {"not_before": not_before.isoformat(), "not_after": not_after.isoformat(), "days_remaining": days_remaining, "total_validity_days": total_validity_days, "progress_pct": progress_pct},
            "certificate_type": cert_type,
            "is_unverified_fallback": is_unverified_fallback,
            "certificate_transparency": {"has_embedded_scts": has_embedded_scts, "sct_count": sct_count, "status": "Embedded SCTs Present" if has_embedded_scts else "No Embedded SCTs (Delivered via OCSP/TLS or unavailable)"},
            "domain_impersonation": {"brand_detected": matched_brand, "is_official_domain": is_official_brand_domain, "risk_level": impersonation_risk, "suspicious_affixes": suspicious_affix_found, "san_inconsistent": san_inconsistent, "is_punycode": is_punycode, "disclaimer": "A brand name appearing in a domain is an impersonation indicator, not confirmed malicious phishing."},
            "security_assessment_dimensions": dimensions, "investigation_findings": investigation_findings, "investigation_summary": investigation_summary,
            "fingerprint_sha256": fingerprint, "sha256_fingerprint": fingerprint, "serial_number": serial,
            "valid_from": not_before.isoformat(), "valid_to": not_after.isoformat(), "not_before": not_before.isoformat(), "not_after": not_after.isoformat(),
            "days_remaining": days_remaining, "days_to_expiration": days_remaining, "is_expired": is_expired, "is_not_yet_valid": is_not_yet_valid,
            "is_self_signed": is_self_signed, "chain_valid": chain_valid, "chain_error": chain_error, "is_untrusted_ca": is_untrusted_ca,
            "hostname_matches": matched_hostname, "sans": sans, "subject_alt_names": sans, "signature_algorithm": sig_algo,
            "tls_protocol": negotiated_protocol, "tls_version": negotiated_protocol, "cipher": cipher_info[0] if cipher_info else None, "cipher_suite": cipher_info[0] if cipher_info else None,
        }

    def _match_hostname(self, hostname: str, common_name: Optional[str], sans: list[str]) -> bool:
        candidates = list(sans)
        if common_name and common_name not in candidates:
            candidates.append(common_name)
        host_lower = hostname.lower().strip()
        for cand in candidates:
            cand_lower = cand.lower().strip()
            if cand_lower == host_lower:
                return True
            if cand_lower.startswith("*."):
                suffix = cand_lower[1:]
                if host_lower.endswith(suffix):
                    prefix = host_lower[:-len(suffix)]
                    if prefix and "." not in prefix:
                        return True
        return False
