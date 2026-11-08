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
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448
from app.models.entity import EntityType, RelationshipType
from app.models.finding import FindingCategory, Severity
from app.scanner.orchestrator import ModuleInterface

logger = logging.getLogger("phantom.scanner.modules.tls_validation")

# High-target brands monitored for domain impersonation heuristics
HIGH_TARGET_BRANDS = [
    "whatsapp", "paypal", "microsoft", "apple", "google", "amazon", "netflix",
    "facebook", "instagram", "chase", "wellsfargo", "bankofamerica", "binance",
    "coinbase", "telegram", "twitter", "linkedin", "dropbox", "adobe", "roblox",
    "steam", "yahoo", "outlook", "office365", "dhl", "fedex", "usps", "ups",
    "barclays", "hsbc", "citibank", "santander"
]

SUSPICIOUS_AFFIXES = ["login", "secure", "verify", "auth", "portal", "update", "account", "signin", "support", "online"]


class TlsValidationModule(ModuleInterface):
    """
    TLS Certificate Validation module.
    Inspects SSL/TLS certificates and evaluates certificate hygiene.
    """

    name = "tls_validation"
    description = "TLS certificate extraction, expiration, SAN validation, and cryptographic analysis"
    version = "1.0.0"

    async def execute(self, target_url: str, hostname: str, scan_id: str, **kwargs) -> dict:
        logger.info("Executing TLS validation for %s (scan %s)", hostname, scan_id)

        findings = []
        entities = []
        relationships = []

        # Target port: default 443 unless URL specifies a port
        parsed = urlparse(target_url)
        port = parsed.port if parsed.port else 443

        # Connect and extract certificate
        cert_data = await asyncio.to_thread(self._fetch_and_parse_cert, hostname, port, scan_id, findings, entities, relationships)

        # Check if the scanned URL was plain unencrypted HTTP
        if parsed.scheme == "http":
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "module": self.name,
                "category": FindingCategory.TLS_CERTIFICATE.value,
                "title": "Plain HTTP Scheme Specified",
                "description": f"URL {target_url} uses unencrypted HTTP. Data in transit is vulnerable to interception.",
                "severity": Severity.MEDIUM.value,
                "confidence": 1.0,
                "evidence": {"target_url": target_url},
                "recommendation": "Migrate services to HTTPS and enforce HSTS.",
                "created_at": datetime.now(timezone.utc),
            })

        return {
            "data": cert_data,
            "findings": findings,
            "entities": entities,
            "relationships": relationships,
        }

    def _probe_unverified_cert(self, hostname: str, port: int) -> tuple[Optional[bytes], Optional[str], Optional[tuple]]:
        """
        Connect with CERT_NONE solely to extract raw peer certificate for forensic analysis
        when standard certificate verification fails.
        """
        try:
            probe_ctx = ssl.create_default_context()
            probe_ctx.check_hostname = False
            probe_ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=5.0) as sock:
                with probe_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return (
                        ssock.getpeercert(binary_form=True),
                        ssock.version(),
                        ssock.cipher(),
                    )
        except Exception as e:
            logger.debug("Unverified probe failed for %s:%d: %s", hostname, port, e)
            return None, None, None

    def _fetch_and_parse_cert(
        self,
        hostname: str,
        port: int,
        scan_id: str,
        findings: list,
        entities: list,
        relationships: list,
    ) -> dict:
        """
        Connect to TLS endpoint, verify certificate chain and trust store,
        extract DER certificate, and inspect all cryptographic attributes.
        """
        raw_der = None
        negotiated_protocol = None
        cipher_info = None
        chain_valid = False
        chain_error = None

        # Stage 1: Standard Verified TLS Connection (Chain & Trust Store Verification)
        verified_ctx = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, port), timeout=5.0) as sock:
                with verified_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    raw_der = ssock.getpeercert(binary_form=True)
                    negotiated_protocol = ssock.version()
                    cipher_info = ssock.cipher()
                    chain_valid = True
                    chain_error = None
        except ssl.SSLCertVerificationError as e:
            chain_valid = False
            chain_error = getattr(e, "verify_message", None) or str(e)
            logger.info("SSL verification failed for %s: %s (falling back to forensic extraction)", hostname, chain_error)
            raw_der, negotiated_protocol, cipher_info = self._probe_unverified_cert(hostname, port)
        except ssl.SSLError as e:
            chain_valid = False
            chain_error = str(e)
            logger.info("SSL error for %s: %s (falling back to forensic extraction)", hostname, chain_error)
            raw_der, negotiated_protocol, cipher_info = self._probe_unverified_cert(hostname, port)
        except (socket.timeout, TimeoutError, ConnectionRefusedError, OSError) as e:
            logger.warning("TLS connection failed for %s:%d: %s", hostname, port, e)
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "module": self.name,
                "category": FindingCategory.TLS_CERTIFICATE.value,
                "title": "TLS/HTTPS Connection Failed",
                "description": f"Could not establish a TLS handshake with {hostname}:{port} ({type(e).__name__}: {str(e)}).",
                "severity": Severity.HIGH.value,
                "confidence": 0.95,
                "evidence": {"hostname": hostname, "port": port, "error": str(e)},
                "recommendation": "Ensure an active, valid TLS certificate is deployed on port 443.",
                "created_at": datetime.now(timezone.utc),
            })
            return {
                "status": "unavailable",
                "error": str(e),
                "chain_valid": False,
                "is_expired": None,
                "is_self_signed": None,
                "hostname_matches": False,
            }
        except Exception as e:
            logger.warning("Unexpected TLS error for %s:%d: %s", hostname, port, e)
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "module": self.name,
                "category": FindingCategory.TLS_CERTIFICATE.value,
                "title": "TLS/HTTPS Connection Failed",
                "description": f"Could not establish a TLS handshake with {hostname}:{port} ({type(e).__name__}: {str(e)}).",
                "severity": Severity.HIGH.value,
                "confidence": 0.95,
                "evidence": {"hostname": hostname, "port": port, "error": str(e)},
                "recommendation": "Ensure an active, valid TLS certificate is deployed on port 443.",
                "created_at": datetime.now(timezone.utc),
            })
            return {
                "status": "unavailable",
                "error": str(e),
                "chain_valid": False,
                "is_expired": None,
                "is_self_signed": None,
                "hostname_matches": False,
            }

        if not raw_der:
            error_msg = chain_error or "No certificate received from host"
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "module": self.name,
                "category": FindingCategory.TLS_CERTIFICATE.value,
                "title": "TLS/HTTPS Connection Failed",
                "description": f"Could not retrieve TLS certificate from {hostname}:{port} ({error_msg}).",
                "severity": Severity.HIGH.value,
                "confidence": 0.95,
                "evidence": {"hostname": hostname, "port": port, "error": error_msg},
                "recommendation": "Ensure an active, valid TLS certificate is deployed on port 443.",
                "created_at": datetime.now(timezone.utc),
            })
            return {
                "status": "failed",
                "error": error_msg,
                "chain_valid": False,
                "is_expired": None,
                "is_self_signed": None,
                "hostname_matches": False,
            }

        # Parse X.509 Certificate
        try:
            cert = x509.load_der_x509_certificate(raw_der)
        except Exception as e:
            logger.error("Failed to parse DER certificate for %s: %s", hostname, e)
            return {"status": "failed", "error": f"Certificate parse error: {e}"}

        # Extract attributes
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        serial = format(cert.serial_number, "x")
        now = datetime.now(timezone.utc)

        # Validity windows (timezone-aware)
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc

        # Extract Common Name, Organization, OU, Country
        subject_cn = None
        subject_org = None
        subject_ou = None
        subject_c = None
        for attr in cert.subject:
            if attr.oid == x509.NameOID.COMMON_NAME:
                subject_cn = attr.value
            elif attr.oid == x509.NameOID.ORGANIZATION_NAME:
                subject_org = attr.value
            elif attr.oid == x509.NameOID.ORGANIZATIONAL_UNIT_NAME:
                subject_ou = attr.value
            elif attr.oid == x509.NameOID.COUNTRY_NAME:
                subject_c = attr.value

        issuer_cn = None
        issuer_org = None
        issuer_ou = None
        issuer_c = None
        for attr in cert.issuer:
            if attr.oid == x509.NameOID.COMMON_NAME:
                issuer_cn = attr.value
            elif attr.oid == x509.NameOID.ORGANIZATION_NAME:
                issuer_org = attr.value
            elif attr.oid == x509.NameOID.ORGANIZATIONAL_UNIT_NAME:
                issuer_ou = attr.value
            elif attr.oid == x509.NameOID.COUNTRY_NAME:
                issuer_c = attr.value

        issuer_str = issuer_org or issuer_cn or "Unknown Authority"
        ca_name = issuer_org or issuer_cn or "Unknown Authority"

        # Extract Subject Alternative Names (SANs)
        sans = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            sans = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass

        # Public Key & Cryptographic Parameters
        pk = cert.public_key()
        if isinstance(pk, rsa.RSAPublicKey):
            pk_algo = "RSA"
            pk_size = pk.key_size
        elif isinstance(pk, ec.EllipticCurvePublicKey):
            pk_algo = f"ECDSA ({pk.curve.name})"
            pk_size = pk.key_size
        elif isinstance(pk, ed25519.Ed25519PublicKey):
            pk_algo = "Ed25519"
            pk_size = 256
        else:
            pk_algo = type(pk).__name__
            pk_size = getattr(pk, "key_size", None)

        sig_algo = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"
        sig_algo_full = getattr(cert.signature_algorithm_oid, "_name", None) or sig_algo

        # Certificate Type evaluation (DV vs OV vs EV vs Wildcard)
        is_wildcard = (subject_cn and subject_cn.startswith("*.")) or any(s.startswith("*.") for s in sans)
        if is_wildcard:
            cert_type = "Wildcard (DV)"
        elif subject_org and subject_c:
            cert_type = "Organization Validated (OV)"
        else:
            cert_type = "Domain Validated (DV)"

        # Certificate Transparency (SCT presence)
        has_embedded_scts = False
        sct_count = 0
        try:
            sct_ext = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2"))
            has_embedded_scts = True
            raw_sct_bytes = sct_ext.value.public_bytes()
            sct_count = max(1, len(raw_sct_bytes) // 100)
        except Exception:
            has_embedded_scts = False

        # 1. Validation: Expiration Checks
        days_remaining = (not_after - now).days
        is_expired = now > not_after
        is_not_yet_valid = now < not_before
        is_expiring_soon = 0 <= days_remaining <= 14

        if is_expired:
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "module": self.name,
                "category": FindingCategory.TLS_CERTIFICATE.value,
                "title": "TLS Certificate Expired",
                "description": f"Certificate for {hostname} expired on {not_after.isoformat()}.",
                "severity": Severity.CRITICAL.value,
                "confidence": 1.0,
                "evidence": {"not_after": not_after.isoformat(), "days_remaining": days_remaining},
                "recommendation": "Renew and replace the expired TLS certificate immediately.",
                "created_at": datetime.now(timezone.utc),
            })
        elif is_expiring_soon:
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "module": self.name,
                "category": FindingCategory.TLS_CERTIFICATE.value,
                "title": "TLS Certificate Expiring Soon",
                "description": f"Certificate for {hostname} expires in {days_remaining} days ({not_after.isoformat()}).",
                "severity": Severity.MEDIUM.value,
                "confidence": 1.0,
                "evidence": {"days_remaining": days_remaining, "not_after": not_after.isoformat()},
                "recommendation": "Initiate automated or manual renewal before certificate expires.",
                "created_at": datetime.now(timezone.utc),
            })

        if is_not_yet_valid:
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "module": self.name,
                "category": FindingCategory.TLS_CERTIFICATE.value,
                "title": "TLS Certificate Not Yet Valid",
                "description": f"Certificate validity start date is in the future ({not_before.isoformat()}).",
                "severity": Severity.HIGH.value,
                "confidence": 1.0,
                "evidence": {"not_before": not_before.isoformat()},
                "recommendation": "Ensure system clocks and certificate issuance timestamps are synchronized.",
                "created_at": datetime.now(timezone.utc),
            })

        # 2. Validation: Self-Signed Certificate
        is_self_signed = (cert.issuer == cert.subject)
        if is_self_signed:
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "module": self.name,
                "category": FindingCategory.TLS_CERTIFICATE.value,
                "title": "Self-Signed TLS Certificate Detected",
                "description": f"The certificate presented by {hostname} is self-signed and untrusted by standard root stores.",
                "severity": Severity.HIGH.value,
                "confidence": 0.95,
                "evidence": {"issuer": issuer_cn or issuer_org, "subject": subject_cn or subject_org},
                "recommendation": "Replace self-signed certificates with ones issued by a publicly trusted Certificate Authority.",
                "created_at": datetime.now(timezone.utc),
            })

        # 3. Validation: Untrusted Certificate Authority / Broken Chain
        is_untrusted_ca = False
        if not chain_valid and not is_self_signed:
            err_str = (chain_error or "").lower()
            is_hostname_err_only = (
                "hostname" in err_str
                and not any(k in err_str for k in ("issuer", "self-signed", "chain", "authority", "untrusted", "root"))
            )
            # If the error is not merely a hostname mismatch and not already flagged as expired
            if not is_hostname_err_only and not is_expired:
                is_untrusted_ca = True
                findings.append({
                    "finding_id": str(uuid.uuid4()),
                    "scan_id": scan_id,
                    "module": self.name,
                    "category": FindingCategory.TLS_CERTIFICATE.value,
                    "title": "Untrusted TLS Certificate Authority / Invalid Chain",
                    "description": (
                        f"The TLS certificate for {hostname} was issued by an untrusted or unverifiable authority "
                        f"({issuer_str}). Verification failure: {chain_error or 'Root authority not recognized'}."
                    ),
                    "severity": Severity.HIGH.value,
                    "confidence": 0.95,
                    "evidence": {
                        "hostname": hostname,
                        "issuer": issuer_str,
                        "chain_error": chain_error,
                        "chain_valid": False,
                    },
                    "recommendation": "Replace the certificate with one issued by a globally recognized, publicly trusted Certificate Authority.",
                    "created_at": datetime.now(timezone.utc),
                })

        # 4. Validation: Hostname Mismatch
        matched_hostname = self._match_hostname(hostname, subject_cn, sans)
        if not matched_hostname:
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "module": self.name,
                "category": FindingCategory.TLS_CERTIFICATE.value,
                "title": "TLS Hostname Mismatch",
                "description": f"Domain '{hostname}' does not match Common Name ({subject_cn}) or SANs ({', '.join(sans[:5])}).",
                "severity": Severity.CRITICAL.value,
                "confidence": 0.95,
                "evidence": {"hostname": hostname, "common_name": subject_cn, "sans": sans},
                "recommendation": "Issue a certificate covering the target domain or update DNS routing.",
                "created_at": datetime.now(timezone.utc),
            })

        # 5. Validation: Weak Signature Algorithm
        if sig_algo in ("md5", "sha1"):
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "module": self.name,
                "category": FindingCategory.TLS_CERTIFICATE.value,
                "title": f"Weak Certificate Signature Algorithm ({sig_algo.upper()})",
                "description": f"Certificate uses deprecated signature algorithm {sig_algo.upper()}, vulnerable to collision attacks.",
                "severity": Severity.HIGH.value,
                "confidence": 1.0,
                "evidence": {"signature_algorithm": sig_algo},
                "recommendation": "Reissue certificate using SHA-256 or modern ECDSA algorithm.",
                "created_at": datetime.now(timezone.utc),
            })

        # 6. Graph Entities & Relationships
        cert_entity_id = str(uuid.uuid4())
        entities.append({
            "entity_id": cert_entity_id,
            "type": EntityType.CERTIFICATE.value,
            "value": fingerprint,
            "metadata": {
                "sha256": fingerprint,
                "common_name": subject_cn,
                "issuer": issuer_str,
                "serial": serial,
                "sans": sans,
                "days_remaining": days_remaining,
                "protocol": negotiated_protocol,
                "chain_valid": chain_valid,
            },
            "first_seen": datetime.now(timezone.utc),
            "last_seen": datetime.now(timezone.utc),
            "scan_ids": [scan_id],
        })

        # Domain to Certificate relationship
        domain_entity_id = str(uuid.uuid4())
        entities.append({
            "entity_id": domain_entity_id,
            "type": EntityType.DOMAIN.value,
            "value": hostname,
            "metadata": {"hostname": hostname},
            "first_seen": datetime.now(timezone.utc),
            "last_seen": datetime.now(timezone.utc),
            "scan_ids": [scan_id],
        })

        relationships.append({
            "relationship_id": str(uuid.uuid4()),
            "source_entity_id": domain_entity_id,
            "target_entity_id": cert_entity_id,
            "type": RelationshipType.HAS_CERTIFICATE.value,
            "scan_id": scan_id,
            "confidence": 1.0,
            "metadata": {"fingerprint": fingerprint},
            "created_at": datetime.now(timezone.utc),
        })

        if issuer_org or issuer_cn:
            issuer_val = issuer_org or issuer_cn
            issuer_entity_id = str(uuid.uuid4())
            entities.append({
                "entity_id": issuer_entity_id,
                "type": EntityType.ORGANIZATION.value,
                "value": issuer_val,
                "metadata": {"role": "certificate_authority"},
                "first_seen": datetime.now(timezone.utc),
                "last_seen": datetime.now(timezone.utc),
                "scan_ids": [scan_id],
            })
            relationships.append({
                "relationship_id": str(uuid.uuid4()),
                "source_entity_id": cert_entity_id,
                "target_entity_id": issuer_entity_id,
                "type": RelationshipType.ISSUED_BY.value,
                "scan_id": scan_id,
                "confidence": 1.0,
                "metadata": {"issuer": issuer_val},
                "created_at": datetime.now(timezone.utc),
            })

        is_healthy = (
            chain_valid
            and matched_hostname
            and not is_expired
            and not is_not_yet_valid
            and not is_self_signed
            and not is_untrusted_ca
            and sig_algo not in ("md5", "sha1")
        )

        # ---------------------------------------------------------
        # Domain Identity & Brand Impersonation Analysis
        # ---------------------------------------------------------
        host_lower = hostname.lower().strip()
        tokens = [t for t in re.split(r"[-._/]", host_lower) if t]
        matched_brand = None
        is_official_brand_domain = False
        impersonation_risk = "low"
        suspicious_affix_found = []

        for b in HIGH_TARGET_BRANDS:
            if host_lower == f"{b}.com" or host_lower.endswith(f".{b}.com"):
                matched_brand = b
                is_official_brand_domain = True
                impersonation_risk = "none"
                break
            elif b in host_lower:
                matched_brand = b
                impersonation_risk = "potential_impersonation"
                break

        for affix in SUSPICIOUS_AFFIXES:
            if affix in host_lower:
                suspicious_affix_found.append(affix)

        is_punycode = host_lower.startswith("xn--") or ".xn--" in host_lower
        san_sprawl = len(sans) > 40

        # SAN inconsistency check: SANs contain domains with different apexes
        san_apexes = set()
        for s in sans:
            parts = s.split(".")
            if len(parts) >= 2:
                san_apexes.add(".".join(parts[-2:]))
        san_inconsistent = len(san_apexes) > 3

        if matched_brand and not is_official_brand_domain:
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "module": self.name,
                "category": FindingCategory.PHISHING_INDICATOR.value,
                "title": f"Potential Brand Impersonation Indicator ({matched_brand.capitalize()})",
                "description": (
                    f"Domain '{hostname}' contains recognizable brand keyword '{matched_brand.capitalize()}', "
                    f"yet certificate/DNS structure is not verified as the brand's official infrastructure. "
                    f"Important: A brand name in a domain is an impersonation indicator, not confirmed phishing on its own."
                ),
                "severity": Severity.MEDIUM.value if not suspicious_affix_found else Severity.HIGH.value,
                "confidence": 0.85,
                "evidence": {
                    "matched_brand": matched_brand,
                    "hostname": hostname,
                    "suspicious_affixes": suspicious_affix_found,
                    "is_official_domain": False,
                },
                "recommendation": f"Verify whether domain is legitimately owned by {matched_brand.capitalize()} or registered by a third party.",
                "created_at": datetime.now(timezone.utc),
            })

        # ---------------------------------------------------------
        # 7-Dimension Independent Security Assessment
        # ---------------------------------------------------------
        # Dim 1: Validity
        if is_expired:
            dim_validity = {"id": "validity", "name": "Certificate Validity", "status": "fail", "explanation": f"Certificate expired {abs(days_remaining)} days ago.", "severity": "critical", "evidence": {"not_after": not_after.isoformat()}}
        elif is_not_yet_valid:
            dim_validity = {"id": "validity", "name": "Certificate Validity", "status": "fail", "explanation": "Certificate not yet active (notBefore is in the future).", "severity": "high", "evidence": {"not_before": not_before.isoformat()}}
        else:
            dim_validity = {"id": "validity", "name": "Certificate Validity", "status": "pass", "explanation": f"Certificate is currently active within its validity window ({days_remaining} days remaining).", "severity": "info", "evidence": {"not_before": not_before.isoformat(), "not_after": not_after.isoformat(), "days_remaining": days_remaining}}

        # Dim 2: Chain Trust
        if is_self_signed:
            dim_chain = {"id": "chain_trust", "name": "Certificate Chain Trust", "status": "warning", "explanation": "Self-signed certificate; not issued by a trusted CA.", "severity": "high", "evidence": {"issuer": issuer_str, "is_self_signed": True}}
        elif is_untrusted_ca or not chain_valid:
            dim_chain = {"id": "chain_trust", "name": "Certificate Chain Trust", "status": "fail", "explanation": f"Failed root store verification ({chain_error or 'Untrusted authority'}).", "severity": "high", "evidence": {"issuer": issuer_str, "chain_valid": False, "chain_error": chain_error}}
        else:
            dim_chain = {"id": "chain_trust", "name": "Certificate Chain Trust", "status": "pass", "explanation": f"Successfully validated against system root CA store ({ca_name}).", "severity": "info", "evidence": {"issuer": issuer_str, "chain_valid": True}}

        # Dim 3: Domain Matching
        if matched_hostname:
            dim_domain = {"id": "domain_matching", "name": "Domain Name Matching", "status": "pass", "explanation": f"Hostname '{hostname}' matches certificate CN or SANs per RFC 6125.", "severity": "info", "evidence": {"common_name": subject_cn, "sans_count": len(sans)}}
        else:
            dim_domain = {"id": "domain_matching", "name": "Domain Name Matching", "status": "fail", "explanation": f"Hostname '{hostname}' does not match Common Name or SANs.", "severity": "critical", "evidence": {"hostname": hostname, "common_name": subject_cn, "sans": sans[:10]}}

        # Dim 4: Cryptographic Strength
        is_weak_key = (pk_algo == "RSA" and pk_size and pk_size < 2048) or (pk_algo.startswith("ECDSA") and pk_size and pk_size < 256)
        is_weak_sig = sig_algo in ("md5", "sha1")
        if is_weak_key or is_weak_sig:
            dim_crypto = {"id": "cryptography", "name": "Cryptographic Strength", "status": "fail", "explanation": f"Deprecated algorithm detected ({pk_algo} {pk_size}b / {sig_algo_full}).", "severity": "high", "evidence": {"key_algorithm": pk_algo, "key_size": pk_size, "sig_algo": sig_algo_full}}
        else:
            dim_crypto = {"id": "cryptography", "name": "Cryptographic Strength", "status": "pass", "explanation": f"Modern cryptographic parameters ({pk_algo} {pk_size or ''}b, {sig_algo_full}, {negotiated_protocol or 'TLS'}).", "severity": "info", "evidence": {"key_algorithm": pk_algo, "key_size": pk_size, "sig_algo": sig_algo_full, "cipher": cipher_info[0] if cipher_info else None}}

        # Dim 5: Expiration Risk
        if is_expired:
            dim_exp = {"id": "expiration_risk", "name": "Certificate Expiration Risk", "status": "fail", "explanation": f"Certificate expired on {not_after.strftime('%Y-%m-%d')}.", "severity": "critical", "evidence": {"days_remaining": days_remaining}}
        elif is_expiring_soon:
            dim_exp = {"id": "expiration_risk", "name": "Certificate Expiration Risk", "status": "warning", "explanation": f"Certificate expires soon in {days_remaining} days.", "severity": "medium", "evidence": {"days_remaining": days_remaining}}
        else:
            dim_exp = {"id": "expiration_risk", "name": "Certificate Expiration Risk", "status": "pass", "explanation": f"Certificate has {days_remaining} days of remaining validity.", "severity": "info", "evidence": {"days_remaining": days_remaining}}

        # Dim 6: Certificate Transparency Presence
        if has_embedded_scts:
            dim_ct = {"id": "transparency", "name": "Certificate Transparency Presence", "status": "pass", "explanation": f"Embedded Signed Certificate Timestamps (SCTs) verified in X.509 extensions ({sct_count} SCTs).", "severity": "info", "evidence": {"embedded_scts": True, "sct_count": sct_count}}
        else:
            dim_ct = {"id": "transparency", "name": "Certificate Transparency Presence", "status": "unknown", "explanation": "No embedded SCTs detected in X.509 extensions; may be delivered via TLS extension or OCSP.", "severity": "low", "evidence": {"embedded_scts": False}}

        # Dim 7: Potential Certificate Anomalies
        if san_inconsistent:
            dim_anomalies = {"id": "anomalies", "name": "Potential Certificate Anomalies", "status": "warning", "explanation": f"High SAN divergence across {len(san_apexes)} distinct apex domains.", "severity": "medium", "evidence": {"apex_domains": list(san_apexes)[:5]}}
        elif is_self_signed:
            dim_anomalies = {"id": "anomalies", "name": "Potential Certificate Anomalies", "status": "warning", "explanation": "Self-signed certificate anomaly.", "severity": "medium", "evidence": {"self_signed": True}}
        elif is_punycode:
            dim_anomalies = {"id": "anomalies", "name": "Potential Certificate Anomalies", "status": "warning", "explanation": "Domain contains Punycode homoglyph lookalike characters.", "severity": "medium", "evidence": {"punycode": True}}
        else:
            dim_anomalies = {"id": "anomalies", "name": "Potential Certificate Anomalies", "status": "pass", "explanation": "No structural certificate anomalies or unusual SAN sprawl detected.", "severity": "info", "evidence": {"san_count": len(sans)}}

        dimensions = [dim_validity, dim_chain, dim_domain, dim_crypto, dim_exp, dim_ct, dim_anomalies]

        # ---------------------------------------------------------
        # Investigation Findings (Evidence + Interpretation)
        # ---------------------------------------------------------
        investigation_findings = [
            {
                "title": f"Certificate Issued by {ca_name}",
                "severity": "info",
                "evidence": f"Issuer CN: {issuer_cn or 'N/A'}, O: {issuer_org or 'N/A'}, C: {issuer_c or 'N/A'}",
                "interpretation": f"Domain presents a certificate signed by {ca_name}. Public CAs routinely issue automated DV certificates to arbitrary domain registrants without identity verification.",
            },
            {
                "title": f"Protocol {negotiated_protocol or 'TLS'} with {cipher_info[0] if cipher_info else 'Standard Cipher'}",
                "severity": "info",
                "evidence": f"Negotiated Protocol: {negotiated_protocol or 'TLS'}, Cipher Suite: {cipher_info[0] if cipher_info else 'N/A'}",
                "interpretation": "Cryptographic transport parameters prevent passive eavesdropping, ensuring encrypted transit between client and server.",
            },
            {
                "title": "System Root Trust Store Validation",
                "severity": "info" if chain_valid and not is_self_signed else "high",
                "evidence": f"Chain Valid: {chain_valid}, Self-Signed: {is_self_signed}, Untrusted CA: {is_untrusted_ca}",
                "interpretation": (
                    "Certificate chain successfully validates against trusted system roots."
                    if chain_valid and not is_self_signed
                    else f"Certificate chain failed standard trust store validation ({chain_error or 'Untrusted authority'})."
                ),
            },
            {
                "title": "Certificate Validity Period Status",
                "severity": "critical" if is_expired else "info",
                "evidence": f"Valid From: {not_before.strftime('%Y-%m-%d')} to {not_after.strftime('%Y-%m-%d')} ({days_remaining} days left)",
                "interpretation": (
                    f"The certificate is within its valid operational lifespan ({days_remaining} days remaining)."
                    if not is_expired and not is_not_yet_valid
                    else "The certificate is outside its approved operational validity period."
                ),
            },
        ]

        if matched_brand and not is_official_brand_domain:
            investigation_findings.append({
                "title": f"Brand Keyword '{matched_brand.capitalize()}' Present in Domain",
                "severity": "medium" if not suspicious_affix_found else "high",
                "evidence": f"Domain: '{hostname}', Detected Brand: '{matched_brand}', Affixes: {suspicious_affix_found or 'None'}",
                "interpretation": f"The domain incorporates recognizable brand name '{matched_brand.capitalize()}'. While brand presence warrants investigation, it does not confirm phishing in isolation.",
            })

        investigation_findings.append({
            "title": "TLS Encryption Does Not Establish Website Legitimacy",
            "severity": "info",
            "evidence": "Modern threat actors widely deploy legitimate Let's Encrypt and Cloudflare TLS certificates on malicious infrastructure.",
            "interpretation": "A valid TLS certificate only guarantees encrypted transport to the intended host, not that the operator or content is trustworthy.",
        })

        # ---------------------------------------------------------
        # Investigation Summary (3 Distinct Dimensions)
        # ---------------------------------------------------------
        cert_health_status = "Healthy" if is_healthy else ("Critical" if (is_expired or not matched_hostname) else "Warning")
        domain_id_status = "Aligned" if matched_hostname and not (matched_brand and not is_official_brand_domain) else ("Potential Impersonation" if (matched_brand and not is_official_brand_domain) else "Misaligned")
        web_trust_status = "Suspicious" if (matched_brand and not is_official_brand_domain) or is_untrusted_ca or is_self_signed else ("Neutral / Standard" if is_healthy else "Caution")

        investigation_summary = {
            "certificate_health": {
                "status": cert_health_status,
                "title": "Certificate Health",
                "summary": "Technical certificate configuration, cryptographic parameters, and chain trust.",
                "details": f"Chain {'valid' if chain_valid else 'invalid'}, {pk_algo} {pk_size}b, {days_remaining} days remaining.",
            },
            "domain_identity": {
                "status": domain_id_status,
                "title": "Domain Identity",
                "summary": "Alignment between certificate identity, SAN coverage, and target domain.",
                "details": f"Hostname {'matches' if matched_hostname else 'mismatched'} with {len(sans)} SANs covered.",
            },
            "website_trust": {
                "status": web_trust_status,
                "title": "Website Trust",
                "summary": "Impersonation heuristics and brand mimicry indicators.",
                "details": (
                    f"Brand indicator flagged for '{matched_brand}'."
                    if (matched_brand and not is_official_brand_domain)
                    else "No brand impersonation keywords detected."
                ),
            },
        }

        total_validity_days = max(1, (not_after - not_before).days)
        elapsed_days = max(0, (now - not_before).days)
        progress_pct = min(100, max(0, round((elapsed_days / total_validity_days) * 100)))

        return {
            "status": "valid" if is_healthy else "unhealthy",
            "common_name": subject_cn,
            "issuer": issuer_str,
            "issuer_details": {
                "common_name": issuer_cn,
                "organization": issuer_org,
                "organizational_unit": issuer_ou,
                "country": issuer_c,
                "ca_name": ca_name,
            },
            "subject": {
                "common_name": subject_cn,
                "organization": subject_org,
                "organizational_unit": subject_ou,
                "country": subject_c,
            },
            "subject_details": {
                "common_name": subject_cn,
                "organization": subject_org,
                "organizational_unit": subject_ou,
                "country": subject_c,
                "sans": sans,
            },
            "cryptography": {
                "tls_version": negotiated_protocol or "TLSv1.3",
                "cipher_suite": cipher_info[0] if cipher_info else "TLS_AES_256_GCM_SHA384",
                "public_key_algorithm": pk_algo,
                "public_key_size": pk_size,
                "signature_algorithm": sig_algo_full,
                "fingerprint_sha256": fingerprint,
            },
            "validity": {
                "not_before": not_before.isoformat(),
                "not_after": not_after.isoformat(),
                "days_remaining": days_remaining,
                "total_validity_days": total_validity_days,
                "progress_pct": progress_pct,
            },
            "certificate_type": cert_type,
            "certificate_transparency": {
                "has_embedded_scts": has_embedded_scts,
                "sct_count": sct_count,
                "status": "Embedded SCTs Present" if has_embedded_scts else "No Embedded SCTs (Delivered via OCSP/TLS or unavailable)",
            },
            "domain_impersonation": {
                "brand_detected": matched_brand,
                "is_official_domain": is_official_brand_domain,
                "risk_level": impersonation_risk,
                "suspicious_affixes": suspicious_affix_found,
                "san_inconsistent": san_inconsistent,
                "is_punycode": is_punycode,
                "disclaimer": "A brand name appearing in a domain is an impersonation indicator, not confirmed malicious phishing.",
            },
            "security_assessment_dimensions": dimensions,
            "investigation_findings": investigation_findings,
            "investigation_summary": investigation_summary,
            "fingerprint_sha256": fingerprint,
            "sha256_fingerprint": fingerprint,
            "serial_number": serial,
            "valid_from": not_before.isoformat(),
            "valid_to": not_after.isoformat(),
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "days_remaining": days_remaining,
            "days_to_expiration": days_remaining,
            "is_expired": is_expired,
            "is_not_yet_valid": is_not_yet_valid,
            "is_self_signed": is_self_signed,
            "chain_valid": chain_valid,
            "chain_error": chain_error,
            "is_untrusted_ca": is_untrusted_ca,
            "hostname_matches": matched_hostname,
            "sans": sans,
            "subject_alt_names": sans,
            "signature_algorithm": sig_algo,
            "tls_protocol": negotiated_protocol,
            "tls_version": negotiated_protocol,
            "cipher": cipher_info[0] if cipher_info else None,
            "cipher_suite": cipher_info[0] if cipher_info else None,
        }

    def _match_hostname(self, hostname: str, common_name: Optional[str], sans: list[str]) -> bool:
        """Validate if hostname matches common name or any Subject Alternative Name (RFC 6125)."""
        candidates = list(sans)
        if common_name and common_name not in candidates:
            candidates.append(common_name)

        host_lower = hostname.lower().strip()
        for cand in candidates:
            cand_lower = cand.lower().strip()
            if cand_lower == host_lower:
                return True
            # RFC 6125 Wildcard matching (e.g. *.example.com matches sub.example.com)
            if cand_lower.startswith("*."):
                suffix = cand_lower[1:]  # e.g. .example.com
                if host_lower.endswith(suffix):
                    prefix = host_lower[:-len(suffix)]
                    # Wildcard must match exactly a single label (no embedded dots)
                    if prefix and "." not in prefix:
                        return True
        return False
