"""
PHANTOM TLS Validation Module
Extracts and validates SSL/TLS certificates, verifies certificate authority chains,
checks validity periods, SAN coverage, self-signed status, and generates cryptographic entities.
"""
import asyncio
import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from app.models.entity import EntityType, RelationshipType
from app.models.finding import FindingCategory, Severity
from app.scanner.orchestrator import ModuleInterface

logger = logging.getLogger("phantom.scanner.modules.tls_validation")


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

        # Extract Common Name and Organization
        subject_cn = None
        subject_org = None
        for attr in cert.subject:
            if attr.oid == x509.NameOID.COMMON_NAME:
                subject_cn = attr.value
            elif attr.oid == x509.NameOID.ORGANIZATION_NAME:
                subject_org = attr.value

        issuer_cn = None
        issuer_org = None
        for attr in cert.issuer:
            if attr.oid == x509.NameOID.COMMON_NAME:
                issuer_cn = attr.value
            elif attr.oid == x509.NameOID.ORGANIZATION_NAME:
                issuer_org = attr.value

        issuer_str = issuer_org or issuer_cn or "Unknown Authority"

        # Extract Subject Alternative Names (SANs)
        sans = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            sans = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass

        sig_algo = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"

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

        return {
            "status": "valid" if is_healthy else "unhealthy",
            "common_name": subject_cn,
            "issuer": issuer_str,
            "issuer_details": {"common_name": issuer_cn, "organization": issuer_org},
            "subject": {"common_name": subject_cn, "organization": subject_org},
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
