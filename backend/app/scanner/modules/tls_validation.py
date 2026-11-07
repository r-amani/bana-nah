"""
PHANTOM TLS Validation Module
Extracts and validates SSL/TLS certificates, checks validity periods,
SAN coverage, self-signed status, and generates cryptographic entities.
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
                "created_at": datetime.utcnow(),
            })

        return {
            "data": cert_data,
            "findings": findings,
            "entities": entities,
            "relationships": relationships,
        }

    def _fetch_and_parse_cert(
        self,
        hostname: str,
        port: int,
        scan_id: str,
        findings: list,
        entities: list,
        relationships: list,
    ) -> dict:
        """Connect to TLS endpoint, extract DER certificate, and inspect attributes."""
        # Create unverified context to ensure we can inspect self-signed or invalid certs
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        raw_der = None
        negotiated_protocol = None
        cipher_info = None

        try:
            with socket.create_connection((hostname, port), timeout=5.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    raw_der = ssock.getpeercert(binary_form=True)
                    negotiated_protocol = ssock.version()
                    cipher_info = ssock.cipher()
        except Exception as e:
            logger.warning("TLS handshake failed for %s:%d: %s", hostname, port, e)
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
                "created_at": datetime.utcnow(),
            })
            return {"status": "unavailable", "error": str(e)}

        if not raw_der:
            return {"status": "failed", "error": "No certificate received"}

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
                "created_at": datetime.utcnow(),
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
                "created_at": datetime.utcnow(),
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
                "created_at": datetime.utcnow(),
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
                "created_at": datetime.utcnow(),
            })

        # 3. Validation: Hostname Mismatch
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
                "created_at": datetime.utcnow(),
            })

        # 4. Validation: Weak Signature Algorithm
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
                "created_at": datetime.utcnow(),
            })

        # 5. Graph Entities & Relationships
        cert_entity_id = str(uuid.uuid4())
        entities.append({
            "entity_id": cert_entity_id,
            "type": EntityType.CERTIFICATE.value,
            "value": fingerprint,
            "metadata": {
                "common_name": subject_cn,
                "issuer": issuer_org or issuer_cn,
                "serial": serial,
                "sans": sans,
                "days_remaining": days_remaining,
                "protocol": negotiated_protocol,
            },
            "first_seen": datetime.utcnow(),
            "last_seen": datetime.utcnow(),
            "scan_ids": [scan_id],
        })

        # Domain to Certificate relationship
        domain_entity_id = str(uuid.uuid4())
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
            "source_entity_id": domain_entity_id,
            "target_entity_id": cert_entity_id,
            "type": RelationshipType.HAS_CERTIFICATE.value,
            "scan_id": scan_id,
            "confidence": 1.0,
            "metadata": {"fingerprint": fingerprint},
            "created_at": datetime.utcnow(),
        })

        if issuer_org or issuer_cn:
            issuer_val = issuer_org or issuer_cn
            issuer_entity_id = str(uuid.uuid4())
            entities.append({
                "entity_id": issuer_entity_id,
                "type": EntityType.ORGANIZATION.value,
                "value": issuer_val,
                "metadata": {"role": "certificate_authority"},
                "first_seen": datetime.utcnow(),
                "last_seen": datetime.utcnow(),
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
                "created_at": datetime.utcnow(),
            })

        return {
            "status": "valid" if not (is_expired or not matched_hostname or is_self_signed) else "unhealthy",
            "fingerprint_sha256": fingerprint,
            "serial_number": serial,
            "subject": {"common_name": subject_cn, "organization": subject_org},
            "issuer": {"common_name": issuer_cn, "organization": issuer_org},
            "valid_from": not_before.isoformat(),
            "valid_to": not_after.isoformat(),
            "days_remaining": days_remaining,
            "is_expired": is_expired,
            "is_self_signed": is_self_signed,
            "hostname_matches": matched_hostname,
            "sans": sans,
            "signature_algorithm": sig_algo,
            "tls_protocol": negotiated_protocol,
            "cipher": cipher_info[0] if cipher_info else None,
        }

    def _match_hostname(self, hostname: str, common_name: Optional[str], sans: list[str]) -> bool:
        """Validate if hostname matches common name or any Subject Alternative Name."""
        candidates = list(sans)
        if common_name:
            candidates.append(common_name)

        host_lower = hostname.lower()
        for cand in candidates:
            cand_lower = cand.lower()
            if cand_lower == host_lower:
                return True
            # Wildcard matching (e.g. *.example.com)
            if cand_lower.startswith("*."):
                suffix = cand_lower[2:]
                # e.g. sub.example.com ends with .example.com and has single subdomain
                if host_lower.endswith(suffix) and host_lower.count(".") == cand_lower.count("."):
                    return True
        return False
