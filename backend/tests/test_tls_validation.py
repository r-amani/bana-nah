"""
Unit tests for TLS Certificate Validation Module.
"""
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
import pytest
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from app.scanner.modules.tls_validation import TlsValidationModule


def generate_test_cert(
    common_name: str,
    sans: list[str],
    days_valid: int = 30,
    self_signed: bool = True,
    issuer_cn: str = "Test CA",
    issuer_org: str = "Test CA Ltd",
):
    """Generate in-memory X.509 certificate for testing."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Organization"),
    ])
    issuer = subject if self_signed else x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, issuer_org),
    ])

    if days_valid < 0:
        not_before = now - timedelta(days=abs(days_valid) + 10)
        not_after = now + timedelta(days=days_valid)
    else:
        not_before = now - timedelta(days=1)
        not_after = now + timedelta(days=days_valid)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    if sans:
        dns_sans = [x509.DNSName(san) for san in sans]
        builder = builder.add_extension(
            x509.SubjectAlternativeName(dns_sans), critical=False
        )

    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


def test_hostname_matching():
    mod = TlsValidationModule()
    # Direct match
    assert mod._match_hostname("example.com", "example.com", []) is True
    # SAN match
    assert mod._match_hostname("api.example.com", "example.com", ["api.example.com"]) is True
    # Wildcard SAN match (valid single subdomain)
    assert mod._match_hostname("sub.example.com", None, ["*.example.com"]) is True
    # Subdomain delimiter protection: badexample.com must not match *.example.com
    assert mod._match_hostname("badexample.com", None, ["*.example.com"]) is False
    # Nested subdomain must not match single-level wildcard per RFC 6125
    assert mod._match_hostname("deep.sub.example.com", None, ["*.example.com"]) is False
    # Hostname mismatch
    assert mod._match_hostname("malicious.com", "example.com", ["api.example.com"]) is False


def test_cert_inspection_valid_trusted_ca():
    mod = TlsValidationModule()
    der_bytes = generate_test_cert("safe.bank.org", ["safe.bank.org"], days_valid=90, self_signed=False, issuer_cn="DigiCert Global CA")

    findings = []
    entities = []
    relationships = []

    with patch("socket.create_connection") as mock_conn:
        mock_sock = MagicMock()
        mock_conn.return_value.__enter__.return_value = mock_sock

        with patch("ssl.create_default_context") as mock_ctx:
            mock_ssock = MagicMock()
            mock_ssock.getpeercert.return_value = der_bytes
            mock_ssock.version.return_value = "TLSv1.3"
            mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
            mock_ctx.return_value.wrap_socket.return_value.__enter__.return_value = mock_ssock

            res = mod._fetch_and_parse_cert("safe.bank.org", 443, "scan-valid-1", findings, entities, relationships)

            assert res["status"] == "valid"
            assert res["chain_valid"] is True
            assert res["is_self_signed"] is False
            assert res["hostname_matches"] is True
            assert res["is_expired"] is False
            assert res["issuer"] == "Test CA Ltd"
            assert len(findings) == 0


def test_cert_inspection_self_signed():
    mod = TlsValidationModule()
    der_bytes = generate_test_cert("test.local", ["test.local"], days_valid=365, self_signed=True)

    findings = []
    entities = []
    relationships = []

    with patch("socket.create_connection") as mock_conn:
        mock_sock = MagicMock()
        mock_conn.return_value.__enter__.return_value = mock_sock

        with patch("ssl.create_default_context") as mock_ctx:
            mock_ssock = MagicMock()
            mock_ssock.getpeercert.return_value = der_bytes
            mock_ssock.version.return_value = "TLSv1.3"
            mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
            mock_ctx.return_value.wrap_socket.return_value.__enter__.return_value = mock_ssock

            res = mod._fetch_and_parse_cert("test.local", 443, "scan-tls-1", findings, entities, relationships)

            assert res["is_self_signed"] is True
            assert res["hostname_matches"] is True
            assert any("Self-Signed" in f["title"] for f in findings)
            assert any(e["type"] == "certificate" for e in entities)
            assert any(r["type"] == "has_certificate" for r in relationships)


def test_cert_inspection_untrusted_root():
    mod = TlsValidationModule()
    der_bytes = generate_test_cert("phish-target.com", ["phish-target.com"], days_valid=60, self_signed=False, issuer_cn="Rogue CA Ltd")

    findings = []
    entities = []
    relationships = []

    # Verified handshake fails with SSLCertVerificationError, probe connection extracts DER cert
    with patch("socket.create_connection") as mock_conn:
        mock_sock = MagicMock()
        mock_conn.return_value.__enter__.return_value = mock_sock

        with patch("ssl.create_default_context") as mock_ctx:
            verify_err = ssl.SSLCertVerificationError(19, "self-signed certificate in certificate chain")
            mock_ctx.return_value.wrap_socket.side_effect = verify_err

            with patch.object(mod, "_probe_unverified_cert", return_value=(der_bytes, "TLSv1.3", ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256))):
                res = mod._fetch_and_parse_cert("phish-target.com", 443, "scan-untrusted-1", findings, entities, relationships)

                assert res["status"] == "unhealthy"
                assert res["chain_valid"] is False
                assert res["is_self_signed"] is False
                assert res["is_untrusted_ca"] is True
                assert res["is_unverified_fallback"] is True
                assert "(UNVERIFIED)" in res["certificate_type"]
                assert any("Untrusted TLS Certificate Authority" in f["title"] for f in findings)
                assert any("Raw Certificate Retrieved via Unverified Forensic Fallback" in f["title"] for f in findings)


def test_cert_inspection_expired():
    mod = TlsValidationModule()
    # Negative days = expired
    der_bytes = generate_test_cert("expired.example.com", ["expired.example.com"], days_valid=-2, self_signed=False)

    findings = []
    entities = []
    relationships = []

    with patch("socket.create_connection") as mock_conn:
        mock_sock = MagicMock()
        mock_conn.return_value.__enter__.return_value = mock_sock

        with patch("ssl.create_default_context") as mock_ctx:
            mock_ssock = MagicMock()
            mock_ssock.getpeercert.return_value = der_bytes
            mock_ssock.version.return_value = "TLSv1.2"
            mock_ssock.cipher.return_value = ("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2", 256)
            mock_ctx.return_value.wrap_socket.return_value.__enter__.return_value = mock_ssock

            res = mod._fetch_and_parse_cert("expired.example.com", 443, "scan-tls-2", findings, entities, relationships)

            assert res["is_expired"] is True
            assert any("Expired" in f["title"] for f in findings)


def test_cert_inspection_hostname_mismatch():
    mod = TlsValidationModule()
    der_bytes = generate_test_cert("legit.com", ["legit.com", "www.legit.com"], days_valid=45, self_signed=False)

    findings = []
    entities = []
    relationships = []

    with patch("socket.create_connection") as mock_conn:
        mock_sock = MagicMock()
        mock_conn.return_value.__enter__.return_value = mock_sock

        with patch("ssl.create_default_context") as mock_ctx:
            mock_ssock = MagicMock()
            mock_ssock.getpeercert.return_value = der_bytes
            mock_ssock.version.return_value = "TLSv1.3"
            mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
            mock_ctx.return_value.wrap_socket.return_value.__enter__.return_value = mock_ssock

            res = mod._fetch_and_parse_cert("attacker.com", 443, "scan-mismatch-1", findings, entities, relationships)

            assert res["status"] == "unhealthy"
            assert res["hostname_matches"] is False
            assert any("TLS Hostname Mismatch" in f["title"] for f in findings)


def test_connection_failure_and_timeout():
    mod = TlsValidationModule()
    findings = []
    entities = []
    relationships = []

    with patch("socket.create_connection", side_effect=TimeoutError("Connection timed out")):
        res = mod._fetch_and_parse_cert("unreachable.test", 443, "scan-timeout-1", findings, entities, relationships)

        assert res["status"] == "unavailable"
        assert res["chain_valid"] is False
        assert res["certificate_type"] is None
        assert res["tls_version"] is None
        assert res["is_unverified_fallback"] is False
        fail_finding = next(f for f in findings if "TLS/HTTPS Connection Failed" in f["title"])
        assert fail_finding["severity"] == "info"


def test_port_443_unavailability_does_not_inflate_phishing_risk():
    from app.scanner.modules.risk_scoring import calculate_explainable_risk

    mod = TlsValidationModule()
    findings = []
    entities = []
    relationships = []

    with patch("socket.create_connection", side_effect=ConnectionRefusedError("Connection refused on port 443")):
        mod._fetch_and_parse_cert("offline-server.org", 443, "scan-port443-down", findings, entities, relationships)

    risk_result = calculate_explainable_risk(findings)
    # Merely having port 443 closed must NOT produce a high or critical phishing risk score
    assert risk_result["risk_level"] in ("none", "low")
    assert risk_result["risk_score"] < 5.0


def test_frontend_and_flight_recorder_contract_harmony():
    mod = TlsValidationModule()
    der_bytes = generate_test_cert("portal.secure.org", ["portal.secure.org", "api.secure.org"], days_valid=60, self_signed=False, issuer_org="GlobalTrust Inc")

    findings = []
    entities = []
    relationships = []

    with patch("socket.create_connection") as mock_conn:
        mock_sock = MagicMock()
        mock_conn.return_value.__enter__.return_value = mock_sock

        with patch("ssl.create_default_context") as mock_ctx:
            mock_ssock = MagicMock()
            mock_ssock.getpeercert.return_value = der_bytes
            mock_ssock.version.return_value = "TLSv1.3"
            mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
            mock_ctx.return_value.wrap_socket.return_value.__enter__.return_value = mock_ssock

            res = mod._fetch_and_parse_cert("portal.secure.org", 443, "scan-contract-1", findings, entities, relationships)

            # Frontend required properties
            assert res["common_name"] == "portal.secure.org"
            assert res["issuer"] == "GlobalTrust Inc"
            assert isinstance(res["issuer"], str)
            assert res["tls_version"] == "TLSv1.3"
            assert res["cipher_suite"] == "TLS_AES_256_GCM_SHA384"
            assert "not_before" in res and "not_after" in res
            assert res["days_to_expiration"] > 0
            assert "sha256_fingerprint" in res
            assert len(res["subject_alt_names"]) == 2

            # Legacy and flight recorder compatibility
            assert res["fingerprint_sha256"] == res["sha256_fingerprint"]
            assert res["valid_to"] == res["not_after"]
            assert res["days_remaining"] == res["days_to_expiration"]
            assert res["sans"] == res["subject_alt_names"]
            assert res["subject"]["common_name"] == res["common_name"]


@pytest.mark.anyio
async def test_tls_module_execute_http_scheme():
    mod = TlsValidationModule()
    with patch("socket.create_connection", side_effect=ConnectionRefusedError("Connection refused")):
        result = await mod.execute("http://insecure.test", "insecure.test", "scan-tls-3")

        assert "findings" in result
        assert any(f["title"] == "Plain HTTP Scheme Specified" for f in result["findings"])
        assert any(f["title"] == "TLS/HTTPS Connection Failed" for f in result["findings"])


def test_tls_brand_impersonation_detection():
    mod = TlsValidationModule()
    der_bytes = generate_test_cert("red-whatsapp.com", ["red-whatsapp.com"], days_valid=90, self_signed=False, issuer_org="Let's Encrypt")

    findings = []
    entities = []
    relationships = []

    with patch("socket.create_connection") as mock_conn:
        mock_sock = MagicMock()
        mock_conn.return_value.__enter__.return_value = mock_sock
        with patch("ssl.create_default_context") as mock_ctx:
            mock_ssock = MagicMock()
            mock_ssock.getpeercert.return_value = der_bytes
            mock_ssock.version.return_value = "TLSv1.3"
            mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
            mock_ctx.return_value.wrap_socket.return_value.__enter__.return_value = mock_ssock

            res = mod._fetch_and_parse_cert("red-whatsapp.com", 443, "scan-impersonate-1", findings, entities, relationships)

            # Impersonation detection
            assert res["domain_impersonation"]["brand_detected"] == "whatsapp"
            assert res["domain_impersonation"]["is_official_domain"] is False
            assert "disclaimer" in res["domain_impersonation"]
            assert any("Potential Brand Impersonation" in f["title"] for f in findings)


def test_tls_security_assessment_seven_dimensions_and_summary():
    mod = TlsValidationModule()
    der_bytes = generate_test_cert("secure.portal.org", ["secure.portal.org"], days_valid=90, self_signed=False, issuer_org="DigiCert Inc")

    findings = []
    entities = []
    relationships = []

    with patch("socket.create_connection") as mock_conn:
        mock_sock = MagicMock()
        mock_conn.return_value.__enter__.return_value = mock_sock
        with patch("ssl.create_default_context") as mock_ctx:
            mock_ssock = MagicMock()
            mock_ssock.getpeercert.return_value = der_bytes
            mock_ssock.version.return_value = "TLSv1.3"
            mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
            mock_ctx.return_value.wrap_socket.return_value.__enter__.return_value = mock_ssock

            res = mod._fetch_and_parse_cert("secure.portal.org", 443, "scan-dims-1", findings, entities, relationships)

            # 7-dimension security assessment verification
            dims = res["security_assessment_dimensions"]
            assert len(dims) == 7
            dim_ids = [d["id"] for d in dims]
            assert "validity" in dim_ids
            assert "chain_trust" in dim_ids
            assert "domain_matching" in dim_ids
            assert "cryptography" in dim_ids
            assert "expiration_risk" in dim_ids
            assert "transparency" in dim_ids
            assert "anomalies" in dim_ids

            # Investigation summary 3 dimensions
            summary = res["investigation_summary"]
            assert "certificate_health" in summary
            assert "domain_identity" in summary
            assert "website_trust" in summary
            assert summary["certificate_health"]["status"] == "Healthy"
            assert summary["domain_identity"]["status"] == "Aligned"

            # Cryptographic details
            assert res["cryptography"]["public_key_algorithm"] == "RSA"
            assert res["cryptography"]["public_key_size"] == 2048

