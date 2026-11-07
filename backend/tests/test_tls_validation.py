"""
Unit tests for TLS Certificate Validation Module.
"""
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from app.scanner.modules.tls_validation import TlsValidationModule


def generate_test_cert(common_name: str, sans: list[str], days_valid: int = 30, self_signed: bool = True):
    """Generate in-memory X.509 certificate for testing."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Organization"),
    ])
    issuer = subject if self_signed else x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Test CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test CA Ltd"),
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
    # Wildcard SAN match
    assert mod._match_hostname("sub.example.com", None, ["*.example.com"]) is True
    # Hostname mismatch
    assert mod._match_hostname("malicious.com", "example.com", ["api.example.com"]) is False


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


@pytest.mark.anyio
async def test_tls_module_execute_http_scheme():
    mod = TlsValidationModule()
    # Mock handshake failure for plain HTTP
    with patch("socket.create_connection", side_effect=ConnectionRefusedError("Connection refused")):
        result = await mod.execute("http://insecure.test", "insecure.test", "scan-tls-3")

        assert "findings" in result
        assert any(f["title"] == "Plain HTTP Scheme Specified" for f in result["findings"])
        assert any(f["title"] == "TLS/HTTPS Connection Failed" for f in result["findings"])
