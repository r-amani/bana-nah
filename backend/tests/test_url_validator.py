"""
Tests for URL validation and SSRF protection.
"""
import pytest
from app.security.url_validator import validate_url, URLValidationError, extract_hostname


def test_valid_urls():
    assert validate_url("https://example.com") == "https://example.com"
    assert validate_url("http://sub.domain.example.com/path?query=1") == "http://sub.domain.example.com/path?query=1"
    assert validate_url("example.com") == "https://example.com"


def test_extract_hostname():
    assert extract_hostname("https://sub.example.com:8080/test") == "sub.example.com"
    assert extract_hostname("https://example.com/") == "example.com"


def test_blocked_schemes():
    with pytest.raises(URLValidationError):
        validate_url("ftp://example.com")
    with pytest.raises(URLValidationError):
        validate_url("file:///etc/passwd")
    with pytest.raises(URLValidationError):
        validate_url("javascript:alert(1)")


def test_blocked_hostnames():
    with pytest.raises(URLValidationError):
        validate_url("http://localhost")
    with pytest.raises(URLValidationError):
        validate_url("http://localhost:8000")
    with pytest.raises(URLValidationError):
        validate_url("http://169.254.169.254/latest/meta-data/")
    with pytest.raises(URLValidationError):
        validate_url("http://metadata.google.internal")


def test_blocked_private_ips():
    with pytest.raises(URLValidationError):
        validate_url("http://127.0.0.1")
    with pytest.raises(URLValidationError):
        validate_url("http://10.0.0.1")
    with pytest.raises(URLValidationError):
        validate_url("http://192.168.1.1")
    with pytest.raises(URLValidationError):
        validate_url("http://172.16.0.1")
