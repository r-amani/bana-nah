"""
Unit tests for URL Threat Detection Module.
"""
from unittest.mock import MagicMock, patch
import pytest

from app.scanner.modules.url_detection import (
    UrlDetectionModule,
    compute_entropy,
    levenshtein_distance,
)
from app.models.finding import Severity, FindingCategory


def test_entropy_computation():
    # Uniform text has lower entropy than randomized strings
    assert compute_entropy("aaaaaa") == 0.0
    assert compute_entropy("abcdef") > compute_entropy("aabbaa")


def test_levenshtein_distance():
    assert levenshtein_distance("paypal", "paypal") == 0
    assert levenshtein_distance("paypa1", "paypal") == 1
    assert levenshtein_distance("paypaal", "paypal") == 1
    assert levenshtein_distance("google", "microsoft") > 3


def test_lexical_analysis_ip_host():
    mod = UrlDetectionModule()
    findings = []
    res = mod._analyze_lexical("http://192.168.1.1/login", "192.168.1.1", "/login", "", "scan-1", findings)
    assert res["is_ip_host"] is True
    assert any(f["title"] == "Raw IP Address Used as Hostname" for f in findings)


def test_lexical_analysis_at_symbol_and_keywords():
    mod = UrlDetectionModule()
    findings = []
    res = mod._analyze_lexical("https://user@evil.xyz/account/login", "evil.xyz", "/account/login", "", "scan-2", findings)
    assert res["is_suspicious_tld"] is True
    assert "login" in res["detected_keywords"] or "account" in res["detected_keywords"]
    assert any(f["title"] == "Embedded '@' Symbol in URL" for f in findings)
    assert any("High-Abuse Top-Level Domain" in f["title"] for f in findings)


def test_typosquatting_detection():
    mod = UrlDetectionModule()
    findings = []
    res = mod._analyze_typosquatting("paypa1-update.com", "scan-3", findings)
    assert res["targeted_brand"] == "paypal"
    assert any("Brand Typosquatting Detected" in f["title"] for f in findings)


def test_punycode_detection():
    mod = UrlDetectionModule()
    findings = []
    res = mod._analyze_typosquatting("xn--pple-43d.com", "scan-4", findings)
    assert res["is_punycode"] is True
    assert any("Punycode" in f["title"] for f in findings)


@pytest.mark.anyio
async def test_url_detection_execute_mocked_dns():
    mod = UrlDetectionModule()

    # Mock dns.resolver.Resolver
    with patch("dns.resolver.Resolver") as mock_resolver_cls:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver

        # Mock A record
        mock_a = MagicMock()
        mock_a.to_text.return_value = "93.184.216.34"
        mock_resolver.resolve.side_effect = lambda host, rtype: [mock_a] if rtype == "A" else []

        result = await mod.execute("https://paypa1.xyz/secure/login", "paypa1.xyz", "scan-100")

        assert "data" in result
        assert "findings" in result
        assert "entities" in result
        assert "relationships" in result
        assert len(result["findings"]) > 0
        assert any(e["type"] == "ip_address" for e in result["entities"])
        assert any(r["type"] == "resolves_to" for r in result["relationships"])
