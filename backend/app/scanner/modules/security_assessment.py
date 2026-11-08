"""
PHANTOM Security Assessment Module
Audits HTTP response headers, security hygiene (HSTS, CSP, X-Frame-Options, etc.),
and inspects HTML DOM for credential harvesting forms, external actions, and evasion tricks.
"""
import asyncio
import logging
import re
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse, urljoin
import uuid

import httpx
from bs4 import BeautifulSoup
from app.models.entity import EntityType, RelationshipType
from app.models.finding import FindingCategory, Severity
from app.scanner.orchestrator import ModuleInterface

logger = logging.getLogger("phantom.scanner.modules.security_assessment")
SCANNER_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) PHANTOM-Threat-Scanner/1.0"


def _add_finding(findings: list, scan_id: str, title: str, desc: str, severity: Severity, conf: float, evidence: dict, rec: str, cat: FindingCategory = FindingCategory.SECURITY_HEADERS):
    findings.append({
        "finding_id": str(uuid.uuid4()), "scan_id": scan_id, "module": "security_assessment",
        "category": cat.value if hasattr(cat, "value") else cat,
        "title": title, "description": desc,
        "severity": severity.value if hasattr(severity, "value") else severity,
        "confidence": conf, "evidence": evidence, "recommendation": rec,
        "created_at": datetime.utcnow(),
    })


class SecurityAssessmentModule(ModuleInterface):
    name = "security_assessment"
    description = "HTTP security headers audit, DOM credential form analysis, and redirect tracing"
    version = "1.0.0"

    async def execute(self, target_url: str, hostname: str, scan_id: str, **kwargs) -> dict:
        logger.info("Executing security assessment for %s (scan %s)", hostname, scan_id)
        findings, entities, relationships = [], [], []
        domain_entity_id = str(uuid.uuid4())
        now = datetime.utcnow()
        entities.append({"entity_id": domain_entity_id, "type": EntityType.DOMAIN.value, "value": hostname, "metadata": {"hostname": hostname}, "first_seen": now, "last_seen": now, "scan_ids": [scan_id]})

        http_data = await self._fetch_and_audit(target_url, hostname, scan_id, domain_entity_id, findings, entities, relationships)
        return {"data": http_data, "findings": findings, "entities": entities, "relationships": relationships}

    async def _fetch_and_audit(self, target_url: str, hostname: str, scan_id: str, domain_entity_id: str, findings: list, entities: list, relationships: list) -> dict:
        headers = {"User-Agent": SCANNER_USER_AGENT, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
        redirect_chain = []

        try:
            async with httpx.AsyncClient(headers=headers, timeout=httpx.Timeout(8.0, connect=5.0), follow_redirects=True, max_redirects=5, verify=False) as client:
                response = await client.get(target_url)
                for r in response.history:
                    redirect_chain.append(str(r.url))
                final_url = str(response.url)
        except Exception as e:
            logger.warning("HTTP request to %s failed: %s", target_url, e)
            _add_finding(findings, scan_id, "Website Inaccessible or Refused Connection", f"Could not retrieve webpage content from {target_url} ({type(e).__name__}: {str(e)}).", Severity.LOW, 0.85, {"target_url": target_url, "error": str(e)}, "Check if the website is online and not restricting automated scanning.", FindingCategory.CONTENT_ANALYSIS)
            return {"status": "inaccessible", "error": str(e)}

        status_code = response.status_code
        response_headers = {k.lower(): v for k, v in response.headers.items()}
        is_https = str(response.url).startswith("https://")

        if redirect_chain:
            final_host = urlparse(final_url).hostname or ""
            if final_host.lower() != hostname.lower():
                dest_id, now = str(uuid.uuid4()), datetime.utcnow()
                entities.append({"entity_id": dest_id, "type": EntityType.DOMAIN.value, "value": final_host, "metadata": {"redirected_from": hostname}, "first_seen": now, "last_seen": now, "scan_ids": [scan_id]})
                relationships.append({"relationship_id": str(uuid.uuid4()), "source_entity_id": domain_entity_id, "target_entity_id": dest_id, "type": RelationshipType.REDIRECTS_TO.value, "scan_id": scan_id, "confidence": 1.0, "metadata": {"redirect_chain": redirect_chain, "final_url": final_url}, "created_at": now})
                _add_finding(findings, scan_id, "Cross-Domain Redirect Detected", f"Initial target redirected across domain boundaries to '{final_host}'.", Severity.MEDIUM, 0.90, {"initial_host": hostname, "final_host": final_host, "chain": redirect_chain}, "Examine destination domain for unauthorized redirection.", FindingCategory.URL_ANALYSIS)

        header_audit = self._audit_security_headers(response_headers, is_https, scan_id, findings)
        dom_audit = self._analyze_html_dom(response.text, final_url, hostname, is_https, scan_id, findings)

        return {"status_code": status_code, "final_url": final_url, "redirect_chain": redirect_chain, "headers_audit": header_audit, "dom_analysis": dom_audit}

    def _audit_security_headers(self, headers: dict, is_https: bool, scan_id: str, findings: list) -> dict:
        results = {}
        hsts, csp, xfo, xcto, ref_pol = headers.get("strict-transport-security"), headers.get("content-security-policy"), headers.get("x-frame-options"), headers.get("x-content-type-options"), headers.get("referrer-policy")
        results["hsts"], results["csp"], results["x_frame_options"], results["x_content_type_options"], results["referrer_policy"] = bool(hsts), bool(csp), bool(xfo), bool(xcto), bool(ref_pol)

        if is_https and not hsts:
            _add_finding(findings, scan_id, "Missing HTTP Strict Transport Security (HSTS)", "The web server does not enforce HTTPS via HSTS, making clients vulnerable to SSL-stripping attacks.", Severity.MEDIUM, 1.0, {"header": "Strict-Transport-Security"}, "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to response headers.")

        if not csp:
            _add_finding(findings, scan_id, "Missing Content-Security-Policy (CSP)", "Content-Security-Policy header is missing. The site lacks defense-in-depth against XSS and data injection.", Severity.LOW, 1.0, {"header": "Content-Security-Policy"}, "Configure a Content-Security-Policy restricting unauthorized script execution.")
        elif any(k in csp for k in ("unsafe-inline", "unsafe-eval", "*")):
            _add_finding(findings, scan_id, "Permissive Content-Security-Policy (CSP) Directives", "CSP contains 'unsafe-inline', 'unsafe-eval', or wildcards, reducing effectiveness against XSS.", Severity.LOW, 0.80, {"csp_snippet": csp[:200]}, "Use CSP nonces or hashes instead of 'unsafe-inline'.")

        if not xfo and not (csp and "frame-ancestors" in (csp or "")):
            _add_finding(findings, scan_id, "Missing Anti-Clickjacking Header (X-Frame-Options)", "Neither X-Frame-Options nor CSP frame-ancestors is configured, allowing framing and clickjacking attacks.", Severity.LOW, 1.0, {"header": "X-Frame-Options"}, "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent clickjacking.")

        if not xcto or "nosniff" not in xcto.lower():
            _add_finding(findings, scan_id, "Missing X-Content-Type-Options Header", "X-Content-Type-Options is not set to 'nosniff', permitting MIME-type sniffing vulnerabilities.", Severity.LOW, 1.0, {"header": "X-Content-Type-Options"}, "Add 'X-Content-Type-Options: nosniff' header.")

        if not ref_pol or "unsafe-url" in ref_pol.lower():
            _add_finding(findings, scan_id, "Missing or Weak Referrer-Policy", "Referrer-Policy header is missing or configured with 'unsafe-url', risking URL credential leakage.", Severity.INFO, 1.0, {"referrer_policy": ref_pol}, "Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.")

        server_h, powered_by = headers.get("server"), headers.get("x-powered-by")
        if (server_h and re.search(r"\d+\.\d+", server_h)) or powered_by:
            _add_finding(findings, scan_id, "Detailed Server / Technology Version Disclosure", f"HTTP headers leak specific software versions: Server={server_h}, X-Powered-By={powered_by}.", Severity.LOW, 0.90, {"server": server_h, "x_powered_by": powered_by}, "Disable detailed technology banner disclosure in web server configuration.")

        return results

    def _analyze_html_dom(self, html_content: str, final_url: str, hostname: str, is_https: bool, scan_id: str, findings: list) -> dict:
        if not html_content:
            return {"title": None, "forms_count": 0, "password_inputs": 0}

        try:
            soup = BeautifulSoup(html_content, "html.parser")
        except Exception as e:
            logger.debug("HTML parsing error: %s", e)
            return {"parse_error": str(e)}

        title_tag = soup.find("title")
        forms = soup.find_all("form")
        password_inputs = soup.find_all("input", attrs={"type": re.compile(r"^password$", re.I)})

        if password_inputs and not is_https:
            _add_finding(findings, scan_id, "Insecure Password Form Over Plain HTTP", "Page contains password input field(s) served over plain HTTP, exposing credentials to interception.", Severity.CRITICAL, 1.0, {"password_inputs_count": len(password_inputs), "url": final_url}, "Never collect credentials over plain HTTP. Serve all authentication pages over HTTPS.", FindingCategory.CONTENT_ANALYSIS)

        suspicious_form_actions = []
        for form in forms:
            action = form.get("action")
            if not action:
                continue
            abs_action = urljoin(final_url, action)
            action_host = urlparse(abs_action).hostname or ""

            if action_host and action_host.lower() != hostname.lower() and not action_host.lower().endswith(f".{hostname.lower()}"):
                has_pass = bool(form.find("input", attrs={"type": re.compile(r"^password$", re.I)}))
                suspicious_form_actions.append({"action": abs_action, "has_password": has_pass})
                _add_finding(findings, scan_id, "Cross-Domain Form Submission Target", f"Form action submits data to an external domain '{action_host}', a potential credential exfiltration vector.", Severity.HIGH if has_pass else Severity.MEDIUM, 0.85, {"form_action": abs_action, "contains_password_field": has_pass}, "Verify whether form targets an authorized payment processor or authentication API.", FindingCategory.CONTENT_ANALYSIS)

        meta_refresh = soup.find("meta", attrs={"http-equiv": re.compile(r"^refresh$", re.I)})
        if meta_refresh and meta_refresh.get("content"):
            _add_finding(findings, scan_id, "Client-Side Meta Refresh Redirect Detected", f"Page contains automated meta refresh redirect: '{meta_refresh.get('content')}'.", Severity.MEDIUM, 0.80, {"content": meta_refresh.get("content")}, "Inspect target destination for malicious evasion tactics.", FindingCategory.CONTENT_ANALYSIS)

        hidden_iframes = soup.find_all("iframe", style=re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden", re.I))
        if hidden_iframes:
            _add_finding(findings, scan_id, "Hidden Inline Iframe Detected", "Page contains hidden iframe element(s), often utilized for drive-by downloads or tracking.", Severity.MEDIUM, 0.75, {"hidden_iframes_count": len(hidden_iframes)}, "Investigate source of hidden iframes to ensure no malicious payloads are rendered.", FindingCategory.CONTENT_ANALYSIS)

        return {
            "title": title_tag.get_text(strip=True) if title_tag else None,
            "total_forms": len(forms), "password_inputs_count": len(password_inputs),
            "cross_domain_forms": suspicious_form_actions, "has_meta_refresh": bool(meta_refresh),
            "hidden_iframes_count": len(hidden_iframes),
        }
