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

# User-Agent for scan requests
SCANNER_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) PHANTOM-Threat-Scanner/1.0"


class SecurityAssessmentModule(ModuleInterface):
    """
    Website Security Assessment Module.
    Evaluates HTTP security headers and analyzes HTML DOM content for phishing/security risks.
    """

    name = "security_assessment"
    description = "HTTP security headers audit, DOM credential form analysis, and redirect tracing"
    version = "1.0.0"

    async def execute(self, target_url: str, hostname: str, scan_id: str, **kwargs) -> dict:
        logger.info("Executing security assessment for %s (scan %s)", hostname, scan_id)

        findings = []
        entities = []
        relationships = []

        # Domain Entity
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

        # Fetch HTTP response
        http_data = await self._fetch_and_audit(target_url, hostname, scan_id, domain_entity_id, findings, entities, relationships)

        return {
            "data": http_data,
            "findings": findings,
            "entities": entities,
            "relationships": relationships,
        }

    async def _fetch_and_audit(
        self,
        target_url: str,
        hostname: str,
        scan_id: str,
        domain_entity_id: str,
        findings: list,
        entities: list,
        relationships: list,
    ) -> dict:
        """Perform HTTP request, audit security headers, and analyze DOM."""
        headers = {
            "User-Agent": SCANNER_USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

        response = None
        redirect_chain = []

        try:
            async with httpx.AsyncClient(
                headers=headers,
                timeout=httpx.Timeout(8.0, connect=5.0),
                follow_redirects=True,
                max_redirects=5,
                verify=False,  # Permissive so we can inspect servers with self-signed certs
            ) as client:
                response = await client.get(target_url)
                # Track redirect history if any
                for r in response.history:
                    redirect_chain.append(str(r.url))
                final_url = str(response.url)
        except Exception as e:
            logger.warning("HTTP request to %s failed: %s", target_url, e)
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "module": self.name,
                "category": FindingCategory.CONTENT_ANALYSIS.value,
                "title": "Website Inaccessible or Refused Connection",
                "description": f"Could not retrieve webpage content from {target_url} ({type(e).__name__}: {str(e)}).",
                "severity": Severity.LOW.value,
                "confidence": 0.85,
                "evidence": {"target_url": target_url, "error": str(e)},
                "recommendation": "Check if the website is online and not restricting automated scanning.",
                "created_at": datetime.utcnow(),
            })
            return {"status": "inaccessible", "error": str(e)}

        status_code = response.status_code
        response_headers = {k.lower(): v for k, v in response.headers.items()}
        is_https = str(response.url).startswith("https://")

        # 1. Tracing Redirects
        if redirect_chain:
            final_parsed = urlparse(final_url)
            final_host = final_parsed.hostname or ""
            if final_host.lower() != hostname.lower():
                # Cross-domain redirect
                dest_entity_id = str(uuid.uuid4())
                entities.append({
                    "entity_id": dest_entity_id,
                    "type": EntityType.DOMAIN.value,
                    "value": final_host,
                    "metadata": {"redirected_from": hostname},
                    "first_seen": datetime.utcnow(),
                    "last_seen": datetime.utcnow(),
                    "scan_ids": [scan_id],
                })
                relationships.append({
                    "relationship_id": str(uuid.uuid4()),
                    "source_entity_id": domain_entity_id,
                    "target_entity_id": dest_entity_id,
                    "type": RelationshipType.REDIRECTS_TO.value,
                    "scan_id": scan_id,
                    "confidence": 1.0,
                    "metadata": {"redirect_chain": redirect_chain, "final_url": final_url},
                    "created_at": datetime.utcnow(),
                })

                findings.append({
                    "finding_id": str(uuid.uuid4()),
                    "scan_id": scan_id,
                    "module": self.name,
                    "category": FindingCategory.URL_ANALYSIS.value,
                    "title": "Cross-Domain Redirect Detected",
                    "description": f"Initial target redirected across domain boundaries to '{final_host}'.",
                    "severity": Severity.MEDIUM.value,
                    "confidence": 0.90,
                    "evidence": {"initial_host": hostname, "final_host": final_host, "chain": redirect_chain},
                    "recommendation": "Examine the destination domain to determine whether it is an unauthorized redirect.",
                    "created_at": datetime.utcnow(),
                })

        # 2. Audit Security Headers
        header_audit = self._audit_security_headers(response_headers, is_https, scan_id, findings)

        # 3. Analyze DOM Content
        dom_audit = self._analyze_html_dom(response.text, final_url, hostname, is_https, scan_id, findings)

        return {
            "status_code": status_code,
            "final_url": final_url,
            "redirect_chain": redirect_chain,
            "headers_audit": header_audit,
            "dom_analysis": dom_audit,
        }

    def _audit_security_headers(self, headers: dict, is_https: bool, scan_id: str, findings: list) -> dict:
        """Evaluate key defense-in-depth HTTP security headers."""
        results = {}

        # 1. HSTS (Strict-Transport-Security)
        hsts = headers.get("strict-transport-security")
        results["hsts"] = bool(hsts)
        if is_https and not hsts:
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "module": self.name,
                "category": FindingCategory.SECURITY_HEADERS.value,
                "title": "Missing HTTP Strict Transport Security (HSTS)",
                "description": "The web server does not enforce HTTPS via HSTS, making clients vulnerable to SSL-stripping attacks.",
                "severity": Severity.MEDIUM.value,
                "confidence": 1.0,
                "evidence": {"header": "Strict-Transport-Security"},
                "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to response headers.",
                "created_at": datetime.utcnow(),
            })

        # 2. CSP (Content-Security-Policy)
        csp = headers.get("content-security-policy")
        results["csp"] = bool(csp)
        if not csp:
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "module": self.name,
                "category": FindingCategory.SECURITY_HEADERS.value,
                "title": "Missing Content-Security-Policy (CSP)",
                "description": "Content-Security-Policy header is missing. The site lacks defense-in-depth against XSS and data injection.",
                "severity": Severity.LOW.value,
                "confidence": 1.0,
                "evidence": {"header": "Content-Security-Policy"},
                "recommendation": "Configure a Content-Security-Policy restricting unauthorized script execution and object sources.",
                "created_at": datetime.utcnow(),
            })
        elif "unsafe-inline" in csp or "unsafe-eval" in csp or "*" in csp:
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "module": self.name,
                "category": FindingCategory.SECURITY_HEADERS.value,
                "title": "Permissive Content-Security-Policy (CSP) Directives",
                "description": "CSP contains 'unsafe-inline', 'unsafe-eval', or wildcards, reducing effectiveness against XSS.",
                "severity": Severity.LOW.value,
                "confidence": 0.80,
                "evidence": {"csp_snippet": csp[:200]},
                "recommendation": "Use CSP nonces or hashes instead of 'unsafe-inline' and avoid wildcard script sources.",
                "created_at": datetime.utcnow(),
            })

        # 3. X-Frame-Options
        xfo = headers.get("x-frame-options")
        results["x_frame_options"] = bool(xfo)
        if not xfo and not (csp and "frame-ancestors" in (csp or "")):
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "module": self.name,
                "category": FindingCategory.SECURITY_HEADERS.value,
                "title": "Missing Anti-Clickjacking Header (X-Frame-Options)",
                "description": "Neither X-Frame-Options nor CSP frame-ancestors is configured, allowing framing and clickjacking attacks.",
                "severity": Severity.LOW.value,
                "confidence": 1.0,
                "evidence": {"header": "X-Frame-Options"},
                "recommendation": "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent clickjacking.",
                "created_at": datetime.utcnow(),
            })

        # 4. X-Content-Type-Options
        xcto = headers.get("x-content-type-options")
        results["x_content_type_options"] = bool(xcto)
        if not xcto or "nosniff" not in xcto.lower():
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "module": self.name,
                "category": FindingCategory.SECURITY_HEADERS.value,
                "title": "Missing X-Content-Type-Options Header",
                "description": "X-Content-Type-Options is not set to 'nosniff', permitting MIME-type sniffing vulnerabilities.",
                "severity": Severity.LOW.value,
                "confidence": 1.0,
                "evidence": {"header": "X-Content-Type-Options"},
                "recommendation": "Add 'X-Content-Type-Options: nosniff' header.",
                "created_at": datetime.utcnow(),
            })

        # 5. Referrer-Policy
        ref_pol = headers.get("referrer-policy")
        results["referrer_policy"] = bool(ref_pol)
        if not ref_pol or "unsafe-url" in ref_pol.lower():
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "module": self.name,
                "category": FindingCategory.SECURITY_HEADERS.value,
                "title": "Missing or Weak Referrer-Policy",
                "description": "Referrer-Policy header is missing or configured with 'unsafe-url', risking URL credential leakage.",
                "severity": Severity.INFO.value,
                "confidence": 1.0,
                "evidence": {"referrer_policy": ref_pol},
                "recommendation": "Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
                "created_at": datetime.utcnow(),
            })

        # 6. Server Version Leakage
        server_header = headers.get("server")
        powered_by = headers.get("x-powered-by")
        if (server_header and re.search(r"\d+\.\d+", server_header)) or powered_by:
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "module": self.name,
                "category": FindingCategory.SECURITY_HEADERS.value,
                "title": "Detailed Server / Technology Version Disclosure",
                "description": f"HTTP headers leak specific software versions: Server={server_header}, X-Powered-By={powered_by}.",
                "severity": Severity.LOW.value,
                "confidence": 0.90,
                "evidence": {"server": server_header, "x_powered_by": powered_by},
                "recommendation": "Disable detailed technology banner disclosure in web server configuration.",
                "created_at": datetime.utcnow(),
            })

        return results

    def _analyze_html_dom(self, html_content: str, final_url: str, hostname: str, is_https: bool, scan_id: str, findings: list) -> dict:
        """Inspect HTML DOM for credential harvesting forms and evasion tricks."""
        if not html_content:
            return {"title": None, "forms_count": 0, "password_inputs": 0}

        try:
            soup = BeautifulSoup(html_content, "html.parser")
        except Exception as e:
            logger.debug("HTML parsing error: %s", e)
            return {"parse_error": str(e)}

        title_tag = soup.find("title")
        page_title = title_tag.get_text(strip=True) if title_tag else None

        forms = soup.find_all("form")
        password_inputs = soup.find_all("input", attrs={"type": re.compile(r"^password$", re.I)})

        # Check if password input is present on an unencrypted HTTP page
        if password_inputs and not is_https:
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "module": self.name,
                "category": FindingCategory.CONTENT_ANALYSIS.value,
                "title": "Insecure Password Form Over Plain HTTP",
                "description": "Page contains password input field(s) served over plain HTTP, exposing credentials to interception.",
                "severity": Severity.CRITICAL.value,
                "confidence": 1.0,
                "evidence": {"password_inputs_count": len(password_inputs), "url": final_url},
                "recommendation": "Never collect credentials over plain HTTP. Serve all authentication pages over HTTPS.",
                "created_at": datetime.utcnow(),
            })

        # Form action analysis
        suspicious_form_actions = []
        for form in forms:
            action = form.get("action")
            if not action:
                continue
            abs_action = urljoin(final_url, action)
            parsed_action = urlparse(abs_action)
            action_host = parsed_action.hostname or ""

            # Check for cross-domain form actions
            if action_host and action_host.lower() != hostname.lower() and not action_host.lower().endswith(f".{hostname.lower()}"):
                has_pass = bool(form.find("input", attrs={"type": re.compile(r"^password$", re.I)}))
                suspicious_form_actions.append({"action": abs_action, "has_password": has_pass})

                severity = Severity.HIGH.value if has_pass else Severity.MEDIUM.value
                findings.append({
                    "finding_id": str(uuid.uuid4()),
                    "scan_id": scan_id,
                    "module": self.name,
                    "category": FindingCategory.CONTENT_ANALYSIS.value,
                    "title": "Cross-Domain Form Submission Target",
                    "description": f"Form action submits data to an external domain '{action_host}', a potential credential exfiltration vector.",
                    "severity": severity,
                    "confidence": 0.85,
                    "evidence": {"form_action": abs_action, "contains_password_field": has_pass},
                    "recommendation": "Verify whether form targets an authorized payment processor or authentication API.",
                    "created_at": datetime.utcnow(),
                })

        # Check for client-side meta refresh
        meta_refresh = soup.find("meta", attrs={"http-equiv": re.compile(r"^refresh$", re.I)})
        if meta_refresh and meta_refresh.get("content"):
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "module": self.name,
                "category": FindingCategory.CONTENT_ANALYSIS.value,
                "title": "Client-Side Meta Refresh Redirect Detected",
                "description": f"Page contains automated meta refresh redirect: '{meta_refresh.get('content')}'.",
                "severity": Severity.MEDIUM.value,
                "confidence": 0.80,
                "evidence": {"content": meta_refresh.get("content")},
                "recommendation": "Inspect target destination for malicious evasion tactics.",
                "created_at": datetime.utcnow(),
            })

        # Check for hidden iframes
        hidden_iframes = soup.find_all("iframe", style=re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden", re.I))
        if hidden_iframes:
            findings.append({
                "finding_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "module": self.name,
                "category": FindingCategory.CONTENT_ANALYSIS.value,
                "title": "Hidden Inline Iframe Detected",
                "description": "Page contains hidden iframe element(s), often utilized for drive-by downloads or tracking.",
                "severity": Severity.MEDIUM.value,
                "confidence": 0.75,
                "evidence": {"hidden_iframes_count": len(hidden_iframes)},
                "recommendation": "Investigate source of hidden iframes to ensure no malicious payloads are rendered.",
                "created_at": datetime.utcnow(),
            })

        return {
            "title": page_title,
            "total_forms": len(forms),
            "password_inputs_count": len(password_inputs),
            "cross_domain_forms": suspicious_form_actions,
            "has_meta_refresh": bool(meta_refresh),
            "hidden_iframes_count": len(hidden_iframes),
        }
