# PHANTOM — Engineering Progress & Architecture Report

> **Project:** PHANTOM (Phishing Detection & Digital Threat Investigation Platform)  
> **Computer 1 Role:** Backend Architect & Integration Lead (Phase 1–3 Complete)  
> **Computer 2 Role:** Threat Detection, Security Assessment & Risk Engine Lead (Phase 4–5 Complete)  
> **Repository Branch:** `develop`  
> **Latest Commit Hash:** `2b88d46`  
> **Date:** 2026-11-07  

---

## Executive Summary

- **Computer 1** established the FastAPI backend foundation, MongoDB schemas, REST endpoints, SSRF validation, and module orchestration interface.
- **Computer 2** took over on branch `develop`, verified the existing foundation, and fully implemented all assigned detection, assessment, and risk scoring modules:
  1. `url_detection` (lexical heuristics, Punycode homographs, brand typosquatting, DNS resolution).
  2. `tls_validation` (certificate extraction, expiry/SAN/self-signed validation, CA graph nodes).
  3. `security_assessment` (security headers audit, DOM credential form analysis, redirect tracing).
  4. `risk_scoring` (explainable multi-factor scoring engine with factor breakdowns and remediation guidance).
- All modules are registered in `backend/app/main.py` and integrated into `app/scanner/orchestrator.py`.
- Comprehensive test coverage expanded from 11 tests to **32 tests**, achieving a **100% pass rate**.
- The repository is fully prepared for **Computer 3** to implement Intelligence and Investigation Graph capabilities.

---

## 1. Directory Structure

```
phantom/
├── .gitignore                          # Standard git ignore rules for Python, Node, data
├── PHANTOM_API_CONTRACT.md             # Formal REST API contracts for all endpoints
├── PHANTOM_DATABASE_SCHEMA.md          # Complete MongoDB schema, index, and model documentation
├── PHANTOM_BACKEND_SETUP.md            # Onboarding and startup guide for teammates
├── PHANTOM_WORK_DONE.md                # Comprehensive log of architecture & work completed
└── backend/
    ├── .env.example                    # Environment variable template with safe defaults
    ├── requirements.txt                # Production backend dependencies
    ├── app/
    │   ├── __init__.py
    │   ├── main.py                     # FastAPI app with all modules & routers registered
    │   ├── config.py                   # Pydantic BaseSettings environment manager
    │   ├── database.py                 # Async Motor MongoDB manager with index generation
    │   ├── models/                     # Shared Pydantic schemas and database models
    │   │   ├── __init__.py
    │   │   ├── scan.py                 # ScanRequest, ScanResponse, ScanDocument, ModuleResult
    │   │   ├── finding.py              # FindingDocument, FindingResponse, Severity, FindingCategory
    │   │   ├── report.py               # ReportRequest, ReportResponse, ReportDocument, ReportStatus
    │   │   └── entity.py               # EntityDocument, RelationshipDocument, GraphResponse
    │   ├── routers/                    # Cleanly separated FastAPI routers
    │   │   ├── __init__.py
    │   │   ├── health.py               # GET /health
    │   │   ├── scans.py                # POST /api/scans, GET /api/scans/{id}, GET /api/scans/{id}/findings
    │   │   ├── domains.py              # GET /api/domains/{host}/history, GET /api/domains/{host}/compare
    │   │   ├── reports.py              # POST /api/reports, GET /api/reports, PATCH /api/reports/{id}
    │   │   ├── entities.py             # GET /api/entities/{id}/relationships
    │   │   └── graph.py                # GET /api/graph
    │   ├── scanner/                    # Central orchestration pipeline
    │   │   ├── __init__.py
    │   │   ├── orchestrator.py         # Multi-module concurrent executor with risk evaluation
    │   │   └── modules/                # Plug-in detection & analysis modules
    │   │       ├── __init__.py
    │   │       ├── placeholder.py      # Pipeline validation placeholder (Computer 1)
    │   │       ├── url_detection.py    # URL lexical & homograph threat detection (Computer 2)
    │   │       ├── tls_validation.py   # TLS certificate validation & cryptography (Computer 2)
    │   │       ├── security_assessment.py # Headers & DOM security assessment (Computer 2)
    │   │       └── risk_scoring.py     # Explainable risk scoring engine (Computer 2)
    │   └── security/                   # Hardened security controls
    │       ├── __init__.py
    │       └── url_validator.py        # Strict URL validation, SSRF defense, DNS resolution checks
    └── tests/                          # 32 unit and integration tests
        ├── __init__.py
        ├── test_url_validator.py       # SSRF blocking, RFC 1918 filter tests (5 tests)
        ├── test_models.py              # Schema validation & serialization tests (4 tests)
        ├── test_orchestrator.py        # Orchestration & registration tests (3 tests)
        ├── test_url_detection.py       # URL lexical, typosquatting & DNS tests (7 tests)
        ├── test_tls_validation.py      # TLS expiry, SAN, self-signed tests (4 tests)
        ├── test_security_assessment.py # Headers & DOM analysis tests (5 tests)
        └── test_risk_scoring.py        # Multi-factor scoring engine tests (4 tests)
```

---

## 2. Work Completed by Computer 2

### 1. `url_detection` Module (`app/scanner/modules/url_detection.py`)
- **Lexical & Structural Heuristics**:
  - Shannon entropy computation on hostnames to flag algorithmically generated domains (DGA).
  - Suspicious TLD detection across high-abuse extensions (`.xyz`, `.top`, `.buzz`, `.click`, `.loan`, etc.).
  - Raw IP address as hostname detection.
  - Credential injection & URL obfuscation detection (embedded `@` symbol).
  - Subdomain nesting depth tracking (>3 dots).
  - Targeted credential keyword detection (`login`, `verify`, `account`, `banking`, `wallet`, etc.).
- **Homoglyph & Brand Typosquatting**:
  - Punycode detection (`xn--` prefix) for visual spoofing.
  - Levenshtein edit distance analysis with tokenized label splitting against high-value brands (`paypal`, `google`, `microsoft`, `apple`, `amazon`, `binance`, `chase`, etc.).
- **DNS Resolution & Network Graph**:
  - Resolves A, CNAME, MX, and NS records via `dnspython`.
  - Flags domains lacking active A records.
  - Emits graph entities (`url`, `domain`, `ip_address`, `nameserver`) and relationships (`resolves_to`, `uses_nameserver`).

### 2. `tls_validation` Module (`app/scanner/modules/tls_validation.py`)
- **Certificate Extraction & Parsing**:
  - Non-blocking socket handshake on port 443 with strict timeout.
  - X.509 DER parsing via Python `cryptography` library.
  - Timezone-aware expiration evaluation (`not_valid_before_utc`, `not_valid_after_utc`).
- **Cryptographic & Operational Checks**:
  - Immediate `CRITICAL` finding for expired certificates.
  - `MEDIUM` finding for certificates expiring within 14 days.
  - Hostname matching against Common Name (CN) and Subject Alternative Names (SANs) with wildcard (`*.domain.com`) matching support.
  - Self-signed certificate identification (`issuer == subject`).
  - Weak signature algorithm flagging (`MD5`, `SHA1`).
  - Unencrypted plain HTTP detection.
- **Graph Generation**:
  - Emits `certificate` entity with SHA-256 fingerprint, serial, and SAN metadata.
  - Emits `organization` entity for Certificate Authorities.
  - Emits `has_certificate` and `issued_by` relationships.

### 3. `security_assessment` Module (`app/scanner/modules/security_assessment.py`)
- **HTTP Transport & Redirect Tracing**:
  - Async fetching via `httpx` with safe redirect tracking (up to 5 redirects).
  - Cross-domain redirect detection emitting `redirects_to` graph relationships.
- **Security Headers Audit**:
  - `Strict-Transport-Security` (HSTS) validation on HTTPS endpoints.
  - `Content-Security-Policy` (CSP) evaluation, checking for missing CSP or dangerous wildcards/`unsafe-inline`/`unsafe-eval`.
  - `X-Frame-Options` and anti-clickjacking audit.
  - `X-Content-Type-Options` MIME-sniffing prevention check.
  - `Referrer-Policy` leakage check.
  - Server and framework banner disclosure detection (`Server`, `X-Powered-By`).
- **DOM Content & Credential Harvesting Heuristics**:
  - Detects password fields submitted over plain HTTP (`CRITICAL`).
  - Detects cross-domain form submission targets where forms send data to external third-party hosts (`HIGH`/`CRITICAL`).
  - Identifies client-side `<meta http-equiv="refresh">` evasions.
  - Flags hidden iframes (`display:none`, `visibility:hidden`).

### 4. `risk_scoring` Module (`app/scanner/modules/risk_scoring.py`)
- **Explainable Multi-Factor Risk Algorithm**:
  - Severity weights: Critical (25.0), High (15.0), Medium (8.0), Low (3.0), Info (0.5), scaled by module confidence (0.0–1.0).
  - Domain-specific score breakdowns:
    - `url_threats`
    - `tls_vulnerabilities`
    - `content_and_headers`
    - `other`
  - Normalized 0–100 risk score and mapped tiers (`none`, `low`, `medium`, `high`, `critical`).
  - Automatic extraction of the top 5 risk drivers with severity labels.
  - Deduplicated, actionable remediation recommendations.

### 5. Application & Orchestrator Integration
- Registered all 4 new modules alongside `PlaceholderModule` in `backend/app/main.py`.
- Enhanced `ScanOrchestrator` (`app/scanner/orchestrator.py`) to run detection modules concurrently and feed aggregated findings directly into `risk_scoring`.

---

## 3. Files Created or Modified by Computer 2

| File Path | Action | Description |
|---|---|---|
| `backend/app/scanner/modules/url_detection.py` | Created | URL lexical heuristics, typosquatting & DNS analysis |
| `backend/app/scanner/modules/tls_validation.py` | Created | TLS certificate validation & cryptography checks |
| `backend/app/scanner/modules/security_assessment.py` | Created | Security headers audit & DOM analysis |
| `backend/app/scanner/modules/risk_scoring.py` | Created | Explainable risk scoring engine |
| `backend/app/scanner/modules/__init__.py` | Modified | Exported all new modules |
| `backend/app/main.py` | Modified | Registered all 4 detection/risk modules |
| `backend/app/scanner/orchestrator.py` | Modified | Linked aggregated findings into `risk_scoring` |
| `backend/tests/test_url_detection.py` | Created | 7 unit tests for URL heuristics, typosquatting & DNS |
| `backend/tests/test_tls_validation.py` | Created | 4 unit tests for TLS certificate validation |
| `backend/tests/test_security_assessment.py` | Created | 5 unit tests for headers & DOM analysis |
| `backend/tests/test_risk_scoring.py` | Created | 4 unit tests for explainable risk scoring |
| `backend/tests/test_orchestrator.py` | Modified | Added 5-module orchestrator registration test |
| `PHANTOM_WORK_DONE.md` | Modified | Handover and engineering progress documentation |

---

## 4. Test Suite Verification & Results

- **Test Framework**: `pytest 9.2.0` with `anyio 4.16.0`
- **Total Tests**: 32
- **Passed**: 32 (100% pass rate)
- **Execution Time**: ~1.7 seconds

```
tests/test_models.py .............. 4 passed
tests/test_orchestrator.py ........ 3 passed
tests/test_risk_scoring.py ........ 4 passed
tests/test_security_assessment.py . 5 passed
tests/test_tls_validation.py ...... 4 passed
tests/test_url_detection.py ....... 7 passed
tests/test_url_validator.py ....... 5 passed
======================= 32 passed in 1.66s =======================
```

---

## 5. Outstanding Issues

- **None**: All 32 unit and integration tests pass cleanly without errors.
- **Dependencies**: `pytest` was installed in `backend/venv` for the test runner. Production requirements remain pinned in `requirements.txt`.

---

## 6. Handover for Computer 3 (Intelligence & Graph Modules)

Computer 3 is responsible for Phase 6 (Threat Intelligence & Investigation Graph):

### 1. Reserved Modules for Computer 3:
Per [PHANTOM_API_CONTRACT.md](PHANTOM_API_CONTRACT.md):
- `community_intelligence.py` (`name = "community_intelligence"`):
  - Ingest and cross-reference community reports (`/api/reports`).
  - Lookup external feeds (VirusTotal, AbuseIPDB, Shodan) when API keys are configured.
- `flight_recorder.py` (`name = "flight_recorder"`):
  - Record temporal and behavioral telemetry of the target.
- `attack_fingerprint.py` (`name = "attack_fingerprint"`):
  - Fingerprint known phishing kits and attack campaigns.
- `graph_enrichment.py` (`name = "graph_enrichment"`):
  - Correlate domain, IP, ASN, nameserver, and certificate nodes.

### 2. Available Endpoints Ready for Graph Consumption:
- `GET /api/graph`: Returns nodes and edges.
- `GET /api/entities/{entity_id}/relationships`: Node neighborhood adjacency.
- `GET /api/scans/{scan_id}`: Full scan results with explainable risk breakdown.
- `GET /api/domains/{hostname}/compare`: Historical risk trends.

### 3. Commands to Resume Development (Computer 3):

```bash
# 1. Switch to develop and pull updates
git checkout develop
git pull origin develop

# 2. Enter backend directory and activate venv
cd backend
# Windows:
.\venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# 3. Verify all tests pass
python -m pytest

# 4. Start backend server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
