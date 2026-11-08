# PHANTOM — Engineering Progress & Architecture Report

> **Project:** PHANTOM (Phishing Detection & Digital Threat Investigation Platform)  
> **Computer 1 Role:** Backend Architect & Integration Lead (Phase 1–3 Complete)  
> **Computer 2 Role:** Threat Detection, Security Assessment & Risk Engine Lead (Phase 4–5 Complete)  
> **Computer 3 Role:** Intelligence Engineer, Investigation Graph Developer & Final Integration Lead (Phase 6–8 Complete)  
> **Enhanced Intelligence & UI Lead:** TLS Certificate Intelligence, Security Analysis & Windows Event Loop Hardening (Phase 9 Complete)  
> **Repository Branch:** `develop`  
> **Latest Remote Tracking Commit:** `f530b6b` ("feat(tls): strengthen certificate validation and reporting")  
> **Date:** 2026-11-08  
> **Platform Status:** All 8 Core Capabilities Operational • 65 Passing Tests (100% Pass Rate in 7.3s) • Enterprise React Dashboard Live  

---

## Executive Summary

- **Computer 1** established the FastAPI backend foundation, MongoDB schemas, REST endpoints, SSRF validation, and module orchestration interface.
- **Computer 2** implemented primary detection and assessment engines: `url_detection`, `tls_validation`, `security_assessment`, and `risk_scoring`, expanding tests to 32 passing tests.
- **Computer 3** joined on branch `develop`, verified the entire existing repository, and completed all remaining core capabilities:
  1. `community_intelligence`: Deduplicated community threat reporting, report moderation review states, and non-blocking external intelligence integrations (VirusTotal, AbuseIPDB, Shodan).
  2. `flight_recorder`: Point-in-time security snapshot capture and multi-scan delta comparison (new findings, resolved findings, TLS certificate drift, and stripped security headers).
  3. `attack_fingerprint`: Evidence-based attack campaign clustering identifying potentially related domains and shared observable infrastructure (IPs, certificates, brand patterns, and lexical similarity).
  4. `graph_enrichment`: Investigation graph topology builder, deterministic entity ID harmonization, and deduplicated relationship edges.
  5. **Graph and Domains API Enhancements**: Extended `GET /api/graph` with entity/relationship type, date range, scan ID, and hostname filtering; extended `GET /api/domains/{hostname}/compare` with consecutive Flight Recorder snapshot deltas.
  6. **Interactive Single-Page Application (`frontend/`)**: Built a complete React application supporting all 8 requested views (Dashboard, Scanner, Scan Report, Certificate Details, Security Assessment, Flight Recorder, Community Reports, and Interactive Canvas Investigation Graph with pan/zoom, node dragging, and evidence inspection drawer).
- **Phase 9 (Current Milestone) — TLS Certificate Intelligence & Windows Hardening**:
  1. **TLS Certificate Intelligence Dashboard**: Completely elevated the TLS certificate view into a comprehensive security intelligence engine. Implemented deep X.509 attribute extraction (Subject/Issuer C, O, OU, CN, SANs, key algorithm & size, signature algorithm, certificate type), Certificate Transparency (SCT) extension audit, brand impersonation and typosquatting detection (Punycode, suspicious affixes, brand lookalikes), a 7-dimension independent security assessment, evidence-based analyst findings, and a 3-pillar investigation summary (`certificate_health`, `domain_identity`, `website_trust`).
  2. **Enterprise Light-Blue & White UX**: Redesigned UI to an enterprise cybersecurity aesthetic (`#f4f8fb`, `#ffffff`, `#0284c7`, IBM Plex Mono typography) with visual lifecycle timelines (`Issued → Currently Valid → Expiration`), one-click copyable fingerprints, and auto-hydration of recent scan state so views never render blank on initial load.
  3. **Windows Pytest-Asyncio Test Suite Hardening**: Fixed test hangs caused by Windows IOCP deadlocks and unconfigured fixture scopes. Created root and backend `pytest.ini` and `backend/tests/conftest.py`.
  4. **Comprehensive Test Suite**: Expanded test coverage from 51 to **65 tests**, achieving a **100% pass rate** in 7.3s.

---

## 1. Complete Repository Directory Structure

```text
phantom/
├── .gitignore                          # Standard git ignore rules for Python, Node, data
├── pytest.ini                          # Root pytest configuration (pythonpath, asyncio settings)
├── PHANTOM_API_CONTRACT.md             # Formal REST API contracts for all endpoints
├── PHANTOM_DATABASE_SCHEMA.md          # Complete MongoDB schema, index, and model documentation
├── PHANTOM_BACKEND_SETUP.md            # Onboarding and startup guide for teammates
├── PHANTOM_WORK_DONE.md                # Comprehensive log of architecture & work completed
├── PHANTOM_COMPUTER3_HANDOVER.md       # Computer 3 handover report
├── backend/
│   ├── .env.example                    # Environment variable template with safe defaults
│   ├── pytest.ini                      # Backend-local pytest configuration
│   ├── requirements.txt                # Production backend dependencies
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                     # FastAPI app with all 9 modules & routers registered
│   │   ├── config.py                   # Pydantic BaseSettings environment manager
│   │   ├── database.py                 # Async Motor MongoDB manager with index generation
│   │   ├── models/                     # Shared Pydantic schemas and database models
│   │   │   ├── __init__.py
│   │   │   ├── scan.py                 # ScanRequest, ScanResponse, ScanDocument, ModuleResult
│   │   │   ├── finding.py              # FindingDocument, FindingResponse, Severity, FindingCategory
│   │   │   ├── report.py               # ReportRequest, ReportResponse, ReportDocument, ReportStatus
│   │   │   └── entity.py               # EntityDocument, RelationshipDocument, GraphResponse
│   │   ├── routers/                    # Cleanly separated FastAPI routers
│   │   │   ├── __init__.py
│   │   │   ├── health.py               # GET /health
│   │   │   ├── scans.py                # POST /api/scans, GET /api/scans/{id}, GET /api/scans/{id}/findings
│   │   │   ├── domains.py              # GET /api/domains/{host}/history, GET /api/domains/{host}/compare
│   │   │   ├── reports.py              # POST /api/reports, GET /api/reports, PATCH /api/reports/{id}
│   │   │   ├── entities.py             # GET /api/entities/{id}/relationships
│   │   │   └── graph.py                # GET /api/graph (with rich filtering & evidence)
│   │   ├── scanner/                    # Central orchestration pipeline
│   │   │   ├── __init__.py
│   │   │   ├── orchestrator.py         # 5-stage pipeline executor with risk evaluation & graph synthesis
│   │   │   └── modules/                # 9 Plug-in detection, intelligence & analysis modules
│   │   │       ├── __init__.py
│   │   │       ├── placeholder.py      # Pipeline validation placeholder (Computer 1)
│   │   │       ├── url_detection.py    # URL lexical & homograph threat detection (Computer 2)
│   │   │       ├── tls_validation.py   # Enhanced TLS certificate intelligence & brand impersonation (Phase 9)
│   │   │       ├── security_assessment.py # Headers & DOM security assessment (Computer 2)
│   │   │       ├── risk_scoring.py     # Explainable risk scoring engine (Computer 2)
│   │   │       ├── community_intelligence.py # Crowd reporting & external intelligence (Computer 3)
│   │   │       ├── flight_recorder.py  # Historical snapshots & infrastructure drift (Computer 3)
│   │   │       ├── attack_fingerprint.py # Attack campaign & shared infrastructure clustering (Computer 3)
│   │   │       └── graph_enrichment.py # Graph topology synthesis & edge deduplication (Computer 3)
│   │   └── security/                   # Hardened security controls
│   │       ├── __init__.py
│   │       └── url_validator.py        # Strict URL validation, SSRF defense, DNS resolution checks
│   └── tests/                          # 65 unit and integration tests (100% passing)
│       ├── __init__.py
│       ├── conftest.py                 # WindowsSelectorEventLoopPolicy & root sys.path fixture
│       ├── test_url_validator.py       # SSRF blocking, RFC 1918 filter tests (5 tests)
│       ├── test_models.py              # Schema validation & serialization tests (6 tests)
│       ├── test_orchestrator.py        # Orchestration & registration tests (4 tests)
│       ├── test_scans_router.py        # REST API scans router & alias payload tests (5 tests)
│       ├── test_url_detection.py       # URL lexical, typosquatting & DNS tests (7 tests)
│       ├── test_tls_validation.py      # TLS expiry, SAN, brand impersonation & 7-dim audit (11 tests)
│       ├── test_security_assessment.py # Headers & DOM analysis tests (5 tests)
│       ├── test_risk_scoring.py        # Multi-factor scoring engine tests (4 tests)
│       ├── test_community_intelligence.py # Reporting, deduplication & feeds tests (6 tests)
│       ├── test_flight_recorder.py     # Snapshots, deltas & historical drift tests (4 tests)
│       ├── test_attack_fingerprint.py  # Campaign clustering & shared infrastructure tests (3 tests)
│       ├── test_graph_enrichment.py    # Node & edge normalization tests (3 tests)
│       └── test_integration_pipeline.py # End-to-end scan pipeline & graph API tests (2 tests)
└── frontend/                           # React 18 Single-Page Application
    ├── package.json                    # Frontend dependencies & build scripts
    ├── vite.config.js                  # Vite server & API reverse proxy configuration
    ├── index.html                      # Application shell
    └── src/
        ├── main.jsx                    # React entrypoint
        ├── App.jsx                     # Core state, navigation rail, auto-hydration on mount
        ├── index.css                   # Enterprise light-blue & white cybersecurity design system
        └── components/
            ├── Navigation.jsx          # Sticky header with active target indicator
            ├── Dashboard.jsx           # High-level platform statistics & threat metrics
            ├── ScannerHome.jsx         # URL submission form & module selector switches
            ├── ScanReport.jsx          # Risk score gauge, confidence, breakdown & filtered findings
            ├── CertificateDetails.jsx  # TLS Certificate Intelligence Dashboard (Phase 9)
            ├── SecurityAssessment.jsx  # HSTS/CSP/XFO/XCTO matrix, form heuristics, redirects
            ├── FlightRecorder.jsx      # Point-in-time timeline & drift delta comparison
            ├── CommunityReports.jsx    # Crowd report feed, submission modal & moderation actions
            └── InvestigationGraph.jsx  # Interactive SVG canvas with pan/zoom, node drag, & evidence drawer
```

---

## 2. Work Completed by Computer 1
- Initialized FastAPI backend foundation and MongoDB connection lifecycle (`database.py`, `config.py`).
- Defined foundational Pydantic models for scans, findings, reports, and graph entities (`models/`).
- Implemented strict SSRF defense blocking RFC 1918 private IPs, loopback, link-local, and dangerous schemes (`security/url_validator.py`).
- Created initial modular orchestrator interface (`scanner/orchestrator.py`).
- Authored initial architecture specifications (`PHANTOM_API_CONTRACT.md`, `PHANTOM_DATABASE_SCHEMA.md`, `PHANTOM_BACKEND_SETUP.md`).

---

## 3. Work Completed by Computer 2
- Implemented `url_detection` module: Shannon entropy, high-abuse TLDs, Punycode homographs, Levenshtein typosquatting, and DNS resolution.
- Implemented `tls_validation` module: X.509 DER parsing, expiration evaluation, CN/SAN wildcard hostname matching, and self-signed certificate detection.
- Implemented `security_assessment` module: Security headers audit (HSTS, CSP, X-Frame-Options, X-Content-Type-Options) and DOM form heuristics.
- Implemented `risk_scoring` module: Multi-factor explainable risk scoring algorithm with domain breakdown.
- Built test suites expanding coverage to 32 tests.

---

## 4. Work Completed by Computer 3 (Intelligence & Final Integration)

### 1. `community_intelligence` Module (`app/scanner/modules/community_intelligence.py`)
- **De-duplication**: Identifies duplicate submissions by reporter identifier (`reporter_ip`, `reporter_contact`) and content hashes to prevent false corroboration inflation.
- **Status Moderation**: Distinguishes `pending`, `verified` / `corroborated`, `under_review`, `disputed`, and `rejected`. Rejected reports are safely dismissed and produce zero threat findings.
- **Optional External Feeds**: Queries VirusTotal domain endpoint, AbuseIPDB IP reputation, and Shodan open host ports if API keys are configured in environment variables. Safely falls back to `not_configured` or `unavailable` without crashing the scan pipeline.

### 2. `flight_recorder` Module (`app/scanner/modules/flight_recorder.py`)
- **Point-in-Time Snapshots**: Captures normalized hostname, submitted URL, findings summary, TLS certificate parameters, security headers, redirect hops, risk score, and confidence level.
- **Delta Comparison**: Compares against prior scans from MongoDB (`flight_recorder` or `scans` collection). Identifies new findings, resolved findings, TLS certificate replacement (fingerprint / issuer / self-signed status), removed security headers, and risk score escalations (>15 points increase emits behavioral findings).
- **Integrity**: First scans explicitly state `has_history: False` and never fabricate artificial historical data.

### 3. `attack_fingerprint` Module (`app/scanner/modules/attack_fingerprint.py`)
- **Indicator Correlation**: Correlates target observables against historical domain entities in MongoDB across:
  - Shared resolved IP addresses
  - Identical TLS certificate SHA-256 fingerprints
  - Impersonation of identical target brand keywords
  - High lexical similarity (Levenshtein distance <= 3)
- **Defensible Terminology**: Uses strictly evidence-backed classifications such as *"Shared observable infrastructure"* and *"Potentially related domains"*. Generates high-confidence structured relationships and findings when multi-factor indicators align.

### 4. `graph_enrichment` Module (`app/scanner/modules/graph_enrichment.py`)
- **Graph Harmonization**: Normalizes all nodes across URL, Domain, IP, Certificate, Report, and Nameserver into deterministic IDs (e.g. `domain:example.com`, `ip:1.2.3.4`).
- **Edge Deduplication**: Ensures duplicate relationships across modules are unified into single evidence-backed edges with timestamps, confidence scores, and explanatory metadata.

### 5. Orchestrator Pipeline Integration (`app/scanner/orchestrator.py`)
- Coordinated 5-stage pipeline:
  ```text
  URL Submission & DNS SSRF Validation
    ↓
  Stage 1: Primary Detection (URL Detection + TLS Validation + Security Assessment + Community Intelligence)
    ↓
  Stage 2: Explainable Risk Scoring Engine
    ↓
  Stage 3: Phishing Flight Recorder (Snapshot & Drift Delta)
    ↓
  Stage 4: Attack Family Fingerprinting (Shared Infrastructure Clustering)
    ↓
  Stage 5: Graph Enrichment (Topology Synthesis & Deduplication)
    ↓
  Database Persistence (Scans, Findings, Entities, Relationships, Snapshots)
  ```

---

## 5. Phase 9: TLS Certificate Intelligence & Security Analysis Enhancement

### 1. Architectural Motivation & Design Principles
Attackers frequently obtain valid TLS certificates from automated Certificate Authorities (e.g. Let's Encrypt, ZeroSSL) to display a secure padlock icon in victims' browsers. A valid certificate encrypts communications but **does not confirm website legitimacy**. The TLS Certificate Analysis module was overhauled to deliver actionable, enterprise-grade threat intelligence that decouples cryptographic validity from domain and brand trustworthiness.

### 2. Backend Enhancements (`backend/app/scanner/modules/tls_validation.py`)

- **Deep X.509 Attribute Extraction**:
  - Structured extraction of Subject and Issuer components: Country (`C`), Organization (`O`), Organizational Unit (`OU`), Common Name (`CN`).
  - Subject Alternative Names (SANs) with wildcard resolution.
  - Cryptographic parameters: Public key algorithm (`RSA`, `ECDSA`, `Ed25519`), key size in bits (`2048`, `4096`, `256`), signature algorithm (`sha256WithRSAEncryption`, `ecdsa-with-SHA256`).
  - Certificate type classification (`Domain Validated (DV)`, `Organization Validated (OV)`, `Extended Validation (EV)`, `Wildcard`).
- **Certificate Transparency (SCT) Audit**:
  - Evaluates presence of Embedded Signed Certificate Timestamps (`OID 1.3.6.1.4.1.11129.2.4.2`).
  - Detects public log submission conformance required by modern web browsers.
- **Brand Impersonation & Typosquatting Analysis**:
  - Maintained dictionary of high-risk impersonation targets: WhatsApp, PayPal, Microsoft, Apple, Google, Chase, Binance, Amazon, Netflix, Facebook, Instagram, Bank of America, Wells Fargo, Telegram, Coinbase.
  - Scans hostname and SAN entries for brand keywords, suspicious security affixes (`login`, `secure`, `verify`, `account`, `update`, `auth`, `portal`), and IDN/Punycode homoglyphs (`xn--`).
  - Generates structured, high-severity findings when brand impersonation is detected on third-party infrastructure.
  - Adheres to analyst integrity guidelines: clearly notes that brand presence indicates potential impersonation requiring scrutiny, not automatic proof of malicious activity.
- **7-Dimension Independent Security Assessment**:
  1. `validity`: Checks expiration and not-before dates (`PASS`, `WARNING`, `FAIL`).
  2. `chain_trust`: Verifies root store validation and self-signed certificate status.
  3. `domain_matching`: Validates CN/SAN match against target hostname, accounting for wildcard rules.
  4. `cryptography`: Evaluates protocol version (TLS 1.2/1.3), cipher suite, and public key length (flags RSA < 2048 or weak ciphers).
  5. `expiration_risk`: Flags certificates expiring in under 14 days or expired certificates.
  6. `transparency`: Checks SCT presence in X.509 extensions.
  7. `anomalies`: Detects excessive SAN divergence, missing extensions, or unusual issuance characteristics.
- **Analyst Investigation Findings**:
  - Generates clear, evidence-backed observations (e.g. *"Valid certificate issued by Let's Encrypt"*, *"Potential brand impersonation detected for WhatsApp"*, *"Certificate chain validates against system trust store"*).
- **3-Pillar Investigation Summary**:
  - `certificate_health`: Technical cryptographic configuration and validity.
  - `domain_identity`: Alignment between certificate subject, SANs, and investigated domain.
  - `website_trust`: Behavioral and impersonation risk indicators.

### 3. Frontend TLS Intelligence Dashboard (`frontend/src/components/CertificateDetails.jsx`)

- **Overview Card**: Status badge (`VALID`, `EXPIRED`, `NOT_YET_VALID`, `SELF_SIGNED`, `DOMAIN_MISMATCH`, `UNTRUSTED`), CA badge, key metrics bar, and analytical principle disclaimer.
- **Visual Certificate Lifecycle Timeline**: Interactive 3-step progress bar showing `Issued → Currently Valid → Expiration` with remaining days calculation.
- **Subject, Issuer & Validity Tables**: Clean, compact structured rows for CN, O, OU, Country, and SANs.
- **Cryptographic Specifications**: Monospace font for SHA-256 fingerprint with one-click copy and copy-state tooltip, cipher suite, key algorithm & size, and expandable raw JSON drawer.
- **Security Assessment Matrix**: 7 independent dimension cards with color-coded severity pills (`PASS` in green, `WARNING` in amber, `FAIL` in red, `UNKNOWN` in grey) and expandable evidence drawers.
- **Domain Identity & Brand Impersonation Card**: Prominently highlights detected brands, suspicious affixes, and contextual guidance distinguishing impersonation indicators from verified compromise.
- **Auto-Hydration on Mount (`frontend/src/App.jsx`)**: Added an initial `useEffect` fetch to `/api/scans?limit=1` so detail views are pre-populated with the latest investigation rather than starting empty.

---

## 6. Windows Async Test Suite Hardening

### Root Cause Analysis & Resolution
- **Issue**: Running `pytest backend/tests` hung indefinitely on Windows.
- **Root Cause**:
  1. `pytest-asyncio` strict mode in combination with `anyio` created conflicting fixture event loop runners.
  2. Python 3.13 on Windows defaults to `ProactorEventLoop`, which can deadlock on IOCP loopback socketpairs under test runner subprocesses without explicit loop scopes.
  3. Network requests in unmocked edge cases lacked bounded default timeouts.
- **Remediation**:
  1. Added `pytest.ini` and `backend/pytest.ini` with:
     ```ini
     [pytest]
     pythonpath = backend
     testpaths = backend/tests
     asyncio_mode = auto
     asyncio_default_fixture_loop_scope = function
     ```
  2. Added `backend/tests/conftest.py` setting `WindowsSelectorEventLoopPolicy` on Windows platforms and ensuring `backend/` is on `sys.path`.
  3. Isolated async fixtures and mocked external network clients with `httpx` timeouts.

---

## 7. Test Suite Verification & Results

```text
============================= test session starts =============================
platform win32 -- Python 3.13.1, pytest-9.2.0, pluggy-1.7.0
rootdir: D:\Phantom\backend
configfile: pytest.ini
plugins: anyio-4.16.0, asyncio-1.4.1.post1
asyncio: mode=Mode.AUTO, debug=False, asyncio_default_fixture_loop_scope=function, asyncio_default_test_loop_scope=function
collected 65 items

backend\tests\test_attack_fingerprint.py ...                             [  4%]
backend\tests\test_community_intelligence.py ......                      [ 13%]
backend\tests\test_flight_recorder.py ....                               [ 20%]
backend\tests\test_graph_enrichment.py ...                               [ 24%]
backend\tests\test_integration_pipeline.py ..                            [ 27%]
backend\tests\test_models.py ......                                      [ 36%]
backend\tests\test_orchestrator.py ....                                  [ 43%]
backend\tests\test_risk_scoring.py ....                                  [ 49%]
backend\tests\test_scans_router.py .....                                 [ 56%]
backend\tests\test_security_assessment.py .....                          [ 64%]
backend\tests\test_tls_validation.py ...........                         [ 81%]
backend\tests\test_url_detection.py .......                              [ 92%]
backend\tests\test_url_validator.py .....                                [100%]

============================= 65 passed in 7.30s ==============================
```

- **Total Tests**: **65 passed** / 65 (100% pass rate)
- **Execution Time**: **7.30 seconds**
- **Test Modules Covered**:
  - `test_attack_fingerprint.py` (3 tests): Shared infrastructure, campaign clustering, brand matching.
  - `test_community_intelligence.py` (6 tests): Deduplication, status moderation, provider failure tolerance.
  - `test_flight_recorder.py` (4 tests): Baseline snapshot, delta drift, header stripping, TLS changes.
  - `test_graph_enrichment.py` (3 tests): Node normalization, edge deduplication, entity harmonisation.
  - `test_integration_pipeline.py` (2 tests): End-to-end 5-stage pipeline, graph query API.
  - `test_models.py` (6 tests): Pydantic validation, aliases, schema contracts.
  - `test_orchestrator.py` (4 tests): Registration, stage execution, module dependencies.
  - `test_risk_scoring.py` (4 tests): Explainable multi-factor scoring, boundary conditions.
  - `test_scans_router.py` (5 tests): REST API endpoints, input validation, alias payloads.
  - `test_security_assessment.py` (5 tests): HSTS, CSP, XFO, form action heuristics, redirects.
  - `test_tls_validation.py` (11 tests): Expiration, self-signed detection, SAN matching, brand impersonation, 7-dimension audit.
  - `test_url_detection.py` (7 tests): Shannon entropy, Punycode, homoglyphs, high-abuse TLDs.
  - `test_url_validator.py` (5 tests): SSRF defense, RFC 1918 blocking, loopback prevention.

---

## 8. How to Run the Application

### 1. Backend Server (FastAPI)
```powershell
cd backend
.\venv\Scripts\activate
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
- Interactive Swagger API Documentation: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- Health Check: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)

### 2. Frontend Development Server (React + Vite)
```powershell
cd frontend
npm run dev
```
- Web Application Console: [http://localhost:3000](http://localhost:3000) (proxies `/api` and `/health` requests to FastAPI).

### 3. Production Frontend Build
```powershell
npm run build --prefix frontend
```
- Production-optimized static assets compiled to `frontend/dist/`.

### 4. Running the Test Suite
```powershell
backend\venv\Scripts\python.exe -m pytest backend/tests -v
```
