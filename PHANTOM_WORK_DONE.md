# PHANTOM — Engineering Progress & Architecture Report

> **Project:** PHANTOM (Phishing Detection & Digital Threat Investigation Platform)  
> **Computer 1 Role:** Backend Architect & Integration Lead (Phase 1–3 Complete)  
> **Computer 2 Role:** Threat Detection, Security Assessment & Risk Engine Lead (Phase 4–5 Complete)  
> **Computer 3 Role:** Intelligence Engineer, Investigation Graph Developer & Final Integration Lead (Phase 6–8 Complete)  
> **Repository Branch:** `develop`  
> **Latest Commit Hashes:** `7c12b74`, `f934568`  
> **Date:** 2026-11-07  
> **Platform Status:** All 8 Core Capabilities Verified • 51 Passing Tests (100%) • Full React Frontend Operational  

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
  6. **Interactive Single-Page Application (`frontend/`)**: Built a complete dark-themed React application supporting all 8 requested views (Dashboard, Scanner, Scan Report, Certificate Details, Security Assessment, Flight Recorder, Community Reports, and Interactive Canvas Investigation Graph with pan/zoom, node dragging, and evidence inspection drawer).
- Comprehensive test coverage expanded from 32 tests to **51 tests**, achieving a **100% pass rate** in 2.4s.

---

## 1. Complete Repository Directory Structure

```
phantom/
├── .gitignore                          # Standard git ignore rules for Python, Node, data
├── PHANTOM_API_CONTRACT.md             # Formal REST API contracts for all endpoints
├── PHANTOM_DATABASE_SCHEMA.md          # Complete MongoDB schema, index, and model documentation
├── PHANTOM_BACKEND_SETUP.md            # Onboarding and startup guide for teammates
├── PHANTOM_WORK_DONE.md                # Comprehensive log of architecture & work completed
├── PHANTOM_COMPUTER3_HANDOVER.md       # Final Computer 3 handover report
├── backend/
│   ├── .env.example                    # Environment variable template with safe defaults
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
│   │   │       ├── tls_validation.py   # TLS certificate validation & cryptography (Computer 2)
│   │   │       ├── security_assessment.py # Headers & DOM security assessment (Computer 2)
│   │   │       ├── risk_scoring.py     # Explainable risk scoring engine (Computer 2)
│   │   │       ├── community_intelligence.py # Crowd reporting & external intelligence (Computer 3)
│   │   │       ├── flight_recorder.py  # Historical snapshots & infrastructure drift (Computer 3)
│   │   │       ├── attack_fingerprint.py # Attack campaign & shared infrastructure clustering (Computer 3)
│   │   │       └── graph_enrichment.py # Graph topology synthesis & edge deduplication (Computer 3)
│   │   └── security/                   # Hardened security controls
│   │       ├── __init__.py
│   │       └── url_validator.py        # Strict URL validation, SSRF defense, DNS resolution checks
│   └── tests/                          # 51 unit and integration tests (100% passing)
│       ├── __init__.py
│       ├── test_url_validator.py       # SSRF blocking, RFC 1918 filter tests (5 tests)
│       ├── test_models.py              # Schema validation & serialization tests (4 tests)
│       ├── test_orchestrator.py        # Orchestration & registration tests (4 tests)
│       ├── test_url_detection.py       # URL lexical, typosquatting & DNS tests (7 tests)
│       ├── test_tls_validation.py      # TLS expiry, SAN, self-signed tests (4 tests)
│       ├── test_security_assessment.py # Headers & DOM analysis tests (5 tests)
│       ├── test_risk_scoring.py        # Multi-factor scoring engine tests (4 tests)
│       ├── test_community_intelligence.py # Reporting, deduplication & feeds tests (6 tests)
│       ├── test_flight_recorder.py     # Snapshots, deltas & historical drift tests (4 tests)
│       ├── test_attack_fingerprint.py  # Campaign clustering & shared infrastructure tests (3 tests)
│       ├── test_graph_enrichment.py    # Node & edge normalization tests (3 tests)
│       └── test_integration_pipeline.py # End-to-end scan pipeline & graph API tests (2 tests)
└── frontend/                           # React 18 Single-Page Application (Computer 3)
    ├── package.json                    # Frontend dependencies & build scripts
    ├── vite.config.js                  # Vite server & API reverse proxy configuration
    ├── index.html                      # Application shell
    └── src/
        ├── main.jsx                    # React entrypoint
        ├── App.jsx                     # Core application state & tab manager
        ├── index.css                   # Cyberpunk dark design system
        └── components/
            ├── Navigation.jsx          # Sticky header with active target indicator
            ├── Dashboard.jsx           # High-level platform statistics & threat metrics
            ├── ScannerHome.jsx         # URL submission form & module selector switches
            ├── ScanReport.jsx          # Risk score gauge, confidence, breakdown & filtered findings
            ├── CertificateDetails.jsx  # TLS cryptographic validation, issuer, validity, SANs
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
  ```
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

### 6. Interactive React Frontend Single-Page Application (`frontend/`)
- Built using React 18 and Vite with zero external chart library bloat.
- Supports all 8 pages:
  1. **Dashboard**: High-level platform statistics, threat breakdown, and recent activity feed.
  2. **Scanner**: Target URL input and toggle switches for all active modules.
  3. **Scan Report**: Composite risk score gauge (0–100), threat classification, confidence, factor breakdown, and filtered findings with remediation actions.
  4. **Certificate Details**: Cryptographic validation, issuer, validity window, expiry, and SANs.
  5. **Security Assessment**: HSTS/CSP/XFO/XCTO matrix, DOM form analysis, and redirect hops.
  6. **Flight Recorder**: Historical observation timeline and drift delta comparison.
  7. **Community Reports**: Crowd feed, report submission modal, and analyst moderation actions.
  8. **Investigation Graph**: Interactive SVG canvas with force layout, pan/zoom, node dragging, node/edge inspection drawers, association strength indicators, and type filtering.

---

## 5. Test Suite Verification & Results

```text
platform win32 -- Python 3.13.5, pytest-9.2.0, pluggy-1.7.0
rootdir: phantom

backend/tests/test_attack_fingerprint.py ...                             [  5%]
backend/tests/test_community_intelligence.py ......                      [ 17%]
backend/tests/test_flight_recorder.py ....                               [ 25%]
backend/tests/test_graph_enrichment.py ...                               [ 31%]
backend/tests/test_integration_pipeline.py ..                            [ 35%]
backend/tests/test_models.py ....                                        [ 43%]
backend/tests/test_orchestrator.py ....                                  [ 50%]
backend/tests/test_risk_scoring.py ....                                  [ 58%]
backend/tests/test_security_assessment.py .....                          [ 68%]
backend/tests/test_tls_validation.py ....                                [ 76%]
backend/tests/test_url_detection.py .......                              [ 90%]
backend/tests/test_url_validator.py .....                                [100%]

====================== 51 passed, 159 warnings in 2.56s =======================
```

- **Passed**: 51 / 51 (100% pass rate)
- **Execution Time**: ~2.5 seconds

---

## 6. How to Run the Application

### 1. Backend Server
```powershell
cd backend
.\venv\Scripts\activate
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
Interactive Swagger API documentation: `http://127.0.0.1:8000/docs`

### 2. Frontend Development Server
```powershell
cd frontend
npm run dev
```
Web console: `http://localhost:3000` (automatically proxies `/api` and `/health` requests to FastAPI).

### 3. Production Frontend Build
```powershell
npm run build --prefix frontend
```
Builds production-optimized static assets to `frontend/dist/`.
