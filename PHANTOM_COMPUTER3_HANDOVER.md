# PHANTOM — Computer 3 Handover & Integration Report

> **Project:** PHANTOM (Phishing Detection & Digital Threat Investigation Platform)  
> **Role:** Computer 3 — Intelligence Engineer, Investigation Graph Developer & Final Integration Lead  
> **Repository Branch:** `develop`  
> **Date:** 2026-11-07  
> **Status:** All 8 Core Capabilities Implemented & Verified (100% Pass Rate across 51 Tests)  

---

## 1. Executive Summary

Computer 3 has completed the final integration phase of the PHANTOM platform:
- Implemented **Capabilities 5–8**:
  1. **Community Intelligence** (`community_intelligence.py`): Crowd threat report deduplication, moderation review states, and optional multi-provider intelligence (VirusTotal, AbuseIPDB, Shodan) without hardcoded secrets.
  2. **Phishing Flight Recorder** (`flight_recorder.py`): Immutable point-in-time snapshot capture and multi-scan delta comparison (new findings, resolved findings, TLS certificate drift, stripped security headers, risk delta).
  3. **Attack Family Fingerprinting** (`attack_fingerprint.py`): Evidence-driven campaign and shared infrastructure clustering (shared IPs, certificates, nameservers, lexical edit distance).
  4. **Investigation Graph Enrichment** (`graph_enrichment.py`): Topology synthesis, deterministic entity ID harmonization, and deduplicated relationship edges.
- Extended Graph and Domain APIs:
  - `GET /api/graph`: Rich node-edge responses with entity type, relationship type, date range, scan ID, and hostname filtering.
  - `GET /api/domains/{hostname}/compare`: Consecutive scan delta analysis using genuine Flight Recorder snapshots.
- Orchestrator Pipeline Integration:
  - Integrated all 9 modules into the canonical 5-stage pipeline with strict separation of risk score and assessment confidence.
- Complete Frontend Development:
  - Built a production-ready, dark-themed React single-page application in `frontend/` supporting all 8 requested views (Dashboard, Scanner, Scan Report, Certificate Details, Security Assessment, Flight Recorder, Community Reports, and Interactive Investigation Graph with canvas pan/zoom, node/edge inspection, and strength indicators).
- Verification & Test Suite:
  - Expanded test coverage from 32 tests to **51 tests** with a **100% pass rate**.

---

## 2. Modules Implemented

### Module 1: Community Intelligence (`backend/app/scanner/modules/community_intelligence.py`)
- **De-duplication**: Uses reporter identifiers (`reporter_ip`, `reporter_contact`) and content hashes to identify duplicate submissions, preventing artificial corroboration inflation.
- **Status Moderation**: Distinguishes `pending`, `verified` / `corroborated`, `under_review`, `disputed`, and `rejected` reports. Rejected reports are dismissed and generate no threat findings.
- **Optional External Feeds**: Queries VirusTotal domain endpoint, AbuseIPDB IP reputation, and Shodan open host ports if API keys are configured in environment variables. Safely falls back to `not_configured` or `unavailable` without crashing the scan pipeline.

### Module 2: Phishing Flight Recorder (`backend/app/scanner/modules/flight_recorder.py`)
- **Point-in-Time Snapshots**: Captures normalized hostname, submitted URL, findings summary, TLS certificate parameters, security headers, redirect hops, risk score, and confidence level.
- **Delta Comparison**: Compares against prior scans from MongoDB (`flight_recorder` or `scans` collection). Identifies new findings, resolved findings, TLS certificate replacement (fingerprint / issuer / self-signed status), removed security headers, and risk score escalations (>15 points increase emits behavioral findings).
- **Integrity**: First scans explicitly state `has_history: False` and never fabricate artificial historical data.

### Module 3: Attack Family Fingerprinting (`backend/app/scanner/modules/attack_fingerprint.py`)
- **Indicator Correlation**: Correlates target observables against historical domain entities in MongoDB across:
  - Shared resolved IP addresses
  - Identical TLS certificate SHA-256 fingerprints
  - Impersonation of identical target brand keywords
  - High lexical similarity (Levenshtein distance <= 3)
- **Defensible Terminology**: Uses strictly evidence-backed classifications such as *"Shared observable infrastructure"* and *"Potentially related domains"*. Generates high-confidence structured relationships and findings when multi-factor indicators align.

### Module 4: Graph Enrichment (`backend/app/scanner/modules/graph_enrichment.py`)
- **Graph Harmonization**: Normalizes all nodes across URL, Domain, IP, Certificate, Report, and Nameserver into deterministic IDs (e.g. `domain:example.com`, `ip:1.2.3.4`).
- **Edge Deduplication**: Ensures duplicate relationships across modules are unified into single evidence-backed edges with timestamps, confidence scores, and explanatory metadata.

---

## 3. Files Created and Modified

### Backend Files Created:
1. `backend/app/scanner/modules/community_intelligence.py` — Community threat reporting & external feeds.
2. `backend/app/scanner/modules/flight_recorder.py` — Historical snapshots and delta comparison.
3. `backend/app/scanner/modules/attack_fingerprint.py` — Infrastructure & campaign clustering.
4. `backend/app/scanner/modules/graph_enrichment.py` — Topology synthesis and edge harmonization.
5. `backend/tests/test_community_intelligence.py` — 6 unit tests for reporting & de-duplication.
6. `backend/tests/test_flight_recorder.py` — 4 unit tests for snapshotting & drift detection.
7. `backend/tests/test_attack_fingerprint.py` — 3 unit tests for clustering & lexical matching.
8. `backend/tests/test_graph_enrichment.py` — 3 unit tests for node & edge normalization.
9. `backend/tests/test_integration_pipeline.py` — 2 integration tests for orchestrator & graph API.

### Backend Files Modified:
1. `backend/app/scanner/orchestrator.py` — Updated to execute 5-stage coordinated pipeline (Primary detection -> Risk Scoring -> Flight Recorder -> Attack Fingerprint -> Graph Enrichment -> Persistence).
2. `backend/app/main.py` — Registered all 4 new modules into the global orchestrator.
3. `backend/app/models/entity.py` — Added `REPORTED_BY`, `SHARES_INDICATOR`, `POTENTIALLY_RELATED_TO` to `RelationshipType`.
4. `backend/app/models/report.py` — Added `CORROBORATED` and `DISPUTED` to `ReportStatus`.
5. `backend/app/routers/graph.py` — Added entity type, relationship type, date range, scan ID, and hostname filtering.
6. `backend/app/routers/domains.py` — Added detailed Flight Recorder comparison pairs (score delta, new findings, resolved findings, cert drift, stripped headers).
7. `backend/app/scanner/modules/__init__.py` — Exported all 9 modules.
8. `backend/tests/test_orchestrator.py` — Added 9-module registration assertion test.

### Frontend Files Created:
1. `frontend/package.json` — Vite + React 18 configuration.
2. `frontend/vite.config.js` — Development server with reverse proxy for `/api` and `/health`.
3. `frontend/index.html` — Cyberpunk dark theme shell.
4. `frontend/src/index.css` — Modern design system with glassmorphism and badges.
5. `frontend/src/main.jsx` — React root entry.
6. `frontend/src/App.jsx` — Core state manager and tab navigation.
7. `frontend/src/components/Navigation.jsx` — Sticky header with target indicator.
8. `frontend/src/components/Dashboard.jsx` — Platform metrics & threat statistics.
9. `frontend/src/components/ScannerHome.jsx` — Target URL submission & module toggle switches.
10. `frontend/src/components/ScanReport.jsx` — Risk gauge, confidence, breakdown, and filtered findings.
11. `frontend/src/components/CertificateDetails.jsx` — TLS certificate parameters, SANs, and fingerprint.
12. `frontend/src/components/SecurityAssessment.jsx` — Security headers audit & DOM form analysis.
13. `frontend/src/components/FlightRecorder.jsx` — Historical timeline & drift delta comparison.
14. `frontend/src/components/CommunityReports.jsx` — Crowdsourced feed, submission modal, and review actions.
15. `frontend/src/components/InvestigationGraph.jsx` — Interactive canvas with pan/zoom, node dragging, node/edge inspection drawers, and filter bars.

---

## 4. API Endpoints Added / Extended

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/graph` | Returns nodes and edges. Extended with filters: `entity_type`, `relationship_type`, `start_date`, `end_date`, `scan_id`, `hostname`. |
| `GET` | `/api/domains/{hostname}/compare` | Extended to return consecutive Flight Recorder deltas, new findings, resolved findings, and cert drift. |
| `GET` | `/api/domains/{hostname}/history` | Returns scan history and Flight Recorder snapshot timeline. |
| `POST` | `/api/reports` | Submit community report with URL, category, description, reporter contact. |
| `PATCH` | `/api/reports/{id}` | Update report review status (`verified`, `rejected`, `under_review`). |
| `POST` | `/api/scans` | Dispatches scan across all 8 core capabilities. |

---

## 5. Test Suite & Verification Results

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

====================== 51 passed, 159 warnings in 2.43s =======================
```

**Results:**
- **Initial tests passed:** 32 / 32
- **New tests created:** 19
- **Total passing tests:** 51 / 51
- **Pass rate:** **100%**

---

## 6. How to Run the Application

### 1. Backend:
```powershell
cd backend
.\venv\Scripts\activate
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
API Documentation will be live at `http://127.0.0.1:8000/docs`.

### 2. Frontend:
```powershell
cd frontend
npm run dev
```
Open `http://localhost:3000` in your browser. All requests to `/api` are automatically proxied to the FastAPI backend.

### 3. Production Frontend Build:
```powershell
npm run build --prefix frontend
```
Builds production-optimized static assets to `frontend/dist/`.

---

## 7. Known Limitations & Safe Degraded Modes

1. **MongoDB Optionality**: If MongoDB is not running locally, the backend starts in graceful degraded mode: scanning, heuristic detection, TLS validation, and DOM assessment function without throwing 500 errors.
2. **External Intelligence Feeds**: VirusTotal, AbuseIPDB, and Shodan are purely passive and optional. If API keys are omitted or providers fail, they return `not_configured` or `unavailable` without crashing the scan pipeline.
3. **Passive Only**: PHANTOM enforces strict SSRF defense (blocking private RFC 1918 IPs, loopbacks, link-local addresses) and never executes active penetration or arbitrary client-side JavaScript.
