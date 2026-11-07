# PHANTOM — Engineering Progress & Architecture Report

> **Project:** PHANTOM (Phishing Detection & Digital Threat Investigation Platform)  
> **Team Role:** Computer 1 — Backend Architect & Integration Lead  
> **Status:** Phase 1, Phase 2, and Phase 3 Complete  
> **Repository Branch:** `develop`  
> **Date:** 2026-11-07  

---

## Executive Summary

As **Computer 1 (Backend Architect & Integration Lead)**, the core responsibility is to build the backend foundation, define shared data contracts and schemas, implement a resilient scan orchestration pipeline with SSRF/security protections, and prepare a modular system that enables Computer 2 (Detection & Frontend) and Computer 3 (Intelligence & Graph) to develop concurrently without integration friction.

All foundational code, schemas, routers, orchestrator, security validators, unit tests, and cross-computer documentation have been created, verified, and committed to git.

---

## 1. Directory Structure Created

```
phantom/
├── .gitignore                          # Standard git ignore rules for Python, Node, data
├── PHANTOM_API_CONTRACT.md             # Formal REST API contracts for all endpoints
├── PHANTOM_DATABASE_SCHEMA.md          # Complete MongoDB schema, index, and model documentation
├── PHANTOM_BACKEND_SETUP.md            # Onboarding and startup guide for teammates
├── PHANTOM_WORK_DONE.md                # Comprehensive log of architecture & work completed
└── backend/
    ├── .env.example                    # Environment variable template with safe defaults
    ├── requirements.txt                # Pinned production backend dependencies
    ├── app/
    │   ├── __init__.py
    │   ├── main.py                     # FastAPI application entry point, lifecycle, middleware
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
    │   │   ├── orchestrator.py         # ModuleInterface, concurrent execution, risk scoring, persistence
    │   │   └── modules/                # Plug-in directory for detection modules
    │   │       ├── __init__.py
    │   │       └── placeholder.py      # Verification module for pipeline validation
    │   └── security/                   # Hardened security controls
    │       ├── __init__.py
    │       └── url_validator.py        # Strict URL validation, SSRF defense, and DNS resolution checks
    └── tests/                          # Test suite
        ├── __init__.py
        ├── test_url_validator.py       # SSRF blocking, RFC 1918 filter tests
        ├── test_models.py              # Schema validation & serialization tests
        └── test_orchestrator.py        # Orchestration, registration, and risk scoring tests
```

---

## 2. Work Completed by Phase

### Phase 1: Foundation
- [x] **Repository Analysis**: Verified initial clean state and initialized Git version control (`master` and `develop` branches).
- [x] **FastAPI Application Core (`app/main.py`)**:
  - Async lifespan manager with clean database startup and shutdown.
  - CORS middleware supporting Vite and Next.js dev ports (`3000`, `5173`).
  - Rate limiting integration using `slowapi` with client IP keying.
  - Global unhandled exception handler logging error details while returning uniform JSON.
- [x] **Database Engine (`app/database.py`)**:
  - Asynchronous Motor MongoDB client (`AsyncIOMotorClient`).
  - Connection ping on startup with graceful degradation if MongoDB is offline.
  - Automatic index creation on startup for query performance and data integrity.
- [x] **Environment Configuration (`app/config.py`, `.env.example`)**:
  - `pydantic-settings` BaseSettings class with cached singleton loader (`get_settings()`).
  - Configurable timeouts, redirect limits, payload limits, and third-party API keys.

---

### Phase 2: Shared Contracts & Database Schemas
- [x] **Domain Models (`app/models/`)**:
  - **`scan.py`**: Models for scan requests, full results, module results, and scan status lifecycle (`pending`, `running`, `completed`, `failed`, `partial`).
  - **`finding.py`**: Structured security findings with 5 severity tiers (`info`, `low`, `medium`, `high`, `critical`), confidence scoring (0.0 to 1.0), evidence payload, and categories.
  - **`report.py`**: Community threat intelligence submission, status lifecycle (`pending`, `verified`, `rejected`, `under_review`), and triage notes.
  - **`entity.py`**: Graph entities (nodes) and typed relationships (edges) supporting the investigation graph.
- [x] **Contract Documentation**:
  - **`PHANTOM_API_CONTRACT.md`**: Complete specification of all endpoints, parameters, sample payloads, error codes, and reserved module names.
  - **`PHANTOM_DATABASE_SCHEMA.md`**: Exhaustive MongoDB collection documentation, field data types, index definitions, and UUID v4 standards.

---

### Phase 3: Scan Orchestration & Integration Engine
- [x] **Module Interface Contract (`ModuleInterface`)**:
  - Every capability implements `execute(target_url, hostname, scan_id, **kwargs) -> dict`.
  - Modules return discrete findings, entities, and relationships in a standardized dictionary.
- [x] **Central Orchestration Engine (`ScanOrchestrator`)**:
  - Module registration system (`register_module`, `unregister_module`, `list_modules`).
  - Filtered module execution: callers can run all registered modules or request a specific subset.
  - Unregistered or missing requested modules are reported as `unavailable` rather than crashing the scan.
  - Concurrent asynchronous execution via `asyncio.gather` with task isolation.
  - Enforced per-module timeout (30 seconds) to prevent hanging third-party calls.
  - Partial success handling: failures in one module do not abort other modules.
  - Transparent persistence pipeline: stores scans, individual findings, entities (upserting with historical tracking), and relationships in MongoDB.
- [x] **Explainable Risk Scoring Engine**:
  - Severity-weighted algorithm factoring in confidence metrics:
    - `critical` (weight: 25.0)
    - `high` (weight: 15.0)
    - `medium` (weight: 8.0)
    - `low` (weight: 3.0)
    - `info` (weight: 0.5)
  - Normalized 0–100 risk score and mapped risk levels (`none`, `low`, `medium`, `high`, `critical`).
- [x] **Verification Module (`PlaceholderModule`)**:
  - Connects to the pipeline and generates real data structures for end-to-end testing without fabricating detection results.

---

### Phase 4: Security & SSRF Defense (`app/security/url_validator.py`)
- [x] **Scheme Enforcement**: Restricts protocols strictly to `http` and `https`.
- [x] **Length and Format Checks**: Rejects malformed hostnames, port injections, and URLs exceeding 2048 characters.
- [x] **Comprehensive SSRF IP Blacklisting**:
  - Blocks RFC 1918 Private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
  - Blocks loopback (`127.0.0.0/8`, `::1`).
  - Blocks link-local addresses (`169.254.0.0/16`, `fe80::/10`).
  - Blocks test networks, multicast, and broadcast addresses.
  - Blocks cloud provider metadata endpoints (`169.254.169.254`, `metadata.google.internal`).
- [x] **DNS Resolution Validation**: Resolves hostnames to their underlying IP before dispatch and blocks any destination resolving to restricted address space.

---

## 3. Implemented API Endpoints

| Method | Route | Description |
|---|---|---|
| `GET` | `/health` | Service status, MongoDB ping, registered module list |
| `POST` | `/api/scans` | Dispatches new multi-module scan with SSRF checks |
| `GET` | `/api/scans/{scan_id}` | Fetches complete scan summary and module results |
| `GET` | `/api/scans/{scan_id}/findings` | Fetches discrete findings detected during a scan |
| `GET` | `/api/domains/{hostname}/history` | Paginated historical scan records for a domain |
| `GET` | `/api/domains/{hostname}/compare` | Differential comparison and risk score progression |
| `POST` | `/api/reports` | Ingests community threat report |
| `GET` | `/api/reports` | Queries and filters submitted threat reports |
| `PATCH` | `/api/reports/{report_id}` | Updates review status (`verified`, `rejected`, etc.) |
| `GET` | `/api/entities/{entity_id}/relationships`| Queries node adjacency for investigation analysis |
| `GET` | `/api/graph` | Generates graph nodes and edges with scan/domain filters |

Interactive Swagger documentation is available at `/docs` and ReDoc at `/redoc`.

---

## 4. Verification & Testing

- **Syntax & Compilation**: Verified across all modules via Python compiler (`python -m compileall`).
- **Unit Test Suite**:
  - `test_url_validator.py`: Tested valid URLs, malformed URLs, forbidden schemes, blocked internal hostnames, and private IP ranges.
  - `test_models.py`: Tested document serialization, enum constraints, and schema conformance.
  - `test_orchestrator.py`: Tested module registration, dynamic dispatch, and risk scoring logic.
- **Git Repository State**: Clean working tree on branch `develop`, commits tagged with semantic messages.

---

## 5. Integration Guide for Other Computers

### For Computer 2 (Detection & Risk Modules)
1. Pull the `develop` branch.
2. Implement your detection modules inside `backend/app/scanner/modules/`:
   - `url_detection.py`
   - `tls_validation.py`
   - `security_assessment.py`
   - `risk_scoring.py`
3. Inherit from `ModuleInterface` in `app.scanner.orchestrator` and implement `async def execute(...)`.
4. Register your class instance in `backend/app/main.py`:
   ```python
   orchestrator.register_module(MyModule())
   ```

### For Computer 3 (Intelligence & Graph Modules)
1. Pull the `develop` branch.
2. Implement intelligence and graph modules:
   - `community_intelligence.py`
   - `flight_recorder.py`
   - `attack_fingerprint.py`
   - `graph_enrichment.py`
3. Populate graph entities and relationships using the schemas defined in `app/models/entity.py`.
4. Frontend and graph visualizers can query `/api/graph` and `/api/entities/{entity_id}/relationships` directly.

---

## 6. How to Run

```bash
# 1. Navigate to backend directory
cd backend

# 2. Setup virtual environment
python -m venv venv
venv\Scripts\activate      # Windows (or: source venv/bin/activate on Linux/macOS)

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env

# 5. Start MongoDB (locally or via Docker)
docker run -d -p 27017:27017 --name phantom-mongo mongo:7

# 6. Launch the server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
