# PHANTOM Backend Setup Guide

> **Last Updated:** 2026-11-07
> **Owner:** Computer 1 (Backend Architect)

---

## Prerequisites

- **Python 3.11+**
- **MongoDB 6.0+** (running locally or accessible via URI)
- **pip** or **pip3**

---

## Quick Start

### 1. Clone & Navigate

```bash
cd phantom/backend
```

### 2. Create Virtual Environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment

```bash
cp .env.example .env
```

Edit `.env` with your MongoDB URI and other settings. The defaults work for a local MongoDB instance on the default port.

### 5. Start MongoDB

Ensure MongoDB is running. For local development:

```bash
# If using mongod directly:
mongod --dbpath /data/db

# Or via Docker:
docker run -d -p 27017:27017 --name phantom-mongo mongo:7
```

### 6. Start the Backend

```bash
# From the backend/ directory:
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Or:

```bash
python -m app.main
```

### 7. Verify

- **Health check:** http://localhost:8000/health
- **Swagger docs:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc

---

## Project Structure

```
phantom/
├── backend/
│   ├── .env.example          # Environment variable template
│   ├── .env                  # Local environment (git-ignored)
│   ├── requirements.txt      # Python dependencies
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py           # FastAPI application entry point
│   │   ├── config.py         # Settings management
│   │   ├── database.py       # MongoDB connection
│   │   ├── models/           # Pydantic models
│   │   │   ├── __init__.py
│   │   │   ├── scan.py       # Scan models
│   │   │   ├── finding.py    # Finding models
│   │   │   ├── report.py     # Community report models
│   │   │   └── entity.py     # Entity & relationship models
│   │   ├── routers/          # API route handlers
│   │   │   ├── __init__.py
│   │   │   ├── health.py
│   │   │   ├── scans.py
│   │   │   ├── domains.py
│   │   │   ├── reports.py
│   │   │   ├── entities.py
│   │   │   └── graph.py
│   │   ├── scanner/          # Scan orchestration
│   │   │   ├── __init__.py
│   │   │   ├── orchestrator.py
│   │   │   └── modules/      # Scan modules (plug in here)
│   │   │       ├── __init__.py
│   │   │       └── placeholder.py
│   │   └── security/         # Security utilities
│   │       ├── __init__.py
│   │       └── url_validator.py
│   └── tests/                # (Future: test files)
├── PHANTOM_API_CONTRACT.md
├── PHANTOM_DATABASE_SCHEMA.md
└── PHANTOM_BACKEND_SETUP.md
```

---

## Adding a New Module

1. Create a Python file in `backend/app/scanner/modules/`
2. Implement the `ModuleInterface`:

```python
from app.scanner.orchestrator import ModuleInterface

class MyModule(ModuleInterface):
    name = "my_module"
    description = "Description of what this module does"
    version = "1.0.0"

    async def execute(self, target_url: str, hostname: str, scan_id: str, **kwargs) -> dict:
        # Perform analysis...
        return {
            "data": { ... },
            "findings": [ ... ],
            "entities": [ ... ],
            "relationships": [ ... ],
        }
```

3. Register the module in `app/main.py`:

```python
from app.scanner.modules.my_module import MyModule
from app.scanner.orchestrator import orchestrator
orchestrator.register_module(MyModule())
```

4. The orchestrator will automatically include your module in scans.

---

## Environment Variables

| Variable                  | Default                    | Description                  |
|---------------------------|----------------------------|------------------------------|
| MONGODB_URI               | mongodb://localhost:27017  | MongoDB connection string    |
| MONGODB_DB_NAME           | phantom                    | Database name                |
| HOST                      | 0.0.0.0                   | Server bind address          |
| PORT                      | 8000                       | Server port                  |
| DEBUG                     | false                      | Enable debug/reload mode     |
| LOG_LEVEL                 | info                       | Logging level                |
| RATE_LIMIT_REQUESTS       | 100                        | Requests per window          |
| RATE_LIMIT_WINDOW_SECONDS | 60                         | Rate limit window (seconds)  |
| MAX_REDIRECTS             | 5                          | Max allowed URL redirects    |
| REQUEST_TIMEOUT_SECONDS   | 10                         | HTTP request timeout         |
| MAX_RESPONSE_SIZE_BYTES   | 10485760                   | Max response size (10MB)     |
| VIRUSTOTAL_API_KEY        | (empty)                    | Optional VirusTotal key      |
| SHODAN_API_KEY            | (empty)                    | Optional Shodan key          |
| ABUSEIPDB_API_KEY         | (empty)                    | Optional AbuseIPDB key       |

---

## API Quick Reference

| Method | Endpoint                             | Description                  |
|--------|--------------------------------------|------------------------------|
| GET    | /health                              | Service health check         |
| POST   | /api/scans                           | Start a new scan             |
| GET    | /api/scans/{scan_id}                 | Get scan details             |
| GET    | /api/scans/{scan_id}/findings        | Get scan findings            |
| GET    | /api/domains/{hostname}/history      | Domain scan history          |
| GET    | /api/domains/{hostname}/compare      | Compare domain scans         |
| POST   | /api/reports                         | Submit community report      |
| GET    | /api/reports                         | List community reports       |
| PATCH  | /api/reports/{report_id}             | Update report status         |
| GET    | /api/entities/{entity_id}/relationships | Entity relationships      |
| GET    | /api/graph                           | Investigation graph data     |

See [PHANTOM_API_CONTRACT.md](PHANTOM_API_CONTRACT.md) for full request/response schemas.

---

## For Other Computers

- **Computer 2** (Frontend / Detection Modules): Implement modules by following the `ModuleInterface` class in `orchestrator.py`. Your modules slot into the existing scan pipeline. See the API contract for endpoint schemas your frontend should consume.

- **Computer 3** (Intelligence / Graph): Implement intelligence and graph enrichment modules. The entity/relationship schema is designed to support your investigation graph. Use the graph and entity endpoints to query data.

---

## Troubleshooting

| Issue                        | Solution                                              |
|------------------------------|-------------------------------------------------------|
| MongoDB connection refused   | Ensure MongoDB is running on the configured URI       |
| Module not found in scan     | Check module is registered in `main.py`               |
| Import errors                | Ensure virtual environment is activated               |
| Rate limit hit               | Wait or adjust `RATE_LIMIT_*` env vars                |
| SSRF error on valid URL      | URL resolves to a private IP — this is by design      |
