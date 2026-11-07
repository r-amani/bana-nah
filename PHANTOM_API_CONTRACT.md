# PHANTOM API Contract

> **Version:** 1.0.0
> **Last Updated:** 2026-11-07
> **Owner:** Computer 1 (Backend Architect)

This document defines the API contracts that all three computers must follow. **Do not change endpoint paths or request/response schemas without coordinating with the team.**

---

## Base URL

```
http://localhost:8000/api
```

API documentation (Swagger UI): `http://localhost:8000/docs`

---

## Standard Response Envelope

All successful responses return the data directly. Errors follow this format:

```json
{
  "detail": "Human-readable error message"
}
```

HTTP status codes:
| Code | Meaning |
|------|---------|
| 200  | Success |
| 201  | Created |
| 400  | Bad request / validation error |
| 404  | Not found |
| 429  | Rate limited |
| 500  | Internal server error |
| 503  | Service unavailable (e.g., database down) |

---

## Endpoints

### 1. Health Check

```
GET /health
```

**Response:**
```json
{
  "status": "healthy | degraded",
  "service": "PHANTOM Backend",
  "timestamp": "2026-11-07T12:00:00",
  "components": {
    "mongodb": { "status": "connected" },
    "scanner": {
      "registered_modules": 1,
      "modules": [{ "name": "placeholder", "description": "...", "version": "0.1.0" }]
    }
  }
}
```

---

### 2. Create Scan

```
POST /api/scans
```

**Request Body:**
```json
{
  "url": "https://example.com",
  "modules": ["url_detection", "tls_validation"]  // optional — null runs all
}
```

**Response (201):**
```json
{
  "scan_id": "uuid",
  "target_url": "https://example.com",
  "hostname": "example.com",
  "status": "completed | partial | failed",
  "created_at": "2026-11-07T12:00:00",
  "completed_at": "2026-11-07T12:00:01",
  "duration_ms": 1234.56,
  "risk_score": 42.5,
  "risk_level": "medium",
  "module_results": [
    {
      "module": "placeholder",
      "status": "completed",
      "started_at": "...",
      "completed_at": "...",
      "duration_ms": 100.0,
      "data": { "...module-specific..." },
      "error": null
    }
  ],
  "summary": "Scan completed in 1234ms with 3 findings."
}
```

**Errors:**
- `400`: Invalid URL or blocked URL (SSRF protection)
- `503`: Database unavailable

---

### 3. List Scans

```
GET /api/scans?limit=10&offset=0
```

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit`   | int  | 10      | Maximum number of scans to return (1-100) |
| `offset`  | int  | 0       | Number of scans to skip (>= 0) |

**Response (200):**
```json
[
  {
    "scan_id": "uuid",
    "target_url": "https://example.com",
    "hostname": "example.com",
    "status": "completed",
    "created_at": "2026-11-07T12:00:00",
    "completed_at": "2026-11-07T12:00:01",
    "duration_ms": 1234.56,
    "risk_score": 42.5,
    "risk_level": "medium",
    "module_results": [],
    "summary": "Scan completed..."
  }
]
```

**Errors:**
- `503`: Database unavailable

---

### 4. Get Scan

```
GET /api/scans/{scan_id}
```

**Response (200):** Same shape as Create Scan response.

**Errors:**
- `404`: Scan not found

---

### 4. Get Scan Findings

```
GET /api/scans/{scan_id}/findings
```

**Response (200):**
```json
[
  {
    "finding_id": "uuid",
    "scan_id": "uuid",
    "module": "tls_validation",
    "category": "tls_certificate",
    "title": "Certificate expires soon",
    "description": "The TLS certificate expires in 5 days.",
    "severity": "high",
    "confidence": 0.95,
    "evidence": { "expiry_date": "2026-11-12" },
    "recommendation": "Renew the certificate immediately.",
    "created_at": "2026-11-07T12:00:00"
  }
]
```

---

### 5. Domain Scan History

```
GET /api/domains/{hostname}/history?limit=20&offset=0
```

**Response (200):**
```json
{
  "hostname": "example.com",
  "total": 5,
  "offset": 0,
  "limit": 20,
  "scans": [ { "...scan objects..." } ]
}
```

---

### 6. Domain Comparison

```
GET /api/domains/{hostname}/compare?limit=5
```

**Response (200):**
```json
{
  "hostname": "example.com",
  "scan_count": 5,
  "scans": [
    {
      "scan_id": "uuid",
      "created_at": "...",
      "status": "completed",
      "risk_score": 42.5,
      "risk_level": "medium",
      "module_count": 3
    }
  ],
  "risk_trend": [
    { "date": "...", "score": 42.5 }
  ]
}
```

**Errors:**
- `404`: Fewer than 2 scans available

---

### 7. Submit Community Report

```
POST /api/reports
```

**Request Body:**
```json
{
  "url": "https://suspicious-site.com",
  "category": "phishing",
  "description": "This site imitates a bank login page.",
  "reporter_contact": "analyst@example.com"  // optional
}
```

**Categories:** `phishing`, `malware`, `scam`, `spam`, `defacement`, `c2_server`, `data_exfiltration`, `other`

**Response (201):**
```json
{
  "report_id": "uuid",
  "url": "https://suspicious-site.com",
  "hostname": "suspicious-site.com",
  "category": "phishing",
  "description": "This site imitates a bank login page.",
  "status": "pending",
  "reviewer_notes": null,
  "created_at": "2026-11-07T12:00:00",
  "updated_at": null
}
```

---

### 8. List Community Reports

```
GET /api/reports?hostname=example.com&status=pending&limit=50&offset=0
```

All query parameters are optional.

**Response (200):** Array of report objects.

---

### 9. Update Report Status

```
PATCH /api/reports/{report_id}
```

**Request Body:**
```json
{
  "status": "verified",
  "reviewer_notes": "Confirmed phishing page"
}
```

**Statuses:** `pending`, `verified`, `rejected`, `under_review`

**Response (200):** Updated report object.

---

### 10. Entity Relationships

```
GET /api/entities/{entity_id}/relationships
```

**Response (200):**
```json
{
  "entity": {
    "entity_id": "uuid",
    "type": "domain",
    "value": "example.com",
    "metadata": {},
    "first_seen": "...",
    "last_seen": "...",
    "scan_ids": ["uuid"]
  },
  "relationships": [
    {
      "relationship_id": "uuid",
      "source_entity_id": "uuid",
      "target_entity_id": "uuid",
      "type": "resolves_to",
      "confidence": 1.0,
      "metadata": {},
      "scan_id": "uuid",
      "created_at": "..."
    }
  ],
  "related_entities": [ { "...entity objects..." } ]
}
```

---

### 11. Investigation Graph

```
GET /api/graph?scan_id=uuid&hostname=example.com&max_nodes=200
```

All query parameters are optional.

**Response (200):**
```json
{
  "nodes": [ { "...entity objects..." } ],
  "edges": [ { "...relationship objects..." } ],
  "metadata": {
    "total_nodes": 10,
    "total_edges": 15,
    "filters": { "scan_id": null, "hostname": "example.com" }
  }
}
```

---

## Module Registration Contract

Each scan module must implement the `ModuleInterface` class:

```python
from app.scanner.orchestrator import ModuleInterface

class MyModule(ModuleInterface):
    name = "my_module"           # Unique identifier
    description = "What it does"
    version = "1.0.0"

    async def execute(self, target_url: str, hostname: str, scan_id: str, **kwargs) -> dict:
        return {
            "data": { ... },           # Module-specific results
            "findings": [ ... ],       # List of FindingDocument-compatible dicts
            "entities": [ ... ],       # List of EntityDocument-compatible dicts
            "relationships": [ ... ],  # List of RelationshipDocument-compatible dicts
        }
```

Register the module in `backend/app/main.py` or a dedicated registration file:

```python
from app.scanner.orchestrator import orchestrator
from app.scanner.modules.my_module import MyModule
orchestrator.register_module(MyModule())
```

---

## Module Names (Reserved)

| Module Name              | Owner      | Description                    |
|--------------------------|------------|--------------------------------|
| `url_detection`          | Computer 2 | URL threat detection           |
| `tls_validation`         | Computer 2 | TLS certificate validation     |
| `security_assessment`    | Computer 2 | Website security assessment    |
| `risk_scoring`           | Computer 2 | Explainable risk scoring       |
| `community_intelligence` | Computer 3 | Community threat data          |
| `flight_recorder`        | Computer 3 | Phishing flight recorder       |
| `attack_fingerprint`     | Computer 3 | Attack family fingerprinting   |
| `graph_enrichment`       | Computer 3 | Graph data enrichment          |
| `placeholder`            | Computer 1 | Pipeline validation (testing)  |

---

## Severity Levels

Used in findings:

| Level    | Weight | Meaning                            |
|----------|--------|------------------------------------|
| info     | 0.5    | Informational, no risk             |
| low      | 3.0    | Minor issue                        |
| medium   | 8.0    | Moderate risk                      |
| high     | 15.0   | Significant threat                 |
| critical | 25.0   | Immediate danger                   |

---

## Finding Categories

| Category            | Used By                        |
|---------------------|--------------------------------|
| url_analysis        | url_detection                  |
| tls_certificate     | tls_validation                 |
| security_headers    | security_assessment            |
| content_analysis    | security_assessment            |
| dns_analysis        | url_detection, graph_enrichment|
| reputation          | community_intelligence         |
| phishing_indicator  | url_detection, attack_fingerprint |
| malware_indicator   | attack_fingerprint             |
| infrastructure      | graph_enrichment               |
| behavioral          | flight_recorder                |

---

## Entity Types

| Type              | Example Value              |
|-------------------|----------------------------|
| url               | https://example.com/login  |
| domain            | example.com                |
| ip_address        | 93.184.216.34              |
| certificate       | SHA256 fingerprint         |
| nameserver        | ns1.example.com            |
| registrar         | GoDaddy                   |
| asn               | AS15169                    |
| email             | admin@example.com          |
| organization      | Example Inc                |
| network           | 93.184.216.0/24            |
| hosting_provider  | Cloudflare                 |

---

## Relationship Types

| Type              | Example                          |
|-------------------|----------------------------------|
| resolves_to       | domain → ip_address              |
| hosted_on         | domain → hosting_provider        |
| registered_by     | domain → registrar               |
| uses_nameserver   | domain → nameserver              |
| has_certificate   | domain → certificate             |
| issued_by         | certificate → organization       |
| belongs_to_asn    | ip_address → asn                 |
| associated_with   | generic association              |
| redirects_to      | url → url                        |
| similar_to        | domain → domain                  |
| part_of_network   | ip_address → network             |
| contacted_by      | domain → ip_address              |
