# PHANTOM Database Schema

> **Database:** MongoDB
> **Database Name:** `phantom` (configurable via `MONGODB_DB_NAME` env var)
> **Last Updated:** 2026-11-07
> **Owner:** Computer 1 (Backend Architect)

---

## Collections

### 1. `scans`

Stores scan execution records.

| Field           | Type       | Required | Description                                   |
|-----------------|------------|----------|-----------------------------------------------|
| scan_id         | string     | Yes      | UUID — primary identifier (unique index)      |
| target_url      | string     | Yes      | The URL that was scanned                      |
| hostname        | string     | Yes      | Extracted hostname                            |
| status          | string     | Yes      | `pending`, `running`, `completed`, `failed`, `partial` |
| created_at      | datetime   | Yes      | Scan creation timestamp                       |
| completed_at    | datetime   | No       | Scan completion timestamp                     |
| duration_ms     | float      | No       | Total scan duration in milliseconds           |
| risk_score      | float      | No       | Overall risk score (0–100)                    |
| risk_level      | string     | No       | `none`, `low`, `medium`, `high`, `critical`   |
| module_results  | array      | Yes      | Array of ModuleResult objects                 |
| summary         | string     | No       | Human-readable summary                        |
| request_ip      | string     | No       | IP of the requesting client                   |

**Indexes:**
- `scan_id` (unique)
- `target_url`
- `status`
- `created_at`

**ModuleResult subdocument:**

| Field        | Type     | Description                          |
|--------------|----------|--------------------------------------|
| module       | string   | Module identifier                    |
| status       | string   | `pending`, `running`, `completed`, `failed`, `skipped`, `unavailable` |
| started_at   | datetime | Module start time                    |
| completed_at | datetime | Module completion time               |
| duration_ms  | float    | Module execution time                |
| data         | object   | Module-specific result data          |
| error        | string   | Error message if failed              |

---

### 2. `findings`

Individual detection results from modules.

| Field          | Type     | Required | Description                              |
|----------------|----------|----------|------------------------------------------|
| finding_id     | string   | Yes      | UUID — primary identifier                |
| scan_id        | string   | Yes      | Associated scan                          |
| module         | string   | Yes      | Module that generated this finding       |
| category       | string   | Yes      | Finding category (see API contract)      |
| title          | string   | Yes      | Short title                              |
| description    | string   | Yes      | Detailed description                     |
| severity       | string   | Yes      | `info`, `low`, `medium`, `high`, `critical` |
| confidence     | float    | Yes      | 0.0 – 1.0                               |
| evidence       | object   | No       | Supporting evidence                      |
| recommendation | string   | No       | Remediation guidance                     |
| created_at     | datetime | Yes      | Timestamp                                |

**Indexes:**
- `scan_id`
- `module`
- Compound: `(scan_id, module)`

---

### 3. `reports`

Community-submitted threat reports.

| Field            | Type     | Required | Description                                |
|------------------|----------|----------|--------------------------------------------|
| report_id        | string   | Yes      | UUID — primary identifier (unique index)   |
| url              | string   | Yes      | Reported URL                               |
| hostname         | string   | Yes      | Extracted hostname                         |
| category         | string   | Yes      | Threat category                            |
| description      | string   | Yes      | User-submitted description                 |
| reporter_contact | string   | No       | Optional contact info                      |
| reporter_ip      | string   | No       | Submitter IP address                       |
| status           | string   | Yes      | `pending`, `verified`, `rejected`, `under_review` |
| reviewer_notes   | string   | No       | Notes from reviewer                        |
| created_at       | datetime | Yes      | Submission timestamp                       |
| updated_at       | datetime | No       | Last update timestamp                      |

**Indexes:**
- `report_id` (unique)
- `reporter_ip`
- `hostname`
- `created_at`

---

### 4. `entities`

Nodes in the investigation graph.

| Field     | Type     | Required | Description                                 |
|-----------|----------|----------|---------------------------------------------|
| entity_id | string   | Yes      | UUID — primary identifier (unique index)    |
| type      | string   | Yes      | Entity type (see API contract)              |
| value     | string   | Yes      | Entity value (domain, IP, etc.)             |
| metadata  | object   | No       | Additional metadata                         |
| first_seen| datetime | Yes      | First observation timestamp                 |
| last_seen | datetime | Yes      | Most recent observation                     |
| scan_ids  | array    | Yes      | Scans that discovered this entity           |

**Indexes:**
- `entity_id` (unique)
- `type`
- `value`
- Compound unique: `(type, value)` — prevents duplicate entities

---

### 5. `relationships`

Edges in the investigation graph.

| Field              | Type     | Required | Description                             |
|--------------------|----------|----------|-----------------------------------------|
| relationship_id    | string   | Yes      | UUID — primary identifier               |
| source_entity_id   | string   | Yes      | Source entity                           |
| target_entity_id   | string   | Yes      | Target entity                           |
| type               | string   | Yes      | Relationship type (see API contract)    |
| scan_id            | string   | Yes      | Scan that discovered this relationship  |
| confidence         | float    | Yes      | 0.0 – 1.0                              |
| metadata           | object   | No       | Additional data                         |
| created_at         | datetime | Yes      | Timestamp                               |

**Indexes:**
- `source_entity_id`
- `target_entity_id`
- `scan_id`

---

## ID Generation

All IDs are UUID v4 strings generated by Python's `uuid.uuid4()`. Do not use MongoDB `_id` as an external identifier.

## Timestamps

All timestamps are UTC `datetime` objects. The API serializes them as ISO 8601 strings.

## Schema Versioning

If schema changes are needed, coordinate through the team. Add new fields as optional with defaults — never remove or rename existing fields without migration.
