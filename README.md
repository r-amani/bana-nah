# PHANTOM

**Phishing Detection & Digital Threat Investigation Platform** – a full‑stack security platform that goes beyond simple URL checks to provide forensic snapshots, campaign‑level correlation, and an interactive investigation graph.

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black)
![MongoDB](https://img.shields.io/badge/MongoDB-6.0%2B-47A248?logo=mongodb&logoColor=white)
![Tests](https://img.shields.io/badge/Tests-65%20passing-brightgreen)
![License](https://img.shields.io/badge/License-MIT-blue)

---

## Table of Contents

1. [Problem](#2-problem)
2. [Solution](#3-solution)
3. [Demo Links & Screenshot](#4-demo-links--screenshot)
4. [Tech Stack](#5-tech-stack)
5. [Architecture](#6-architecture)
6. [Setup & Run Steps](#7-setup--run-steps)
7. [Disclosures](#8-disclosures)
8. [Track](#9-track)

---

## 1. Project Name and One‑Line Description

**PHANTOM** – **Phishing Detection & Digital Threat Investigation Platform**

### What makes PHANTOM different?
| Feature | Highlights |
|---|---|
| **Phishing Flight Recorder** | Captures point‑in‑time security snapshots; shows new vs. resolved findings; highlights TLS certificate changes and missing security headers. |
| **Attack Family Fingerprinting** | Correlates suspicious domains via shared IPs, TLS fingerprints, brand impersonation, and lexical similarity to surface related campaign infrastructure. |
| **Interactive Investigation Graph** | Visual, node‑drag‑and‑drop SVG graph linking domains, IPs, certificates and reports; supports zoom/pan and evidence inspection. |
| **Advanced TLS Certificate Intelligence** | Deep X.509 parsing, chain verification with system CAs, CT SCT auditing, brand‑impersonation detection, and precise error preservation. |

---

## 2. Problem

- **Phishing attacks** now use sophisticated look‑alike domains, Unicode homographs, and valid HTTPS certificates to trick users.
- **Typosquatting and punycode** allow attackers to register names that appear identical to legitimate brands.
- A valid TLS padlock **does not guarantee legitimacy**; many phishing kits obtain free, trusted certificates.
- Analysts lack **historical visibility** – they cannot see how a site’s security posture changes over time.
- Correlating **related malicious infrastructure** (shared IPs, certificates, branding) is manual and error‑prone.

---

## 3. Solution

PHANTOM tackles these gaps with eight tightly‑integrated capabilities:
1. **URL Threat Detection** – lexical analysis, punycode & typosquatting checks, DNS‑based indicators.
2. **TLS Certificate Validation & Intelligence** – verified chain, expiration, hostname mismatch, CT SCTs, and brand‑impersonation signals.
3. **Website Security Assessment** – security‑header audit, redirect chain, and DOM form heuristics.
4. **Explainable Risk Scoring** – weighted, multi‑factor score (0‑100) with a clear breakdown of each contributing finding.
5. **Community Threat Reporting** – crowdsourced reports with moderation workflow; optional VirusTotal, AbuseIPDB, Shodan enrichments.
6. **Phishing Flight Recorder** – immutable snapshots per scan; delta analysis highlights newly‑appearing or resolved threats.
7. **Attack Family Fingerprinting** – evidence‑based clustering using shared IPs, TLS fingerprints, brand similarity and lexical distance.
8. **Interactive Investigation Graph** – deterministic entity IDs, deduplicated edges, and a responsive SVG canvas for analysts.

### Five‑Stage Investigation Pipeline
```
URL Validation → Primary Detection (URL, TLS, Security, Community) →
Risk Scoring → Flight Recorder → Attack Fingerprinting → Graph Enrichment → Persistence
```
All stages run asynchronously inside the FastAPI backend and results are stored in MongoDB for fast retrieval.

---

## 4. Demo Links & Screenshot

| Resource | Link |
|---|---|
| **GitHub Repository** | https://github.com/rittikasarkar16/bana-nah |
| **Live Application** | <!-- TODO: Add deployed URL --> `[Add Live Demo URL]` |
| **Demo Video (≤3 min)** | <!-- TODO: Upload and link video --> `[Add Demo Video URL]` |
| **Swagger API Docs** | `http://127.0.0.1:8000/docs` *(local dev)* |
| **Health Check** | `http://127.0.0.1:8000/health` *(local dev)* |

### Application screenshot

> No screenshot is present in the repository. Add a PNG of the dashboard to `docs/screenshot.png` and replace the placeholder below:

```
![PHANTOM Dashboard](docs/screenshot.png)
```

---

## 5. Tech Stack

**Frontend** – React 18, JavaScript (ES Modules), Vite 6, CSS.

**Backend** – Python 3.11+, FastAPI 0.115, Pydantic 2, Uvicorn, HTTPX, Cryptography, DNSPython, SlowAPI, BeautifulSoup4, lxml.

**Database & Testing** – MongoDB 6+, Motor async driver, Pytest 9, pytest‑asyncio.

**Optional external intelligence** – VirusTotal, AbuseIPDB, Shodan (API keys are optional; the system degrades gracefully when omitted).

---

## 6. Architecture

```mermaid
flowchart TD
    U[User Browser] -->|HTTPS| FE[React SPA (Vite, port 3000)]
    FE -->|/api proxy| BE[FastAPI (port 8000)]
    BE --> URLV[URL Validation & SSRF Protection]
    URLV --> PIPE[Scanning Pipeline]
    subgraph PIPE [Five‑Stage Pipeline]
        D[Primary Detection]
        S[Risk Scoring]
        FR[Phishing Flight Recorder]
        AF[Attack Fingerprinting]
        GE[Graph Enrichment]
    end
    D --> S --> FR --> AF --> GE --> DB[MongoDB]
    DB --> BE --> FE --> U
```

- **Frontend** communicates with the backend via the Vite proxy (`/api/*`).
- **Backend** validates the URL, runs the five pipeline stages asynchronously, and stores scans, findings, entities, relationships, and snapshots in MongoDB.
- **Investigation Graph** data is built during the Graph Enrichment stage and served through the `/api/graph` endpoint for the interactive canvas.

---

## 7. Setup & Run Steps (Windows PowerShell)

### Prerequisites
| Tool | Minimum version |
|---|---|
| **Python** | 3.11 |
| **Node.js** | 18 LTS (includes npm) |
| **MongoDB** | 6.0 (local instance or Docker) |
| **Git** | any |

### 1️⃣ Clone the repository
```powershell
git clone https://github.com/rittikasarkar16/bana-nah.git
cd bana-nah
```

### 2️⃣ Backend setup
```powershell
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
# Edit .env if you need a custom MongoDB URI or external API keys
```

### 3️⃣ Start MongoDB (choose one)
```powershell
# Local mongod
mongod --dbpath C:\data\db

# Or Docker
docker run -d -p 27017:27017 --name phantom-mongo mongo:7
```

### 4️⃣ Launch the FastAPI backend
```powershell
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
Verify:
- Health: `http://127.0.0.1:8000/health`
- Swagger UI: `http://127.0.0.1:8000/docs`

### 5️⃣ Frontend setup (new terminal)
```powershell
cd ..\frontend
npm install
npm run dev
```
The dev server starts on **port 3000** and proxies `/api/*` to the backend.

### 6️⃣ Access the application
- Frontend UI: `http://localhost:3000`
- API docs & health as above.

### 7️⃣ Run the test suite (optional)
```powershell
cd ..\backend
.\venv\Scripts\Activate.ps1
pytest -q
```
**Result:** 65 tests passed.

> **Note:** VirusTotal, AbuseIPDB, and Shodan API keys are optional. If omitted the corresponding intelligence modules will report *not configured* and the scan will continue.

---

## 8. Disclosures

- **Open‑source libraries** used include FastAPI, Pydantic, Motor, HTTPX, Cryptography, dnspython, NetworkX, SlowAPI, BeautifulSoup4, lxml, validators, python‑whois, and their transitive dependencies (all MIT/BSD‑style licenses).
- **External APIs** – optional integrations with VirusTotal, AbuseIPDB, and Shodan (require user‑provided API keys). The platform degrades gracefully when keys are absent.
- **UI assets** – no third‑party UI frameworks, templates, or icon packs were imported; the dashboard is hand‑crafted CSS/JS.
- **AI assistance** – <!-- TODO: List AI coding assistants (e.g., GitHub Copilot, ChatGPT, Claude) used during development -->

No secrets, passwords, or private keys are stored in the repository; `.env.example` contains only placeholder values and `.env` is git‑ignored.

---

## 9. Track

[TEAM: INSERT OFFICIAL HACKMATRIX 2026 TRACK NAME]

*PHANTOM aligns with the cybersecurity/threat‑intelligence track by providing automated phishing detection, historical drift analysis, and campaign‑level correlation—all essential for modern defensive research.*

---

*This project is intended for authorized security research, defensive analysis, and educational use only. Findings are evidence‑based indicators and must be validated by a qualified analyst.*
