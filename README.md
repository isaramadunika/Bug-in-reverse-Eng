# ReverseBug — AI-Powered Android Reverse Engineering & Security Intelligence SaaS

[![CI/CD Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Go Version](https://img.shields.io/badge/Go-1.24%2B-00ADD8?logo=go)](https://golang.org)
[![Python Version](https://img.shields.io/badge/Python-3.13%2B-3776AB?logo=python)](https://python.org)
[![React Version](https://img.shields.io/badge/React-19%20%2B%20TypeScript-61DAFB?logo=react)](https://react.dev)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16%20Authoritative-336791?logo=postgresql)](https://postgresql.org)
[![License](https://img.shields.io/badge/license-Proprietary-red.svg)]()

> **ReverseBug** is a production-grade, enterprise-ready Android APK reverse-engineering, static security analysis, and AI-assisted threat intelligence platform. Engineered with a strict zero-trust architecture, authoritative state management, cryptographic audit log hash chaining, interactive React Flow evidence graphs, and deterministic OWASP MASVS vulnerability correlation.

---

## Architecture & System Topology

ReverseBug separates stateless web orchestration from sandboxed asynchronous static analysis while keeping **PostgreSQL as the single authoritative source of truth and job queue**.

```mermaid
graph TD
    User([Security Analyst / CI/CD]) -->|HTTPS / REST API| Web[React 19 + TypeScript SPA]
    Web -->|JSON + CSRF / Cookies| API[Go 1.24 Chi API Gateway :8080]
    API -->|Bearer Token rb_live_...| API
    
    subgraph Storage & Infrastructure
        DB[(PostgreSQL 16\nAuthoritative State & Queue)]
        Redis[(Redis 7\nFixed-Window Rate Limiter)]
        Storage[(Quarantine & Artifact Storage\nLocal / S3)]
        Mailpit[(Mailpit SMTP :1025 / UI :8025)]
    end

    API -->|Auth, Attestation, Scans| DB
    API -->|Per-IP / Per-User Limits| Redis
    API -->|Quarantined APK Uploads| Storage
    API -->|Email Verification & Alerts| Mailpit

    subgraph Asynchronous Analysis Worker
        Worker[Python 3.13 Analysis Worker]
        Worker -->|FOR UPDATE SKIP LOCKED| DB
        Worker -->|Unpack & Decompile| Storage
        Worker -->|Static Rulepack Engine| Worker
        Worker -->|Shannon Entropy Scanner| Worker
        Worker -->|Evidence Graph Builder| Worker
        Worker -->|ReportLab PDF Engine| Worker
    end

    subgraph AI Threat Intelligence
        Copilot[AI Investigation Agent & Copilot]
        Copilot -->|Tool Registry QueryEvidence| DB
        Copilot -->|InspectSource & TracePaths| Storage
        Copilot -->|LLM Provider Anthropic/OpenAI/Gemini/Mock| LLM[(LLM Engine)]
    end

    API -->|AI Analysis Requests| Copilot
```

---

## Technology Stack

| Layer | Component | Technology & Rationale |
|---|---|---|
| **API & Gateway** | Backend Service | **Go 1.24+**, `go-chi/v5` router, `jackc/pgx/v5` connection pool, structured `log/slog`. |
| **Authentication** | Zero-Trust Auth | **Argon2id** password hashing (PHC format), **RFC 6238 TOTP MFA**, timing-safe HMAC-SHA256 API keys with server pepper. |
| **Audit Logging** | Tamper-Evident Logs | **Cryptographic Hash Chaining** (each row stores `prev_hash` & `row_hash` using HMAC-SHA256). |
| **Analysis Engine** | Static Worker | **Python 3.13**, `pydantic v2`, `networkx`, zip-slip quarantine protection, bytecode parsing, Shannon entropy calculation. |
| **Authoritative State** | Database & Queue | **PostgreSQL 16** with transactional `SELECT ... FOR UPDATE SKIP LOCKED` worker queue and 41 relational schema tables. |
| **Cache & Throttling** | Rate Limiter | **Redis 7** fixed-window algorithm with graceful memory fallback for standalone dev. |
| **AI Threat Agent** | Investigation Engine | Multi-turn reasoning agent with bounded execution budgets, strict tool permission checks, and cited evidence validation. |
| **Frontend Application** | Web Dashboard | **React 19**, **TypeScript**, **Tailwind CSS**, **Vite**, **React Flow v12** (evidence graph), **Monaco Editor** (decompiled bytecode & manifest inspection). |
| **Report Generation** | Reporting Engine | **ReportLab** pure-Python vector PDF generator + standalone responsive HTML report exporter. |

---

## Security Hardening & Zero-Knowledge Architecture

1. **ZIP-Slip & Compression Bomb Defense:**
   - File counts capped at $10,000$ entries, uncompressed size capped at $500\text{ MB}$, and compression ratio capped at $100\times$.
   - Path traversal prevention rejects entries with `..`, absolute paths, or invalid null characters.
2. **SSRF Hardening with DNS Pinning:**
   - URL imports resolve target DNS before connection, validating against non-routable CIDRs (RFC 1918, RFC 3927, RFC 4193, loopback, multicast).
   - Re-pins IP during the HTTP connection handshake to eliminate DNS rebinding time-of-check to time-of-use (TOCTOU) exploits.
3. **Zero-Knowledge API Keys:**
   - API tokens use format `rb_live_<prefix>_<random_hex>`.
   - Keys are verified using constant-time HMAC-SHA256 against `RB_API_KEY_PEPPER`. Plaintext keys are never stored in the database.
   - Database check constraint `CHECK (NOT (scopes && ARRAY['admin','admin:*']))` prevents privilege escalation to admin surfaces.
4. **Attestation of Authorization (AoA):**
   - Scans cannot be triggered without an immutable Attestation record confirming ownership or authorized penetration testing engagement.
5. **Tamper-Evident Audit Chain:**
   - Sequential audit logs link previous row hash to current row hash. Verified in real-time via `admin.audit_verify`.

---

## Local Development & Setup

### Prerequisites

- **Docker Desktop** (for PostgreSQL, Redis, Mailpit)
- **Go 1.24+**
- **Python 3.13+**
- **Node.js 20+** & **npm**

### Step 1: Start Container Infrastructure

Start the PostgreSQL database (port `5433`), Redis cache (port `6379`), and Mailpit SMTP inspector (ports `1025` and `8025`):

```powershell
# From project root
docker compose up -d
```

Verify containers are running:
```powershell
docker ps
```

### Step 2: Configure Environment

Copy `.env.example` to `.env` (already configured for local dev):
```powershell
Copy-Item .env.example .env
```

### Step 3: Run the Go API Server

The Go API automatically executes Goose database migrations on startup:

```powershell
cd api
$env:RB_DATABASE_URL="postgres://reversebug:reversebug_dev_password@127.0.0.1:5433/reversebug?sslmode=disable"
$env:RB_REDIS_URL="redis://127.0.0.1:6379/0"
$env:RB_ENV="development"
& 'C:\Program Files\Go\bin\go.exe' run cmd/api/main.go
```
*The API gateway starts at `http://localhost:8080`.*

### Step 4: Run the Python Analysis Worker

In a separate terminal, launch the worker daemon to claim and process analysis jobs:

```powershell
cd worker
& '.\.venv\Scripts\python.exe' -m app.main
```
*The worker daemon continuously polls the `scan_jobs` queue and processes pending analysis pipelines.*

### Step 5: Run the React Web Dashboard

In a separate terminal, launch the Vite dev server:

```powershell
cd web
npm run dev
```
*Open `http://localhost:5173` in your browser.*

---

## End-to-End Testing & Evaluation Guide

Follow these steps to run a complete penetration test and analysis pipeline on a sample Android APK.

### 1. Generating or Downloading a Test APK

#### Option A: Instant Local Vulnerable APK Generator (Recommended)
We provide a built-in generator script that packages an APK with simulated vulnerabilities (cleartext network security configs, hardcoded AWS/GitHub secrets, exported sensitive components, and excessive permissions):

```powershell
# Run from repository root
& 'worker\.venv\Scripts\python.exe' scripts/generate_test_apk.py test-vulnerable-app.apk
```
*This produces `test-vulnerable-app.apk` in your project root ready for scanning.*

#### Option B: Download Standard Vulnerable Mobile Apps
You can also download standard security benchmark APKs:
- **OWASP AndroGoat:** [GitHub Releases](https://github.com/satishpatani/AndroGoat/releases)
- **InsecureBankv2:** [GitHub Repository](https://github.com/dineshshetty/Android-InsecureBankv2)
- **Damn Vulnerable Bank App (DVBA):** [GitHub Releases](https://github.com/rewanthtammana/Damn-Vulnerable-Bank)
- **F-Droid Open Source Apps:** [f-droid.org](https://f-droid.org)

---

### 2. Full Workspace Walkthrough

#### Step 1: Account Creation & Email Verification
1. Navigate to `http://localhost:5173/register`.
2. Fill in your Name, Email (e.g. `analyst@reversebug.local`), and Password.
3. Open the **Mailpit Web UI** at `http://localhost:8025`.
4. Open the verification email and click the verification link (or copy the token and complete verification).
5. Sign in at `http://localhost:5173/login`.

#### Step 2: Complete the 12-Step Security Onboarding
- Follow the interactive onboarding modal detailing project organization, authorization records, quarantine rules, and evidence graphing.

#### Step 3: Create a Project & Attestation of Authorization
1. Go to **Projects** $\to$ **New Project**.
2. Enter Name: `Mobile Banking Security Audit`, Package Name: `com.reversebug.vulnerableapp`, Owner: `SecOps Team`.
3. Fill in the **Attestation of Authorization (AoA)** modal declaring that you have explicit testing authorization.

#### Step 4: Upload APK & Trigger Scan
1. In the project workspace, click **Upload Artifact**.
2. Drag and drop `test-vulnerable-app.apk` (or use the File Selector).
3. Click **Start Scan** and select your analysis profile:
   - **Quick Profile:** Android Manifest, DEX bytecode, and Secrets scan.
   - **Standard Profile:** Deep static rules, call-graph indexing, and taint analysis.
   - **Deep Profile:** Cross-finding correlation, AI agent triage, and full evidence graph.
4. Watch the real-time stage progress bar transition from `queued` $\to$ `unpacking` $\to$ `analyzing` $\to$ `scoring` $\to$ `completed`.

#### Step 5: Explore Findings & Evidence Graph
1. Navigate to the **Scan Detail** workspace.
2. Review the **Security Score (0-100)** and severity breakdown (Critical, High, Medium, Low, Informational).
3. Click on the **Evidence Graph** tab to interact with the React Flow v12 visualization:
   - Pan, zoom, and inspect nodes representing components, findings, and sensitive API calls.
   - Filter by severity or search for `AWS_KEY` or `InsecureCipher`.
4. Open the **Code Inspector** tab to view decompiled DEX classes and `AndroidManifest.xml` with syntax highlighting in Monaco Editor.

#### Step 6: AI-Assisted Security Copilot & Root-Cause Investigation
1. In the findings table, click **Investigate with AI** on any critical finding.
2. The AI Agent executes multi-turn tool reasoning (`QueryEvidence`, `InspectSource`, `ExplainRule`).
3. Inspect the verified root-cause analysis, blast-radius assessment, and copy the proposed remediation patch.
4. Use the floating **Scan Copilot** drawer to query the APK in natural language (e.g., *"Does this application transmit user credentials over cleartext HTTP?"*).

#### Step 7: Export Executive & Developer PDF Reports
1. In the scan workspace, click **Generate Report**.
2. Choose **Executive Summary** or **Technical Developer Report**.
3. Click **Download PDF** to generate a print-ready vector PDF document complete with severity distribution charts and finding breakdowns.

#### Step 8: Generate API Keys for CI/CD Pipelines
1. Navigate to **API Keys** in the top navbar (`/api-keys`).
2. Click **Generate New Key**, select scopes (`scans:read`, `scans:write`, `projects:read`), and click **Create Key**.
3. Copy your secret token (`rb_live_...`).
4. Test programmatic authentication using cURL:
   ```bash
   curl -X GET "http://localhost:8080/api/v1/projects" \
     -H "Authorization: Bearer YOUR_RB_LIVE_TOKEN"
   ```

#### Step 9: Administrator Console & Hash-Chain Audit Verification
1. To elevate a user to admin in local development, run:
   ```powershell
   docker exec -it reversebug-postgres psql -U reversebug -d reversebug -c "UPDATE users SET platform_role = 'system_admin' WHERE email = 'YOUR_EMAIL';"
   ```
2. Refresh the browser and click the **Admin** link in the navbar (`/admin`).
3. View platform-wide telemetry: Total Scans, Active Users, Artifact Storage, Average Score.
4. Click **Verify Hash Chain** to run cryptographic verification over all `audit_events` rows.

---

## Test Automation Suite

To run all automated test suites across backend Go, Python workers, and frontend React:

### 1. Go API Server Integration Tests
```powershell
cd api
& 'C:\Program Files\Go\bin\go.exe' test -v -count=1 ./internal/server
```
*Runs all integration suites including Auth, Upload quarantine, Evidence Graph, AI Copilot, and Phase 5 API Keys/Billing/Admin.*

### 2. Python Worker Unit & Static Analysis Tests
```powershell
cd worker
& '.\.venv\Scripts\pytest.exe' -v
```
*Validates ZIP-slip quarantine extraction, manifest parsing, Shannon entropy secret detection, evidence graph synthesis, and security scoring.*

### 3. Frontend Production TypeScript & Vite Build
```powershell
cd web
npm run build
```
*Runs TypeScript strict type-checking (`tsc -b`) and asset minification.*

---

## Environment Variables Reference

| Variable | Default (Dev) | Description |
|---|---|---|
| `RB_ENV` | `development` | Runtime environment (`development`, `staging`, `production`). |
| `RB_HTTP_ADDR` | `:8080` | Port and host address for the Go API server. |
| `RB_PUBLIC_BASE_URL` | `http://localhost:5173` | Public URL for the frontend SPA (used in verification emails). |
| `RB_DATABASE_URL` | `postgres://...:5433/reversebug` | PostgreSQL authoritative connection string. |
| `RB_REDIS_URL` | `redis://127.0.0.1:6379/0` | Redis rate limiting connection string. |
| `RB_STORAGE_DIR` | `../api/data/storage` | Local directory for quarantined uploads and decompiled output. |
| `RB_DATA_ENCRYPTION_KEY` | *(32 bytes base64)* | AES-256-GCM encryption key for TOTP MFA secrets. |
| `RB_API_KEY_PEPPER` | *(32 bytes base64)* | HMAC key for peppered API key verification. |
| `RB_SMTP_HOST` | `127.0.0.1` | SMTP server host (Mailpit in dev). |
| `RB_SMTP_PORT` | `1025` | SMTP port (Mailpit in dev). |
| `RB_AI_PROVIDER` | `mock` | Active AI provider (`mock`, `openai_compatible`, `anthropic`, `gemini`). |

---

## License

ReverseBug is proprietary enterprise security software. All rights reserved.
