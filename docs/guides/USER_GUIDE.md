# ReverseBug — User & Operator Guide

## 1. Quickstart: Running ReverseBug Locally

### Prerequisites
- Docker Engine & Docker Compose
- Go 1.23+ (installed on system or inside Docker)
- Node.js 20+

### Starting Infrastructure Services
```bash
# 1. Start PostgreSQL, Redis, and Mailpit
docker compose -f deploy/docker-compose.yml up -d postgres redis mailpit

# 2. Apply database migrations
cd api
go run ./cmd/rbctl migrate

# 3. Start the Go API server
go run ./cmd/api
# API is accessible at http://localhost:8080
```

### Starting the Frontend Development Server
```bash
cd web
npm install
npm run dev
# Web application is accessible at http://localhost:5173
```

---

## 2. Bootstrapping the First Administrator

Per security guidelines, ReverseBug does not ship with default administrative credentials:
1. Register a normal account through the UI at `http://localhost:5173/register` (e.g. `admin@reversebug.local`).
2. Verify the email address via the Mailpit web interface at `http://localhost:8025`.
3. Promote the user via the `rbctl` operator CLI:
```bash
cd api
go run ./cmd/rbctl bootstrap-admin -email=admin@reversebug.local -role=system_admin
```
4. Sign in to your account. You will now have administrative oversight and audit verification access.

---

## 3. Key Workflows

### Attestation of Authorization
Before running analysis on an APK, you must certify your legal basis:
- **Application Owner**: You created or hold copyright for the application.
- **Employer**: You are employed by the application developer and authorized to perform security testing.
- **Client Contract**: You are conducting an authorized third-party penetration test.
- **Bug Bounty Program**: You are operating strictly within the documented scope of a public or private vulnerability disclosure program.

### Scan Profiles
- **Quick Scan**: Manifest inspection, exported component access checks, dangerous permission combinations (&lt;1 min).
- **Standard Scan**: DEX decompilation, secret audit, dependency SBOM generation, Evidence Graph creation, and AI triage (~3-5 mins).
- **Deep Analysis**: Full inter-procedural call-graph traversal, data-flow sink tracking, advanced rule packs, and optional emulator sandbox execution (~10-15 mins).

### Multi-Factor Authentication (TOTP)
1. Go to **Settings** → **Multi-Factor Authentication**.
2. Click **Enable Two-Factor Authentication**.
3. Scan the secret into Google Authenticator or 1Password.
4. Enter the 6-digit verification code to activate.
