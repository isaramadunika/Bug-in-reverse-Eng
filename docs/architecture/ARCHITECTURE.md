# ReverseBug — Architecture Plan

Status: living document. Last reviewed at the start of Phase 1.

## 1. Repository layout

```
ReverseBug/
├── api/                    Go API + orchestration (chi, pgx, slog)
│   ├── cmd/api/            HTTP server entrypoint
│   ├── cmd/rbctl/          Operator CLI (migrate, bootstrap-admin)
│   ├── internal/
│   │   ├── config/         Env-based configuration
│   │   ├── db/             pgx pool, embedded migrations runner
│   │   ├── auth/           Password hashing, sessions, tokens, MFA
│   │   ├── httpx/          Middleware, typed errors, JSON helpers
│   │   ├── mail/           SMTP mailer (Mailpit in dev)
│   │   ├── audit/          Append-only audit events
│   │   └── handlers/       REST handlers under /api/v1
│   └── migrations/         SQL migrations (goose format, embedded)
├── worker/                 Python analysis worker (Phase 2+)
├── web/                    React + TS + Vite + Tailwind
├── deploy/                 Docker Compose, Dockerfiles, prod manifests
├── docs/                   Architecture, ADRs, guides, threat model
└── .github/workflows/      CI
```

## 2. Logical services and runtime processes

| Logical service | Runtime process | Notes |
|---|---|---|
| Web app | `web` (static, served by nginx in prod) | SPA, route-level code splitting |
| API, auth, orchestration, metering, API keys, admin | `api` (Go) | Single deployable, modular packages |
| Upload quarantine | `api` + private bucket `rb-quarantine` | Never executes content |
| Static analysis, evidence graph, AI agents, reports | `worker` (Python) | Non-root, no network except DB/S3/LLM allowlist |
| Dynamic validation | `sandbox-worker` (optional, later) | Disposable emulator, isolated network |

Splitting into more processes is deferred until load measurements justify it.

## 3. Architecture decisions (ADRs)

### ADR-001: PostgreSQL is the single authoritative job queue
Go enqueues and Python consumes, so a language-specific queue (Asynq is Go-only, Celery is Python-only) would need a second system. Jobs live in `scan_jobs` and are claimed with `SELECT ... FOR UPDATE SKIP LOCKED`, with leases (`locked_until`) and heartbeats.
- Pros: one source of truth, transactional enqueue alongside scan creation, persisted transitions, no extra broker.
- Cons: polling latency (mitigated with `LISTEN/NOTIFY`); throughput ceiling is far above expected scan volume.
- Redis is used only for rate limiting, short-lived caches, and SSE fan-out. It is not authoritative.

### ADR-002: First-party session auth in Go
- Passwords: Argon2id via `golang.org/x/crypto/argon2` with per-hash salts in PHC string format.
- Sessions: 256-bit random opaque tokens in `HttpOnly; Secure; SameSite=Lax` cookies. Only the SHA-256 hash is stored, with idle and absolute expiry. Sessions are revocable.
- CSRF: SameSite cookies plus a required `X-CSRF-Token` header (double-submit token bound to the session) on all state-changing cookie-authenticated requests.
- MFA: TOTP (RFC 6238). Required before privileged admin actions.
- Email verification and reset tokens: random, single-use, hashed at rest, and short-lived.
- An external IdP (OIDC) can be added later behind the same session layer.

### ADR-003: API keys
Format `rb_live_<8-char prefix>_<32-byte base62 secret>`. The DB stores the prefix plus an HMAC-SHA256 of the secret, using a server-side pepper. Keys are shown once, scoped, expirable, and quota-limited. They can never carry admin scopes.

### ADR-004: Object storage
S3-compatible (MinIO in dev). Buckets: `rb-quarantine` (raw APKs), `rb-artifacts` (intermediate outputs), and `rb-reports`. All are private. Downloads use authenticated streaming through the API or short-lived presigned URLs.

### ADR-005: Deterministic scoring, AI only for explanation
The score is a pure, versioned function over normalized findings (`scoring_v1`). LLM output is schema-validated (Pydantic) and must cite evidence IDs that exist. Otherwise it is rejected.

### ADR-006: AI provider abstraction
Python `LLMProvider` protocol with `openai_compatible`, `anthropic`, `gemini`, and `mock` implementations. The mock provider is labelled as such in every output and the UI. A redaction pass runs before any external call.

### ADR-007: PDF generation with ReportLab
Pure Python with no headless browser in the worker image. That means a smaller attack surface and reproducible output.

## 4. Pipeline

Browser → API (authn/z, entitlement check) → quarantine bucket (hash, size, zip structure validation) → `scans` + `scan_jobs` rows (one transaction) → worker claims job → stages (validate → hash → metadata → manifest → resources → dex → decompile → secrets → rules → deps → index → normalize → evidence → correlate → AI triage → score → report) → each stage persisted to `scan_jobs.stage`/`scan_stage_events` → `LISTEN/NOTIFY` → API SSE stream.

## 5. Phase acceptance criteria

**Phase 1 — Foundation**
- `docker compose up` brings up postgres, redis, minio, mailpit, api, and web.
- Migrations create the full relational schema; `rbctl migrate` is idempotent.
- Register → verification email (Mailpit) → verify → login → logout → password reset all work end to end.
- Sessions are revocable, login is throttled, and audit events are written.
- Onboarding state is persisted. The wizard shows once and can be replayed.
- Public website pages and the authenticated dashboard shell render. The design system is in place.
- CI runs Go tests, web typecheck/tests/build, and Python tests.

**Phase 2 — Projects, uploads, first pipeline**
- CRUD projects with authorization records.
- APK upload validates the ZIP structure (entry count, ratio, path traversal) and computes SHA-256.
- URL import passes the SSRF test suite.
- Worker claims jobs; quick scan produces manifest/permission findings with evidence; cancellation works.

**Phase 3 — Findings, Evidence Graph, reports**
- Normalized findings carry evidence records.
- The graph API returns paged neighbourhoods; the React Flow UI supports filtering and highlighting.
- Monaco source view and a PDF/JSON/CSV report built from persisted data.

**Phase 4 — AI and scoring**
- Six agents with typed contracts and budgets; prompt-injection test fixtures.
- Deterministic `scoring_v1` with unit tests; tool registry with scope checks.

**Phase 5 — Billing, keys, metering**
- Plans/entitlements enforced server-side; usage metering.
- API keys with scopes, expiry, rotation, and revocation; payment-provider abstraction with signed, idempotent webhooks.

**Phase 6 — Admin, hardening, ops**
- Role-scoped admin console (support vs. system admin) with audit views.
- Worker controls; load tests; deployment, backup, and runbooks.
