# ReverseBug — Threat Model (STRIDE Methodology)

## 1. System Overview & Boundaries

ReverseBug accepts untrusted third-party Android APK files and external URLs, decompiles bytecode, extracts resources, models evidence relationships, and triages vulnerabilities.

### Trust Boundaries
1. **Untrusted Internet → Public Web / API**: Users, bug bounty researchers, external URLs.
2. **Go API → PostgreSQL / Redis**: Authoritative state, sessions, rate limits.
3. **Go API → Private Object Storage**: Quarantined APKs and generated PDF reports.
4. **Go API → Isolated Analysis Workers**: Ephemeral workspaces, restricted network egress.
5. **Worker → External AI Provider**: Sanitized/redacted excerpts only, strict prompt/response bounds.

---

## 2. STRIDE Threat Analysis & Defenses

| Threat Category | Specific Attack Vector | ReverseBug Defensive Countermeasure |
| :--- | :--- | :--- |
| **Spoofing** | Forged session tokens or credential stuffing | • 256-bit random session tokens stored as SHA-256 digests.<br>• Argon2id password hashing with constant-time verification.<br>• NIST SP 800-63B password policy.<br>• Progressive account lockout & timing equalization.<br>• RFC 6238 TOTP Multi-Factor Authentication. |
| **Tampering** | Malicious APK archives (Zip-bombs, path traversal) | • Archive extraction limits: max 200MB, bounded compression ratios, entry count caps.<br>• Validation checks prevent `../` directory traversal in filenames.<br>• Content-addressed SHA-256 storage keys.<br>• Cryptographic hash chaining on append-only `audit_events`. |
| **Repudiation** | Denying initiated scans or unauthorized target submissions | • Mandatory **Attestation of Authorization** recording legal basis before any scan.<br>• Append-only `audit_events` with database-level triggers blocking UPDATE and DELETE. |
| **Information Disclosure** | Leakage of customer secrets found in decompiled code | • Shannon entropy classification and pattern detection with automated redaction.<br>• Redaction performed *before* displaying in UI, PDF reports, or sending to AI providers.<br>• Strict tenant isolation via SQL queries bound to organization membership. |
| **Denial of Service** | Resource exhaustion via large payloads or infinite loops | • Worker timeouts, CPU/memory quotas, and maximum decompilation runtimes.<br>• Rate limiting via Redis atomic fixed-window token scripts.<br>• Server-side token limits on all LLM queries. |
| **Elevation of Privilege** | Normal user calling administrative endpoints | • Server-side role checks (`support_admin`, `billing_admin`, `system_admin`) on `/api/v1/admin/*`.<br>• Enforced MFA verification for administrative sessions.<br>• API keys restricted from carrying `admin` scopes. |

---

## 3. Server-Side Request Forgery (SSRF) Defense for URL Import

Direct APK URL import is disabled by default via feature flags. When enabled:
- Only `https://` schemes are permitted.
- Hostnames are resolved to IP addresses prior to connection.
- Private, loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`), and cloud metadata IP ranges (`169.254.169.254`, `metadata.google.internal`) are blocked.
- DNS resolution is revalidated on every HTTP redirect to prevent DNS rebinding.
- Max download size and timeout are strictly capped.

---

## 4. Prompt Injection & AI Safety Boundaries

Decompiled Java source, Smali bytecode, and manifest strings are treated as **untrusted user input**:
- Artifact contents are isolated in data blocks and never formatted as system instructions.
- All AI responses are validated against strict Pydantic schemas.
- Hallucinated evidence is rejected: any finding citing non-existent evidence IDs is dropped.
- AI never executes arbitrary commands or acts as an unrestricted agent on the host system.
