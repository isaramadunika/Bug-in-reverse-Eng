-- +goose Up
-- ReverseBug core schema v1.
-- Conventions: UUID primary keys (gen_random_uuid), timestamptz everywhere,
-- tenant ownership through organization_id, citext for case-insensitive email.

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

-- ---------------------------------------------------------------------------
-- Identity
-- ---------------------------------------------------------------------------
CREATE TABLE users (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email                 citext NOT NULL UNIQUE,
    display_name          text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 120),
    password_hash         text NOT NULL,
    email_verified_at     timestamptz,
    platform_role         text NOT NULL DEFAULT 'user'
                          CHECK (platform_role IN ('user','support_admin','billing_admin','system_admin')),
    status                text NOT NULL DEFAULT 'active'
                          CHECK (status IN ('active','suspended','pending_deletion','deleted')),
    mfa_totp_secret_enc   bytea,
    mfa_enabled_at        timestamptz,
    onboarding_completed_at timestamptz,
    onboarding_step       integer NOT NULL DEFAULT 0,
    theme_preference      text NOT NULL DEFAULT 'dark' CHECK (theme_preference IN ('dark','light','system')),
    failed_login_count    integer NOT NULL DEFAULT 0,
    locked_until          timestamptz,
    last_login_at         timestamptz,
    deletion_requested_at timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash      bytea NOT NULL UNIQUE,
    csrf_token      text NOT NULL,
    mfa_verified    boolean NOT NULL DEFAULT false,
    ip_address      inet,
    user_agent      text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_seen_at    timestamptz NOT NULL DEFAULT now(),
    idle_expires_at timestamptz NOT NULL,
    expires_at      timestamptz NOT NULL,
    revoked_at      timestamptz
);
CREATE INDEX sessions_user_idx ON sessions(user_id) WHERE revoked_at IS NULL;

-- Single-use tokens for email verification, password reset, account deletion confirmation.
CREATE TABLE user_tokens (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose     text NOT NULL CHECK (purpose IN ('email_verify','password_reset','account_delete')),
    token_hash  bytea NOT NULL UNIQUE,
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX user_tokens_user_purpose_idx ON user_tokens(user_id, purpose);

CREATE TABLE organizations (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 120),
    slug        text NOT NULL UNIQUE,
    is_personal boolean NOT NULL DEFAULT false,
    created_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE organization_members (
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id         uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role            text NOT NULL CHECK (role IN ('owner','admin','member','viewer')),
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, user_id)
);
CREATE INDEX organization_members_user_idx ON organization_members(user_id);

-- ---------------------------------------------------------------------------
-- Projects and artifacts
-- ---------------------------------------------------------------------------
CREATE TABLE projects (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 120),
    description     text NOT NULL DEFAULT '' CHECK (char_length(description) <= 2000),
    package_name    text CHECK (package_name IS NULL OR package_name ~ '^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$'),
    application_owner text NOT NULL DEFAULT '',
    environment     text NOT NULL DEFAULT 'production',
    tags            text[] NOT NULL DEFAULT '{}',
    created_by      uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    deleted_at      timestamptz
);
CREATE INDEX projects_org_idx ON projects(organization_id) WHERE deleted_at IS NULL;

CREATE TABLE project_members (
    project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role       text NOT NULL CHECK (role IN ('admin','editor','viewer')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, user_id)
);

CREATE TABLE authorization_records (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    attested_by     uuid NOT NULL REFERENCES users(id),
    basis           text NOT NULL CHECK (basis IN ('owner','employer','client_contract','bug_bounty_program','research_license')),
    scope_description text NOT NULL CHECK (char_length(scope_description) BETWEEN 10 AND 4000),
    allows_dynamic_validation boolean NOT NULL DEFAULT false,
    reference_url   text,
    valid_from      timestamptz NOT NULL DEFAULT now(),
    valid_until     timestamptz,
    ip_address      inet,
    created_at      timestamptz NOT NULL DEFAULT now(),
    revoked_at      timestamptz
);
CREATE INDEX authorization_records_project_idx ON authorization_records(project_id);

-- Content-addressed artifact (one row per unique APK per organization).
CREATE TABLE artifacts (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    sha256          char(64) NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    size_bytes      bigint NOT NULL CHECK (size_bytes > 0),
    storage_key     text NOT NULL,
    validation_status text NOT NULL DEFAULT 'pending'
                    CHECK (validation_status IN ('pending','valid','invalid')),
    validation_error text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, sha256)
);

-- A specific upload of an artifact into a project, with parsed metadata.
CREATE TABLE artifact_versions (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    artifact_id     uuid NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    original_filename text NOT NULL DEFAULT '',
    source          text NOT NULL CHECK (source IN ('upload','url_import','api')),
    source_url      text,
    package_name    text,
    version_name    text,
    version_code    bigint,
    min_sdk         integer,
    target_sdk      integer,
    signing_metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    permissions     text[] NOT NULL DEFAULT '{}',
    uploaded_by     uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX artifact_versions_project_idx ON artifact_versions(project_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- Scans and jobs
-- ---------------------------------------------------------------------------
CREATE TABLE scan_profiles (
    id          text PRIMARY KEY CHECK (id IN ('quick','standard','deep')),
    name        text NOT NULL,
    description text NOT NULL,
    stages      text[] NOT NULL,
    min_plan_rank integer NOT NULL DEFAULT 0
);

CREATE TABLE scans (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id          uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    artifact_version_id uuid NOT NULL REFERENCES artifact_versions(id) ON DELETE CASCADE,
    profile_id          text NOT NULL REFERENCES scan_profiles(id),
    authorization_record_id uuid NOT NULL REFERENCES authorization_records(id),
    status              text NOT NULL DEFAULT 'queued'
                        CHECK (status IN ('queued','running','cancelling','cancelled','completed','failed')),
    current_stage       text,
    last_completed_stage text,
    progress_numerator  integer,
    progress_denominator integer,
    failure_reason      text,
    security_score      integer CHECK (security_score BETWEEN 0 AND 100),
    score_state         text CHECK (score_state IN ('scored','insufficient_evidence')),
    score_version       text,
    score_breakdown     jsonb,
    analysis_coverage   jsonb,
    tool_versions       jsonb NOT NULL DEFAULT '{}'::jsonb,
    rule_pack_version   text,
    config_hash         text,
    previous_scan_id    uuid REFERENCES scans(id) ON DELETE SET NULL,
    requested_by        uuid REFERENCES users(id) ON DELETE SET NULL,
    idempotency_key     text,
    created_at          timestamptz NOT NULL DEFAULT now(),
    started_at          timestamptz,
    finished_at         timestamptz,
    UNIQUE (project_id, idempotency_key)
);
CREATE INDEX scans_project_idx ON scans(project_id, created_at DESC);
CREATE INDEX scans_status_idx ON scans(status);

-- Authoritative queue (ADR-001). Claimed with FOR UPDATE SKIP LOCKED.
CREATE TABLE scan_jobs (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id       uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    kind          text NOT NULL CHECK (kind IN ('static_analysis','ai_triage','dynamic_validation','report')),
    status        text NOT NULL DEFAULT 'queued'
                  CHECK (status IN ('queued','running','succeeded','failed','cancelled','dead')),
    priority      integer NOT NULL DEFAULT 100,
    attempts      integer NOT NULL DEFAULT 0,
    max_attempts  integer NOT NULL DEFAULT 3,
    run_after     timestamptz NOT NULL DEFAULT now(),
    locked_by     text,
    locked_until  timestamptz,
    last_heartbeat_at timestamptz,
    last_error    text,
    payload       jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX scan_jobs_claim_idx ON scan_jobs(priority, run_after) WHERE status = 'queued';
CREATE INDEX scan_jobs_scan_idx ON scan_jobs(scan_id);

CREATE TABLE scan_stage_events (
    id          bigserial PRIMARY KEY,
    scan_id     uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    stage       text NOT NULL,
    status      text NOT NULL CHECK (status IN ('started','completed','skipped','failed')),
    message     text,
    duration_ms integer,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX scan_stage_events_scan_idx ON scan_stage_events(scan_id, id);

-- ---------------------------------------------------------------------------
-- Rules
-- ---------------------------------------------------------------------------
CREATE TABLE rule_definitions (
    id              text PRIMARY KEY,           -- e.g. RB-MANIFEST-001
    title           text NOT NULL,
    category        text NOT NULL,
    enabled         boolean NOT NULL DEFAULT true,
    current_version text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE rule_versions (
    rule_id          text NOT NULL REFERENCES rule_definitions(id) ON DELETE CASCADE,
    version          text NOT NULL,
    default_severity text NOT NULL CHECK (default_severity IN ('critical','high','medium','low','info')),
    cwe_ids          text[] NOT NULL DEFAULT '{}',
    masvs_ids        text[] NOT NULL DEFAULT '{}',
    mastg_ids        text[] NOT NULL DEFAULT '{}',
    description      text NOT NULL,
    remediation      text NOT NULL,
    definition       jsonb NOT NULL DEFAULT '{}'::jsonb,
    test_status      text NOT NULL DEFAULT 'untested' CHECK (test_status IN ('untested','passing','failing')),
    created_by       uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (rule_id, version)
);

-- ---------------------------------------------------------------------------
-- Findings and evidence
-- ---------------------------------------------------------------------------
CREATE TABLE findings (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    fingerprint     text NOT NULL,           -- stable across versions for comparison
    rule_id         text NOT NULL,
    rule_version    text NOT NULL,
    title           text NOT NULL,
    description     text NOT NULL,
    severity        text NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
    confidence      text NOT NULL CHECK (confidence IN ('high','medium','low')),
    verification_status text NOT NULL DEFAULT 'static_evidence'
                    CHECK (verification_status IN ('static_evidence','runtime_validated','likely_false_positive','inconclusive','needs_human_review')),
    reachability    text NOT NULL DEFAULT 'unknown'
                    CHECK (reachability IN ('reachable','unreachable','unknown')),
    category        text NOT NULL,
    cwe_ids         text[] NOT NULL DEFAULT '{}',
    masvs_ids       text[] NOT NULL DEFAULT '{}',
    impact          text NOT NULL DEFAULT '',
    preconditions   text NOT NULL DEFAULT '',
    remediation     text NOT NULL DEFAULT '',
    false_positive_notes text NOT NULL DEFAULT '',
    review_status   text NOT NULL DEFAULT 'open'
                    CHECK (review_status IN ('open','confirmed','false_positive','accepted_risk','fixed')),
    include_in_report boolean NOT NULL DEFAULT true,
    report_exclusion_reason text,
    duplicate_of    uuid REFERENCES findings(id) ON DELETE SET NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (scan_id, fingerprint)
);
CREATE INDEX findings_scan_sev_idx ON findings(scan_id, severity);

CREATE TABLE finding_occurrences (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id  uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    file_path   text,
    line_start  integer,
    line_end    integer,
    class_name  text,
    method_name text,
    component_name text,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX finding_occurrences_finding_idx ON finding_occurrences(finding_id);

CREATE TABLE evidence (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    finding_id      uuid REFERENCES findings(id) ON DELETE CASCADE,
    artifact_sha256 char(64) NOT NULL,
    evidence_type   text NOT NULL,
    location        text,                    -- file path or resource id
    line_start      integer,
    line_end        integer,
    byte_offset     bigint,
    excerpt         text NOT NULL DEFAULT '' CHECK (char_length(excerpt) <= 4000), -- sanitized
    raw_storage_key text,                    -- restricted object storage, optional
    rule_id         text,
    analysis_source text NOT NULL,
    tool_name       text NOT NULL,
    tool_version    text NOT NULL,
    confidence      text NOT NULL CHECK (confidence IN ('high','medium','low')),
    verification_status text NOT NULL DEFAULT 'observed' CHECK (verification_status IN ('observed','inferred','unverified')),
    redaction       jsonb NOT NULL DEFAULT '{}'::jsonb,
    provenance      jsonb NOT NULL DEFAULT '{}'::jsonb,
    collected_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX evidence_scan_idx ON evidence(scan_id);
CREATE INDEX evidence_finding_idx ON evidence(finding_id);

CREATE TABLE evidence_nodes (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id     uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    node_key    text NOT NULL,              -- deterministic key, e.g. "class:com.a.B"
    node_type   text NOT NULL CHECK (node_type IN (
                  'apk','component','permission','class','method','source_location','entry_point',
                  'sensitive_source','transformation','sink','finding','dependency','advisory',
                  'validation_result','remediation')),
    label       text NOT NULL,
    severity    text CHECK (severity IN ('critical','high','medium','low','info')),
    properties  jsonb NOT NULL DEFAULT '{}'::jsonb,
    evidence_id uuid REFERENCES evidence(id) ON DELETE SET NULL,
    UNIQUE (scan_id, node_key)
);
CREATE INDEX evidence_nodes_type_idx ON evidence_nodes(scan_id, node_type);

CREATE TABLE evidence_edges (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id     uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    source_id   uuid NOT NULL REFERENCES evidence_nodes(id) ON DELETE CASCADE,
    target_id   uuid NOT NULL REFERENCES evidence_nodes(id) ON DELETE CASCADE,
    edge_type   text NOT NULL CHECK (edge_type IN (
                  'DECLARES','CALLS','REFERENCES','REQUIRES_PERMISSION','READS_FROM','TRANSFORMS',
                  'FLOWS_TO','WRITES_TO','NETWORK_SENDS_TO','ASSOCIATED_WITH','SUPPORTED_BY',
                  'VALIDATED_BY','FIXED_BY')),
    relation_status text NOT NULL CHECK (relation_status IN ('observed','inferred','unverified')),
    evidence_id uuid REFERENCES evidence(id) ON DELETE SET NULL,
    provenance  jsonb NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (scan_id, source_id, target_id, edge_type)
);
CREATE INDEX evidence_edges_source_idx ON evidence_edges(scan_id, source_id);
CREATE INDEX evidence_edges_target_idx ON evidence_edges(scan_id, target_id);

CREATE TABLE components (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id     uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    kind        text NOT NULL CHECK (kind IN ('activity','service','receiver','provider','activity_alias')),
    name        text NOT NULL,
    exported    boolean,
    exported_explicit boolean NOT NULL DEFAULT false,
    permission  text,
    intent_filters jsonb NOT NULL DEFAULT '[]'::jsonb,
    UNIQUE (scan_id, kind, name)
);

CREATE TABLE dependencies (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id     uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ecosystem   text NOT NULL,
    name        text NOT NULL,
    version     text,
    purl        text,
    identification_method text NOT NULL,
    confidence  text NOT NULL CHECK (confidence IN ('high','medium','low')),
    UNIQUE (scan_id, ecosystem, name, version)
);

CREATE TABLE advisories (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    dependency_id uuid NOT NULL REFERENCES dependencies(id) ON DELETE CASCADE,
    source        text NOT NULL,       -- e.g. OSV
    advisory_id   text NOT NULL,
    summary       text NOT NULL DEFAULT '',
    severity      text,
    fixed_versions text[] NOT NULL DEFAULT '{}',
    fetched_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (dependency_id, source, advisory_id)
);

-- ---------------------------------------------------------------------------
-- AI
-- ---------------------------------------------------------------------------
CREATE TABLE agent_runs (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id       uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    finding_id    uuid REFERENCES findings(id) ON DELETE CASCADE,
    agent         text NOT NULL CHECK (agent IN ('re_analyst','validation_analyst','secret_auditor','risk_assessor','remediation_advisor','report_analyst')),
    provider      text NOT NULL,
    model         text NOT NULL,
    is_mock       boolean NOT NULL DEFAULT false,
    status        text NOT NULL CHECK (status IN ('running','succeeded','failed','rejected','budget_exceeded','timeout')),
    iterations    integer NOT NULL DEFAULT 0,
    tool_calls    integer NOT NULL DEFAULT 0,
    input_tokens  integer NOT NULL DEFAULT 0,
    output_tokens integer NOT NULL DEFAULT 0,
    cost_usd_micros bigint NOT NULL DEFAULT 0,
    error         text,
    started_at    timestamptz NOT NULL DEFAULT now(),
    finished_at   timestamptz
);
CREATE INDEX agent_runs_scan_idx ON agent_runs(scan_id);

CREATE TABLE ai_analyses (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_run_id  uuid NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
    scan_id       uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    finding_id    uuid REFERENCES findings(id) ON DELETE CASCADE,
    kind          text NOT NULL,
    output        jsonb NOT NULL,              -- schema-validated structured output
    cited_evidence_ids uuid[] NOT NULL DEFAULT '{}',
    schema_version text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ai_analyses_finding_idx ON ai_analyses(finding_id);

-- ---------------------------------------------------------------------------
-- Reports
-- ---------------------------------------------------------------------------
CREATE TABLE reports (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id       uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    format        text NOT NULL CHECK (format IN ('pdf','json','csv')),
    status        text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','generating','ready','failed')),
    storage_key   text,
    sha256        char(64),
    size_bytes    bigint,
    is_sample     boolean NOT NULL DEFAULT false,
    requested_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    error         text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    ready_at      timestamptz,
    expires_at    timestamptz
);
CREATE INDEX reports_scan_idx ON reports(scan_id);

-- ---------------------------------------------------------------------------
-- Billing and entitlements
-- ---------------------------------------------------------------------------
CREATE TABLE plans (
    id            text NOT NULL,                -- free, pro, researcher, team
    version       integer NOT NULL,
    name          text NOT NULL,
    rank          integer NOT NULL,
    price_cents   integer NOT NULL CHECK (price_cents >= 0),
    currency      char(3) NOT NULL DEFAULT 'USD',
    interval      text NOT NULL DEFAULT 'month' CHECK (interval IN ('month','year')),
    is_active     boolean NOT NULL DEFAULT true,
    is_public     boolean NOT NULL DEFAULT true,
    created_by    uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (id, version)
);

CREATE TABLE entitlements (
    plan_id       text NOT NULL,
    plan_version  integer NOT NULL,
    key           text NOT NULL,     -- e.g. scans_per_month, profile.deep, ai_triage
    limit_value   bigint,            -- NULL = unlimited / boolean feature
    enabled       boolean NOT NULL DEFAULT true,
    scope         text NOT NULL CHECK (scope IN ('organization','user','project')),
    PRIMARY KEY (plan_id, plan_version, key),
    FOREIGN KEY (plan_id, plan_version) REFERENCES plans(id, version) ON DELETE CASCADE
);

CREATE TABLE subscriptions (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id   uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    plan_id           text NOT NULL,
    plan_version      integer NOT NULL,
    status            text NOT NULL CHECK (status IN ('active','trialing','past_due','grace','cancelled','expired')),
    provider          text NOT NULL DEFAULT 'none',
    provider_subscription_id text,
    current_period_start timestamptz NOT NULL,
    current_period_end   timestamptz NOT NULL,
    cancel_at_period_end boolean NOT NULL DEFAULT false,
    grace_until       timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (plan_id, plan_version) REFERENCES plans(id, version)
);
CREATE UNIQUE INDEX subscriptions_one_live_per_org ON subscriptions(organization_id)
    WHERE status IN ('active','trialing','past_due','grace');

CREATE TABLE usage_counters (
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    period_start    date NOT NULL,
    metric          text NOT NULL,
    value           bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (organization_id, period_start, metric)
);

CREATE TABLE invoices (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    subscription_id   uuid NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
    provider_invoice_id text,
    amount_cents      integer NOT NULL,
    currency          char(3) NOT NULL,
    status            text NOT NULL CHECK (status IN ('draft','open','paid','void','uncollectible','refunded','disputed')),
    period_start      timestamptz,
    period_end        timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider_invoice_id)
);

CREATE TABLE payment_events (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    provider          text NOT NULL,
    provider_event_id text NOT NULL,
    event_type        text NOT NULL,
    signature_valid   boolean NOT NULL,
    processed_at      timestamptz,
    processing_error  text,
    payload           jsonb NOT NULL,
    received_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider, provider_event_id)       -- replay protection / idempotency
);

-- ---------------------------------------------------------------------------
-- API keys
-- ---------------------------------------------------------------------------
CREATE TABLE api_keys (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id         uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name            text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
    prefix          text NOT NULL UNIQUE,
    secret_hmac     bytea NOT NULL,
    scopes          text[] NOT NULL CHECK (array_length(scopes, 1) >= 1),
    usage_limit     bigint,
    usage_count     bigint NOT NULL DEFAULT 0,
    expires_at      timestamptz,
    last_used_at    timestamptz,
    last_used_ip    inet,
    revoked_at      timestamptz,
    revoked_by      uuid REFERENCES users(id) ON DELETE SET NULL,
    disabled_by_admin boolean NOT NULL DEFAULT false,
    rotated_from    uuid REFERENCES api_keys(id) ON DELETE SET NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    CHECK (NOT (scopes && ARRAY['admin','admin:*']))
);
CREATE INDEX api_keys_user_idx ON api_keys(user_id);

CREATE TABLE api_usage_events (
    id          bigserial PRIMARY KEY,
    api_key_id  uuid NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
    method      text NOT NULL,
    route       text NOT NULL,
    status_code integer NOT NULL,
    duration_ms integer NOT NULL,
    ip_address  inet,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX api_usage_events_key_time_idx ON api_usage_events(api_key_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- Audit, notifications, feedback, settings
-- ---------------------------------------------------------------------------
CREATE TABLE audit_events (
    id              bigserial PRIMARY KEY,
    occurred_at     timestamptz NOT NULL DEFAULT now(),
    actor_user_id   uuid REFERENCES users(id) ON DELETE SET NULL,
    actor_api_key_id uuid REFERENCES api_keys(id) ON DELETE SET NULL,
    actor_type      text NOT NULL CHECK (actor_type IN ('user','api_key','system','worker','anonymous')),
    organization_id uuid REFERENCES organizations(id) ON DELETE SET NULL,
    action          text NOT NULL,
    target_type     text,
    target_id       text,
    outcome         text NOT NULL CHECK (outcome IN ('success','failure','denied')),
    ip_address      inet,
    user_agent      text,
    metadata        jsonb NOT NULL DEFAULT '{}'::jsonb,
    prev_hash       bytea,
    row_hash        bytea
);
CREATE INDEX audit_events_time_idx ON audit_events(occurred_at DESC);
CREATE INDEX audit_events_actor_idx ON audit_events(actor_user_id, occurred_at DESC);
CREATE INDEX audit_events_action_idx ON audit_events(action, occurred_at DESC);

-- Audit log is append-only: block UPDATE/DELETE at the database level.
-- Retention purges run as a dedicated role that temporarily disables this trigger.
-- +goose StatementBegin
CREATE FUNCTION audit_events_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    -- Permit only the FK-nulling performed by ON DELETE SET NULL cascades.
    IF TG_OP = 'UPDATE'
       AND NEW.id = OLD.id AND NEW.occurred_at = OLD.occurred_at AND NEW.action = OLD.action
       AND NEW.outcome = OLD.outcome AND NEW.metadata = OLD.metadata
       AND NEW.actor_type = OLD.actor_type
       AND NEW.target_type IS NOT DISTINCT FROM OLD.target_type
       AND NEW.target_id IS NOT DISTINCT FROM OLD.target_id
       AND NEW.row_hash IS NOT DISTINCT FROM OLD.row_hash
       AND (NEW.actor_user_id IS NOT DISTINCT FROM OLD.actor_user_id OR NEW.actor_user_id IS NULL)
       AND (NEW.actor_api_key_id IS NOT DISTINCT FROM OLD.actor_api_key_id OR NEW.actor_api_key_id IS NULL)
       AND (NEW.organization_id IS NOT DISTINCT FROM OLD.organization_id OR NEW.organization_id IS NULL)
    THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'audit_events is append-only';
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER audit_events_no_update BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_immutable();

CREATE TABLE notifications (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind        text NOT NULL,
    title       text NOT NULL,
    body        text NOT NULL DEFAULT '',
    link        text,
    read_at     timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX notifications_user_idx ON notifications(user_id, created_at DESC);

CREATE TABLE feedback (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id  uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    user_id     uuid REFERENCES users(id) ON DELETE SET NULL,
    verdict     text NOT NULL CHECK (verdict IN ('true_positive','false_positive','needs_info','accepted_risk')),
    comment     text NOT NULL DEFAULT '' CHECK (char_length(comment) <= 4000),
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX feedback_finding_idx ON feedback(finding_id);

CREATE TABLE feature_flags (
    key         text PRIMARY KEY,
    enabled     boolean NOT NULL DEFAULT false,
    description text NOT NULL DEFAULT '',
    updated_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE system_settings (
    key         text PRIMARY KEY,
    value       jsonb NOT NULL,
    updated_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Reference data (not demo data): scan profiles, launch plans, flags.
-- ---------------------------------------------------------------------------
INSERT INTO scan_profiles (id, name, description, stages, min_plan_rank) VALUES
 ('quick', 'Quick Scan', 'Artifact validation, manifest and permission inspection, high-confidence basic rules.',
  ARRAY['validate','hash','metadata','manifest','rules_basic','normalize','score'], 0),
 ('standard', 'Standard Scan', 'Full static analysis with decompilation, secret detection, dependency checks, Evidence Graph and AI triage.',
  ARRAY['validate','hash','metadata','manifest','resources','dex','decompile','secrets','rules','dependencies','index','normalize','evidence','correlate','ai_triage','score','report'], 1),
 ('deep', 'Deep Analysis', 'Expanded call-reference and data-flow analysis, advanced rule packs, cross-finding correlation, optional authorized runtime validation.',
  ARRAY['validate','hash','metadata','manifest','resources','dex','decompile','secrets','rules','rules_advanced','dependencies','index','dataflow','normalize','evidence','correlate','ai_triage','validation','score','report'], 2);

INSERT INTO plans (id, version, name, rank, price_cents) VALUES
 ('free', 1, 'Free', 0, 0),
 ('pro', 1, 'Pro', 1, 1900),
 ('researcher', 1, 'Researcher', 2, 4900),
 ('team', 1, 'Team', 3, 14900);

INSERT INTO entitlements (plan_id, plan_version, key, limit_value, enabled, scope) VALUES
 ('free',1,'scans_per_month',5,true,'organization'),
 ('free',1,'profile.quick',NULL,true,'organization'),
 ('free',1,'reports_per_month',3,true,'organization'),
 ('free',1,'evidence_graph.basic',NULL,true,'organization'),
 ('free',1,'retention_days',14,true,'organization'),
 ('pro',1,'scans_per_month',50,true,'organization'),
 ('pro',1,'profile.quick',NULL,true,'organization'),
 ('pro',1,'profile.standard',NULL,true,'organization'),
 ('pro',1,'evidence_graph.full',NULL,true,'organization'),
 ('pro',1,'ai_triage',NULL,true,'organization'),
 ('pro',1,'version_comparison',NULL,true,'organization'),
 ('pro',1,'secret_inventory',NULL,true,'organization'),
 ('pro',1,'reports_per_month',50,true,'organization'),
 ('pro',1,'retention_days',90,true,'organization'),
 ('researcher',1,'scans_per_month',200,true,'organization'),
 ('researcher',1,'profile.quick',NULL,true,'organization'),
 ('researcher',1,'profile.standard',NULL,true,'organization'),
 ('researcher',1,'profile.deep',NULL,true,'organization'),
 ('researcher',1,'evidence_graph.full',NULL,true,'organization'),
 ('researcher',1,'ai_triage',NULL,true,'organization'),
 ('researcher',1,'ai_investigation_expanded',NULL,true,'organization'),
 ('researcher',1,'version_comparison',NULL,true,'organization'),
 ('researcher',1,'secret_inventory',NULL,true,'organization'),
 ('researcher',1,'api_access',NULL,true,'organization'),
 ('researcher',1,'api_requests_per_month',20000,true,'organization'),
 ('researcher',1,'reports_per_month',500,true,'organization'),
 ('researcher',1,'retention_days',365,true,'organization'),
 ('team',1,'scans_per_month',1000,true,'organization'),
 ('team',1,'profile.quick',NULL,true,'organization'),
 ('team',1,'profile.standard',NULL,true,'organization'),
 ('team',1,'profile.deep',NULL,true,'organization'),
 ('team',1,'evidence_graph.full',NULL,true,'organization'),
 ('team',1,'ai_triage',NULL,true,'organization'),
 ('team',1,'ai_investigation_expanded',NULL,true,'organization'),
 ('team',1,'version_comparison',NULL,true,'organization'),
 ('team',1,'secret_inventory',NULL,true,'organization'),
 ('team',1,'api_access',NULL,true,'organization'),
 ('team',1,'api_requests_per_month',100000,true,'organization'),
 ('team',1,'team_members',25,true,'organization'),
 ('team',1,'reports_per_month',2000,true,'organization'),
 ('team',1,'retention_days',365,true,'organization');

INSERT INTO feature_flags (key, enabled, description) VALUES
 ('url_import', false, 'Allow direct HTTPS APK URL import (SSRF-hardened).'),
 ('dynamic_validation', false, 'Allow optional authorized sandbox validation.'),
 ('registration_open', true, 'Allow public self-service registration.');

-- +goose Down
DROP TABLE IF EXISTS system_settings, feature_flags, feedback, notifications, audit_events,
  api_usage_events, api_keys, payment_events, invoices, usage_counters, subscriptions,
  entitlements, plans, reports, ai_analyses, agent_runs, advisories, dependencies, components,
  evidence_edges, evidence_nodes, evidence, finding_occurrences, findings, rule_versions,
  rule_definitions, scan_stage_events, scan_jobs, scans, scan_profiles, artifact_versions,
  artifacts, authorization_records, project_members, projects, organization_members,
  organizations, user_tokens, sessions, users CASCADE;
DROP FUNCTION IF EXISTS audit_events_immutable();
