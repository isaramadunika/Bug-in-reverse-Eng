import json
import logging
from typing import Any, Dict, List, Optional
import psycopg
from psycopg.rows import dict_row
from .config import settings
from .models import AnalysisResult

logger = logging.getLogger("reversebug.worker.db")

def get_connection():
    return psycopg.connect(settings.database_url, autocommit=False)

def claim_job(worker_id: str) -> Optional[Dict[str, Any]]:
    """
    Claims a queued scan_job using SELECT FOR UPDATE SKIP LOCKED.
    Returns the claimed job row dictionary or None if queue is empty.
    """
    query = """
        SELECT id, scan_id, kind, payload, priority, attempts, max_attempts
        FROM scan_jobs
        WHERE status = 'queued' AND run_after <= now()
        ORDER BY priority ASC, run_after ASC
        FOR UPDATE SKIP LOCKED
        LIMIT 1;
    """
    update_query = """
        UPDATE scan_jobs
        SET status = 'running',
            locked_by = %s,
            locked_until = now() + interval '5 minutes',
            last_heartbeat_at = now(),
            attempts = attempts + 1,
            updated_at = now()
        WHERE id = %s
        RETURNING id, scan_id, kind, payload, priority, attempts, max_attempts;
    """
    with get_connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(query)
            row = cur.fetchone()
            if not row:
                conn.rollback()
                return None
            job_id = row["id"]
            cur.execute(update_query, (worker_id, job_id))
            claimed = cur.fetchone()

            # Update scans table status to running
            cur.execute(
                """
                UPDATE scans
                SET status = 'running',
                    started_at = COALESCE(started_at, now()),
                    current_stage = 'static_analysis'
                WHERE id = %s;
                """,
                (claimed["scan_id"],)
            )
            conn.commit()
            return claimed

def heartbeat_job(job_id: str, worker_id: str) -> bool:
    """Refreshes the worker lock on an active job."""
    query = """
        UPDATE scan_jobs
        SET locked_until = now() + interval '5 minutes',
            last_heartbeat_at = now(),
            updated_at = now()
        WHERE id = %s AND locked_by = %s AND status = 'running';
    """
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, (job_id, worker_id))
            conn.commit()
            return cur.rowcount > 0

def record_stage_event(
    scan_id: str,
    stage: str,
    status: str,
    message: Optional[str] = None,
    duration_ms: Optional[int] = None,
):
    query = """
        INSERT INTO scan_stage_events (scan_id, stage, status, message, duration_ms)
        VALUES (%s, %s, %s, %s, %s);
    """
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, (scan_id, stage, status, message, duration_ms))
            conn.commit()

def calculate_security_score(findings: list) -> int:
    """
    Deterministic scoring algorithm (scoring_v1):
    Base score: 100
    Critical finding: -25 points
    High finding: -15 points
    Medium finding: -5 points
    Low finding: -1 point
    Clamped strictly between 0 and 100.
    """
    score = 100
    deductions = {
        "critical": 25,
        "high": 15,
        "medium": 5,
        "low": 1,
        "info": 0,
    }
    for f in findings:
        sev = f.severity.lower() if hasattr(f, "severity") else f.get("severity", "").lower()
        score -= deductions.get(sev, 0)
    return max(0, min(100, score))

def persist_analysis_results(
    scan_id: str,
    artifact_version_id: str,
    artifact_sha256: str,
    result: AnalysisResult,
):
    with get_connection() as conn:
        with conn.cursor() as cur:
            # 1. Update artifact_versions metadata
            cur.execute(
                """
                UPDATE artifact_versions
                SET package_name = COALESCE(%s, package_name),
                    version_name = COALESCE(%s, version_name),
                    version_code = COALESCE(%s, version_code),
                    min_sdk = COALESCE(%s, min_sdk),
                    target_sdk = COALESCE(%s, target_sdk),
                    permissions = %s
                WHERE id = %s;
                """,
                (
                    result.package_name,
                    result.version_name,
                    result.version_code,
                    result.min_sdk,
                    result.target_sdk,
                    result.permissions,
                    artifact_version_id,
                ),
            )

            # 2. Insert components
            for comp in result.components:
                cur.execute(
                    """
                    INSERT INTO components (scan_id, kind, name, exported, exported_explicit, permission, intent_filters)
                    VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb)
                    ON CONFLICT (scan_id, kind, name) DO NOTHING;
                    """,
                    (
                        scan_id,
                        comp.kind,
                        comp.name,
                        comp.exported,
                        comp.exported_explicit,
                        comp.permission,
                        json.dumps(comp.intent_filters),
                    ),
                )

            # 3. Insert findings and map fingerprints to finding IDs
            finding_id_map = {}
            for f in result.findings:
                cur.execute(
                    """
                    INSERT INTO findings (
                        scan_id, fingerprint, rule_id, rule_version, title, description,
                        severity, confidence, verification_status, reachability, category,
                        cwe_ids, masvs_ids, impact, preconditions, remediation, review_status
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (scan_id, fingerprint) DO UPDATE
                    SET title = EXCLUDED.title
                    RETURNING id;
                    """,
                    (
                        scan_id,
                        f.fingerprint,
                        f.rule_id,
                        f.rule_version,
                        f.title,
                        f.description,
                        f.severity,
                        f.confidence,
                        f.verification_status,
                        f.reachability,
                        f.category,
                        f.cwe_ids,
                        f.masvs_ids,
                        f.impact,
                        f.preconditions,
                        f.remediation,
                        f.review_status,
                    ),
                )
                row = cur.fetchone()
                if row:
                    finding_id_map[f.fingerprint] = row[0]

            # 4. Insert evidence
            for ev in result.evidence:
                finding_id = finding_id_map.get(ev.finding_fingerprint)
                cur.execute(
                    """
                    INSERT INTO evidence (
                        scan_id, finding_id, artifact_sha256, evidence_type, location,
                        line_start, line_end, byte_offset, excerpt, rule_id, analysis_source,
                        tool_name, tool_version, confidence, verification_status, redaction, provenance
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb);
                    """,
                    (
                        scan_id,
                        finding_id,
                        artifact_sha256,
                        ev.evidence_type,
                        ev.location,
                        ev.line_start,
                        ev.line_end,
                        ev.byte_offset,
                        ev.excerpt,
                        ev.rule_id,
                        ev.analysis_source,
                        ev.tool_name,
                        ev.tool_version,
                        ev.confidence,
                        ev.verification_status,
                        json.dumps(ev.redaction),
                        json.dumps(ev.provenance),
                    ),
                )

            # 5. Insert finding occurrences
            for occ in result.occurrences:
                finding_id = finding_id_map.get(occ.finding_fingerprint)
                if finding_id:
                    cur.execute(
                        """
                        INSERT INTO finding_occurrences (
                            finding_id, file_path, line_start, line_end, class_name, method_name, component_name
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s);
                        """,
                        (
                            finding_id,
                            occ.file_path,
                            occ.line_start,
                            occ.line_end,
                            occ.class_name,
                            occ.method_name,
                            occ.component_name,
                        ),
                    )

            # 6. Compute security score & finalize scan
            score = calculate_security_score(result.findings)
            score_breakdown = {
                "algorithm": "scoring_v1",
                "base_score": 100,
                "final_score": score,
                "total_findings": len(result.findings),
                "by_severity": {
                    "critical": sum(1 for f in result.findings if f.severity == "critical"),
                    "high": sum(1 for f in result.findings if f.severity == "high"),
                    "medium": sum(1 for f in result.findings if f.severity == "medium"),
                    "low": sum(1 for f in result.findings if f.severity == "low"),
                    "info": sum(1 for f in result.findings if f.severity == "info"),
                },
            }

            cur.execute(
                """
                UPDATE scans
                SET status = 'completed',
                    security_score = %s,
                    score_state = 'scored',
                    score_version = 'scoring_v1',
                    score_breakdown = %s::jsonb,
                    last_completed_stage = 'static_analysis',
                    current_stage = 'completed',
                    progress_numerator = 100,
                    progress_denominator = 100,
                    finished_at = now()
                WHERE id = %s;
                """,
                (score, json.dumps(score_breakdown), scan_id),
            )
            conn.commit()

def fail_job(job_id: str, scan_id: str, error_message: str):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE scan_jobs
                SET status = 'failed',
                    last_error = %s,
                    updated_at = now()
                WHERE id = %s;
                """,
                (error_message, job_id),
            )
            cur.execute(
                """
                UPDATE scans
                SET status = 'failed',
                    failure_reason = %s,
                    finished_at = now()
                WHERE id = %s;
                """,
                (error_message, scan_id),
            )
            conn.commit()

def complete_job(job_id: str):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE scan_jobs
                SET status = 'succeeded',
                    updated_at = now()
                WHERE id = %s;
                """,
                (job_id,),
            )
            conn.commit()
