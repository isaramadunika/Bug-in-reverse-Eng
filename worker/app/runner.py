import logging
import shutil
import time
from pathlib import Path
from typing import Dict, Any

from .config import settings
from .db import (
    complete_job,
    fail_job,
    get_connection,
    persist_analysis_results,
    record_stage_event,
)
from .models import AnalysisResult
from .pipeline.manifest import ManifestParser, parse_manifest_file
from .pipeline.rules import evaluate_static_rules
from .pipeline.secrets import scan_for_secrets
from .pipeline.unpacker import unpack_apk

logger = logging.getLogger("reversebug.worker.runner")

def execute_scan_job(job: Dict[str, Any]):
    job_id = job["id"]
    scan_id = job["scan_id"]
    payload = job.get("payload") or {}
    artifact_version_id = payload.get("artifact_version_id")

    logger.info("Starting execution for scan job %s (scan %s)", job_id, scan_id)

    # 1. Fetch artifact details from database
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT a.storage_key, a.sha256, av.original_filename
                FROM artifact_versions av
                JOIN artifacts a ON a.id = av.artifact_id
                WHERE av.id = %s;
                """,
                (artifact_version_id,),
            )
            row = cur.fetchone()
            if not row:
                raise ValueError(f"Artifact version {artifact_version_id} not found in database")
            storage_key, artifact_sha256, original_filename = row

    # Resolve APK file on disk
    apk_path = settings.storage_dir / storage_key
    if not apk_path.is_file():
        # Fallback check relative to repository root
        alt_path = Path("api/data/storage") / storage_key
        if alt_path.is_file():
            apk_path = alt_path
        else:
            alt_path2 = Path("../api/data/storage") / storage_key
            if alt_path2.is_file():
                apk_path = alt_path2
            else:
                raise FileNotFoundError(f"Storage object {storage_key} not found at {apk_path}")

    extract_dir = None
    try:
        # Stage 1: Unpacking & validation
        start_t = time.perf_counter()
        record_stage_event(scan_id, "unpacking", "started", "Extracting APK archive and validating integrity")
        extract_dir, verified_sha256 = unpack_apk(apk_path, artifact_sha256)
        dur_ms = int((time.perf_counter() - start_t) * 1000)
        record_stage_event(scan_id, "unpacking", "completed", f"Extracted successfully ({dur_ms}ms)", dur_ms)

        # Stage 2: Manifest Analysis
        start_t = time.perf_counter()
        record_stage_event(scan_id, "manifest_analysis", "started", "Parsing AndroidManifest.xml and registering components")
        manifest_path = extract_dir / "AndroidManifest.xml"
        manifest = parse_manifest_file(manifest_path)
        dur_ms = int((time.perf_counter() - start_t) * 1000)
        record_stage_event(
            scan_id,
            "manifest_analysis",
            "completed",
            f"Parsed {len(manifest.components)} components and {len(manifest.permissions)} permissions",
            dur_ms,
        )

        # Stage 3: Static Security Rules Pack
        start_t = time.perf_counter()
        record_stage_event(scan_id, "rules_engine", "started", "Evaluating static security rules")
        comp_findings, comp_evidence, comp_occurrences = evaluate_static_rules(
            manifest, verified_sha256
        )
        dur_ms = int((time.perf_counter() - start_t) * 1000)
        record_stage_event(
            scan_id,
            "rules_engine",
            "completed",
            f"Evaluated static rules, identified {len(comp_findings)} findings",
            dur_ms,
        )

        # Stage 4: Secret & Entropy Scanning
        start_t = time.perf_counter()
        record_stage_event(scan_id, "secrets_scan", "started", "Scanning files and assets for hardcoded secrets")
        secret_findings, secret_evidence, secret_occurrences = scan_for_secrets(
            extract_dir, verified_sha256
        )
        dur_ms = int((time.perf_counter() - start_t) * 1000)
        record_stage_event(
            scan_id,
            "secrets_scan",
            "completed",
            f"Secret scan completed, identified {len(secret_findings)} secret exposures",
            dur_ms,
        )

        # Combine all findings
        all_findings = comp_findings + secret_findings
        all_evidence = comp_evidence + secret_evidence
        all_occurrences = comp_occurrences + secret_occurrences

        result = AnalysisResult(
            package_name=manifest.package_name,
            version_name=manifest.version_name,
            version_code=manifest.version_code,
            min_sdk=manifest.min_sdk,
            target_sdk=manifest.target_sdk,
            permissions=manifest.permissions,
            components=manifest.components,
            findings=all_findings,
            evidence=all_evidence,
            occurrences=all_occurrences,
        )

        # Persist results and complete job
        persist_analysis_results(scan_id, artifact_version_id, verified_sha256, result)
        complete_job(job_id)
        record_stage_event(scan_id, "completed", "completed", "Static analysis pipeline completed successfully")
        logger.info(
            "Scan %s completed with %d findings and score calculated",
            scan_id,
            len(all_findings),
        )

    except Exception as e:
        logger.exception("Scan job %s failed: %s", job_id, e)
        fail_job(job_id, scan_id, str(e))
        record_stage_event(scan_id, "static_analysis", "failed", f"Analysis failed: {e}")
        raise
    finally:
        if extract_dir and extract_dir.exists():
            shutil.rmtree(extract_dir, ignore_errors=True)
