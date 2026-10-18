import hashlib
import json
import zipfile
from pathlib import Path
import psycopg
import pytest

from app.config import settings
from app.db import claim_job
from app.runner import execute_scan_job

def create_mock_vulnerable_apk(path: Path) -> str:
    """Creates a mock APK with manifest and embedded secret for E2E worker testing."""
    manifest_xml = """<?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android"
        package="io.reversebug.benchmark"
        android:versionCode="2026"
        android:versionName="2.6.0">
        <uses-permission android:name="android.permission.INTERNET" />
        <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
        <application
            android:debuggable="true"
            android:allowBackup="true"
            android:usesCleartextTraffic="true">
            <activity android:name=".MainActivity" android:exported="true">
                <intent-filter>
                    <action android:name="android.intent.action.MAIN" />
                    <category android:name="android.intent.category.LAUNCHER" />
                </intent-filter>
            </activity>
            <activity android:name=".SecretAdminActivity" android:exported="true" />
            <service android:name=".BackgroundSyncService" android:exported="true" />
            <receiver android:name=".SMSBroadcastReceiver" android:exported="true" />
            <provider android:name=".UserDataContentProvider" android:exported="true" />
        </application>
    </manifest>
    """
    strings_xml = """<resources>
        <string name="aws_access">AKIAIOSFODNN7EXAMP1E</string>
        <string name="stripe_live">sk_live_51ReverseBugSecretToken987654321</string>
    </resources>
    """
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest_xml.encode("utf-8"))
        zf.writestr("classes.dex", b"dex\n035\x00mockbytecode")
        zf.writestr("res/values/strings.xml", strings_xml.encode("utf-8"))

    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()

def test_e2e_worker_scan_execution(tmp_path: Path):
    try:
        conn = psycopg.connect(settings.database_url)
    except Exception as e:
        pytest.skip(f"Database not available for E2E worker test: {e}")

    with conn:
        with conn.cursor() as cur:
            # 1. Setup organization, user, project, auth record, artifact, version, scan, scan_job
            cur.execute("SELECT id FROM users LIMIT 1;")
            user_row = cur.fetchone()
            if not user_row:
                pytest.skip("No users in DB to bind E2E scan")
            user_id = user_row[0]

            cur.execute("SELECT id FROM organizations WHERE created_by = %s LIMIT 1;", (user_id,))
            org_row = cur.fetchone()
            org_id = org_row[0]

            # Create test project
            cur.execute(
                """
                INSERT INTO projects (organization_id, name, created_by)
                VALUES (%s, 'E2E Worker Benchmark Project', %s)
                RETURNING id;
                """,
                (org_id, user_id),
            )
            project_id = cur.fetchone()[0]

            # Create auth record
            cur.execute(
                """
                INSERT INTO authorization_records (project_id, attested_by, basis, scope_description)
                VALUES (%s, %s, 'research_license', 'ReverseBug automated E2E testing benchmark')
                RETURNING id;
                """,
                (project_id, user_id),
            )
            auth_record_id = cur.fetchone()[0]

            # Generate and store APK in storage_dir
            storage_dir = settings.storage_dir
            storage_dir.mkdir(parents=True, exist_ok=True)
            apk_filename = "e2e_test_app.apk"
            apk_path = storage_dir / "artifacts" / str(org_id)
            apk_path.mkdir(parents=True, exist_ok=True)
            target_apk_file = apk_path / apk_filename
            sha256_hex = create_mock_vulnerable_apk(target_apk_file)
            size_bytes = target_apk_file.stat().st_size
            storage_key = f"artifacts/{org_id}/{apk_filename}"

            # Create artifact
            cur.execute(
                """
                INSERT INTO artifacts (organization_id, sha256, size_bytes, storage_key, validation_status)
                VALUES (%s, %s, %s, %s, 'valid')
                ON CONFLICT (organization_id, sha256) DO UPDATE SET size_bytes = EXCLUDED.size_bytes
                RETURNING id;
                """,
                (org_id, sha256_hex, size_bytes, storage_key),
            )
            artifact_id = cur.fetchone()[0]

            # Create artifact version
            cur.execute(
                """
                INSERT INTO artifact_versions (project_id, artifact_id, original_filename, source, uploaded_by)
                VALUES (%s, %s, 'e2e_test_app.apk', 'upload', %s)
                RETURNING id;
                """,
                (project_id, artifact_id, user_id),
            )
            artifact_version_id = cur.fetchone()[0]

            # Create scan and scan_job
            cur.execute(
                """
                INSERT INTO scans (project_id, artifact_version_id, profile_id, authorization_record_id, status, requested_by)
                VALUES (%s, %s, 'standard', %s, 'queued', %s)
                RETURNING id;
                """,
                (project_id, artifact_version_id, auth_record_id, user_id),
            )
            scan_id = cur.fetchone()[0]

            cur.execute(
                """
                INSERT INTO scan_jobs (scan_id, kind, status, priority, payload)
                VALUES (%s, 'static_analysis', 'queued', 10, jsonb_build_object(
                    'scan_id', %s::text,
                    'artifact_version_id', %s::text
                ))
                RETURNING id;
                """,
                (scan_id, str(scan_id), str(artifact_version_id)),
            )
            job_id = cur.fetchone()[0]
            conn.commit()

    # 2. Worker claims job
    claimed = claim_job("e2e-worker-test")
    assert claimed is not None, "Worker failed to claim queued job"
    assert str(claimed["id"]) == str(job_id)

    # 3. Worker executes job
    execute_scan_job(claimed)

    # 4. Verify scan was completed with score, findings, components, and stage events
    with psycopg.connect(settings.database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT status, security_score, score_state, current_stage, last_completed_stage
                FROM scans WHERE id = %s;
                """,
                (scan_id,),
            )
            scan_status, score, score_state, current_stage, last_stage = cur.fetchone()
            assert scan_status == "completed"
            assert score is not None
            assert score_state == "scored"
            assert score < 100, f"Expected score deductions for vulnerable APK, got {score}"

            # Verify findings exist
            cur.execute("SELECT rule_id, severity FROM findings WHERE scan_id = %s;", (scan_id,))
            findings = cur.fetchall()
            rule_ids = {f[0] for f in findings}
            assert "RB-MANIFEST-DEBUGGABLE" in rule_ids
            assert "RB-SECRET-AWS" in rule_ids
            assert "RB-SECRET-STRIPE" in rule_ids
            assert "RB-COMP-001" in rule_ids

            # Verify components recorded
            cur.execute("SELECT kind, name, exported FROM components WHERE scan_id = %s;", (scan_id,))
            components = cur.fetchall()
            assert len(components) >= 5

            # Verify stage events recorded
            cur.execute("SELECT stage, status FROM scan_stage_events WHERE scan_id = %s ORDER BY id ASC;", (scan_id,))
            stages = cur.fetchall()
            stage_names = [s[0] for s in stages]
            assert "unpacking" in stage_names
            assert "manifest_analysis" in stage_names
            assert "rules_engine" in stage_names
            assert "secrets_scan" in stage_names
            assert "completed" in stage_names

            # Verify job marked succeeded
            cur.execute("SELECT status FROM scan_jobs WHERE id = %s;", (job_id,))
            job_status = cur.fetchone()[0]
            assert job_status == "succeeded"
