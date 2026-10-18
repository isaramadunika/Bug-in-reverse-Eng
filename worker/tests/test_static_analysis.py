import io
import zipfile
from pathlib import Path
import pytest

from app.db import calculate_security_score
from app.models import ComponentModel, FindingModel
from app.pipeline.manifest import ManifestParser
from app.pipeline.rules import evaluate_static_rules
from app.pipeline.secrets import (
    redact_secret,
    scan_for_secrets,
    shannon_entropy,
)
from app.pipeline.unpacker import UnpackError, unpack_apk

def test_shannon_entropy():
    # Low entropy: repeated characters
    assert shannon_entropy("aaaaaaaaaaaa") < 1.0
    # High entropy: randomized base64 string
    assert shannon_entropy("w9X$qL2#pM8&kR5!vN1@zT4*") > 4.0

def test_redact_secret():
    assert redact_secret("AKIAIOSFODNN7EXAMPLE") == "AKIA************MPLE"
    assert redact_secret("sk_live_1234567890abcdef") == "sk_l****************cdef"
    assert redact_secret("short") == "*****"

def test_unpacker_zip_slip_defense(tmp_path: Path):
    apk_path = tmp_path / "slip.apk"
    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr("../../escape.txt", "malicious payload")

    with pytest.raises(UnpackError) as excinfo:
        unpack_apk(apk_path, "")
    assert "Dangerous entry" in str(excinfo.value) or "escape" in str(excinfo.value)

def test_manifest_parser_components():
    xml_data = """<?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android"
        package="com.example.bank"
        android:versionCode="100"
        android:versionName="1.0.0">
        <uses-permission android:name="android.permission.INTERNET" />
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
            <activity android:name=".DebugActivity" android:exported="true" />
            <service android:name=".PaymentService" android:exported="true" />
            <receiver android:name=".PushReceiver" android:exported="true" />
            <provider android:name=".UserProvider" android:exported="true" />
        </application>
    </manifest>
    """.encode("utf-8")

    parser = ManifestParser(xml_data)
    parser.parse()

    assert parser.package_name == "com.example.bank"
    assert parser.version_code == 100
    assert "android.permission.INTERNET" in parser.permissions
    assert parser.application_attrs.get("android:debuggable") == "true"
    assert len(parser.components) == 5

    # Run static rules
    findings, evidence, occurrences = evaluate_static_rules(parser, "0" * 64)
    rule_ids = {f.rule_id for f in findings}

    assert "RB-MANIFEST-DEBUGGABLE" in rule_ids
    assert "RB-MANIFEST-BACKUP" in rule_ids
    assert "RB-NET-CLEARTEXT" in rule_ids
    assert "RB-COMP-001" in rule_ids  # DebugActivity
    assert "RB-COMP-002" in rule_ids  # PushReceiver
    assert "RB-COMP-003" in rule_ids  # PaymentService
    assert "RB-COMP-004" in rule_ids  # UserProvider

def test_secrets_scanner(tmp_path: Path):
    source_dir = tmp_path / "extracted"
    source_dir.mkdir()
    res_file = source_dir / "keys.xml"
    res_file.write_text(
        """<resources>
            <string name="aws_key">AKIAIOSFODNN7EXAMPLE</string>
            <string name="stripe_key">sk_live_51Abcdef1234567890abcdef</string>
        </resources>""",
        encoding="utf-8",
    )

    findings, evidence, occurrences = scan_for_secrets(source_dir, "0" * 64)
    rule_ids = {f.rule_id for f in findings}

    assert "RB-SECRET-AWS" in rule_ids
    assert "RB-SECRET-STRIPE" in rule_ids

    # Check that excerpt in evidence does not expose raw secret
    for ev in evidence:
        assert "AKIAIOSFODNN7EXAMPLE" not in ev.excerpt
        assert "sk_live_51Abcdef1234567890abcdef" not in ev.excerpt

def test_calculate_security_score():
    # Clean scan
    assert calculate_security_score([]) == 100

    # 1 critical (-25), 1 high (-15), 1 medium (-5)
    findings = [
        FindingModel(
            fingerprint="fp1",
            rule_id="R1",
            title="T1",
            description="D1",
            severity="critical",
            confidence="high",
            category="secrets",
        ),
        FindingModel(
            fingerprint="fp2",
            rule_id="R2",
            title="T2",
            description="D2",
            severity="high",
            confidence="high",
            category="manifest",
        ),
        FindingModel(
            fingerprint="fp3",
            rule_id="R3",
            title="T3",
            description="D3",
            severity="medium",
            confidence="high",
            category="component",
        ),
    ]
    # 100 - 25 - 15 - 5 = 55
    assert calculate_security_score(findings) == 55

    # Clamp at 0 minimum
    excessive_findings = findings * 10
    assert calculate_security_score(excessive_findings) == 0
