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

def test_evidence_graph_builder():
    from app.pipeline.graph import GraphBuilder
    from app.models import AnalysisResult, ComponentModel, FindingModel

    res = AnalysisResult(
        package_name="com.test.app",
        version_code="10",
        version_name="1.0",
        permissions=["android.permission.CAMERA", "android.permission.INTERNET"],
        components=[
            ComponentModel(
                kind="activity",
                name="com.test.app.MainActivity",
                exported=True,
                exported_explicit=True,
                intent_filters=[{"actions": ["android.intent.action.MAIN"]}],
            ),
            ComponentModel(
                kind="service",
                name="com.test.app.InternalSyncService",
                exported=False,
                exported_explicit=True,
                permission="android.permission.CAMERA",
                intent_filters=[],
            ),
        ],
        findings=[
            FindingModel(
                fingerprint="fp_cam",
                rule_id="RB-PERM-001",
                title="Camera Access",
                description="Accesses camera",
                severity="medium",
                confidence="high",
                category="permission",
            )
        ]
    )

    builder = GraphBuilder("scan-123", "sha-abc", res)
    nodes, edges = builder.build()

    node_types = {n["node_type"] for n in nodes}
    assert "apk" in node_types
    assert "permission" in node_types
    assert "component" in node_types
    assert "entry_point" in node_types
    assert "finding" in node_types

    edge_types = {e["edge_type"] for e in edges}
    assert "DECLARES" in edge_types
    assert "REQUIRES_PERMISSION" in edge_types
    assert len(nodes) >= 5
    assert len(edges) >= 4

def test_clean_nul_sanitization():
    from app.db import clean_nul
    payload = {
        "title": "SQL Injection\x00 in auth",
        "description": "Found null byte \u0000 here",
        "nested": ["data\x001", {"key\x00": "val\x00ue"}],
        "number": 42,
    }
    cleaned = clean_nul(payload)
    assert cleaned["title"] == "SQL Injection in auth"
    assert cleaned["description"] == "Found null byte  here"
    assert cleaned["nested"][0] == "data1"
    assert "key" in cleaned["nested"][1]
    assert cleaned["nested"][1]["key"] == "value"
    assert cleaned["number"] == 42

def test_secrets_scanner_with_nul_bytes(tmp_path: Path):
    source_dir = tmp_path / "extracted_nul"
    source_dir.mkdir()
    res_file = source_dir / "binary_strings.dex"
    # Write mock binary dex data containing NUL bytes and an AWS secret
    res_file.write_bytes(
        b"\x00\x01\x00\x00classes.dex\x00\x00AKIAIOSFODNN7EXAMPLE\x00\x00more binary\x00\x00"
    )

    findings, evidence, occurrences = scan_for_secrets(source_dir, "0" * 64)
    assert any(f.rule_id == "RB-SECRET-AWS" for f in findings)
    for ev in evidence:
        # Crucial: PostgreSQL rejects NUL bytes
        assert "\x00" not in ev.excerpt
        assert "\u0000" not in ev.excerpt
        assert "\x00" not in (ev.location or "")

def test_unpacker_selective_extraction(tmp_path: Path):
    apk_path = tmp_path / "selective.apk"
    with zipfile.ZipFile(apk_path, "w") as zf:
        zf.writestr("AndroidManifest.xml", "<manifest></manifest>")
        zf.writestr("classes.dex", "dex bytecode")
        zf.writestr("assets/config.json", '{"key": "val"}')
        zf.writestr("res/drawable/image.png", "binary png data")
        zf.writestr("res/layout/activity_main.xml", "binary xml layout")
        zf.writestr("lib/arm64-v8a/libnative.so", "binary so")

    extracted_dir, _ = unpack_apk(apk_path, "")
    extracted_files = [p.relative_to(extracted_dir).as_posix() for p in extracted_dir.rglob("*") if p.is_file()]

    assert "AndroidManifest.xml" in extracted_files
    assert "classes.dex" in extracted_files
    assert "assets/config.json" in extracted_files
    # Irrelevant heavy assets should NOT be extracted
    assert "res/drawable/image.png" not in extracted_files
    assert "res/layout/activity_main.xml" not in extracted_files
    assert "lib/arm64-v8a/libnative.so" in extracted_files

def test_bytecode_vulnerability_scanner(tmp_path: Path):
    from app.pipeline.bytecode import scan_bytecode_vulnerabilities

    source_dir = tmp_path / "bytecode_test"
    source_dir.mkdir()
    dex_file = source_dir / "classes.dex"
    # Write mock bytecode with ECB cipher, TrustAllCerts, and WebView file access
    dex_file.write_bytes(
        b"Cipher.getInstance(\"AES/ECB/PKCS5Padding\");"
        b"TrustAllCerts = new X509TrustManager();"
        b"webSettings.setAllowUniversalAccessFromFileURLs(true);"
    )

    findings, evidence, occurrences = scan_bytecode_vulnerabilities(source_dir, "0" * 64)
    rule_ids = {f.rule_id for f in findings}

    assert "RB-CRYPTO-ECB" in rule_ids
    assert "RB-NET-TRUSTALL" in rule_ids
    assert "RB-WEBVIEW-FILE-ACCESS" in rule_ids
    assert "RB-RESILIENCE-ROOT" in rule_ids  # Detected lack of root check

def test_expanded_secrets_scanner(tmp_path: Path):
    source_dir = tmp_path / "expanded_secrets"
    source_dir.mkdir()
    config_file = source_dir / "app_config.json"
    config_file.write_text(
        '{"github": "ghp_1234567890abcdef1234567890abcdef1234",'
        ' "sendgrid": "SG.abcdefghijklmnopqrstuv.1234567890abcdefghijklmnopqrstuvwxyz12345678",'
        ' "twilio": "SK0123456789abcdef0123456789abcdef"}'
    )

    findings, evidence, occurrences = scan_for_secrets(source_dir, "0" * 64)
    rule_ids = {f.rule_id for f in findings}

    assert "RB-SECRET-GITHUB" in rule_ids
    assert "RB-SECRET-SENDGRID" in rule_ids
    assert "RB-SECRET-TWILIO" in rule_ids


def test_crash_surface_and_reverse_engineering_scanner(tmp_path: Path):
    from app.pipeline.re_engine import scan_reverse_engineering_and_crash_surface
    from app.pipeline.manifest import ManifestParser

    source_dir = tmp_path / "re_crash_test"
    source_dir.mkdir()

    # Create dummy classes.dex with crash & dynamic loading patterns
    dex_file = source_dir / "classes.dex"
    dex_content = (
        "public void onReceive(Context ctx, Intent intent) {\n"
        "    String param = intent.getStringExtra(\"user_token\");\n"
        "    PendingIntent pi = PendingIntent.getActivity(ctx, 0, intent, PendingIntent.FLAG_MUTABLE);\n"
        "    DexClassLoader loader = new DexClassLoader(\"/sdcard/payload.dex\", null, null, null);\n"
        "    String dbUrl = \"https://my-vulnerable-app.firebaseio.com\";\n"
        "}\n"
    )
    dex_file.write_text(dex_content)

    manifest_xml = (
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.app">\n'
        '  <application>\n'
        '    <activity android:name="com.test.app.VulnerableActivity" android:exported="true" />\n'
        '  </application>\n'
        '</manifest>\n'
    )
    manifest = ManifestParser(manifest_xml.encode("utf-8"))
    manifest.parse()

    findings, evidence, occurrences = scan_reverse_engineering_and_crash_surface(
        source_dir, manifest, "0" * 64
    )
    rule_ids = {f.rule_id for f in findings}

    assert "RB-CRASH-INTENT-DOS" in rule_ids
    assert "RB-CRASH-MUTABLE-PENDINGINTENT" in rule_ids
    assert "RB-REVERSE-DYNAMIC-LOAD" in rule_ids
    assert "RB-SENSITIVE-FIREBASE" in rule_ids
    assert "RB-REVERSE-ANTI-DEBUG-ABSENT" in rule_ids
    assert "RB-REVERSE-FRIDA-HOOK-ABSENT" in rule_ids
    assert "RB-SENSITIVE-TAPJACKING" in rule_ids


def test_elf_native_binary_audit(tmp_path: Path):
    import struct
    from app.pipeline.re_engine import audit_elf_native_binary

    so_dir = tmp_path / "lib" / "arm64-v8a"
    so_dir.mkdir(parents=True)
    so_path = so_dir / "libtest.so"

    # Construct minimal 64-bit ELF binary
    # Magic: \x7fELF, 64-bit (2), little endian (1), ELF version (1), System V (0), padding
    header = bytearray(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8)
    # e_type (2=ET_DYN), e_machine (183=AArch64), e_version (1)
    header.extend(struct.pack("<HHI", 3, 183, 1))
    # e_entry (0), e_phoff (64), e_shoff (0), e_flags (0), e_ehsize (64), e_phentsize (56), e_phnum (2), e_shentsize (64), e_shnum (0), e_shstrndx (0)
    header.extend(struct.pack("<QQQIHHHHHH", 0, 64, 0, 0, 64, 56, 2, 64, 0, 0))

    # Program header 1: PT_LOAD
    header.extend(struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, 0x1000, 0x1000, 0x1000))
    # Program header 2: PT_GNU_STACK with Execute flag (PF_X = 1) -> triggers RB-NATIVE-EXEC-STACK
    header.extend(struct.pack("<IIQQQQQQ", 0x6474E551, 1, 0, 0, 0, 0, 0, 8))

    so_path.write_bytes(header)

    so_findings = audit_elf_native_binary(so_path)
    rule_ids = {f["rule_id"] for f in so_findings}

    assert "RB-NATIVE-NO-CANARY" in rule_ids
    assert "RB-NATIVE-NO-RELRO" in rule_ids
    assert "RB-NATIVE-EXEC-STACK" in rule_ids
