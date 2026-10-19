import os
import re
from pathlib import Path
from typing import List, Tuple
from ..models import EvidenceModel, FindingModel, OccurrenceModel
from .rules import make_fingerprint

BYTECODE_RULES = [
    {
        "rule_id": "RB-CRYPTO-ECB",
        "title": "Insecure ECB Encryption Mode in Cipher Initialization",
        "regex": re.compile(r"AES/ECB/(?:PKCS5Padding|NoPadding)|DES/ECB", re.IGNORECASE),
        "severity": "high",
        "category": "crypto",
        "cwe": "CWE-327",
        "masvs": "MASVS-CRYPTO-1",
        "desc": "The application initializes cryptographic ciphers using Electronic Codebook (ECB) mode. ECB mode does not utilize an Initialization Vector (IV), causing identical plaintext blocks to encrypt into identical ciphertext blocks. This exposes encrypted payloads to frequency analysis, replay, and pattern deduction.",
        "impact": "Ciphertext pattern leakage allowing adversaries to recover structured plaintext without knowing the key.",
        "preconditions": "Extraction of encrypted local databases, tokens, or network payloads.",
        "remediation": "Migrate to AES-GCM (e.g. 'AES/GCM/NoPadding') with a unique 96-bit random IV per operation generated using SecureRandom.",
    },
    {
        "rule_id": "RB-NET-TRUSTALL",
        "title": "Insecure TrustManager / Disabled SSL Certificate Validation",
        "regex": re.compile(r"AllowAllHostnameVerifier|checkServerTrusted|TrustAllCerts|ALLOW_ALL_HOSTNAME_VERIFIER", re.IGNORECASE),
        "severity": "critical",
        "category": "network",
        "cwe": "CWE-295",
        "masvs": "MASVS-NETWORK-2",
        "desc": "A custom X509TrustManager or HostnameVerifier was detected that disables standard TLS server identity validation. This completely breaks HTTPS encryption, allowing adversaries on the local network (e.g. public Wi-Fi) to perform Man-in-the-Middle (MitM) traffic interception, credential harvesting, and active payload tampering.",
        "impact": "Full MitM eavesdropping and credential theft on all application network requests.",
        "preconditions": "Attacker positioned on the same network or controlling an intermediate router.",
        "remediation": "Remove custom TrustManagers that bypass certificate validation. Enforce TLS certificate validation using Android Network Security Configuration (res/xml/network_security_config.xml).",
    },
    {
        "rule_id": "RB-WEBVIEW-FILE-ACCESS",
        "title": "Insecure WebView Cross-Origin Local File Access Enabled",
        "regex": re.compile(r"setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)|setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)", re.IGNORECASE),
        "severity": "high",
        "category": "platform",
        "cwe": "CWE-749",
        "masvs": "MASVS-PLATFORM-2",
        "desc": "A WebView instance explicitly enables universal or cross-origin access from local file schemes (setAllowUniversalAccessFromFileURLs(true)). A malicious website or local HTML file rendered in this WebView can read arbitrary private files from the application sandbox (including tokens, databases, and preferences) and exfiltrate them.",
        "impact": "Arbitrary exfiltration of private application sandbox data, session tokens, and local databases.",
        "preconditions": "WebView loading untrusted or attacker-influenced file URLs.",
        "remediation": "Explicitly disable file URL access: call setAllowFileAccess(false), setAllowFileAccessFromFileURLs(false), and setAllowUniversalAccessFromFileURLs(false).",
    },
    {
        "rule_id": "RB-CODE-SQLI",
        "title": "Dynamic SQL Query Construction Without Parameter Binding",
        "regex": re.compile(r"rawQuery\s*\(\s*[\"'][^\"']*SELECT[^\"']*[\"']\s*\+|execSQL\s*\(\s*[\"'][^\"']*(?:INSERT|UPDATE|DELETE|DROP)[^\"']*[\"']\s*\+", re.IGNORECASE),
        "severity": "high",
        "category": "storage",
        "cwe": "CWE-89",
        "masvs": "MASVS-STORAGE-2",
        "desc": "An internal SQLite database query is constructed using dynamic string concatenation instead of parameterized binding arguments. Attackers providing tainted input or crafted Intent parameters can manipulate SQL syntax, bypass security checks, or corrupt database contents.",
        "impact": "Unauthorized database modification, data exfiltration, or denial of service.",
        "preconditions": "Untrusted user or Intent input supplied to the query.",
        "remediation": "Use parameterized queries with selection arguments (db.rawQuery(\"SELECT ... WHERE id = ?\", new String[]{id})) or modern ORMs like Room.",
    },
    {
        "rule_id": "RB-STORAGE-WORLD-READABLE",
        "title": "Insecure World-Readable or World-Writable File Creation",
        "regex": re.compile(r"MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE", re.IGNORECASE),
        "severity": "critical",
        "category": "storage",
        "cwe": "CWE-276",
        "masvs": "MASVS-STORAGE-1",
        "desc": "The application instantiates local storage files or preferences with MODE_WORLD_READABLE or MODE_WORLD_WRITEABLE. Any untrusted application installed on the same device can inspect, steal, or maliciously overwrite private application databases and tokens.",
        "impact": "Full compromise of application private sandbox data by any third-party app.",
        "preconditions": "Any malicious application installed on the same Android device.",
        "remediation": "Strictly use Context.MODE_PRIVATE for local file creation, or use Android Jetpack EncryptedFile.",
    },
    {
        "rule_id": "RB-CRYPTO-WEAK-HASH",
        "title": "Use of Cryptographically Broken Hashing Algorithm (MD5/SHA-1)",
        "regex": re.compile(r"MessageDigest\.getInstance\s*\(\s*[\"'](?:MD5|SHA-1|SHA1)[\"']\)", re.IGNORECASE),
        "severity": "medium",
        "category": "crypto",
        "cwe": "CWE-328",
        "masvs": "MASVS-CRYPTO-1",
        "desc": "The application initializes MessageDigest using MD5 or SHA-1. Both algorithms are mathematically broken due to practical collision attacks and must not be used for security-sensitive operations such as password storage, integrity checks, or signature generation.",
        "impact": "Hash collision attacks undermining data integrity and digital signature authenticity.",
        "preconditions": "Adversary capable of generating crafted collision payloads.",
        "remediation": "Upgrade hashing to SHA-256 (MessageDigest.getInstance(\"SHA-256\")) or SHA-512, and use Argon2id or PBKDF2 with salt for passwords.",
    },
    {
        "rule_id": "RB-LOG-SENSITIVE",
        "title": "Sensitive Credential Debug Logging in Production Binary",
        "regex": re.compile(r"Log\.(?:d|v|i)\s*\([^)]*(?:password|bearer|apiKey|creditCard)", re.IGNORECASE),
        "severity": "medium",
        "category": "storage",
        "cwe": "CWE-532",
        "masvs": "MASVS-STORAGE-3",
        "desc": "Verbose debug logging statements were identified outputting sensitive authentication or credential keywords. Logcat outputs can be read by connected USB debugging (ADB) or forensic device acquisition tools.",
        "impact": "Exposure of session tokens or user credentials in local system logs.",
        "preconditions": "Physical device access with USB debugging or log monitoring tools.",
        "remediation": "Strip all debug logging in release builds via ProGuard / R8 rules (-assumenosideeffects class android.util.Log { ... }).",
    },
]

ROOT_HEURISTIC_PATTERNS = re.compile(
    r"/system/xbin/su|/system/bin/su|/sbin/su|Superuser\.apk|com\.topjohnwu\.magisk|eu\.chainfire\.supersu|com\.noshufou\.android\.su",
    re.IGNORECASE,
)

def scan_bytecode_vulnerabilities(
    extract_dir: Path,
    artifact_sha256: str,
    max_file_size_mb: int = 30,
) -> Tuple[List[FindingModel], List[EvidenceModel], List[OccurrenceModel]]:
    findings: List[FindingModel] = []
    evidence: List[EvidenceModel] = []
    occurrences: List[OccurrenceModel] = []
    seen_fingerprints = set()

    max_bytes = max_file_size_mb * 1024 * 1024
    has_root_check = False
    has_dex_files = False

    target_extensions = {".dex", ".json", ".js", ".ts", ".xml", ".properties", ".txt"}

    for root, _, files in os.walk(extract_dir):
        for file in files:
            file_path = Path(root) / file
            ext = file_path.suffix.lower()

            if ext not in target_extensions:
                continue

            rel_path = file_path.relative_to(extract_dir).as_posix().replace("\x00", "")

            try:
                if file_path.stat().st_size > max_bytes:
                    continue
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            if not content:
                continue

            if ext == ".dex":
                has_dex_files = True

            # Check for root detection heuristics
            if not has_root_check and ROOT_HEURISTIC_PATTERNS.search(content):
                has_root_check = True

            # Match bytecode security rules
            for rule in BYTECODE_RULES:
                rule_id = rule["rule_id"]
                rx = rule["regex"]

                for match in rx.finditer(content):
                    raw_token = match.group(0).replace("\x00", "")
                    if not raw_token:
                        continue

                    fp = make_fingerprint(rule_id, f"{rel_path}:{raw_token[:16]}")
                    if fp in seen_fingerprints:
                        continue
                    seen_fingerprints.add(fp)

                    start_pos = match.start()
                    line_idx = content[:start_pos].count("\n") + 1

                    l_start = content.rfind("\n", max(0, start_pos - 100), start_pos)
                    l_start = 0 if l_start == -1 else l_start + 1
                    l_end = content.find("\n", match.end(), min(len(content), match.end() + 100))
                    l_end = len(content) if l_end == -1 else l_end

                    raw_snippet = content[l_start:l_end]
                    clean_snippet = "".join(c for c in raw_snippet if c.isprintable() or c in "\t ")
                    clean_snippet = clean_snippet.replace("\x00", "").strip()[:200]

                    findings.append(
                        FindingModel(
                            fingerprint=fp,
                            rule_id=rule_id,
                            title=rule["title"],
                            description=rule["desc"],
                            severity=rule["severity"],
                            confidence="high",
                            category=rule["category"],
                            cwe_ids=[rule["cwe"]],
                            masvs_ids=[rule["masvs"]],
                            impact=rule["impact"],
                            preconditions=rule["preconditions"],
                            remediation=rule["remediation"],
                        )
                    )

                    evidence.append(
                        EvidenceModel(
                            finding_fingerprint=fp,
                            evidence_type="bytecode_signature",
                            location=rel_path,
                            line_start=line_idx,
                            line_end=line_idx,
                            excerpt=clean_snippet or raw_token,
                            rule_id=rule_id,
                            confidence="high",
                        )
                    )

                    occurrences.append(
                        OccurrenceModel(
                            finding_fingerprint=fp,
                            file_path=rel_path,
                            line_start=line_idx,
                            line_end=line_idx,
                        )
                    )

    # Posture check: Lack of root detection in DEX applications
    if has_dex_files and not has_root_check:
        fp = make_fingerprint("RB-RESILIENCE-ROOT", "application_sandbox")
        if fp not in seen_fingerprints:
            findings.append(
                FindingModel(
                    fingerprint=fp,
                    rule_id="RB-RESILIENCE-ROOT",
                    title="Application Lacks Device Integrity & Root Detection Checks",
                    description="The application bytecode does not contain standard root detection or device integrity verification checks. On rooted or jailbroken devices, adversaries can attach dynamic instrumentation tools (e.g. Frida, Xposed), hook runtime methods, bypass authentication, and inspect memory-resident secrets.",
                    severity="medium",
                    confidence="high",
                    category="resilience",
                    cwe_ids=["CWE-693"],
                    masvs_ids=["MASVS-RESILIENCE-1"],
                    impact="Full client-side security control bypass via runtime hooking and memory tampering on compromised devices.",
                    preconditions="Device physical access or rooted operating system environment.",
                    remediation="Integrate Google Play Integrity API or multi-layered root detection heuristics to restrict execution or alert backends on compromised devices.",
                )
            )
            evidence.append(
                EvidenceModel(
                    finding_fingerprint=fp,
                    evidence_type="resilience_audit",
                    location="classes.dex",
                    excerpt="No su binary, Superuser, or Magisk integrity checks detected in Dalvik bytecode.",
                    rule_id="RB-RESILIENCE-ROOT",
                    confidence="high",
                )
            )
            occurrences.append(
                OccurrenceModel(
                    finding_fingerprint=fp,
                    file_path="classes.dex",
                )
            )

    return findings, evidence, occurrences
