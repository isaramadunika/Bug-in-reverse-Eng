import os
import re
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from ..models import ComponentModel, EvidenceModel, FindingModel, OccurrenceModel
from .manifest import ManifestParser
from .rules import make_fingerprint

# ---------------------------------------------------------------------------
# Reverse Engineering, Crash Resilience & Sensitive Data Scanning Engine
# ---------------------------------------------------------------------------

RE_CODE_RULES = [
    # 1. Crash / Fuzzing / IPC Denial-of-Service Attack Surface
    {
        "rule_id": "RB-CRASH-INTENT-DOS",
        "title": "Unprotected Intent Extra Deserialization (IPC Crash / Fuzzing Vector)",
        "regex": re.compile(
            r"(?:getIntent\s*\(\s*\)\.)?get(?:Extras|StringExtra|IntExtra|ParcelableExtra|SerializableExtra|BundleExtra|BooleanExtra)\s*\(",
            re.IGNORECASE,
        ),
        "severity": "high",
        "category": "crash",
        "cwe": "CWE-20",
        "masvs": "MASVS-PLATFORM-1",
        "desc": (
            "An exported component or IPC handler deserializes Intent extras without explicit null verification "
            "or boundary defensive checks. Adversaries or local intent fuzzers (e.g. 'am start', Drozer) can inject "
            "empty intents or mismatched serialized types, triggering an unhandled NullPointerException or BadParcelableException "
            "that immediately crashes the host process (Denial of Service)."
        ),
        "impact": "Application process crash (Denial of Service) when triggered by any unprivileged application on the device.",
        "preconditions": "Component is exported or reachable via IPC without signature-level permissions.",
        "remediation": (
            "Wrap intent parameter extraction in defensive try-catch blocks: "
            "'if (getIntent() != null && getIntent().getExtras() != null) { try { ... } catch (Exception e) { ... } }'."
        ),
    },
    {
        "rule_id": "RB-CRASH-MUTABLE-PENDINGINTENT",
        "title": "Mutable PendingIntent Created Without Flag Immutability",
        "regex": re.compile(
            r"PendingIntent\.(?:getActivity|getBroadcast|getService)\s*\([^)]*(?:FLAG_MUTABLE|(?:(?<!FLAG_IMMUTABLE)[0-9]+))\)",
            re.IGNORECASE,
        ),
        "severity": "high",
        "category": "crash",
        "cwe": "CWE-927",
        "masvs": "MASVS-PLATFORM-1",
        "desc": (
            "A PendingIntent instance is instantiated without explicitly specifying 'PendingIntent.FLAG_IMMUTABLE'. "
            "On modern Android runtimes, mutable PendingIntents allow malicious recipient apps to mutate the inner intent "
            "destination, rewrite parameters, hijack administrative tasks, or crash calling processes."
        ),
        "impact": "Intent redirection, privilege escalation, or IPC crash injection by malicious third-party apps.",
        "preconditions": "PendingIntent handed to notifications, alarms, or external components.",
        "remediation": "Always pass 'PendingIntent.FLAG_IMMUTABLE' unless mutable behavior is strictly required by design.",
    },
    {
        "rule_id": "RB-CRASH-FRAGMENT-INJECTION",
        "title": "Dynamic Fragment Instantiation with Intent-Controlled Class Name",
        "regex": re.compile(
            r"Fragment\.instantiate\s*\([^)]*(?:getIntent|getExtra|getStringExtra)",
            re.IGNORECASE,
        ),
        "severity": "high",
        "category": "crash",
        "cwe": "CWE-470",
        "masvs": "MASVS-PLATFORM-1",
        "desc": (
            "The application dynamically instantiates Android Fragments using classes specified directly in Intent extras. "
            "An attacker can pass the name of non-existent classes, internal private fragments, or incompatible components, "
            "causing fatal instantiation exceptions (ClassCastException / InstantiationException) or unauthorized internal screen rendering."
        ),
        "impact": "Remote or local intent fuzzing crash (DoS) and potential unauthorized access to private fragments.",
        "preconditions": "Exported activity instantiating fragments from Intent parameters.",
        "remediation": "Implement an allowlist of permitted fragment class names before calling Fragment.instantiate().",
    },

    # 2. Advanced Reverse Engineering & Dynamic Code Loading
    {
        "rule_id": "RB-REVERSE-DYNAMIC-LOAD",
        "title": "Dynamic Bytecode Execution via DexClassLoader / PathClassLoader",
        "regex": re.compile(
            r"(?:DexClassLoader|PathClassLoader|InMemoryDexClassLoader|dalvik\.system\.BaseDexClassLoader)",
            re.IGNORECASE,
        ),
        "severity": "high",
        "category": "reverse_engineering",
        "cwe": "CWE-470",
        "masvs": "MASVS-CODE-4",
        "desc": (
            "The application dynamically loads Dalvik executable code (DEX/JAR/APK) at runtime using DexClassLoader or PathClassLoader. "
            "Dynamic code loading bypasses static analysis auditing. If secondary DEX payloads are loaded from unencrypted, external, "
            "or temporary storage, local or network attackers can tamper with the payload to achieve arbitrary code execution."
        ),
        "impact": "Arbitrary code execution and subversion of mobile security controls via dynamic payload manipulation.",
        "preconditions": "Adversary capable of modifying dynamic secondary DEX file on device storage.",
        "remediation": "Bundle all executable logic directly within the primary APK package, or verify cryptographic signatures before loading.",
    },
    {
        "rule_id": "RB-REVERSE-REFLECTION",
        "title": "Invasive Reflection Invoking Internal / Restricted SDK APIs",
        "regex": re.compile(
            r"Class\.forName\s*\(\s*[\"'](?:android\.os\.SystemProperties|com\.android\.internal|dalvik\.system)",
            re.IGNORECASE,
        ),
        "severity": "medium",
        "category": "reverse_engineering",
        "cwe": "CWE-470",
        "masvs": "MASVS-CODE-4",
        "desc": (
            "The application utilizes Java reflection (Class.forName) to access hidden Android framework internals "
            "(android.os.SystemProperties, com.android.internal). This practice bypasses API level restrictions and "
            "may introduce unstable execution, hidden behavior, or evasion of runtime behavioral monitoring."
        ),
        "impact": "Execution of undocumented internal APIs and potential sandbox evasion.",
        "preconditions": "Runtime execution on supported Android OS distributions.",
        "remediation": "Replace hidden reflection calls with documented, official Android Jetpack / SDK public APIs.",
    },

    # 3. Deep Sensitive Data & Cloud Exposure Scanning
    {
        "rule_id": "RB-SENSITIVE-FIREBASE",
        "title": "Hardcoded Firebase Realtime Database URL Discovered",
        "regex": re.compile(
            r"https?://([a-zA-Z0-9_-]+)\.firebaseio\.com",
            re.IGNORECASE,
        ),
        "severity": "high",
        "category": "storage",
        "cwe": "CWE-200",
        "masvs": "MASVS-STORAGE-2",
        "desc": (
            "A Google Firebase Realtime Database URL was found hardcoded in the application assets or bytecode. "
            "If the Firebase project database rules (.read: true, .write: true) are misconfigured, attackers can directly "
            "query and download all customer databases, user records, and credentials without authentication."
        ),
        "impact": "Potential full exfiltration or unauthorized alteration of cloud databases.",
        "preconditions": "Firebase security rules permitting unauthenticated or overly permissive client read/write.",
        "remediation": "Audit Firebase Realtime Database security rules; enforce strict authenticated access per user ID.",
    },
    {
        "rule_id": "RB-SENSITIVE-S3-BUCKET",
        "title": "Hardcoded Cloud Storage Bucket URL Discovered",
        "regex": re.compile(
            r"https?://([a-zA-Z0-9.-]+)\.s3(?:[.-][a-zA-Z0-9-]+)?\.amazonaws\.com|s3://([a-zA-Z0-9._-]+)",
            re.IGNORECASE,
        ),
        "severity": "medium",
        "category": "storage",
        "cwe": "CWE-200",
        "masvs": "MASVS-STORAGE-2",
        "desc": (
            "An Amazon S3 or compatible object storage bucket endpoint was discovered embedded in the binary. "
            "Attackers can enumerate, inspect permissions, or scrape sensitive media, documents, and backups stored in the bucket."
        ),
        "impact": "Data exposure and unauthorized asset reconnaissance on cloud infrastructure.",
        "preconditions": "Misconfigured public bucket permissions (ListBucket, GetObject allowed).",
        "remediation": "Block public access on S3 buckets and deliver media through signed URLs via secure backend APIs.",
    },
    {
        "rule_id": "RB-SENSITIVE-CLIPBOARD",
        "title": "Sensitive Authentication Data Copied to System Clipboard",
        "regex": re.compile(
            r"(?:setPrimaryClip|ClipboardManager)\s*\([^)]*(?:password|token|pin|secret|auth|bearer)",
            re.IGNORECASE,
        ),
        "severity": "medium",
        "category": "storage",
        "cwe": "CWE-200",
        "masvs": "MASVS-STORAGE-3",
        "desc": (
            "The application places sensitive credential keywords (tokens, passwords, PINs) onto the Android system clipboard. "
            "On Android devices, clipboard contents can be monitored by third-party background applications or malicious keyboards, "
            "exposing user credentials to theft."
        ),
        "impact": "Credential leakage to untrusted third-party apps with clipboard read permissions.",
        "preconditions": "User triggering clipboard copy operations on sensitive input fields.",
        "remediation": "Avoid copying sensitive credentials to system clipboard, or set ClipDescription.EXTRA_IS_SENSITIVE on Android 13+.",
    },
]

# Anti-Reverse-Engineering / Anti-Debugging Heuristics
ANTI_DEBUG_PATTERNS = re.compile(
    r"isDebuggerConnected|TracerPid|PTRACE_TRACEME|android\.os\.Debug\.waitingForDebugger",
    re.IGNORECASE,
)

FRIDA_HOOK_PATTERNS = re.compile(
    r"frida-server|xposed\.installer|libfrida-gadget|27042|frida_agent|gum-js-loop",
    re.IGNORECASE,
)

# Known Commercial & Open Source Android Packers
KNOWN_PACKER_SIGNATURES = [
    ("Qihoo 360", re.compile(r"libprotectClass\.so|libjiagu\.so|libjiagu_art\.so", re.IGNORECASE)),
    ("Tencent Legu", re.compile(r"libtxloader\.so|libshell\.so|libshellx\.so", re.IGNORECASE)),
    ("Bangcle / SecShell", re.compile(r"libsecexe\.so|libsecmain\.so|libbangcle\.so", re.IGNORECASE)),
    ("DexProtector", re.compile(r"com\.dexprotector|dp\.arm64-v8a\.so", re.IGNORECASE)),
    ("Baidu Protect", re.compile(r"libbaiduprotect\.so", re.IGNORECASE)),
    ("Ijiami / SecNeo", re.compile(r"libexec\.so|libexec4p\.so", re.IGNORECASE)),
]


def audit_elf_native_binary(so_path: Path) -> List[Dict[str, Any]]:
    """
    Parses ELF header and program headers of a native shared library (.so)
    to verify binary exploitation hardening (RELRO, NX/DEP, Stack Canaries).
    """
    findings = []
    try:
        data = so_path.read_bytes()
    except Exception:
        return findings

    # Verify ELF magic: \x7fELF
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return findings

    is_64_bit = data[4] == 2
    # Endianness: 1 = Little Endian, 2 = Big Endian
    endian = "<" if data[5] == 1 else ">"

    has_relro = False
    has_exec_stack = False

    try:
        if is_64_bit:
            # ELF64: phoff is at offset 32 (8 bytes), phentsize at 54 (2 bytes), phnum at 56 (2 bytes)
            phoff = struct.unpack_from(f"{endian}Q", data, 32)[0]
            phentsize, phnum = struct.unpack_from(f"{endian}HH", data, 54)
            # Program header types: PT_GNU_RELRO = 0x6474e552, PT_GNU_STACK = 0x6474e551
            for i in range(phnum):
                offset = phoff + i * phentsize
                if offset + phentsize > len(data):
                    break
                p_type, p_flags = struct.unpack_from(f"{endian}II", data, offset)
                if p_type == 0x6474E552:  # PT_GNU_RELRO
                    has_relro = True
                elif p_type == 0x6474E551:  # PT_GNU_STACK
                    # PF_X = 1
                    if p_flags & 1 != 0:
                        has_exec_stack = True
        else:
            # ELF32: phoff is at offset 28 (4 bytes), phentsize at 42 (2 bytes), phnum at 44 (2 bytes)
            phoff = struct.unpack_from(f"{endian}I", data, 28)[0]
            phentsize, phnum = struct.unpack_from(f"{endian}HH", data, 42)
            for i in range(phnum):
                offset = phoff + i * phentsize
                if offset + phentsize > len(data):
                    break
                p_type = struct.unpack_from(f"{endian}I", data, offset)[0]
                p_flags = struct.unpack_from(f"{endian}I", data, offset + 24)[0]
                if p_type == 0x6474E552:
                    has_relro = True
                elif p_type == 0x6474E551:
                    if p_flags & 1 != 0:
                        has_exec_stack = True
    except Exception:
        pass

    # Check for stack canary symbol
    has_canary = b"__stack_chk_fail" in data

    rel_name = so_path.name
    if not has_canary:
        findings.append({
            "rule_id": "RB-NATIVE-NO-CANARY",
            "title": f"Native Library Missing Stack Canary Protection: {rel_name}",
            "desc": f"The shared native library '{rel_name}' was compiled without stack-smashing protection (__stack_chk_fail). Native buffer overflows can corrupt the return address on the stack, leading to remote code execution.",
            "severity": "high",
            "category": "native",
            "cwe": "CWE-121",
            "masvs": "MASVS-CODE-3",
            "impact": "Stack buffer overflow vulnerabilities leading to arbitrary code execution or native crash.",
            "remediation": "Recompile native code with '-fstack-protector-strong' or '-fstack-protector-all' flags.",
        })

    if not has_relro:
        findings.append({
            "rule_id": "RB-NATIVE-NO-RELRO",
            "title": f"Native Library Missing RELRO Hardening: {rel_name}",
            "desc": f"The shared library '{rel_name}' lacks Read-Only Relocations (RELRO). Attackers exploiting memory corruption can overwrite the Global Offset Table (GOT) function pointers to redirect execution flow.",
            "severity": "medium",
            "category": "native",
            "cwe": "CWE-119",
            "masvs": "MASVS-CODE-3",
            "impact": "Global Offset Table (GOT) overwrite attacks in native memory space.",
            "remediation": "Enable full RELRO during native compilation using '-Wl,-z,relro,-z,now'.",
        })

    if has_exec_stack:
        findings.append({
            "rule_id": "RB-NATIVE-EXEC-STACK",
            "title": f"Native Library Has Executable Stack (NX Disabled): {rel_name}",
            "desc": f"The shared library '{rel_name}' has an executable stack flag (PT_GNU_STACK PF_X). This disables No-Execute / Data Execution Prevention, allowing shellcode injected on the stack to execute directly.",
            "severity": "critical",
            "category": "native",
            "cwe": "CWE-119",
            "masvs": "MASVS-CODE-3",
            "impact": "Direct arbitrary shellcode execution on native stack frames.",
            "remediation": "Recompile native library with '-Wl,-z,noexecstack'.",
        })

    return findings


def scan_reverse_engineering_and_crash_surface(
    extract_dir: Path,
    manifest: Optional[ManifestParser],
    artifact_sha256: str,
    max_file_size_mb: int = 30,
) -> Tuple[List[FindingModel], List[EvidenceModel], List[OccurrenceModel]]:
    """
    Executes deep reverse engineering analysis, attack crash resilience scanning,
    sensitive data identification, and native library ELF binary audits.
    """
    findings: List[FindingModel] = []
    evidence: List[EvidenceModel] = []
    occurrences: List[OccurrenceModel] = []
    seen_fingerprints: Set[str] = set()

    max_bytes = max_file_size_mb * 1024 * 1024
    has_dex_files = False
    has_anti_debug = False
    has_frida_check = False
    detected_packers: Set[str] = set()

    target_extensions = {".dex", ".json", ".js", ".ts", ".xml", ".properties", ".txt"}

    # 1. Audit files for crash vectors, reflection, dynamic loading, and sensitive cloud storage
    for root, _, files in os.walk(extract_dir):
        for file in files:
            file_path = Path(root) / file
            ext = file_path.suffix.lower()

            # Native library inspection (.so)
            if ext == ".so":
                so_findings = audit_elf_native_binary(file_path)
                rel_path = file_path.relative_to(extract_dir).as_posix().replace("\x00", "")
                for sf in so_findings:
                    fp = make_fingerprint(sf["rule_id"], rel_path)
                    if fp in seen_fingerprints:
                        continue
                    seen_fingerprints.add(fp)

                    findings.append(
                        FindingModel(
                            fingerprint=fp,
                            rule_id=sf["rule_id"],
                            title=sf["title"],
                            description=sf["desc"],
                            severity=sf["severity"],
                            confidence="high",
                            category=sf["category"],
                            cwe_ids=[sf["cwe"]],
                            masvs_ids=[sf["masvs"]],
                            impact=sf["impact"],
                            preconditions="Physical or native execution context.",
                            remediation=sf["remediation"],
                        )
                    )
                    evidence.append(
                        EvidenceModel(
                            finding_fingerprint=fp,
                            evidence_type="elf_binary_audit",
                            location=rel_path,
                            excerpt=f"ELF binary hardening inspection for {file_path.name}",
                            rule_id=sf["rule_id"],
                            confidence="high",
                        )
                    )
                    occurrences.append(
                        OccurrenceModel(
                            finding_fingerprint=fp,
                            file_path=rel_path,
                        )
                    )
                continue

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

            # Anti-debugging check
            if not has_anti_debug and ANTI_DEBUG_PATTERNS.search(content):
                has_anti_debug = True

            # Frida / dynamic hooking detection
            if not has_frida_check and FRIDA_HOOK_PATTERNS.search(content):
                has_frida_check = True

            # Packer signature scanning
            for packer_name, rx in KNOWN_PACKER_SIGNATURES:
                if rx.search(rel_path) or rx.search(content[:4096]):
                    detected_packers.add(packer_name)

            # Match code rules
            for rule in RE_CODE_RULES:
                rule_id = rule["rule_id"]
                rx = rule["regex"]

                for match in rx.finditer(content):
                    raw_token = match.group(0).replace("\x00", "")
                    if not raw_token:
                        continue

                    fp = make_fingerprint(rule_id, f"{rel_path}:{raw_token[:20]}")
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
                            evidence_type="code_signature",
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

    # 2. Packer Detection Finding
    if detected_packers:
        packer_list = ", ".join(sorted(detected_packers))
        fp = make_fingerprint("RB-REVERSE-PACKER-DETECT", packer_list)
        if fp not in seen_fingerprints:
            seen_fingerprints.add(fp)
            findings.append(
                FindingModel(
                    fingerprint=fp,
                    rule_id="RB-REVERSE-PACKER-DETECT",
                    title=f"Commercial / Anti-Analysis Packer Detected: {packer_list}",
                    description=(
                        f"The application appears to be protected with a third-party packer or protector ({packer_list}). "
                        "The primary bytecode is unpacked dynamically into process memory at launch. While this impedes "
                        "naive reverse engineering, automated static analysis may not inspect classes packed in encrypted containers."
                    ),
                    severity="low",
                    confidence="high",
                    category="reverse_engineering",
                    cwe_ids=["CWE-693"],
                    masvs_ids=["MASVS-RESILIENCE-4"],
                    impact="Application bytecode is obfuscated/packed, requiring dynamic memory dumping for full inspection.",
                    preconditions="Binary reverse engineering analysis.",
                    remediation="Maintain verified symbol maps and perform authenticated SAST prior to packing stages.",
                )
            )
            evidence.append(
                EvidenceModel(
                    finding_fingerprint=fp,
                    evidence_type="packer_recon",
                    location="lib/ / classes.dex",
                    excerpt=f"Signatures identified: {packer_list}",
                    rule_id="RB-REVERSE-PACKER-DETECT",
                    confidence="high",
                )
            )
            occurrences.append(OccurrenceModel(finding_fingerprint=fp, file_path="classes.dex"))

    # 3. Anti-Debugging Posture
    if has_dex_files and not has_anti_debug:
        fp = make_fingerprint("RB-REVERSE-ANTI-DEBUG-ABSENT", "application_runtime")
        if fp not in seen_fingerprints:
            seen_fingerprints.add(fp)
            findings.append(
                FindingModel(
                    fingerprint=fp,
                    rule_id="RB-REVERSE-ANTI-DEBUG-ABSENT",
                    title="Application Lacks Anti-Debugging Defenses",
                    description=(
                        "The application does not implement active anti-debugging defenses (such as "
                        "android.os.Debug.isDebuggerConnected(), ptrace(PTRACE_TRACEME), or monitoring /proc/self/status TracerPid). "
                        "Adversaries can attach interactive debuggers (JDB, IDA Pro, Ghidra, GDB) to step through execution, "
                        "inspect cryptographic keys in RAM, and bypass runtime security validations."
                    ),
                    severity="medium",
                    confidence="high",
                    category="resilience",
                    cwe_ids=["CWE-693"],
                    masvs_ids=["MASVS-RESILIENCE-2"],
                    impact="Unrestricted debugger attachment allowing memory inspection and runtime control-flow alteration.",
                    preconditions="Device with USB debugging or root access.",
                    remediation="Incorporate anti-debugging routines that check Debug.isDebuggerConnected() and verify TracerPid.",
                )
            )
            evidence.append(
                EvidenceModel(
                    finding_fingerprint=fp,
                    evidence_type="resilience_audit",
                    location="classes.dex",
                    excerpt="No Debug.isDebuggerConnected() or ptrace debugging checks observed in Dalvik bytecode.",
                    rule_id="RB-REVERSE-ANTI-DEBUG-ABSENT",
                    confidence="high",
                )
            )
            occurrences.append(OccurrenceModel(finding_fingerprint=fp, file_path="classes.dex"))

    # 4. Frida / Dynamic Hooking Posture
    if has_dex_files and not has_frida_check:
        fp = make_fingerprint("RB-REVERSE-FRIDA-HOOK-ABSENT", "application_runtime")
        if fp not in seen_fingerprints:
            seen_fingerprints.add(fp)
            findings.append(
                FindingModel(
                    fingerprint=fp,
                    rule_id="RB-REVERSE-FRIDA-HOOK-ABSENT",
                    title="Application Lacks Dynamic Hooking / Frida Detection",
                    description=(
                        "The application bytecode lacks defenses against dynamic method hooking frameworks such as Frida or Xposed. "
                        "Security analysts and attackers can inject JavaScript hooks via Frida to bypass biometric login, "
                        "defeat SSL pinning, or intercept encrypted communications in memory."
                    ),
                    severity="medium",
                    confidence="high",
                    category="resilience",
                    cwe_ids=["CWE-693"],
                    masvs_ids=["MASVS-RESILIENCE-1"],
                    impact="Runtime method hooking allowing bypass of critical business logic and security controls.",
                    preconditions="Rooted or instrumented Android device with frida-server.",
                    remediation="Implement runtime integrity checks that inspect open ports (27042), loaded libraries, and memory map signatures.",
                )
            )
            evidence.append(
                EvidenceModel(
                    finding_fingerprint=fp,
                    evidence_type="resilience_audit",
                    location="classes.dex",
                    excerpt="No Frida server port or agent library detection heuristics observed in application bytecode.",
                    rule_id="RB-REVERSE-FRIDA-HOOK-ABSENT",
                    confidence="high",
                )
            )
            occurrences.append(OccurrenceModel(finding_fingerprint=fp, file_path="classes.dex"))

    # 5. Tapjacking / Screen Overlay Check on Exported Activities
    if manifest:
        for comp in manifest.components:
            if comp.kind == "activity" and comp.exported:
                # If exported, check if it's main launcher or sensitive
                is_launcher = False
                for filt in comp.intent_filters:
                    if "android.intent.action.MAIN" in filt.get("actions", []) and "android.intent.category.LAUNCHER" in filt.get("categories", []):
                        is_launcher = True
                        break
                if is_launcher:
                    continue

                fp = make_fingerprint("RB-SENSITIVE-TAPJACKING", comp.name)
                if fp not in seen_fingerprints:
                    seen_fingerprints.add(fp)
                    findings.append(
                        FindingModel(
                            fingerprint=fp,
                            rule_id="RB-SENSITIVE-TAPJACKING",
                            title=f"Exported Activity Vulnerable to Tapjacking / UI Overlays: {comp.name.split('.')[-1]}",
                            description=(
                                f"The exported activity '{comp.name}' does not enforce 'android:filterTouchesWhenObscured=\"true\"'. "
                                "A malicious application with SYSTEM_ALERT_WINDOW permission can draw a transparent or deceptive "
                                "overlay above this activity, tricking the user into clicking administrative buttons or approving sensitive actions."
                            ),
                            severity="medium",
                            confidence="high",
                            category="platform",
                            cwe_ids=["CWE-1021"],
                            masvs_ids=["MASVS-PLATFORM-1"],
                            impact="UI spoofing and unauthorized user action coercion via invisible tapjacking overlays.",
                            preconditions="Malicious overlay app installed on user device with overlay permissions.",
                            remediation="Set 'android:filterTouchesWhenObscured=\"true\"' or call 'setFilterTouchesWhenObscured(true)' on root views.",
                        )
                    )
                    evidence.append(
                        EvidenceModel(
                            finding_fingerprint=fp,
                            evidence_type="manifest_component",
                            location="AndroidManifest.xml",
                            excerpt=f"<activity android:name='{comp.name}' android:exported='true' /> (missing filterTouchesWhenObscured)",
                            rule_id="RB-SENSITIVE-TAPJACKING",
                            confidence="high",
                        )
                    )
                    occurrences.append(
                        OccurrenceModel(
                            finding_fingerprint=fp,
                            file_path="AndroidManifest.xml",
                            component_name=comp.name,
                        )
                    )

    return findings, evidence, occurrences
