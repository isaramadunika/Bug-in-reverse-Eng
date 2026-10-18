import hashlib
from typing import List, Tuple
from ..models import ComponentModel, EvidenceModel, FindingModel, OccurrenceModel
from .manifest import ManifestParser

def make_fingerprint(rule_id: str, identifier: str) -> str:
    return hashlib.sha256(f"{rule_id}:{identifier}".encode("utf-8")).hexdigest()

def evaluate_static_rules(
    manifest: ManifestParser,
    artifact_sha256: str,
) -> Tuple[List[FindingModel], List[EvidenceModel], List[OccurrenceModel]]:
    findings: List[FindingModel] = []
    evidence: List[EvidenceModel] = []
    occurrences: List[OccurrenceModel] = []

    # Rule: RB-MANIFEST-DEBUGGABLE
    debuggable = manifest.application_attrs.get("android:debuggable", "").lower() == "true"
    if debuggable:
        fp = make_fingerprint("RB-MANIFEST-DEBUGGABLE", "application")
        findings.append(
            FindingModel(
                fingerprint=fp,
                rule_id="RB-MANIFEST-DEBUGGABLE",
                title="Application is Marked as Debuggable",
                description="The android:debuggable flag is explicitly set to true in AndroidManifest.xml. This allows attackers or unauthorized users with ADB access to attach a debugger, inspect memory, execute arbitrary code, and dump sensitive credentials.",
                severity="high",
                confidence="high",
                category="manifest",
                cwe_ids=["CWE-215", "CWE-489"],
                masvs_ids=["MASVS-RESILIENCE-1", "MASVS-CODE-4"],
                impact="Full process memory inspection, code execution via JDWP, and extraction of internal storage secrets.",
                preconditions="Physical device or ADB debugging access.",
                remediation="Ensure android:debuggable is false or omitted in release builds in build.gradle / AndroidManifest.xml.",
            )
        )
        evidence.append(
            EvidenceModel(
                finding_fingerprint=fp,
                evidence_type="manifest_snippet",
                location="AndroidManifest.xml",
                excerpt='<application android:debuggable="true" ...>',
                rule_id="RB-MANIFEST-DEBUGGABLE",
                confidence="high",
            )
        )
        occurrences.append(
            OccurrenceModel(
                finding_fingerprint=fp,
                file_path="AndroidManifest.xml",
                component_name="application",
            )
        )

    # Rule: RB-MANIFEST-BACKUP
    allow_backup = manifest.application_attrs.get("android:allowBackup", "").lower() == "true"
    if allow_backup:
        fp = make_fingerprint("RB-MANIFEST-BACKUP", "application")
        findings.append(
            FindingModel(
                fingerprint=fp,
                rule_id="RB-MANIFEST-BACKUP",
                title="Application Allows Private Data Backup",
                description="The android:allowBackup attribute is set to true without strict backup rules. Attackers with physical access or ADB can dump the entire private sandbox (shared_prefs, databases, tokens) via 'adb backup'.",
                severity="medium",
                confidence="high",
                category="manifest",
                cwe_ids=["CWE-312", "CWE-922"],
                masvs_ids=["MASVS-STORAGE-2"],
                impact="Unauthorized exfiltration of user databases, session tokens, and local cache.",
                preconditions="Device physical access with USB debugging enabled.",
                remediation="Set android:allowBackup='false' or configure a restricted fullBackupContent XML policy.",
            )
        )
        evidence.append(
            EvidenceModel(
                finding_fingerprint=fp,
                evidence_type="manifest_snippet",
                location="AndroidManifest.xml",
                excerpt='<application android:allowBackup="true" ...>',
                rule_id="RB-MANIFEST-BACKUP",
                confidence="high",
            )
        )
        occurrences.append(
            OccurrenceModel(
                finding_fingerprint=fp,
                file_path="AndroidManifest.xml",
                component_name="application",
            )
        )

    # Rule: RB-NET-CLEARTEXT
    cleartext = manifest.application_attrs.get("android:usesCleartextTraffic", "").lower() == "true"
    if cleartext:
        fp = make_fingerprint("RB-NET-CLEARTEXT", "application")
        findings.append(
            FindingModel(
                fingerprint=fp,
                rule_id="RB-NET-CLEARTEXT",
                title="Cleartext HTTP Network Traffic Permitted",
                description="The application explicitly enables android:usesCleartextTraffic='true', permitting unencrypted HTTP communication and exposing API credentials and personal data to MitM eavesdropping.",
                severity="high",
                confidence="high",
                category="network",
                cwe_ids=["CWE-319"],
                masvs_ids=["MASVS-NETWORK-1"],
                impact="Network eavesdropping and active tampering on hostile Wi-Fi or compromised gateways.",
                preconditions="Attacker located on the same network path.",
                remediation="Enforce HTTPS across all endpoints and configure a strict networkSecurityConfig XML.",
            )
        )
        evidence.append(
            EvidenceModel(
                finding_fingerprint=fp,
                evidence_type="manifest_snippet",
                location="AndroidManifest.xml",
                excerpt='<application android:usesCleartextTraffic="true" ...>',
                rule_id="RB-NET-CLEARTEXT",
                confidence="high",
            )
        )
        occurrences.append(
            OccurrenceModel(
                finding_fingerprint=fp,
                file_path="AndroidManifest.xml",
                component_name="application",
            )
        )

    # Component rules: RB-COMP-001..004
    rule_map = {
        "activity": ("RB-COMP-001", "Exported Activity Without Permission Protection", "high", "CWE-926", "MASVS-PLATFORM-1"),
        "activity_alias": ("RB-COMP-001", "Exported Activity-Alias Without Permission Protection", "high", "CWE-926", "MASVS-PLATFORM-1"),
        "receiver": ("RB-COMP-002", "Exported Broadcast Receiver Without Permission Protection", "high", "CWE-925", "MASVS-PLATFORM-1"),
        "service": ("RB-COMP-003", "Exported Service Without Permission Protection", "high", "CWE-926", "MASVS-PLATFORM-1"),
        "provider": ("RB-COMP-004", "Exported Content Provider Without Permission Protection", "critical", "CWE-926", "MASVS-PLATFORM-1"),
    }

    for comp in manifest.components:
        if comp.exported and not comp.permission:
            # Launcher activities (main entry points) are meant to be exported
            is_launcher = False
            for filt in comp.intent_filters:
                if "android.intent.action.MAIN" in filt.get("actions", []) and "android.intent.category.LAUNCHER" in filt.get("categories", []):
                    is_launcher = True
                    break
            if is_launcher and comp.kind == "activity":
                continue

            meta = rule_map.get(comp.kind)
            if not meta:
                continue

            rule_id, title, sev, cwe, masvs = meta
            fp = make_fingerprint(rule_id, comp.name)

            desc = f"The {comp.kind} '{comp.name}' is exported to third-party applications without requiring an enforcing android:permission. Any app on the device can initiate or access this component."
            remed = f"Set android:exported='false' if the {comp.kind} is intended only for internal application usage, or declare a custom signature-level android:permission."

            findings.append(
                FindingModel(
                    fingerprint=fp,
                    rule_id=rule_id,
                    title=f"{title}: {comp.name.split('.')[-1]}",
                    description=desc,
                    severity=sev,
                    confidence="high",
                    category="component",
                    cwe_ids=[cwe],
                    masvs_ids=[masvs],
                    impact=f"Inter-component communication hijacking, unauthorized triggering of internal application logic, or data leakage.",
                    preconditions="Any untrusted malicious application installed on the same Android device.",
                    remediation=remed,
                )
            )

            evidence.append(
                EvidenceModel(
                    finding_fingerprint=fp,
                    evidence_type="component_ref",
                    location="AndroidManifest.xml",
                    excerpt=f"<{comp.kind} android:name='{comp.name}' android:exported='{comp.exported}' ...>",
                    rule_id=rule_id,
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
