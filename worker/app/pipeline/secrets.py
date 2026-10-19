import math
import os
import re
from pathlib import Path
from typing import List, Tuple
from ..models import EvidenceModel, FindingModel, OccurrenceModel
from .rules import make_fingerprint

SECRET_PATTERNS = [
    {
        "rule_id": "RB-SECRET-AWS",
        "title": "Hardcoded AWS Access Key Discovered",
        "regex": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "severity": "critical",
        "cwe": "CWE-798",
        "desc": "An Amazon Web Services (AWS) Access Key ID was discovered hardcoded in application binaries or assets. Hardcoded cloud credentials expose backend infrastructure to account takeover, unauthorized data exfiltration, and resource hijacking.",
    },
    {
        "rule_id": "RB-SECRET-GOOGLE",
        "title": "Hardcoded Google API Key Discovered",
        "regex": re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        "severity": "medium",
        "cwe": "CWE-798",
        "desc": "A Google Cloud API Key was discovered hardcoded in application resources. While some Firebase client keys are public, unrestricted Google API keys can be abused for unauthorized API quota consumption and cloud services billing.",
    },
    {
        "rule_id": "RB-SECRET-SLACK",
        "title": "Hardcoded Slack API Token Discovered",
        "regex": re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b"),
        "severity": "critical",
        "cwe": "CWE-798",
        "desc": "A Slack Bot, User, or App token was identified. Attackers decompiling this APK can authenticate to company workspaces, read internal chats, and compromise confidential communications.",
    },
    {
        "rule_id": "RB-SECRET-STRIPE",
        "title": "Hardcoded Stripe Live Secret Key Discovered",
        "regex": re.compile(r"\b(sk_live_[0-9a-zA-Z]{24,})\b"),
        "severity": "critical",
        "cwe": "CWE-798",
        "desc": "A live Stripe Secret Key was discovered embedded in the mobile binary. Live payment secrets must never exist on client devices; attackers can issue unauthorized transactions or access customer financial data.",
    },
    {
        "rule_id": "RB-SECRET-PRIVKEY",
        "title": "Embedded Private Cryptographic Key Discovered",
        "regex": re.compile(r"(-----BEGIN (?:RSA|EC|OPENSSH|DSA|PRIVATE) KEY-----)"),
        "severity": "critical",
        "cwe": "CWE-321",
        "desc": "A private cryptographic key PEM block was found stored within the application package. Client-side private keys can be extracted and used to forge signatures, decrypt user traffic, or impersonate clients.",
    },
    {
        "rule_id": "RB-SECRET-GITHUB",
        "title": "Hardcoded GitHub Personal Access Token Discovered",
        "regex": re.compile(r"\b(gh[pousr]_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b"),
        "severity": "critical",
        "cwe": "CWE-798",
        "desc": "A GitHub Personal Access Token was identified embedded in application files. Adversaries can access private repositories, push malicious commits, or compromise CI/CD pipelines.",
    },
    {
        "rule_id": "RB-SECRET-SENDGRID",
        "title": "Hardcoded SendGrid API Key Discovered",
        "regex": re.compile(r"\b(SG\.[0-9a-zA-Z_-]{16,32}\.[0-9a-zA-Z_-]{38,64})\b"),
        "severity": "high",
        "cwe": "CWE-798",
        "desc": "A SendGrid email service API key was found in the application binary. Attackers can hijack email quotas, send phishing campaigns from verified corporate domains, and access email delivery logs.",
    },
    {
        "rule_id": "RB-SECRET-TWILIO",
        "title": "Hardcoded Twilio API Key Discovered",
        "regex": re.compile(r"\b(SK[0-9a-fA-F]{32})\b"),
        "severity": "high",
        "cwe": "CWE-798",
        "desc": "A Twilio API secret key was identified. Attackers can abuse SMS/voice gateways, access caller logs, and generate unauthorized communications billing.",
    },
    {
        "rule_id": "RB-SECRET-JWT",
        "title": "Hardcoded Production JSON Web Token (JWT) Identified",
        "regex": re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"),
        "severity": "medium",
        "cwe": "CWE-798",
        "desc": "A static JSON Web Token (JWT) was found embedded in application resources. Static bearer tokens can grant unauthorized API access or expose sensitive tenant metadata.",
    },
]

def shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a string in bits per character."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = {}
    for char in data:
        counts[char] = counts.get(char, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def redact_secret(token: str) -> str:
    """Redacts secret tokens preserving prefix and suffix."""
    if len(token) <= 8:
        return "*" * len(token)
    prefix_len = min(4, len(token) // 4)
    suffix_len = min(4, len(token) // 4)
    masked_len = len(token) - prefix_len - suffix_len
    return token[:prefix_len] + ("*" * masked_len) + token[-suffix_len:]

def scan_for_secrets(
    extract_dir: Path,
    artifact_sha256: str,
    max_file_size_mb: int = 25,
) -> Tuple[List[FindingModel], List[EvidenceModel], List[OccurrenceModel]]:
    findings: List[FindingModel] = []
    evidence: List[EvidenceModel] = []
    occurrences: List[OccurrenceModel] = []
    seen_fingerprints = set()

    max_bytes = max_file_size_mb * 1024 * 1024

    # Extensions that never contain secrets
    skip_exts = {
        ".png", ".jpg", ".jpeg", ".webp", ".mp3", ".mp4", ".wav", ".gif", ".svg",
        ".ico", ".bmp", ".ttf", ".otf", ".woff", ".woff2", ".eot", ".so", ".dylib",
        ".dll", ".a", ".o", ".arsc", ".flat",
    }

    for root, _, files in os.walk(extract_dir):
        for file in files:
            file_path = Path(root) / file
            rel_path = file_path.relative_to(extract_dir).as_posix().replace("\x00", "")

            # Skip large media and binary formats
            if file_path.suffix.lower() in skip_exts:
                continue

            try:
                if file_path.stat().st_size > max_bytes:
                    continue
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            if not content:
                continue

            # Regex Pattern Matching using C-accelerated finditer
            for pattern in SECRET_PATTERNS:
                rule_id = pattern["rule_id"]
                rx = pattern["regex"]

                for match in rx.finditer(content):
                    raw_token = match.group(1).replace("\x00", "")
                    if not raw_token:
                        continue
                    redacted = redact_secret(raw_token)
                    fp = make_fingerprint(rule_id, f"{rel_path}:{raw_token[:8]}")

                    if fp in seen_fingerprints:
                        continue
                    seen_fingerprints.add(fp)

                    # Compute line number only for matched token
                    start_pos = match.start()
                    line_idx = content[:start_pos].count("\n") + 1

                    # Extract context snippet around the match
                    l_start = content.rfind("\n", max(0, start_pos - 120), start_pos)
                    l_start = 0 if l_start == -1 else l_start + 1
                    l_end = content.find("\n", match.end(), min(len(content), match.end() + 120))
                    l_end = len(content) if l_end == -1 else l_end

                    raw_snippet = content[l_start:l_end]
                    # Sanitize snippet: printable only, strip NUL bytes
                    clean_snippet = "".join(c for c in raw_snippet if c.isprintable() or c in "\t ")
                    clean_snippet = clean_snippet.replace("\x00", "").strip()[:200]
                    excerpt = clean_snippet.replace(raw_token, redacted)

                    findings.append(
                        FindingModel(
                            fingerprint=fp,
                            rule_id=rule_id,
                            title=pattern["title"],
                            description=pattern["desc"],
                            severity=pattern["severity"],
                            confidence="high",
                            category="secrets",
                            cwe_ids=[pattern["cwe"]],
                            masvs_ids=["MASVS-STORAGE-1", "MASVS-CRYPTO-1"],
                            impact="Unauthorized cloud access, service misuse, or credential exfiltration.",
                            preconditions="Decompilation or string inspection of the APK package.",
                            remediation="Revoke the exposed key immediately and migrate authentication to a secure backend API with short-lived tokens.",
                        )
                    )

                    evidence.append(
                        EvidenceModel(
                            finding_fingerprint=fp,
                            evidence_type="code_snippet",
                            location=rel_path,
                            line_start=line_idx,
                            line_end=line_idx,
                            excerpt=excerpt,
                            rule_id=rule_id,
                            confidence="high",
                            redaction={"original_length": len(raw_token), "redacted_token": redacted},
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

    return findings, evidence, occurrences
