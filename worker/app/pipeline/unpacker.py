import hashlib
import os
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Tuple

class UnpackError(Exception):
    pass

# Code, config, and credential extensions relevant for security analysis
ANALYSIS_TEXT_EXTENSIONS = {
    ".dex", ".json", ".js", ".ts", ".xml", ".properties",
    ".env", ".txt", ".yaml", ".yml", ".conf", ".cfg", ".ini",
    ".key", ".pem", ".cert", ".so",
}

def should_extract_entry(filename: str) -> bool:
    """Returns True if the archive member is needed for static security analysis."""
    low = filename.lower()
    # Always extract root manifest and DEX bytecode
    if low == "androidmanifest.xml" or low.endswith(".dex"):
        return True
    _, ext = os.path.splitext(low)
    if ext not in ANALYSIS_TEXT_EXTENSIONS:
        return False
    # If in res/ but not in raw, values, or xml, skip compiled binary UI assets
    if low.startswith("res/") and not low.startswith(("res/raw/", "res/values/", "res/xml/")):
        return False
    return True

def unpack_apk(apk_path: Path, expected_sha256: str) -> Tuple[Path, str]:
    """
    Safely unpacks the target APK file into a temporary directory after verifying
    its SHA-256 digest and checking for path traversal attempts.
    Only extracts files relevant for static security analysis to maximize speed and efficiency.
    """
    if not apk_path.is_file():
        raise UnpackError(f"APK file does not exist at path: {apk_path}")

    # 1. Compute and verify SHA-256
    hasher = hashlib.sha256()
    with open(apk_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    actual_sha256 = hasher.hexdigest().lower()

    if expected_sha256 and actual_sha256 != expected_sha256.lower():
        raise UnpackError(
            f"SHA-256 mismatch: expected {expected_sha256}, got {actual_sha256}"
        )

    # 2. Create isolated extraction directory
    extract_dir = Path(tempfile.mkdtemp(prefix="rb-unpack-"))
    extract_dir_str = str(extract_dir.resolve())
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for member in zf.infolist():
                filename = member.filename
                # Path traversal checks
                if ".." in filename or filename.startswith(("/", "\\")) or "\x00" in filename:
                    raise UnpackError(f"Dangerous entry in archive: {filename}")

                # Skip non-analysis files immediately before expensive disk operations
                if not should_extract_entry(filename):
                    continue

                target_path = (extract_dir / filename).resolve()
                if not str(target_path).startswith(extract_dir_str):
                    raise UnpackError(f"Zip slip escape detected: {filename}")

                # Extract member safely
                zf.extract(member, extract_dir)

    except Exception as e:
        shutil.rmtree(extract_dir, ignore_errors=True)
        raise UnpackError(f"Failed to unpack APK: {e}") from e

    return extract_dir, actual_sha256
