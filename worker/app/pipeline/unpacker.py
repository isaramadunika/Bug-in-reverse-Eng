import hashlib
import os
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Tuple

class UnpackError(Exception):
    pass

def unpack_apk(apk_path: Path, expected_sha256: str) -> Tuple[Path, str]:
    """
    Safely unpacks the target APK file into a temporary directory after verifying
    its SHA-256 digest and checking for path traversal attempts.
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
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for member in zf.infolist():
                filename = member.filename
                # Path traversal checks
                if ".." in filename or filename.startswith(("/", "\\")) or "\x00" in filename:
                    raise UnpackError(f"Dangerous entry in archive: {filename}")

                target_path = (extract_dir / filename).resolve()
                if not str(target_path).startswith(str(extract_dir.resolve())):
                    raise UnpackError(f"Zip slip escape detected: {filename}")

                # Extract member safely
                zf.extract(member, extract_dir)

    except Exception as e:
        shutil.rmtree(extract_dir, ignore_errors=True)
        raise UnpackError(f"Failed to unpack APK: {e}") from e

    return extract_dir, actual_sha256
