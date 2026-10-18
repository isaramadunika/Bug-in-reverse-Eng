import struct
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from ..models import ComponentModel

NS_ANDROID = "{http://schemas.android.com/apk/res/android}"

class ManifestParser:
    def __init__(self, manifest_bytes: bytes):
        self.data = manifest_bytes
        self.package_name: Optional[str] = None
        self.version_name: Optional[str] = None
        self.version_code: Optional[int] = None
        self.min_sdk: Optional[int] = None
        self.target_sdk: Optional[int] = None
        self.permissions: List[str] = []
        self.components: List[ComponentModel] = []
        self.application_attrs: Dict[str, str] = {}

    def parse(self):
        if not self.data:
            return

        # Check if standard text XML or binary AXML
        if self.data.lstrip().startswith(b"<"):
            self._parse_text_xml(self.data.decode("utf-8", errors="replace"))
        elif len(self.data) >= 8 and struct.unpack("<I", self.data[:4])[0] == 0x00080003:
            self._parse_binary_axml()

    def _parse_text_xml(self, xml_text: str):
        try:
            root = ET.fromstring(xml_text)
        except Exception:
            return

        self.package_name = root.attrib.get("package")
        self.version_name = root.attrib.get(f"{NS_ANDROID}versionName") or root.attrib.get("versionName")
        vc = root.attrib.get(f"{NS_ANDROID}versionCode") or root.attrib.get("versionCode")
        if vc and vc.isdigit():
            self.version_code = int(vc)

        # Uses-sdk
        uses_sdk = root.find("uses-sdk")
        if uses_sdk is not None:
            min_sdk = uses_sdk.attrib.get(f"{NS_ANDROID}minSdkVersion") or uses_sdk.attrib.get("minSdkVersion")
            if min_sdk and min_sdk.isdigit():
                self.min_sdk = int(min_sdk)
            target_sdk = uses_sdk.attrib.get(f"{NS_ANDROID}targetSdkVersion") or uses_sdk.attrib.get("targetSdkVersion")
            if target_sdk and target_sdk.isdigit():
                self.target_sdk = int(target_sdk)

        # Uses-permission
        for p in root.findall("uses-permission"):
            name = p.attrib.get(f"{NS_ANDROID}name") or p.attrib.get("name")
            if name:
                self.permissions.append(name)

        # Application
        app = root.find("application")
        if app is not None:
            for k, v in app.attrib.items():
                clean_k = k.replace(NS_ANDROID, "android:")
                self.application_attrs[clean_k] = v

            component_tags = {
                "activity": "activity",
                "activity-alias": "activity_alias",
                "service": "service",
                "receiver": "receiver",
                "provider": "provider",
            }

            for tag, kind in component_tags.items():
                for elem in app.findall(tag):
                    name = elem.attrib.get(f"{NS_ANDROID}name") or elem.attrib.get("name")
                    if not name:
                        continue
                    # Canonicalize relative class names (e.g. .MainActivity -> com.example.MainActivity)
                    if name.startswith(".") and self.package_name:
                        name = self.package_name + name

                    perm = elem.attrib.get(f"{NS_ANDROID}permission") or elem.attrib.get("permission")

                    # Parse intent filters
                    filters = []
                    for f in elem.findall("intent-filter"):
                        actions = [
                            a.attrib.get(f"{NS_ANDROID}name") or a.attrib.get("name")
                            for a in f.findall("action")
                            if a.attrib.get(f"{NS_ANDROID}name") or a.attrib.get("name")
                        ]
                        categories = [
                            c.attrib.get(f"{NS_ANDROID}name") or c.attrib.get("name")
                            for c in f.findall("category")
                            if c.attrib.get(f"{NS_ANDROID}name") or c.attrib.get("name")
                        ]
                        filters.append({"actions": actions, "categories": categories})

                    # Exported attribute resolution
                    exp_attr = elem.attrib.get(f"{NS_ANDROID}exported") or elem.attrib.get("exported")
                    if exp_attr is not None:
                        exported = exp_attr.lower() == "true"
                        exported_explicit = True
                    else:
                        # If intent filters exist, default is exported=True; otherwise False
                        exported = len(filters) > 0
                        exported_explicit = False

                    self.components.append(
                        ComponentModel(
                            kind=kind,
                            name=name,
                            exported=exported,
                            exported_explicit=exported_explicit,
                            permission=perm,
                            intent_filters=filters,
                        )
                    )

    def _parse_binary_axml(self):
        """Extract strings and basic structure from Android compiled binary XML."""
        strings = self._extract_string_pool(self.data)
        # Scan strings for package name and permissions
        for s in strings:
            if s.startswith("android.permission.") and s not in self.permissions:
                self.permissions.append(s)
            elif "." in s and not self.package_name and not s.startswith("android.") and not s.startswith("http"):
                parts = s.split(".")
                if len(parts) >= 2 and all(p.isidentifier() for p in parts):
                    self.package_name = s

    @staticmethod
    def _extract_string_pool(data: bytes) -> List[str]:
        strings = []
        if len(data) < 16:
            return strings
        idx = 8
        while idx + 8 < len(data):
            chunk_type, chunk_size = struct.unpack("<II", data[idx : idx + 8])
            if chunk_size < 8 or idx + chunk_size > len(data):
                break
            if chunk_type == 0x00010001:  # RES_STRING_POOL_TYPE
                pool_data = data[idx : idx + chunk_size]
                if len(pool_data) >= 28:
                    string_count, _, flags, strings_start, _ = struct.unpack("<IIIII", pool_data[8:28])
                    is_utf8 = bool(flags & (1 << 8))
                    offsets = []
                    for i in range(string_count):
                        off_pos = 28 + i * 4
                        if off_pos + 4 <= len(pool_data):
                            offsets.append(struct.unpack("<I", pool_data[off_pos : off_pos + 4])[0])

                    for offset in offsets:
                        pos = strings_start + offset
                        if pos >= len(pool_data):
                            continue
                        try:
                            if is_utf8:
                                if pos + 1 < len(pool_data):
                                    length = pool_data[pos + 1]
                                    s = pool_data[pos + 2 : pos + 2 + length].decode("utf-8", errors="ignore")
                                    if s:
                                        strings.append(s)
                            else:
                                if pos + 2 <= len(pool_data):
                                    u16_len = struct.unpack("<H", pool_data[pos : pos + 2])[0]
                                    s = pool_data[pos + 2 : pos + 2 + u16_len * 2].decode("utf-16le", errors="ignore")
                                    if s:
                                        strings.append(s)
                        except Exception:
                            continue
                break
            idx += chunk_size
        return strings

def parse_manifest_file(manifest_path: Path) -> ManifestParser:
    if not manifest_path.is_file():
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")
    with open(manifest_path, "rb") as f:
        parser = ManifestParser(f.read())
    parser.parse()
    return parser
