import struct
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional
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
        elif len(self.data) >= 8 and (
            struct.unpack("<I", self.data[:4])[0] == 0x00080003
            or struct.unpack("<H", self.data[:2])[0] == 0x0003
        ):
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

                    exp_attr = elem.attrib.get(f"{NS_ANDROID}exported") or elem.attrib.get("exported")
                    if exp_attr is not None:
                        exported = exp_attr.lower() == "true"
                        exported_explicit = True
                    else:
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
        """Extract elements, attributes, components, and permissions from Android binary XML."""
        data = self.data
        if len(data) < 8:
            return

        # 1. Parse string pool
        idx = 8
        strings: List[str] = []
        while idx + 8 <= len(data):
            chunk_type, header_size, chunk_size = struct.unpack("<HHI", data[idx : idx + 8])
            if chunk_type == 0x0001:  # RES_STRING_POOL_TYPE
                string_count, _, flags, strings_start, _ = struct.unpack("<5I", data[idx + 8 : idx + 28])
                is_utf8 = bool(flags & (1 << 8))
                offsets = struct.unpack(f"<{string_count}I", data[idx + 28 : idx + 28 + string_count * 4])
                pool_base = idx + strings_start
                for off in offsets:
                    pos = pool_base + off
                    if pos >= len(data):
                        continue
                    try:
                        if is_utf8:
                            b1 = data[pos]
                            pos += 1
                            if b1 & 0x80:
                                pos += 1
                            b2 = data[pos]
                            pos += 1
                            if b2 & 0x80:
                                pos += 1
                            length = b2
                            s = data[pos : pos + length].decode("utf-8", errors="ignore").replace("\x00", "")
                            strings.append(s)
                        else:
                            u16_len = struct.unpack("<H", data[pos : pos + 2])[0]
                            s = data[pos + 2 : pos + 2 + u16_len * 2].decode("utf-16le", errors="ignore").replace("\x00", "")
                            strings.append(s)
                    except Exception:
                        strings.append("")
                break
            if chunk_size < 8:
                break
            idx += chunk_size

        if not strings:
            return

        def get_str(i: int) -> str:
            return strings[i] if 0 <= i < len(strings) else ""

        # 2. Walk AXML tags and reconstruct components, intent filters, and permissions
        component_tags = {
            "activity": "activity",
            "activity-alias": "activity_alias",
            "service": "service",
            "receiver": "receiver",
            "provider": "provider",
        }

        element_stack: List[dict] = []
        current_component: Optional[dict] = None
        current_intent_filter: Optional[dict] = None

        idx = 8
        while idx + 8 <= len(data):
            chunk_type, header_size, chunk_size = struct.unpack("<HHI", data[idx : idx + 8])
            if chunk_size < 8 or idx + chunk_size > len(data):
                break

            if chunk_type == 0x0102:  # START_TAG
                _, _, ns_idx, name_idx, attr_start, attr_size, attr_count = struct.unpack(
                    "<IIIIHHH", data[idx + 8 : idx + 30]
                )
                tag_name = get_str(name_idx)
                attrs: Dict[str, str] = {}
                attr_offset = idx + header_size
                for a_i in range(attr_count):
                    a_pos = attr_offset + a_i * 20
                    if a_pos + 20 > len(data):
                        break
                    _, a_name, a_raw, val_size, _, val_type, val_data = struct.unpack(
                        "<IIIHBB I", data[a_pos : a_pos + 20]
                    )
                    attr_key = get_str(a_name)
                    if val_type == 0x03:  # string
                        val = get_str(val_data)
                    elif val_type == 0x12:  # boolean
                        val = "true" if val_data != 0 else "false"
                    elif val_type in (0x10, 0x11):  # integer
                        val = str(val_data)
                    else:
                        val = get_str(a_raw) or str(val_data)
                    attrs[attr_key] = val

                elem = {"tag": tag_name, "attrs": attrs}
                element_stack.append(elem)

                # Process tag
                if tag_name == "manifest":
                    if "package" in attrs:
                        self.package_name = attrs["package"]
                    if "versionName" in attrs:
                        self.version_name = attrs["versionName"]
                    if "versionCode" in attrs and attrs["versionCode"].isdigit():
                        self.version_code = int(attrs["versionCode"])

                elif tag_name == "uses-sdk":
                    if "minSdkVersion" in attrs and attrs["minSdkVersion"].isdigit():
                        self.min_sdk = int(attrs["minSdkVersion"])
                    if "targetSdkVersion" in attrs and attrs["targetSdkVersion"].isdigit():
                        self.target_sdk = int(attrs["targetSdkVersion"])

                elif tag_name in ("uses-permission", "permission"):
                    p_name = attrs.get("name")
                    if p_name and p_name not in self.permissions:
                        self.permissions.append(p_name)

                elif tag_name == "application":
                    for k, v in attrs.items():
                        self.application_attrs[f"android:{k}"] = v

                elif tag_name in component_tags:
                    name = attrs.get("name", "")
                    if name.startswith(".") and self.package_name:
                        name = self.package_name + name
                    elif self.package_name and "." not in name:
                        name = f"{self.package_name}.{name}"

                    exp_attr = attrs.get("exported")
                    if exp_attr is not None:
                        exported = exp_attr.lower() == "true"
                        exported_explicit = True
                    else:
                        exported = False
                        exported_explicit = False

                    current_component = {
                        "kind": component_tags[tag_name],
                        "name": name,
                        "exported": exported,
                        "exported_explicit": exported_explicit,
                        "permission": attrs.get("permission"),
                        "intent_filters": [],
                    }

                elif tag_name == "intent-filter" and current_component is not None:
                    current_intent_filter = {"actions": [], "categories": []}

                elif tag_name == "action" and current_intent_filter is not None:
                    act_name = attrs.get("name")
                    if act_name:
                        current_intent_filter["actions"].append(act_name)

                elif tag_name == "category" and current_intent_filter is not None:
                    cat_name = attrs.get("name")
                    if cat_name:
                        current_intent_filter["categories"].append(cat_name)

            elif chunk_type == 0x0103:  # END_TAG
                if element_stack:
                    popped = element_stack.pop()
                    tag_name = popped["tag"]
                    if tag_name == "intent-filter":
                        if current_component is not None and current_intent_filter is not None:
                            current_component["intent_filters"].append(current_intent_filter)
                            # If exported was not explicitly specified, an intent-filter defaults exported to True
                            if not current_component["exported_explicit"]:
                                current_component["exported"] = True
                        current_intent_filter = None
                    elif tag_name in component_tags:
                        if current_component and current_component["name"]:
                            self.components.append(
                                ComponentModel(
                                    kind=current_component["kind"],
                                    name=current_component["name"],
                                    exported=current_component["exported"],
                                    exported_explicit=current_component["exported_explicit"],
                                    permission=current_component["permission"],
                                    intent_filters=current_component["intent_filters"],
                                )
                            )
                        current_component = None

            idx += chunk_size

def parse_manifest_file(manifest_path: Path) -> ManifestParser:
    if not manifest_path.is_file():
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")
    with open(manifest_path, "rb") as f:
        parser = ManifestParser(f.read())
    parser.parse()
    return parser
