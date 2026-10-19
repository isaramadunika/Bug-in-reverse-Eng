import json
import logging
from typing import Dict, List, Tuple
from ..models import AnalysisResult, ComponentModel, EvidenceModel, FindingModel

logger = logging.getLogger("reversebug.worker.graph")

class GraphBuilder:
    def __init__(self, scan_id: str, artifact_sha256: str, result: AnalysisResult):
        self.scan_id = scan_id
        self.artifact_sha256 = artifact_sha256
        self.result = result
        self.nodes: List[dict] = []
        self.edges: List[dict] = []
        self.node_key_map: Dict[str, dict] = {}

    def add_node(
        self,
        node_key: str,
        node_type: str,
        label: str,
        severity: str = None,
        properties: dict = None,
    ) -> dict:
        if node_key in self.node_key_map:
            return self.node_key_map[node_key]

        node = {
            "scan_id": self.scan_id,
            "node_key": node_key,
            "node_type": node_type,
            "label": label,
            "severity": severity,
            "properties": properties or {},
        }
        self.nodes.append(node)
        self.node_key_map[node_key] = node
        return node

    def add_edge(
        self,
        source_key: str,
        target_key: str,
        edge_type: str,
        relation_status: str = "observed",
        provenance: dict = None,
    ):
        if source_key not in self.node_key_map or target_key not in self.node_key_map:
            return
        edge = {
            "scan_id": self.scan_id,
            "source_key": source_key,
            "target_key": target_key,
            "edge_type": edge_type,
            "relation_status": relation_status,
            "provenance": provenance or {},
        }
        self.edges.append(edge)

    def build(self) -> Tuple[List[dict], List[dict]]:
        # 1. Root APK Node
        apk_label = self.result.package_name or "Android Application Package"
        apk_key = f"apk:{self.artifact_sha256[:16]}"
        self.add_node(
            node_key=apk_key,
            node_type="apk",
            label=apk_label,
            properties={
                "sha256": self.artifact_sha256,
                "version_name": self.result.version_name,
                "version_code": self.result.version_code,
                "min_sdk": self.result.min_sdk,
                "target_sdk": self.result.target_sdk,
            },
        )

        # 2. Permission Nodes
        perm_keys = {}
        for perm in self.result.permissions:
            clean_name = perm.replace("android.permission.", "")
            perm_key = f"permission:{perm}"
            perm_keys[perm] = perm_key
            self.add_node(
                node_key=perm_key,
                node_type="permission",
                label=clean_name,
                properties={"full_name": perm},
            )
            # Edge: APK declares permission
            self.add_edge(apk_key, perm_key, "DECLARES")

        # 3. Component Nodes (Activities, Services, Receivers, Providers)
        comp_keys = {}
        for comp in self.result.components:
            short_name = comp.name.split(".")[-1]
            comp_key = f"component:{comp.kind}:{comp.name}"
            comp_keys[comp.name] = comp_key

            node_type = "entry_point" if comp.exported else "component"
            self.add_node(
                node_key=comp_key,
                node_type=node_type,
                label=f"{comp.kind.capitalize()}: {short_name}",
                properties={
                    "full_name": comp.name,
                    "kind": comp.kind,
                    "exported": comp.exported,
                    "exported_explicit": comp.exported_explicit,
                    "permission": comp.permission,
                },
            )

            # Edge: APK declares Component
            self.add_edge(apk_key, comp_key, "DECLARES")

            # Edge: Component requires permission
            if comp.permission and comp.permission in perm_keys:
                self.add_edge(comp_key, perm_keys[comp.permission], "REQUIRES_PERMISSION")

        # 4. Finding Nodes
        for f in self.result.findings:
            f_key = f"finding:{f.fingerprint[:16]}"
            self.add_node(
                node_key=f_key,
                node_type="finding",
                label=f.title,
                severity=f.severity,
                properties={
                    "rule_id": f.rule_id,
                    "category": f.category,
                    "confidence": f.confidence,
                    "cwe_ids": f.cwe_ids,
                },
            )

            # Use schema-compliant edge type (CHECK constraint in DB) with rich provenance
            edge_type = "ASSOCIATED_WITH"
            if f.category == "network":
                edge_type = "NETWORK_SENDS_TO"
            elif f.category in ("secrets", "storage"):
                edge_type = "READS_FROM"
            elif f.category in ("crash", "reverse_engineering", "native", "component"):
                edge_type = "REFERENCES"

            edge_provenance = {
                "category": f.category,
                "rule_id": f.rule_id,
                "severity": f.severity,
            }

            # Connect finding to affected component or sink
            connected = False
            for comp_name, c_key in comp_keys.items():
                short_name = comp_name.split(".")[-1]
                if short_name in f.title or comp_name in f.description:
                    self.add_edge(f_key, c_key, edge_type, provenance=edge_provenance)
                    connected = True
                    break

            if not connected:
                # Associate directly with root APK or manifest
                self.add_edge(f_key, apk_key, "ASSOCIATED_WITH", provenance=edge_provenance)

        return self.nodes, self.edges
