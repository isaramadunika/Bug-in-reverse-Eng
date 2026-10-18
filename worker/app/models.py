from typing import Any, List, Optional
from pydantic import BaseModel, Field

class ComponentModel(BaseModel):
    kind: str  # activity, service, receiver, provider, activity_alias
    name: str
    exported: bool = False
    exported_explicit: bool = False
    permission: Optional[str] = None
    intent_filters: List[dict] = Field(default_factory=list)

class FindingModel(BaseModel):
    fingerprint: str
    rule_id: str
    rule_version: str = "1.0.0"
    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    confidence: str  # high, medium, low
    category: str
    cwe_ids: List[str] = Field(default_factory=list)
    masvs_ids: List[str] = Field(default_factory=list)
    impact: str = ""
    preconditions: str = ""
    remediation: str = ""
    verification_status: str = "static_evidence"
    reachability: str = "unknown"
    review_status: str = "open"

class EvidenceModel(BaseModel):
    finding_fingerprint: str
    evidence_type: str
    location: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    byte_offset: Optional[int] = None
    excerpt: str = ""
    rule_id: Optional[str] = None
    analysis_source: str = "static_worker"
    tool_name: str = "reversebug-static-engine"
    tool_version: str = "1.0.0"
    confidence: str = "high"
    verification_status: str = "observed"
    redaction: dict = Field(default_factory=dict)
    provenance: dict = Field(default_factory=dict)

class OccurrenceModel(BaseModel):
    finding_fingerprint: str
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    class_name: Optional[str] = None
    method_name: Optional[str] = None
    component_name: Optional[str] = None

class AnalysisResult(BaseModel):
    package_name: Optional[str] = None
    version_name: Optional[str] = None
    version_code: Optional[int] = None
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None
    permissions: List[str] = Field(default_factory=list)
    components: List[ComponentModel] = Field(default_factory=list)
    findings: List[FindingModel] = Field(default_factory=list)
    evidence: List[EvidenceModel] = Field(default_factory=list)
    occurrences: List[OccurrenceModel] = Field(default_factory=list)
