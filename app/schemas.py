"""API response schemas (also drive the Swagger/OpenAPI docs)."""
from typing import Optional, List
from pydantic import BaseModel


class ItemStocktake(BaseModel):
    id: str
    seq: int
    kind: str
    source_name: str
    fmt: Optional[str] = None
    size_bytes: int
    extracted_chars: int
    segment_count: int
    status: str


class JobSummary(BaseModel):
    id: str
    name: Optional[str] = None
    status: str
    decision: Optional[str] = None
    created_at: float
    item_count: int
    total_bytes: int
    items: List[ItemStocktake]


class ItemStatus(BaseModel):
    id: str
    seq: int
    source_name: str
    status: str
    decision: Optional[str] = None
    risk_tier: Optional[str] = None


class JobStatus(BaseModel):
    id: str
    status: str
    decision: Optional[str] = None
    done: int
    total: int
    items: List[ItemStatus]


class Finding(BaseModel):
    stage: str
    code: str
    severity: str
    title: str
    explanation: Optional[str] = None
    provenance: Optional[str] = None
    verbatim: Optional[str] = None
    position: Optional[int] = None
    occurrences: Optional[str] = None


class EvidencePart(BaseModel):
    kind: str                         # "plain" | "hl" | "mask"
    t: Optional[str] = None           # text for plain/hl (omitted for mask — see reveal)
    code: Optional[str] = None        # category code for hl/mask
    mid: Optional[int] = None         # masked-span index (for the reveal endpoint)


class EvidenceSegment(BaseModel):
    provenance: str
    parts: List[EvidencePart]


class ItemDetail(BaseModel):
    id: str
    seq: int
    source_name: str
    fmt: Optional[str] = None
    kind: str
    status: str
    decision: Optional[str] = None
    risk_tier: Optional[str] = None
    stages: dict
    findings: List[Finding]
    segments: List[EvidenceSegment] = []


class JobListEntry(BaseModel):
    id: str
    label: str
    name: Optional[str] = None
    status: str
    decision: Optional[str] = None
    created_at: float
    confirmed_at: Optional[float] = None
    completed_at: Optional[float] = None
    item_count: int
    done: int


class JobList(BaseModel):
    in_progress: List[JobListEntry]
    completed: List[JobListEntry]
