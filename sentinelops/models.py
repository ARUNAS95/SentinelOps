from datetime import datetime, timezone
from enum import StrEnum
from pydantic import BaseModel, Field

class Severity(StrEnum):
    critical="critical"; high="high"; medium="medium"; low="low"; info="info"

class Finding(BaseModel):
    id: str
    title: str
    description: str
    severity: Severity
    source: str
    resource: str
    evidence: str
    recommendation: str
    remediation: str | None = None

class Triage(BaseModel):
    summary: str
    priority: int = Field(ge=1, le=5)
    rationale: str
    next_steps: list[str]
    provider: str = "local-rules"

class RemediationRequest(BaseModel):
    finding_id: str
    action: str
    requested_by: str = Field(min_length=1, max_length=120)

class Remediation(BaseModel):
    id: str
    finding_id: str
    action: str
    requested_by: str
    status: str
    message: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
