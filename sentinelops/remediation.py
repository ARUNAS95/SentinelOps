from uuid import uuid4
from .models import Finding, Remediation, RemediationRequest
from .store import AuditStore

ALLOWED={"enable_public_access_block","enable_default_encryption","scope_iam_policy","rotate_exposed_credential"}
class RemediationService:
    def __init__(self,audit: AuditStore):
        self.audit=audit; self.pending={}
    def request(self,request: RemediationRequest,findings: list[Finding]):
        finding=next((f for f in findings if f.id==request.finding_id),None)
        if finding is None: raise ValueError("Finding not found in the current scan.")
        if request.action not in ALLOWED or request.action!=finding.remediation:
            raise ValueError("Action is not allowlisted for this finding.")
        item=Remediation(id=str(uuid4()),finding_id=finding.id,action=request.action,
            requested_by=request.requested_by,status="pending_approval",
            message="Simulation only. No cloud API or local resource was changed.")
        self.pending[item.id]=item
        self.audit.record("remediation_requested",request.requested_by,
            {"remediation_id":item.id,"finding_id":finding.id,"action":request.action,"status":item.status})
        return item
    def decide(self,remediation_id,approved,reviewer):
        item=self.pending.get(remediation_id)
        if item is None: raise ValueError("Remediation request not found.")
        if item.status!="pending_approval": raise ValueError("Remediation request has already been reviewed.")
        item.status="approved_simulated" if approved else "rejected"
        item.message="Approval recorded; action simulated; no change was made." if approved else "Request rejected; no change was made."
        self.audit.record("remediation_reviewed",reviewer,
            {"remediation_id":item.id,"approved":approved,"status":item.status,"action":item.action})
        return item
