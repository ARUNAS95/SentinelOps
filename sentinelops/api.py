from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from .models import Finding, RemediationRequest, Triage
from .remediation import RemediationService
from .scanner import scan_cloud, scan_text
from .store import AuditStore
from .triage import TriageProvider, configured_provider

app=FastAPI(title="SentinelOps",version="0.1.0",description="Safe cloud security review. Remediation is simulated.")
audit=AuditStore(); remediator=RemediationService(audit); provider=configured_provider(); findings={}
class CloudScan(BaseModel):
    config: dict=Field(default_factory=dict)
class TextScan(BaseModel):
    text: str
    resource: str="inline"
class Review(BaseModel):
    approved: bool
    reviewer: str=Field(min_length=1,max_length=120)

@app.get("/",include_in_schema=False)
def home(): return {"name":"SentinelOps","docs":"/docs","safety":"simulation-only"}
@app.get("/health")
def health(): return {"status":"ok","cloud_execution":False}
@app.post("/scan/cloud",response_model=list[Finding])
def cloud_scan(body: CloudScan):
    results=scan_cloud(body.config); findings.update({f.id:f for f in results})
    audit.record("cloud_scan","system",{"finding_ids":[f.id for f in results]}); return results
@app.post("/scan/secrets",response_model=list[Finding])
def secrets_scan(body: TextScan):
    results=scan_text(body.text,body.resource); findings.update({f.id:f for f in results})
    audit.record("secret_scan","system",{"resource":body.resource,"finding_ids":[f.id for f in results],"matches":len(results)})
    return results
@app.get("/findings",response_model=list[Finding])
def list_findings(): return list(findings.values())
@app.post("/triage",response_model=Triage)
def triage():
    current=list(findings.values())
    try:
        result=provider.triage(current)
    except Exception as exc:
        # AI is advisory; any provider, network, or validation failure falls back locally.
        result=TriageProvider().triage(current)
        result.provider="local-rules-fallback"
        audit.record("triage_fallback","system",{"reason":type(exc).__name__})
    audit.record("triage","system",{"finding_count":len(findings),"provider":result.provider,"priority":result.priority})
    return result
@app.post("/remediations")
def request_remediation(body: RemediationRequest):
    try: return remediator.request(body,list(findings.values()))
    except ValueError as exc: raise HTTPException(status_code=400,detail=str(exc)) from exc
@app.post("/remediations/{remediation_id}/review")
def review_remediation(remediation_id: str,body: Review):
    try: return remediator.decide(remediation_id,body.approved,body.reviewer)
    except ValueError as exc:
        status=404 if "not found" in str(exc).lower() else 409
        raise HTTPException(status_code=status,detail=str(exc)) from exc
@app.get("/audit")
def audit_log(limit: int=100):
    if not 1<=limit<=500: raise HTTPException(status_code=422,detail="limit must be 1..500")
    return audit.list(limit)
