from fastapi.testclient import TestClient
from sentinelops.api import app, findings, remediator
client=TestClient(app)
def setup_function():
    findings.clear(); remediator.pending.clear()
def test_approval_is_simulation_only():
    finding=client.post("/scan/cloud",json={"config":{"buckets":[
        {"name":"demo","public_access_block":{"block_public_acls":False}}]}}).json()[0]
    assert client.post("/triage").json()["priority"]==1
    pending=client.post("/remediations",json={"finding_id":finding["id"],
        "action":"enable_public_access_block","requested_by":"operator"}).json()
    assert pending["status"]=="pending_approval"
    reviewed=client.post(f"/remediations/{pending['id']}/review",
        json={"approved":True,"reviewer":"security-reviewer"}).json()
    assert reviewed["status"]=="approved_simulated" and "no change" in reviewed["message"]
    assert client.get("/audit").status_code==200
def test_unknown_action_is_rejected():
    finding=client.post("/scan/cloud",json={"config":{"buckets":[
        {"name":"demo","public_access_block":{"block_public_acls":False}}]}}).json()[0]
    result=client.post("/remediations",json={"finding_id":finding["id"],
        "action":"delete_bucket","requested_by":"operator"})
    assert result.status_code==400
def test_secret_api_redacts_match():
    secret="AKIA" + "ABCDEFGHIJKLMNOP"
    assert secret not in client.post("/scan/secrets",json={"text":f"KEY={secret}"}).text
