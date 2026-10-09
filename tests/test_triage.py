from sentinelops.models import Finding, Severity
from sentinelops.triage import OpenAITriageProvider

def test_ai_payload_contains_only_allowlisted_finding_metadata():
    finding=Finding(id="abc123",title="Credential detected",description="private detail",
        severity=Severity.critical,source="secret-scan",resource="private.env:4",
        evidence="secret value redacted",recommendation="Rotate the exposed credential.",
        remediation="rotate_exposed_credential")
    safe=OpenAITriageProvider.safe_findings([finding])[0]
    assert safe=={"id":"abc123","title":"Credential detected","severity":"critical",
        "recommendation":"Rotate the exposed credential.",
        "allowed_remediation":"rotate_exposed_credential"}
    assert "private.env" not in str(safe)
    assert "private detail" not in str(safe)
    assert "secret value" not in str(safe)
