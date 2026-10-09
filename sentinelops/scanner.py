import hashlib
import re
from pathlib import Path
from .models import Finding, Severity

def _id(source, resource, rule):
    return hashlib.sha256(f"{source}:{resource}:{rule}".encode()).hexdigest()[:12]

def scan_cloud(config: dict) -> list[Finding]:
    """Scan an AWS-style snapshot only; no SDK, account access, or credentials."""
    findings=[]
    for bucket in config.get("buckets", []):
        name=str(bucket.get("name","unnamed-bucket"))
        block=bucket.get("public_access_block",{})
        if any(block.get(k) is False for k in ("block_public_acls","ignore_public_acls","block_public_policy","restrict_public_buckets")):
            findings.append(Finding(id=_id("cloud",name,"public"),title="Public access guardrail disabled",
                description="At least one S3 public-access block is disabled.",severity=Severity.critical,
                source="cloud-config",resource=name,evidence="public_access_block contains false",
                recommendation="Enable all four S3 public-access block settings.",
                remediation="enable_public_access_block"))
        if bucket.get("encryption") in (None,"","none","NONE"):
            findings.append(Finding(id=_id("cloud",name,"encryption"),title="Bucket encryption is not configured",
                description="Stored objects may lack server-side encryption.",severity=Severity.high,
                source="cloud-config",resource=name,evidence="encryption is missing or set to none",
                recommendation="Enable default server-side encryption using a managed key.",
                remediation="enable_default_encryption"))
    for policy in config.get("iam_policies", []):
        name=str(policy.get("name","unnamed-policy"))
        for i,stmt in enumerate(policy.get("statements", [])):
            actions=stmt.get("action",[]); resources=stmt.get("resource",[])
            actions=[actions] if isinstance(actions,str) else actions
            resources=[resources] if isinstance(resources,str) else resources
            if stmt.get("effect","Allow")=="Allow" and ("*" in actions or "*" in resources):
                findings.append(Finding(id=_id("cloud",name,f"wildcard-{i}"),title="Overly broad IAM permission",
                    description="An allow statement grants every action or applies to every resource.",
                    severity=Severity.high,source="cloud-config",resource=name,
                    evidence=f"statement {i} includes wildcard action or resource",
                    recommendation="Scope actions and resources to the minimum required set.",
                    remediation="scope_iam_policy"))
    return findings

PATTERNS=[
    ("aws-key",re.compile(r"\bAKIA[0-9A-Z]{16}\b"),Severity.critical,"AWS access key"),
    ("private-key",re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),Severity.critical,"Private key"),
    ("generic",re.compile(r"""(?i)(?:api[_-]?key|secret|password|token)\s*[:=]\s*['"][A-Za-z0-9_./+=:-]{12,}['"]"""),Severity.high,"Hardcoded credential"),
]
def scan_text(text: str, resource="inline") -> list[Finding]:
    findings=[]
    for number,line in enumerate(text.splitlines(),1):
        for rule,pattern,severity,label in PATTERNS:
            if pattern.search(line):
                findings.append(Finding(id=_id("secret",f"{resource}:{number}",rule),
                    title=f"{label} detected",description="A credential-like value was found in source.",
                    severity=severity,source="secret-scan",resource=f"{resource}:{number}",
                    evidence=f"{label} pattern matched on line {number}; value redacted.",
                    recommendation="Revoke or rotate the credential, remove it from source, and use a secret manager.",
                    remediation="rotate_exposed_credential"))
                break
    return findings

def scan_path(path: str, max_bytes=1_000_000) -> list[Finding]:
    target=Path(path)
    if target.is_symlink(): raise ValueError("Symlinks are not scanned.")
    if not target.is_file(): raise ValueError("Path must point to a regular file.")
    if target.stat().st_size>max_bytes: raise ValueError(f"File exceeds the {max_bytes}-byte scan limit.")
    return scan_text(target.read_text(errors="replace"),str(target))
