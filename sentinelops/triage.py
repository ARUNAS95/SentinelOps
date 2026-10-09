from .models import Finding, Triage

class TriageProvider:
    """Adapter boundary for future AI; receives findings, never raw credentials."""
    name="local-rules"
    def triage(self, findings: list[Finding]) -> Triage:
        ranks={"critical":1,"high":2,"medium":3,"low":4,"info":5}
        if not findings:
            return Triage(summary="No security findings were reported.",priority=5,
                rationale="The supplied snapshot and files contained no matching rules.",
                next_steps=["Continue scanning changes in CI."])
        priority=min(ranks[f.severity.value] for f in findings)
        top=[f for f in findings if ranks[f.severity.value]==priority]
        return Triage(summary=f"{len(findings)} finding(s); {len(top)} at highest urgency.",
            priority=priority,rationale="Priority is deterministic from rule severity; verify evidence.",
            next_steps=[f"Review {f.id}: {f.recommendation}" for f in top],provider=self.name)
