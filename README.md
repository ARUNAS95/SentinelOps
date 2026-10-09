# SentinelOps

**Safe-by-default cloud security triage lab** — inspect local AWS-style snapshots and source files, prioritize findings, and route remediation through human review. Every remediation is a recorded simulation.

[![Security checks](https://github.com/ARUNAS95/SentinelOps/actions/workflows/security.yml/badge.svg)](https://github.com/ARUNAS95/SentinelOps/actions/workflows/security.yml)

## Safety model

- No cloud SDK, account discovery, or cloud credentials are used.
- Remediation only changes a simulation status; it never mutates cloud resources or local files.
- Requests must match a predefined, allowlisted action for the finding.
- A named human reviewer must approve or reject each request.
- Finding evidence stores rule and location only; matched credential values are never returned.
- AI triage is opt-in, has no tools or execution access, receives only fixed rule-generated metadata, and cannot lower deterministic severity.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
uvicorn sentinelops.api:app --reload
```

Open http://127.0.0.1:8000/docs. Try `sentinelops scan-cloud examples/aws-snapshot.json`, or scan local text with `sentinelops scan-secrets path/to/file`.

## Optional AI-assisted triage

AI triage is disabled by default. To enable it, set `SENTINELOPS_AI_API_KEY` in the server environment; optionally set `SENTINELOPS_AI_MODEL` (defaults to `gpt-4.1-mini`). This sends finding IDs, fixed rule titles, severities, fixed recommendations, and allowlisted remediation names to the OpenAI Responses API. It excludes submitted source text, match evidence, secret values, and resource labels. The model has no tools and cannot execute remediation. Its output is schema-validated, bounded, and advisory; local severity rules remain the floor. If the provider fails, the API returns deterministic triage and writes a fallback audit event.

## Workflow

1. `POST /scan/cloud` accepts an AWS-style JSON snapshot; `POST /scan/secrets` accepts inline text.
2. `GET /findings` lists findings; `POST /triage` returns severity-based prioritization.
3. `POST /remediations` accepts a finding ID, its listed action, and requester name.
4. A reviewer calls `POST /remediations/{id}/review` with approval and reviewer name.
5. `GET /audit` shows scan, triage, request, and review events in SQLite.

Checks cover S3 public access and encryption, wildcard IAM actions/resources, AWS access keys, private key headers, and common hardcoded credentials. This illustrative MVP is not a full posture or secret scanning engine. Never submit production secrets to the API. A real deployment needs authentication, tenant isolation, audit retention controls, and security review before any execution integration.

## Development

```bash
pip install -e ".[dev]"
ruff check .
pytest
```

Actions runs Ruff, tests, dependency auditing, and Gitleaks on pushes and pull requests.
