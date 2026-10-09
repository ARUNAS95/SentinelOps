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

## Local AWS demo: KMS and Secrets Manager

This exercise uses LocalStack with fixed dummy credentials (`test/test`) and binds its AWS-compatible API to `127.0.0.1`. The SDK helper accepts only localhost or the Compose-only `localstack` hostname on port 4566; it cannot target AWS or arbitrary hosts. Never replace the dummy values with real credentials.

Requirements: Docker Compose and Terraform.

```bash
docker compose up --build -d localstack api
docker compose --profile infra run --rm terraform init
docker compose --profile infra run --rm terraform apply -auto-approve
docker compose --profile infra run --rm terraform output
```

Copy the displayed `kms_key_id` and `secret_id` into this check. It performs a KMS encrypt/decrypt roundtrip and writes/reads a dummy value through Secrets Manager. It prints only pass/fail status:

```bash
docker compose exec api sentinelops local-aws-check --key-id <kms-key-id> --secret-id <secret-id>
```

The Terraform configuration creates a demo KMS key, alias, and Secrets Manager secret encrypted with that key. State and services run locally. LocalStack is in-memory for this demo; stopping the container discards its resources.

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
