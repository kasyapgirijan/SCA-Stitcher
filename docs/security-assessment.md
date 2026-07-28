# Production security assessment

Assessment date: 2026-07-27

Scope: Flask application, report parsers and exporters, container image, dependency
set, and the supplied AWS ECS deployment example.

## Remediated findings

| Severity | Finding | Resolution |
| --- | --- | --- |
| Critical | Public first-user registration allowed administrative takeover | Removed the HTTP setup route. Local accounts can only be provisioned with the `create-admin` CLI, and production requires ALB OIDC authentication. |
| High | CSV and XLSX cells could execute attacker-controlled spreadsheet formulas | All spreadsheet-bound text is neutralized; XLSX output writes untrusted values as strings. Regression tests inspect the workbook XML for formula cells. |
| High | Production accepted weak secrets, local authentication, and incomplete proxy configuration | Startup now fails unless the secret is at least 32 bytes, cookies are secure, trusted hosts are set, and the ALB ARN, client ID, issuer, and logout URL are present. |
| High | ALB identity headers could be trusted without cryptographic verification | The signed ES256 JWT is verified against the expected ALB signer, client, issuer, expiry, key ID, and asserted subject. Signing keys are fetched only from the allowlisted regional AWS endpoint. |
| High | Deep, oversized, compressed, or high-cardinality reports could exhaust resources | Upload bytes, ZIP members, JSON depth/nodes, packages, rows, output bytes, request rate, and concurrent report generation are bounded. |
| Medium | Login attempts disclosed timing differences and had no throttling | Local development login performs a uniform password check and applies per-IP and per-account rate limits. Production delegates authentication and MFA to the IdP. |
| Medium | Sessions and browser responses lacked a complete production security profile | Secure host-only cookies, short session lifetime, CSRF checks, no-store caching, CSP, HSTS, frame denial, content sniffing protection, referrer policy, and permissions policy are configured. |
| Medium | HTML exports could be interpreted as an active same-origin document | HTML is escaped, returned as an attachment, and receives a restrictive sandboxed CSP. |
| Medium | The image was mutable, privileged, and dependency versions were not reproducible | The base image is digest-pinned, dependencies are hash-locked, the runtime is non-root, setuid/setgid bits are removed, and the ECS example uses a read-only root filesystem with all Linux capabilities dropped. |
| Critical | Concurrent role changes could remove every administrator, and the documented recovery could not restore the role | The "last administrator" check is evaluated inside the same SQL statement that performs the demotion or delete, so two concurrent requests can no longer both observe a stale count. `reset-password --grant-admin` restores a lost role and `list-admins` reports the current holders. Regression tests exercise both races over repeated trials. |
| High | Unauthenticated callers could force unbounded ALB signing-key fetches and cache growth | The key ID is attacker-controlled and is resolved before signature verification, so the cache is now capped and expired entries are evicted on write. |
| Medium | Consolidator defects were reported to users as invalid input and never surfaced | Report parsing raises a dedicated `ReportError` instead of `SystemExit`; the request handler distinguishes rejected input from internal faults, which are logged with a traceback and returned as 500. |

## Deployment findings

These controls are documented but remain open until they are verified in the target
AWS account:

| Severity | Required AWS evidence |
| --- | --- |
| High | The ECS target security group accepts traffic only from the HTTPS ALB security group; tasks have no public IP. |
| High | Cognito or the configured OIDC provider enforces MFA, appropriate sign-in throttling, and a suitably short session. |
| High | AWS WAF protects the ALB with managed rule groups, IP rate rules, explicit upload oversize handling, and logging. Application throttling is intentionally process-local and is not a substitute for WAF. |
| High | `SECRET_KEY` is supplied from Secrets Manager, is rotated under an approved procedure, and is not present in task definitions, images, logs, or CI output. |
| Medium | ECR enhanced scanning or an equivalent release gate blocks critical/high vulnerable images and deployment uses an immutable image digest. |
| Medium | CloudWatch alarms cover ALB 4xx/5xx spikes, WAF blocks, task restarts/OOM events, latency, and the structured `security_event` records. |
| Medium | Task egress is limited to required AWS/IdP endpoints, including the regional ALB public-key endpoint. |

Use [aws-production.md](aws-production.md) as the deployment checklist. A production
release is not approved until every deployment finding above has account-level
evidence.

## Verification performed

- `pytest`: 35 passing security and behavior tests, including repeated-trial
  concurrency tests for the administrator role and delete guards.
- `bandit`: no findings in the web app, verifier, or exposed consolidator.
- `pip-audit`: no known vulnerabilities in the production lock file.
- Hash-locked production and development dependency installation.
- Docker build from a digest-pinned base.
- Container smoke test as a non-root user with a read-only root filesystem.
- Healthy `/healthz` response with HSTS in production mode.
- Fail-closed container startup when required ALB configuration is omitted.
- Browser review of login, authenticated workspace, format selection, theme
  switching, and console output.

Not performed: an authenticated external DAST against the final AWS hostname,
cloud configuration review, penetration testing of the selected IdP, or ECR image
scan policy verification.
