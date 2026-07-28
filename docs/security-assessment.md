# Production security assessment

Assessment date: 2026-07-28 (second review round; first round 2026-07-27)

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

## Remediated in the second review round

| Severity | Finding | Resolution |
| --- | --- | --- |
| Major | The audit trail could not attribute a privileged action to the administrator who performed it | `audit()` now resolves the actor from the request and records `actor` and `target` as separate fields. Administrator create, reset, role change, and delete all identify both parties, and role changes record the resulting role so a promotion is distinguishable from a demotion. |
| Major | One user produced a different `principal` fingerprint per event type, so events could not be correlated | A single `current_principal()` (username in local mode, ALB `sub` in `alb_oidc`) backs every event. Previously a login recorded the username while a report recorded the numeric row id. |
| Major | `X-Amzn-Trace-Id` was interpolated unquoted into the `key=value` audit line, letting a caller forge fields such as `outcome=succeeded` | The header is reduced to a safe character set and emitted as a single quoted token, so it cannot introduce additional space-delimited pairs. |
| Major | The HTML preview bypassed `MAX_EXPORT_BYTES` entirely; only `MAX_REPORT_ROWS` bounded it, allowing a multi-hundred-megabyte response | The preview renders at most `MAX_PREVIEW_ROWS` (default 2000) and states how many findings were withheld. Exports remain complete and keep the byte cap. |
| Major | Rate-limiter saturation failed closed on attacker-controlled keys: flooding distinct usernames denied sign-in to every user | `SlidingWindowLimiter` evicts the least recently used key instead of refusing new ones. AWS WAF remains the control expected to absorb a flood. |
| Major | `extract_vulns()` walked each package's object graph two or three times, dominating report generation | The traversal runs once per package and is shared by `is_reportable()` and `vuln_cell()`. Verified at one walk per package in both the count-bearing and count-less branches. |
| Minor | Forwarded headers were never honoured, so behind a load balancer every audit event recorded the proxy address | `TRUST_PROXY_HOPS` enables `ProxyFix` for a stated number of proxies. It defaults to 0, which ignores the headers, because trusting them on a directly reachable socket would let a client spoof its own audit address and rate-limit key. Production logs a startup warning when it is unset. |
| Minor | Concurrent requests bypassed the ALB signing-key cap, failed lookups were never negatively cached, and a full cache refused new key IDs for an hour | Concurrent requests for one key ID share a single fetch, failures are negatively cached, and the cache evicts its oldest entry rather than refusing, so genuine ALB key rotation cannot be blocked. |
| Minor | `SESSION_LIFETIME_MINUTES` ignored programmatic overrides, and two `env_int` implementations disagreed on blank values | One `env_int` with range validation is shared by the CLI and the web app; a blank variable falls back to the documented default in both. |
| Minor | Admin mutations could surface a SQLite lock timeout as a 500 | The database opens in WAL mode with a busy timeout, and the four admin mutations turn contention into a retry prompt. |
| Minor | `MAX_REPORT_BYTES` was configured for the web service but only ever applied to the CLI | Removed from `compose.yaml` and `.env.example`, and documented as CLI-only. |
| Minor | `reset-password --grant-admin` assembled its SQL by concatenation | Replaced with two complete statements selected by the flag. Nothing there was user-controlled, but the pattern does not belong in an auth path. |
| Minor | Unreachable entries in `FORMULA_PREFIXES` and a dead `action` form fallback | Removed. Leading whitespace is stripped before the formula-prefix test, so the whitespace entries never applied. |

Not changed, and deliberately so: `MAX_REPORT_ROWS` cheaply rejects row-multiplication
shapes (an adversarial 1000-locations x 50-chains report is refused in under a second),
and the ALB assertion checks the signed header `exp` before the signature purely as an
early reject -- the JWS signature covers that header, so the verified decode remains
authoritative.

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

- `pytest`: 64 passing security and behavior tests, including repeated-trial
  concurrency tests for the administrator role and delete guards, CSRF rejection on
  every state-changing route, non-admin rejection on every admin mutation, preview
  row bounds, audit attribution and log-injection resistance, forwarded-header trust,
  limiter eviction, and ALB signing-key fetch deduplication.
- `bandit`: no findings in the web app, verifier, or exposed consolidator.
- `ruff check --select F,E9`: clean.
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
