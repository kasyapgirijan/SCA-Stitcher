# AWS production security profile

The web process is designed to run as an ECS/Fargate target behind an HTTPS
Application Load Balancer. Docker Compose remains a local-development profile.
Do not expose an ECS task, container port, or EC2 host directly to the internet.

## Required identity flow

1. Configure an ACM certificate and an ALB HTTPS listener.
2. Add an `authenticate-cognito` or `authenticate-oidc` listener action before
   the target-group forward action.
3. Set `OnUnauthenticatedRequest` to `authenticate` or `deny`.
4. Restrict the target security group to inbound TCP/8080 from only the ALB
   security group. The signed ALB headers are not an authorization boundary if
   callers can reach the target directly.
5. Configure a short ALB authentication session and MFA in Cognito or the
   corporate identity provider.
6. Set `ALB_LOGOUT_URL` to the IdP/Cognito HTTPS logout URL. If the logout return
   page is hosted by this service, add a narrowly scoped unauthenticated ALB rule
   for that path.

The application verifies the ALB ES256 signature, expected ALB ARN, client ID,
issuer when configured, header expiry, and signed subject. The task needs HTTPS
egress to `public-keys.auth.elb.<region>.amazonaws.com` to retrieve signing keys.

## Required application configuration

Store `SECRET_KEY` in AWS Secrets Manager and inject it with the ECS task
definition `secrets` field. Generate at least 32 random bytes. A rotated secret
requires a forced ECS deployment and invalidates existing application sessions.

Required production values:

```text
APP_ENV=production
AUTH_MODE=alb_oidc
COOKIE_SECURE=true
TRUSTED_HOSTS=reports.example.com
ALB_ARN=arn:aws:elasticloadbalancing:REGION:ACCOUNT:loadbalancer/app/NAME/ID
ALB_CLIENT_ID=the configured Cognito or OIDC client ID
ALB_ISSUER=https://expected-issuer.example
ALB_LOGOUT_URL=https://identity-provider.example/logout
```

Production startup fails closed when the signing secret, secure cookie,
trusted-host list, or ALB identity configuration is missing.

## WAF and network controls

Attach AWS WAF to the ALB and enable the current AWS managed common and IP
reputation rule groups. Add:

- a blanket IP rate rule for the application;
- a stricter rate rule scoped to `POST /report`;
- geo or corporate-network restrictions where business requirements allow;
- logging to a dedicated CloudWatch Logs group or Firehose destination.

ALB WAF body inspection is limited to 8 KiB, while legitimate reports are much
larger. Review oversize-body handling and override any managed body-size rule
that would reject `POST /report`; retain the application's byte and structural
limits as the authoritative upload controls.

Use private subnets for tasks. Permit inbound only from the ALB security group
and grant the task no AWS API permissions unless they are explicitly required.
Use VPC endpoints where practical for ECR, CloudWatch Logs, and Secrets Manager.

## ECS and image controls

Start from `aws/ecs-task-definition.example.json` and replace every placeholder.
The required controls are:

- Fargate `awsvpc` networking with explicit CPU and memory;
- non-root `app` user;
- read-only root filesystem and a writable ephemeral `/tmp` mount;
- all Linux capabilities dropped and no privileged mode;
- CloudWatch `awslogs` logging;
- health check on `/healthz`;
- immutable ECR image digest rather than a mutable tag;
- ECR enhanced scanning with deployment blocked on High or Critical findings.

The task definition intentionally has no user database volume. AWS production
uses managed ALB/Cognito/OIDC identity, so the local SQLite authentication store
is not part of the production architecture.

## Monitoring and release gates

Create alarms for ALB 4xx/5xx rates, target response time, unhealthy targets,
ECS restarts and memory pressure, WAF blocks, and repeated application
`security_event` records. Do not log uploaded report content, cookies, OIDC
tokens, CSRF values, or passwords.

Before each release:

```powershell
python -m pytest -q
python -m pip_audit -r requirements.txt
python -m bandit -q -r web_app.py security.py checkmarx_sca_consolidator_v2.py
docker build --pull -t checkmarx-sca-stitcher:release .
```

Push by immutable digest, review ECR/Inspector findings, and deploy through an
audited infrastructure pipeline. Back up configuration and identity-provider
settings; no uploaded report data is intended to require backup.
