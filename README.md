# Instagram Operations Manager

A semi-automated operations system for provisioning and managing **one company-authorised Instagram business
account**. The application automates the coordination and record-keeping: tasks, owners, deadlines,
reminders, escalation, verification evidence, the account register, weekly security audits, offboarding,
proxy health and reports. Every action on Instagram or Meta itself is a **tracked human task**, because those
actions have no supported integration or are security-sensitive.

> **What it never does:** automate Instagram signup, login or identity verification; touch CAPTCHA, MFA,
> checkpoints, rate limits or any platform enforcement; use proxies to evade anything; send traffic to any
> social platform; store or log passwords, codes, tokens or cookies.

---

## Contents

1. [Status at a glance](#1-status-at-a-glance)
2. [Architecture](#2-architecture)
3. [Quick start: synthetic demo](#3-quick-start-synthetic-demo)
4. [Live run in the company test environment](#4-live-run-in-the-company-test-environment)
5. [Configuration](#5-configuration)
6. [Database and migrations](#6-database-and-migrations)
7. [Running the application (and Docker)](#7-running-the-application-and-docker)
8. [Authentication and the first administrator](#8-authentication-and-the-first-administrator)
9. [API usage](#9-api-usage)
10. [Provisioning lifecycle and the human steps](#10-provisioning-lifecycle-and-the-human-steps)
11. [Reminders and escalation](#11-reminders-and-escalation)
12. [Weekly security audit](#12-weekly-security-audit)
13. [Offboarding](#13-offboarding)
14. [Vault integration](#14-vault-integration)
15. [Proxies: health, failover, rotate vs preserve](#15-proxies-health-failover-rotate-vs-preserve)
16. [Secret handling and log redaction](#16-secret-handling-and-log-redaction)
17. [Reliability and recovery after interruption](#17-reliability-and-recovery-after-interruption)
18. [Tests](#18-tests)
19. [Reports and evidence](#19-reports-and-evidence)
20. [Demo mode vs real integrations](#20-demo-mode-vs-real-integrations)
21. [Security and platform boundaries](#21-security-and-platform-boundaries)
22. [Known limitations](#22-known-limitations)
23. [Troubleshooting](#23-troubleshooting)

Related documents: [DECISION_LOG.md](DECISION_LOG.md) · [DEMO_SCRIPT.md](DEMO_SCRIPT.md) ·
[docs/device_fleet_plan.md](docs/device_fleet_plan.md) · [reports/README.md](reports/README.md)

---

## 1. Status at a glance

Requirement-by-requirement evidence is in [docs/requirements_traceability.md](docs/requirements_traceability.md).

| Area | State |
|---|---|
| Provisioning workflow (handle, email, phone, signup, verification, 2FA, profile, business conversion, Meta link, roles) | **Implemented and tested.** Every Instagram/Meta step is a guided human task. |
| Human tasks: owners, deadlines, reminders, escalation, resumption, reconciliation | **Implemented and tested.** |
| Account register (JSON / Markdown / CSV) | **Implemented and tested.** |
| Weekly audit with verification labels and deduplicated remediation | **Implemented and tested.** Scheduled in-process (one scheduled live run: `weekly:2026-W42`), or run from cron. |
| Offboarding (completed / pending / blocked, sole-admin protection) | **Implemented and tested with synthetic data. Blocked live:** no second real person exists to hold the temporary test role. |
| Proxy manager (timeouts, bounded retries with backoff and jitter, affinity, controlled failover) | **Implemented and run for real** against two operator-run proxies (open-source `proxy.py` on 127.0.0.1) to the neutral endpoint `https://example.com/`. No company-approved proxies were provided, and public/free proxy lists were deliberately not used. These proxies need no credentials, so the vault-stored proxy-credential path is exercised only in tests. Security challenges are shown in simulation only. |
| Vault | **Live run: a candidate-run HashiCorp Vault 2.2.0 on 127.0.0.1** (no company vault was provided). `python -m scripts.vault_check` passed against it on 2026-10-17: the app's token sees Instagram entries' existence and version but is refused their values (HTTP 403). `reference_only` (the default) and a dev-only synthetic vault also work. **It is not the company vault.** |
| Meta Graph (read-only verification) | Implemented, but **tested against a simulated transport only. Disabled by default.** |
| Email notifications (SMTP) | **Live: delivered through Gmail SMTP** (a candidate-provided relay; the app password is read from the vault). On 2026-10-17 the queued assignment emails for the 3 open tasks were delivered to the operator's inbox and the 3 for already-closed tasks were `superseded`, not sent. Also tested with a fake SMTP class and over a real SMTP conversation with a local sink. No reminder or escalation has fallen due live yet (first deadlines 2026-10-18). |
| Live Instagram account | **Not done by the software; in progress by hand.** The human tasks are being completed in the dashboard (the first handle check, confirmed with placeholder evidence, was reset and redone on 2026-10-17). The current state is in `reports/live/account_register.md`, re-exported with a timestamp after each session. See section 4 for the human steps. |
| Live evidence in `reports/live/` | Account register, redacted run log, audit reports (incl. one scheduled weekly run), 8 real proxy checks (bounded retries, failover, no fail-back, planned rotation) and 2 vault checks against the candidate-run HashiCorp Vault. **No live offboarding report:** that test is blocked (no second real person). |
| Optional Part D (Android device fleet) | **Skipped**; the plan is in [docs/device_fleet_plan.md](docs/device_fleet_plan.md). |
| Automated tests | **245 passing** (`python -m pytest -q`), including the 2026-10-17 review's regression tests (`tests/test_independent_review.py`, `tests/test_outside_transaction_reads.py`, `tests/test_smtp_socket.py`). |

## 2. Architecture

```
            +---------------------- FastAPI app (app/main.py) -----------------------+
 operators  |  /api/v1/*  (Bearer tokens, RBAC)        /dashboard (session + CSRF)   |
 ---------> |  middleware: correlation id, security headers, redacted access log     |
            +-----------------------------+-------------------------------------------+
                                          |
     +------------------+  +--------------+--------------+  +----------------------+
     | TaskManager      |  | ProvisioningService         |  | AuditService         |
     | state machine,   |<-| deterministic advance(),    |  | 10 checks, labels,   |
     | idempotent keys, |  | completion handlers,        |  | dedupe, remediation  |
     | completion hooks |  | reconciliation              |  +----------------------+
     +--------+---------+  +-----------------------------+  +----------------------+
              |            | ReminderService / Outbox    |  | OffboardingService   |
              |            | (reminders, escalation,     |  | actions, sole-admin  |
              |            |  3-phase dispatch)          |  | guard, reconcile()   |
              |            +-----------------------------+  +----------------------+
              |            | ProxyManager                |  | ReportService        |
              |            | probes, affinity, failover  |  | register/audit/off-  |
              |            +-----------------------------+  | boarding/run log     |
              v                                             +----------------------+
   SQLAlchemy 2 + Alembic (SQLite; PostgreSQL-ready)      Integrations (adapters):
   persisted: people, accounts, steps, tasks, events,     vault: reference_only | dev_memory | hashicorp_kv2
   notifications, findings, runs, cases, actions,         meta:  disabled | graph_readonly (verification only)
   proxies, sessions, proxy events                        notify: none | smtp
```

| Module | Responsibility |
|---|---|
| `app/services/task_manager.py` | Task creation (idempotency keys), validated transitions, owner/supervisor/admin authorisation, completion with evidence, and the completion and transition hooks |
| `app/services/task_types.py` | One spec per task type: human instructions, required outcome fields (confirmations, vault references, references), default deadline and priority, and outcome validation |
| `app/services/provisioning.py` | Account creation, handle suggestions, the `advance()` workflow engine, completion handlers, blockers, reconciliation, integration re-verification |
| `app/services/reminder_service.py` | Overdue marking, throttled reminders, escalation up the supervisor chain |
| `app/services/notification_service.py` | Notification outbox with dedupe keys; honest delivery states |
| `app/services/audit_service.py` | Weekly and manual audits, finding deduplication, remediation tasks, ISO-week idempotency |
| `app/services/offboarding_service.py` | Offboarding cases and actions, sole-admin protection, vault-version cross-check |
| `app/services/proxy_manager.py` | Probes, failure classification, health, sessions, failover, controlled rotation |
| `app/services/report_service.py` | Account register, audit report, offboarding report, redacted run-log export, leak guard |
| `app/services/recovery.py` | Idempotent startup recovery |
| `app/security/*` | Redaction, secret guards, token and session authentication, RBAC |
| `app/integrations/*` | Vault, Meta and notification adapters |
| `app/simulation/local_network.py` | Local neutral endpoint and forward proxies (simulation only) |

## 3. Quick start: synthetic demo

Prerequisites: Python 3.11+ (tested on 3.11, Windows 10). Docker is optional.

**Windows (PowerShell)**

```powershell
cd instagram-ops
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
python -m scripts.make_dev_env        # writes .env.demo (random secret key, dev-only synthetic vault)
$env:IOM_ENV_FILE = ".env.demo"       # select the demo config (bash: export IOM_ENV_FILE=.env.demo)
python -m scripts.init_db             # alembic upgrade head -> data/demo.db
python -m scripts.seed_demo --reset   # SYNTHETIC timeline and evidence pack in reports/synthetic_demo/
python -m scripts.proxy_demo          # SIMULATED proxy failover on 127.0.0.1
python -m scripts.export_reports      # refresh reports, including the redacted run log
python -m app                         # http://127.0.0.1:8077/dashboard
python -m pytest -q                   # 245 tests (tests ignore .env files)
```

**macOS / Linux**: the same commands, using `python3.11 -m venv .venv`, `source .venv/bin/activate` and
`export IOM_ENV_FILE=.env.demo`.

The demo and the live run use **separate** settings files (`.env.demo` and `.env`), databases
(`data/demo.db` and `data/live.db`), logs (`logs/demo/` and `logs/live/`) and reports
(`reports/synthetic_demo/` and `reports/live/`), so synthetic data can never mix with live evidence.

Sign in to the dashboard with a demo operator token. Tokens are in `data/demo_tokens.local.json`, which is
git-ignored and holds synthetic personas only. `owner` is an admin, `operator` an operator, `auditor` an
auditor and `publisher` a viewer. Both configs use port 8077; change `PORT` in the file if needed.

## 4. Live run in the company test environment

The assessment requires the account to be provisioned **on real Instagram by a human**, using the throwaway
brand kit, test email and phone, vault, separate Meta business and approved proxies. The application
coordinates and records that work.

1. **Configure.** Generate the live `.env` (no platform secrets go in it):
   ```powershell
   python -m scripts.make_live_env --meta-business-id <portfolio id> [--company-email-domain <company domain>] --vault-scheme bw [--candidate-provided]
   ```
   - `--candidate-provided` sets `ENVIRONMENT_LABEL=candidate_provided_test_environment`. Use it when the
     company did not supply the test environment and you created throwaway substitutes yourself. Every
     report and the dashboard then say so.
   - `--company-email-domain` (`COMPANY_EMAIL_DOMAINS`) must be a domain the **company** controls. Consumer
     domains such as `gmail.com` are refused: listing one would make the audit report every address there
     as company-controlled. If you only have a personal-provider mailbox, omit the option and choose
     `personal_provider_substitute` in the email task; the step completes and the audit flags it.
     **An existing `.env` with `COMPANY_EMAIL_DOMAINS=gmail.com` should be edited to remove it.**
   - Vault: with the company's HashiCorp Vault, or a candidate-run one (section 14; used for this live run), set
     `VAULT_BACKEND=hashicorp_kv2` and record references such as `vault://instagram/<handle>/password`: presence
     and versions are then machine-verified while the app's token is refused the values. Otherwise keep
     `reference_only` and record references to your password manager (e.g. `bw://...`), which stay human-confirmed.
   - Keep `META_INTEGRATION=disabled` unless a read-only token has been issued and the endpoint confirmed.
   - Proxies, only if approved ones exist: copy `config/proxies.example.json` to `config/proxies.json` and
     set `PROXY_CONFIG_FILE`, `PROXY_HEALTHCHECK_ALLOWED_URLS` and `PROXY_HEALTHCHECK_DEFAULT_URL`.
2. **Initialise:** `python -m scripts.init_db` (creates `data/live.db`). Make sure `IOM_ENV_FILE` is
   **not** set, so the live `.env` is used. Run it again after every code update, with the server stopped:
   it applies new migrations (for example `0003`, which records who controls the mailbox) and is safe to
   repeat.
3. **Bootstrap people.** There is no default admin:
   ```powershell
   python -m scripts.create_operator --name "Security Lead" --email security@testco.example --role admin --responsibility security_owner --responsibility escalation_default --responsibility vault_admin
   python -m scripts.create_operator --name "Account Owner" --email owner@testco.example --role admin --supervisor-email security@testco.example
   python -m scripts.create_operator --name "Departing Tester" --email tester@testco.example --role viewer --supervisor-email owner@testco.example
   ```
   Each command prints its token once (or writes it with `--token-file`). Put the tokens in your password manager.
4. **Create the account record**, its approved profile spec and access register (idempotent; repeat to add
   more). Then start with `python -m app` and sign in at `/dashboard`:
   ```powershell
   python -m scripts.create_account --brand "Test Brand" --owner-email owner@testco.example --profile-name "Test Brand" `
     --bio "Max 150 characters" --link https://brand.example --category "Product/service" --image-ref brandkit://logo.png `
     --assign owner@testco.example:business_admin --assign tester@testco.example:temporary_test_role `
     --access tester@testco.example:backup_codes:bw://Instagram/testbrand/backup-codes
   ```
5. **Do the human tasks in order.** Each task page carries the instructions, safety rules and completion
   form. Record only references and observations, never secrets.
6. **Access register:** add the owner as `business_admin`, the requested people with least-privilege roles,
   and the departing tester with `temporary_test_role` (`POST /api/v1/accounts/{id}/assignments`). Record
   which vault entries each person can read (`POST /api/v1/people/{id}/credential-access`).
7. **Audit:** `python -m scripts.run_audit` (or the dashboard button).
8. **Offboard the tester:** `POST /api/v1/offboarding`, then work the generated tasks.
9. **Export** with `python -m scripts.export_reports` (written to `reports/live/`).


Anything you cannot complete (missing access, a checkpoint, an unavailable integration) should be recorded
as a **blocked task** or an account blocker (`POST /api/v1/accounts/{id}/blocker`). The register and reports
then show it honestly. Unblocking resumes the workflow where it stopped.

To **redo** a completed handle, email or phone step before signup (for example, when it was confirmed with
placeholder evidence), an admin runs `python -m scripts.reset_step --step handle_selected --reason "..."` (or
`POST /api/v1/accounts/{id}/steps/{step}/reset`). The completed task stays in the history with a `step_reset`
event and the superseded evidence; the step returns to pending and a fresh task is issued. After signup it is
refused: those facts then describe the live account, and they are corrected with new evidence instead.

## 5. Configuration

All settings are environment variables (or a local `.env`); see `.env.example` for the full list.

| Variable | Default | Notes |
|---|---|---|
| `IOM_ENV_FILE` (process env only) | `.env` | Which settings file to read; the synthetic demo uses `.env.demo` |
| `ENVIRONMENT_LABEL` | `company_test_environment` | `candidate_provided_test_environment` when you created the test resources yourself; shown on every report |
| `APP_ENV` | `development` | `production` refuses the dev vault, disables docs and requires `TRUSTED_HOSTS` |
| `APP_SECRET_KEY` | none (required) | ≥32 random characters; keys HMACs of tokens, sessions and CSRF. Placeholders are rejected. |
| `DATABASE_URL` | `sqlite:///./data/instagram_ops.db` | PostgreSQL URLs work with an installed driver (e.g. `psycopg`) |
| `VAULT_BACKEND` | `reference_only` | `dev_memory` (dev/test only), `hashicorp_kv2` |
| `COMPANY_EMAIL_DOMAINS` | empty | Used to reject non-company aliases and in audit checks |
| `META_INTEGRATION` | `disabled` | `graph_readonly` needs `META_GRAPH_API_VERSION`, `META_BUSINESS_ID`, `META_ACCESS_TOKEN_VAULT_REF` |
| `NOTIFICATION_BACKEND` | `none` | `smtp` needs `SMTP_HOST`, `SMTP_FROM` (password by vault reference) |
| `REMINDER_INTERVAL_HOURS` / `OVERDUE_REMINDER_INTERVAL_HOURS` | 24 / 12 | Reminder throttle |
| `MAX_REMINDERS` / `MAX_ESCALATIONS` / `ESCALATION_REPEAT_HOURS` | 6 / 2 / 24 | Bounds |
| `AUDIT_WEEKLY_DAY` / `AUDIT_WEEKLY_HOUR_UTC` | `mon` / 9 | Weekly audit schedule |
| `ACCESS_STALE_DAYS` | 30 | Age at which access records count as stale |
| `SCHEDULER_ENABLED` | `false` | In-process jobs; alternatively run the scripts from cron |
| `PROXY_*` | see `.env.example` | Timeouts, attempts, backoff, cooldown, failover budget, allowlist |
| `CORS_ALLOWED_ORIGINS` | empty | CORS is off unless set |
| `AUTH_MAX_FAILED_ATTEMPTS` / `AUTH_FAILURE_WINDOW_SECONDS` | 10 / 900 | Failed-sign-in throttle per client address |

## 6. Database and migrations

- Schema migrations live in `migrations/` (Alembic). Apply them with `python -m scripts.init_db` or
  `alembic upgrade head`. Downgrade with `alembic downgrade base`.
- `tests/test_migrations.py` checks that the migration produces exactly the models' schema.
- SQLite is configured for safe concurrency: WAL mode, `busy_timeout`, and `BEGIN IMMEDIATE`, so writers
  serialise instead of failing. On PostgreSQL the same code relies on `SELECT ... FOR UPDATE`, unique and
  partial-unique indexes and optimistic version columns.

## 7. Running the application (and Docker)

```powershell
python -m app                      # uvicorn on HOST:PORT; uvicorn's access log is off (the app logs redacted lines)
```

- Dashboard: `/dashboard` (Overview, Accounts, Tasks, Audit, Offboarding, Proxies, Notifications; server-rendered light theme, no JavaScript, works at phone width). Health: `/health/live`, `/health/ready`. In development the OpenAPI docs are at
  `/docs`; they are always off in production.
- With `SCHEDULER_ENABLED=true` the process runs reminders every 15 minutes, notification dispatch every
  minute, proxy checks every 10 minutes, the weekly audit, and an hourly catch-up for a missed weekly audit.

Docker (optional; **the Dockerfile has not been built in this environment**):

```bash
cp .env.example .env   # fill in APP_SECRET_KEY etc.
docker compose up --build   # binds 127.0.0.1:8000; runs migrations then the app as a non-root user
```

## 8. Authentication and the first administrator

- **API:** `Authorization: Bearer iom_...`. Only an HMAC-SHA256 (keyed by `APP_SECRET_KEY`) of each token
  is stored. Tokens are shown once.
- **Bootstrap:** there is no default user or password. The first admin is created from a shell on the host
  with `python -m scripts.create_operator ... --role admin`. Later operators can be created through the API
  (`POST /api/v1/people`, then `POST /api/v1/people/{id}/credentials`).
- **Roles:** `viewer` (read), `operator` (accounts, tasks, reminders), `auditor` (read, audits, exports),
  `admin` (everything: access register, offboarding, proxy control, people). Task actions are further
  restricted to the task owner, the task supervisor or an admin.
- **Dashboard:** a token is exchanged for a server-side session cookie (HttpOnly, SameSite=Strict, Secure
  in production). Every form carries an HMAC-derived CSRF token.
- Offboarding revokes the person's own tokens and sessions immediately. It won't revoke the last active
  admin credential.
- **Rotate an exposed token** (pasted into a chat, a ticket or a screen share) with
  `python -m scripts.rotate_token --email <person> --token-file <file>`: it issues a new token with the same role,
  writes it to the file only, and revokes every other token and dashboard session the person holds.
- Change where a person's notifications go with `python -m scripts.update_person_email --from-email ... --to-email ...`.
- **Failed attempts are throttled:** after `AUTH_MAX_FAILED_ATTEMPTS` (10) invalid tokens from one client
  address within `AUTH_FAILURE_WINDOW_SECONDS` (900), the API and the sign-in page answer 429 with
  `Retry-After` until the window ends, without checking any token. Each failure is logged as
  `auth.failed_attempt` (the token itself is never logged).

## 9. API usage

PowerShell:

```powershell
$h = @{ Authorization = "Bearer $env:IOM_TOKEN" }
$base = "http://127.0.0.1:8077/api/v1"

# create (idempotent per brand) - 201 first time, 200 + existing record afterwards
$body = @{ brand_name = "Test Brand"; owner_id = "per_..."; handle_keywords = @("studio")
  profile = @{ profile_name = "Test Brand"; bio = "Max 150 characters"; profile_link = "https://brand.company.example"
               category = "Product/service"; profile_image_ref = "brandkit://logo-v1.png" } } | ConvertTo-Json -Depth 4
Invoke-RestMethod -Method Post "$base/accounts" -Headers $h -ContentType application/json -Body $body

Invoke-RestMethod "$base/tasks?open_only=true" -Headers $h            # what is waiting, for whom, until when
Invoke-RestMethod "$base/tasks/<task_id>" -Headers $h                 # instructions + required outcome fields

# complete a task (only references / confirmations - never secrets)
$done = @{ evidence_ref = "searched handle in official app"; outcome = @{ selected_handle = "testbrand"; checked_via = "instagram_app" } } | ConvertTo-Json
Invoke-RestMethod -Method Post "$base/tasks/<task_id>/complete" -Headers $h -ContentType application/json -Body $done
```

curl:

```bash
curl -s -X POST $BASE/tasks/<task_id>/fail -H "Authorization: Bearer $IOM_TOKEN" -H 'Content-Type: application/json' \
  -d '{"reason":"browser crashed after submitting signup","outcome_uncertain":true}'
curl -s -X POST $BASE/audits/run -H "Authorization: Bearer $IOM_TOKEN" -H 'Idempotency-Key: audit-2026-10-16'
curl -s -X POST $BASE/offboarding -H "Authorization: Bearer $IOM_TOKEN" -H 'Content-Type: application/json' \
  -d '{"person_id":"per_...","reason":"test team member leaving"}'
```

Endpoint summary (all under `/api/v1` unless noted):

| Purpose | Endpoint |
|---|---|
| Health / readiness | `GET /health/live`, `GET /health/ready` |
| Who am I / integration status | `GET /me`, `GET /integrations` |
| People and credentials | `GET/POST /people`, `POST /people/{id}/credentials`, `GET/POST /people/{id}/credential-access` |
| Accounts | `POST/GET /accounts`, `GET /accounts/{id}`, `GET /accounts/{id}/handle-suggestions`, `GET /accounts/handle-format/{handle}`, `PUT /accounts/{id}/profile`, `POST /accounts/{id}/assignments`, `POST /accounts/{id}/reconcile`, `POST /accounts/{id}/steps/{step}/evidence`, `POST /accounts/{id}/steps/{step}/reset` (admin, pre-signup steps), `POST /accounts/{id}/verify-integrations`, `POST/DELETE /accounts/{id}/blocker` |
| Tasks | `GET/POST /tasks`, `GET /tasks/overdue`, `GET /tasks/{id}`, `POST /tasks/{id}/{start,assign,complete,block,unblock,fail,cancel}` |
| Reminders and notifications | `POST /tasks/reminders/run`, `GET /notifications`, `POST /notifications/dispatch`, `POST /notifications/{id}/requeue` |
| Audits | `POST /audits/run` (optional `Idempotency-Key`), `GET /audits`, `GET /audits/{run_id}`, `GET /audits/findings` |
| Offboarding | `POST/GET /offboarding`, `GET /offboarding/{id}`, `POST /offboarding/{id}/reconcile`, `GET /offboarding/{id}/report?format=json\|md` |
| Proxies | `GET /proxies`, `POST /proxies/health-check`, `POST /proxies/{id}/health-check`, `POST/GET /proxies/sessions`, `POST /proxies/sessions/{id}/probe`, `POST /proxies/sessions/{id}/failover`, `POST /proxies/sessions/{id}/end` |
| Reports | `GET /reports/account-register?format=json\|md\|csv`, `POST /reports/export`, `GET /reports/run-log` |

Errors always have the shape `{"error": {"code", "message", "details", "correlation_id"}}`. Validation errors
never echo submitted values.

## 10. Provisioning lifecycle and the human steps

```
draft -> awaiting_handle_check -> awaiting_contact_assignment -> awaiting_signup -> awaiting_verification
      -> awaiting_security_setup -> awaiting_profile_setup -> awaiting_meta_link -> provisioned
                         awaiting_signup --(signup failed/cancelled/uncertain)--> awaiting_reconciliation
any state --(task blocked / operator blocker)--> blocked --(unblocked)--> previous state
```

| Step (task type) | Human does | Records (no secrets) | Verification label |
|---|---|---|---|
| Handle check | Checks availability in the official app or web | selected handle | human_confirmed |
| Company email | Requests or creates an alias on an approved domain | ticket ref + address (stored only as a masked hint and domain) + who controls the mailbox (`personal_provider_substitute` is recorded as non-company and flagged by the audit) | human_confirmed |
| Company phone | Reserves a company-controlled number | inventory ref + E.164 number (stored only as a masked hint) | human_confirmed |
| Signup | Signs up manually once; password generated and saved in the vault | handle + password vault ref | human_confirmed (vault presence integration_verified when the vault exposes metadata) |
| Verification | Completes Instagram's own email/SMS checks; checks recovery details | four confirmations | human_confirmed |
| 2FA | Enables an authenticator app or security key (SMS discouraged); backup codes straight to the vault | method + vault refs | human_confirmed (+ vault metadata) |
| Profile | Applies the approved name, bio (≤150, validated), link, category and image | confirmation | human_confirmed |
| Business conversion | Switches to a professional **business** account | account type | human_confirmed |
| Meta link | Adds the account to the separate test business in Business Suite / Manager | business ref | integration_verified if the read-only Meta integration lists it, otherwise human_confirmed |
| Roles | Grants exactly the approved least-privilege roles | confirmation | human_confirmed |

Rules enforced in code:

- An account becomes `provisioned` only when every step is complete with evidence and verification above
  `unverified`.
- A failed, cancelled or interrupted signup **never triggers a second signup**. A reconciliation task asks
  whether the account exists. `does_not_exist` creates attempt *n+1*; `exists_controlled` resumes;
  `exists_not_controlled` blocks.
- Evidence and notes are scanned for secret-looking material (backup-code digit groups, `password=...`,
  tokens, JWTs, URLs with credentials, high-entropy strings) and rejected with a message that never repeats
  the value.

## 11. Reminders and escalation

- Reminders are throttled by **persisted** state (`last_reminder_at`, `reminder_count`): every 24 hours,
  every 12 hours once overdue, capped at `MAX_REMINDERS`. Running the job more often sends nothing extra.
- After the deadline, escalation goes to the task supervisor (level 1) and one step further up (level 2),
  falling back to the person holding `escalation_default`. It repeats at most every
  `ESCALATION_REPEAT_HOURS`, up to `MAX_ESCALATIONS`. Blocked tasks are escalated; their owners are not
  nagged.
- Every notification has a dedupe key (`reminder:<task>:<n>`, `escalation:<task>:<level>`), so it's queued
  exactly once.
- Delivery is honest. With no provider, notifications are `not_delivered_no_provider` and listed on the
  dashboard; they go out automatically once SMTP is configured, **except** those whose task has meanwhile
  been completed, cancelled or failed: they become `superseded` and are never sent, so a late provider
  cannot announce finished work. A send interrupted mid-transfer becomes `uncertain` and is only resent
  when a human requeues it.
- Trigger reminders with `python -m scripts.run_reminders`, `POST /api/v1/tasks/reminders/run`, the
  dashboard button, or the scheduler.

## 12. Weekly security audit

Ten checks per account. Each result carries a verification label and an evidence reference:

| Check | Example finding (label) |
|---|---|
| `recovery_email_company_controlled` / `recovery_phone_company_controlled` | not company-controlled (human_confirmed); no evidence yet (**unverified**, explicitly *not* a failure) |
| `two_factor_enabled` | not verified (unverified); SMS method (human_confirmed, low) |
| `backup_codes_in_vault` | vault reports no entry (integration_verified); replacement pending after offboarding |
| `required_vault_references` | password reference missing or malformed |
| `meta_business_association` | not confirmed; does not match the designated business |
| `people_roles_match_register` | offboarded person still active (critical); unapproved role; no admin; too many admins |
| `access_records_fresh` | not re-verified in `ACCESS_STALE_DAYS` (unverified) |
| `provisioning_tasks_complete` | steps pending or overdue (integration_verified from the system of record) |
| `outstanding_security_offboarding_actions` | open or blocked offboarding actions, overdue remediation, unresolved challenge reviews |

- **Labels:** `integration_verified` means read from the authoritative system: a configured integration, or
  this application's own records where it *is* the system of record. `human_confirmed` means attested by a
  named human with evidence. `unverified` means no adequate evidence. Missing data never becomes "disabled"
  or "failed".
- **Deduplication:** one open finding per (account, fingerprint), enforced by a partial unique index.
  Re-detection increments `occurrence_count`. Remediation reuses any active task of the right type,
  including the provisioning task already covering it. A finding that is no longer detected is resolved,
  and its audit-created task is closed. Completing a remediation task re-checks the finding at once.
- **Scheduling:** weekly runs use the key `weekly:<ISO year>-W<week>`, so duplicates or restarts never create a
  second run, and an interrupted run is re-run under the same key.
- **Manual run:** `python -m scripts.run_audit` (add `--weekly` for the idempotent weekly key),
  `POST /api/v1/audits/run`, or the dashboard button. Each run writes
  `reports/audit/audit_report_<timestamp>_<run>.{json,md}`.

## 13. Offboarding

`POST /api/v1/offboarding {"person_id": "...", "reason": "...", "replacement_admin_id": "...optional"}`
opens one case per person; repeated calls return the same case. `reconcile` can run any number of times.

| Action | Who or what | Completed when |
|---|---|---|
| `revoke_app_access` | The system | The person's tokens and sessions are revoked and verified (integration_verified). Blocked if it would remove the last admin credential. |
| `identify_roles`, `identify_credentials` | The system | Inventory captured from the register (human_confirmed source) |
| `remove_account_role` (per role) | An active admin or the owner (never the departing person) | Human confirms removal on the platform |
| `grant_replacement_admin` | Owner or security owner | Required before removing a **sole** admin; without a replacement the removal is BLOCKED |
| `remove_vault_access` (per entry) | Person holding `vault_admin` | Human confirms; BLOCKED if nobody holds `vault_admin` |
| `rotate_credential` / `replace_backup_codes` | Platform operator, or `proxy_provider_admin` for proxies | Human confirms. If the vault exposes metadata, the entry's version **must have increased**, otherwise BLOCKED `VAULT_VERSION_UNCHANGED`. If the vault is unreachable at that moment, BLOCKED `VAULT_UNAVAILABLE` and re-checked on the next reconcile (the version check is never skipped) |
| `verify_access_state` | Security owner | Created only after every removal and rotation is done. If new access is recorded for the person afterwards, the open request is cancelled (or a completed verification reopened) and a fresh one follows the new removals |
| `update_register` | The system | Person marked offboarded; all assignments removed; no removal or rotation outstanding |

A pending action means a task exists, **not** that access is gone. The report says so and lists outstanding
risks. Recording vault access for a person with an open case (`POST /people/{id}/credential-access`)
reconciles the case immediately. Use the designated **temporary test role** for the departing tester in the
live run.

## 14. Vault integration

| Backend | Use | Verification effect |
|---|---|---|
| `reference_only` (default) | Live run with any company vault product. Humans store secrets; the app records references only. | Vault facts are `human_confirmed` |
| `hashicorp_kv2` | Company (or candidate-run) HashiCorp Vault KV v2. Set `VAULT_ADDR`, `VAULT_KV_MOUNT`, `VAULT_TOKEN_FILE` (least-privilege token: metadata read, plus read on proxy/SMTP entries). | Presence and versions are `integration_verified`; a soft-deleted or destroyed current version counts as **absent**. Reads retry with backoff; writes are never retried blindly. Checked against a real candidate-run Vault 2.2.0 with `scripts/vault_check.py`; **not yet against the company vault.** |
| `dev_memory` | Development and tests only. Accepts only `devvault://` refs and `SYNTHETIC-*` values; refuses production. | Synthetic `integration_verified` (reports flag it) |

### Candidate-run local HashiCorp Vault (when no company vault is provided)

This is a substitute you run yourself, so reports must call it "candidate-run", never "the company vault".
Config and policy are in `config/vault/`; the encrypted storage folder `vault-data/` is git-ignored and never
packaged. Run these in PowerShell from the project folder. **You** run `init`: its output is your unseal key
and root token, so save both in your password manager at once and never paste them anywhere else.

```powershell
# terminal 1 (leave running)
vault server "-config=config/vault/vault-local.hcl"   # quoted: Windows PowerShell 5.1 splits unquoted -x=a.b at the dot

# terminal 2
$env:VAULT_ADDR = "http://127.0.0.1:8200"
vault operator init -key-shares=1 -key-threshold=1   # save "Unseal Key 1" and "Initial Root Token" in your password manager
vault operator unseal                                # hidden prompt: the unseal key
vault login                                          # hidden prompt: the root token (admin work only)
vault secrets enable -path=secret kv-v2
vault policy write instagram-ops config/vault/instagram-ops-policy.hcl
New-Item -ItemType Directory -Force secrets | Out-Null
vault token create -policy=instagram-ops -ttl=720h -field=token | Set-Content -NoNewline -Encoding ascii secrets\vault-token
```

Store secret **values** in the Vault web UI (http://127.0.0.1:8200/ui, under `secret/`), not on a command line:
`instagram/<handle>/password`, `instagram/<handle>/backup-codes`, and, if used, `smtp/gmail` (field `password`),
`meta/graph-token` (field `value`), `proxies/<proxy id>` (fields `username`, `password`). Then set in `.env`:
`VAULT_BACKEND=hashicorp_kv2`, `VAULT_ADDR=http://127.0.0.1:8200`, `VAULT_KV_MOUNT=secret`,
`VAULT_TOKEN_FILE=secrets/vault-token`, and run `python -m scripts.vault_check`. It proves, with the app's own
token, that Vault is unsealed, that Instagram entries' metadata is visible but their **values are denied**, and
that each configured runtime secret is readable. It writes `reports/<env>/vault/vault_check_<ts>.json`, with no
values in it. Task completions then record references such as `vault://instagram/<handle>/password`, and their
presence and versions become `integration_verified`.

After every restart Vault starts **sealed**: start the server and run `vault operator unseal` before the app.
While it is sealed, readiness reports `sealed` and vault facts are recorded as `unverified`, never as failures.

To add another vault product (1Password Connect, AWS Secrets Manager, ...), implement the five methods of
`app/integrations/vault/base.py:VaultAdapter`. The application only reads secrets it needs at runtime:
proxy credentials, the SMTP password and the Meta token. Instagram passwords and backup codes are never read.

## 15. Proxies: health, failover, rotate vs preserve

- **Configuration:** `config/proxies.json` (see `config/proxies.example.json`) lists approved proxies.
  Inline credentials are rejected; `credential_ref` points to a vault entry with `username` and `password`.
  Health checks may only target `PROXY_HEALTHCHECK_ALLOWED_URLS`, and social-platform domains are refused
  unconditionally, even if configured.
- **Probes:** separate connect/read timeouts; at most `PROXY_MAX_ATTEMPTS` (≤10) attempts with capped
  exponential backoff and jitter. Each failure is classified as proxy-side (refused, connect timeout, 407,
  protocol error, credential unavailable), endpoint-side (relayed 5xx/502/504), ambiguous (read timeout),
  or *stop* (429, security challenge).
- **Health:** healthy, unhealthy (with cooldown) or quarantined (407; a maintenance task is created and the
  proxy is only used again after a successful check). `check_all` uses cross-evidence: if every proxy fails
  the same way, the **endpoint** is diagnosed instead of the proxies being penalised.
- **Rotate vs preserve:**
  - **Preserve by default.** A session keeps its proxy, so the account sees one consistent connection
    identity.
  - **Fail over** only when the proxy itself has failed after bounded retries, and only to a candidate that
    has just passed a health check. Failovers per session are capped (`PROXY_MAX_FAILOVERS_PER_SESSION`);
    beyond that the session pauses for review. A recovered proxy doesn't pull the session back.
  - **Never rotate** in response to the destination. A 429 means back off on the same proxy. A security
    challenge pauses the session and creates a human review task; no retry, no rotation. Rotating there
    would be evasion.
  - **Endpoint failures** keep the proxy, because moving would not help.
  - **Planned rotation** (`POST /proxies/sessions/{id}/failover`) only accepts operational reasons
    (`scheduled_maintenance`, `proxy_degraded`, `credential_rotation`, `provider_request`). It is refused
    during back-off or review.
- **Live check with operator-run proxies** (used because no company proxies were provided). Start two real
  proxies you control, in two terminals:
  ```powershell
  python -m proxy --hostname 127.0.0.1 --port 8899 --num-workers 1 --num-acceptors 1   # proxy A
  python -m proxy --hostname 127.0.0.1 --port 8900 --num-workers 1 --num-acceptors 1   # proxy B
  python -m scripts.proxy_check --new-session   # session bound to A, request preserved on A
  # stop proxy A (Ctrl+C), then:
  python -m scripts.proxy_check                 # 3 bounded attempts on A -> verified failover to B
  # start proxy A again, then:
  python -m scripts.proxy_check                 # A healthy again, session stays on B (no flapping)
  ```
  Each run writes `reports/live/proxy/proxy_check_<timestamp>.json`; the transitions are in the redacted run
  log. `config/proxies.operator-local.json` lists the two proxies. **Never use public/free proxy lists:**
  they are not approved, often run on compromised machines, and anonymous proxies are evasion tools.
- **Simulation:** `python -m scripts.proxy_demo` (with `.env.demo`) also exercises rate limits and security
  challenges, which real proxies to example.com cannot produce. It writes `reports/synthetic_demo/proxy_demo/`.
- With company proxies, put them in `config/proxies.json` and use `POST /api/v1/proxies/health-check`.

## 16. Secret handling and log redaction

- No secret is stored in the database. Accounts hold vault **references** and masked hints; raw contact
  email and phone values are used only to derive hints. Tokens and sessions are stored as HMACs.
- `SecretValue` wraps anything read from the vault; `str()`, `repr()` and f-strings print `[REDACTED]`.
- `Redactor` runs on every log record (third-party loggers included), every task event and payload, every
  notification, and every report. It works at three levels:
  - **Keys:** password, token, cookie, authorization, backup codes and similar are replaced; `*_ref`,
    `*_status` and other metadata keys stay readable.
  - **Patterns:** credentials in URLs, Bearer/Basic headers, `key=value` secrets, JWTs, known token
    formats, 8-digit backup codes and private keys are replaced; phones and emails are masked.
  - **Exact values:** every secret resolved at runtime (including its URL-encoded form) is registered and
    replaced wherever it appears.
- Request bodies and query strings are never logged. Validation errors don't echo inputs. Unhandled errors
  return a generic 500 with a correlation id.
- Reports are scanned after writing; a file containing any registered secret is deleted and the export
  fails (`SecretLeakDetected`).
- Tests deliberately inject synthetic secrets into notes, payloads, exceptions, proxy errors and requests,
  and assert they appear in no log, response or report.

## 17. Reliability and recovery after interruption

- **Idempotency.** The brand key is unique (no duplicate accounts). Every task has a stable unique
  idempotency key (`<account>:<type>:g<n>`, `<account>:account_signup:a<attempt>`, `remediation:<finding>:g<n>`,
  `offboarding:<action>:g<n>`). Offboarding actions are deduped, and the open-case and open-finding indexes
  are partial-unique. The ISO-week key covers weekly audits; dedupe keys cover notifications.
- **Transactions.** A task's status change, its completion handler and downstream task creation commit or
  roll back together. Row locks and version counters make repeated or concurrent completions safe: a
  4-thread test produces exactly one downstream task.
- **Restart.** `run_startup_recovery` marks audits left running as `interrupted` (safe to re-run) and
  notifications left `sending` as `uncertain`. It then re-syncs proxy config, marks overdue tasks,
  re-evaluates accounts (creating only *missing* human tasks) and reconciles open offboarding cases. It
  never treats a pending task as failed and never repeats an external action.
- **Uncertain outcomes are reconciled, not retried:** signup (reconciliation task), vault writes
  (`outcome_uncertain`, no auto-retry), notifications (`uncertain`), proxy challenges (paused for review).
- **No network call runs inside a DB transaction.** Proxy probes and notification sends are made between
  short transactions. Vault-metadata and Meta checks, whose answers a completion, audit or offboarding
  reconcile needs, go through `app/integrations/reads.py`: inside a unit of work they are answered from a
  cache; a miss rolls the unit back, makes the read with no transaction open, and re-runs the unit on fresh
  state. Events logged during a rolled-back pass are discarded. `tests/test_outside_transaction_reads.py`
  checks, from a second connection, that the SQLite write lock is free during every such read.
- **Bounded retries everywhere:** proxies, vault reads, Meta reads, notification sends. Each has a cap,
  backoff and jitter.

## 18. Tests

```powershell
python -m pytest -q                      # 245 tests, ~2-3 minutes
python -m pytest -q -m integration       # the real-socket proxy test only (127.0.0.1)
```

The suite covers account validation and the 150-character bio; task creation, assignment and transitions;
duplicate and concurrent completion; idempotent resumption and reconciliation; restart persistence;
reminder throttling and escalation; audit labels and deduplication; offboarding tracking, repetition and
sole-admin protection; proxy timeouts, retries, failover and unavailable endpoints; secret redaction in
logs, responses and reports; authentication, RBAC, CSRF and production settings; report generation;
missing integrations; uncertain outcomes; and migrations. External services are faked (MockTransport, fake
SMTP, local servers). No automated test touches Instagram, Meta, a real vault or a real proxy; the live checks
(`scripts.vault_check`, `scripts.proxy_check`) do, by design, and only against your own resources.

## 19. Reports and evidence

Reports go to `REPORTS_DIR`: `reports/live/` for the live run, `reports/synthetic_demo/` for the demo.

| File (inside the reports folder) | Content |
|---|---|
| `account_register.{json,md,csv}` | Register: status, owner, contacts (masked), recovery and 2FA with labels, vault refs, roles, steps with evidence, blockers, gaps |
| `audit/audit_report_<ts>_<run>.{json,md}` | One per audit run (history) |
| `audit/audit_report_latest.{json,md}` | Latest run with current finding states |
| `offboarding/offboarding_report_<case>.{json,md}` | Completed / pending / blocked, owners, evidence, labels, outstanding risks |
| `run_log_redacted.jsonl` | Structured run log (ts, correlation_id, event, account_id, task_id, action, outcome, retry_count, verification_source, redacted error) |
| `proxy_demo/proxy_failover_demo.{json,md}` | **Simulated** proxy demonstration |
| `proxy/proxy_check_<ts>.json` | Live proxy checks through operator-run proxies (`python -m scripts.proxy_check`) |
| `vault/vault_check_<ts>.json` | Vault checks with the app's own token (`python -m scripts.vault_check`); statuses only, no values |

Every report states its `data_classification` (`SYNTHETIC_DEMO_DATA`, `COMPANY_TEST_ENVIRONMENT`,
`CANDIDATE_PROVIDED_TEST_ENVIRONMENT`, or mixed) and the true state of each integration. See
[reports/README.md](reports/README.md).

## 20. Demo mode vs real integrations

| | Synthetic demo (`make_dev_env` + `seed_demo`) | Live company test environment |
|---|---|---|
| Accounts and people | Flagged `is_synthetic`; "(SYNTHETIC)" names | Real test brand and team |
| Human confirmations | Performed by synthetic personas on a simulated clock | Performed by the people doing the tasks |
| Vault | `dev_memory` with `SYNTHETIC-*` values | The company vault, or a candidate-run HashiCorp Vault (this run); `reference_only` if neither |
| Proxies | Local stand-ins (`proxy_demo`) | `config/proxies.json` + approved neutral endpoint |
| Notifications | Not delivered (no provider) | SMTP through the company relay, or a candidate-provided one (Gmail in this run) |

The dashboard shows a banner and reports carry a classification whenever synthetic data is present.

## 21. Security and platform boundaries

- No code path automates or contacts Instagram, Facebook or Meta (except the optional read-only verification
  call), or any social platform. Health-check destinations are allowlisted, and social domains are rejected
  at configuration time and at request time.
- Security challenges and checkpoints are handed to humans: the task instructions say *stop and mark
  blocked*, and the proxy layer pauses sessions.
- Least privilege: RBAC roles, task-level ownership checks, at most two business admins, a dedicated
  temporary test role, a read-only Meta scope, and a vault token needing only metadata and specific reads.
- Production guards: the dev vault is refused, docs are disabled, trusted hosts are required, HSTS and
  secure cookies are on, CORS is off by default, and a strict CSP is set on every non-docs page.

## 22. Known limitations

- **Nothing has run against a company-provided environment** (none was supplied). The live run uses
  candidate-provided substitutes (see DECISION_LOG.md) and is still in progress (see the exported register).
  The vault (a candidate-run HashiCorp Vault) and the mail relay (Gmail) were exercised for real; a Meta app
  token and company-approved proxies were never available, so those paths are tested against simulated
  transports (proxies also through operator-run local proxies).
- The Meta Graph edge used for verification (`GET /{business-id}/instagram_accounts`, a list of IGUser
  nodes) was confirmed in the Graph API v26.0 reference on 2026-10-17. That page does not name the required
  permission: confirm the token's permissions before enabling. The adapter never calls the same path's DELETE.
- Platform-side facts (2FA state, recovery details, granted roles) can only be **human_confirmed**; Instagram
  offers no supported API to read them.
- Single-process scheduler. Running several app instances is safe for data integrity (keys and locks), but
  startup recovery assumes one worker when it marks in-flight audits interrupted.
- Failed sign-ins are throttled per client address, in memory and per process. There is no MFA for
  operators: put the app behind the company SSO or a reverse proxy before any shared deployment.
- The Dockerfile and docker-compose file have not been built (Docker is not installed in this environment).
- The dashboard is functional rather than polished; the API is the primary interface.
- The three live audit reports dated 2026-10-17 05:50–06:48 UTC were produced before a labelling fix: they
  show `people_roles_match_register` as `pass / human_confirmed` although no role had been granted. The run
  at 07:53 UTC (`aud_2548f6ed…`, also `audit_report_latest`) reports it correctly as `not_applicable / unverified`.
- The Meta check reads at most 5 pages (500 accounts). Beyond that it reports `unknown`, not "not linked".

## 23. Troubleshooting

| Symptom | Fix |
|---|---|
| `APP_SECRET_KEY must be set...` | Run `python -m scripts.make_dev_env` (demo) or set a ≥32-character random key in `.env` |
| `Database schema is missing` / readiness `schema_missing` | `python -m scripts.init_db` |
| `no such column: instagram_accounts.company_email_control` | The code is newer than the database: stop the server, `python -m scripts.init_db`, restart |
| `error while attempting to bind on address ... 8000` | Port in use: `PORT=8077 python -m app` (PowerShell: `$env:PORT="8077"`) |
| Dashboard redirects to `/login` | Session expired (8h) or token revoked; sign in again |
| `secret_material_rejected` (422) | You pasted something that looks like a secret; store it in the vault and submit only the reference |
| `No vault entry exists at ...` on task completion | Store the secret in the vault first (vault backends with metadata check presence) |
| Readiness `vault: sealed`, vault facts `unverified` | Vault restarted sealed: `vault operator unseal` (start it with `vault server "-config=config/vault/vault-local.hcl"` from the project folder) |
| `vault server` says it cannot find `config/vault/vault-local` | Windows PowerShell split the argument at the dot: put the whole `-config=...hcl` argument in quotes |
| Notifications `failed` with `SMTP authentication failed` | The relay refused the login: for Gmail, create a new app password and store it in the vault at `smtp/gmail` (key `password`), then requeue (`POST /api/v1/notifications/{id}/requeue`) |
| Email task refuses `company_controlled` for a gmail.com address | Correct: a consumer mailbox is never company-controlled. Choose `personal_provider_substitute` |
| Proxy check `destination_not_approved` | Add the neutral endpoint to `PROXY_HEALTHCHECK_ALLOWED_URLS` (social platforms can never be added) |
| `seed_demo` refuses to run | It needs `VAULT_BACKEND=dev_memory` + `DEV_VAULT_FILE` and only resets synthetic data |
| Notifications show `not_delivered_no_provider` | Expected without SMTP; configure `NOTIFICATION_BACKEND=smtp` |
