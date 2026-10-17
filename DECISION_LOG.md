# Decision log

**Built.** A FastAPI + SQLAlchemy service that coordinates one company-authorised Instagram business account: a
persistent human-task engine (owners, deadlines, evidence, reminders, escalation); a deterministic provisioning
workflow (handle → email → phone → signup → verification → 2FA → profile → business → Meta link → roles) with
reconciliation for interrupted signups; a register with per-fact verification labels; a weekly audit (10 checks,
deduplicated findings, remediation tasks); offboarding with completed, pending and blocked actions; a proxy
manager; redacted JSON-lines logs, reports, a dashboard, Alembic migrations and 245 tests.

**Skipped, and why.** Part D is optional; the time went to the weighted areas (plan: `docs/device_fleet_plan.md`).
Meta and Instagram *mutations* stay human tasks: they are security-sensitive and API support was unconfirmed. Meta
is used only for read-only verification, off by default. Operator SSO/MFA, PostgreSQL and a multi-worker scheduler
are deferred: the prototype is one process.

**Architecture.** One process, one database, an in-process scheduler, no broker. Durability comes from persisted
state and idempotency keys, and every job is idempotent, so APScheduler, cron scripts and the API run the same
code. A DI container lets tests swap the clock, vault, transports and notifier, so concurrency, restart, failover
and leak paths are tested deterministically.

**Security.** The app never reads Instagram passwords or backup codes. By default it only records references; in the live
run a candidate-run HashiCorp Vault lets it verify their presence and version while its token is refused the values.
Runtime secrets (proxy, SMTP, Meta) are read per use, wrapped, and registered with a three-layer redactor (keys,
patterns, exact values) covering logs, events, notifications and reports. Written reports are leak-scanned, and
`scripts/package_submission.py` refuses to build a zip that contains any secret present on this machine.
Secret-looking input is rejected without being echoed. Tokens and sessions are stored as HMACs; RBAC plus
owner/supervisor checks; failed sign-ins are throttled per client; no default admin. Production refuses the dev
vault and enforces trusted hosts, secure cookies, CSRF, a strict CSP and closed CORS.

**Reliability.** Unique keys back every create (brand, task idempotency keys, partial-unique open findings and
cases, notification dedupe keys, the ISO-week audit key). Completion locks the row and commits its side effects
atomically (a 4-thread test proves one downstream task). Vault and Meta reads happen between transactions, never
inside one (tested by checking the SQLite write lock during every read). Anything that may have happened
externally is reconciled, never blindly retried: signup, vault writes, notifications (`sending` → `uncertain`).
Startup recovery is idempotent and never treats a pending task as failed.

**Rotate vs preserve.** Preserve by default (session affinity). Fail over only when the proxy itself fails after
bounded retries, to a candidate that has just passed a check, within a per-session budget; a recovered proxy does
not pull the session back. Planned rotation only for operational reasons. Never rotate on a 429 (back off) or a
security challenge (pause for human review): that would be evasion. If every proxy fails the same way, the
endpoint is at fault, so keep the proxy.

**Known failure points.** Human confirmations can be wrong; they stay `human_confirmed` and audits re-check them.
Vault metadata proves an entry exists, not that the secret works. SQLite serialises writers, and the scheduler
assumes one worker. The "company-controlled" verdict depends on `COMPANY_EMAIL_DOMAINS`: consumer domains are
refused, and a personal mailbox is recorded as `personal_provider_substitute` (my first live `.env` listed
`gmail.com`, which would have laundered it). If the mail relay is down, notifications wait or become `uncertain`; this is shown, not hidden.

**Not completed, and blockers.**
- The company test environment was not provided (raised with the company). I created throwaway substitutes: a
  test brand, a Gmail mailbox, `@demo_workaccount` (created by hand) and a free Meta business portfolio. Every live
  report is labelled `CANDIDATE_PROVIDED_TEST_ENVIRONMENT`; secrets stay in my own password manager.
- The live run is in progress by hand; `reports/live/account_register.md` shows the state at its export time. A
  handle check first confirmed with placeholder evidence was reset (history kept) and redone.
- Live offboarding is blocked: there is no second real person for the temporary test role (a blocked task tracks
  it). It is shown with synthetic data.
- No company vault, Meta app token, approved proxies or mail relay. I run HashiCorp Vault 2.2.0 locally instead, with a
  least-privilege app token (`scripts/vault_check.py` passed against it), and send notifications through my own Gmail
  (app password in that vault; real deliveries on 2026-10-17). Meta and approved proxies are tested against simulated
  transports. Proxies ran for real through two operator-run local proxies to
  `https://example.com/` (failover, no fail-back, planned rotation). I refused public proxy lists: unapproved, often
  compromised, and anonymising. Challenges and rate limits are simulated. The Dockerfile was never built.

**Next-day improvements.** 1) Connect the company vault and the read-only Meta check (the edge is confirmed in the
Graph API v26.0 reference; its permission must be confirmed). 2) Approved proxies. 3) PostgreSQL with a leader lock
for the scheduler. 4) Operator SSO and MFA. 5) Redaction-checked evidence attachments. 6) CI: tests, ruff,
migration check, image build.

**AI tools used.** Claude Code (Anthropic, Claude Opus 5.5) in VS Code for the architecture and threat model; the
application, tests, migrations and documentation; debugging; and two review passes. The first found 12 defects
(`tests/test_review_regressions.py`). The second traced every requirement (`docs/requirements_traceability.md`) and
reproduced 10 defects plus several gaps, each fixed with a test that failed first (`tests/test_independent_review.py`,
`tests/test_outside_transaction_reads.py`, `tests/test_smtp_socket.py`); the worst let a person be marked offboarded
while newly found vault access was still pending. AI output was accepted only after the full suite and ruff passed,
the synthetic pipeline ran end to end, the live server answered over HTTP, and every report and log scanned clean of
every secret on this machine. I chose the scope, created the test resources and do every Instagram and Meta step by
hand.
