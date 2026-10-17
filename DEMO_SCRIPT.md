# Demo recording script (2–3 minutes)

The recording must show the real application and, where access exists, the **company-authorised test
environment**. Never show secrets on screen: no passwords, codes, backup codes or vault values. Show vault
*references* only, and keep the vault window off-camera. If something could not be done because access was
missing, show the blocker on screen and say so. Do not present synthetic data as a live walkthrough.

## Before recording (about 10 minutes)

- [ ] `python -m pytest -q` passes. Note the count for the voice-over.
- [ ] **Live run:** `.env` was created by `scripts.make_live_env` (use `--candidate-provided` if you made
      the test resources yourself). `IOM_ENV_FILE` is not set, and operators were created with
      `scripts.create_operator`.
- [ ] **Synthetic parts** (proxy demo, or the full fallback): in a second terminal, `$env:IOM_ENV_FILE=".env.demo"`,
      then `python -m scripts.seed_demo --reset`, `python -m scripts.proxy_demo` and
      `python -m scripts.export_reports`. They write to `reports/synthetic_demo/`.
- [ ] `python -m app` is running (http://127.0.0.1:8077). Two browser tabs: `/dashboard` (signed in) and
      Instagram on the test device.
- [ ] If the company did not provide the environment, say so at the start. The dashboard chip
      "resources: candidate provided test environment" shows it too.
- [ ] Terminal open in the project folder, font large, nothing sensitive in its history.

## Script

| Time | Show | Say (short) |
|---|---|---|
| 0:00–0:20 | `/health/ready`, then the Overview page: headline numbers, the account card with its 10-step progress bar, "Needs attention", and "System status" (vault, Meta, notifications, test resources) | "One company-authorised test account. Every Instagram step is a tracked human task. The chips show which integrations are real: here the vault is reference-only and Meta isn't configured, so those facts are human-confirmed." |
| 0:20–0:50 | Account page: handle suggestions ("format-checked only"); the handle-check task; then the signup task with owner, deadline and instructions; complete the handle task in the form | "Suggestions are format-checked, not availability claims; a human checks in the official app. Signup is manual: owner, 48-hour deadline, and safety rules saying never paste codes here and stop on a checkpoint." |
| 0:50–1:15 | An overdue or waiting task: reminder count, escalation; the notification table (*not delivered: no provider*). Mark the signup **failed – outcome uncertain** → the reconciliation task appears; **restart the server** (Ctrl+C, `python -m app`) → the same tasks are still there; complete reconciliation → verification task appears | "Reminders are throttled from persisted state and escalate to the supervisor. An interrupted signup is never retried blindly: a human first confirms whether the account exists. After a restart nothing is duplicated, and work resumes where it stopped." |
| 1:15–1:40 | Click **Run security audit**; open findings: severity, the three labels, remediation owner and due date; run it again → "seen 2x", no new tasks | "Missing evidence is reported as unverified, not as failure. Re-running the audit reuses the same finding and task." |
| 1:40–2:05 | Two terminals running proxy A and B (`python -m proxy --hostname 127.0.0.1 --port 8899 ...` / `--port 8900`). Run `python -m scripts.proxy_check --new-session` (bound to A), **stop A with Ctrl+C**, run `python -m scripts.proxy_check` again: 3 bounded attempts, then failover to B. Start A and run again: the session stays on B. Briefly show the challenge and rate-limit rows in `reports/synthetic_demo/proxy_demo/proxy_failover_demo.md` | "These are proxies I run myself, because no approved proxies were provided; I deliberately didn't use free public proxy lists. Preserve by default; fail over only when the proxy itself fails, and only to one that just passed a check; a recovered proxy doesn't pull the session back. Rate limits and challenges never cause a rotation, shown here in the simulation." |
| 2:05–2:30 | `reports/live/account_register.md` (run `python -m scripts.export_reports` first). Then the blocked live-offboarding task, and `reports/synthetic_demo/offboarding/*.md`: completed, pending and blocked actions (e.g. `NO_PROXY_PROVIDER_ADMIN`), the sole-admin rule | "The register shows exactly what is verified and how. Live offboarding is blocked because there is no second real person to hold the temporary test role, so this report is **synthetic**. A pending action means a task exists, not that access is gone; rotation is checked against the vault version." |
| 2:30–2:50 | `DECISION_LOG.md` blockers section | "Honest blockers: [list what access was missing]. Once it's granted, unblocking the task resumes the workflow." |

## If live access was missing

Say this at the start: *"This recording uses clearly labelled synthetic data because [vault / Meta business
/ proxies / test account] access was not available. It shows the implemented workflow, not a completed
live-account walkthrough."* Then show the account blocker, for example
`POST /api/v1/accounts/{id}/blocker {"code":"META_ACCESS_MISSING","detail":"..."}`, and how clearing it
(`DELETE .../blocker`) resumes the workflow.
