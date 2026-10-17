# Evidence pack

| Folder | What it is |
|---|---|
| `live/` | Reports from the live run on the real Instagram test account, created with the live `.env`. Every file says where the test resources came from: `COMPANY_TEST_ENVIRONMENT`, or `CANDIDATE_PROVIDED_TEST_ENVIRONMENT` when the company did not supply them and the candidate created throwaway substitutes. **Currently:** the account register (state at its export time), the redacted run log, `audit/` (the scheduled weekly run, two manual runs and CLI runs; the first three pre-date a labelling fix, see README section 22), `proxy/` (8 real checks through operator-run proxies: bounded retries, failover, no fail-back, planned rotation) and `vault/` (checks of the candidate-run HashiCorp Vault with the app's own token; statuses only). There is no live offboarding report: the live test is blocked (no second real person). |
| `synthetic_demo/` | **SYNTHETIC** reports from `seed_demo`, `proxy_demo` and `export_reports` run with `IOM_ENV_FILE=.env.demo`. They use synthetic personas, a simulated clock, a dev-only vault with `SYNTHETIC-*` values, and local stand-in proxies. They show the mechanics and are **not** live-account verification. |

Files in each folder:

| File | What it shows |
|---|---|
| `account_register.json` / `.md` / `.csv` | The account register: status, owner, masked contacts, recovery and 2FA facts with verification labels, vault references (never values), people and roles, step evidence, blockers, provisioning gaps |
| `audit/audit_report_<ts>_<run>.*` | One report per audit run |
| `audit/audit_report_latest.*` | The latest run with current finding and remediation states |
| `offboarding/offboarding_report_<case>.*` | Completed / pending / blocked actions, owners, evidence, labels, outstanding risks |
| `run_log_redacted.jsonl` | Structured, redacted run log (correlation ids, events, retries, outcomes, verification sources) |
| `proxy_demo/proxy_failover_demo.*` (synthetic only) | SIMULATED proxy health, bounded retries, failover, rate-limit and challenge handling, with a redacted transition log and a credential-leak check |
| `proxy/proxy_check_<ts>.json` (live only) | Real health checks, bounded retries, failover and session affinity through the operator-run proxies to `https://example.com/` |

The synthetic pack was scanned for every known synthetic secret (vault values, operator tokens, the
signing key): 0 occurrences. On 2026-10-17 all of `reports/` and `logs/` was re-scanned for every secret on
the developer's machine (both `APP_SECRET_KEY`s, all operator tokens, the synthetic vault values) and for
token formats: 0 occurrences.
