# Security audit report - aud_f67a60ca114c49b797391fdb1376bf0e

Run: 2026-10-16T10:46:58+00:00 -> 2026-10-16T10:46:58+00:00 | trigger: manual | status: completed | key: -  
Data classification: **SYNTHETIC_DEMO_DATA**

> Contains explicitly synthetic records created by scripts/seed_demo.py. Synthetic results are NOT live-account verification.
> Vault: development-only in-memory vault holding synthetic secrets - not the company vault.
> Meta: integration not configured - business association is human-confirmed.
> Notifications: no provider configured - reminders/escalations were queued and shown on the dashboard but NOT delivered.

Verification labels: **integration_verified** = Read directly from the authoritative system (configured integration, or this application's own records where it is the system of record).; **human_confirmed** = Attested by a named, authorised human with an evidence reference; not machine-verified.; **unverified** = No adequate evidence either way. Missing evidence is not proof of failure.

Totals: 1 account(s); findings new 1, re-detected (deduplicated) 1, resolved 0.

## Open findings

| Severity | Check | Verification | Description | Evidence | Remediation task | Owner | Task status | Due |
|---|---|---|---|---|---|---|---|---|
| high | outstanding_security_offboarding_actions | integration_verified | 4 offboarding action(s) outstanding (1 blocked) | system-of-record:offboarding_actions | tsk_efb66ae0fd684c98b010e8fbbb62d720 | Morgan Lee (SYNTHETIC security lead) | pending | 2026-10-17T07:46:58+00:00 |
| low | two_factor_enabled | human_confirmed | Two-factor authentication uses SMS (SIM-swap risk); prefer an authenticator app or security key | 2FA enabled in Accounts Center; codes saved straight to vault [SYNTHETIC] | tsk_0f33e12514884b0e9674192144d5cf3f | Sam Rivera (SYNTHETIC account owner) | pending | 2026-10-24T18:46:58+00:00 |

## Resolved in this run

_None._

## Check results by account

### Lumen Lab Test Brand (SYNTHETIC) (@lumenlabtestbrand) [SYNTHETIC]

| Check | Outcome | Verification | Severity | Description | Evidence |
|---|---|---|---|---|---|
| recovery_email_company_controlled | pass | human_confirmed |  | Recovery email confirmed company-controlled | Accounts Center personal details checked on company device [SYNTHETIC] |
| recovery_phone_company_controlled | pass | human_confirmed |  | Recovery phone confirmed company-controlled | Accounts Center personal details checked on company device [SYNTHETIC] |
| two_factor_enabled | finding | human_confirmed | low | Two-factor authentication uses SMS (SIM-swap risk); prefer an authenticator app or security key | 2FA enabled in Accounts Center; codes saved straight to vault [SYNTHETIC] |
| backup_codes_in_vault | pass | integration_verified |  | Vault entry for backup codes exists | devvault://instagram/lumen-lab/backup-codes (vault-metadata:v2) |
| required_vault_references | pass | integration_verified |  | Required vault references present: password |  |
| meta_business_association | pass | human_confirmed |  | Meta business association human-confirmed (Meta integration not configured) | account listed under Business settings > Instagram accounts [SYNTHETIC] |
| people_roles_match_register | pass | human_confirmed |  | Register roles match the approved register (platform-side roles human-confirmed; no Meta role integration) |  |
| access_records_fresh | pass | human_confirmed |  | All 3 active access record(s) verified within 30 days |  |
| provisioning_tasks_complete | pass | integration_verified |  | All provisioning steps complete | system-of-record:account_steps |
| outstanding_security_offboarding_actions | finding | integration_verified | high | 4 offboarding action(s) outstanding (1 blocked) | system-of-record:offboarding_actions |

## Unresolved issues

- [high] 4 offboarding action(s) outstanding (1 blocked) - remediation task pending
- [low] Two-factor authentication uses SMS (SIM-swap risk); prefer an authenticator app or security key - remediation task pending
