# Security audit report - aud_8406bdde03e14127b3be3f557623f6dd

Run: 2026-10-17T09:50:58.221710+00:00 -> 2026-10-17T09:50:58.259606+00:00 | trigger: manual | status: completed | key: -  
Data classification: **CANDIDATE_PROVIDED_TEST_ENVIRONMENT**

> The company test environment was not provided. The candidate created throwaway substitute resources (test brand, email, Instagram account, Meta business portfolio); they are not company-authorised resources.
> Vault: a candidate-run HashiCorp Vault (not the company vault), KV v2. Presence and versions of vault:// references are machine-verified; the application token may not read Instagram secret values. References to other password managers stay human-confirmed.
> Meta: integration not configured - business association is human-confirmed.

Verification labels: **integration_verified** = Read directly from the authoritative system (configured integration, or this application's own records where it is the system of record).; **human_confirmed** = Attested by a named, authorised human with an evidence reference; not machine-verified.; **unverified** = No adequate evidence either way. Missing evidence is not proof of failure.

Totals: 1 account(s); findings new 0, re-detected (deduplicated) 1, resolved 0.

## Open findings

| Severity | Check | Verification | Description | Evidence | Remediation task | Owner | Task status | Due |
|---|---|---|---|---|---|---|---|---|
| medium | provisioning_tasks_complete | integration_verified | Provisioning incomplete (awaiting_signup); pending steps: signup, platform_verification, two_factor, profile, business_conversion, meta_link, roles_assigned | system-of-record:account_steps | tsk_1835fe6fc095431892915ec8dd0612f1 | Candidate (account owner) | pending | 2026-10-19T09:49:24.581721+00:00 |

## Resolved in this run

_None._

## Check results by account

### demo_workaccount (@demo_workaccount)

| Check | Outcome | Verification | Severity | Description | Evidence |
|---|---|---|---|---|---|
| recovery_email_company_controlled | not_applicable | unverified |  | Account not yet created on Instagram |  |
| recovery_phone_company_controlled | not_applicable | unverified |  | Account not yet created on Instagram |  |
| two_factor_enabled | not_applicable | unverified |  | Account not yet created on Instagram |  |
| backup_codes_in_vault | not_applicable | unverified |  | Account not yet created on Instagram |  |
| required_vault_references | not_applicable | unverified |  | Account not yet created on Instagram |  |
| meta_business_association | not_applicable | unverified |  | Account not yet created on Instagram |  |
| people_roles_match_register | not_applicable | unverified |  | No role has been granted or confirmed yet (1 approved assignment(s) requested; granting them is a provisioning task). Nothing to compare. |  |
| access_records_fresh | not_applicable | unverified |  | No active access records |  |
| provisioning_tasks_complete | finding | integration_verified | medium | Provisioning incomplete (awaiting_signup); pending steps: signup, platform_verification, two_factor, profile, business_conversion, meta_link, roles_assigned | system-of-record:account_steps |
| outstanding_security_offboarding_actions | pass | integration_verified |  | No outstanding offboarding or security actions | system-of-record:tasks |

## Unresolved issues

- [medium] Provisioning incomplete (awaiting_signup); pending steps: signup, platform_verification, two_factor, profile, business_conversion, meta_link, roles_assigned - remediation task pending
