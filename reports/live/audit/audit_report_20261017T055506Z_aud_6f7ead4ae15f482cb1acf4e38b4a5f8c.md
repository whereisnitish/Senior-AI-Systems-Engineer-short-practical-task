# Security audit report - aud_6f7ead4ae15f482cb1acf4e38b4a5f8c

Run: 2026-10-17T05:55:05.984625+00:00 -> 2026-10-17T05:55:05.990591+00:00 | trigger: manual | status: completed | key: -  
Data classification: **CANDIDATE_PROVIDED_TEST_ENVIRONMENT**

> The company test environment was not provided. The candidate created throwaway substitute resources (test brand, email, Instagram account, Meta business portfolio); they are not company-authorised resources.
> Vault: reference-only mode - vault presence is human-confirmed, not machine-verified.
> Meta: integration not configured - business association is human-confirmed.
> Notifications: no provider configured - reminders/escalations were queued and shown on the dashboard but NOT delivered.

Verification labels: **integration_verified** = Read directly from the authoritative system (configured integration, or this application's own records where it is the system of record).; **human_confirmed** = Attested by a named, authorised human with an evidence reference; not machine-verified.; **unverified** = No adequate evidence either way. Missing evidence is not proof of failure.

Totals: 1 account(s); findings new 0, re-detected (deduplicated) 1, resolved 0.

## Open findings

| Severity | Check | Verification | Description | Evidence | Remediation task | Owner | Task status | Due |
|---|---|---|---|---|---|---|---|---|
| medium | provisioning_tasks_complete | integration_verified | Provisioning incomplete (awaiting_handle_check); pending steps: handle_selected, company_email, company_phone, signup, platform_verification, two_factor, profile, business_conversion, meta_link, roles_assigned | system-of-record:account_steps | tsk_c13f0b8ed2b84bf78f8e33bbe7357560 | Candidate (account owner) | pending | 2026-10-18T05:18:43.015225+00:00 |

## Resolved in this run

_None._

## Check results by account

### demo_workaccount (@-)

| Check | Outcome | Verification | Severity | Description | Evidence |
|---|---|---|---|---|---|
| recovery_email_company_controlled | not_applicable | unverified |  | Account not yet created on Instagram |  |
| recovery_phone_company_controlled | not_applicable | unverified |  | Account not yet created on Instagram |  |
| two_factor_enabled | not_applicable | unverified |  | Account not yet created on Instagram |  |
| backup_codes_in_vault | not_applicable | unverified |  | Account not yet created on Instagram |  |
| required_vault_references | not_applicable | unverified |  | Account not yet created on Instagram |  |
| meta_business_association | not_applicable | unverified |  | Account not yet created on Instagram |  |
| people_roles_match_register | pass | human_confirmed |  | Register roles match the approved register (platform-side roles human-confirmed; no Meta role integration) |  |
| access_records_fresh | not_applicable | unverified |  | No active access records |  |
| provisioning_tasks_complete | finding | integration_verified | medium | Provisioning incomplete (awaiting_handle_check); pending steps: handle_selected, company_email, company_phone, signup, platform_verification, two_factor, profile, business_conversion, meta_link, roles_assigned | system-of-record:account_steps |
| outstanding_security_offboarding_actions | pass | integration_verified |  | No outstanding offboarding or security actions | system-of-record:tasks |

## Unresolved issues

- [medium] Provisioning incomplete (awaiting_handle_check); pending steps: handle_selected, company_email, company_phone, signup, platform_verification, two_factor, profile, business_conversion, meta_link, roles_assigned - remediation task pending
