# Account register

Generated: 2026-10-17T05:47:11.694733+00:00  
Data classification: **SYNTHETIC_DEMO_DATA**

> Contains explicitly synthetic records created by scripts/seed_demo.py. Synthetic results are NOT live-account verification.
> Vault: development-only in-memory vault holding synthetic secrets - not the company vault.
> Meta: integration not configured - business association is human-confirmed.
> Notifications: no provider configured - reminders/escalations were queued and shown on the dashboard but NOT delivered.

## Lumen Lab Test Brand (SYNTHETIC) (@lumenlabtestbrand) - provisioned

| Field | Value | Verification |
|---|---|---|
| Account ID | acc_d24c3d54a0ef4488a8064ee13004b8e9 |  |
| Synthetic record | True |  |
| Owner | Sam Rivera (SYNTHETIC account owner) |  |
| Company email | IT-REQ-4821 (i***@testco.example) |  |
| Company phone | TEL-0042 (+**********23) - company_controlled |  |
| Recovery email | company_controlled | human_confirmed |
| Recovery phone | company_controlled | human_confirmed |
| Two-factor | enabled via sms | human_confirmed |
| Backup codes | present_in_vault @ devvault://instagram/lumen-lab/backup-codes | integration_verified |
| Password | devvault://instagram/lumen-lab/password | integration_verified |
| Other vault refs | - |  |
| Profile | Lumen Lab Test Brand / bio 95/150 / Product/service |  |
| Business account | converted |  |
| Meta business | linked (biz-synthetic-0001) | human_confirmed |
| Blocker | - |  |
| Last verified | 2026-10-16T06:46:58+00:00 | integration_verified |

### Provisioning steps

| Step | State | Verification | Evidence | Completed |
|---|---|---|---|---|
| handle_selected | completed | human_confirmed | searched handle in official app; not taken [SYNTHETIC] | 2026-10-08T06:46:58+00:00 |
| company_email | completed | human_confirmed | IT ticket IT-REQ-4821 fulfilled [SYNTHETIC] | 2026-10-08T06:46:58+00:00 |
| company_phone | completed | human_confirmed | telecom inventory TEL-0042 [SYNTHETIC] | 2026-10-08T06:46:58+00:00 |
| signup | completed | human_confirmed | profile instagram.com/lumenlabtestbrand exists; Instagram welcome email in company alias inbox [SYNTHETIC] | 2026-10-10T10:46:58+00:00 |
| platform_verification | completed | human_confirmed | Accounts Center personal details checked on company device [SYNTHETIC] | 2026-10-10T16:46:58+00:00 |
| two_factor | completed | human_confirmed | 2FA enabled in Accounts Center; codes saved straight to vault [SYNTHETIC] | 2026-10-10T18:46:58+00:00 |
| profile | completed | human_confirmed | live profile compared with approved spec [SYNTHETIC] | 2026-10-11T02:46:58+00:00 |
| business_conversion | completed | human_confirmed | account type shows Business [SYNTHETIC] | 2026-10-11T02:46:58+00:00 |
| meta_link | completed | human_confirmed | account listed under Business settings > Instagram accounts [SYNTHETIC] | 2026-10-11T04:46:58+00:00 |
| roles_assigned | completed | human_confirmed | people list matches approved register [SYNTHETIC] | 2026-10-11T04:46:58+00:00 |

### People and roles

| Person | Platform | Role | Status | Temporary | Verification | Last verified |
|---|---|---|---|---|---|---|
| Sam Rivera (SYNTHETIC account owner) | meta_business | business_admin | active | False | human_confirmed | 2026-10-11T04:46:58+00:00 |
| Morgan Lee (SYNTHETIC security lead) | meta_business | business_admin | active | False | human_confirmed | 2026-10-11T04:46:58+00:00 |
| Riley Kim (SYNTHETIC content publisher) | meta_business | content_publisher | active | False | human_confirmed | 2026-10-11T04:46:58+00:00 |
| Jordan Patel (SYNTHETIC departing tester) | meta_business | temporary_test_role | removed | True | human_confirmed | 2026-10-11T04:46:58+00:00 |

### Open tasks

| Task | Owner | Status | Due | Reminders | Escalations |
|---|---|---|---|---|---|
| Enable two-factor authentication on @lumenlabtestbrand and vault the backup codes | Sam Rivera (SYNTHETIC account owner) | pending | 2026-10-24T18:46:58+00:00 | 1 | 0 |

### Provisioning gaps

_None - all steps complete and verified._
