# Offboarding report - Jordan Patel (SYNTHETIC departing tester)

Case off_0b936b1c4aac4ba69ac9ad93be0ac7e6 | status: **open** | opened 2026-10-16T07:46:58+00:00 | reason: SYNTHETIC test team member leaving the project  
Replacement admin: - | reconciliations run: 5  
Data classification: **SYNTHETIC_DEMO_DATA**

> Contains explicitly synthetic records created by scripts/seed_demo.py. Synthetic results are NOT live-account verification.
> Vault: development-only in-memory vault holding synthetic secrets - not the company vault.
> Meta: integration not configured - business association is human-confirmed.
> Notifications: no provider configured - reminders/escalations were queued and shown on the dashboard but NOT delivered.

A pending action means a task exists; it does NOT mean access has been removed.

## Completed (6)

| Action | Description | Owner | Verification | Evidence | Completed |
|---|---|---|---|---|---|
| revoke_app_access | Revoke this application's API tokens and dashboard sessions for the person | system (this application) | integration_verified | ops-manager:api_credentials revoked=1 active_remaining=0 | 2026-10-16T07:46:58+00:00 |
| identify_roles | Identify every registered role and permission the person holds | system (this application) | human_confirmed | register:account_assignments | 2026-10-16T07:46:58+00:00 |
| remove_account_role | Remove Jordan Patel (SYNTHETIC departing tester)'s temporary_test_role on meta_business for Lumen Lab Test Brand (SYNTHETIC) | Sam Rivera (SYNTHETIC account owner) | human_confirmed | People list no longer shows the departing tester [SYNTHETIC] | 2026-10-16T09:46:58+00:00 |
| identify_credentials | Identify every vault entry (credential) the person could access | system (this application) | human_confirmed | register:credential_access | 2026-10-16T07:46:58+00:00 |
| remove_vault_access | Remove Jordan Patel (SYNTHETIC departing tester)'s access to vault entry devvault://instagram/lumen-lab/backup-codes | Morgan Lee (SYNTHETIC security lead) | human_confirmed | removed from vault group instagram-lumen-codes [SYNTHETIC] | 2026-10-16T09:46:58+00:00 |
| replace_backup_codes | Replace possibly exposed backup codes (Lumen Lab Test Brand (SYNTHETIC)) | Sam Rivera (SYNTHETIC account owner) | integration_verified | vault-metadata:devvault://instagram/lumen-lab/backup-codes v1->v2; new backup codes generated; old set invalidated [SYNTHETIC] | 2026-10-16T09:46:58+00:00 |

## Pending (3)

| Action | Description | Owner | Task | Task status | Due |
|---|---|---|---|---|---|
| remove_vault_access | Remove Jordan Patel (SYNTHETIC departing tester)'s access to vault entry devvault://proxies/approved-proxy-a | Morgan Lee (SYNTHETIC security lead) | tsk_efb66ae0fd684c98b010e8fbbb62d720 | pending | 2026-10-17T07:46:58+00:00 |
| verify_access_state | Verify on Meta Business Suite, Instagram and the vault that no access remains | - | waiting on 2 prerequisite action(s) | - | - |
| update_register | Mark the person offboarded in the personnel records and the account register | system (this application) | waiting on prerequisites | - | - |

## Blocked (1)

| Action | Description | Responsible owner | Blocker | Detail |
|---|---|---|---|---|
| rotate_credential | Rotate proxy_credential the person could access (shared infrastructure) | Morgan Lee (SYNTHETIC security lead) | NO_PROXY_PROVIDER_ADMIN | Nobody holds the proxy_provider_admin responsibility and this system cannot rotate provider credentials; assign a provider administrator. |

## Outstanding risks

- Jordan Patel (SYNTHETIC departing tester) may still be able to read vault entry devvault://proxies/approved-proxy-a [pending]
- Credential devvault://proxies/approved-proxy-a may still be known to Jordan Patel (SYNTHETIC departing tester) until rotated [blocked]
- No independent verification of the final access state yet [pending]
