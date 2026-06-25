# Task Spec: COMPANION_DEVICE Skip Logic Removal + Decryption Flow Confirmation

## Task Metadata

| Field | Content |
|-------|---------|
| Task ID | TASK-3 |
| Related ACs | AC-3.1~AC-3.5, AC-4.1~AC-4.5 |
| Dependencies | TASK-1 completed |
| Status | Done |

## Target

Remove COMPANION_DEVICE skip condition in UnlockUserScreen() function in account_iam_callback.cpp (keep RECOVERY_KEY skip logic), confirm HandleAuthResult() executes full unlock flow for CUSTOM type (no new code needed), confirm COMPANION_DEVICE is not in CheckAllowUnlockUserStorage allowlist (does not trigger ActivateUserKey, EL2 not decrypted).

## Affected Files

| File | Change Type | Change Description |
|------|-------------|-------------------|
| services/accountmgr/src/account_iam/account_iam_callback.cpp | Modify | Remove COMPANION_DEVICE skip condition in UnlockUserScreen(): `if (authType_ == AuthType::RECOVERY_KEY || authType_ == AuthType::COMPANION_DEVICE)` → `if (authType_ == AuthType::RECOVERY_KEY)` |

## Out-of-Scope

- Do not modify DOMAIN early return logic in HandleAuthResult()
- Do not modify internal flow of UnlockAccount()
- Do not add CUSTOM type special handling branch

## Verification Method

- Source confirmation that HandleAuthResult() only does early return for DOMAIN
- Unit tests covering CUSTOM/COMPANION_DEVICE decryption flow

## AC Verification Mapping

| AC | Verification Focus |
|----|---------------------|
| AC-3.1 | ActivateUserKey() is called after CUSTOM auth success |
| AC-3.2 | UnlockUserScreen() is called after CUSTOM auth success (not skipped) |
| AC-3.3 | isVerified/isLoggedIn set to true after CUSTOM auth success |
| AC-3.4 | Retry 20 times × 100ms on decryption failure, return error on all retries failed |
| AC-3.5 | No decryption executed when account is deactivating |
| AC-4.1 | ActivateUserKey() is NOT called after COMPANION_DEVICE auth success (EL2 not decrypted) |
| AC-4.2 | UnlockUserScreen() is called after COMPANION_DEVICE auth success (not skipped) |
| AC-4.3 | isVerified/isLoggedIn set to true after COMPANION_DEVICE auth success |
| AC-4.4 | Retry 20 times × 100ms on decryption failure, return error on all retries failed |
| AC-4.5 | No decryption executed when account is deactivating |