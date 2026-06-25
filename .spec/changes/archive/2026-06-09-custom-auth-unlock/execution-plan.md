# Execution Plan

> Multi-task orchestration and handover information.

## Plan Metadata

| Field | Content |
|-------|---------|
| Related Requirement | proposal.md |
| Related Design | design.md |
| Related Spec | spec.md |
| Complexity | Standard |
| Status | Done |

## Handover Information

| Item | Value |
|------|-------|
| Upstream artifacts | proposal.md (Approved) + design.md (Approved) + spec.md (Approved) |
| Core constraints | Layered calling compliance; HandleAuthResult only DOMAIN early return; COMPANION_DEVICE only remove UnlockUserScreen skip logic (EL3/EL4 decryption), does not trigger ActivateUserKey (EL2 not decrypted) |
| Out-of-scope items | Performance/Build/Internationalization/Data Migration |
| External dependencies | UserIam framework needs to support CUSTOM auth type first (not in this spec scope); SDK d.ts type declarations in interface_sdk-js external repo (PR: https://gitcode.com/openharmony/interface_sdk-js/pull/33557) |

## Task Orchestration

| Task ID | Target | Affected Files | Dependencies | AC Coverage |
|---------|--------|---------------|--------------|-------------|
| TASK-1 | Type definitions + AuthTypeIndex mapping + IPC serialization | account_iam_info.h, account_iam_client.cpp | None | AC-1.1, AC-1.2, AC-1.3 |
| TASK-2 | NAPI/Taihe parameter parsing | napi_account_iam_user_auth.cpp, napi_account_iam_common.h, ohos.account.osAccount.taihe, ohos.account.osAccount.impl.cpp | TASK-1 | AC-2.1, AC-2.2, AC-2.3 |
| TASK-3 | COMPANION_DEVICE skip logic removal (only UnlockUserScreen) + decryption flow confirmation | account_iam_callback.cpp | TASK-1 | AC-3.1~AC-3.5, AC-4.1~AC-4.5 |
| TASK-4 | Unit tests | test/ directory | TASK-1~3 | Full AC coverage |
| TASK-5 | Fuzz test updates | fuzz/ directory | TASK-4 | VM-1~VM-7 |

## Execution Order

```
TASK-1 → TASK-2 (parallel with TASK-3) → TASK-4 → TASK-5
```

## Verification Commands

```bash
# Unit tests
./start.sh run -p rk3568 -t UT -tp os_account -ts OsAccountIAMTest

# Fuzz tests
./start.sh run -p rk3568 -t UT -tp os_account -ts AccountIAMFuzzTest
```