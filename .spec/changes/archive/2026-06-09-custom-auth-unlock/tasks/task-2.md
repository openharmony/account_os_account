# Task Spec: NAPI/Taihe Parameter Parsing

## Task Metadata

| Field | Content |
|-------|---------|
| Task ID | TASK-2 |
| Related ACs | AC-2.1, AC-2.2, AC-2.3 |
| Dependencies | TASK-1 completed |
| Status | Done |

## Target

Add additionalInfo parsing logic in NAPI layer ParseContextForAuthOptions function (using GetOptionalStringPropertyByKey), add CUSTOM = 128 enum value and AuthOptions.additionalInfo Optional<String> field in Taihe IDL, and update ConvertToAuthOptionsInner() function in Taihe impl to support additionalInfo conversion.

## Affected Files

| File | Change Type | Change Description |
|------|-------------|-------------------|
| interfaces/kits/napi/account_iam/src/napi_account_iam_user_auth.cpp | Modify | ParseContextForAuthOptions adds additionalInfo parsing |
| frameworks/ets/taihe/os_account/idl/ohos.account.osAccount.taihe | Modify | AuthType adds CUSTOM = 128, AuthOptions adds additionalInfo Optional<String> |
| frameworks/ets/taihe/os_account/src/ohos.account.osAccount.impl.cpp | Modify | ConvertToAuthOptionsInner() adds additionalInfo conversion |

## Out-of-Scope

- Do not modify InnerKit data structures (TASK-1 responsible)
- Do not modify service layer auth flow (TASK-3 responsible)
- Do not modify AuthUser method in account_iam_service.cpp (TASK-1 already covers IPC serialization)

## Verification Method

- Compile pass
- Unit tests covering additionalInfo passing (with value / without value / undefined three scenarios)

## AC Verification Mapping

| AC | Verification Focus |
|----|---------------------|
| AC-2.1 | ParseContextForAuthOptions correctly passes additionalInfo when it has a value |
| AC-2.2 | ParseContextForAuthOptions uses default value when additionalInfo is missing |
| AC-2.3 | NAPI layer treats undefined additionalInfo as not provided |