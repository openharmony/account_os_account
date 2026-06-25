# Task Spec: Type Definitions + AuthTypeIndex Mapping + IPC Serialization

## Task Metadata

| Field | Content |
|-------|---------|
| Task ID | TASK-1 |
| Related ACs | AC-1.1, AC-1.2, AC-1.3 |
| Dependencies | design.md + spec.md Approved |
| Status | Done |

## Target

Add AuthType.CUSTOM = 128 and AuthTypeIndex.CUSTOM = 7 in the type definition layer, extend AuthOptions struct with additionalInfo and hasAdditionalInfo fields, extend AuthParam IPC serialization to support additionalInfo passing, and add CUSTOM branch mapping in GetAuthTypeIndex().

## Affected Files

| File | Change Type | Change Description |
|------|-------------|-------------------|
| interfaces/innerkits/account_iam/native/include/account_iam_info.h | Modify | Add CUSTOM = 128 to AuthType enum, add CUSTOM = 7 to AuthTypeIndex, add additionalInfo/hasAdditionalInfo to AuthOptions |
| interfaces/kits/napi/account_iam/include/napi_account_iam_common.h | Modify | Add CUSTOM = 128 to NAPI AuthType mapping |
| services/accountmgr/src/account_iam/account_iam_client.cpp | Modify | Add case AuthType::CUSTOM_AUTH in GetAuthTypeIndex() |
| services/accountmgr/src/common/database/account_iam_info.cpp (Marshalling/Unmarshalling) | Modify | AuthParam serialization extension for additionalInfo |

## Out-of-Scope

- Do not modify HandleAuthResult() or UnlockAccount() flow
- Do not modify NAPI parameter parsing logic (TASK-2 responsible)
- Do not modify Taihe IDL/impl (TASK-2 responsible)

## Verification Method

- Compile pass
- Unit tests covering new enum values and IPC serialization

## AC Verification Mapping

| AC | Verification Focus |
|----|---------------------|
| AC-1.1 | AuthType.CUSTOM = 128 enum value exists and GetAuthTypeIndex(CUSTOM) returns 7 |
| AC-1.2 | CUSTOM type is recognizable in availability check flow |
| AC-1.3 | AuthType.CUSTOM and AuthOptions.additionalInfo type declarations complete in d.ts |