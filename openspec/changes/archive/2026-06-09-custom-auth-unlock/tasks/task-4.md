# Task Spec: Unit Tests

## Task Metadata

| Field | Content |
|-------|---------|
| Task ID | TASK-4 |
| Related ACs | Full AC coverage |
| Dependencies | TASK-1~3 completed |
| Status | Done |

## Target

Write unit tests covering all ACs: additionalInfo data structures, NAPI parameter parsing (with value / without value / undefined), Taihe parameter conversion, AuthType.CUSTOM availability check, GetAuthTypeIndex(CUSTOM) mapping, CUSTOM/COMPANION_DEVICE auth success decryption flow, unlock failure retry logic, account deactivating state.

## Affected Files

| File | Change Type | Change Description |
|------|-------------|-------------------|
| services/accountmgr/test/unittest/ | New | additionalInfo data structure tests |
| services/accountmgr/test/unittest/ | New | NAPI parameter parsing tests |
| services/accountmgr/test/unittest/ | New | Taihe parameter conversion tests |
| services/accountmgr/test/unittest/ | New | CUSTOM/COMPANION_DEVICE decryption flow tests |

## Out-of-Scope

- Do not write Fuzz tests (TASK-5 responsible)
- Do not write integration tests (requires joint debugging environment)

## Verification Method

- All unit tests PASS

## AC Verification Mapping

Full coverage of all 16 ACs with unit test verification.