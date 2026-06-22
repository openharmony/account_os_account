# Task Spec: Fuzz Test Updates

## Task Metadata

| Field | Content |
|-------|---------|
| Task ID | TASK-5 |
| Related ACs | VM-1~VM-7 |
| Dependencies | TASK-4 completed |
| Status | Done |

## Target

Update auth_fuzzer.cpp and authuser_fuzzer.cpp, add additionalInfo fuzz test data generation and CUSTOM auth type coverage.

## Affected Files

| File | Change Type | Change Description |
|------|-------------|-------------------|
| test/fuzztest/auth_fuzzer.cpp | Modify | Add additionalInfo fuzz test data generation |
| test/fuzztest/authuser_fuzzer.cpp | Modify | Add CUSTOM auth type coverage |

## Out-of-Scope

- Do not add new Fuzz test entry points (only modify existing ones)
- Do not write unit tests (TASK-4 responsible)

## Verification Method

- Fuzz tests compile and can run