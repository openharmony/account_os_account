---
id: domain-account-unlock
type: feature
title: "Use domain account information to perform device unlock"
spec_schema: ohos-sdd/v1
profile: none
target_release:
  id: TBD
  name: TBD
  label: TBD
  release_note: ""
  status: proposed
  source: requirement
  decided_by: "Account Team"
  decided_at: 2026-07-03
release_change_log:
  - from: TBD
    to: TBD
    reason: Initial draft, target release version to be confirmed
    decided_by: "Account Team"
    decided_at: 2026-07-03
complexity: complex
lineage: new-on-legacy
status: archived
owner: "Account Team"
source_issue: ""
created_at: 2026-07-03
updated_at: 2026-07-17
related_features: []
related_bugs: []
related_tasks: []
related_decisions: []
code_refs: []
commits: []
baseline_approval:
  approved: true
  approver: "Account Team (requirement owner/owner self-confirmation)"
  evidence: "2026-07-03 After Q-12~Q-15 changes, re-confirmed baseline pass: GetUnlockDeviceConfig not exposed externally; modifying AuthUser signature replaces standalone method; new DomainAccountUnlockOptions; unlock restricted to AccountIAMClient entry trigger only. 15 clarification items all closed, 29 ACs complete and testable"
---
