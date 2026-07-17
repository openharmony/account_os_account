# Specify Stage Review Record

> Corresponds to the Stage 2 (Specify) review of the 4-stage model.

## Review Metadata

| Item | Content |
|----|------|
| Stage | Specify |
| Related documents | `design.md` / `epic.md` / `proposal.md` |
| Complexity | Complex |
| Review date | 2026-07-03 |
| Reviewer | Account Team |

## Entry Check

| Check item | Conclusion | Evidence |
|--------|------|------|
| Parallel output anchor: API change item list in proposal.md filled in | PASS | proposal.md §III API change item list: 14 items |
| Parallel output anchor: repos/modules referenced in design.md match the impact scope in proposal.md | PASS | design.md call-chain layering analysis matches proposal.md impact scope of 18 files |
| Context retrieval log created | PASS | proposal.md §II K-1~K-15, 15 retrieval records |
| Context conclusions annotated with confidence | PASS | All "high" confidence |
| Multi-repo/component ownership/API impact confirmed | PASS | Single-repo change, all API impacts confirmed via source code analysis |

## Design Check

| Check item | Conclusion | Evidence |
|--------|------|------|
| Layered call compliance (application→framework→service→kernel) | PASS | design.md 3 capability call chains all top-down; InnerDomainAuthCallback→InnerAccountIAMManager is a cross-module same-layer call via public API |
| No cross-layer violation calls (except SA proxy) | PASS | All calls follow InnerKit→Framework→IDL→Service→InnerManager→Adapter→Plugin direction |
| Subsystem boundaries clear, dependencies declared | PASS | All changes within the account subsystem; epic.md declares 3 external dependencies (plugin .so, StorageManager, UserAccessCtrlClient) |
| API naming and parameters conform to OH conventions | PASS | Follows existing naming patterns (SetDomainAuthUnlockEnabled, AuthUserWithUnlockOptions, GetUnlockDeviceConfig) |
| Error codes do not conflict with existing subsystem | PASS | Reuses existing error codes (ERR_DOMAIN_ACCOUNT_SERVICE_NOT_DOMAIN_ACCOUNT, ERR_DOMAIN_ACCOUNT_NOT_SUPPORT, etc.) |
| Data model definition complete | PASS | PluginAuthResultInfo (+secret), DomainAuthResult (+secret), DomainAccountUnlockOptions (new), PluginUnlockDeviceConfigResult (new), UnlockDeviceMode (new) all defined |
| Build system impact assessed (BUILD.gn / bundle.json) | PASS | design.md §build system impact: no changes required |
| For IPC/async calls, timeout behavior defined | PASS | Storage operations reuse existing 20×100ms retry; plugin async calls reuse existing CancelAuth mechanism |
| For InnerAPI changes, interface parameter specs filled in | PASS | design.md §interface parameter specs: 6 parameter constraints defined |

## Consistency Check (design.md vs proposal.md cross-validation)

| Check item | Conclusion | Evidence |
|--------|------|------|
| Involved repo and module names consistent | PASS | design.md call chains match proposal.md impact scope of 18 files |
| API names and change types consistent | PASS | SetDomainAuthUnlockEnabled (new), AuthUser signature change, DomainAccountUnlockOptions (new struct), GetUnlockDeviceConfig (internal method), AuthUserWithUnlockOptions (IDL) — design.md and proposal.md are consistent |
| Architecture constraints not contradictory | PASS | ADR-1~ADR-6 are consistent with proposal.md decision 1/decision 2 |
| Not-applicable item conclusions consistent | PASS | Performance/build/i18n/data migration all marked N/A; security/compatibility/API/IPC marked "involved" with design conclusions |

## Spec Check

> spec.md has been produced (one per 3 Features). Below are the Spec check results.

| Check item | Conclusion | Evidence |
|--------|------|------|
| User stories and ACs complete | PASS | F1: 4 US + 10 AC; F2: 4 US + 16 AC; F3: 2 US + 13 AC; total 10 US + 39 AC |
| ACs cover normal/abnormal/boundary | PASS | Normal/abnormal/boundary/security types all covered; F3 contains 4 Gherkin scenarios |
| No InnerKit interface definitions/internal implementation in spec | WARN | Specs reference internal class names (InnerDomainAuthCallback, InnerAccountIAMManager, etc.), but this feature is an InnerAPI with behavior at the service layer; referencing internal class names is to ensure AC testability. Acceptable |
| API change analysis complete | PASS | F1: 7 new + 4 changed; F2: 3 new; F3: 4 new + 4 changed; all include parameter summary, return value, error codes, open scope |
| Compatibility declaration complete | PASS | All 3 specs have compatibility declarations (existing API behavior change/config/data/minimum version) |
| Non-functional requirements have metrics or explicit N/A | PASS | Security (zeroing/permission/entry restriction), reliability (retry), performance (async), diagnostics (logging) |
| Global feature impact screened | PASS | All 3 specs have global feature impact tables (accessibility/multi-user/version upgrade, etc.) |
| Context references complete | PASS | All 3 specs have context-references |
| Cross-Feature consistency | PASS | F3 references F1 interface 22 times, F2 interface 11 times; API names/change types/architecture constraints are consistent |
| proposal AC mapping | PASS | proposal 29 AC → spec 39 AC (F1 adds 10 infrastructure ACs supporting proposal ACs, finer granularity) |
| Placeholder check | PASS | No TODO/TBD/to-be-supplemented (minimum supported version TBD references manifest, acceptable) |

### Outstanding Issue Handling Status

| # | Outstanding issue | Handling status |
|---|----------|----------|
| 7 | sequence-diagrams.md does not exist | Not blocking — design.md exception propagation sequence diagram is embedded inline; sequence-diagrams.md can be added later |
| 8 | design.md risk title is ambiguous | Not blocking — does not affect implementation |
| 9 | AuthUserWithUnlockOptions permission check | ✅ Resolved — F3 spec architecture constraint explicitly uses `ACCESS_USER_AUTH_INTERNAL` |
| 10 | DomainAccountUnlockOptions IDL sequenceable | ✅ Resolved — F3 spec architecture constraint explicitly requires declaring `sequenceable` |
| 11 | spec.md not yet produced | ✅ Resolved — 3 Feature spec.md produced |

## Issues Found

### Fixed (synchronously fixed during this review)

| # | Issue | Fix content |
|---|------|----------|
| 1 | epic.md affected subsystem references old solution "AuthUserWithUnlockIntent" | Updated to "AuthUser signature change + AuthUserWithUnlockOptions IDL" |
| 2 | epic.md F1 change scope missing DomainAccountUnlockOptions | Added domain_account_common.h new DomainAccountUnlockOptions |
| 3 | epic.md F2 change scope includes domain_account_client GetUnlockDeviceConfig | Removed (GetUnlockDeviceConfig is an internal method, not on DomainAccountClient) |
| 4 | epic.md F3 change scope references "AuthUserWithUnlockIntent" method/IDL | Updated to "AuthUser signature change" + "AuthUserWithUnlockOptions" IDL |
| 5 | epic.md API change overview count wrong (3 InnerKit APIs) | Corrected to 2 InnerKit APIs + 1 internal method + 1 new struct |
| 6 | epic.md IDL method name wrong "AuthUserWithUnlockIntent" | Corrected to "AuthUserWithUnlockOptions" |

### Outstanding issues (not blocking this review, recorded for later handling)

| # | Issue | Severity | Handling approach |
|---|------|--------|----------|
| 7 | `sequence-diagrams.md` does not exist but design.md references it | Medium | Need to recreate or embed sequence diagrams in spec.md |
| 8 | design.md risk table line 410 title "AuthWithUnlockIntent IDL parameter design" is ambiguous | Low | IDL method name is AuthUserWithUnlockOptions, risk title should be corrected |
| 9 | DomainAccountManagerService::AuthUserWithUnlockOptions permission check not explicit | Medium | Should use ACCESS_USER_AUTH_INTERNAL (consistent with existing methods), to be added in spec.md |
| 10 | DomainAccountUnlockOptions needs sequenceable declaration in IDomainAccount.idl | Medium | IDL needs new sequenceable declaration, to be added in spec.md |
| 11 | spec.md not yet produced | - | Expand per Feature; start after this review passes |

## Exit Check

| Check item | Conclusion | Evidence |
|--------|------|------|
| design.md design review passed | PASS | 6 ADRs + 3 call chains + 12 Tasks + exception propagation + resource ownership + concurrency model all complete |
| epic.md Feature decomposition reasonable | PASS | F1/F2/F3 decomposition + dependencies + milestones + API overview (fixed) |
| design.md and proposal.md consistency | PASS | API names/change types/architecture constraints/not-applicable items all consistent |
| design.md status updated | PASS | Draft → Reviewing → Approved (updated after this review) |

## Overall Conclusion

| Item | Content |
|----|------|
| Decision | Approved |
| Next stage | Implement — produce execution-plan.md + task.md + code |
| Recheck Scope | N/A |
| Review comments | None |

**Review summary:**
- Conclusion: pass
- design.md: 6 ADRs + 3 call chains + 12 Tasks + exception propagation + resource ownership + concurrency model all complete
- epic.md: F1/F2/F3 decomposition + dependencies + milestones + API overview (fixed 6 old-solution references)
- spec.md: 3 Feature specs produced, 10 US + 39 AC, cross-Feature consistent, no placeholders
- Outstanding issues: 2 non-blocking (sequence-diagrams.md missing, risk title ambiguous), 3 resolved (permission check, IDL sequenceable, spec.md production)
- Acceptable risk: Specs reference internal class names (InnerAPI feature, to ensure AC testability)

---

**Approver:** Account Team　**Date:** 2026-07-03
