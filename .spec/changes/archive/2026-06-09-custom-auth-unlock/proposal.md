# Requirements Document

## I. Original Requirements

### Basic Information

| Field | Content |
|-------|---------|
| Requirement ID | REQ-20260528-001 |
| Requirement Name | Custom Auth Type and Trusted Possession Auth User Space Decryption Support |
| Source | IAM module capability extension |
| Proposer | Account Team |
| Target Release | OpenHarmony-6.0-Release |
| Candidate Profile | none |
| Priority | P0 |
| Status | Draft |

### Original Description

**Original Problem:** The current IAM module supports multiple authentication types (PIN, FACE, FINGERPRINT, etc.), but lacks support for "custom authentication" methods. Custom authentication refers to users completing identity authentication through custom authentication methods (such as smart cards, security tokens, hardware keys, or other third-party authentication mechanisms), and unlocking the system upon successful authentication. Meanwhile, after COMPANION_DEVICE authentication succeeds, the current code skips user space decryption (EL3/EL4), causing trusted possession authentication to fail to fully unlock user storage space.

**Pain Points:**

| User Type | Current Pain Point | Impact |
|-----------|-------------------|--------|
| App Developer | Missing AuthType.CUSTOM authentication type, unable to integrate custom authentication plugins | Cannot support smart card/security token enterprise authentication scenarios |
| System Developer | AuthOptions does not support passing custom authentication additional information | Custom authentication plugins cannot receive external parameters |
| End User | EL3/EL4 not decrypted after COMPANION_DEVICE auth success | Trusted possession (e.g., smart watch) authentication cannot unlock EL3/EL4 (EL2 also not decrypted) |

**Expected Result:** Support AuthType.CUSTOM = 128 authentication type and AuthOptions.additionalInfo parameter; after CUSTOM auth success, fully decrypt user space (EL2-EL5); after COMPANION_DEVICE auth success, decrypt EL3/EL4 (excluding EL2).

### Background Evidence

| Evidence Type | Link/Path | Description |
|--------------|-----------|-------------|
| Source analysis | account_iam_callback.cpp | Current UnlockUserScreen() skips COMPANION_DEVICE, HandleAuthResult() only skips DOMAIN |
| Source analysis | account_iam_info.h | AuthType/AuthTypeIndex/IAMAuthType enum definitions |
| Source analysis | napi_account_iam_user_auth.cpp | NAPI layer parameter parsing logic |

### Initial Scope

**Possibly included:**
- AuthType.CUSTOM = 128 enum value
- AuthOptions.additionalInfo optional field
- NAPI/Taihe layer parameter parsing extension
- User space decryption after CUSTOM auth success (EL2-EL5)
- Remove COMPANION_DEVICE skip logic in UnlockUserScreen after auth success (EL3/EL4 decryption, EL2 not decrypted)

**Explicitly excluded:**
- UserIam framework side CUSTOM auth type support (implemented independently by UserIam team)
- Specific custom authentication plugin logic (provided by external plugins)
- Credential management (AddCredential/UpdateCredential) changes
- DOMAIN auth type behavior changes

### Initial Assumptions

| Assumption | Type | Verification Method | Status |
|------------|------|---------------------|--------|
| UserIam framework already supports AuthType.CUSTOM = 128 | Technical | Source confirmation | Verified |
| HandleAuthResult() only does early return for DOMAIN type, CUSTOM naturally enters unlock flow | Technical | Source analysis of account_iam_callback.cpp | Verified |
| COMPANION_DEVICE skip logic is in UnlockUserScreen() | Technical | Source analysis of account_iam_callback.cpp:256 | Verified |
| additionalInfo using simple string can meet initial needs | Technical | Solution evaluation | Verified |

### Initial Classification

| Classification Item | Result | Basis |
|--------------------|--------|-------|
| Complexity | Standard | Single-repo multi-module feature, involves NAPI/service layer/type declarations, has new API |
| Number of affected repos | 1 (os_account) | All changes within this repo |
| Involves Public/System API | Yes | AuthType.CUSTOM enum addition, AuthOptions.additionalInfo field addition |
| Involves security/performance critical path | Yes | User space decryption after auth success is a security-critical path |
| Cross-SIG | No | All changes within account subsystem |

### Entry Clarification Conditions

- [x] Original problem and expected result recorded
- [x] Requirement source and responsible person identified
- [x] Initial scope and excluded items recorded
- [x] Key assumptions and questions to clarify listed
- [x] Complexity classification made

---

## II. Clarification Record

### Questions to Clarify

| ID | Question | Why Clarification Needed | Status |
|----|----------|--------------------------|--------|
| Q-1 | Is AuthType.CUSTOM enum value confirmed as 128? | Need to confirm consistency with existing enum style and no conflicts | Clarified — 128 is a power of 2, consistent with existing style, no conflict with DOMAIN=1024 |
| Q-2 | Should additionalInfo data type use string? | Type choice affects NAPI parsing complexity and extensibility | Clarified — string type is sufficiently flexible, can pass JSON-formatted structured data |
| Q-3 | Does CUSTOM auth have the same security level as PIN? | Security level determines decryption privilege after auth success | Clarified — Same level as PIN, can fully unlock user space |
| Q-4 | Should COMPANION_DEVICE also have full decryption privilege? | Current code skips EL3/EL4 decryption | Clarified — Same security level as PIN, need to remove UnlockUserScreen skip logic; but COMPANION_DEVICE is not in CheckAllowUnlockUserStorage allowlist, does not trigger ActivateUserKey (EL2 not decrypted) |
| Q-5 | Does HandleAuthResult() need new CUSTOM special handling code? | Determines implementation complexity | Clarified — No new code needed, existing logic automatically supports this |

### Discussion Record

| Date | Participants | Discussion Topic | Conclusion | Follow-up Action |
|------|-------------|-----------------|------------|-----------------|
| 2026-05-19 | Account Team | CUSTOM auth security level and decryption privilege | Same level as PIN/FACE/FINGERPRINT, with full decryption privilege | No new special handling code needed |
| 2026-05-19 | Account Team | COMPANION_DEVICE decryption behavior | Remove COMPANION_DEVICE skip logic in UnlockUserScreen() (EL3/EL4 decryption); COMPANION_DEVICE not in ActivateUserKey allowlist (EL2 not decrypted) | Only modify UnlockUserScreen conditional |
| 2026-05-19 | Account Team | additionalInfo type selection | String type, optional parameter, ensures backward compatibility | NAPI layer uses GetOptionalStringPropertyByKey for parsing |

### Functional Scope Confirmation

| Question | Answer | Confirmed By | Status |
|----------|--------|-------------|--------|
| What are the core features? | AuthType.CUSTOM + AuthOptions.additionalInfo + CUSTOM/COMPANION_DEVICE user space decryption | Account Team | Confirmed |
| What is explicitly excluded? | UserIam framework CUSTOM support, auth plugin logic, credential management changes, DOMAIN behavior changes | Account Team | Confirmed |
| Is there a phased delivery strategy? | No phasing, one-time delivery | Account Team | Confirmed |

### Solution Exploration

| ID | Solution Overview | Advantages | Risks/Costs | Selection Conclusion |
|----|-------------------|-----------|-------------|---------------------|
| A-1 | Add explicit branch handling for CUSTOM in HandleAuthResult() | Logic is explicit and clear | Code redundancy, inconsistent with existing flow, increased maintenance cost | Abandoned |
| A-2 | Rely on existing HandleAuthResult() logic (only DOMAIN early return), CUSTOM naturally enters unlock flow | Zero new code, reuses existing logic, consistent with PIN/FACE flow | Need to confirm DOMAIN is the only skipped type | Recommended |

**Trade-off Reasoning:** Solution A-2 has zero new code, full reuse of existing unlock flow, consistent behavior with PIN/FACE/FINGERPRINT, and is the minimal implementation.

### Subsystem Impact

| Question | Answer | Confirmed By | Status |
|----------|--------|-------------|--------|
| Which subsystems are involved? | account (os_account repo) | Account Team | Confirmed |
| Are new subsystems or components needed? | No | Account Team | Confirmed |

### API Change Assessment

| Question | Answer | Confirmed By | Status |
|----------|--------|-------------|--------|
| Are new/modified Public APIs needed? | Yes — AuthType.CUSTOM enum value, AuthOptions.additionalInfo optional field | Account Team | Confirmed |
| Are new System APIs needed? | No | Account Team | Confirmed |
| Will existing APIs be deprecated? | No | Account Team | Confirmed |
| Are new permission declarations needed? | No | Account Team | Confirmed |

### Compatibility and Non-Functional Requirements

| Category | Core Question | Conclusion | Confirmed By | Status |
|----------|--------------|------------|-------------|--------|
| Compatibility | Forward/backward compatibility requirements? | All new fields are optional, backward compatible; no breaking changes | Account Team | Confirmed |
| Performance | No new time-consuming paths | N/A | Account Team | Confirmed |
| Security | Decryption privilege after auth success | CUSTOM same level as PIN (EL2-EL5); COMPANION_DEVICE only EL3/EL4 decryption (EL2 not decrypted) | Account Team | Confirmed |
| Reliability | Decryption failure retry | Reuse existing 20 times × 100ms retry mechanism | Account Team | Confirmed |

### Dependencies and Risks

| Dependency | Type | Description | Status |
|------------|------|-------------|--------|
| useriam/user_auth_framework | Runtime | UserIam framework needs to support CUSTOM auth type first (not in this spec scope) | Confirmed |
| storage_service | Runtime | User space decryption depends on StorageManager's ActivateUserKey and UnlockUserScreen | Confirmed |

| Risk | Type | Impact | Mitigation | Status |
|------|------|--------|------------|--------|
| UserIam framework does not support CUSTOM type | External | High | Need UserIam framework to add support on their side | Confirmed |
| Removing COMPANION_DEVICE skip logic may affect RECOVERY_KEY | Technical | Low | Only remove COMPANION_DEVICE condition, keep RECOVERY_KEY skip logic | Confirmed |
| CUSTOM auth decryption failure causing user space inaccessible | Technical | Medium | Reuse existing retry mechanism (20 times × 100ms), return clear error on failure | Confirmed |
| additionalInfo string format not standardized | Technical | Low | Documentation recommends JSON format | Confirmed |

### AC Completeness

- [x] Each user story has acceptance criteria
- [x] All ACs use WHEN/THEN format
- [x] Covers normal flow, exception flow, and boundary conditions
- [x] ACs are testable and measurable

### Clarification Conclusion

- [x] Functional scope fully defined
- [x] Subsystem impact identified
- [x] API changes assessed
- [x] Compatibility and non-functional requirements confirmed
- [x] Dependencies and risks identified with mitigation plans
- [x] ACs are complete and testable
- [x] Standard or above complexity has completed solution exploration

**Conclusion:** Passed

---

## III. Requirements Baseline

### Baseline Information

| Field | Content |
|-------|---------|
| Baseline Version | v1.0 |
| Baseline Date | 2026-05-28 |
| Owner | Account Team |
| Confirmed By | Account Team |
| Complexity | Standard |
| Profile | none |
| Target Release | OpenHarmony-6.0-Release |
| Version Status | proposed |

### Problem Statement

The current IAM module lacks support for custom authentication type (CUSTOM), and after COMPANION_DEVICE authentication succeeds, the EL3/EL4 decryption step is skipped, causing trusted possession authentication to fail to fully unlock user storage space. It is necessary to add CUSTOM = 128 to the AuthType enum, extend AuthOptions to support the additionalInfo parameter, and ensure CUSTOM and COMPANION_DEVICE authentication success executes the complete user space decryption flow (EL2-EL5).

### Goals and Success Metrics

| Goal | Success Metric | Verification Method |
|------|---------------|---------------------|
| Support CUSTOM auth type | UserAuth.auth() accepts authType = 128 and executes normally | Unit test + Integration test |
| Support additionalInfo parameter | AuthOptions.additionalInfo can be correctly passed to auth flow | Unit test |
| Unlock EL2-EL5 after CUSTOM auth success | ActivateUserKey + UnlockUserScreen called normally | Unit test |
| Unlock EL3/EL4 (excluding EL2) after COMPANION_DEVICE auth success | After removing skip logic, UnlockUserScreen called normally (EL2 not decrypted) | Unit test |

### User Stories and ACs

| Story ID | User Story | Priority |
|----------|-----------|----------|
| US-1 | As an app developer, I want to use AuthType.CUSTOM for authentication, so that I can integrate custom authentication plugins | P0 |
| US-2 | As an app developer, I want to pass additional information through AuthOptions.additionalInfo, so that custom authentication plugins can receive external parameters | P0 |
| US-3 | As an end user, I want the user space to be fully unlocked after CUSTOM auth success, so that I can have an unlock experience consistent with PIN auth | P0 |
| US-4 | As an end user, I want EL3/EL4 (excluding EL2) to be unlocked after COMPANION_DEVICE auth success, so that trusted possession auth can unlock screen-encrypted storage | P0 |

| AC ID | Acceptance Criteria | Type | Related Story |
|-------|---------------------|------|---------------|
| AC-1.1 | WHEN app calls UserAuth.auth() with authType = 128 (CUSTOM) THEN system should accept auth type and enter custom auth flow | Normal | US-1 |
| AC-1.2 | WHEN app calls UserAuth.getAvailableStatus() with authType = 128 (CUSTOM) THEN system should return availability status of custom auth capability | Normal | US-1 |
| AC-1.3 | WHEN TypeScript app imports osAccount module THEN compiler should recognize AuthType.CUSTOM and AuthOptions.additionalInfo as valid types | Normal | US-1 |
| AC-2.1 | WHEN app calls UserAuth.auth() with options.additionalInfo set THEN auth flow should receive provided additional information | Normal | US-2 |
| AC-2.2 | WHEN app calls UserAuth.auth() without options.additionalInfo set THEN auth flow should proceed normally without depending on additional info | Normal | US-2 |
| AC-2.3 | WHEN NAPI layer receives additionalInfo as undefined THEN should treat as not provided, use default value | Boundary | US-2 |
| AC-3.1 | WHEN CUSTOM auth succeeds and token and secret are valid THEN system should call ActivateUserKey() to activate user keys and decrypt EL2 | Normal | US-3 |
| AC-3.2 | WHEN CUSTOM auth succeeds and screen is locked THEN system should call UnlockUserScreen() to decrypt EL3/EL4 | Normal | US-3 |
| AC-3.3 | WHEN CUSTOM auth succeeds with user space unlock THEN system should set isVerified and isLoggedIn to true | Normal | US-3 |
| AC-3.4 | WHEN CUSTOM auth succeeds but ActivateUserKey() or UnlockUserScreen() fails THEN system should retry up to 20 times (100ms interval); on all retries failed, return error and do not set verified/logged-in status | Exception | US-3 |
| AC-3.5 | WHEN CUSTOM auth succeeds but target account is in deactivating state THEN system should not execute user space decryption and return auth result | Boundary | US-3 |
| AC-4.1 | WHEN COMPANION_DEVICE auth succeeds and token and secret are valid THEN system should NOT call ActivateUserKey(); EL2 storage not decrypted | Boundary | US-4 |
| AC-4.2 | WHEN COMPANION_DEVICE auth succeeds and screen is locked THEN system should call UnlockUserScreen() to decrypt EL3/EL4 | Normal | US-4 |
| AC-4.3 | WHEN COMPANION_DEVICE auth succeeds with user space unlock THEN system should set isVerified and isLoggedIn to true | Normal | US-4 |
| AC-4.4 | WHEN COMPANION_DEVICE auth succeeds but decryption operation fails THEN system should retry up to 20 times (100ms interval); on all retries failed, return error and do not set verified/logged-in status | Exception | US-4 |
| AC-4.5 | WHEN COMPANION_DEVICE auth succeeds but target account is in deactivating state THEN system should not execute user space decryption and return auth result | Boundary | US-4 |

### Scope Boundary

**Included:** AuthType.CUSTOM = 128, AuthOptions.additionalInfo optional field, NAPI/Taihe parameter parsing, user space decryption after CUSTOM auth success (EL2-EL5), COMPANION_DEVICE UnlockUserScreen skip logic removal (EL3/EL4 decryption, EL2 not decrypted)

**Excluded:** UserIam framework CUSTOM type support, custom authentication plugin logic, credential management changes, DOMAIN auth behavior changes

### Impact Scope

| Subsystem | Repo | Module/Path | Current Responsibility | Impact Type | Owner |
|-----------|------|-------------|----------------------|-------------|-------|
| account | os_account | frameworks/account_iam | NAPI parameter parsing | Modify | Account Team |
| account | os_account | frameworks/ets/taihe | Taihe static NAPI | Modify | Account Team |
| account | os_account | interfaces/innerkits/account_iam | InnerAPI data structures | Modify | Account Team |
| account | os_account | services/accountmgr/src/account_iam | Auth flow processing | Modify | Account Team |
| account | os_account | interfaces/kits/napi | NAPI type declarations | Modify | Account Team |

### API Change Item List

| API Name | Change Type | Scope | Summary Description |
|----------|-------------|-------|---------------------|
| AuthType.CUSTOM (= 128) | New enum value | Public | Custom authentication type enum value |
| AuthOptions.additionalInfo | New optional field | Public | Custom authentication additional info parameter |

### Out-of-Scope Items Confirmation

| Dimension | Involved? | Basis | If Involved, Which Downstream Document |
|-----------|-----------|-------|---------------------------------------|
| Performance | No | No new time-consuming paths, reuse existing flow | N/A |
| Security & Permissions | Yes | Decryption privilege after auth success is security-critical path | design.md / spec.md |
| Compatibility | Yes | New optional fields, need to declare compatibility impact | spec.md |
| API/SDK | Yes | New Public API enum value and optional field | design.md / spec.md |
| IPC/Cross-process | Yes | AuthParam serialization needs to extend additionalInfo | design.md |
| Build & Components | No | No new source files or components | N/A |
| Internationalization/Accessibility | No | No UI-related changes | N/A |
| Data Migration | No | No storage format changes | N/A |

### Change Control

| Change Type | Trigger Condition | Handling Rule |
|-------------|-------------------|---------------|
| Scope addition | New auth type or decryption flow added | Re-evaluate security level and design impact |
| AC change | Modify observable behavior or error codes | Re-approve baseline and Spec |
| API change | Add/modify Public API | Trigger design approval |
| Non-functional metric change | Security threshold changes | Re-confirm test plan |

### Entry to Design/Spec Conditions

- [x] All P0/P1 user stories have ACs
- [x] Each AC is testable and measurable
- [x] In-scope/out-of-scope confirmed
- [x] manifest.target_release confirmed
- [x] manifest.profile confirmed (none)
- [x] Affected repos, modules, SIGs identified
- [x] Out-of-scope items marked as N/A
- [x] Change control rules confirmed

**Baseline Conclusion:** Passed