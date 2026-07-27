# OS Account Management - Agent Instruction Guide

> Scope: **subsystem** `base/account/os_account` (System Ability 200, `accountmgr`).
> Target: any coding agent (Claude Code, Codex, Copilot) working in this repo.
> Language: C++17. Build: GN + Ninja. IPC: OpenHarmony IPC/SAMGR.

---

## 0. Quick Index

### By task type
| Task | Read first |
|---|---|
| Locate a feature | §1.4 Where to Look table → §1.3 Nested AGENTS.md routing table |
| Understand a mechanism | §2.1–2.2 vocabulary/path routing → matching nested AGENTS.md §1–3 |
| Verify whether a risk holds | §3.4 Pitfalls (incl. CE checklists) → §2.3 pre-edit protocol |
| Modify code | §5 Verification Loop → §3.1 Do-not → §3.4 Pitfall |

### By pitfall (quick lookup)
| Risk | Pitfall | CE checklist | Key function (grep to locate) |
|---|---|---|---|
| SA startup blocking | P1 | CE6 | AccountMgrService::Init |
| Data consistency | P2 | — | Transaction-related functions |
| Sensitive-data clearing | P3 | — | memset_s / std::fill |
| errno clobbered by HILOG | P4 | — | errno save point |
| First-user path | P5 | CE6 | CreateBaseStandardAccount / ActivateDefaultOsAccount |
| Slow operation inside lock | P6 | CE6 | Functions doing I/O/IPC while holding lock_guard/unique_lock |
| Verify state not propagated | P7 | CE7 | UnlockUserStorage / SetOsAccountIsVerified / preVerified |
| Slow recovery while holding lock | P8 | CE8 | HandleFileKeyException / try_lock |
| OTA dirty-data loop | P9 | CE9 | GetDomainAccountInfo / accountName_.empty() |
| GetOsAccountType loop | P10 | CE10 | GetOsAccountType / GetOsAccountInfoById |

### Non-greppable information (unique value of AGENTS.md)
The following information **cannot be obtained via code grep** and must be sourced from this file:
- Constraint file names (base/global/specific_os_account_constraints.json) — the constant names are in os_account_constants.h, but "which is which" needs this file
- DVID algorithm parameters (PBKDF2_HMAC-SHA256, iter=1000, keylen=32) — the GenerateDVID function body has them, but "this is DVID" needs this file
- Pitfall mapping (which function has loop risk / slow-in-lock) — code does not self-label "I have risk"
- EL2/EL3/EL4 level definitions — code has StorageManager calls but "EL2=user key / EL3=screen lock" needs this file
- Standard call chain vs real code divergence (e.g. DVID is generated on the query path, not the login path) — code is readable but "the standard chain is wrong" needs this file

---

## 1. Code Map

### 1.1 Responsibility

The OS Account subsystem (SA 200) manages account lifecycle, authentication, and
distributed account data storage for OpenHarmony. It exposes **public NAPI/C APIs**
to applications and **internal C++ inner APIs** to other system abilities.

### 1.2 Key Paths Quick Reference

(Use `codegraph_files` or `ls` for the full tree on demand; below are high-frequency modification paths.)

- `services/accountmgr/src/<type>/` — service logic (osaccount / appaccount / domain_account / account_iam); `account_mgr_service.cpp` is the SA 200 entry, HIGH-RISK
- `frameworks/<type>/native/` — per-account-type framework implementation
- `interfaces/innerkits/<type>/native/include/` — internal C++ API (inter-SA, compatibility-sensitive)
- `interfaces/kits/{napi,capi,cj}/` — public external API (do-not-break)
- `os_account.gni` (feature flags) / `dfx/` (HiDumper·HiSysEvent·HiTrace) / `sa_profile/accountmgr.json` (SA profile) / `tools/acm/` (CLI) / `.refdocs/` (architecture/dev guide/FAQ)

### 1.3 Nested AGENTS.md (read these first when working in the module)

Each module-level `AGENTS.md` contains component breakdowns, data structures,
lock hierarchies, and interaction flows. **Always read the matching file before
editing that module.**

| If working in… | Read this first |
|----------------|-----------------|
| `services/accountmgr/src/osaccount/` | [services/accountmgr/src/osaccount/AGENTS.md](services/accountmgr/src/osaccount/AGENTS.md) — OsAccountManagerService, IInnerOsAccountManager, constraints, lifecycle state machine |
| `services/accountmgr/src/appaccount/` | [services/accountmgr/src/appaccount/AGENTS.md](services/accountmgr/src/appaccount/AGENTS.md) — AppAccountControlManager, authenticator sessions, UID-based locking, OAuth |
| `services/accountmgr/src/distributed_account/` | [services/accountmgr/src/distributed_account/AGENTS.md](services/accountmgr/src/distributed_account/AGENTS.md) — OhosAccountManager, DVID generation, anonymization, JSON schema |
| `services/accountmgr/src/account_iam/` | [services/accountmgr/src/account_iam/AGENTS.md](services/accountmgr/src/account_iam/AGENTS.md) — credential management, EL2/EL3/EL4 unlock, IAM state machine, token validity |

### 1.4 Where to Look (task / path → primary location + read-first)

(Merges the former §1.4 task→path and §2.2 path→read-first tables.)

| Path / Task type | Primary location | Read first (also-read) |
|------------------|------------------|------------------------|
| Public API (NAPI) | `interfaces/kits/napi/` + matching `d.ts` | §3.1 Do-not; error-code docs |
| Public C API | `interfaces/kits/capi/` | §3.1 Do-not |
| Internal C++ API | `interfaces/innerkits/<type>/native/include/` | Nested AGENTS.md (contract may affect callers) |
| Service logic — osaccount | `services/accountmgr/src/osaccount/` | [osaccount/AGENTS.md](services/accountmgr/src/osaccount/AGENTS.md) |
| Service logic — appaccount | `services/accountmgr/src/appaccount/` | [appaccount/AGENTS.md](services/accountmgr/src/appaccount/AGENTS.md) |
| Service logic — distributed_account | `services/accountmgr/src/distributed_account/` | [distributed_account/AGENTS.md](services/accountmgr/src/distributed_account/AGENTS.md) |
| Service logic — account_iam | `services/accountmgr/src/account_iam/` | [account_iam/AGENTS.md](services/accountmgr/src/account_iam/AGENTS.md) |
| Framework logic | `frameworks/<type>/native/` | Per-type framework dirs |
| Feature flag / build | `os_account.gni` | §1.6 (flag affects whole subsystem) |
| Unit/module test | `services/accountmgr/test/` or `test/{unittest,moduletest}/` | `*_test.cpp` / `*_moduletest.cpp` |
| Fuzz test | `test/fuzztest/` | `*_fuzztest.cpp` |
| SA profile | `sa_profile/accountmgr.json` | §3.2 (ask before changing) |
| DFX / diagnostics | `dfx/` | HiSysEvent schema must not break consumers |
| ACM CLI | `tools/acm/` | `acm` executable |
| Persistent data | on-device `/data/service/el1/public/account/` | §4 Configuration Files |
| SA startup entry | `services/accountmgr/src/account_mgr_service.cpp` | Pitfall 1 & 5 (high-risk) |

### 1.5 Key Entry Points

| Component | File | Notes |
|-----------|------|-------|
| Service entry | `services/accountmgr/src/account_mgr_service.cpp` | SA 200 main entry; startup sequence is high-risk (see Pitfall 5) |
| OS account inner | `services/accountmgr/src/osaccount/inner_os_account_manager.cpp` | Central orchestrator; singleton; first-user creation during boot |
| App account inner | `services/accountmgr/src/appaccount/inner_app_account_manager.cpp` | Coordinator; delegates to control/session/subscribe managers |
| Distributed account | `services/accountmgr/src/ohos_account_manager.cpp` | Login/logout state machine; DVID generation |
| IAM inner | `services/accountmgr/src/account_iam/inner_account_iam_manager.cpp` | Credential lifecycle; EL2/EL3/EL4 unlock |
| Error codes | `interfaces/innerkits/common/include/account_error_no.h` | All `ERR_*` definitions |

### 1.6 Feature Flags

Defined in [os_account.gni](os_account.gni). Changing a flag alters compile-time
behavior across the entire subsystem — check impact before toggling.

| Flag | Effect when enabled |
|------|---------------------|
| `os_account_multiple_active_accounts` | Multiple active OS accounts |
| `os_account_support_deactivate_main_os_account` | Allow deactivating main OS account |
| `os_account_distributed_feature` | Distributed features (KV store); disables SQLite fallback |
| `os_account_enable_multiple_foreground_os_accounts` | Multiple foreground OS accounts |
| `os_account_enable_multiple_os_accounts` | Multiple OS accounts feature |
| `os_account_enable_default_admin_name` | Default admin account name |
| `os_account_enable_account_short_name` | Account short name |
| `os_account_activate_last_logged_in_account` | Activate last logged-in account on start |
| `os_account_support_domain_accounts` | Domain account support |
| `os_account_enable_account_1` | User 1 support |
| `os_account_support_lock_os_account` | Account lock feature |
| `os_account_support_authorization` | Authorization manager |

### 1.7 API Reference

**Internal C++ APIs** (inter-SA, compatibility-sensitive):
- [os_account_manager.h](interfaces/innerkits/osaccount/native/include/os_account_manager.h)
- [app_account_manager.h](interfaces/innerkits/appaccount/native/include/app_account_manager.h)
- [domain_account_client.h](interfaces/innerkits/domain_account/native/include/domain_account_client.h)
- [account_iam_client.h](interfaces/innerkits/account_iam/native/include/account_iam_client.h)
- [account_error_no.h](interfaces/innerkits/common/include/account_error_no.h) — error codes

**External NAPI APIs** (public, do-not-break):
- OS Account: [d.ts](https://gitcode.com/openharmony/interface_sdk-js/blob/master/api/@ohos.account.osAccount.d.ts) · [sys docs](https://gitcode.com/openharmony/docs/blob/master/en/application-dev/reference/apis-basic-services-kit/js-apis-osAccount-sys.md) · [public docs](https://gitcode.com/openharmony/docs/blob/master/en/application-dev/reference/apis-basic-services-kit/js-apis-osAccount.md)
- App Account: [d.ts](https://gitcode.com/openharmony/interface_sdk-js/blob/master/api/@ohos.account.appAccount.d.ts) · [docs](https://gitcode.com/openharmony/docs/blob/master/en/application-dev/reference/apis-basic-services-kit/js-apis-appAccount.md)
- Distributed Account: [d.ts](https://gitcode.com/openharmony/interface_sdk-js/blob/master/api/@ohos.account.distributedAccount.d.ts) · [sys docs](https://gitcode.com/openharmony/docs/blob/master/en/application-dev/reference/apis-basic-services-kit/js-apis-distributed-account-sys.md) · [public docs](https://gitcode.com/openharmony/docs/blob/master/en/application-dev/reference/apis-basic-services-kit/js-apis-distributed-account.md)
- [Error Codes](https://gitcode.com/openharmony/docs/blob/master/en/application-dev/reference/apis-basic-services-kit/errorcode-account.md)

**External C API**: [interfaces/kits/capi/](interfaces/kits/capi/) · [docs](https://gitcode.com/openharmony/docs/blob/master/en/application-dev/reference/apis-basic-services-kit/capi-osaccount.md)

---

## 2. Knowledge Routing

Read deeper docs **based on the task**, not in full every time.

### 2.1 Task-based routing

| If the task involves… | Read this first |
|----------------------|-----------------|
| Public NAPI/C API signature, error code, or lifecycle change | §3.1 Do-not; [errorcode-account.md](https://gitcode.com/openharmony/docs/blob/master/en/application-dev/reference/apis-basic-services-kit/errorcode-account.md); the matching `d.ts` |
| Layering, dependency direction, or cross-layer data flow | [.refdocs/layered_architecture.md](.refdocs/layered_architecture.md) |
| Adding a feature end-to-end (flag → API → framework → service → test) | [.refdocs/development_guide.md](.refdocs/development_guide.md) §"Adding New Features" |
| Boot / startup / first-user-creation debugging | [.refdocs/frequent_asked_questions.md](.refdocs/frequent_asked_questions.md) Q1; Pitfall 5 below |
| A specific account type (os/app/domain/iam/distributed) | The matching Nested AGENTS.md (§1.3) |
| Permission or access-token changes | Nested AGENTS.md §"Permission Model"; `access_token` dependency |
| Persistent data / on-disk JSON / KV schema | §4 Configuration Files; Nested AGENTS.md for the module's data structures |
| DFX / HiSysEvent / HiTrace changes | `dfx/` adapters; [Coding Standards](https://gitcode.com/openharmony/docs/blob/master/en/contribute/OpenHarmony-c-cpp-secure-coding-guide.md) |
| Build config / feature flag / GN target | `os_account.gni`; `BUILD.gn` in the target dir |
| Locking / concurrency / deadlock | Nested AGENTS.md §"Thread Safety" / "Lock Hierarchy" for the module |

### 2.2 Vocabulary routing

When the task, a log, an issue, or a file mentions these terms, read the
indicated source before editing:

| Term / acronym | What it means | Read |
|---------------|---------------|------|
| SA 200 / accountmgr | System Ability ID 200, the account service process | §1.1; `account_mgr_service.cpp` |
| Inner API / innerkits | C++ APIs shared between system abilities (not public) | `interfaces/innerkits/` headers |
| NAPI / CAPI / CJ | Public external API bindings (applications depend on these) | `interfaces/kits/`; §3.1 Do-not |
| OsAccount constraints | Per-account capability restrictions (e.g. `constraint.wifi.set`) | [osaccount/AGENTS.md](services/accountmgr/src/osaccount/AGENTS.md) §"Constraints & Restrictions" |
| DVID | Distributed Virtual Device ID = `PBKDF2_HMAC-SHA256(raw_uid, bundleName)` | [distributed_account/AGENTS.md](services/accountmgr/src/distributed_account/AGENTS.md) §"DVID Generation" |
| Authenticator | App extension providing authentication (OAuth) | [appaccount/AGENTS.md](services/accountmgr/src/appaccount/AGENTS.md) §"Authenticator Architecture" |
| EL1/EL2/EL3/EL4 | Encryption levels for user data (EL2=user key, EL3/EL4=screen lock) | [account_iam/AGENTS.md](services/accountmgr/src/account_iam/AGENTS.md) §"Storage Key Management" |
| KV Store / SQLite | Distributed KV (`distributeddata_inner`) or local SQLite fallback | §4 Data Storage; `os_account_distributed_feature` flag |
| `memset_s` | Secure-clear sensitive data (credentials/tokens) after use | [appaccount/AGENTS.md](services/accountmgr/src/appaccount/AGENTS.md) §"Security Considerations" |
| `OsAccountInfo` | Core struct: `localId`, `localName`, `type`, `constraints`, `isActived` | [osaccount/AGENTS.md](services/accountmgr/src/osaccount/AGENTS.md) §"Key Data Structures" |
| IAM fault flag | File marking a user needs key-context restoration after a crash | [account_iam/AGENTS.md](services/accountmgr/src/account_iam/AGENTS.md) §"IAM Fault Flag" |

### 2.3 Pre-edit protocol

Before writing any code, state in your response:
1. **Task category**: which of (public API / inner API / service logic / framework / build config / DFX / test / other).
2. **Documents read**: which nested AGENTS.md, `.refdocs/`, or external docs you loaded (per §2.1–2.2).
3. **Constraints found**: which Do-not / Ask-before rules (§3) apply to this task.

If you cannot identify the task category or relevant constraints, **ask the user
before editing**.

- **Document references are not code evidence**: citing AGENTS.md / FAQ / nested AGENTS.md sections in a final answer **does not count as code-level evidence** — it is only a knowledge-routing record. Every judgment must be backed by an independent source line number. Citing a doc section cannot replace tracing code details.
- **Do not stop at concepts**: AGENTS.md gives you the "what" (concept) and the "where" (entry point), but the "how" (code-level evidence) must be traced by you to file:line. Citing an AGENTS.md concept description is not completion — you must trace into function bodies, service-layer call sites, secondary gating, and early-return paths.
- **Do not read without verifying**: AGENTS.md references are now by function name (line numbers drift with code). You must use grep/codegraph to locate the current line number in real time; do not assume positions given in AGENTS.md are still accurate.
- **Quick-lookup → deep-trace two-step method**: first use the quick index (§0) to fast-locate relevant knowledge entries, then trace code evidence item by item against the CE checklists. Every CE checklist item is a "code detail that must be traced", not an "optional reference".

---

## 3. Constraints & Boundaries

### 3.1 Do not (without explicit user escalation)

These changes carry high risk and must not be made autonomously:

- **Public API signatures** (NAPI `d.ts`, CAPI headers, CJ bindings under
  `interfaces/kits/`): do not add/remove/rename parameters, change return types,
  or alter error-code values/semantics. Applications and the SDK depend on these.
- **Public API error codes** (`account_error_no.h` public section): do not change
  existing numeric values or meanings; only append new codes.
- **Permission checks** in `*ManagerService` classes: do not remove or weaken
  `AccountPermissionManager` / `AccessTokenKit` verification calls.
- **On-disk data schema**: do not change the JSON field names, structure, or
  version field of files in `/data/service/el1/public/account/` (see §4) —
  breaks upgrade compatibility.
- **SA startup sequence** (`account_mgr_service.cpp` Init/DelayUnload): do not
  reorder, add blocking calls, or introduce failure paths (see Pitfall 1 & 5).
- **First-user creation/activation** (`inner_os_account_manager.cpp`
  `CreateBaseStandardAccount` / `ActivateDefaultOsAccount`): do not change this
  flow — affects device boot (see Pitfall 5).
- **Generated IPC code**: IDL-generated stubs/proxies (under `*_proxy.cpp`,
  `*_stub.cpp` in `interfaces/innerkits/`) are generated from `.idl` files; do
  not hand-edit generated files — change the `.idl` and regenerate.
- **Feature flags** (`os_account.gni`): do not toggle a flag without checking
  compile impact across the entire subsystem.
- **HiSysEvent definitions** (`dfx/hisysevent_adapter/`): do not change event
  names, param names, or domains — existing consumers and fault attribution
  depend on them.

### 3.2 Ask before

Ask the user for confirmation before:
- Running ACM commands that mutate device state (`acm create`, `acm switch`,
  `acm remove`) on a non-test device.
- Changing `sa_profile/accountmgr.json` (SA registration config).
- Adding a new third-party dependency or changing `BUILD.gn` deps direction
  (layering — see `.refdocs/layered_architecture.md`).
- Changing the distributed-data backend (KV Store ↔ SQLite) or its
  conditional-compile flag.
- Modifying anything in the SA startup or first-user path (Pitfall 1 & 5).

### 3.3 Architecture & layering invariants

- **Dependency direction**: Application (NAPI/CAPI/CJ) → Interface (innerkits)
  → Framework → Service → Data Storage. Never call upward.
- **Service delegates to inner manager**: `*ManagerService` (IPC stub) does
  permission check + param validation, then forwards to `IInner*Manager` /
  `Inner*Manager`. Do not put business logic in the service class.
- **Singletons**: `IInnerOsAccountManager`, `AppAccountControlManager`,
  `InnerAccountIAMManager` are singletons (`GetInstance()`). Do not create
  additional instances.
- **Optional modules**: AppAccount, DomainAccount, AccountIAM are conditional
  (see feature flags). Guard new code with the correct `#ifdef` / GN flag.

### 3.4 Project-specific pitfalls

**Pitfall 1 — Do NOT block SA initialization.**
SA startup must complete quickly. No blocking I/O, network, or heavy compute
during `Init()`. Startup operations must not fail — prepare all dependencies
before init. (`account_mgr_service.cpp`)

**Pitfall 2 — DB/file operations must be data-consistent.**
Keep database and file storage consistent; use transactions for atomicity. A
crash mid-write must not corrupt account data. (`services/accountmgr/src/common/database/`)

**Pitfall 3 — Secure storage for sensitive data, or clear after use.**
Passwords, PINs, tokens, and credentials must use encrypted storage (`asset`)
or be cleared with `memset_s()` / `std::fill(...,0)` immediately after use.
IPC marshalling may copy buffers — explicit zeroing defeats compiler
optimization. (See [appaccount/AGENTS.md](services/accountmgr/src/appaccount/AGENTS.md) §"Security Considerations")

**Pitfall 4 — Handle error codes properly; HILOG modifies `errno`.**
HILOG may alter `errno` when flow control drops log data. If you log between a
syscall and `errno` use, capture `errno` into a local variable first. Do not
rely on `errno` being stable across a HILOG call.

**Pitfall 5 — Do NOT change SA startup or first-user create/activate.**
The boot path (`account_mgr_service.cpp` startup → `CreateBaseStandardAccount`
→ `ActivateDefaultOsAccount`) is device-critical. Changes here can brick boot.
Escalate to the user before touching this path.

**Pitfall 6 — Keep work inside locks fast.**
Locks protect in-memory account lists and per-UID state. Do not perform disk
I/O, IPC, or long computations while holding a lock — risk of deadlock or IPC
thread exhaustion. Follow the lock hierarchy in each module's nested AGENTS.md.

**Code-level evidence checklist (CE6):**
- Trace lock-holding functions (e.g. `CreateOsAccount` holding `createOsAccountMutex_`) for whether they contain disk I/O (`UpdateOsAccount`/DB write), IPC (`AccountIAMClient` calls), or long compute loops.
- Confirm that `WriteOsAccountFile` / `SaveAccountList` and other persistence calls occur only after the lock is released.
- Check whether a per-UID lock calls a function that reverse-acquires the same lock or a higher-level lock (lock-hierarchy inversion).

⚠ **Common omissions**: ① only checking `lock_guard` but not `unique_lock`/`shared_lock` ② ignoring in-lock Common Event Service event-publishing IPC ③ ignoring in-lock Bundle Manager Service / Ability Manager Service IPC.

**Pitfall 7 — Verify state must be set on every unlock path, including no-password.**
After device reboot, features like screenshot, screen recording, and memo
creation depend on `OsAccountInfo.isVerified == true`. This flag is set via
`SetOsAccountIsVerified(true)` only when `isUpdateVerifiedStatus` is true
(at the `SetOsAccountIsVerified` call site in `account_iam_callback.cpp`). In
`UnlockUserStorage()` (the `UnlockUserStorage()` entry in
`inner_account_iam_manager.cpp`), `isUpdateVerifiedStatus` is set to true only
inside the `needActivateKey` branch. If the account is already marked verified
(verified branch), `needActivateKey` may stay false and the verify state is
never propagated. When adding or modifying any unlock code path, trace that
`SetOsAccountIsVerified(true)` is eventually reached — especially no-password /
auto-unlock scenarios where authentication is skipped.
  Historical: "device reboot breaks screenshot/screen-recording/memo — verify
  state not set to true during no-password unlock"

**Code-level evidence checklist (CE7):**
- Trace the internal sub-call chain of `HandleFileKeyException()`: whether `UpdateStorageUserAuth()` / `UpdateStorageKeyContext()` finally triggers `SetOsAccountIsVerified(true)`.
- Inside `SetOsAccountIsVerified()`, confirm the `preVerified` secondary gating logic — an unverified account does not short-circuit past propagation.
- Trace the `OnResult` path of `account_iam_callback`: confirm every branch either calls `SetOsAccountIsVerified(true)` or has a justified early return; specifically check whether the no-password / already-verified branch returns early and skips `SetOsAccountIsVerified`.

⚠ **Common omissions**: ① missing the `UpdateStorageUserAuth`/`UpdateStorageKeyContext` sub-calls inside `HandleFileKeyException` ② missing the `preVerified` secondary gating (`if(!preVerified && isVerified)` inside `SetOsAccountIsVerified`) ③ missing the 4 early returns in `OnResult` before `SetOsAccountIsVerified` ④ no-password scenario `secret.empty()` early return.

**Pitfall 8 — Avoid holding per-user lock during slow storage operations; use try_lock in recovery paths.**
`HandleFileKeyException()` (at the `HandleFileKeyException()` definition in
`inner_account_iam_manager.cpp`) restores key context after a crash by calling
`UpdateStorageUserAuth()` and `UpdateStorageKeyContext()` — both involve IPC
retry loops (20×100ms). Before the fix, it held the per-user lock
(`GetOperatingUserLock(userId)`) during the entire slow operation. Meanwhile,
the normal unlock path (`UnlockUserStorage()`) also calls
`HandleFileKeyException()` at entry (the `HandleFileKeyException` call at the
`UnlockUserStorage()` entry), then proceeds to `ActivateUserKey()` and
`UnlockUserScreen()`. Multiple concurrent unlock requests would block on the
per-user lock, exhausting the `accountmgr` thread pool and causing the service
to freeze (device black screen). Fix: use `try_lock()` in recovery paths that
may be slow; if the lock is held, return `ERR_ACCOUNT_COMMON_BUSY` immediately.
Also ensure `ActivateUserKey()` and `UnlockUserScreen()` properly acquire the
per-user lock via `lock_guard` to serialize storage access.
  Historical: "device black screen then recovers — accountmgr threads exhausted
  waiting on lock held by slow reenroll"

**Code-level evidence checklist (CE8):**
- At the `HandleFileKeyException()` definition, confirm the recovery path uses `try_lock()` rather than `lock()`, returning `ERR_ACCOUNT_COMMON_BUSY` when the lock is held.
- Confirm `ActivateUserKey()` / `UnlockUserScreen()` use `lock_guard` to acquire the per-user lock and serialize storage access.
- Verify that after `UnlockUserStorage()` calls `HandleFileKeyException()` at entry, it does not re-hold the lock to do slow operations.

⚠ **Common omissions**: ① only checking `try_lock` but not `lock_guard` serialization ② ignoring the thread occupancy of the 20×100ms retry loop ③ missing the `lock_guard` in `ActivateUserKey`/`UnlockUserScreen`.

**Pitfall 9 — Guard against empty/invalid data from OTA migration; prevent cross-module circular calls.**
OTA upgrades may leave dirty data from old versions (e.g. empty
`domainServerConfigId`). During boot, `QueryOsAccountById()`
(at the `QueryOsAccountById()` definition in `inner_os_account_manager.cpp`)
calls `GetDomainAccountStatus()`, which queries domain account info. If the
domain plugin query encounters empty config data and falls back to querying
`account_info` again, a circular call chain forms: query account → query
domain → query account → … — crashing or hanging boot, causing repeated reboot
loops. Fix patterns: (1) Add empty/null guards at every cross-module query entry
point (e.g. `GetDomainAccountInfo()` checks `accountName_.empty()` before
invoking the plugin, at the `accountName_.empty()` check site in
`GetDomainAccountInfo()`). (2) Provide a synchronous overload of cross-module
query APIs to avoid callback re-entrancy. (3) Always null-check callbacks
before invoking them (e.g. `CallbackOnResult()` helper wrapping
`callback->OnResult()`). When adding cross-module calls, explicitly verify no
circular dependency exists in the call graph.
  Historical: "OTA → device repeatedly reboots — empty domainServerConfigId
  triggered circular account_info query"

**Code-level evidence checklist (CE9):**
- At the `GetDomainAccountInfo()` entry, confirm the `accountName_.empty()` / `domainServerConfigId.empty()` null guard — on empty it returns directly without triggering the plugin query.
- Confirm cross-module query APIs have a synchronous overload to avoid the account→domain→account loop caused by callback re-entrancy.
- Trace whether the `CallbackOnResult()` wrapper null-checks before calling `callback->OnResult()`.

⚠ **Common omissions**: ① missing the `accountName_.empty()` null guard ② missing the `CallbackOnResult` null-pointer check ③ not distinguishing sync vs async overload callback re-entrancy risk.

**Pitfall 10 — `GetOsAccountType()` must not call `GetOsAccountInfoById()` — self-referencing circular call.**
`GetOsAccountType()` (at the `GetOsAccountType()` definition in
`inner_os_account_manager.cpp`) needs the account type. Calling
`GetOsAccountInfoById()` to obtain it forms a circular chain:
`GetOsAccountType` → `GetOsAccountInfoById` → `QueryOsAccountById` →
`GetDomainAccountStatus` → (potentially back to `GetOsAccountType`). On
emulator builds without TEE hardware this is especially dangerous because the
software fallback path hits the same circular dependency. Fix: read the account
type from an independent data source — TEE hardware
(`teeAdapter_.GetOsAccountType()`), a type-only cache
(`osAccountCacheManager_`), or a direct DB read that bypasses the full
`QueryOsAccountById` flow. Never use `GetOsAccountInfoById` inside
`GetOsAccountType` or any function called by `GetOsAccountType`.
  Historical: "emulator won't boot — GetOsAccountType → GetOsAccountInfoById
  circular call"

**Code-level evidence checklist (CE10):**
- Distinguish the two same-named methods: `IInnerOsAccountManager::GetOsAccountInfoById()` (goes through the full `QueryOsAccountById` flow, has loop risk) vs `OsAccountControlFileManager::GetOsAccountInfoById()` (direct file read, safe).
- At the `GetOsAccountType()` definition, confirm the type source is `teeAdapter_.GetOsAccountType()` / `osAccountCacheManager_` / direct DB read, not `IInnerOsAccountManager::GetOsAccountInfoById()`.
- Trace all callees of `GetOsAccountType` and confirm none can reach `GetOsAccountType` again via `QueryOsAccountById`.

⚠ **Common omissions**: ① not distinguishing `IInnerOsAccountManager::GetOsAccountInfoById` (full `QueryOsAccountById` flow, loop risk) vs `OsAccountControlFileManager::GetOsAccountInfoById` (direct file read, safe) ② missing the emulator no-TEE software fallback path.

---

## 4. Data Storage & Configuration

### 4.1 Storage backends

- **KV Store** (`distributeddata_inner`): distributed key-value storage (when
  `os_account_distributed_feature` is enabled).
- **SQLite** (fallback): local database when distributed feature is disabled.
  Adapter: `services/accountmgr/src/common/database/`.
- **File Storage**: JSON files in `/data/service/el1/public/account/`.
- **Asset storage** (`asset`, optional): high-sensitivity data (credentials,
  tokens) — `HAS_ASSET_PART` flag.

### 4.2 Configuration files on device

Located at `/data/service/el1/public/account/`. **Do not change these schemas
without upgrade-compatibility handling** (see §3.1).

| File | Purpose |
|------|---------|
| `account_info_digest.json` | Restore digest data for configs |
| `account_list.json` | Restore account base info |
| `base_os_account_constraints.json` | Restore base account constraints |
| `global_os_account_constraints.json` | Restore global account constraints |
| `specific_os_account_constraints.json` | Restore specific account constraints |
| `{userId}\account.json` | Restore base info for distributed account |
| `{userId}\account_avatar` | Restore avatar for distributed accounts |
| `{userId}\account_info.json` | Restore base info for current OS account |

See [distributed_account/AGENTS.md](services/accountmgr/src/distributed_account/AGENTS.md)
for the distributed-account JSON schema (version, bind_time, user_id, etc.).

---

## 5. Verification Loop

### 5.1 Minimum checks (always)

Run from the **OpenHarmony root directory** (the repo that contains `build.sh`):

```bash
# 1. Build the service (fastest sanity check)
./build.sh --product-name rk3568 --build-target accountmgr

# 2. Build + run tests for the changed area
./build.sh --product-name rk3568 --build-target os_account account_build_unittest account_build_moduletest
```

Common products: `rk3568`, `hi3516`, `ohos-sdk`.

### 5.2 Task-specific validation

| If you changed… | Also run / check |
|----------------|-----------------|
| `interfaces/kits/` (public API) | API-diff / compatibility check; confirm no signature or error-code change leaked into the SDK. **Escalate to user if any public surface changed.** |
| `interfaces/innerkits/` (inner API) | Build all callers in the subsystem; grep for the changed signature across `services/` and `frameworks/` |
| `services/accountmgr/src/*` (service logic) | Run the matching module test suite (see §5.3) |
| `os_account.gni` (feature flag) | Full build with the flag both on and off |
| `dfx/` (HiSysEvent) | Confirm event names/params unchanged; run `hidumper -s AccountMgrService` |
| Anything in SA startup path | **Do not commit without user approval** (Pitfall 5) |
| Locking / concurrency | Review lock hierarchy in nested AGENTS.md; check for new cross-lock calls |

### 5.3 Test commands

```bash
cd {OpenHarmonyRootFolder}/test/testfwk/developer_test

# Run a specific test suite
./start.sh run -p rk3568 -t UT MST -tp os_account -ts <testSuiteName>

# Run all os_account tests
./start.sh run -p rk3568 -t UT MST -tp os_account

# Run a single test case
./start.sh run -p rk3568 -t UT MST -tp os_account -ts <suite> -tc <case>
```

- Unit test naming: `*_test.cpp` → executable `*_test`
- Module test naming: `*_moduletest.cpp` → executable `*_moduletest`
- Fuzz tests: `./build.sh --product-name rk3568 --build-target account_build_fuzztest --gn-args use_thin_lto=false`

### 5.4 Build artifacts

| Artifact | Location |
|----------|----------|
| Service library | `out/{product}/account/os_account/` |
| ACM tool | `out/{product}/account/os_account/` |
| Unstripped (symbols) | `out/{product}/lib.unstripped/account/os_account` |
| Test executables | `out/{product}/tests/unittest/os_account`, `out/{product}/tests/moduletest/os_account` |

### 5.5 Done definition, escalation & fallback

- **Done**: build + relevant test suite pass, with no new compiler warnings (warnings as errors).
- **Escalate before committing** (module-specific, §3.1 / §3.2): public API surface changed / inner API signature changed / on-disk schema changed / permissions changed / SA startup or first-user path touched.
- **Final response must include**: summary, files changed, build/test status (suite name + pass/fail counts), compatibility impact (public API / inner API / schema / permissions yes/no), constraints checked.
- **Fallback**: if build/tests cannot run (no OpenHarmony root / toolchain), explicitly state the reason + ask the user to run §5.1–5.3 and return the output; **must not** claim verified/done.

---

## 6. Diagnostics

### 6.1 Log domain

- **Domain**: `0xD001B00` · **Tag**: `accountmgr` (varies per module)
```bash
hdc shell "hilog | grep -i C01B00"
```

### 6.2 HiDumper

```bash
hidumper -s AccountMgrService
```

### 6.3 HiSysEvent

```bash
hdc shell "hisysevent -l -o ACCOUNT"        # list current events
hdc shell "hisysevent -r -o ACCOUNT"        # recursive new events
```

### 6.4 Boot/startup debugging

See [.refdocs/frequent_asked_questions.md](.refdocs/frequent_asked_questions.md) Q1:
check `ps -ef | grep accountmgr`, hilog `C01B00`, faultlog, and first-user
creation (`CreateBaseStandardAccount` / `ActivateDefaultOsAccount` in
`inner_os_account_manager.cpp`).

---

## 7. Tools — ACM (Account Command Manager)

CLI tool at [tools/acm/](tools/acm/), executable `acm`. Runs in `hdc shell`.

```bash
acm dump -a                    # List OS accounts (read-only, safe)
acm create -n <name> -t normal  # Create account — MUTATES DEVICE STATE
acm switch -i <accountId>       # Activate account — MUTATES DEVICE STATE
```

> **Warning**: `acm create` / `switch` / `remove` change real device state.
> Ask the user before running on a non-test device (§3.2).

---

## 8. Coding Standards

Follow the official OpenHarmony [C Coding Style Guide](https://gitcode.com/openharmony/docs/blob/master/en/contribute/OpenHarmony-c-coding-style-guide.md) and [C/C++ Secure Coding Guide](https://gitcode.com/openharmony/docs/blob/master/en/contribute/OpenHarmony-c-cpp-secure-coding-guide.md) (change history in `git log`).
