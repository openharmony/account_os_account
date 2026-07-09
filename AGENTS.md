# OS Account Management - Agent Instruction Guide

> Scope: **subsystem** `base/account/os_account` (System Ability 200, `accountmgr`).
> Target: any coding agent (Claude Code, Codex, Copilot) working in this repo.
> Language: C++17. Build: GN + Ninja. IPC: OpenHarmony IPC/SAMGR.

---

## 1. Code Map

### 1.1 Responsibility

The OS Account subsystem (SA 200) manages account lifecycle, authentication, and
distributed account data storage for OpenHarmony. It exposes **public NAPI/C APIs**
to applications and **internal C++ inner APIs** to other system abilities.

### 1.2 Directory Structure

```
os_account/
├── frameworks/                # Framework implementations per account type
│   ├── osaccount/             #   OS account framework
│   ├── appaccount/            #   App account framework
│   ├── domain_account/        #   Domain account framework
│   ├── account_iam/           #   Identity and authentication framework
│   ├── ohosaccount/           #   Distributed account framework
│   ├── authorization/         #   Authorization framework (optional)
│   ├── common/                #   Shared utilities (log, json, database, error)
│   ├── ets/                   #   Static native APIs (ArkTS)
│   └── cj/                    #   CJ (FFI) bindings
├── services/accountmgr/       # Main service (SA 200) — HIGH-RISK, frequently modified
│   ├── src/
│   │   ├── osaccount/         #   OS account service logic
│   │   ├── appaccount/        #   App account service logic
│   │   ├── domain_account/    #   Domain account service logic
│   │   ├── account_iam/       #   IAM service logic
│   │   └── ohos_account_manager.cpp  # Distributed account manager
│   ├── include/               #   Internal headers
│   ├── test/                  #   Unit & module tests
│   └── *.json                 #   SA config files
├── interfaces/
│   ├── innerkits/             # Internal C++ APIs (inter-SA) — compatibility-sensitive
│   │   ├── osaccount/native/
│   │   ├── appaccount/native/
│   │   ├── domain_account/native/
│   │   ├── account_iam/native/
│   │   └── common/            #   Shared interfaces + error codes
│   └── kits/                  # External APIs (NAPI, C API, CJ) — PUBLIC API, do-not-break
│       ├── napi/              #   Node.js API (JS/TS)
│       ├── capi/              #   C API
│       └── cj/                #   CJ (FFI) bindings
├── sa_profile/                # SA profile (accountmgr.json)
├── tools/acm/                 # ACM CLI tool
├── dfx/                       # HiDumper / HiSysEvent / HiTrace adapters
├── test/                      # unittest / moduletest / fuzztest / systemtest
├── .refdocs/                  # Deep-dive docs (architecture, dev guide, FAQ)
└── os_account.gni             # Global build + feature-flag config
```

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

### 1.4 Where to Look (task → path)

| Task type | Primary path | Key files |
|-----------|-------------|-----------|
| Add/change a **public API** (NAPI) | `interfaces/kits/napi/` | `@ohos.account.osAccount.d.ts`, `appAccount.d.ts`, `distributedAccount.d.ts` |
| Add/change a **public C API** | `interfaces/kits/capi/` | CAPI headers + `capi-osaccount.md` docs |
| Add/change an **internal C++ API** | `interfaces/innerkits/<type>/native/include/` | `os_account_manager.h`, `app_account_manager.h`, `domain_account_client.h`, `account_iam_client.h` |
| Implement **service logic** | `services/accountmgr/src/<type>/` | See Nested AGENTS.md above |
| Implement **framework logic** | `frameworks/<type>/native/` | Per-type framework dirs |
| Add/modify a **feature flag** | `os_account.gni` | Feature flags table below |
| Add a **unit/module test** | `services/accountmgr/test/` or `test/unittest/`, `test/moduletest/` | `*_test.cpp`, `*_moduletest.cpp` |
| Add a **fuzz test** | `test/fuzztest/` | `*_fuzztest.cpp` |
| Change **SA profile** | `sa_profile/accountmgr.json` | SA 200 config |
| Change **DFX / diagnostics** | `dfx/` | `hidumper_adapter/`, `hisysevent_adapter/`, `hitrace_adapter/` |
| Change **ACM CLI tool** | `tools/acm/` | `acm` executable |
| Debug **persistent data** | on-device `/data/service/el1/public/account/` | See Configuration Files table below |

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

### 2.2 Path-based routing

| When editing files under… | Also read |
|--------------------------|-----------|
| `interfaces/kits/` | §3.1 (public API do-not); the matching `d.ts` and error-code docs |
| `interfaces/innerkits/` | The matching nested AGENTS.md (interface contract may affect callers) |
| `services/accountmgr/src/osaccount/` | [osaccount/AGENTS.md](services/accountmgr/src/osaccount/AGENTS.md) |
| `services/accountmgr/src/appaccount/` | [appaccount/AGENTS.md](services/accountmgr/src/appaccount/AGENTS.md) |
| `services/accountmgr/src/distributed_account/` | [distributed_account/AGENTS.md](services/accountmgr/src/distributed_account/AGENTS.md) |
| `services/accountmgr/src/account_iam/` | [account_iam/AGENTS.md](services/accountmgr/src/account_iam/AGENTS.md) |
| `services/accountmgr/src/account_mgr_service.cpp` | Pitfall 1 & 5 (SA startup is high-risk) |
| `os_account.gni` | §1.6 Feature Flags (flag changes affect whole subsystem) |
| `dfx/` | HiSysEvent schema must not break existing consumers |

### 2.3 Vocabulary routing

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

### 2.4 Pre-edit protocol

Before writing any code, state in your response:
1. **Task category**: which of (public API / inner API / service logic / framework / build config / DFX / test / other).
2. **Documents read**: which nested AGENTS.md, `.refdocs/`, or external docs you loaded (per §2.1–2.3).
3. **Constraints found**: which Do-not / Ask-before rules (§3) apply to this task.

If you cannot identify the task category or relevant constraints, **ask the user
before editing**.

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

### 5.5 Done definition

A change is **done** when **all** of the following hold:
1. `./build.sh --product-name rk3568 --build-target os_account` succeeds with no errors.
2. The relevant test suite passes: `./start.sh run -p rk3568 -t UT MST -tp os_account -ts <suite>`
   — report the suite name and pass/fail counts.
3. No new compiler warnings in changed files (treat warnings as errors).
4. If `interfaces/kits/` or `interfaces/innerkits/` changed: API-diff / caller
   build confirmed; **explicitly state whether any public surface changed**.
5. If the change touches SA startup, first-user path, permissions, or on-disk
   schema: user has approved (§3.1 / §3.2).

### 5.6 Final response expectations

When reporting a completed task, include:
- **Summary**: one-line description of the change.
- **Files changed**: list of paths.
- **Build status**: command + result.
- **Test status**: suite name, pass/fail counts (or "not run — reason").
- **Compatibility**: whether public API / inner API / on-disk schema / permissions
  were affected (yes/no + detail).
- **Constraints checked**: which §3 Do-not / Ask-before rules were reviewed.

### 5.7 Fallback if validation cannot run

If you cannot run the build or tests (e.g., no OpenHarmony root, no toolchain):
1. State explicitly: "I could not run the build/tests because <reason>."
2. Ask the user to run the commands in §5.1–5.3 and share the output.
3. Do **not** claim the change is verified or done.

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

- [C Coding Style Guide](https://gitcode.com/openharmony/docs/blob/master/en/contribute/OpenHarmony-c-coding-style-guide.md)
- [C/C++ Secure Coding Guide](https://gitcode.com/openharmony/docs/blob/master/en/contribute/OpenHarmony-c-cpp-secure-coding-guide.md)

---

## Version History

| Version | Date | Changes | Maintainer |
|---------|------|---------|------------|
| v1.0 | 2026-01-31 | Initial AGENTS.md creation | AI Assistant |
| v2.0 | 2026-07-09 | Rewritten per agent-instruction quality review: added code map, knowledge routing, constraints & boundaries, verification loop | AI Assistant |
