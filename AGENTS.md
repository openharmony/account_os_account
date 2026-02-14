# OS Account Management - AI Knowledge Base

---

## Basic Information

| Property | Value |
|----------|-------|
| **Repository Name** | os_account |
| **Subsystem** | account |
| **Primary Language** | C++ |
| **Last Updated** | 2026-01-31 |
| **System Ability ID** | 200 (accountmgr) |

---

## Architecture Design

### Architecture Overview
### Layered Architecture
Please check at [Layered Architecture](.refdocs/layered_architecture.md)

### Main Service Components

The account service (System Ability 200) is composed of:

- **AccountMgrService**: Main service entry point ([services/accountmgr/src/account_mgr_service.cpp](services/accountmgr/src/account_mgr_service.cpp))
- **OsAccountManagerService**: OS account management
- **AppAccountManagerService**: App account management (optional, depends on `has_app_account_part`)
- **DomainAccountManagerService**: Domain account management (optional, depends on `os_account_support_domain_accounts`)
- **AccountIAMService**: Identity and authentication (optional, depends on `has_user_auth_part`)
- **OhosAccountManager**: Distributed account management

### Feature Flags

Defined in [os_account.gni](os_account.gni):

| Flag | Description |
|------|-------------|
| `os_account_multiple_active_accounts`               | Enable multiple active OS accounts |
| `os_account_support_deactivate_main_os_account`     | Enable deactivation of main OS account |
| `os_account_distributed_feature`                    | Enable distributed features |
| `os_account_enable_multiple_foreground_os_accounts` | Enable multiple foreground OS accounts |
| `os_account_enable_multiple_os_accounts`            | Enable multiple OS accounts feature |
| `os_account_enable_default_admin_name`              | Enable default admin name |
| `os_account_enable_account_short_name`              | Enable account short name feature |
| `os_account_activate_last_logged_in_account`        | Enable activate last logged in account on start |
| `os_account_support_domain_accounts`                | Enable domain account support |
| `os_account_enable_account_1`                       | Enable User 1 support |
| `os_account_support_lock_os_account`                | Enable account lock feature |
| `os_account_support_authorization`                  | Enable authorization manager |

### Data Storage

#### Storage Mechanisms

- **KV Store** (`distributeddata_inner`): Distributed key-value storage for account data
- **File Storage**: JSON files in `/data/service/el1/public/account/`

#### Configuration Files On Device

You can find files below in `/data/service/el1/public/account/`.
| File | Purpose |
|------|---------|
| `account_index_info.json`              | Restore short names and local names |
| `account_info_digest.json`             | Restore digest data for configs |
| `account_list.json`                    | Restore account base info |
| `base_os_account_constraints.json`     | Restore base account constraints |
| `global_os_account_constraints.json`   | Restore global account constraints |
| `specific_os_account_constraints.json` | Restore specific account constraints |
| `{userId}\account.json`                | Restore base information for distributed account |
| `{userId}\account_avatar`              | Restore avatar for distributed accounts |
| `{userId}\account_info.json`           | Restore base information for current OS account |

#### Database

When distributed feature is disabled, uses SQLite for local storage. Database adapter is in `services/accountmgr/src/common/database/`.

---

## Directory Structure

```
os_account/
├── frameworks/                # Framework implementations for different account types
│   ├── osaccount/             # OS account framework
│   ├── appaccount/            # App account framework
│   ├── domain_account/        # Domain account framework
│   ├── account_iam/           # Identity and authentication framework
│   ├── ohosaccount/           # Distributed account framework
│   ├── authorization/         # Authorization framework
│   ├── common/                # Shared utilities (log, json, database, etc.)
│   ├── ets/                   # Static native APIs (ArkTS)
│   └── cj/                    # CJ (FFI) bindings
├── services/                  # Main account service running as System Ability 200
│   └── accountmgr/            # Main account service (SA 200)
│       ├── src/               # Service implementation
│       │   ├── osaccount/     # OS account service logic
│       │   ├── appaccount/    # App account service logic
│       │   ├── domain_account/# Domain account service logic
│       │   ├── account_iam/   # IAM service logic
│       │   └── ohos_account_manager.cpp
│       ├── include/           # Internal headers
│       ├── test/              # Unit tests, module tests
│       └── *.json             # Configuration files
├── interfaces/
│   ├── innerkits/             # Internal C++ APIs for inter-module communication
│   │   ├── osaccount/native/  # OS account inner API
│   │   ├── appaccount/native/ # App account inner API
│   │   ├── domain_account/native/
│   │   ├── account_iam/native/
│   │   └── common/            # Shared interfaces
│   └── kits/                  # External APIs (NAPI, C API, CJ) for application developers
│       ├── napi/              # Node.js API (JavaScript/TypeScript)
│       ├── capi/              # C API
│       └── cj/                # CJ (FFI) bindings
├── sa_profile/                # System Ability profile definitions
│   └── accountmgr.json        # SA 200 configuration
├── tools/
│   └── acm/                   # ACM (Account Command Manager) CLI tool
├── dfx/                       # Diagnostic facilities (HiDumper, HiSysEvent, HiTrace)
│   ├── hidumper_adapter/      # Dump support
│   ├── hisysevent_adapter/    # Event logging
│   └── hitrace_adapter/       # Performance tracing
├── test/                      # Comprehensive test suites (unit, module, fuzz, system)
│   ├── unittest/              # Unit tests
│   ├── moduletest/            # Module tests
│   ├── fuzztest/              # Fuzz tests
│   ├── systemtest/            # System tests
│   └── common/                # Test utilities
├── figures/                   # Documentation figures
├── os_account.gni             # Global build configuration
└── BUILD.gn                   # Build files in each directory
```

---

## Repository Overview

### Introduction

The **OS Account** subsystem is a core component of OpenHarmony, providing comprehensive account management capabilities for the operating system. It manages multiple types of accounts including OS-level user accounts, domain accounts for enterprise integration, distributed accounts for multi-device scenarios, identity authentication management(IAM), and application-level accounts.

The service runs as **System Ability 200** (accountmgr) and is responsible for account lifecycle management, authentication, and distributed account data storage.

### Core Features

- **OS Account Management**: System-level user account lifecycle with support for multiple active accounts and account constraints
- **Domain Account Management**: Enterprise domain account support with pluggable authentication
- **Distributed Account Management**: Distributed account management and data storage
- **Identity & Authentication Management (IAM)**: Integration with User IAM framework for secure authentication
- **App Account Management**: Application-level accounts for app-specific data isolation and sharing

### Main Dependencies

| Dependency | Purpose |
|------------|---------|
| `ability_runtime` | Ability manager integration for account lifecycle manager |
| `bundle_manager` | User-level application management, application package information query |
| `storage_service` | User-level directory management (creation, deletion, mounting, and unmounting); user-level file key management (encryption and decryption). |
| `user_auth_framework` | User authentication integration |
| `pin_auth` | PIN authentication integration |
| `kv_store` | Distributed key-value storage for account data |
| `sqlite` | Local database storage (fallback) |
| `asset` | High-sensitivity data storage |
| `hilog` | Logging facility |
| `hisysevent` | System event logging |
| `security_guard` | Reporting audit events |
| `access_token` | Access token and permission management |
| `common_event_service` | Common event service for account-related events |
| `safwk` | System Ability framework |
| `ipc` | IPC mechanism |

---

## API Reference

### Internal C++ APIs

- [OS Account Manager](interfaces/innerkits/osaccount/native/include/os_account_manager.h)
- [App Account Manager](interfaces/innerkits/appaccount/native/include/app_account_manager.h)
- [Domain Account Client](interfaces/innerkits/domain_account/native/include/domain_account_client.h)
- [Account IAM Client](interfaces/innerkits/account_iam/native/include/account_iam_client.h)
- [Error Codes](interfaces/innerkits/common/include/account_error_no.h)

### External NAPI APIs

- [OS Account NAPI](https://gitcode.com/openharmony/interface_sdk-js/blob/master/api/@ohos.account.osAccount.d.ts)
- [OS Account NAPI Docs For System API](https://gitcode.com/openharmony/docs/blob/master/en/application-dev/reference/apis-basic-services-kit/js-apis-osAccount-sys.md)
- [OS Account NAPI Docs For Public API](https://gitcode.com/openharmony/docs/blob/master/en/application-dev/reference/apis-basic-services-kit/js-apis-osAccount.md)
- [App Account NAPI](https://gitcode.com/openharmony/interface_sdk-js/blob/master/api/@ohos.account.appAccount.d.ts)
- [App Account NAPI Docs](https://gitcode.com/openharmony/docs/blob/master/en/application-dev/reference/apis-basic-services-kit/js-apis-appAccount.md)
- [Distributed Account NAPI](https://gitcode.com/openharmony/interface_sdk-js/blob/master/api/@ohos.account.distributedAccount.d.ts)
- [Distributed Account NAPI Docs For System API](https://gitcode.com/openharmony/docs/blob/master/en/application-dev/reference/apis-basic-services-kit/js-apis-distributed-account-sys.md)
- [Distributed Account NAPI Docs For Public API](https://gitcode.com/openharmony/docs/blob/master/en/application-dev/reference/apis-basic-services-kit/js-apis-distributed-account.md)
- [Account Management Error Codes](https://gitcode.com/openharmony/docs/blob/master/en/application-dev/reference/apis-basic-services-kit/errorcode-account.md)

### External C API

- [Account C API](interfaces/kits/capi/)
- [Account C API Docs](https://gitcode.com/openharmony/docs/blob/master/en/application-dev/reference/apis-basic-services-kit/capi-osaccount.md)
---

## Technology Stack

### Programming Languages

- **C++ (C++17)**: Primary language for service and framework implementation
- **JavaScript/TypeScript (NAPI)**: External API bindings
- **CJ (FFI)**: Foreign Function Interface bindings
- **IDL**: Interface Definition Language for IPC

### Frameworks & Libraries

- **Node.JS**: Runtime for NAPI bindings
- **OpenHarmony IPC/SAMGR**: Inter-process communication

### Build Tools

- **GN**: Build configuration (BUILD.gn files)
- **Ninja**: Build execution
- **llvm-gcc**: C++ compiler

---

## Coding Standards

[Coding Style Guide](https://gitcode.com/openharmony/docs/blob/master/en/contribute/OpenHarmony-c-coding-style-guide.md)
 	 
[Secure Coding Guide](https://gitcode.com/openharmony/docs/blob/master/en/contribute/OpenHarmony-c-cpp-secure-coding-guide.md)

---

## Common Pitfalls

### Pitfall 1: Do NOT Stop Or Block SA Initialization
- **Avoid time-consuming operations**: System ability startup must complete quickly; do not perform blocking I/O, network requests, or complex computations during initialization
- **No failures allowed**: Startup operations must not fail; ensure all dependencies and resources are properly prepared before initialization.

### Pitfall 2: Database And File Operation should be Data Consistency
- **Database and File Operation**: Ensure data consistency between database and file storage; avoid data loss or corruption during operations.
- **Transaction Management**: Use transactions to ensure atomicity and consistency of database operations.

### Pitfall 3: Use Secure Storage For Sensitive Data OR Clear Sensitive Data After Use
- **Sensitive Data**: Store sensitive data such as passwords, PINs, and tokens securely using encrypted storage or clear sensitive data after use.
- **Access Control**: Implement strict access controls to ensure only authorized entities can access sensitive data.

### Pitfall4: Should Handling Error Codes Properly
- **Error Handling**: Handle error codes properly to ensure proper error reporting and recovery.
- **`errno` Usage**: HILOG would modify errno when hilog data is dropped when flow control happened, which would cause the errno value to be unexpected.

### Pitfall 5: Avoid Change SA startup & First User Create And Activate Process
- **Avoid Change SA startup**: Avoid changing the startup process of the system ability, as it may affect the device boot process.
- **Avoid Change First User Create And Activate Process**: Avoid changing the first user creation and activation process, as it may affect the device boot process.

### Pitfall 6: Process In Lock Should Be Fast
- **Avoid Long-running Operations**: Avoid long-running operations within locks, as it may cause deadlocks or performance issues.
- **Monitor Lock Performance**: Monitor lock performance and add timeouts or monitoring to avoid resource exhaustion, especially IPC resources.

---

## Development & Build & Test

### Development Guide
Please check [Development Guide](.refdocs/development_guide.md)

### Build Commands

Build from OpenHarmony root directory:

```bash
# Common product: rk3568
# Build everything (service + tests)
./build.sh --product-name <product> --build-target os_account account_build_unittest account_build_moduletest

# Build specific test groups
./build.sh --product-name <product> --build-target account_build_unittest account_build_moduletest
./build.sh --product-name <product> --build-target account_build_fuzztest --gn-args use_thin_lto=false

# Build the main service only
./build.sh --product-name <product> --build-target accountmgr

# Build with dependent compile (NOT RECOMMEND)
hb build os_account -i # compile service
hb build os_account -t # compile tests

# Common product names: rk3568, hi3516, ohos-sdk
```

### Build Artifacts

| Artifact Type | Location |
|---------------|----------|
| Service library | `out/{product}/account/os_account/` |
| ACM Tool executable | `out/{product}/account/os_account/` |
| Service library With Symbol | `out/{product}/lib.unstripped/account/os_account` |
| Test executables | `out/{product}/tests/unittest/os_account` `out/{product}/tests/moduletest/os_account` |

### Test Commands

```bash
# Navigate to test framework directory
cd {OpenHarmonyRootFolder}/test/testfwk/developer_test

# Common product: rk3568
# Run specific test
./start.sh run -p <product> -t UT MST -tp os_account -ts <testSuiteName>

# Run all os_account tests
./start.sh run -p <product> -t UT MST -tp os_account

# Test executable naming convention: *_test (unit), *_moduletest (module)
```

---

## Tools

### ACM (Account Command Manager)

CLI tool for account management.

**Location**: [tools/acm/](tools/acm/)
**Executable**: `acm`
**Documentation**: [ACM Tool Guide](https://gitcode.com/openharmony/docs/blob/master/en/application-dev/tools/acm-tool.md)

### Usage Examples

```bash(in hdc shell)
# List OS accounts
acm dump -a

# Create OS account
acm create -n testAccountName -t normal

# Activate account
acm switch -i <accountId>
```

---

## Diagnostics

### HiDumper

Dump account information:

```bash
hidumper -s AccountMgrService
```

### HiSysEvent

Query account events:

```bash
# List all current hisysevents
hdc shell "hisysevent -l -o ACCOUNT"
# List new current hisysevents recursively
hdc shell "hisysevent -r -o ACCOUNT"
```

### Log Domain

- **Log Domain**: `0xD001B00`
- **Log Tag**: Various (e.g., `accountmgr`)
```bash
hdc shell "hilog | grep -i C01B00"
```
---

## Additional Resources

- [OpenHarmony Documentation](https://gitcode.com/openharmony/docs)
- [Account Subsystem Design](https://gitcode.com/openharmony/docs/blob/master/en/application-dev/basic-services/account/account-overview-sys.md)
- [GN Build System](https://gn.googlesource.com/gn/)

---

## FAQ
Please check [FAQ](.refdocs/frequent_asked_questions.md)

---

## Version History

| Version | Date | Changes | Maintainer |
|---------|------|---------|------------|
| v1.0 | 2026-01-31 | Initial AGENTS.md creation | AI Assistant |


**End of Document**
