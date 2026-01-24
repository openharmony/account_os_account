# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build System

This project uses the **GN (Generate Ninja)** build system. Key build files:
- `BUILD.gn` - Main build file in each directory
- `os_account.gni` - Global build configuration defining paths and feature flags
- `services/accountmgr/os_account_service.gni` - Service source file lists

### Building the Project

```bash
# Build everything (run from OpenHarmony root)
./build.sh --product-name <product> --build-target os_account account_build_unittest account_build_moduletest

# Build specific test groups
./build.sh --product-name <product> --build-target account_build_unittest
./build.sh --product-name <product> --build-target account_build_moduletest
./build.sh --product-name <product> --build-target account_build_fuzztest --gn-args use_thin_lto=false

# Build the main service
./build.sh --product-name <product> --build-target accountmgr
```

### Running Tests

Tests are defined using `ohos_unittest` and `ohos_moduletest` templates in BUILD.gn files. Test executables are typically named with `_test` suffix.

```bash
# in {code_base}/test/testfwk/developer_test
# Run single tests
./start.sh run -p rk3568 -t UT MST -tp os_account -ts OsAccountControlFileManagerUnitTest

# Run all tests
./start.sh run -p rk3568 -t UT MST -tp os_account
```

## Architecture

This is the **OS Account** subsystem for OpenHarmony, managing multiple types of accounts:

### Account Types

1. **OS Account** (`osaccount`) - System-level user accounts with lifecycle management
2. **App Account** (`appaccount`) - Application-level accounts for app-specific data
3. **Domain Account** (`domain_account`) - Domain (e.g. enterprise) account framework service
4. **Distributed Account** (`ohosaccount`) - Distributed account framework service
5. **Account IAM** (`account_iam`) - Identity and authentication management for os accounts

### Directory Structure

```
os_account/
├── frameworks/             # Framework implementations
│   ├── osaccount/          # OS account framework
│   ├── appaccount/         # App account framework
│   ├── domain_account/     # Domain account framework
│   ├── account_iam/        # IAM framework
│   ├── ohosaccount/        # Distributed account framework
│   ├── common/             # Shared utilities (log, json, database, etc.)
│   └── ets/taihe           # Static native apis
├── services/
│   └── accountmgr/         # Main account service (SA 200)
│       └── src/            # Service implementation
│           ├── osaccount/                  # OS account service logic
│           ├── appaccount/                 # App account service logic
│           ├── domain_account/             # Domain account service logic
│           ├── account_iam/                # IAM service logic
│           └── ohos_account_manager.cpp    # Distributed account service logic
├── interfaces/
│   ├── innerkits/          # Internal C++ APIs
│   └── kits/               # External APIs
│       ├── napi/           # Node.js API (JavaScript/TypeScript)
│       ├── capi/           # C API
│       └── cj/             # CJ (FFI) bindings
├── sa_profile/             # System Ability profiles
├── tools/
│   └── acm/                # Account management CLI tool
├── dfx/                    # Diagnostics (hilog, hidumper, hisysevent, hitrace)
└── test/                   # Tests (unittest, moduletest, fuzztest, systemtest)
```

## Key Components

### Main Service

The account service runs as **System Ability 200** (defined in `sa_profile/accountmgr.json`). The main service class is `AccountMgrService` in `services/accountmgr/src/account_mgr_service.cpp`.

The service is composed of:
- `OsAccountManagerService` - OS account management
- `AppAccountManagerService` - App account management (optional)
- `DomainAccountManagerService` - Domain account management (optional)
- `AccountIAMService` - Identity and authentication (optional, depends on User IAM)
- `OhosAccountManager` - Distributed account management

### Feature Flags

Defined in `os_account.gni`:
- `os_account_multiple_active_accounts` - Multiple active accounts
- `os_account_enable_multiple_os_accounts` - Multiple OS accounts
- `os_account_support_domain_accounts` - Domain account support
- `os_account_distributed_feature` - Distributed features
- `has_app_account_part` - App account (requires kv_store)
- `has_user_auth_part` - User authentication support (requires user_auth_framework)

### Data Storage

Account data is stored using:
- **KV Store** (`distributeddata_inner`) - Distributed key-value storage
- **File storage** - JSON files in `/data/service/el1/public/account` for device's runtime storage data

Configuration files:
- `os_account_config.json` - Account limits (max accounts, max logged in)
- `os_account_constraint_config.json` - Account constraint configuration
- `os_account_constraint_definition.json` - Constraint definitions list

### Privileges System

The privileges system is code-generated from JSON:
- Source: `services/authorization_manager/config/privileges.json`
- Parser: `frameworks/common/privileges/privileges_definition_parser.py`
- Generates: C++ code with privilege definitions at build time

To add a new privilege:
1. Add entry to `privileges.json`
2. Rebuild os_account(the parser runs automatically)

### IPC and Communication

- Uses **HiSysEvent** for system event logging
- Uses **HiDumper** for getting os accounts information
- Uses **HiTrace** for performance tracing
- IPC based on OpenHarmony's IPC/SAMGR framework

## Tools

### ACM (Account Command Manager)

Command-line tool for account management, built at `tools/acm/`. Executable is `acm`. Docs at [acm docs](https://gitcode.com/openharmony/docs/blob/master/zh-cn/application-dev/tools/acm-tool.md)

## Important Headers

Key interfaces:
- `interfaces/innerkits/osaccount/native/include/os_account_manager.h` - OS account management inner API
- `interfaces/innerkits/appaccount/native/include/app_account_manager.h` - App account inner API
- `interfaces/innerkits/domain_account/native/include/domain_account_client.h` - Domain account Inner API
- `interfaces/innerkits/account_iam/native/include/account_iam_client.h` - IAM client inner API
- `interfaces/innerkits/common/include/account_error_no.h` - Error codes for inner API
- [OS Account NAPI Interface](https://gitcode.com/openharmony/interface_sdk-js/blob/master/api/@ohos.account.osAccount.d.ts) - OS account NAPI interface
- [App Account NAPI Interface](https://gitcode.com/openharmony/interface_sdk-js/blob/master/api/@ohos.account.appAccount.d.ts) - App account NAPI interface
- [Distributed Account NAPI Interface](https://gitcode.com/openharmony/interface_sdk-js/blob/master/api/@ohos.account.distributedAccount.d.ts) - Distributed account NAPI interface

## Development Notes

- All paths are relative to `//base/account/os_account` in GN files
- The `os_account.gni` file defines all path variables used across the project
- Log domain is `0xD001B00` for account subsystem
- Service runs in the "accountmgr" process
- Tests use `ACCOUNT_TEST` define for test-specific behavior
