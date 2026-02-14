# OS Account Management - Layered architecture

---

## Basic Information

| Property | Value |
|----------|-------|
| **Repository Name** | os_account |
| **Subsystem** | base/account |
| **Primary Language** | C++ |
| **Last Updated** | 2026-02-04 |
| **System Ability ID** | 200 (accountmgr) |

---

## Layered architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                        │
│                  (NAPI JavaScript/TypeScript)               │
│                         (CAPI - C)                          │
│                         (CJ - FFI)                          │
├─────────────────────────────────────────────────────────────┤
│                      Interface Layer                        │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Innerkits (C++) - For System Abilities              │   │
│  │  - os_account_manager.h                              │   │
│  │  - app_account_manager.h                             │   │
│  │  - account_iam_client.h                              │   │
│  │  - domain_account_client.h                           │   │
│  └──────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Native or CJ Kits - For Applications                │   │
│  │  - napi/ (NAPI Binding)                              │   │
│  │  - capi/ (C API)                                     │   │
│  │  - cj/ (CJ FFI Binding)                              │   │
│  └──────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│                     Framework Layer                         │
│  ┌──────────────────┐  ┌──────────────────┐                 │
│  │   OsAccount      │  │   AppAccount     │                 │
│  │   Framework      │  │   Framework      │                 │
│  └──────────────────┘  └──────────────────┘                 │
│  ┌──────────────────┐  ┌──────────────────┐                 │
│  │  DomainAccount   │  │       IAM        │                 │
│  │   Framework      │  │   Framework      │                 │
│  └──────────────────┘  └──────────────────┘                 │
│  ┌──────────────────┐  ┌──────────────────┐                 │
│  │DistributedAccount│  │     Common       │                 │
│  │   Framework      │  │   Framework      │                 │
│  └──────────────────┘  └──────────────────┘                 │
├─────────────────────────────────────────────────────────────┤
│                       Service Layer                         │
│  ┌──────────────────────────────────────────────────────┐   │
│  │         AccountMgrService (SA 200)                   │   │
│  │  ┌────────────────────────────────────────────────┐  │   │
│  │  │ OsAccountManagerService                        │  │   │
│  │  │ - IInnerOsAccountManager                       │  │   │
│  │  │ - OsAccountControlFileManager                  │  │   │
│  │  │ - OsAccountSubscribeManager                    │  │   │
│  │  └────────────────────────────────────────────────┘  │   │
│  │  ┌────────────────────────────────────────────────┐  │   │
│  │  │ AppAccountManagerService (Optional)            │  │   │
│  │  └────────────────────────────────────────────────┘  │   │
│  │  ┌────────────────────────────────────────────────┐  │   │
│  │  │ DomainAccountManagerService (Optional)         │  │   │
│  │  └────────────────────────────────────────────────┘  │   │
│  │  ┌────────────────────────────────────────────────┐  │   │
│  │  │ AccountIAMService (Optional)                   │  │   │
│  │  └────────────────────────────────────────────────┘  │   │
│  │  ┌────────────────────────────────────────────────┐  │   │
│  │  │ DistributedAccountManager                      │  │   │
│  │  └────────────────────────────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│                    Data Storage Layer                       │
│  ┌──────────────────┐  ┌──────────────────┐                 │
│  │  KV Database     │  │  File Storage    │                 │
│  │                  │  │ (Persist File)   │                 │
│  │ - AppAccount Data│  │ - /data/service/ │                 │
│  │                  │  │   el1/public/    │                 │
│  │                  │  │   account/       │                 │
│  └──────────────────┘  └──────────────────┘                 │
└─────────────────────────────────────────────────────────────┘
```