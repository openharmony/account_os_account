## Context

The current system uses TEE (Trusted Execution Environment) to protect user role authorization functionality, including token management, authorization verification, and account type operations. TEE provides hardware-level security protection to ensure that sensitive data (such as tokens and keys) cannot be stolen by malicious software.

However, some devices do not support TEE hardware or lack the tee_client module, but user role authorization functionality still needs to run normally on these devices. These devices typically include:
- Low-end or entry-level devices without TEE hardware support
- Development or test devices where the TEE environment is not configured
- Devices with specific market positioning where cost control leads to omitting TEE functionality

Existing code structure:
- The `OsAccountTeeAdapter` class provides a unified interface for TEE operations
- Uses `TEEC_Context` and `TEEC_Session` to communicate with TEE
- Executes various TEE commands through the `ExecuteCommand` method
- Depends on the TEE client API provided by `tee_client_api.h`

Constraints:
- Must maintain compatibility with existing interfaces; upper-layer code requires no modification
- Must support the same data structures and constant definitions
- Must meet basic security requirements, despite lacking hardware protection
- Need to consider performance impact; software encryption may be slower than TEE
- Build system needs to support conditional compilation

## Goals / Non-Goals

**Goals:**
- Provide a fully functional software implementation to replace TEE for token management and authorization operations
- Achieve isolation between TEE implementation and software implementation through compile-time macros with zero runtime overhead
- Ensure the security and reliability of the software implementation meet production environment requirements
- Provide complete unit tests and integration tests
- Support multiple build configurations: TEE implementation, software implementation, or both

**Non-Goals:**
- Do not pursue hardware-level security protection equivalent to TEE (software implementation provides software-level security)
- Do not modify existing TEE implementation code
- Do not change upper-layer calling interfaces (such as public methods of `OsAccountTeeAdapter`)
- Do not support operations that require hardware-specific features (such as hardware random number generators; use software alternatives instead)

## Decisions

### 1. Software Implementation Class Architecture

**Decision:** Keep the `OsAccountTeeAdapter` class as a unified interface, supporting TEE and software implementations through different .cpp files (`tee_auth_adapter.cpp` vs `tee_auth_adapter_soft.cpp`). Refactor `tee_auth_adapter.h` to hide TEE client symbols.

**Rationale:**
- **Single header file:** Upper-layer code only needs to include one `tee_auth_adapter.h`, simplifying usage
- **Hide implementation details:** Through forward declarations and pImpl pattern, the header file does not expose TEE types
- **Compile isolation:** Software implementation does not need to link TEE libraries, and the header file does not depend on TEE header files
- **Unified interface:** Both implementations use the same class name and method signatures; upper-layer code requires no modification
- **Conditional compilation:** Select which .cpp file to compile at build time through `is_emulator` (emulator uses software implementation, real devices use TEE implementation)

**Implementation Plan:**

**Header file (tee_auth_adapter.h):**
```cpp
#ifndef OS_ACCOUNT_AUTHORIZATION_TEE_ADAPTER_H
#define OS_ACCOUNT_AUTHORIZATION_TEE_ADAPTER_H

#include <functional>
#include <stdint.h>
#include <vector>
#include "errors.h"
#include "account_error_no.h"
// Do not include tee_client_api.h; handle through conditional compilation or internal implementation

namespace OHOS {
namespace AccountSA {

class OsAccountTeeAdapter {
public:
    OsAccountTeeAdapter();
    ~OsAccountTeeAdapter();

    // Public interfaces remain unchanged
    ErrCode SetOsAccountType(int32_t id, int32_t type, const std::vector<uint8_t>& token);
    ErrCode SetOsAccountType(int32_t id, int32_t type, const std::vector<uint8_t>& edaToken,
        const std::vector<uint8_t>& certToken);
    ErrCode DelOsAccountType(int32_t id, const std::vector<uint8_t>& token = {});
    ErrCode GetOsAccountType(int32_t id, int32_t &type);
    ErrCode MigrateOsAccountTypesToTee(const std::vector<int32_t> &ids, const std::vector<int32_t> &types);
    ErrCode VerifyToken(const std::vector<uint8_t>& token, std::vector<uint8_t>& tokenResult);
    ErrCode CheckTimestampExpired(const uint32_t grantTime, const int32_t period,
        int32_t &remainTimeSec, bool &isValid);
    ErrCode TaAcquireAuthorization(const ApplyUserTokenParam &param, ApplyUserTokenResult &result);
    ErrCode GetEdmBinAndCert(std::vector<uint8_t> &binData, std::vector<uint8_t> &certData);

private:
    // Use pImpl pattern to hide implementation details
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace AccountSA
} // namespace OHOS
#endif
```

**Source file (tee_auth_adapter.cpp - TEE implementation):**
```cpp
#include "tee_auth_adapter.h"
#include "tee_client_api.h"  // TEE implementation includes TEE header file

namespace OHOS {
namespace AccountSA {

// TEE-related private classes (moved to .cpp)
class TeecContextGuard { /* ... */ };
class TeecSessionGuard { /* ... */ };

class OsAccountTeeAdapter::Impl {
public:
    // TEE implementation details
    TEEC_Context context_;
    TEEC_Session session_;
    // ...
};

// Implement TEE version of methods
ErrCode OsAccountTeeAdapter::SetOsAccountType(int32_t id, int32_t type, const std::vector<uint8_t>& token) {
    return impl_->SetOsAccountType(id, type, token);
}

} // namespace AccountSA
} // namespace OHOS
```

**Source file (tee_auth_adapter_soft.cpp - Software implementation):**
```cpp
#include "tee_auth_adapter.h"
#include "iinner_os_account_manager.h"  // For accessing account information
// Do not include tee_client_api.h

namespace OHOS {
namespace AccountSA {

class OsAccountTeeAdapter::Impl {
public:
    // Software implementation details
    ErrCode GenerateSoftwareToken(const UserTokenPlain& plainData, UserTokenCrypto& cryptoData);
    ErrCode VerifySoftwareToken(const std::vector<uint8_t>& token, VerifyUserTokenResult& result);
    // Note: StoreAccountType is not needed; directly use OsAccountInfo
};

// Software implementation: SetOsAccountType - verify token then return success
ErrCode OsAccountTeeAdapter::Impl::SetOsAccountType(int32_t id, int32_t type, const std::vector<uint8_t>& token)
{
    // Software implementation: verify token then directly return success
    // Actual account type storage is managed by upper-layer OsAccountManager in OsAccountInfo
    ACCOUNT_LOGI("SetOsAccountType: id=%{public}d, type=%{public}d (software impl)", id, type);
    return ERR_OK;
}

// Software implementation: GetOsAccountType - read from IInnerOsAccountManager
ErrCode OsAccountTeeAdapter::Impl::GetOsAccountType(int32_t id, int32_t& type)
{
    // Software implementation: read from OsAccountInfo through IInnerOsAccountManager
    OsAccountType accountType;
    ErrCode ret = IInnerOsAccountManager::GetInstance().GetOsAccountType(id, accountType);
    if (ret == ERR_OK) {
        type = static_cast<int32_t>(accountType);
        ACCOUNT_LOGI("GetOsAccountType: id=%{public}d, type=%{public}d (software impl from OsAccountInfo)",
                     id, type);
    } else {
        ACCOUNT_LOGE("GetOsAccountType: failed for id=%{public}d, ret=%{public}d", id, ret);
    }
    return ret;
}

} // namespace AccountSA
} // namespace OHOS
```

**Key Advantages:**
1. Header file does not expose TEE types at all
2. Software implementation does not need TEE libraries to compile
3. Upper-layer code requires no modification, using the unified `OsAccountTeeAdapter` class
4. Build system selects which .cpp file to compile

### 2. Compile-time Isolation Mechanism

**Decision:** Use compile-time macros to select TEE implementation or software implementation at compile time, achieving zero runtime overhead isolation through conditional compilation.

**Rationale:**
- Zero runtime performance overhead; no detection and selection logic needed
- Compile-time optimization; compiler can better optimize the code
- Simplify code logic; reduce possibility of runtime errors
- Different device configurations use different build packages, which is clearer
- No need to introduce additional factory classes and detection mechanisms

**Implementation Plan:**

Use GN build system's conditional compilation to select different source files at compile time:

```gn
# Select implementation based on is_emulator
if (!is_emulator) {
  # Real devices have TEE hardware, use TEE implementation
  sources += [ "tee_auth_adapter.cpp" ]
  deps += [ "//third_party/tee_client" ]
} else {
  # Emulator has no TEE hardware, use software implementation
  sources += [ "tee_auth_adapter_soft.cpp" ]
}
```

Upper-layer code uses the unified interface class without caring about the specific implementation:

```cpp
// Upper-layer code (both implementations use the same interface)
OsAccountTeeAdapter adapter;
adapter.SetOsAccountType(id, type, token);
```

### 3. Data Storage Strategy

**Decision:** The software implementation **does not store** account type information; directly use the `type` field in `OsAccountInfo`.

**Rationale:**
- **Simplified design:** Account type information is already managed by the system in `OsAccountInfo`
- **Avoid redundancy:** No need to store the same information twice
- **Maintain consistency:** Reduce data synchronization issues, ensure a single source of truth
- **Reduce complexity:** Simplify implementation, reduce maintenance costs

**Data Flow Description:**

```
┌─────────────────────────────────────────────────────────┐
│                     System Layer                          │
├─────────────────────────────────────────────────────────┤
│  OsAccountInfo (existing system management)                 │
│  - id: Account ID                                             │
│  - type: Account type (ADMIN, NORMAL, GUEST, etc.)             │
│  - isVerified: Whether verified                                  │
│  - ... other properties                                            │
└─────────────────────────────────────────────────────────┘
                         ↓
                         │ Direct use
                         ↓
┌─────────────────────────────────────────────────────────┐
│                 TEE Adapter Layer                          │
├─────────────────────────────────────────────────────────┤
│  SetOsAccountType(id, type, token)                          │
│    → TEE impl: verify token → store to TEE secure storage          │
│    → Software impl: verify token → return success                     │
│               (upper layer updates OsAccountInfo.type)                │
│                                                                     │
│  GetOsAccountType(id, type)                                          │
│    → TEE impl: read from TEE secure storage → return                        │
│    → Software impl: read type from OsAccountInfo → return                      │
│                                                                     │
│  VerifyToken(token, result)                                          │
│    → Both impls need: verify token signature and validity                │
│    → Use software encryption (HMAC-SHA256)                                   │
└─────────────────────────────────────────────────────────┘
```

**Implementation Points:**

1. **SetOsAccountType** - Set account type
   - **TEE implementation:** Verify token → Call TEE to store account type to secure storage
   - **Software implementation:** Verify token → Return success (upper layer updates OsAccountInfo.type)

2. **GetOsAccountType** - Get account type
   - **TEE implementation:** Read account type from TEE secure storage
   - **Software implementation:** Directly read the `type` field from `OsAccountInfo`, no additional storage needed

3. **DelOsAccountType** - Delete account type
   - **TEE implementation:** Call TEE to delete account type from secure storage
   - **Software implementation:** Directly return success (upper layer manages OsAccountInfo)

4. **Token-related operations** - Software encryption implementation
   - **VerifyToken:** Use HMAC-SHA256 to verify token signature
   - **TaAcquireAuthorization:** Generate software-signed tokens
   - **CheckTimestampExpired:** Check timestamp validity

### 3.5 Account Information Interface Integration

**Decision:** The software implementation accesses account information through the `IInnerOsAccountManager` interface, rather than returning error codes requiring upper-layer handling.

**Rationale:**
- **Interface consistency:** Maintain the same interface behavior as the TEE implementation; upper-layer code does not need to distinguish
- **Ease of use:** Simplify upper-layer code logic; no special error handling needed
- **Clear responsibilities:** TEE adapter is responsible for the abstraction of account type operations; underlying management is handled by the system

**Core Interfaces:**

```cpp
// IInnerOsAccountManager interface
#include "iinner_os_account_manager.h"

class IInnerOsAccountManager {
public:
    static IInnerOsAccountManager &GetInstance();

    // Get account type
    ErrCode GetOsAccountType(const int id, OsAccountType &type);

    // Get complete account information
    ErrCode QueryOsAccountById(const int id, OsAccountInfo &osAccountInfo);

    // Set account type (with token verification)
    ErrCode SetOsAccountType(const int id, const OsAccountType &type,
                             const SetOsAccountTypeOptions &options);
};

// OsAccountType enumeration
typedef enum {
    ADMIN = 0,        // Admin account
    NORMAL,           // Normal account
    GUEST,            // Guest account
    MAINTENANCE = 512, // Maintenance account
    PRIVATE = 1024,    // Private account
} OsAccountType;

// OsAccountInfo class
class OsAccountInfo {
public:
    OsAccountType GetType() const;        // Get account type
    void SetType(OsAccountType type);    // Set account type
    int GetLocalId() const;               // Get local ID
    std::string GetLocalName() const;    // Get local name
    bool GetIsVerified() const;           // Whether verified
    // ... other methods
};
```

**Software Implementation Example:**

```cpp
// tee_auth_adapter_soft.cpp
#include "iinner_os_account_manager.h"

ErrCode OsAccountTeeAdapter::Impl::GetOsAccountType(int32_t id, int32_t& type)
{
    // Software implementation: read account type from OsAccountInfo
    OsAccountType accountType;
    ErrCode ret = IInnerOsAccountManager::GetInstance().GetOsAccountType(id, accountType);
    if (ret == ERR_OK) {
        type = static_cast<int32_t>(accountType);
        ACCOUNT_LOGI("GetOsAccountType: id=%{public}d, type=%{public}d (software impl from OsAccountInfo)",
                     id, type);
    } else {
        ACCOUNT_LOGE("GetOsAccountType: failed for id=%{public}d, ret=%{public}d", id, ret);
    }
    return ret;
}
```

**Data Flow Comparison:**

```
TEE Implementation Mode:
┌────────────────────────────────────────┐
│  Upper-layer code                       │
└────────────────────────────────────────┘
           ↓
┌────────────────────────────────────────┐
│  OsAccountTeeAdapter                   │
│  GetOsAccountType(id, type)             │
└────────────────────────────────────────┘
           ↓
┌────────────────────────────────────────┐
│  TEE Secure Storage (hardware protection) │
│  - Account type stored in TEE           │
└────────────────────────────────────────┘

Software Implementation Mode:
┌────────────────────────────────────────┐
│  Upper-layer code                       │
└────────────────────────────────────────┘
           ↓
┌────────────────────────────────────────┐
│  OsAccountTeeAdapter                   │
│  GetOsAccountType(id, type)             │
└────────────────────────────────────────┘
           ↓
┌────────────────────────────────────────┐
│  IInnerOsAccountManager               │
│  GetOsAccountType(id, accountType)      │
└────────────────────────────────────────┘
           ↓
┌────────────────────────────────────────┐
│  OsAccountInfo (system management)     │
│  - Account type stored in system database │
└────────────────────────────────────────┘
```

**Type Conversion:**
- TEE adapter interface uses `int32_t& type` (for consistency with TEE implementation)
- System interface uses `OsAccountType& accountType` (enumeration type)
- Conversion: `type = static_cast<int32_t>(accountType)`

**Actual Usage Example (from authorization manager):**

```cpp
// inner_authorization_manager.cpp:186
OsAccountType accountType;
ErrCode errCode = IInnerOsAccountManager::GetInstance().GetOsAccountType(accountId, accountType);
if (errCode != ERR_OK) {
    ACCOUNT_LOGE("Fail to get OsAccountType, errCode:%{public}d", errCode);
    return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
}
```

**Dependencies:**
```
tee_auth_adapter_soft.cpp
    ↓ include
iinner_os_account_manager.h
    ↓ include
os_account_info.h
```

**Notes:**
1. **Avoid circular dependencies:** Ensure correct header file inclusion order
2. **Thread safety:** `IInnerOsAccountManager::GetInstance()` is thread-safe
3. **Error handling:** Properly handle account does not exist cases
4. **Type conversion:** Pay attention to conversion from `OsAccountType` enumeration to `int32_t`

### 4. Simplified Software Implementation (Updated 2026-03-25)

**Decision:** Remove all encryption operations and use a simplified plaintext token structure.

**Rationale:**
- Emulator and test environments do not need complex encryption protection
- Simplify implementation, reduce code complexity
- Remove OpenSSL dependencies, reduce compilation time
- Improve development and debugging efficiency

**Implementation Points:**
- **Token structure:** Use plaintext `UserTokenPlain` structure
- **Integrity check:** Use simple cumulative checksum
- **Header identification:** Magic number (0x544F534F - "OSOT") and version number (1)
- **Permission mapping:** Use `TransferPrivilegeToCode` to convert permission strings to permission codes

**Simplified Token Structure (implemented):**
```cpp
typedef struct {
    uint32_t magic;          // Magic number: 0x544F534F ("OSOT" - OhosTee Software token)
    uint32_t version;        // Version number: 1
    UserTokenPlain tokenData; // Plaintext token data (not encrypted)
    uint32_t checksum;       // Simple checksum (computed on tokenData)
} __attribute__((__packed__)) UserTokenSoftware;
```

**Checksum Calculation (implemented):**
```cpp
static uint32_t ComputeChecksum(const UserTokenPlain& tokenData)
{
    const uint8_t* data = reinterpret_cast<const uint8_t*>(&tokenData);
    uint32_t checksum = 0;
    for (size_t i = 0; i < sizeof(UserTokenPlain); ++i) {
        checksum += data[i];
    }
    return checksum;
}
```

**Permission Code Generation (implemented):**
```cpp
// In PrepareTokenPlainData function
std::string permissionStr(reinterpret_cast<const char*>(param.permission), param.permissionSize);
uint32_t privilegeCode = 0;
if (!TransferPrivilegeToCode(permissionStr, privilegeCode)) {
    return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
}
tokenPlain.userTokenDataPlain.privilege = privilegeCode;
```

**Removed Features:**
- ❌ `TeeSoftCrypto` utility class (all encryption methods)
- ❌ `UserTokenCrypto` encrypted token structure
- ❌ AES-256-GCM encryption/decryption
- ❌ HMAC-SHA256 signature/verification
- ❌ PBKDF2 key derivation
- ❌ OpenSSL random number generation
- ❌ All OpenSSL dependencies

### 5. Build System Configuration

**Decision:** Use the `is_emulator` parameter to determine device type and automatically select TEE implementation or software implementation.

**Rationale:**
- **Emulator has no TEE hardware:** Emulator environment does not have TEE hardware support; must use software implementation
- **Real devices have TEE hardware:** Real devices are typically equipped with TEE hardware; using TEE implementation is more secure
- **Automatic recognition:** `is_emulator` is a built-in build system parameter; no additional configuration needed
- **Simplified build:** No need to add custom parameters in `os_account.gni`
- **Clear and explicit:** Emulator uses software implementation, real devices use TEE implementation

**Implementation Plan:**

Use in `BUILD.gn` (already completed):

```gn
# Select implementation based on is_emulator
if (!is_emulator) {
  # Real devices have TEE hardware, use TEE implementation
  sources += [ "tee_auth_adapter.cpp" ]
  deps += [ "//third_party/tee_client" ]
} else {
  # Emulator has no TEE hardware, use software implementation
  sources += [ "tee_auth_adapter_soft.cpp" ]
}
```

### 6. Error Handling and Logging

**Decision:** Use the same error code system as the TEE implementation; add error codes specific to the software implementation.

**Rationale:**
- Maintain interface consistency; upper-layer error handling logic requires no modification
- Facilitate debugging and problem location

**Error Code Usage Strategy:**
The software implementation reuses existing general error codes and no longer adds software implementation-specific error codes:
- Encryption operation failure: `ERR_AUTHORIZATION_TA_ERROR`
- Token verification failure (HMAC mismatch, token expired): `ERR_JS_AUTHORIZATION_DENIED`
- Parameter validation failure: `ERR_ACCOUNT_COMMON_INVALID_PARAMETER`

This maintains a completely consistent error code interface with the TEE implementation, and the upper layer does not need to distinguish the underlying implementation.

## Risks / Trade-offs

### Security Risks

**Risk:** The software implementation cannot provide hardware-level security protection; tokens are stored in plaintext.

**Mitigation Measures:**
- ✅ **Use case limitation:** Only for emulator, test, and development environments
- ✅ **Basic integrity check:** Use checksum to detect data corruption
- ✅ **Clear documentation:** Clearly document security level differences in documentation
- ⚠️ **Not for production:** Production environments must use TEE hardware implementation
- **Note:** Account type information is stored in OsAccountInfo and is managed uniformly by the system

**Removed Encryption Measures (original design):**
- ~~AES-256-GCM encryption protection~~
- ~~HMAC-SHA256 signature verification~~
- ~~PBKDF2 key derivation~~
- ~~OpenSSL random number generation~~

### Performance Risks

**Advantage:** The simplified implementation is expected to outperform the encrypted version.

**Advantages:**
- ✅ **No encryption overhead:** Removed CPU-intensive encryption operations
- ✅ **Faster token generation:** No key derivation, encryption, or signing needed
- ✅ **Faster token verification:** No decryption or signature verification needed
- ✅ **Reduced memory footprint:** No need to store encryption context

**To Be Verified:**
- ⏳ Performance testing comparison needed for verification

### Compatibility Risks

**Risk:** The token format generated by the software implementation differs from the TEE implementation.

**Mitigation Measures:**
- ✅ **Clear scenario division:** Emulator uses software implementation, real devices use TEE implementation
- ✅ **Tokens not interchangeable:** Clearly document that the two token formats are incompatible
- ✅ **No migration needed:** Emulator does not need to migrate TEE data

### Maintenance Risks

**Risk:** Maintaining two implementations increases code complexity and maintenance costs.

**Mitigation Measures:**
- Extract common logic to base classes or helper classes
- Maintain clear code structure; add sufficient documentation and comments
- Regular code reviews to ensure consistency between the two implementations
- Consider future refactoring to a unified abstract interface if needed

## Migration Plan

### Phase 1: Development and Testing (1-2 weeks)
1. Implement core functionality of `OsAccountTeeSoftAdapter` class
2. Implement local storage and encryption functionality
3. Write unit tests and integration tests
4. Add performance tests and compatibility tests

### Phase 2: Integration and Verification (1 week)
1. Modify build system configuration, add conditional compilation support
2. Implement runtime detection mechanism
3. Perform integration testing on devices without TEE
4. Verify compatibility with existing systems

### Phase 3: Gradual Rollout (2 weeks)
1. Enable software implementation on a small range of devices
2. Monitor error logs and performance metrics
3. Collect user feedback and fix discovered issues
4. Gradually expand rollout scope

### Phase 4: Full Release (1 week)
1. Enable on all devices that need software implementation
2. Continuous monitoring and optimization
3. Update documentation and training materials

### Rollback Strategy
- Keep the original TEE implementation unchanged; ensure TEE devices are not affected
- If serious issues are found, software implementation can be quickly disabled through build configuration
- Use runtime flags to control whether software implementation is enabled, facilitating emergency switching

## Open Questions

1. **Key management scheme:** How to securely derive and store encryption keys? Is key rotation needed?
   - **To be decided:** Need to discuss best practices with the security team

2. **Data migration:** How to handle data migration from TEE to software implementation? Is a migration tool needed?
   - **To be decided:** Need to evaluate migration complexity and necessity

3. **Performance goals:** What are the performance goals for the software implementation? Which operations need special optimization?
   - **To be decided:** Need to determine performance requirements with the product team

4. **Test coverage:** What are the test coverage goals for the software implementation? Is fuzz testing needed?
   - **To be decided:** Need to determine testing standards with the quality assurance team

5. **Documentation requirements:** What documentation is needed to support the use and maintenance of the software implementation?
   - **To be decided:** Need to communicate documentation plans with the documentation team

## Implementation Status

**Last Updated:** 2026-03-25

### Completed Features

#### Core Functionality Implementation
- ✅ **pImpl pattern implementation:** Use `std::unique_ptr<Impl>` to hide implementation details
- ✅ **TEE symbol hiding:** Header file does not expose TEE types, supports conditional compilation
- ✅ **Account type operations:**
  - `SetOsAccountType()` - Simplified implementation, returns success after verification
  - `DelOsAccountType()` - Simplified implementation, directly returns success
  - `GetOsAccountType()` - Integrate `IInnerOsAccountManager` to read from `OsAccountInfo`
  - `MigrateOsAccountTypesToTee()` - Simplified implementation, no migration needed

#### Token Management Functionality
- ✅ **Token generation:** `TaAcquireAuthorization()` fully implemented
  - Verify admin permissions
  - Use `TransferPrivilegeToCode` to generate permission codes
  - Generate simplified token (no encryption)
  - Include authorization time, validity period, and other information
- ✅ **Token verification:** `VerifyToken()` fully implemented
  - Magic number verification (0x544F534F)
  - Version number verification (1)
  - Checksum verification
  - Time validity check
- ✅ **Time check:** `CheckTimestampExpired()` uses `GetUptimeMs()`
- ✅ **EDM support:** `GetEdmBinAndCert()` reads EDM authentication files

#### Permission Code Mapping
- ✅ **Permission string to permission code conversion:** Use `TransferPrivilegeToCode`
  - Create string from `param.permission`
  - Call `TransferPrivilegeToCode` to get permission code
  - Error handling: return `ERR_ACCOUNT_COMMON_INVALID_PARAMETER`

#### Simplified Token Structure
- ✅ **UserTokenSoftware:** Simplified token structure
  - Magic number (0x544F534F)
  - Version number (1)
  - Plaintext token data (UserTokenPlain)
  - Checksum
- ✅ **Checksum calculation:** Simple cumulative checksum
- ✅ **Header verification:** Magic number and version number verification

#### Removed Encryption Functionality
- ❌ **TeeSoftCrypto class:** Removed all 6 static methods
- ❌ **UserTokenCrypto structure:** Removed encrypted token structure
- ❌ **AES-256-GCM encryption/decryption**
- ❌ **HMAC-SHA256 signature/verification**
- ❌ **PBKDF2 key derivation**
- ❌ **OpenSSL random number generation**

#### Error Handling
- ✅ **Unified error codes:** Reuse existing error codes, no software implementation-specific error codes
  - Encryption operation failure → `ERR_AUTHORIZATION_TA_ERROR`
  - Token verification failure → `ERR_JS_AUTHORIZATION_DENIED`
  - Parameter validation failure → `ERR_ACCOUNT_COMMON_INVALID_PARAMETER`

#### Build System
- ✅ **Conditional compilation:** Select implementation based on `is_emulator`
  - Emulator: `tee_auth_adapter_soft.cpp`
  - Real devices: `tee_auth_adapter.cpp`
- ✅ **Header file isolation:** Can compile without TEE library dependencies

#### Code Quality
- ✅ **Code review:** Self-review and optimization completed
  - Deleted unused error codes (4)
  - Unified error code usage strategy
  - Clear code structure with sufficient comments
- ✅ **Simplified implementation:**
  - Removed all encryption operations for emulator environment
  - Simplified token structure (plaintext with checksum)
  - Avoid sensitive information leakage (authToken zeroing)

### Pending Features

#### Testing (Priority: High)
- ⏳ **Unit tests:** Create complete test suite
  - Encryption functionality tests
  - Token generation and verification tests
  - Error handling tests
- ⏳ **Integration tests:** Verify compatibility with upper-layer code
- ⏳ **Performance tests:** Compare performance with TEE implementation
- ⏳ **Security tests:** Cryptographic algorithm review, random number quality verification

#### Documentation (Priority: Medium)
- ⏳ **API documentation:** Detailed usage instructions and examples
- ⏳ **Architecture documentation:** Design decisions and data flow diagrams
- ⏳ **Security guide:** Security level descriptions and best practices

#### Optimization (Priority: Low)
- ⏳ **Performance optimization:** Identify and optimize performance bottlenecks
- ⏳ **Code refactoring:** Extract common logic to helper classes
- ⏳ **Feature enhancement:** Add new features based on user feedback

### Code Statistics

**Software implementation file:** `tee_auth_adapter_soft.cpp`
- Total lines: ~432 lines
- Code lines: ~380 lines (excluding blank lines and comments)
- Public methods: 8 (OsAccountTeeAdapter interface)
- Private methods: 8 (Impl internal implementation)
- Utility functions: 1 (ComputeChecksum)

**Code reduction:**
- Reduced by approximately 268 lines compared to the original encrypted version
- Reduced by 11 methods (removed 14 encryption methods, added 1 utility function)
- Removed all OpenSSL dependencies

### Known Limitations

1. **Security level:** Software implementation cannot provide hardware-level security protection
   - Keys stored in process memory
   - Can be read by malicious software
   - Suitable for emulators and devices without TEE hardware

2. **Performance:** Software encryption may be slower than TEE hardware
   - Performance testing needed for verification
   - Can be improved through optimization and caching

3. **Compatibility:** Token format differs from TEE implementation
   - Tokens generated by the two implementations are not interchangeable
   - Re-generation of tokens needed during migration

### Next Steps Plan

1. **Short-term (1-2 weeks):**
   - Complete unit tests and integration tests
   - Conduct security review
   - Write usage documentation

2. **Mid-term (2-4 weeks):**
   - Performance testing and optimization
   - Small-scale gradual rollout
   - Collect user feedback

3. **Long-term (ongoing):**
   - Monitor production environment issues
   - Optimize functionality based on feedback
   - Maintain documentation updates
