# TEE Client Software Fallback Implementation - Summary

**Project Name:** TEE Client Software Fallback Implementation
**Status:** Core functionality completed, simplified for emulator environment
**Last Updated:** 2026-03-25

## Project Overview

Provide a software implementation for devices that do not support TEE hardware (such as emulators) to ensure that user role authorization functionality runs normally on all devices.

**Latest Simplification (2026-03-25):**
- Removed complex encryption operations (AES-256-GCM, HMAC-SHA256, PBKDF2)
- Simplified token structure, suitable for emulator/test scenarios
- Added use of `TransferPrivilegeToCode` to generate permission codes

## Core Architecture

### Design Pattern: pImpl (Pointer to Implementation)

```
OsAccountTeeAdapter (Public Interface)
    ↓ unique_ptr<Impl>
OsAccountTeeAdapter::Impl (Private Implementation)
    - TEE implementation: tee_auth_adapter.cpp
    - Software implementation: tee_auth_adapter_soft.cpp
```

### Compile-time Isolation

```gn
if (!is_emulator) {
  sources += [ "tee_auth_adapter.cpp" ]
  deps += [ "//third_party/tee_client" ]
} else {
  sources += [ "tee_auth_adapter_soft.cpp" ]
}
```

## Implemented Features

### 1. Account Type Operations

| Method | TEE Implementation | Software Implementation | Description |
|------|---------|---------|------|
| `SetOsAccountType()` | Verify token → Store to TEE | Verify token → Return success | Upper layer updates OsAccountInfo |
| `DelOsAccountType()` | Call TEE to delete | Directly return success | Upper layer manages OsAccountInfo |
| `GetOsAccountType()` | Read from TEE | Read from OsAccountInfo | Use IInnerOsAccountManager |
| `MigrateOsAccountTypesToTee()` | Batch store to TEE | No migration needed | Directly return success |

### 2. Token Management

#### Token Generation (TaAcquireAuthorization)
```cpp
ErrCode TaAcquireAuthorization(
    const ApplyUserTokenParam &param,  // Input: permissions, user ID, auth token, etc.
    ApplyUserTokenResult &result       // Output: user token, validity period, authorization time
)
```

**Implementation Flow:**
1. Verify if user is an administrator
2. Use `TransferPrivilegeToCode` to convert permission string to permission code
3. Prepare token plaintext data
4. Generate simplified token (no encryption)
5. Return token with checksum

**Permission Code Generation:**
```cpp
std::string permissionStr(reinterpret_cast<const char*>(param.permission), param.permissionSize);
uint32_t privilegeCode = 0;
if (!TransferPrivilegeToCode(permissionStr, privilegeCode)) {
    return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
}
tokenPlain.userTokenDataPlain.privilege = privilegeCode;
```

#### Token Verification (VerifyToken)
```cpp
ErrCode VerifyToken(
    const std::vector<uint8_t> &token,      // Input: simplified token
    std::vector<uint8_t> &tokenResult       // Output: verification result
)
```

**Implementation Flow:**
1. Verify magic number (0x544F534F - "OSOT")
2. Verify version number (1)
3. Verify checksum (simple cumulative checksum)
4. Check token validity period
5. Return verification result

### 3. Simplified Token Structure

**Design Philosophy:**
- Use plaintext token structure, suitable for emulator/test scenarios
- Add basic integrity checks (magic number + version number + checksum)
- Remove complex encryption operations
- Suitable for development and test environments

**Token Structure:**
```cpp
typedef struct {
    uint32_t magic;          // Magic number: 0x544F534F ("OSOT" - OhosTee Software token)
    uint32_t version;        // Version number: 1
    UserTokenPlain tokenData; // Plaintext token data (not encrypted)
    uint32_t checksum;       // Simple checksum (computed on tokenData)
} __attribute__((__packed__)) UserTokenSoftware;
```

**Checksum Calculation:**
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

## Removed Features (Compared to Original Design)

To simplify the emulator environment implementation, the following encryption-related features have been **removed**:

### ❌ Removed Encryption Operations
- **AES-256-GCM encryption/decryption** - No longer encrypt token data
- **HMAC-SHA256 signature/verification** - Replaced with simple checksum
- **PBKDF2 key derivation** - No longer use derived keys
- **OpenSSL RAND_bytes()** - No need for random IV generation

### ❌ Removed Data Structures
- **UserTokenCrypto** structure (containing encrypted data, GCM tag, IV, HMAC signature)

### ❌ Removed Utility Functions
- `TeeSoftCrypto` class (removed all 6 static methods)
- `PrepareEncryptionKey()`
- `InitializeTokenStructure()`
- `EncryptTokenPayload()`
- `DecryptTokenPayload()`
- `SignToken()`
- `EncryptAndSignToken()`
- `VerifyTokenHmac()`
- `CopyTokenResult()`

## Error Handling Strategy

### Unified Error Codes (No Software Implementation-Specific Error Codes)

| Error Scenario | Error Code | Usage Count |
|---------|--------|---------|
| Token generation failure | `ERR_AUTHORIZATION_TA_ERROR` | 2 |
| Token verification failure (checksum mismatch, expired) | `ERR_JS_AUTHORIZATION_DENIED` | 2 |
| Parameter validation failure | `ERR_ACCOUNT_COMMON_INVALID_PARAMETER` | 8+ |
| Permission conversion failure | `ERR_ACCOUNT_COMMON_INVALID_PARAMETER` | 1 |

**Advantages:**
- ✅ Completely consistent error code interface with TEE implementation
- ✅ Upper-layer code does not need to distinguish underlying implementation
- ✅ Simplified error handling logic

## Data Storage Strategy

### Simplified Design for Software Implementation

**Does not store account types**, directly uses the system's `OsAccountInfo`:

```
┌─────────────────────────────┐
│   OsAccountInfo (System Managed)    │
│   - type: Account type           │
│   - id: Account ID              │
│   - isVerified: Whether verified      │
└─────────────────────────────┘
         ↑ Read/Write
         │
┌─────────────────────────────┐
│  OsAccountTeeAdapter        │
│  GetOsAccountType()         │
│    → Read from OsAccountInfo   │
└─────────────────────────────┘
```

**Rationale:**
- Avoid data redundancy
- Simplify implementation
- Ensure data consistency

## Code Statistics

| File | Lines | Description |
|------|------|------|
| `tee_auth_adapter_soft.cpp` | ~432 | Simplified software implementation |
| `tee_auth_adapter.h` | ~238 | Public interface |
| **Total** | **~670** | - |

**Reduction:** Approximately 268 lines (removed about 200+ lines of encryption code)

### Method Statistics

| Type | Count |
|------|------|
| Public interface methods | 8 |
| Private implementation methods | 8 |
| Utility functions | 1 (ComputeChecksum) |
| **Total** | **17** |

**Reduction:** Reduced by 11 methods (removed 14 encryption-related methods)

## Dependencies

### Removed Dependencies
- ❌ OpenSSL library: `libcrypto`, `libssl`
- ❌ OpenSSL header files: `openssl/evp.h`, `openssl/rand.h`, `openssl/hmac.h`, `openssl/aes.h`

### Current Dependencies
- ✅ Account framework: `iinner_os_account_manager.h`
- ✅ Permission mapping: `privileges_map.h` (for `TransferPrivilegeToCode`)
- ✅ Account file operations: `account_file_operator.h`
- ✅ System utilities: `securec.h`

## Security Considerations

### ⚠️ Important Limitations

**Software Implementation (Simplified Version):**
- ✅ **Suitable for:** Emulator, test, development environments
- ❌ **Not suitable for:** Production environments without TEE hardware
- ⚠️ **Security level:** Only basic integrity checks (checksum)
- ⚠️ **Token storage:** Plaintext, no encryption

**Comparison with TEE Implementation:**
| Feature | TEE Implementation | Software Implementation |
|------|---------|---------|
| Security level | Hardware-level protection | Basic integrity checks |
| Token encryption | Yes (TEE hardware) | No (plaintext) |
| Token signing | Yes (TEE) | No (simple checksum) |
| Key protection | Hardware protection | N/A |
| Use case | Production devices | Emulator/test |

## Implementation Status

### ✅ Completed Features

#### Core Features
- ✅ **pImpl pattern implementation:** Use `std::unique_ptr<Impl>` to hide implementation details
- ✅ **TEE symbol hiding:** Header file does not expose TEE types, supports conditional compilation
- ✅ **Account type operations:**
  - `SetOsAccountType()` - Simplified implementation, returns success after verification
  - `DelOsAccountType()` - Simplified implementation, directly returns success
  - `GetOsAccountType()` - Integrate `IInnerOsAccountManager` to read from `OsAccountInfo`
  - `MigrateOsAccountTypesToTee()` - Simplified implementation, no migration needed

#### Token Management
- ✅ **Token generation:** `TaAcquireAuthorization()` with permission code mapping
  - Verify admin permissions
  - Use `TransferPrivilegeToCode` to convert permission string to permission code
  - Generate simplified token with checksum
  - Include authorization time and validity period
- ✅ **Token verification:** `VerifyToken()` fully implemented
  - Magic number verification (0x544F534F)
  - Version number verification (1)
  - Checksum verification
  - Time validity check
- ✅ **Time check:** `CheckTimestampExpired()` uses `GetUptimeMs()`
- ✅ **EDM support:** `GetEdmBinAndCert()` reads EDM authentication files

#### Permission Code Generation
- ✅ **Permission string to permission code mapping:** Use `TransferPrivilegeToCode` from `privileges_map.h`
  - Convert permission strings (e.g., "ohos.permission.GET_SENSITIVE_PRIVACY")
  - Return permission code (uint32_t)
  - Error handling for invalid permissions

#### Error Handling
- ✅ **Unified error codes:** Reuse existing error codes
  - Token generation failure → `ERR_AUTHORIZATION_TA_ERROR`
  - Token verification failure → `ERR_JS_AUTHORIZATION_DENIED`
  - Parameter validation failure → `ERR_ACCOUNT_COMMON_INVALID_PARAMETER`

#### Build System
- ✅ **Conditional compilation:** Select implementation based on `is_emulator`
  - Emulator: `tee_auth_adapter_soft.cpp`
  - Real devices: `tee_auth_adapter.cpp`
- ✅ **Header file isolation:** Can compile without TEE library dependencies

### ⏳ Pending Features

#### Testing (Priority: High)
- ⏳ **Unit tests:** Create complete test suite
  - Token generation and verification tests
  - Error handling tests
  - Permission code mapping tests
- ⏳ **Integration tests:** Verify compatibility with upper-layer code
- ⏳ **Performance tests:** Compare with TEE implementation (expected to be faster)

#### Documentation (Priority: Medium)
- ⏳ **API documentation:** Detailed usage instructions and examples
- ⏳ **Architecture documentation:** Design decisions and data flow diagrams
- ⏳ **Security guide:** Security level descriptions and best practices

## Known Limitations

### Security
- ⚠️ **Cannot provide hardware-level security protection**
- Tokens are stored in plaintext without encryption protection
- Only uses simple checksum to detect data corruption
- **Use case:** Emulator, test, development environments

### Performance
- ✅ **Expected performance better than encrypted version**
- No encryption/decryption overhead
- Performance testing still needed for verification

### Compatibility
- ⚠️ **Token format differs from TEE implementation**
- Tokens generated by the two implementations are not interchangeable
- Re-generation of tokens needed during migration

## Next Steps Plan

### Short-term (1-2 weeks)
- [ ] Complete unit tests and integration tests
- [ ] Add performance benchmark tests
- [ ] Write usage documentation

### Mid-term (2-4 weeks)
- [ ] Performance optimization if needed
- [ ] Collect user feedback

### Long-term (ongoing)
- [ ] Monitor production environment issues
- [ ] Optimize functionality based on feedback
- [ ] Maintain documentation updates

## Key Decision Records

1. **pImpl pattern:** Hide TEE symbols, support conditional compilation
2. **Do not store account types:** Directly use OsAccountInfo, simplify design
3. **Unified error codes:** Reuse existing error codes, maintain interface consistency
4. **Simplified token structure:** No encryption, only basic integrity checks
5. **Permission code mapping:** Use `TransferPrivilegeToCode` to maintain consistency with system

## Related Files

### Source Code
- `services/accountmgr/include/common/tee/tee_auth_adapter.h` - Public interface
- `services/accountmgr/src/common/tee/tee_auth_adapter_soft.cpp` - Software implementation (simplified version)
- `services/accountmgr/src/common/tee/tee_auth_adapter.cpp` - TEE implementation
- `interfaces/innerkits/common/include/account_error_no.h` - Error code definitions
- `frameworks/common/privileges/include/privileges_map.h` - Permission mapping function

### Documentation
- `openspec/changes/tee-client-fallback-implementation/design.md` - Design documentation
- `openspec/changes/tee-client-fallback-implementation/specs/tee-client-software-implementation/spec.md` - Specification documentation
- `openspec/changes/tee-client-fallback-implementation/tasks.md` - Task list
- `openspec/changes/tee-client-fallback-implementation/proposal.md` - Proposal documentation

## Contact Information

For questions or suggestions, please contact:
- **Project Owner:** [To be filled]
- **Technical Review:** [To be filled]
- **Security Issues:** [To be filled]

---

**Documentation Version:** 2.0 (Simplified Implementation Version)
**Creation Date:** 2026-03-25
**Last Modified:** 2026-03-25
