# TEE Software Implementation - Quick Reference

**Quick Reference Guide - TEE Software Implementation**

## Core Concepts

### What is TEE Software Implementation?
- Provides a software fallback solution for devices without TEE hardware (such as emulators)
- Implements the same user role authorization functionality
- Uses software encryption to replace hardware encryption

### Key Features
- ✅ **Compile-time isolation:** Select implementation through `is_emulator`
- ✅ **Unified interface:** Uses the same API as TEE implementation
- ✅ **Simplified design:** Does not store account types, directly uses OsAccountInfo
- ✅ **Simplified token structure:** Plaintext token with magic number, version, and checksum
- ✅ **No OpenSSL dependency:** Removed all encryption operations for emulator environment

## Quick Start

### Build Configuration

```gn
# In BUILD.gn
if (!is_emulator) {
  sources += [ "tee_auth_adapter.cpp" ]  # TEE implementation
  deps += [ "//third_party/tee_client" ]
} else {
  sources += [ "tee_auth_adapter_soft.cpp" ]  # Software implementation
}
```

### Usage Example

```cpp
// Create adapter (both implementations use the same interface)
OsAccountTeeAdapter adapter;

// Set account type
ErrCode ret = adapter.SetOsAccountType(userId, accountType, token);

// Get account type
int32_t type;
ret = adapter.GetOsAccountType(userId, type);

// Verify token
std::vector<uint8_t> tokenResult;
ret = adapter.VerifyToken(token, tokenResult);

// Get authorization
ApplyUserTokenParam param = { /* ... */ };
ApplyUserTokenResult result;
ret = adapter.TaAcquireAuthorization(param, result);
```

## Key Differences

### TEE Implementation vs Software Implementation

| Feature | TEE Implementation | Software Implementation |
|------|---------|---------|
| **Storage** | TEE secure storage | No storage (use OsAccountInfo) |
| **Encryption** | Hardware encryption | No encryption (plaintext) |
| **Signing** | Hardware signing | Simple checksum (cumulative) |
| **Security** | Hardware-level protection | Basic integrity checks only |
| **Performance** | Fast | Faster (no encryption overhead) |
| **Target Devices** | Devices with TEE hardware | Emulator/test environments |

## Error Handling

### Unified Error Codes

```cpp
// Encryption operation failure
return ERR_AUTHORIZATION_TA_ERROR;

// Token verification failure (HMAC mismatch, expired)
return ERR_JS_AUTHORIZATION_DENIED;

// Parameter validation failure
return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
```

**Note:** There are no software implementation-specific error codes; maintains consistency with TEE implementation.

## Token Structure (Simplified)

### Software Implementation Token

```
UserTokenSoftware {
    magic: uint32_t            // Magic number: 0x544F534F ("OSOT" - OhosTee Software token)
    version: uint32_t          // Version number: 1
    tokenData: UserTokenPlain  // Plaintext token data (not encrypted)
    checksum: uint32_t         // Simple checksum (computed from tokenData)
}
```

### Checksum Calculation

```
checksum = 0
for each byte in tokenData:
    checksum += byte
```

**Note:** This is a simple cumulative checksum for basic integrity detection, not a cryptographically secure hash.

## Debugging Tips

### Enable Logging

```cpp
ACCOUNT_LOGI("SetOsAccountType: id=%{public}d, type=%{public}d (software impl)", id, type);
ACCOUNT_LOGE("VerifyToken: token verification failed, ret=%{public}d", ret);
```

### Common Issues

**Issue:** Token verification failure
- Check: Does magic number match (0x544F534F)
- Check: Does version number match (1)
- Check: Does checksum match
- Check: Is token expired
- Check: Is token size correct

**Issue:** Token generation failure
- Check: Is user an administrator
- Check: Did permission string to privilege code conversion succeed
- Check: Are parameters valid

**Issue:** Cannot get account type
- Check: Is IInnerOsAccountManager working normally
- Check: Is there data in OsAccountInfo
- Check: Is account ID valid

## Performance Considerations

### Optimization Recommendations

1. **No encryption overhead:** Simplified implementation has better performance than encrypted version
2. **Direct system calls:** Use `IInnerOsAccountManager` to access account information efficiently
3. **Batch operations:** Reduce number of token generation and verification calls

### Performance Testing

```cpp
// Test token generation performance
auto start = std::chrono::high_resolution_clock::now();
adapter.TaAcquireAuthorization(param, result);
auto end = std::chrono::high_resolution_clock::now();
auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
```

## Security Notes

### ⚠️ Important Reminders

1. **Simplified Token Structure:**
   - Tokens are stored in plaintext without encryption
   - Only basic integrity check via cumulative checksum
   - Suitable for emulator, test, and development environments

2. **No Encryption:**
   - Removed all encryption operations (AES-256-GCM, HMAC-SHA256, PBKDF2)
   - Removed all OpenSSL dependencies
   - Token data is readable by anyone with access to the token

3. **Use Cases:**
   - ✅ Emulator environment
   - ✅ Test and development environments
   - ❌ Production environments (if TEE hardware available)

## Code Locations

### Core Files

```
services/accountmgr/
├── include/common/tee/
│   └── tee_auth_adapter.h              # Public interface
└── src/common/tee/
    ├── tee_auth_adapter.cpp            # TEE implementation
    └── tee_auth_adapter_soft.cpp       # Software implementation
```

### Key Classes and Functions

```cpp
// Public interface
class OsAccountTeeAdapter {
public:
    ErrCode SetOsAccountType(...);
    ErrCode GetOsAccountType(...);
    ErrCode VerifyToken(...);
    ErrCode TaAcquireAuthorization(...);
    // ...
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// Utility function (software implementation)
static uint32_t ComputeChecksum(const UserTokenPlain& tokenData);
```

## Documentation Links

- **Complete Design Documentation:** `design.md`
- **Implementation Summary:** `IMPLEMENTATION_SUMMARY.md`
- **Task List:** `tasks.md`
- **Project Proposal:** `proposal.md`

## Getting Help

### Related Resources

- OpenHarmony Account Subsystem Documentation
- TEE Client API Specification (for reference only)
- Permission Mapping: `privileges_map.h` (for `TransferPrivilegeToCode`)

### Common Commands

```bash
# Build software implementation
./build.sh --product-name <product> --build-target ohos_account

# Run tests
./unittest/ohos_account_test

# View logs
hdc shell hilog -T OHOS.Account
```

---

**Version:** 1.0
**Last Updated:** 2026-03-25
