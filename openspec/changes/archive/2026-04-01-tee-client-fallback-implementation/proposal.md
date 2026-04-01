## Why

The emulator environment does not support TEE (Trusted Execution Environment) hardware, but user role authorization functionality still needs to run normally. A software implementation is needed as a fallback solution to provide the same authorization functionality on emulator devices.

## What Changes

- Add a software implementation layer that provides the same interface as the TEE adapter
- Implement software-based token generation, verification, and authorization management functionality
- Achieve isolation through compile-time macros, with different build packages for different device configurations
- Refactor `tee_auth_adapter.h` to hide TEE client symbols, maintaining a single header file
- Maintain compatibility with existing interfaces without modifying upper-layer calling code
- Add unit tests and integration tests to verify the correctness of the software implementation

## Capabilities

### New Capabilities
- `tee-client-software-implementation`: Provides a software fallback implementation for the TEE client, including token management, authorization verification, encryption operations, and other functionality

### Modified Capabilities
None (this is new functionality and does not modify existing specification requirements)

## Impact

**Scope of Impact:**
- `services/accountmgr/include/common/tee/tee_auth_adapter.h` - Refactor header file to hide TEE client symbols
- `services/accountmgr/src/common/tee/tee_auth_adapter.cpp` - Existing TEE implementation (refactor internal classes)
- `services/accountmgr/src/common/tee/tee_auth_adapter_soft.cpp` - New software implementation source file
- Build system - Automatically select which .cpp file to compile based on `is_emulator`

**Dependencies:**
- Need to maintain compatibility with the existing `tee_client_api.h` interface (software implementation does not depend on this header file)
- Need to support existing cryptographic algorithms and data structures
- Need to ensure that the security of the software implementation meets basic requirements

**Compatibility:**
- For emulator devices (`is_emulator = true`): Use software implementation, no dependency on tee_client library
- For real devices (`is_emulator = false`): Use TEE implementation, link tee_client library
- API interface: Remains unchanged, upper-layer code requires no modifications
