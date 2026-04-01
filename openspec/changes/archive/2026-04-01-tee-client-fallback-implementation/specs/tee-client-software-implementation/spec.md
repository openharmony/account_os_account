## ADDED Requirements

### Requirement: Software implementation provides TEE client interface
The system SHALL provide a software implementation class that implements the same public interface as `OsAccountTeeAdapter`, including methods for token management, authorization verification, and account type operations.

#### Scenario: Software implementation class provides complete TEE adapter interface
- **WHEN** the system runs on devices without TEE hardware
- **THEN** the software implementation class SHALL provide all public methods of the TEE adapter
- **AND** method signatures SHALL be completely consistent with the TEE adapter
- **AND** return value types SHALL be compatible with existing error code definitions

### Requirement: Compile-time isolation of TEE and software implementations
The system SHALL automatically select TEE implementation or software implementation at compile time through the `is_emulator` parameter.

#### Scenario: Real device uses TEE implementation
- **WHEN** building on a real device (`is_emulator = false`)
- **THEN** the build process SHALL include TEE implementation code
- **AND** link the tee_client library
- **AND** upper-layer code uses the unified OsAccountTeeAdapter interface

#### Scenario: Emulator uses software implementation
- **WHEN** building on an emulator (`is_emulator = true`)
- **THEN** the build process SHALL only include software implementation code
- **AND** not link the tee_client library, reducing package size
- **AND** upper-layer code uses the same OsAccountTeeAdapter interface
- **AND** the API interface remains completely consistent

### Requirement: Software-based token generation and verification
The software implementation SHALL be able to generate and verify user tokens, using a simplified plaintext token structure suitable for emulator and test environments.

#### Scenario: Generate user token
- **WHEN** an application requests a user token and provides valid authorization parameters
- **THEN** the software SHALL generate a simplified token containing user ID, permissions, timestamp, and other information
- **AND** the token SHALL use a plaintext structure with header identification (magic number and version) and checksum for integrity
- **AND** the permission string SHALL be converted to privilege code using `TransferPrivilegeToCode`
- **AND** the generated token format is simplified and differs from the TEE implementation

#### Scenario: Verify user token
- **WHEN** the system receives a user token verification request
- **THEN** the software SHALL verify the token's magic number, version number, and checksum
- **AND** after successful verification, SHALL return the user information and remaining validity time in the token
- **AND** if the token is expired or invalid, SHALL return the corresponding error code

### Requirement: Account type management without TEE
The software implementation SHALL support account type setting, retrieval, and deletion operations, using local storage to replace TEE's secure storage.

#### Scenario: Set account type
- **WHEN** requesting to set account type and providing a valid authorization token
- **THEN** the software SHALL verify the validity of the token
- **AND** after successful verification, SHALL store the account type information in local secure storage
- **AND** SHALL return a success status code

#### Scenario: Get account type
- **WHEN** requesting to get the type of a specified account
- **THEN** the software SHALL read the account type information from local storage
- **AND** SHALL return the account type or corresponding error code (e.g., account does not exist)

#### Scenario: Delete account type
- **WHEN** requesting to delete account type and providing a valid authorization token
- **THEN** the software SHALL verify the validity of the token
- **AND** after successful verification, SHALL delete the account type information from local storage
- **AND** SHALL return a success status code

### Requirement: Authorization management with simplified token structure
The software implementation SHALL support authorization management functionality, including permission granting, token application, and timestamp verification, using a simplified plaintext token structure suitable for emulator environments.

#### Scenario: Apply for authorization token
- **WHEN** an application applies for permission authorization and provides valid parameters
- **THEN** the software SHALL verify the user is an administrator
- **AND** SHALL convert the permission string to privilege code using `TransferPrivilegeToCode`
- **AND** after successful verification, SHALL generate a simplified user token containing permissions, validity period, and other information
- **AND** the token SHALL include a checksum for basic integrity detection

#### Scenario: Verify authorization timestamp
- **WHEN** the system verifies the authorization token's timestamp
- **THEN** the software SHALL calculate the difference between the current time and the authorization time
- **AND** SHALL check if it exceeds the validity period
- **AND** SHALL return whether it is valid and the remaining validity time

### Requirement: Data structure compatibility
The software implementation SHALL use a simplified token structure compatible with the public interface but adapted for emulator environments.

#### Scenario: Use simplified token data structures
- **WHEN** the software implementation generates or parses tokens
- **THEN** SHALL use the simplified `UserTokenSoftware` structure containing:
  - `magic`: Magic number (0x544F534F - "OSOT" - OhosTee Software token)
  - `version`: Version number (1)
  - `tokenData`: Plaintext token data (UserTokenPlain, not encrypted)
  - `checksum`: Simple cumulative checksum for basic integrity detection
- **AND** SHALL maintain compatibility with the `UserTokenPlain` structure used by TEE implementation
- **AND** constant values (such as challenge length, etc.) SHALL remain consistent with the TEE implementation
- **AND** the token format differs from TEE implementation and is not interchangeable

### Requirement: Simplified storage for software implementation
The software implementation SHALL use the system's existing `OsAccountInfo` for account type storage and SHALL NOT use additional file storage for account types.

#### Scenario: No additional storage for account types
- **WHEN** the software implementation needs to store or retrieve account type information
- **THEN** SHALL directly use the `type` field in `OsAccountInfo` managed by the system
- **AND** SHALL NOT create additional files for account type storage
- **AND** tokens are generated and verified but not persistently stored by the adapter

#### Scenario: EDM file reading
- **WHEN** the software implementation needs to read EDM authentication files
- **THEN** SHALL read `/data/service/el1/public/cust/enterprise/eda.bin` for EDM binary data
- **AND** SHALL read `/etc/edm/cacert.pem` for EDM certificate data

### Requirement: Error handling and fallback
The software implementation SHALL provide comprehensive error handling mechanisms, using unified error codes consistent with the TEE implementation.

#### Scenario: Token generation operation fails
- **WHEN** token generation operations fail
- **THEN** the system SHALL return `ERR_AUTHORIZATION_TA_ERROR`
- **AND** error information SHALL be recorded in system logs

#### Scenario: Token verification fails
- **WHEN** token verification fails (checksum mismatch, expired, invalid format)
- **THEN** the system SHALL return `ERR_JS_AUTHORIZATION_DENIED` or `ERR_ACCOUNT_COMMON_INVALID_PARAMETER`
- **AND** error information SHALL be recorded in system logs

#### Scenario: Parameter validation fails
- **WHEN** input parameters are invalid
- **THEN** the system SHALL return `ERR_ACCOUNT_COMMON_INVALID_PARAMETER`
- **AND** error information SHALL be recorded in system logs

### Requirement: Configuration and build system support
The build system SHALL automatically select TEE implementation or software implementation based on the `is_emulator` parameter.

#### Scenario: BUILD.gn uses is_emulator
- **WHEN** using `is_emulator` in BUILD.gn
- **THEN** if `is_emulator = false` (real device), SHALL include TEE implementation code and dependencies
- **AND** if `is_emulator = true` (emulator), SHALL include software implementation code
- **AND** no need to set preprocessor macro definitions

### Requirement: Testing and validation
The software implementation SHALL include complete unit tests and integration tests to ensure functional correctness and compatibility with the TEE implementation.

#### Scenario: Unit tests cover all software implementation methods
- **WHEN** running the unit test suite
- **THEN** all public methods of the software implementation SHALL have corresponding test cases
- **AND** tests SHALL cover both normal flows and error scenarios
- **AND** test coverage SHALL meet project requirements

#### Scenario: Integration tests verify compatibility with existing systems
- **WHEN** running integration tests
- **THEN** tests SHALL verify the compatibility of the software implementation with upper-layer calling code
- **AND** tests SHALL verify token format compatibility with the TEE implementation
- **AND** tests SHALL verify the correctness of data persistence and recovery
