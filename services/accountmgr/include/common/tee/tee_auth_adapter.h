/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OS_ACCOUNT_AUTHORIZATION_TEE_ADAPTER_H
#define OS_ACCOUNT_AUTHORIZATION_TEE_ADAPTER_H

#include <functional>
#include <stdint.h>
#include <vector>
#include <memory>
#include <securec.h>
#include "errors.h"
#include "account_error_no.h"

namespace OHOS {
namespace AccountSA {
constexpr int32_t USER_TOKEN_LEN = 2048;
constexpr int32_t AUTH_TOKEN_LEN = 1024;
constexpr int32_t PERMISSION_MAX_LEN = 1024;
constexpr size_t MAX_TOKEN_SIZE = 1024;
constexpr size_t CHALLENGE_LEN = 32;
constexpr size_t TOKEN_DATA_CIPHER_SIZE = 4;
constexpr size_t TOKEN_DATA_TAG_SIZE = 16;
constexpr size_t TOKEN_DATA_IV_SIZE = 12;
constexpr size_t TOKEN_CRYPTO_SIGN_SIZE = 32;

typedef struct {
    uint32_t pid;
    uint32_t privilege;
    uint32_t grantTime;
    int32_t grantValidityPeriod;
    uint8_t challenge[CHALLENGE_LEN];
    uint8_t authToken[AUTH_TOKEN_LEN];
    size_t authTokenSize;
} __attribute__((__packed__)) UserTokenDataPlain;

typedef struct {
    int32_t grantUserId;
} UserTokenDataToEncrypt;

typedef struct {
    UserTokenDataPlain userTokenDataPlain;
    UserTokenDataToEncrypt userTokenDataToEncrypt;
} UserTokenPlain;

typedef struct {
    uint8_t dataCipher[TOKEN_DATA_CIPHER_SIZE];
    uint8_t tag[TOKEN_DATA_TAG_SIZE];
    uint8_t iv[TOKEN_DATA_IV_SIZE];
} __attribute__((__packed__)) UserTokenDataCipher;

typedef struct {
    UserTokenPlain userTokenPlain;
    int32_t remainValidityTime;
} __attribute__((__packed__)) VerifyUserTokenResult;

struct VerifyGrantTimeResult {
    int32_t isEffective = 0;
    int32_t remainValidityTime = 0;
};

typedef struct ApplyUserTokenParam {
    uint32_t pid;
    uint8_t permission[PERMISSION_MAX_LEN + 1];
    uint8_t permissionSize;
    int32_t grantValidityPeriod;
    int32_t grantUserId;
    uint8_t authToken[AUTH_TOKEN_LEN];
    size_t authTokenSize;
    uint8_t challenge[CHALLENGE_LEN];
    ~ApplyUserTokenParam()
    {
        (void)memset_s(&authToken, authTokenSize * sizeof(uint8_t), 0, authTokenSize * sizeof(uint8_t));
        (void)memset_s(&challenge, CHALLENGE_LEN * sizeof(uint8_t), 0, CHALLENGE_LEN * sizeof(uint8_t));
    }
} __attribute__((__packed__)) ApplyUserTokenParam;

typedef struct ApplyUserTokenResult {
    uint8_t userToken[USER_TOKEN_LEN];
    size_t userTokenSize;
    int32_t remainValidityTime;
    uint32_t grantTime;
    ~ApplyUserTokenResult()
    {
        (void)memset_s(&userToken, userTokenSize * sizeof(uint8_t), 0, userTokenSize * sizeof(uint8_t));
    }
} __attribute__((__packed__)) ApplyUserTokenResult;

/**
 * @brief An adapter class for managing OS account operations with Trusted Application (TA) in TEE.
 *
 * This class provides a unified interface for interacting with TEE to perform various
 * OS account operations such as setting account type, creating accounts, deleting accounts, etc.
 *
 * Implementation details are hidden using pImpl pattern to support both TEE hardware
 * and software fallback implementations without exposing TEE client symbols.
 */
class OsAccountTeeAdapter {
public:
    OsAccountTeeAdapter();
    ~OsAccountTeeAdapter();

    // Disable copy and move
    OsAccountTeeAdapter(const OsAccountTeeAdapter&) = delete;
    OsAccountTeeAdapter& operator=(const OsAccountTeeAdapter&) = delete;
    OsAccountTeeAdapter(OsAccountTeeAdapter&&) = delete;
    OsAccountTeeAdapter& operator=(OsAccountTeeAdapter&&) = delete;

    /**
     * @brief Sets OS account type to TA.
     * @param id - Indicates the local ID of the OS account.
     * @param type - Indicates the target account type.
     * @param token - Indicates the authorization token for authentication.
     *     The length of the token should be checked before calling this function.
     * @return error code, see account_error_no.h
     */
    ErrCode SetOsAccountType(int32_t id, int32_t type, const std::vector<uint8_t>& token);

    /**
     * @brief Sets domain account type to TA for EDM (Enterprise Device Management).
     *
     * This function sets the account type for domain/enterprise accounts with dual-token
     * authentication support. The behavior varies based on token availability:
     * - If both edaToken and certToken are empty: uses EMPTY token type
     * - Otherwise: uses ENT_DEVICE_TYPE with EDA and certificate tokens for authorization
     *
     * @param id - Indicates the local ID of the OS account.
     * @param type - Indicates the target account type to set.
     * @param edaToken - Indicates the EDA (Enterprise Device Authorization) token for EDM authentication.
     *     Can be empty for non-EDM scenarios.
     * @param certToken - Indicates the certificate token for EDM authentication.
     *     Can be empty for non-EDM scenarios.
     *     The length of tokens should be checked before calling this function.
     * @return ERR_OK on success, error code on failure (see account_error_no.h)
     */
    ErrCode SetOsAccountType(int32_t id, int32_t type, const std::vector<uint8_t>& edaToken,
        const std::vector<uint8_t>& certToken);

    /**
     * @brief Deletes OS account type from TA.
     * @param id - Indicates the local ID of the OS account.
     * @param token - Indicates the authorization token for authentication.
     *     The length of the token should be checked before calling this function.
     * @return error code, see account_error_no.h
     */
    ErrCode DelOsAccountType(int32_t id, const std::vector<uint8_t>& token = {});

    /**
     * @brief Gets OS account type from TA.
     * @param id - Indicates the local ID of the OS account.
     * @param type - Indicates the output account type.
     * @return error code, see account_error_no.h
     */
    ErrCode GetOsAccountType(int32_t id, int32_t &type);

    /**
     * @brief Migrates OS account types to TA in batch.
     * @param ids - Indicates the local IDs of OS accounts to migrate.
     * @param types - Indicates the target account types for migration.
     * @return error code, see account_error_no.h
     */
    ErrCode MigrateOsAccountTypesToTee(const std::vector<int32_t> &ids, const std::vector<int32_t> &types);

    /**
     * @brief Verify token.
     * @param token - Indicates the authorization token for authentication.
     *     The length of the token should be checked before calling this function.
     * @param tokenResult - Indicates the result of token verification.
     * @return error code, see account_error_no.h
     */
    ErrCode VerifyToken(const std::vector<uint8_t>& token, std::vector<uint8_t>& tokenResult);

    /**
     * @brief Checks whether the timestamp is expired.
     * @param grantTime - Indicates the timestamp of the grant.
     * @param period - Indicates the period of the grant.
     * @param remainTimeSec - Indicates the remaining time.
     * @param isValid - Indicates whether the timestamp is valid.
     * @return error code, see account_error_no.h
     */
    ErrCode CheckTimestampExpired(const uint32_t grantTime,
        const int32_t period, int32_t &remainTimeSec, bool &isValid);

    /**
     * @brief Acquires authorization from Trusted Application (TA) in TEE.
     *
     * This method communicates with the TA to obtain an authorization token
     * for a specific privilege. The TA validates the request and returns
     * a user token if authorization is granted.
     *
     * @param param The parameters for the authorization request, including:
     *             - pid: The process ID of the requesting application
     *             - permission: The privilege string to authorize
     *             - permissionSize: Size of the privilege string
     *             - grantValidityPeriod: Validity period in seconds
     *             - grantUserId: The user ID to grant privilege
     *             - authToken: The IAM authentication token
     *             - authTokenSize: Size of the authentication token
     * @param result The output result containing:
     *             - userToken: The granted user token from TA
     *             - userTokenSize: Size of the user token
     *             - remainValidityTime: Remaining validity time in seconds
     *             - grantTime: The timestamp when privilege was granted
     * @return ERR_OK on success, error code on failure (see account_error_no.h)
     */
    ErrCode TaAcquireAuthorization(const ApplyUserTokenParam &param, ApplyUserTokenResult &result);

    /**
     * @brief Get bin and cert for EDM authentication.
     * @param binData The bin file data for authentication
     * @param certData The certificate data for authentication
     * @return ERR_OK on success, error code on failure
     */
    ErrCode GetEdmBinAndCert(std::vector<uint8_t> &binData, std::vector<uint8_t> &certData);

private:
    // pImpl pattern - hide all implementation details including TEE types
    class Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace AccountSA
} // namespace OHOS
#endif // OS_ACCOUNT_AUTHORIZATION_TEE_ADAPTER_H
