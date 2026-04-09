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

#include "tee_auth_adapter.h"

#include <fstream>
#include <securec.h>
#include <string>
#include "account_file_operator.h"
#include "account_log_wrapper.h"
#include "authorization_manager/privilege_utils.h"  // For GetUptimeMs
#include "iinner_os_account_manager.h"  // For GetOsAccountInfoById
#include "privileges_map.h"  // For TransferPrivilegeToCode

namespace OHOS {
namespace AccountSA {
namespace {
    // Software implementation token structure (simplified, no encryption)
    // Uses plaintext token structure with header identifier and checksum only
    typedef struct {
        uint32_t magic;          // Magic number: 0x544F534F
        uint32_t version;        // Version: 1
        UserTokenPlain tokenData; // Plaintext token data (not encrypted)
        uint32_t checksum;       // Simple checksum (computed from tokenData)
    } __attribute__((__packed__)) UserTokenSoftware;

    // Token constants
    constexpr uint32_t TOKEN_MAGIC = 0x544F534F;
    constexpr uint32_t TOKEN_VERSION = 1;
    constexpr int64_t MILLIS_PER_SECOND = 1000;
}

// Simplified checksum calculation (simple cumulative checksum for data corruption detection)
static uint32_t ComputeChecksum(const UserTokenPlain& tokenData)
{
    const uint8_t* data = reinterpret_cast<const uint8_t*>(&tokenData);
    uint32_t checksum = 0;
    for (size_t i = 0; i < sizeof(UserTokenPlain); ++i) {
        checksum += data[i];
    }
    return checksum;
}

// Note: Account type storage is NOT needed in software implementation.
// The account type is directly managed by OsAccountInfo in the system layer.
// This simplifies the design and avoids data redundancy.

// Software implementation of OsAccountTeeAdapter::Impl
class OsAccountTeeAdapter::Impl {
public:
    Impl() = default;
    ~Impl() = default;

    ErrCode SetOsAccountType(int32_t id, int32_t type, const std::vector<uint8_t>& token)
    {
        if (id <= 0 || token.empty()) {
            ACCOUNT_LOGE("Invalid parameters, id=%{public}d (must>0), tokenSize=%{public}zu (must>0)",
                         id, token.size());
            return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
        }

        // Software implementation: Validate token and return success
        // The actual account type storage is managed by OsAccountManager in OsAccountInfo
        ACCOUNT_LOGI("Id=%{public}d, type=%{public}d, tokenSize=%{public}zu (software impl)",
                     id, type, token.size());
        return ERR_OK;
    }

    ErrCode SetOsAccountType(int32_t id, int32_t type,
        const std::vector<uint8_t>& edaToken, const std::vector<uint8_t>& certToken)
    {
        if (id <= 0) {
            ACCOUNT_LOGE("Invalid id=%{public}d (must>0), type=%{public}d (EDM mode)", id, type);
            return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
        }

        // Software implementation: Return success
        // OsAccountManager will update OsAccountInfo.type
        ACCOUNT_LOGI("Id=%{public}d, type=%{public}d, edaSize=%{public}zu, certSize=%{public}zu (software impl)",
                     id, type, edaToken.size(), certToken.size());
        return ERR_OK;
    }

    ErrCode DelOsAccountType(int32_t id, const std::vector<uint8_t>& token)
    {
        if (id <= 0) {
            ACCOUNT_LOGE("Invalid id=%{public}d (must>0), tokenSize=%{public}zu", id, token.size());
            return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
        }

        // Software implementation: Return success
        // OsAccountManager will handle the actual deletion from OsAccountInfo
        ACCOUNT_LOGI("Id=%{public}d, tokenSize=%{public}zu (software impl)", id, token.size());
        return ERR_OK;
    }

    ErrCode GetOsAccountType(int32_t id, int32_t& type)
    {
        if (id <= 0) {
            ACCOUNT_LOGE("Invalid id=%{public}d (must>0)", id);
            return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
        }

        // Software implementation: Get account info first, then return type
        OsAccountInfo osAccountInfo;
        ErrCode ret = IInnerOsAccountManager::GetInstance().GetOsAccountInfoById(id, osAccountInfo);
        if (ret == ERR_OK) {
            type = static_cast<int32_t>(osAccountInfo.GetType());
            ACCOUNT_LOGI("Id=%{public}d, type=%{public}d (software impl from OsAccountInfo)",
                         id, type);
        } else {
            ACCOUNT_LOGE("Failed to get account info for id=%{public}d, ret=%{public}d, check if account exists",
                         id, ret);
        }
        return ret;
    }

    ErrCode MigrateOsAccountTypesToTee(const std::vector<int32_t>& ids, const std::vector<int32_t>& types)
    {
        if (ids.empty() || types.empty() || ids.size() != types.size()) {
            ACCOUNT_LOGE("Invalid parameters, ids.size()=%{public}zu, types.size()=%{public}zu",
                         ids.size(), types.size());
            return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
        }

        // Software implementation: No migration needed
        // Account types are already in OsAccountInfo
        ACCOUNT_LOGI("%{public}zu accounts (software impl - no-op, types already in OsAccountInfo",
                     ids.size());
        return ERR_OK;
    }

    ErrCode VerifyToken(const std::vector<uint8_t>& token,
        const std::string &privilege, std::vector<uint8_t>& tokenResult)
    {
        if (token.empty()) {
            ACCOUNT_LOGE("Token is empty, tokenSize=%{public}zu (must>0)", token.size());
            return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
        }

        tokenResult.resize(sizeof(VerifyUserTokenResult));
        VerifyUserTokenResult* result = reinterpret_cast<VerifyUserTokenResult*>(tokenResult.data());

        ErrCode ret = VerifySoftwareToken(token, *result);
        if (ret != ERR_OK) {
            ACCOUNT_LOGE("Token verification failed, tokenSize=%{public}zu, ret=%{public}d",
                         token.size(), ret);
            return ret;
        }

        return ERR_OK;
    }

    ErrCode CheckTimestampExpired(const uint32_t grantTime, const int32_t period,
        int32_t& remainTimeSec, bool& isValid)
    {
        // Get current time in seconds using GetUptimeMs
        int64_t currentTimeMs = 0;
        ErrCode ret = GetUptimeMs(currentTimeMs);
        if (ret != ERR_OK) {
            ACCOUNT_LOGE("Failed to get current time, ret=%{public}d", ret);
            return ret;
        }
        uint32_t currentTime = static_cast<uint32_t>(currentTimeMs / MILLIS_PER_SECOND);  // Convert ms to seconds

        if (period <= 0) {
            // Software implementation: permanent tokens (period=0) are not supported
            ACCOUNT_LOGE("Permanent tokens not supported in software impl, period=%{public}d", period);
            remainTimeSec = -1;
            isValid = false;
            return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
        }

        // Prevent underflow: check if currentTime < grantTime
        if (currentTime < grantTime) {
            ACCOUNT_LOGW("System time appears to be before grant time, curr=%{public}u, grant=%{public}u",
                         currentTime, grantTime);
            // Time anomaly, reject token
            remainTimeSec = 0;
            isValid = false;
            return ERR_ACCOUNT_COMMON_OPERATION_FAIL;
        }

        // Safe to subtract: currentTime >= grantTime
        uint32_t elapsedTime = currentTime - grantTime;

        if (elapsedTime <= static_cast<uint32_t>(period)) {
            remainTimeSec = period - static_cast<int32_t>(elapsedTime);
            isValid = true;
        } else {
            remainTimeSec = 0;
            isValid = false;
        }

        return ERR_OK;
    }

    ErrCode TaAcquireAuthorization(const ApplyUserTokenParam& param, ApplyUserTokenResult& result)
    {
        int32_t accountType = -1;
        ErrCode ret = GetOsAccountType(param.grantUserId, accountType);
        if (ret != ERR_OK) {
            ACCOUNT_LOGE("Failed to get account type for userId=%{public}d, ret=%{public}d",
                         param.grantUserId, ret);
            return ret;
        }
        if (accountType != OsAccountType::ADMIN) {
            ACCOUNT_LOGE("UserId=%{public}d is not admin (accountType=%{public}d)",
                param.grantUserId, accountType);
            return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
        }

        ret = GenerateSoftwareToken(param, result);
        if (ret != ERR_OK) {
            ACCOUNT_LOGE("Failed to generate software token for userId=%{public}d, ret=%{public}d",
                         param.grantUserId, ret);
            return ERR_AUTHORIZATION_TA_ERROR;
        }

        return ERR_OK;
    }

    ErrCode GetEdmBinAndCert(std::vector<uint8_t>& binData, std::vector<uint8_t>& certData)
    {
        std::string binPath = "/data/service/el1/public/cust/enterprise/eda.bin";
        std::string certPath = "/etc/edm/cacert.pem";

        ErrCode errCode = GetFileContextWithNoLock(binPath, binData);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("Failed to read EDM bin file, path=%{public}s, errCode=%{public}d",
                         binPath.c_str(), errCode);
            return errCode;
        }

        errCode = GetFileContextWithNoLock(certPath, certData);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("Failed to read EDM cert file, path=%{public}s, errCode=%{public}d",
                         certPath.c_str(), errCode);
            return errCode;
        }

        ACCOUNT_LOGI("Successfully loaded EDM bin and cert, binSize=%{public}zu, certSize=%{public}zu",
                     binData.size(), certData.size());
        return ERR_OK;
    }

private:
    ErrCode PrepareTokenPlainData(const ApplyUserTokenParam& param, UserTokenPlain& tokenPlain)
    {
        tokenPlain.userTokenDataPlain.pid = param.pid;

        // Keep parity with the TEE path: admin tokens may be issued without a specific privilege.
        if (param.permissionSize == 0) {
            tokenPlain.userTokenDataPlain.privilege = 0;
        } else {
            std::string permissionStr(reinterpret_cast<const char*>(param.permission), param.permissionSize);
            uint32_t privilegeCode = 0;
            if (!TransferPrivilegeToCode(permissionStr, privilegeCode)) {
                ACCOUNT_LOGE("Failed to map permission to privilege code, permissionStr=%{public}s",
                    permissionStr.c_str());
                return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
            }
            tokenPlain.userTokenDataPlain.privilege = privilegeCode;
        }

        // Get current time in seconds using GetUptimeMs
        int64_t currentTimeMs = 0;
        ErrCode ret = GetUptimeMs(currentTimeMs);
        if (ret != ERR_OK) {
            ACCOUNT_LOGE("Failed to get current time for token grant, ret=%{public}d", ret);
            return ret;
        }
        uint32_t currentTimeSeconds = static_cast<uint32_t>(currentTimeMs / MILLIS_PER_SECOND);

        // Validate grantValidityPeriod
        if (param.grantValidityPeriod <= 0) {
            ACCOUNT_LOGE("Invalid grantValidityPeriod=%{public}d", param.grantValidityPeriod);
            return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
        }

        tokenPlain.userTokenDataPlain.grantTime = currentTimeSeconds;
        tokenPlain.userTokenDataPlain.grantValidityPeriod = param.grantValidityPeriod;
        tokenPlain.userTokenDataPlain.authTokenSize = 0;

        // Clear auth token in software implementation (not stored in token for security)
        if (memset_s(tokenPlain.userTokenDataPlain.authToken, AUTH_TOKEN_LEN, 0, AUTH_TOKEN_LEN) != 0) {
            ACCOUNT_LOGE("Failed to clear auth token for security (memset_s error), userId=%{public}d",
                         param.grantUserId);
            return ERR_AUTHORIZATION_TA_ERROR;
        }

        if (memcpy_s(tokenPlain.userTokenDataPlain.challenge, CHALLENGE_LEN,
            param.challenge, CHALLENGE_LEN) != 0) {
            ACCOUNT_LOGE("Failed to copy challenge data, userId=%{public}d", param.grantUserId);
            return ERR_AUTHORIZATION_TA_ERROR;
        }

        tokenPlain.userTokenDataToEncrypt.grantUserId = param.grantUserId;
        return ERR_OK;
    }

    ErrCode CheckTokenValidity(const UserTokenPlain& tokenPlain, VerifyUserTokenResult& result)
    {
        // Get current time in seconds using GetUptimeMs
        int64_t currentTimeMs = 0;
        ErrCode ret = GetUptimeMs(currentTimeMs);
        if (ret != ERR_OK) {
            ACCOUNT_LOGE("Failed to get current time to check token expiry, ret=%{public}d", ret);
            return ret;
        }
        uint32_t currentTime = static_cast<uint32_t>(currentTimeMs / MILLIS_PER_SECOND);

        uint32_t grantTime = tokenPlain.userTokenDataPlain.grantTime;
        int32_t period = tokenPlain.userTokenDataPlain.grantValidityPeriod;
        result.userTokenPlain.userTokenDataPlain.pid = tokenPlain.userTokenDataPlain.pid;

        // Validate period parameter
        if (period <= 0) {
            ACCOUNT_LOGE("Invalid period=%{public}d", period);
            result.remainValidityTime = -1;
            return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
        }

        // Prevent underflow: check if currentTime < grantTime
        if (currentTime < grantTime) {
            ACCOUNT_LOGW("System time appears to be before grant time, curr=%{public}u, grant=%{public}u",
                         currentTime, grantTime);
            result.remainValidityTime = 0;
            return ERR_JS_AUTHORIZATION_DENIED;
        }

        // Safe to subtract: currentTime >= grantTime
        uint32_t elapsedTime = currentTime - grantTime;

        if (elapsedTime <= static_cast<uint32_t>(period)) {
            result.remainValidityTime = period - static_cast<int32_t>(elapsedTime);
            return ERR_OK;
        }

        // Token expired
        ACCOUNT_LOGW("Token expired, grant=%{public}u, curr=%{public}u, period=%{public}d, elapsed=%{public}u",
                     grantTime, currentTime, period, elapsedTime);
        result.remainValidityTime = 0;
        return ERR_JS_AUTHORIZATION_DENIED;
    }

    ErrCode GenerateSoftwareToken(const ApplyUserTokenParam& param, ApplyUserTokenResult& result)
    {
        // Prepare token data
        UserTokenPlain tokenPlain;
        ErrCode ret = PrepareTokenPlainData(param, tokenPlain);
        if (ret != ERR_OK) {
            ACCOUNT_LOGE("Failed to prepare token data for userId=%{public}d, ret=%{public}d",
                         param.grantUserId, ret);
            return ret;
        }

        // Build software token structure
        UserTokenSoftware softwareToken;
        softwareToken.magic = TOKEN_MAGIC;
        softwareToken.version = TOKEN_VERSION;
        softwareToken.tokenData = tokenPlain;
        softwareToken.checksum = ComputeChecksum(tokenPlain);

        // Copy to result
        if (memcpy_s(result.userToken, USER_TOKEN_LEN, &softwareToken, sizeof(UserTokenSoftware)) != 0) {
            ACCOUNT_LOGE("Failed to copy token data to result, userId=%{public}d", param.grantUserId);
            return ERR_AUTHORIZATION_TA_ERROR;
        }
        result.userTokenSize = sizeof(UserTokenSoftware);
        result.remainValidityTime = param.grantValidityPeriod;
        result.grantTime = tokenPlain.userTokenDataPlain.grantTime;

        ACCOUNT_LOGI("Success, userId=%{public}d, grantTime=%{public}u, validity=%{public}d sec, tokenSize=%{public}zu",
                     param.grantUserId, result.grantTime, result.remainValidityTime, result.userTokenSize);
        return ERR_OK;
    }

    ErrCode VerifySoftwareToken(const std::vector<uint8_t>& token, VerifyUserTokenResult& result)
    {
        if (token.size() != sizeof(UserTokenSoftware)) {
            ACCOUNT_LOGE("Token size mismatch, expected=%{public}zu, got=%{public}zu",
                         sizeof(UserTokenSoftware), token.size());
            return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
        }

        const UserTokenSoftware* softwareToken = reinterpret_cast<const UserTokenSoftware*>(token.data());

        // Verify magic number
        if (softwareToken->magic != TOKEN_MAGIC) {
            ACCOUNT_LOGE("Invalid magic number, expected=0x%{public}x, got=0x%{public}x",
                         TOKEN_MAGIC, softwareToken->magic);
            return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
        }

        // Verify version
        if (softwareToken->version != TOKEN_VERSION) {
            ACCOUNT_LOGE("Unsupported version, expected=%{public}u, got=%{public}u",
                         TOKEN_VERSION, softwareToken->version);
            return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
        }

        // Verify checksum
        uint32_t computedChecksum = ComputeChecksum(softwareToken->tokenData);
        if (softwareToken->checksum != computedChecksum) {
            ACCOUNT_LOGE("Checksum mismatch, expected=%{public}u, got=%{public}u",
                         computedChecksum, softwareToken->checksum);
            return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
        }

        // Check token validity
        return CheckTokenValidity(softwareToken->tokenData, result);
    }

    static ErrCode GetFileContextWithNoLock(const std::string& path, std::vector<uint8_t>& byteData)
    {
        AccountFileOperator fileOperator;
        ErrCode err = fileOperator.CheckFileExistence(path);
        if (err != ERR_OK) {
            return err;
        }

        byteData.clear();
        std::ifstream file(path);
        if (!file.is_open()) {
            return ERR_ACCOUNT_COMMON_FILE_OPEN_FAILED;
        }

        std::copy(
            std::istreambuf_iterator<char>(file),
            std::istreambuf_iterator<char>(),
            std::back_inserter(byteData));

        return ERR_OK;
    }
};

// Public interface implementation - delegates to pImpl
OsAccountTeeAdapter::OsAccountTeeAdapter() : impl_(std::make_unique<Impl>()) {}
OsAccountTeeAdapter::~OsAccountTeeAdapter() = default;

ErrCode OsAccountTeeAdapter::GetOsAccountType(int32_t id, int32_t& type)
{
    return impl_->GetOsAccountType(id, type);
}

ErrCode OsAccountTeeAdapter::SetOsAccountType(int32_t id, int32_t type, const std::vector<uint8_t>& token)
{
    return impl_->SetOsAccountType(id, type, token);
}

ErrCode OsAccountTeeAdapter::SetOsAccountType(int32_t id, int32_t type,
    const std::vector<uint8_t>& edaToken, const std::vector<uint8_t>& certToken)
{
    return impl_->SetOsAccountType(id, type, edaToken, certToken);
}

ErrCode OsAccountTeeAdapter::DelOsAccountType(int32_t id, const std::vector<uint8_t>& token)
{
    return impl_->DelOsAccountType(id, token);
}

ErrCode OsAccountTeeAdapter::MigrateOsAccountTypesToTee(
    const std::vector<int32_t>& ids, const std::vector<int32_t>& types)
{
    return impl_->MigrateOsAccountTypesToTee(ids, types);
}

ErrCode OsAccountTeeAdapter::VerifyToken(
    const std::vector<uint8_t>& token, const std::string &privilege, std::vector<uint8_t>& tokenResult)
{
    return impl_->VerifyToken(token, privilege, tokenResult);
}

ErrCode OsAccountTeeAdapter::CheckTimestampExpired(const uint32_t grantTime, const int32_t period,
    int32_t& remainTimeSec, bool& isValid)
{
    return impl_->CheckTimestampExpired(grantTime, period, remainTimeSec, isValid);
}

ErrCode OsAccountTeeAdapter::TaAcquireAuthorization(const ApplyUserTokenParam& param, ApplyUserTokenResult& result)
{
    return impl_->TaAcquireAuthorization(param, result);
}

ErrCode OsAccountTeeAdapter::GetEdmBinAndCert(std::vector<uint8_t>& binData, std::vector<uint8_t>& certData)
{
    return impl_->GetEdmBinAndCert(binData, certData);
}

} // namespace AccountSA
} // namespace OHOS
