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
#include <mutex>
#include "account_file_operator.h"
#include "account_log_wrapper.h"
#include "tee_client_api.h"  // TEE API only included in .cpp file

namespace OHOS {
namespace AccountSA {
namespace {
    constexpr uint32_t INDEX_ZERO = 0;
    constexpr uint32_t INDEX_ONE = 1;
    constexpr uint32_t INDEX_TWO = 2;
    constexpr uint32_t INDEX_THREE = 3;
    constexpr uint32_t ADMIN_TOKEN_TYPE = 0;
    constexpr uint32_t ENT_DEVICE_TYPE = 1;
    constexpr uint32_t NO_TOKEN_TYPE = 2;
    constexpr TEEC_Result TEEC_ERROR_USER_TOKEN_INVALID = static_cast<TEEC_Result>(0x10000004);
    constexpr TEEC_Result TEEC_ERROR_USER_TOKEN_EXPIRED = static_cast<TEEC_Result>(0x10000005);
    constexpr TEEC_Result TEEC_ERROR_REACH_LIMIT = static_cast<TEEC_Result>(0xFFFF7108);
    uint8_t g_taPATH[] = "/vendor/bin/edab8b4f-3bfd-486d-863c-ca04744e49d0.sec";
    const TEEC_UUID ACCOUNT_TA_UUID = {
        0xedab8b4f, 0x3bfd, 0x486d,
        {0x86, 0x3c, 0xca, 0x04, 0x74, 0x4e, 0x49, 0xd0}
    };
    enum TA_CommonId : uint32_t {
        USER_ROLE_GET_VERSION_CMD_ID = 0x00000001,
        USER_ROLE_SET_CMD_ID = 0x00010001,
        USER_ROLE_DELETE_CMD_ID = 0x00010002,
        USER_ROLE_GET_CMD_ID = 0x00010003,
        USER_TOKEN_VERIFY_CMD_ID = 0x00020002,
        CHECK_TIMESTAMP_EXPIRE_CMD_ID = 0x00020003,
        USER_TOKEN_APPLY_CMD_ID = 0x00020001,
        USER_ROLE_BATCH_SET_CMD_ID = 0X00010004,
    };
}

// pImpl implementation class - contains all TEE-specific implementation details
class OsAccountTeeAdapter::Impl {
public:
    Impl() = default;
    ~Impl() = default;

    // Disable copy and move
    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;
    Impl(Impl&&) = delete;
    Impl& operator=(Impl&&) = delete;

    ErrCode GetOsAccountType(int32_t id, int32_t &type);
    ErrCode SetOsAccountType(int32_t id, int32_t type, const std::vector<uint8_t>& token);
    ErrCode SetOsAccountType(int32_t id, int32_t type, const std::vector<uint8_t>& edaToken,
        const std::vector<uint8_t>& certToken);
    ErrCode DelOsAccountType(int32_t id, const std::vector<uint8_t>& token);
    ErrCode MigrateOsAccountTypesToTee(const std::vector<int32_t> &ids, const std::vector<int32_t> &types);
    ErrCode VerifyToken(const std::vector<uint8_t>& token,
        const std::string &privilege, std::vector<uint8_t>& tokenResult);
    ErrCode CheckTimestampExpired(const uint32_t grantTime, const int32_t period,
        int32_t &remainTimeSec, bool &isValid);
    ErrCode TaAcquireAuthorization(const ApplyUserTokenParam &param, ApplyUserTokenResult &result);
    ErrCode GetEdmBinAndCert(std::vector<uint8_t> &binData, std::vector<uint8_t> &certData);

private:
    /**
     * @brief A RAII wrapper class for TEEC_Context.
     * Moved to pImpl implementation to hide TEE types.
     */
    class TeecContextGuard {
    public:
        TeecContextGuard() = default;
        ~TeecContextGuard();

        // Disable copy and move
        TeecContextGuard(const TeecContextGuard&) = delete;
        TeecContextGuard& operator=(const TeecContextGuard&) = delete;
        TeecContextGuard(TeecContextGuard&&) = delete;
        TeecContextGuard& operator=(TeecContextGuard&&) = delete;

        TEEC_Result Initialize();
        TEEC_Context* Get() { return &context_; }
        bool IsInitialized() const { return initResult_ == TEEC_SUCCESS; }

    private:
        TEEC_Context context_;
        std::once_flag initFlag_;
        TEEC_Result initResult_ = TEEC_ERROR_GENERIC;
    };

    /**
     * @brief A RAII wrapper class for TEEC_Session.
     * Moved to pImpl implementation to hide TEE types.
     */
    class TeecSessionGuard {
    public:
        TeecSessionGuard() = default;
        ~TeecSessionGuard();

        // Disable copy and move
        TeecSessionGuard(const TeecSessionGuard&) = delete;
        TeecSessionGuard& operator=(const TeecSessionGuard&) = delete;
        TeecSessionGuard(TeecSessionGuard&&) = delete;
        TeecSessionGuard& operator=(TeecSessionGuard&&) = delete;

        TEEC_Result Open(TEEC_Context* context, const TEEC_UUID* uuid);
        TEEC_Session* Get() { return &session_; }
        bool IsOpened() const { return openResult_ == TEEC_SUCCESS; }

    private:
        TEEC_Session session_;
        std::once_flag openFlag_;
        TEEC_Result openResult_ = TEEC_ERROR_GENERIC;
    };

    /**
     * @brief Executes TA command with given parameters.
     */
    ErrCode ExecuteCommand(uint32_t command, const std::function<ErrCode(TEEC_Operation&)>& setParams,
        const std::function<ErrCode(TEEC_Operation&)>& processResult = nullptr);

    /**
     * @brief Converts TEEC error code to account error code.
     */
    static ErrCode ConvertTeecErrCode(TEEC_Result teeResult);
};

// TeecContextGuard implementation
OsAccountTeeAdapter::Impl::TeecContextGuard::~TeecContextGuard()
{
    if (initResult_ == TEEC_SUCCESS) {
        TEEC_FinalizeContext(&context_);
    }
}

TEEC_Result OsAccountTeeAdapter::Impl::TeecContextGuard::Initialize()
{
    std::call_once(initFlag_, [&]() {
        initResult_ = TEEC_InitializeContext(nullptr, &context_);
        if (initResult_ == TEEC_SUCCESS) {
            context_.ta_path = g_taPATH;
        }
    });
    return initResult_;
}

// TeecSessionGuard implementation
TEEC_Result OsAccountTeeAdapter::Impl::TeecSessionGuard::Open(TEEC_Context* context, const TEEC_UUID* uuid)
{
    std::call_once(openFlag_, [&]() {
        uint32_t origin = 0;
        TEEC_Operation dummyOperation = {};
        dummyOperation.started = 1;
        dummyOperation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

        openResult_ = TEEC_OpenSession(context, &session_, uuid,
            TEEC_LOGIN_IDENTIFY, nullptr, &dummyOperation, &origin);
    });
    return openResult_;
}

OsAccountTeeAdapter::Impl::TeecSessionGuard::~TeecSessionGuard()
{
    if (openResult_ == TEEC_SUCCESS) {
        TEEC_CloseSession(&session_);
    }
}

ErrCode OsAccountTeeAdapter::Impl::ConvertTeecErrCode(TEEC_Result teeResult)
{
    switch (teeResult) {
        case TEEC_ERROR_ACCESS_DENIED:
            return ERR_ACCOUNT_COMMON_TEE_PERMISSION_DENIED;
        case TEEC_ERROR_BAD_PARAMETERS:
            return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
        case TEEC_ERROR_USER_TOKEN_INVALID:
            return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
        case TEEC_ERROR_USER_TOKEN_EXPIRED:
            return ERR_JS_AUTHORIZATION_DENIED;
        case TEEC_ERROR_REACH_LIMIT:
            return ERR_ACCOUNT_COMMON_TEE_REACH_LIMIT;
        default:
            return ERR_ACCOUNT_COMMON_OPERATION_FAIL;
    }
}

ErrCode OsAccountTeeAdapter::Impl::ExecuteCommand(
    uint32_t command, const std::function<ErrCode(TEEC_Operation &)> &setParams,
    const std::function<ErrCode(TEEC_Operation &)> &processResult)
{
    // Initialize TEE context
    TeecContextGuard contextGuard;
    TEEC_Result result = contextGuard.Initialize();
    if (result != TEEC_SUCCESS) {
        ACCOUNT_LOGE("TEEC_InitializeContext failed, result: %{public}u", result);
        return ERR_ACCOUNT_COMMON_OPERATION_FAIL;
    }
    // Open TEE session
    TeecSessionGuard sessionGuard;
    result = sessionGuard.Open(contextGuard.Get(), &ACCOUNT_TA_UUID);
    if (result != TEEC_SUCCESS) {
        ACCOUNT_LOGE("TEEC_OpenSession failed, result: %{public}u", result);
        return ERR_ACCOUNT_COMMON_OPERATION_FAIL;
    }
    TEEC_Operation operation = {0};
    ErrCode ret = setParams(operation);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("setParams failed, ret: %{public}d", ret);
        return ret;
    }
    uint32_t origin = 0;
    result = TEEC_InvokeCommand(sessionGuard.Get(), command, &operation, &origin);
    if (result != TEEC_SUCCESS) {
        ACCOUNT_LOGE("TEEC_InvokeCommand failed, command: %{public}u, result: 0x%{public}x, origin: %{public}u",
            command, result, origin);
        return ConvertTeecErrCode(result);
    }
    if (processResult != nullptr) {
        return processResult(operation);
    }
    return ERR_OK;
}

ErrCode OsAccountTeeAdapter::Impl::GetOsAccountType(int32_t id, int32_t &type)
{
    std::function<ErrCode(TEEC_Operation &)> setParamTask = [id](TEEC_Operation &operation) {
        operation.started = 1;
        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_NONE);
        operation.params[INDEX_ZERO].value.a = static_cast<uint32_t>(id);
        return ERR_OK;
    };
    std::function<ErrCode(TEEC_Operation &)> processResultTask = [&type](TEEC_Operation &operation) {
        type = static_cast<int32_t>(operation.params[INDEX_ONE].value.a);
        return ERR_OK;
    };
    ErrCode ret = ExecuteCommand(USER_ROLE_GET_CMD_ID, setParamTask, processResultTask);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("GetOsAccountType failed, ret = %{public}d", ret);
    }
    return ret;
}

ErrCode OsAccountTeeAdapter::Impl::SetOsAccountType(int32_t id, int32_t type, const std::vector<uint8_t>& token)
{
    std::function<ErrCode(TEEC_Operation &)> setParamTask = [id, type, &token](TEEC_Operation &operation) {
        operation.started = 1;
        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
                                                 TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT);
        operation.params[INDEX_ZERO].value.a = static_cast<uint32_t>(id);
        operation.params[INDEX_ZERO].value.b = static_cast<uint32_t>(type);
        operation.params[INDEX_ONE].value.a = ADMIN_TOKEN_TYPE;
        operation.params[INDEX_TWO].tmpref.buffer = const_cast<uint8_t*>(token.data());
        operation.params[INDEX_TWO].tmpref.size = static_cast<uint32_t>(token.size());
        return ERR_OK;
    };
    ErrCode ret = ExecuteCommand(USER_ROLE_SET_CMD_ID, setParamTask);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("SetOsAccountType failed, ret = %{public}d", ret);
    }
    return ret;
}

ErrCode OsAccountTeeAdapter::Impl::SetOsAccountType(int32_t id, int32_t type,
    const std::vector<uint8_t>& edaToken, const std::vector<uint8_t>& certToken)
{
    std::function<ErrCode(TEEC_Operation &)> setParamTask;
    if (edaToken.empty() && certToken.empty()) {
        setParamTask = [id, type](TEEC_Operation &operation) {
            operation.started = 1;
            operation.paramTypes =
                TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT);
            operation.params[INDEX_ZERO].value.a = static_cast<uint32_t>(id);
            operation.params[INDEX_ZERO].value.b = static_cast<uint32_t>(type);
            operation.params[INDEX_ONE].value.a = NO_TOKEN_TYPE;
            return ERR_OK;
        };
    } else {
        setParamTask = [id, type, &edaToken, &certToken](TEEC_Operation &operation) {
            operation.started = 1;
            operation.paramTypes =
                TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT);
            operation.params[INDEX_ZERO].value.a = static_cast<uint32_t>(id);
            operation.params[INDEX_ZERO].value.b = static_cast<uint32_t>(type);
            operation.params[INDEX_ONE].value.a = ENT_DEVICE_TYPE;
            operation.params[INDEX_TWO].tmpref.buffer = const_cast<uint8_t *>(edaToken.data());
            operation.params[INDEX_TWO].tmpref.size = static_cast<uint32_t>(edaToken.size());
            operation.params[INDEX_THREE].tmpref.buffer = const_cast<uint8_t *>(certToken.data());
            operation.params[INDEX_THREE].tmpref.size = static_cast<uint32_t>(certToken.size());
            return ERR_OK;
        };
    }
    ErrCode ret = ExecuteCommand(USER_ROLE_SET_CMD_ID, setParamTask);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("SetOsAccountType for edm failed, ret = %{public}d", ret);
    }
    return ret;
}

ErrCode OsAccountTeeAdapter::Impl::MigrateOsAccountTypesToTee(
    const std::vector<int32_t> &ids, const std::vector<int32_t> &types)
{
    if (ids.empty() || types.empty()) {
        ACCOUNT_LOGE("MigrateOsAccountTypesToTee: ids or types is empty");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    if (ids.size() != types.size()) {
        ACCOUNT_LOGE("MigrateOsAccountTypesToTee: ids size %{public}zu != types size %{public}zu",
            ids.size(), types.size());
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    // Batch migration: migrate multiple account types in one TEE call
    ACCOUNT_LOGI("MigrateOsAccountTypesToTee: start batch migration, count=%{public}zu", ids.size());

    std::vector<uint32_t> idArray;
    std::vector<uint32_t> typeArray;

    // Convert to uint32 arrays
    for (size_t i = 0; i < ids.size(); ++i) {
        idArray.push_back(static_cast<uint32_t>(ids[i]));
        typeArray.push_back(static_cast<uint32_t>(types[i]));
    }

    std::function<ErrCode(TEEC_Operation &)> setParamTask =
        [&idArray, &typeArray](TEEC_Operation &operation) {
            operation.started = 1;
            operation.paramTypes = TEEC_PARAM_TYPES(
                TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE);
            operation.params[INDEX_ZERO].tmpref.buffer = reinterpret_cast<uint8_t*>(idArray.data());
            operation.params[INDEX_ZERO].tmpref.size = static_cast<uint32_t>(idArray.size() * sizeof(uint32_t));
            operation.params[INDEX_ONE].tmpref.buffer = reinterpret_cast<uint8_t*>(typeArray.data());
            operation.params[INDEX_ONE].tmpref.size = static_cast<uint32_t>(typeArray.size() * sizeof(uint32_t));
            return ERR_OK;
        };

    ErrCode ret = ExecuteCommand(USER_ROLE_BATCH_SET_CMD_ID, setParamTask);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("MigrateOsAccountTypesToTee failed, count=%{public}zu, ret=%{public}d",
            ids.size(), ret);
    } else {
        ACCOUNT_LOGI("MigrateOsAccountTypesToTee success, count=%{public}zu", ids.size());
    }
    return ret;
}

ErrCode OsAccountTeeAdapter::Impl::DelOsAccountType(int32_t id, const std::vector<uint8_t>& token)
{
    std::function<ErrCode(TEEC_Operation &)> setParamTask = [id, &token](TEEC_Operation &operation) {
        operation.started = 1;
        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_INPUT,
            TEEC_NONE, TEEC_NONE);
        operation.params[INDEX_ZERO].value.a = static_cast<uint32_t>(id);
        operation.params[INDEX_ONE].tmpref.buffer = const_cast<uint8_t*>(token.data());
        operation.params[INDEX_ONE].tmpref.size = static_cast<uint32_t>(token.size());
        return ERR_OK;
    };
    ErrCode ret = ExecuteCommand(USER_ROLE_DELETE_CMD_ID, setParamTask);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("DelOsAccountType failed, ret = %{public}d", ret);
    }
    return ret;
}

ErrCode OsAccountTeeAdapter::Impl::VerifyToken(
    const std::vector<uint8_t>& token, const std::string &privilege, std::vector<uint8_t>& tokenResult)
{
    VerifyTokenParam param;
    param.permissionSize = static_cast<uint8_t>(privilege.size());
    errno_t err = memset_s(param.permission, PERMISSION_MAX_LEN + 1, 0, privilege.size());
    if (err != 0) {
        ACCOUNT_LOGI("Failed to memset privilege, err: %{public}d", err);
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    err = memcpy_s(param.permission, PERMISSION_MAX_LEN, privilege.c_str(), privilege.size());
    if (err != 0) {
        ACCOUNT_LOGI("Failed to memcpy privilege, err: %{public}d", err);
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    std::function<ErrCode(TEEC_Operation &)> setParamTask =
        [&token, &param, &tokenResult] (TEEC_Operation &operation) {
            operation.started = 1;
            operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
                TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);
            operation.params[INDEX_ZERO].tmpref.buffer = const_cast<uint8_t*>(token.data());
            operation.params[INDEX_ZERO].tmpref.size = static_cast<uint32_t>(token.size());
            operation.params[INDEX_ONE].tmpref.buffer = reinterpret_cast<uint8_t*>(&param);
            operation.params[INDEX_ONE].tmpref.size = sizeof(param);
            operation.params[INDEX_TWO].tmpref.buffer = const_cast<uint8_t*>(tokenResult.data());
            operation.params[INDEX_TWO].tmpref.size = static_cast<uint32_t>(tokenResult.size());
            return ERR_OK;
        };
    ErrCode ret = ExecuteCommand(USER_TOKEN_VERIFY_CMD_ID, setParamTask);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("VerifyToken failed, ret = %{public}d", ret);
    }
    return ret;
}

ErrCode OsAccountTeeAdapter::Impl::CheckTimestampExpired(
    const uint32_t grantTime, const int32_t period, int32_t &remainTimeSec, bool &isValid)
{
    VerifyGrantTimeResult result;
    std::function<ErrCode(TEEC_Operation &)> setParamTask = [&grantTime, &period, &result](TEEC_Operation &operation) {
        operation.started = 1;
        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
        operation.params[INDEX_ZERO].value.a = grantTime;
        operation.params[INDEX_ZERO].value.b = static_cast<uint32_t>(period);
        operation.params[INDEX_ONE].tmpref.buffer = reinterpret_cast<uint8_t *>(&result);
        operation.params[INDEX_ONE].tmpref.size = sizeof(VerifyGrantTimeResult);
        return ERR_OK;
    };
    ErrCode ret = ExecuteCommand(CHECK_TIMESTAMP_EXPIRE_CMD_ID, setParamTask);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("CheckTimestampExpired failed, ret = %{public}d", ret);
        return ret;
    }
    isValid = (result.isEffective == 1);
    remainTimeSec = result.remainValidityTime;
    return ERR_OK;
}

ErrCode OsAccountTeeAdapter::Impl::TaAcquireAuthorization(
    const ApplyUserTokenParam &param, ApplyUserTokenResult &tokenResult)
{
    std::function<ErrCode(TEEC_Operation &)> setParamTask = [&param, &tokenResult](TEEC_Operation &operation) {
        (void)memset_s(&operation, sizeof(TEEC_Operation), 0, sizeof(TEEC_Operation));
        operation.started = 1;
        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
        operation.params[INDEX_ZERO].tmpref.buffer =
            reinterpret_cast<uint8_t *>(const_cast<ApplyUserTokenParam *>(&param));
        operation.params[INDEX_ZERO].tmpref.size = sizeof(param);
        operation.params[INDEX_ONE].tmpref.buffer = reinterpret_cast<uint8_t *>(&tokenResult);
        operation.params[INDEX_ONE].tmpref.size = sizeof(tokenResult);
        return ERR_OK;
    };
    ErrCode ret = ExecuteCommand(USER_TOKEN_APPLY_CMD_ID, setParamTask);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Failt to TAAcquireAuthorization, errCode:%{public}d", ret);
        return ERR_AUTHORIZATION_TA_ERROR;
    }
    return ERR_OK;
}

static ErrCode GetFileContextWithNoLock(const std::string &path, std::vector<uint8_t> &byteData)
{
    AccountFileOperator fileOperator;
    ErrCode err = fileOperator.CheckFileExistence(path);
    if (err != ERR_OK) {
        ACCOUNT_LOGE("Check file existence failed, path=%{public}s, ret=%{public}d", path.c_str(), err);
        return err;
    }
    byteData.clear();
    std::ifstream file(path);
    if (!file.is_open()) {
        ACCOUNT_LOGE("Open file failed");
        return ERR_ACCOUNT_COMMON_FILE_OPEN_FAILED;
    }
    std::copy(
        std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>(), std::back_inserter(byteData));
    return ERR_OK;
}

ErrCode OsAccountTeeAdapter::Impl::GetEdmBinAndCert(std::vector<uint8_t> &binData, std::vector<uint8_t> &certData)
{
    std::string binPath = "/data/service/el1/public/cust/enterprise/eda.bin";
    std::string certPath = "/etc/edm/cacert.pem";
    ErrCode errCode = GetFileContextWithNoLock(binPath, binData);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to get eda.bin, errCode: %{public}d", errCode);
        return errCode;
    }
    errCode = GetFileContextWithNoLock(certPath, certData);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to get cacert.pem, errCode: %{public}d", errCode);
    }
    return errCode;
}

// Public interface implementation - delegates to pImpl
OsAccountTeeAdapter::OsAccountTeeAdapter() : impl_(std::make_unique<Impl>()) {}
OsAccountTeeAdapter::~OsAccountTeeAdapter() = default;

ErrCode OsAccountTeeAdapter::GetOsAccountType(int32_t id, int32_t &type)
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
    const std::vector<int32_t> &ids, const std::vector<int32_t> &types)
{
    return impl_->MigrateOsAccountTypesToTee(ids, types);
}

ErrCode OsAccountTeeAdapter::VerifyToken(
    const std::vector<uint8_t>& token, const std::string &privilege, std::vector<uint8_t>& tokenResult)
{
    return impl_->VerifyToken(token, privilege, tokenResult);
}

ErrCode OsAccountTeeAdapter::CheckTimestampExpired(const uint32_t grantTime, const int32_t period,
    int32_t &remainTimeSec, bool &isValid)
{
    return impl_->CheckTimestampExpired(grantTime, period, remainTimeSec, isValid);
}

ErrCode OsAccountTeeAdapter::TaAcquireAuthorization(const ApplyUserTokenParam &param, ApplyUserTokenResult &result)
{
    return impl_->TaAcquireAuthorization(param, result);
}

ErrCode OsAccountTeeAdapter::GetEdmBinAndCert(std::vector<uint8_t> &binData, std::vector<uint8_t> &certData)
{
    return impl_->GetEdmBinAndCert(binData, certData);
}
} // namespace AccountSA
} // namespace OHOS
