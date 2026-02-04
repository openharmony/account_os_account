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
#include "account_log_wrapper.h"
#include <mutex>

namespace OHOS {
namespace AccountSA {
namespace {
    constexpr uint32_t INDEX_ZERO = 0;
    constexpr uint32_t INDEX_ONE = 1;
    constexpr uint32_t INDEX_TWO = 2;
    constexpr uint32_t INDEX_THREE = 3;
    constexpr uint32_t ADMIN_TOKEN_TYPE = 0;
    constexpr uint32_t ENT_DEVICE_TYPE = 1;
    constexpr TEEC_Result TEEC_ERROR_USER_TOKEN_INVALID = static_cast<TEEC_Result>(0x10000004);
    constexpr TEEC_Result TEEC_ERROR_USER_TOKEN_EXPIRED = static_cast<TEEC_Result>(0x10000005);
    uint8_t g_taPATH[] = "/vendor/bin/edab8b4f-3bfd-486d-863c-ca04744e49d0.sec";
    const TEEC_UUID ACCOUNT_TA_UUID = {
        0xedab8b4f, 0x3bfd, 0x486d,
        {0x86, 0x3c, 0xca, 0x04, 0x74, 0x4e, 0x49, 0xd0}
    };
    enum TA_CommonId : uint32_t {
        USER_ROLE_GET_VERSION_CMD_ID = 0x00000001,
        USER_ROLE_SET_CMD_ID = 0x00010001,
        USER_ROLE_DELETE_CMD_ID = 0x00010002,
        USER_TOKEN_VERIFY_CMD_ID = 0x00020002,
        CHECK_TIMESTAMP_EXPIRE_CMD_ID = 0x00020003,
        USER_TOKEN_APPLY_CMD_ID = 0x00020001,
    };
}
OsAccountTeeAdapter::TeecContextGuard::~TeecContextGuard()
{
    if (initResult_ == TEEC_SUCCESS) {
        TEEC_FinalizeContext(&context_);
    }
}

TEEC_Result OsAccountTeeAdapter::TeecContextGuard::Initialize()
{
    std::call_once(initFlag_, [&]() {
        initResult_ = TEEC_InitializeContext(nullptr, &context_);
        if (initResult_ == TEEC_SUCCESS) {
            context_.ta_path = g_taPATH;
        }
    });
    return initResult_;
}

TEEC_Result OsAccountTeeAdapter::TeecSessionGuard::Open(TEEC_Context* context, const TEEC_UUID* uuid)
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

OsAccountTeeAdapter::TeecSessionGuard::~TeecSessionGuard()
{
    if (openResult_ == TEEC_SUCCESS) {
        TEEC_CloseSession(&session_);
    }
}

ErrCode OsAccountTeeAdapter::ConvertTeecErrCode(TEEC_Result teeResult)
{
    switch (teeResult) {
        case TEEC_ERROR_ACCESS_DENIED:
            return ERR_ACCOUNT_COMMON_TEE_PERMISSION_DENIED;
        case TEEC_ERROR_BAD_PARAMETERS:
            return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
        case TEEC_ERROR_USER_TOKEN_INVALID:
            return ERR_ACCOUNT_COMMON_TEE_USER_TOKEN_INVALID;
        case TEEC_ERROR_USER_TOKEN_EXPIRED:
            return ERR_ACCOUNT_COMMON_TEE_USER_TOKEN_EXPIRED;
        default:
            return ERR_ACCOUNT_COMMON_OPERATION_FAIL;
    }
}

ErrCode OsAccountTeeAdapter::ExecuteCommand(
    uint32_t command, const std::function<ErrCode(TEEC_Operation &)> &setParams)
{
    // Initialize TEE context
    OsAccountTeeAdapter::TeecContextGuard contextGuard;
    TEEC_Result result = contextGuard.Initialize();
    if (result != TEEC_SUCCESS) {
        ACCOUNT_LOGE("TEEC_InitializeContext failed, result: %{public}u", result);
        return ERR_ACCOUNT_COMMON_OPERATION_FAIL;
    }
    // Open TEE session
    OsAccountTeeAdapter::TeecSessionGuard sessionGuard;
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
        ACCOUNT_LOGE("TEEC_InvokeCommand failed, command: %{public}u, result: %{public}u, origin: %{public}u",
            command, result, origin);
        return ConvertTeecErrCode(result);
    }
    return ERR_OK;
}

ErrCode OsAccountTeeAdapter::SetOsAccountType(int32_t id, int32_t type, const std::vector<uint8_t>& token)
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

ErrCode OsAccountTeeAdapter::SetDomainAccountType(int32_t id, int32_t type,
    const std::vector<uint8_t>& edaToken, const std::vector<uint8_t>& certToken)
{
    std::function<ErrCode(TEEC_Operation &)> setParamTask = [id, type,
            &edaToken, &certToken](TEEC_Operation &operation) {
        operation.started = 1;
        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
                                                 TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT);
        operation.params[INDEX_ZERO].value.a = static_cast<uint32_t>(id);
        operation.params[INDEX_ZERO].value.b = static_cast<uint32_t>(type);
        operation.params[INDEX_ONE].value.a = ENT_DEVICE_TYPE;
        operation.params[INDEX_TWO].tmpref.buffer = const_cast<uint8_t*>(edaToken.data());
        operation.params[INDEX_TWO].tmpref.size = static_cast<uint32_t>(edaToken.size());
        operation.params[INDEX_THREE].tmpref.buffer = const_cast<uint8_t*>(certToken.data());
        operation.params[INDEX_THREE].tmpref.size = static_cast<uint32_t>(certToken.size());
        return ERR_OK;
    };
    ErrCode ret = ExecuteCommand(USER_ROLE_SET_CMD_ID, setParamTask);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("SetOsAccountType failed, ret = %{public}d", ret);
    }
    return ret;
}

ErrCode OsAccountTeeAdapter::DelOsAccountType(int32_t id, const std::vector<uint8_t>& token)
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

ErrCode OsAccountTeeAdapter::VerifyToken(const std::vector<uint8_t>& token, std::vector<uint8_t>& tokenResult)
{
    std::function<ErrCode(TEEC_Operation &)> setParamTask = [&token, &tokenResult] (TEEC_Operation &operation) {
        operation.started = 1;
        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
            TEEC_NONE, TEEC_NONE);
        operation.params[INDEX_ZERO].tmpref.buffer = const_cast<uint8_t*>(token.data());
        operation.params[INDEX_ZERO].tmpref.size = static_cast<uint32_t>(token.size());
        operation.params[INDEX_ONE].tmpref.buffer = const_cast<uint8_t*>(tokenResult.data());
        operation.params[INDEX_ONE].tmpref.size = static_cast<uint32_t>(tokenResult.size());
        return ERR_OK;
    };
    ErrCode ret = ExecuteCommand(USER_TOKEN_VERIFY_CMD_ID, setParamTask);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("VerifyToken failed, ret = %{public}d", ret);
    }
    return ret;
}

ErrCode OsAccountTeeAdapter::CheckTimestampExpired(
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

ErrCode OsAccountTeeAdapter::TaAcquireAuthorization(const ApplyUserTokenParam &param, ApplyUserTokenResult &tokenResult)
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
} // namespace AccountSA
} // namespace OHOS
