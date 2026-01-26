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
    constexpr uint32_t TOKEN_TYPE_AUTHORIZATION = 0;
    constexpr uint32_t ACCOUNT_INFO_PARAM_INDEX = 0;
    constexpr uint32_t TYPE_PARAM_INDEX = 1;
    constexpr uint32_t TOKEN_PARAM_INDEX = 2;
    const TEEC_UUID ACCOUNT_TA_UUID = {
        0xedab8b4f, 0x3bfd, 0x486d,
        {0x86, 0x3c, 0xca, 0x04, 0x74, 0x4e, 0x49, 0xd0}
    };
    uint8_t g_taPath[] = "/vendor/bin/edab8b4f-3bfd-486d-863c-ca04744e49d0.sec";
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
            context_.ta_path = g_taPath;
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
            return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
        case TEEC_ERROR_BAD_PARAMETERS:
            return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
        default:
            return ERR_ACCOUNT_COMMON_OPERATION_FAIL;
    }
}

ErrCode OsAccountTeeAdapter::ExecuteCommand(uint32_t command, int32_t id,
    int32_t param, const std::vector<uint8_t>& token)
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
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
                                             TEEC_MEMREF_TEMP_INPUT, TEEC_NONE);
    operation.params[ACCOUNT_INFO_PARAM_INDEX].value.a = static_cast<uint32_t>(id);
    operation.params[ACCOUNT_INFO_PARAM_INDEX].value.b = static_cast<uint32_t>(param);
    operation.params[TYPE_PARAM_INDEX].value.a = TOKEN_TYPE_AUTHORIZATION;
    operation.params[TOKEN_PARAM_INDEX].tmpref.buffer = const_cast<uint8_t*>(token.data());
    if (token.size() > MAX_TOKEN_SIZE) {
        ACCOUNT_LOGE("Token size exceeds MAX_TOKEN_SIZE");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    operation.params[TOKEN_PARAM_INDEX].tmpref.size = static_cast<uint32_t>(token.size());

    uint32_t origin = 0;
    result = TEEC_InvokeCommand(sessionGuard.Get(), command, &operation, &origin);
    if (result != TEEC_SUCCESS) {
        ACCOUNT_LOGE("TEEC_InvokeCommand failed, command: %{public}u, id: %{public}d, "
                     "result: %{public}u, origin: %{public}u", command, id, result, origin);
        return ConvertTeecErrCode(result);
    }

    return ERR_OK;
}

ErrCode OsAccountTeeAdapter::SetOsAccountType(int32_t id, int32_t type, const std::vector<uint8_t>& token)
{
    if (token.size() > MAX_TOKEN_SIZE) {
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    return ExecuteCommand(0x00010001, id, type, token);
}

ErrCode OsAccountTeeAdapter::DelOsAccountType(int32_t id, int32_t type, const std::vector<uint8_t>& token)
{
    if (token.size() > MAX_TOKEN_SIZE) {
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    return ExecuteCommand(0x00010002, id, type, token);
}
} // namespace AccountSA
} // namespace OHOS
