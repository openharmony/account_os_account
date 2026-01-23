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

#include <stdint.h>
#include <vector>
#include <mutex>
#include "errors.h"
#include "account_error_no.h"
#include "tee_client_api.h"

namespace OHOS {
namespace AccountSA {
constexpr size_t MAX_TOKEN_SIZE = 1024;
/**
 * @brief An adapter class for managing OS account operations with Trusted Application (TA) in TEE.
 *
 * This class provides a unified interface for interacting with TEE to perform various
 * OS account operations such as setting account type, creating accounts, deleting accounts, etc.
 */
class OsAccountTeeAdapter {
public:
    OsAccountTeeAdapter() = default;
    ~OsAccountTeeAdapter() = default;

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
     * @return error code, see account_error_no.h
     */
    ErrCode SetOsAccountType(int32_t id, int32_t type, const std::vector<uint8_t>& token);

    /**
     * @brief Deletes OS account type from TA.
     * @param id - Indicates the local ID of the OS account.
     * @param type - Indicates the account type to be deleted.
     * @param token - Indicates the authorization token for authentication.
     * @return error code, see account_error_no.h
     */
    ErrCode DelOsAccountType(int32_t id, int32_t type, const std::vector<uint8_t>& token);

private:
    /**
     * @brief A RAII wrapper class for TEEC_Context.
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
     * @param command - Indicates the TA command ID.
     * @param id - Indicates the OS account ID.
     * @param param1 - Indicates the first parameter.
     * @param token - Indicates the authorization token.
     * @return error code, see account_error_no.h
     */
    ErrCode ExecuteCommand(uint32_t command, int32_t id, int32_t param1, const std::vector<uint8_t>& token);

    /**
     * @brief Converts TEEC error code to account error code.
     * @param teeResult - Indicates the TEEC_Result from TEE operation.
     * @return error code, see account_error_no.h
     */
    static ErrCode ConvertTeecErrCode(TEEC_Result teeResult);
};
} // namespace AccountSA
} // namespace OHOS
#endif // OS_ACCOUNT_AUTHORIZATION_TEE_ADAPTER_H
