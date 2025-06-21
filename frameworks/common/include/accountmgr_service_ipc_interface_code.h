/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_FRAMEWORK_ACCOUNTMGR_SERVICE_IPC_INTERFACE_CODE_H
#define OS_ACCOUNT_FRAMEWORK_ACCOUNTMGR_SERVICE_IPC_INTERFACE_CODE_H

#include <cstdint>

/* SAID: 200 */
namespace OHOS {
namespace AccountSA {

enum class AccountIAMInterfaceCode : uint32_t {
    OPEN_SESSION = 0,
    CLOSE_SESSION,
    ADD_CREDENTIAL,
    UPDATE_CREDENTIAL,
    CANCEL,
    DEL_CRED,
    DEL_USER,
    GET_CREDENTIAL_INFO,
    PREPARE_REMOTE_AUTH,
    AUTH_USER,
    CANCEL_AUTH,
    GET_AVAILABLE_STATUS,
    GET_PROPERTY,
    GET_PROPERTY_BY_CREDENTIAL_ID,
    SET_PROPERTY,
    GET_ENROLLED_ID,
    GET_ACCOUNT_STATE,
};

enum class DistributedAccountEventInterfaceCode : uint32_t {
    ON_ACCOUNT_CHANGED = 0,
};

enum class AccountIAMCallbackInterfaceCode : uint32_t {
    ON_ACQUIRE_INFO = 0,
    ON_RESULT,
};

enum class IDMCallbackInterfaceCode : uint32_t {
    ON_ACQUIRE_INFO = 0,
    ON_RESULT,
};

enum class GetCredInfoCallbackInterfaceCode : uint32_t {
    ON_CREDENTIAL_INFO = 0,
};

enum class GetSetPropCallbackInterfaceCode : uint32_t {
    ON_RESULT = 0,
};

enum class GetEnrolledIdCallbackInterfaceCode : uint32_t {
    ON_ENROLLED_ID = 0,
};

enum class PreRemoteAuthCallbackInterfaceCode : uint32_t {
    ON_RESULT = 0,
};
}  // namespace AccountSA
}  // namespace OHOS
#endif // OS_ACCOUNT_FRAMEWORK_ACCOUNTMGR_SERVICE_IPC_INTERFACE_CODE_H
