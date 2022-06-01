/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "os_account_interface.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
ErrCode OsAccountInterface::SendToAMSAccountStart(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("mock OsAccountInterface SendToAMSAccountStart start");
    return ERR_OK;
}

ErrCode OsAccountInterface::SendToAMSAccountStop(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("mock OsAccountInterface SendToAMSAccountStop start");
    return ERR_OK;
}

ErrCode OsAccountInterface::SendToBMSAccountCreate(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("mock OsAccountInterface SendToBMSAccountCreate start");
    return ERR_OK;
}

ErrCode OsAccountInterface::SendToBMSAccountDelete(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("mock OsAccountInterface SendToBMSAccountDelete start");
    return ERR_OK;
}

#ifdef HAS_USER_IDM_PART
ErrCode OsAccountInterface::SendToIDMAccountDelete(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("mock OsAccountInterface SendToIDMAccountDelete start");
    return ERR_OK;
}
#endif // HAS_USER_IDM_PART

void OsAccountInterface::SendToCESAccountCreate(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("mock OsAccountInterface SendToCESAccountCreate start");
}

void OsAccountInterface::SendToCESAccountDelete(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("mock OsAccountInterface SendToCESAccountDelete start");
}

void OsAccountInterface::SendToCESAccountSwitched(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("mock OsAccountInterface SendToCESAccountSwitched start");
}

ErrCode OsAccountInterface::SendToStorageAccountCreate(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("mock OsAccountInterface SendToStorageAccountCreate start");
    return ERR_OK;
}

ErrCode OsAccountInterface::SendToStorageAccountRemove(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("mock OsAccountInterface SendToStorageAccountRemove start");
    return ERR_OK;
}

ErrCode OsAccountInterface::SendToStorageAccountStart(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("mock OsAccountInterface SendToStorageAccountStart start");
    return ERR_OK;
}

ErrCode OsAccountInterface::SendToStorageAccountStop(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("mock OsAccountInterface SendToStorageAccountStop start");
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS
