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
#include "os_account_standard_interface.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
ErrCode OsAccountStandardInterface::SendToAMSAccountStart(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountStandardInterface SendToAMSAccountStart start");
    return ERR_OK;
}

ErrCode OsAccountStandardInterface::SendToAMSAccountStop(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountStandardInterface SendToAMSAccountStop start");
    return ERR_OK;
}

ErrCode OsAccountStandardInterface::SendToBMSAccountCreate(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountStandardInterface SendToBMSAccountCreate start");
    return ERR_OK;
}

ErrCode OsAccountStandardInterface::SendToBMSAccountDelete(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountStandardInterface SendToBMSAccountDelete start");
    return ERR_OK;
}

ErrCode OsAccountStandardInterface::SendToIAMAccountDelete(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountStandardInterface SendToIAMAccountDelete start");
    return ERR_OK;
}

void OsAccountStandardInterface::SendToCESAccountCreate(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountStandardInterface SendToCESAccountCreate start");
}

void OsAccountStandardInterface::SendToCESAccountDelete(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountStandardInterface SendToCESAccountDelete start");
}

void OsAccountStandardInterface::SendToCESAccountSwitched(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountStandardInterface SendToCESAccountSwitched start");
}

ErrCode OsAccountStandardInterface::SendToStorageAccountCreate(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountStandardInterface SendToStorageAccountCreate start");
    return ERR_OK;
}

ErrCode OsAccountStandardInterface::SendToStorageAccountRemove(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountStandardInterface SendToStorageAccountRemove start");
    return ERR_OK;
}

ErrCode OsAccountStandardInterface::SendToStorageAccountStart(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountStandardInterface SendToStorageAccountStart start");
    return ERR_OK;
}

ErrCode OsAccountStandardInterface::SendToStorageAccountStop(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountStandardInterface SendToStorageAccountStop start");
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS
