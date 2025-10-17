/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

ErrCode OsAccountInterface::SendToAMSAccountStart(OsAccountInfo &osAccountInfo, const uint64_t displayId,
    const OsAccountStartCallbackFunc &callbackFunc, bool isAppRecovery)
{
    ACCOUNT_LOGI("mock OsAccountInterface SendToAMSAccountStart start");
    sptr<OsAccountUserCallback> osAccountStartUserCallback = new (std::nothrow) OsAccountUserCallback(callbackFunc);
    osAccountStartUserCallback->OnStartUserDone(osAccountInfo.GetLocalId(), 0);
    return ERR_OK;
}

ErrCode OsAccountInterface::SendToAMSAccountStop(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("mock OsAccountInterface SendToAMSAccountStop start");
    return ERR_OK;
}

ErrCode OsAccountInterface::SendToBMSAccountCreate(
    OsAccountInfo &osAccountInfo, const std::vector<std::string> &disallowedHapList,
    const std::optional<std::vector<std::string>> &allowedHapList)
{
    ACCOUNT_LOGI("mock OsAccountInterface SendToBMSAccountCreate start");
    if (osAccountInfo.GetLocalName() == "CreateOsAccountRollback001") {
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER;
    }
    return ERR_OK;
}

ErrCode OsAccountInterface::SendToAMSAccountDeactivate(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("mock OsAccountInterface SendToAMSAccountDeactivate start");
    return ERR_OK;
}

void OsAccountInterface::SendToBMSAccountUnlocked(const OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("mock OsAccountInterface SendToBMSAccountUnlocked start");
}

void OsAccountInterface::SendToBMSAccountUnlockedWithTimeout(const OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("mock OsAccountInterface SendToBMSAccountUnlockedWithTimeout start");
}

void OsAccountInterface::SendToStorageAccountUnlocked(const OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("mock OsAccountInterface SendToStorageAccountUnlocked start");
}

void OsAccountInterface::SendToStorageAccountSwitched(const OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("mock OsAccountInterface SendToStorageAccountSwitched start");
}

ErrCode OsAccountInterface::SendToBMSAccountDelete(OsAccountInfo &osAccountInfo)
{
    DomainAccountInfo info;
    osAccountInfo.GetDomainInfo(info);
    if (!info.domain_.empty() && info.domain_ == "fail") {
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_BM_ACCOUNT_DELETE_ERROR;
    }
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

void OsAccountInterface::SendToCESAccountSwitched(int newId, int oldId, uint64_t displayId)
{
    ACCOUNT_LOGI("mock OsAccountInterface SendToCESAccountSwitched start");
}

void OsAccountInterface::PublishCommonEvent(
    const OsAccountInfo &osAccountInfo, const std::string &commonEvent, const std::string &operation)
{
    ACCOUNT_LOGI("mock OsAccountInterface PublishCommonEvent start");
    return;
}

ErrCode OsAccountInterface::SendToStorageAccountCreateComplete(int32_t localId)
{
    ACCOUNT_LOGI("mock OsAccountInterface SendToStorageAccountCreateComplete start");
    return ERR_OK;
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
    osAccountInfo.SetIsVerified(true);
    osAccountInfo.SetIsLoggedIn(true);
    return ERR_OK;
}

ErrCode OsAccountInterface::SendToStorageAccountStop(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("mock OsAccountInterface SendToStorageAccountStop start");
    return ERR_OK;
}

ErrCode OsAccountInterface::CheckAllAppDied(int32_t accountId)
{
    ACCOUNT_LOGI("mock OsAccountInterface CheckAllAppDied start");
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS
