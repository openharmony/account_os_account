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

#include<thread>

#include "ability_manager_adapter.h"
#include "account_log_wrapper.h"
#include "bundle_manager_adapter.h"
#ifdef HAS_CES_PART
#include "common_event_manager.h"
#include "common_event_support.h"
#endif // HAS_CES_PART
#include "datetime_ex.h"
#include "hisysevent_adapter.h"
#include "hitrace_adapter.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "istorage_manager.h"
#include "os_account_constants.h"
#include "os_account_delete_user_idm_callback.h"
#include "os_account_stop_user_callback.h"
#include "storage_manager.h"
#include "storage_manager_proxy.h"
#include "system_ability_definition.h"
#ifdef HAS_USER_IDM_PART
#include "useridm_client.h"
#endif // HAS_USER_IDM_PART
#ifdef HAS_CES_PART
#include "want.h"
#endif // HAS_CES_PART

namespace OHOS {
namespace AccountSA {
ErrCode OsAccountInterface::SendToAMSAccountStart(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("start");
    HiTraceAdapterSyncTrace tracer("AbilityManagerAdapter StartUser");
    ErrCode code = AAFwk::AbilityManagerAdapter::GetInstance()->StartUser(osAccountInfo.GetLocalId());
    if (code != ERR_OK) {
        ACCOUNT_LOGE("AbilityManagerAdapter StartUser failed! errcode is %{public}d", code);
        ReportAccountOperationFail(osAccountInfo.GetLocalId(), code, "activate",
            "AbilityManagerAdapter StartUser failed!");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_AM_ACCOUNT_START_ERROR;
    }
    ACCOUNT_LOGI("AbilityManagerAdapter StartUser succeed!");
    return ERR_OK;
}

ErrCode OsAccountInterface::SendToAMSAccountStop(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountInterface SendToAMSAccountStop stop");
    sptr<OsAccountStopUserCallback> osAccountStopUserCallback = new (std::nothrow) OsAccountStopUserCallback();
    if (osAccountStopUserCallback == nullptr) {
        ACCOUNT_LOGE("alloc memory for stop user callback failed!");
        ReportAccountOperationFail(osAccountInfo.GetLocalId(),
            ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR,
            "stop",
            "malloc for OsAccountStopUserCallback failed!");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }

    HiTraceAdapterSyncTrace tracer("AbilityManagerAdapter StopUser");
    ErrCode code = AAFwk::AbilityManagerAdapter::GetInstance()->StopUser(osAccountInfo.GetLocalId(),
        osAccountStopUserCallback);
    if (code != ERR_OK) {
        ACCOUNT_LOGE("failed to AbilityManagerAdapter stop errcode is %{public}d", code);
        ReportAccountOperationFail(osAccountInfo.GetLocalId(), code, "stop", "AbilityManagerAdapter StopUser failed!");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_AM_ACCOUNT_START_ERROR;
    }
    struct tm startTime = {0};
    struct tm nowTime = {0};
    OHOS::GetSystemCurrentTime(&startTime);
    OHOS::GetSystemCurrentTime(&nowTime);
    while (OHOS::GetSecondsBetween(startTime, nowTime) < Constants::TIME_WAIT_TIME_OUT &&
           !osAccountStopUserCallback->isCallBackOk_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(Constants::WAIT_ONE_TIME));
        OHOS::GetSystemCurrentTime(&nowTime);
    }
    if (!osAccountStopUserCallback->isReturnOk_) {
        ACCOUNT_LOGE("failed to AbilityManagerAdapter stop in call back");
        ReportTimeoutFail("AbilityManagerService StopUser timeout!");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_AM_ACCOUNT_START_ERROR;
    }
    ACCOUNT_LOGI("send AM to stop is ok");
    return ERR_OK;
}

ErrCode OsAccountInterface::SendToBMSAccountCreate(OsAccountInfo &osAccountInfo)
{
    return BundleManagerAdapter::GetInstance()->CreateNewUser(osAccountInfo.GetLocalId());
}

ErrCode OsAccountInterface::SendToBMSAccountDelete(OsAccountInfo &osAccountInfo)
{
    return BundleManagerAdapter::GetInstance()->RemoveUser(osAccountInfo.GetLocalId());
}

#ifdef HAS_USER_IDM_PART
ErrCode OsAccountInterface::SendToIDMAccountDelete(OsAccountInfo &osAccountInfo)
{
    std::shared_ptr<OsAccountDeleteUserIdmCallback> callback = std::make_shared<OsAccountDeleteUserIdmCallback>();
    if (callback == nullptr) {
        ACCOUNT_LOGE("get idm callback ptr failed! insufficient memory!");
        ReportAccountOperationFail(osAccountInfo.GetLocalId(),
            ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR,
            "delete",
            "malloc for OsAccountDeleteUserIdmCallback failed!");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }

    HiTraceAdapterSyncTrace tracer("UserIDMClient EnforceDelUser");
    int32_t ret = UserIAM::UserIDM::UserIDMClient::GetInstance().EnforceDelUser(osAccountInfo.GetLocalId(), callback);
    if (ret != 0) {
        ACCOUNT_LOGE("idm enforce delete user failed! error %{public}d", ret);
        ReportAccountOperationFail(osAccountInfo.GetLocalId(), ret, "delete", "UserIDMClient EnforceDelUser failed!");
        return ERR_OK;    // do not return fail
    }

    // wait callback
    struct tm startTime = {0};
    struct tm nowTime = {0};
    OHOS::GetSystemCurrentTime(&startTime);
    OHOS::GetSystemCurrentTime(&nowTime);
    while (OHOS::GetSecondsBetween(startTime, nowTime) < Constants::TIME_WAIT_TIME_OUT &&
        !callback->isIdmOnResultCallBack_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(Constants::WAIT_ONE_TIME));
        OHOS::GetSystemCurrentTime(&nowTime);
    }
    if (!callback->isIdmOnResultCallBack_) {
        ACCOUNT_LOGE("idm did not call back! timeout!");
        ReportTimeoutFail("UserIDMClient EnforceDelUser timeout!");
        return ERR_OK;    // do not return fail
    }
    ACCOUNT_LOGI("send to idm account delete and get callback succeed!");
    return ERR_OK;
}
#endif // HAS_USER_IDM_PART

void OsAccountInterface::SendToCESAccountCreate(OsAccountInfo &osAccountInfo)
{
    int osAccountID = osAccountInfo.GetLocalId();
#ifdef HAS_CES_PART
    HiTraceAdapterSyncTrace tracer("PublishCommonEvent account create");
    OHOS::AAFwk::Want want;
    want.SetAction(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_ADDED);
    OHOS::EventFwk::CommonEventData data;
    data.SetCode(osAccountID);
    data.SetWant(want);
    if (!OHOS::EventFwk::CommonEventManager::PublishCommonEvent(data)) {
        ACCOUNT_LOGE("PublishCommonEvent for create account %{public}d failed!", osAccountID);
        ReportOsAccountCESFail(osAccountID, "send common event for account create fail");
    } else {
        ACCOUNT_LOGI("PublishCommonEvent for create account %{public}d succeed!", osAccountID);
    }
#else // HAS_CES_PART
    ACCOUNT_LOGI("No common event part, do not publish for account %{public}d create!", osAccountID);
#endif // HAS_CES_PART
}

void OsAccountInterface::SendToCESAccountDelete(OsAccountInfo &osAccountInfo)
{
    int osAccountID = osAccountInfo.GetLocalId();
#ifdef HAS_CES_PART
    HiTraceAdapterSyncTrace tracer("PublishCommonEvent account delete");
    OHOS::AAFwk::Want want;
    want.SetAction(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED);
    OHOS::EventFwk::CommonEventData data;
    data.SetCode(osAccountID);
    data.SetWant(want);
    if (!OHOS::EventFwk::CommonEventManager::PublishCommonEvent(data)) {
        ACCOUNT_LOGE("PublishCommonEvent for delete account %{public}d failed!", osAccountID);
        ReportOsAccountCESFail(osAccountID, "send common event for account delete fail");
    } else {
        ACCOUNT_LOGI("PublishCommonEvent for delete account %{public}d succeed!", osAccountID);
    }
#else // HAS_CES_PART
    ACCOUNT_LOGI("No common event part, do not publish for account %{public}d delete!", osAccountID);
#endif // HAS_CES_PART
}

void OsAccountInterface::SendToCESAccountSwitched(OsAccountInfo &osAccountInfo)
{
    int osAccountID = osAccountInfo.GetLocalId();
#ifdef HAS_CES_PART
    HiTraceAdapterSyncTrace tracer("PublishCommonEvent account switch");
    OHOS::AAFwk::Want want;
    want.SetAction(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    OHOS::EventFwk::CommonEventData data;
    data.SetCode(osAccountID);
    data.SetWant(want);
    if (!OHOS::EventFwk::CommonEventManager::PublishCommonEvent(data)) {
        ACCOUNT_LOGE("PublishCommonEvent for switched to account %{public}d failed!", osAccountID);
        ReportOsAccountCESFail(osAccountID, "send common event for account switch fail");
    } else {
        ACCOUNT_LOGI("PublishCommonEvent for switched to account %{public}d succeed!", osAccountID);
    }
#else // HAS_CES_PART
    ACCOUNT_LOGI("No common event part, do not publish for account %{public}d switched!", osAccountID);
#endif // HAS_CES_PART
}

ErrCode OsAccountInterface::SendToStorageAccountCreate(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("start");
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        ACCOUNT_LOGE("failed to get system ability mgr.");
        ReportAccountOperationFail(osAccountInfo.GetLocalId(),
            ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_CREATE_ERROR,
            "create",
            "GetSystemAbilityManager for storage failed!");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_CREATE_ERROR;
    }
    auto remote = systemAbilityManager->GetSystemAbility(STORAGE_MANAGER_MANAGER_ID);
    if (!remote) {
        ACCOUNT_LOGE("failed to get STORAGE_MANAGER_MANAGER_ID service.");
        ReportAccountOperationFail(osAccountInfo.GetLocalId(),
            ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_CREATE_ERROR,
            "create",
            "GetSystemAbility for storage failed!");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_CREATE_ERROR;
    }
    auto proxy = iface_cast<StorageManager::IStorageManager>(remote);
    if (!proxy) {
        ACCOUNT_LOGE("failed to get STORAGE_MANAGER_MANAGER_ID proxy.");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_CREATE_ERROR;
    }
    HiTraceAdapterSyncTrace tracer("StorageManager PrepareAddUser");
    int err = proxy->PrepareAddUser(osAccountInfo.GetLocalId(),
        StorageManager::CRYPTO_FLAG_EL1 | StorageManager::CRYPTO_FLAG_EL2);
    if (err != 0) {
        ReportAccountOperationFail(osAccountInfo.GetLocalId(), err, "create", "Storage PrepareAddUser failed!");
    }

    ACCOUNT_LOGI("end, Storage PrepareAddUser ret %{public}d.", err);
    return ERR_OK;
}

ErrCode OsAccountInterface::SendToStorageAccountRemove(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("start");
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        ACCOUNT_LOGE("failed to get system ability mgr.");
        ReportAccountOperationFail(osAccountInfo.GetLocalId(),
            ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_REMOVE_ERROR,
            "delete",
            "GetSystemAbilityManager for storage failed!");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_REMOVE_ERROR;
    }
    auto remote = systemAbilityManager->GetSystemAbility(STORAGE_MANAGER_MANAGER_ID);
    if (!remote) {
        ACCOUNT_LOGE("failed to get STORAGE_MANAGER_MANAGER_ID service.");
        ReportAccountOperationFail(osAccountInfo.GetLocalId(),
            ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_REMOVE_ERROR,
            "delete",
            "GetSystemAbility for storage failed!");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_REMOVE_ERROR;
    }
    auto proxy = iface_cast<StorageManager::IStorageManager>(remote);
    if (!proxy) {
        ACCOUNT_LOGE("failed to get STORAGE_MANAGER_MANAGER_ID proxy.");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_REMOVE_ERROR;
    }

    HiTraceAdapterSyncTrace tracer("StorageManager RemoveUser");
    int err = proxy->RemoveUser(osAccountInfo.GetLocalId(),
        StorageManager::CRYPTO_FLAG_EL1 | StorageManager::CRYPTO_FLAG_EL2);
    if (err != 0) {
        ReportAccountOperationFail(osAccountInfo.GetLocalId(), err, "delete", "Storage RemoveUser failed!");
    }

    ACCOUNT_LOGI("end, Storage RemoveUser ret %{public}d.", err);
    return ERR_OK;
}

ErrCode OsAccountInterface::SendToStorageAccountStart(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("start");
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        ACCOUNT_LOGE("failed to get system ability mgr.");
        ReportAccountOperationFail(osAccountInfo.GetLocalId(),
            ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_START_ERROR,
            "activate",
            "GetSystemAbilityManager for storage failed!");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_START_ERROR;
    }
    auto remote = systemAbilityManager->GetSystemAbility(STORAGE_MANAGER_MANAGER_ID);
    if (!remote) {
        ACCOUNT_LOGE("failed to get STORAGE_MANAGER_MANAGER_ID service.");
        ReportAccountOperationFail(osAccountInfo.GetLocalId(),
            ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_START_ERROR,
            "activate",
            "GetSystemAbility for storage failed!");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_START_ERROR;
    }
    auto proxy = iface_cast<StorageManager::IStorageManager>(remote);
    if (!proxy) {
        ACCOUNT_LOGE("failed to get STORAGE_MANAGER_MANAGER_ID proxy.");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_START_ERROR;
    }
    HiTraceAdapterSyncTrace tracer("StorageManager PrepareStartUser");
    int err = proxy->PrepareStartUser(osAccountInfo.GetLocalId());
    if (err != 0) {
        ReportAccountOperationFail(osAccountInfo.GetLocalId(), err, "activate", "Storage PrepareStartUser failed!");
    }

    ACCOUNT_LOGI("end, Storage PrepareStartUser ret %{public}d.", err);
    return ERR_OK;
}

ErrCode OsAccountInterface::SendToStorageAccountStop(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("start");
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        ACCOUNT_LOGE("failed to get system ability mgr.");
        ReportAccountOperationFail(osAccountInfo.GetLocalId(),
            ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_STOP_ERROR,
            "stop",
            "GetSystemAbilityManager for storage failed!");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_STOP_ERROR;
    }
    auto remote = systemAbilityManager->GetSystemAbility(STORAGE_MANAGER_MANAGER_ID);
    if (!remote) {
        ACCOUNT_LOGE("failed to get STORAGE_MANAGER_MANAGER_ID service.");
        ReportAccountOperationFail(osAccountInfo.GetLocalId(),
            ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_STOP_ERROR,
            "stop",
            "GetSystemAbility for storage failed!");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_STOP_ERROR;
    }
    auto proxy = iface_cast<StorageManager::IStorageManager>(remote);
    if (!proxy) {
        ACCOUNT_LOGE("failed to get STORAGE_MANAGER_MANAGER_ID proxy.");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_STOP_ERROR;
    }

    HiTraceAdapterSyncTrace tracer("StorageManager StopUser");
    int err = proxy->StopUser(osAccountInfo.GetLocalId());
    if (err != 0) {
        ReportAccountOperationFail(osAccountInfo.GetLocalId(), err, "stop", "Storage StopUser failed!");
    }
    ACCOUNT_LOGI("end, Storage StopUser ret %{public}d", err);
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS
