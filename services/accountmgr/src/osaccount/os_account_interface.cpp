/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include<cerrno>
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
#ifdef HAS_STORAGE_PART
#include "istorage_manager.h"
#endif
#include "os_account_constants.h"
#include "os_account_delete_user_idm_callback.h"
#include "os_account_stop_user_callback.h"
#ifdef HAS_STORAGE_PART
#include "storage_manager_proxy.h"
#endif
#include "system_ability_definition.h"
#ifdef HAS_USER_IDM_PART
#include "user_idm_client.h"
#endif // HAS_USER_IDM_PART
#ifdef HAS_CES_PART
#include "want.h"
#endif // HAS_CES_PART

namespace OHOS {
namespace AccountSA {
namespace {
constexpr uint32_t CRYPTO_FLAG_EL1 = 1;
constexpr uint32_t CRYPTO_FLAG_EL2 = 2;
}

ErrCode OsAccountInterface::SendToAMSAccountStart(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("start");
    StartTraceAdapter("AbilityManagerAdapter StartUser");
    ErrCode code = AbilityManagerAdapter::GetInstance()->StartUser(osAccountInfo.GetLocalId());
    if (code != ERR_OK) {
        ACCOUNT_LOGE("AbilityManagerAdapter StartUser failed! errcode is %{public}d", code);
        ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_ACTIVATE, code,
            "AbilityManagerAdapter StartUser failed!");
        FinishTraceAdapter();
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_AM_ACCOUNT_START_ERROR;
    }
    ACCOUNT_LOGI("end, succeed!");
    FinishTraceAdapter();
    return ERR_OK;
}

ErrCode OsAccountInterface::SendToAMSAccountStop(OsAccountInfo &osAccountInfo)
{
    sptr<OsAccountStopUserCallback> osAccountStopUserCallback = new (std::nothrow) OsAccountStopUserCallback();
    if (osAccountStopUserCallback == nullptr) {
        ACCOUNT_LOGE("alloc memory for stop user callback failed!");
        ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_STOP,
            ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR,
            "malloc for OsAccountStopUserCallback failed!");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    StartTraceAdapter("AbilityManagerAdapter StopUser");
    ErrCode code = AbilityManagerAdapter::GetInstance()->StopUser(osAccountInfo.GetLocalId(),
        osAccountStopUserCallback);
    if (code != ERR_OK) {
        ACCOUNT_LOGE("failed to AbilityManagerAdapter stop errcode is %{public}d", code);
        ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_STOP, code,
            "AbilityManagerService StopUser failed!");
        FinishTraceAdapter();
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
        ACCOUNT_LOGE("failed to AbilityManagerService stop in call back");
        ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_STOP, -1,
            "AbilityManagerService StopUser timeout!");
        FinishTraceAdapter();
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_AM_ACCOUNT_START_ERROR;
    }

    FinishTraceAdapter();
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
        ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_DELETE,
            ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR,
            "malloc for OsAccountDeleteUserIdmCallback failed!");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    StartTraceAdapter("UserIDMClient EnforceDelUser");
    int32_t ret = UserIam::UserAuth::UserIdmClient::GetInstance().EraseUser(osAccountInfo.GetLocalId(), callback);
    if (ret != 0) {
        ACCOUNT_LOGE("idm enforce delete user failed! error %{public}d", ret);
        ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_DELETE, ret,
            "UserIDMClient EnforceDelUser failed!");
        FinishTraceAdapter();
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
        ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_DELETE, -1,
            "UserIDMClient EnforceDelUser timeout!");
        FinishTraceAdapter();
        return ERR_OK;    // do not return fail
    }
    ACCOUNT_LOGI("send to idm account delete and get callback succeed!");
    FinishTraceAdapter();
    return ERR_OK;
}
#endif // HAS_USER_IDM_PART

void OsAccountInterface::SendToCESAccountCreate(OsAccountInfo &osAccountInfo)
{
    int osAccountID = osAccountInfo.GetLocalId();
#ifdef HAS_CES_PART
    StartTraceAdapter("PublishCommonEvent account create");
    OHOS::AAFwk::Want want;
    want.SetAction(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_ADDED);
    OHOS::EventFwk::CommonEventData data;
    data.SetCode(osAccountID);
    data.SetWant(want);
    if (!OHOS::EventFwk::CommonEventManager::PublishCommonEvent(data)) {
        ACCOUNT_LOGE("PublishCommonEvent for create account %{public}d failed!", osAccountID);
        ReportOsAccountOperationFail(osAccountID, Constants::OPERATION_CREATE, -1, "PublishCommonEvent failed!");
    } else {
        ACCOUNT_LOGI("PublishCommonEvent for create account %{public}d succeed!", osAccountID);
    }
    FinishTraceAdapter();
#else // HAS_CES_PART
    ACCOUNT_LOGI("No common event part, do not publish for account %{public}d create!", osAccountID);
#endif // HAS_CES_PART
}

void OsAccountInterface::SendToCESAccountDelete(OsAccountInfo &osAccountInfo)
{
    int osAccountID = osAccountInfo.GetLocalId();
#ifdef HAS_CES_PART
    StartTraceAdapter("PublishCommonEvent account delete");
    OHOS::AAFwk::Want want;
    want.SetAction(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED);
    OHOS::EventFwk::CommonEventData data;
    data.SetCode(osAccountID);
    data.SetWant(want);
    if (!OHOS::EventFwk::CommonEventManager::PublishCommonEvent(data)) {
        ACCOUNT_LOGE("PublishCommonEvent for delete account %{public}d failed!", osAccountID);
        ReportOsAccountOperationFail(osAccountID, Constants::OPERATION_DELETE, -1, "PublishCommonEvent failed!");
    } else {
        ACCOUNT_LOGI("PublishCommonEvent for delete account %{public}d succeed!", osAccountID);
    }
    FinishTraceAdapter();
#else // HAS_CES_PART
    ACCOUNT_LOGI("No common event part, do not publish for account %{public}d delete!", osAccountID);
#endif // HAS_CES_PART
}

void OsAccountInterface::PublishCommonEvent(
    const OsAccountInfo &osAccountInfo, const std::string &commonEvent, const std::string &operation)
{
    int osAccountID = osAccountInfo.GetLocalId();
#ifdef HAS_CES_PART
    StartTraceAdapter("PublishCommonEvent account");
    OHOS::AAFwk::Want want;
    want.SetAction(commonEvent);
    OHOS::EventFwk::CommonEventData data;
    data.SetCode(osAccountID);
    data.SetWant(want);
    if (!OHOS::EventFwk::CommonEventManager::PublishCommonEvent(data)) {
        ACCOUNT_LOGE("PublishCommonEvent %{public}d failed!", osAccountID);
        ReportOsAccountOperationFail(osAccountID, operation, -1, "PublishCommonEvent failed!");
    } else {
        ACCOUNT_LOGI("PublishCommonEvent %{public}d succeed!", osAccountID);
    }
    FinishTraceAdapter();
#else  // HAS_CES_PART
    ACCOUNT_LOGI("No common event part, do not publish for account %{public}d!", osAccountID);
#endif // HAS_CES_PART
}

void OsAccountInterface::SendToCESAccountSwitched(OsAccountInfo &osAccountInfo)
{
    int osAccountID = osAccountInfo.GetLocalId();
#ifdef HAS_CES_PART
    StartTraceAdapter("PublishCommonEvent account switch");
    OHOS::AAFwk::Want want;
    want.SetAction(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    OHOS::EventFwk::CommonEventData data;
    data.SetCode(osAccountID);
    data.SetWant(want);
    if (!OHOS::EventFwk::CommonEventManager::PublishCommonEvent(data)) {
        ACCOUNT_LOGE("PublishCommonEvent for switched to account %{public}d failed!", osAccountID);
        ReportOsAccountOperationFail(osAccountID, Constants::OPERATION_SWITCH, -1, "PublishCommonEvent failed!");
    } else {
        ACCOUNT_LOGI("PublishCommonEvent for switched to account %{public}d succeed!", osAccountID);
    }
    FinishTraceAdapter();
#else // HAS_CES_PART
    ACCOUNT_LOGI("No common event part, do not publish for account %{public}d switched!", osAccountID);
#endif // HAS_CES_PART
}

ErrCode OsAccountInterface::SendToStorageAccountCreate(OsAccountInfo &osAccountInfo)
{
#ifdef HAS_STORAGE_PART
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        ACCOUNT_LOGE("failed to get system ability mgr.");
        ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_CREATE,
            ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER,
            "GetSystemAbilityManager for storage failed!");
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER;
    }
    auto remote = systemAbilityManager->CheckSystemAbility(STORAGE_MANAGER_MANAGER_ID);
    if (!remote) {
        ACCOUNT_LOGE("failed to get STORAGE_MANAGER_MANAGER_ID service.");
        ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_CREATE,
            ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER,
            "CheckSystemAbility for storage failed!");
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER;
    }
    auto proxy = iface_cast<StorageManager::IStorageManager>(remote);
    if (!proxy) {
        ACCOUNT_LOGE("failed to get STORAGE_MANAGER_MANAGER_ID proxy.");
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER;
    }
    StartTraceAdapter("StorageManager PrepareAddUser");
    int err = proxy->PrepareAddUser(osAccountInfo.GetLocalId(),
        CRYPTO_FLAG_EL1 | CRYPTO_FLAG_EL2);
    if (err != 0) {
        ReportOsAccountOperationFail(
            osAccountInfo.GetLocalId(), Constants::OPERATION_CREATE, err, "Storage PrepareAddUser failed!");
        if (err != -EEXIST) {
            FinishTraceAdapter();
            return ERR_OSACCOUNT_SERVICE_STORAGE_PREPARE_ADD_USER_FAILED;
        }
    }

    FinishTraceAdapter();
#endif
    return ERR_OK;
}

ErrCode OsAccountInterface::SendToStorageAccountRemove(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("start");
#ifdef HAS_STORAGE_PART
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        ACCOUNT_LOGE("failed to get system ability mgr.");
        ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_DELETE,
            ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER,
            "GetSystemAbilityManager for storage failed!");
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER;
    }
    auto remote = systemAbilityManager->GetSystemAbility(STORAGE_MANAGER_MANAGER_ID);
    if (!remote) {
        ACCOUNT_LOGE("failed to get STORAGE_MANAGER_MANAGER_ID service.");
        ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_DELETE,
            ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER,
            "GetSystemAbility for storage failed!");
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER;
    }
    auto proxy = iface_cast<StorageManager::IStorageManager>(remote);
    if (!proxy) {
        ACCOUNT_LOGE("failed to get STORAGE_MANAGER_MANAGER_ID proxy.");
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER;
    }

    StartTraceAdapter("StorageManager RemoveUser");
    int err = proxy->RemoveUser(osAccountInfo.GetLocalId(),
        CRYPTO_FLAG_EL1 | CRYPTO_FLAG_EL2);
    if (err != 0) {
        ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_DELETE,
            err, "Storage RemoveUser failed!");
    }

    ACCOUNT_LOGI("end, Storage RemoveUser ret %{public}d.", err);
    FinishTraceAdapter();
#endif
    return ERR_OK;
}

ErrCode OsAccountInterface::SendToStorageAccountStart(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("start");
    bool isUserUnlocked = false;
#ifdef HAS_STORAGE_PART
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        ACCOUNT_LOGE("failed to get system ability mgr.");
        ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_ACTIVATE,
            ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER,
            "GetSystemAbilityManager for storage failed!");
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER;
    }
    auto remote = systemAbilityManager->CheckSystemAbility(STORAGE_MANAGER_MANAGER_ID);
    if (!remote) {
        ACCOUNT_LOGE("failed to get STORAGE_MANAGER_MANAGER_ID service.");
        ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_ACTIVATE,
            ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER, "CheckSystemAbility for storage failed!");
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER;
    }
    auto proxy = iface_cast<StorageManager::IStorageManager>(remote);
    if (!proxy) {
        ACCOUNT_LOGE("failed to get STORAGE_MANAGER_MANAGER_ID proxy.");
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER;
    }
    StartTraceAdapter("StorageManager PrepareStartUser");
    int localId = osAccountInfo.GetLocalId();
    std::vector<uint8_t> emptyData;
    int err = proxy->ActiveUserKey(localId, emptyData, emptyData);
    if ((err == 0) && !osAccountInfo.GetIsVerified()) {
        isUserUnlocked = true;
    }
    err = proxy->PrepareStartUser(localId);
    if (err != 0) {
        ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_ACTIVATE,
            err, "Storage PrepareStartUser failed!");
    }
    ACCOUNT_LOGI("end, Storage PrepareStartUser ret %{public}d.", err);
    FinishTraceAdapter();
#else
    isUserUnlocked = osAccountInfo.GetIsVerified() ? false : true;
#endif
    if (isUserUnlocked) {
        osAccountInfo.SetIsVerified(true);
        PublishCommonEvent(osAccountInfo, OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED,
            Constants::OPERATION_UNLOCK);
    }
    ACCOUNT_LOGI("end, succeed!");
    return ERR_OK;
}

ErrCode OsAccountInterface::SendToStorageAccountStop(OsAccountInfo &osAccountInfo)
{
#ifdef HAS_STORAGE_PART
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        ACCOUNT_LOGE("failed to get system ability mgr.");
        ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_STOP,
            ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER,
            "GetSystemAbilityManager for storage failed!");
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER;
    }
    auto remote = systemAbilityManager->GetSystemAbility(STORAGE_MANAGER_MANAGER_ID);
    if (!remote) {
        ACCOUNT_LOGE("failed to get STORAGE_MANAGER_MANAGER_ID service.");
        ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_STOP,
            ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER,
            "GetSystemAbility for storage failed!");
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER;
    }
    auto proxy = iface_cast<StorageManager::IStorageManager>(remote);
    if (!proxy) {
        ACCOUNT_LOGE("failed to get STORAGE_MANAGER_MANAGER_ID proxy.");
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER;
    }
    StartTraceAdapter("StorageManager StopUser");
    int localId = osAccountInfo.GetLocalId();
    int err = proxy->StopUser(localId);
    if (err != 0) {
        ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_STOP,
            err, "Storage StopUser failed!");
    }
    err = proxy->InactiveUserKey(localId);
    if (err != 0) {
        ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_STOP,
            err, "Storage StopUser failed!");
    }

    FinishTraceAdapter();
#endif
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS
