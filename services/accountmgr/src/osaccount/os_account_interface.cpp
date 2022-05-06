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

#include "ability_manager_client.h"
#include "account_log_wrapper.h"
#include "bundle_mgr_interface.h"
#ifdef HAS_CES_PART
#include "common_event_manager.h"
#include "common_event_support.h"
#endif // HAS_CES_PART
#include "datetime_ex.h"
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
    ACCOUNT_LOGI("OsAccountInterface SendToAMSAccountStart start");
    ErrCode code = AAFwk::AbilityManagerClient::GetInstance()->StartUser(osAccountInfo.GetLocalId());
    if (code != ERR_OK) {
        ACCOUNT_LOGE("failed to AbilityManagerClient start errcode is %{public}d", code);
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_AM_ACCOUNT_START_ERROR;
    }
    ACCOUNT_LOGI("send AM to start is ok");
    return ERR_OK;
}

ErrCode OsAccountInterface::SendToAMSAccountStop(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountInterface SendToAMSAccountStop stop");
    sptr<OsAccountStopUserCallback> osAccountStopUserCallback = new (std::nothrow) OsAccountStopUserCallback();
    if (osAccountStopUserCallback == nullptr) {
        ACCOUNT_LOGE("alloc memory for stop user callback failed!");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }

    ErrCode code =
        AAFwk::AbilityManagerClient::GetInstance()->StopUser(osAccountInfo.GetLocalId(), osAccountStopUserCallback);
    if (code != ERR_OK) {
        ACCOUNT_LOGE("failed to AbilityManagerClient stop errcode is %{public}d", code);
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
    if (!osAccountStopUserCallback->isReaturnOk_) {
        ACCOUNT_LOGE("failed to AbilityManagerClient stop in call back");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_AM_ACCOUNT_START_ERROR;
    }
    ACCOUNT_LOGI("send AM to stop is ok");
    return ERR_OK;
}

ErrCode OsAccountInterface::SendToBMSAccountCreate(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountInterface SendToBMSAccountCreate start");
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        ACCOUNT_LOGE("failed to get system ability mgr.");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_BM_ACCOUNT_CREATE_ERROR;
    }

    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (!remoteObject) {
        ACCOUNT_LOGE("failed to get bundle manager service.");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_BM_ACCOUNT_CREATE_ERROR;
    }

    auto bunduleMgrProxy = iface_cast<OHOS::AppExecFwk::IBundleMgr>(remoteObject);
    if (!bunduleMgrProxy) {
        ACCOUNT_LOGE("failed to get bunduleMgrProxy");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_BM_ACCOUNT_CREATE_ERROR;
    }
    auto bunduleUserMgrProxy = bunduleMgrProxy->GetBundleUserMgr();
    if (!bunduleUserMgrProxy) {
        ACCOUNT_LOGE("failed to get bunduleUserMgrProxy");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_BM_ACCOUNT_CREATE_ERROR;
    }
    bunduleUserMgrProxy->CreateNewUser(osAccountInfo.GetLocalId());
    ACCOUNT_LOGI("call bm to create user ok");
    return ERR_OK;
}

ErrCode OsAccountInterface::SendToBMSAccountDelete(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountInterface SendToBMSAccountDelete start");
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        ACCOUNT_LOGE("failed to get system ability mgr.");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_BM_ACCOUNT_DELETE_ERROR;
    }

    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (!remoteObject) {
        ACCOUNT_LOGE("failed to get bundle manager service.");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_BM_ACCOUNT_DELETE_ERROR;
    }

    auto bunduleMgrProxy = iface_cast<OHOS::AppExecFwk::IBundleMgr>(remoteObject);
    if (!bunduleMgrProxy) {
        ACCOUNT_LOGE("failed to get bunduleMgrProxy");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_BM_ACCOUNT_DELETE_ERROR;
    }
    auto bunduleUserMgrProxy = bunduleMgrProxy->GetBundleUserMgr();
    if (!bunduleUserMgrProxy) {
        ACCOUNT_LOGE("failed to get bunduleUserMgrProxy");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_BM_ACCOUNT_DELETE_ERROR;
    }
    bunduleUserMgrProxy->RemoveUser(osAccountInfo.GetLocalId());
    ACCOUNT_LOGI("call bm to remove user ok");
    return ERR_OK;
}

#ifdef HAS_USER_IDM_PART
ErrCode OsAccountInterface::SendToIDMAccountDelete(OsAccountInfo &osAccountInfo)
{
    std::shared_ptr<OsAccountDeleteUserIdmCallback> callback = std::make_shared<OsAccountDeleteUserIdmCallback>();
    if (callback == nullptr) {
        ACCOUNT_LOGE("get idm callback ptr failed! insufficient memory!");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }

    int32_t ret = UserIAM::UserIDM::UserIDMClient::GetInstance().EnforceDelUser(osAccountInfo.GetLocalId(), callback);
    if (ret != 0) {
        ACCOUNT_LOGE("idm enforce delete user failed! error %{public}d", ret);
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
    OHOS::AAFwk::Want want;
    want.SetAction(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_ADDED);
    OHOS::EventFwk::CommonEventData data;
    data.SetCode(osAccountID);
    data.SetWant(want);
    if (!OHOS::EventFwk::CommonEventManager::PublishCommonEvent(data)) {
        ACCOUNT_LOGE("PublishCommonEvent for create account %{public}d failed!", osAccountID);
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
    OHOS::AAFwk::Want want;
    want.SetAction(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED);
    OHOS::EventFwk::CommonEventData data;
    data.SetCode(osAccountID);
    data.SetWant(want);
    if (!OHOS::EventFwk::CommonEventManager::PublishCommonEvent(data)) {
        ACCOUNT_LOGE("PublishCommonEvent for delete account %{public}d failed!", osAccountID);
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
    OHOS::AAFwk::Want want;
    want.SetAction(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    OHOS::EventFwk::CommonEventData data;
    data.SetCode(osAccountID);
    data.SetWant(want);
    if (!OHOS::EventFwk::CommonEventManager::PublishCommonEvent(data)) {
        ACCOUNT_LOGE("PublishCommonEvent for switched to account %{public}d failed!", osAccountID);
    } else {
        ACCOUNT_LOGI("PublishCommonEvent for switched to account %{public}d succeed!", osAccountID);
    }
#else // HAS_CES_PART
    ACCOUNT_LOGI("No common event part, do not publish for account %{public}d switched!", osAccountID);
#endif // HAS_CES_PART
}

ErrCode OsAccountInterface::SendToStorageAccountCreate(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountInterface SendToStorageAccountCreate start");
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        ACCOUNT_LOGE("failed to get system ability mgr.");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_CREATE_ERROR;
    }
    auto remote = systemAbilityManager->GetSystemAbility(STORAGE_MANAGER_MANAGER_ID);
    if (!remote) {
        ACCOUNT_LOGE("failed to get STORAGE_MANAGER_MANAGER_ID service.");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_CREATE_ERROR;
    }
    auto proxy = iface_cast<StorageManager::IStorageManager>(remote);
    if (!proxy) {
        ACCOUNT_LOGE("failed to get STORAGE_MANAGER_MANAGER_ID proxy.");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_CREATE_ERROR;
    }
    int err = proxy->PrepareAddUser(osAccountInfo.GetLocalId(),
        StorageManager::CRYPTO_FLAG_EL1 | StorageManager::CRYPTO_FLAG_EL2);
    ACCOUNT_LOGI("PrepareAddUser code is %{public}d", err);
    ACCOUNT_LOGI("OsAccountInterface PrepareAddUser succeed");
    return ERR_OK;
}

ErrCode OsAccountInterface::SendToStorageAccountRemove(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountInterface SendToStorageAccountRemove start");
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        ACCOUNT_LOGE("failed to get system ability mgr.");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_REMOVE_ERROR;
    }
    auto remote = systemAbilityManager->GetSystemAbility(STORAGE_MANAGER_MANAGER_ID);
    if (!remote) {
        ACCOUNT_LOGE("failed to get STORAGE_MANAGER_MANAGER_ID service.");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_REMOVE_ERROR;
    }
    auto proxy = iface_cast<StorageManager::IStorageManager>(remote);
    if (!proxy) {
        ACCOUNT_LOGE("failed to get STORAGE_MANAGER_MANAGER_ID proxy.");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_REMOVE_ERROR;
    }
    int err = proxy->RemoveUser(osAccountInfo.GetLocalId(),
        StorageManager::CRYPTO_FLAG_EL1 | StorageManager::CRYPTO_FLAG_EL2);
    ACCOUNT_LOGI("RemoveUser code is %{public}d", err);
    ACCOUNT_LOGI("OsAccountInterface RemoveUser succeed");
    return ERR_OK;
}

ErrCode OsAccountInterface::SendToStorageAccountStart(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountInterface SendToStorageAccountStart start");
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        ACCOUNT_LOGE("failed to get system ability mgr.");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_START_ERROR;
    }
    auto remote = systemAbilityManager->GetSystemAbility(STORAGE_MANAGER_MANAGER_ID);
    if (!remote) {
        ACCOUNT_LOGE("failed to get STORAGE_MANAGER_MANAGER_ID service.");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_START_ERROR;
    }
    auto proxy = iface_cast<StorageManager::IStorageManager>(remote);
    if (!proxy) {
        ACCOUNT_LOGE("failed to get STORAGE_MANAGER_MANAGER_ID proxy.");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_START_ERROR;
    }
    int err = proxy->PrepareStartUser(osAccountInfo.GetLocalId());
    ACCOUNT_LOGI("PrepareStartUser code is %{public}d", err);
    ACCOUNT_LOGI("OsAccountInterface PrepareStartUser succeed");
    return ERR_OK;
}

ErrCode OsAccountInterface::SendToStorageAccountStop(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("OsAccountInterface SendToStorageAccountStop start");
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        ACCOUNT_LOGE("failed to get system ability mgr.");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_STOP_ERROR;
    }
    auto remote = systemAbilityManager->GetSystemAbility(STORAGE_MANAGER_MANAGER_ID);
    if (!remote) {
        ACCOUNT_LOGE("failed to get STORAGE_MANAGER_MANAGER_ID service.");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_STOP_ERROR;
    }
    auto proxy = iface_cast<StorageManager::IStorageManager>(remote);
    if (!proxy) {
        ACCOUNT_LOGE("failed to get STORAGE_MANAGER_MANAGER_ID proxy.");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_STORAGE_ACCOUNT_STOP_ERROR;
    }
    int err = proxy->StopUser(osAccountInfo.GetLocalId());
    ACCOUNT_LOGI("StopUser code is %{public}d", err);
    ACCOUNT_LOGI("OsAccountInterface StopUser succeed");
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS
