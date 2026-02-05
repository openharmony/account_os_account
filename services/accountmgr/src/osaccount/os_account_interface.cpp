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

#include <cerrno>
#include <condition_variable>
#include <future>
#include <thread>

#include "ability_manager_adapter.h"
#include "account_constants.h"
#include "account_log_wrapper.h"
#include "bundle_manager_adapter.h"
#ifdef HAS_CES_PART
#include "common_event_manager.h"
#include "common_event_support.h"
#endif // HAS_CES_PART
#include "datetime_ex.h"
#ifdef HICOLLIE_ENABLE
#include "xcollie/xcollie.h"
#endif // HICOLLIE_ENABLE
#include "account_hisysevent_adapter.h"
#include "hitrace_adapter.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#ifdef HAS_STORAGE_PART
#include "istorage_manager.h"
#endif
#include "os_account_constants.h"
#include "os_account_delete_user_idm_callback.h"
#include "os_account_user_callback.h"
#include "os_account_subscribe_manager.h"
#ifdef HAS_STORAGE_PART
#include "storage_manager_proxy.h"
#include "storage_service_errno.h"
#include "storage_service_constants.h"
#endif
#include "iinner_os_account_manager.h"
#include "system_ability_definition.h"
#ifdef HAS_USER_IDM_PART
#include "account_iam_callback.h"
#include "user_idm_client.h"
#endif // HAS_USER_IDM_PART
#ifdef HAS_CES_PART
#include "want.h"
#endif // HAS_CES_PART


namespace OHOS {
namespace AccountSA {
namespace {
const char OPERATION_START[] = "start";

#ifdef HAS_STORAGE_PART
constexpr uint32_t CRYPTO_FLAG_EL1 = 1;
constexpr uint32_t CRYPTO_FLAG_EL2 = 2;
#endif

constexpr int32_t WAIT_BMS_TIMEOUT = 5;
#ifdef HICOLLIE_ENABLE
constexpr int32_t STORAGE_TIMEOUT = 10; // seconds
#endif // HICOLLIE_ENABLE
constexpr int32_t DELAY_FOR_EXCEPTION = 100;
constexpr int32_t MAX_RETRY_TIMES = 10;
constexpr int32_t MAX_GETBUNDLE_WAIT_TIMES = 10 * 1000 * 1000;
constexpr int32_t GET_MSG_FREQ = 100 * 1000;
constexpr int32_t DEAL_TIMES = MAX_GETBUNDLE_WAIT_TIMES / GET_MSG_FREQ;
constexpr int64_t MAX_BMS_UNLOCK_TIMES = 5 * 1000;
}

ErrCode InnerSendToAMSAccountStart(
    int32_t localId, sptr<OsAccountUserCallback> callback, uint64_t displayId, bool isAppRecovery)
{
    ErrCode code = ERR_OK;
    int32_t retryTimes = 0;
    while (retryTimes < MAX_RETRY_TIMES) {
        code = AbilityManagerAdapter::GetInstance()->StartUser(localId, displayId, callback, isAppRecovery);
        if (code == ERR_OK || (code != Constants::E_IPC_ERROR && code != Constants::E_IPC_SA_DIED)) {
            break;
        }
        ACCOUNT_LOGE("AbilityManagerAdapter StartUser failed! errcode is %{public}d, retry %{public}d",
            code, retryTimes + 1);
        retryTimes++;
        std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_EXCEPTION));
    }
    return code;
}

ErrCode OsAccountInterface::SendToAMSAccountStart(OsAccountInfo &osAccountInfo, const uint64_t displayId,
    const OsAccountStartCallbackFunc &callbackFunc, bool isAppRecovery)
{
    int32_t localId = osAccountInfo.GetLocalId();
    ACCOUNT_LOGI("Start OS account %{public}d", localId);
    sptr<OsAccountUserCallback> osAccountStartUserCallback = new (std::nothrow) OsAccountUserCallback(callbackFunc);
    if (osAccountStartUserCallback == nullptr) {
        ACCOUNT_LOGE("Alloc memory for start user callback failed!");
        ReportOsAccountOperationFail(localId, OPERATION_START,
            ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR, "malloc for OsAccountUserCallback failed!");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    StartTraceAdapter("AbilityManagerAdapter StartUser");

    ErrCode code = InnerSendToAMSAccountStart(localId, osAccountStartUserCallback, displayId, isAppRecovery);
    if (code != ERR_OK) {
        ACCOUNT_LOGE("AbilityManagerAdapter StartUser failed after retries! errcode is %{public}d", code);
        ReportOsAccountOperationFail(localId, Constants::OPERATION_ACTIVATE, code,
            "AbilityManager failed to start user");
        FinishTraceAdapter();
        return code;
    }
    std::unique_lock<std::mutex> lock(osAccountStartUserCallback->mutex_);
    osAccountStartUserCallback->onStartCondition_.wait(
        lock, [osAccountStartUserCallback] { return osAccountStartUserCallback->isCalled_; });
    FinishTraceAdapter();
    if (osAccountStartUserCallback->resultCode_ != ERR_OK) {
        ACCOUNT_LOGE("Failed to AbilityManagerService in call back");
        ReportOsAccountOperationFail(localId, OPERATION_START, osAccountStartUserCallback->resultCode_,
                                     "AbilityManager failed to start user in callback");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_AM_ACCOUNT_START_ERROR;
    }
    ACCOUNT_LOGI("End, succeed %{public}d", localId);
    return code;
}

ErrCode InnerSendToAMSAccountStop(int32_t localId, sptr<OsAccountUserCallback> callback)
{
    ErrCode code = ERR_OK;
    int32_t retryTimes = 0;
    while (retryTimes < MAX_RETRY_TIMES) {
        code = AbilityManagerAdapter::GetInstance()->StopUser(localId, callback);
        if (code == ERR_OK || (code != Constants::E_IPC_ERROR && code != Constants::E_IPC_SA_DIED)) {
            break;
        }
        ACCOUNT_LOGE("AbilityManagerAdapter StopUser failed! errcode is %{public}d, retry %{public}d",
            code, retryTimes + 1);
        retryTimes++;
        std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_EXCEPTION));
    }
    return code;
}

ErrCode OsAccountInterface::SendToAMSAccountStop(OsAccountInfo &osAccountInfo)
{
    int32_t localId = osAccountInfo.GetLocalId();
    ACCOUNT_LOGI("Stop OS account %{public}d", localId);
    sptr<OsAccountUserCallback> osAccountStopUserCallback = new (std::nothrow) OsAccountUserCallback();
    if (osAccountStopUserCallback == nullptr) {
        ACCOUNT_LOGE("Alloc memory for stop user callback failed!");
        ReportOsAccountOperationFail(localId, Constants::OPERATION_STOP,
            ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR, "malloc for OsAccountUserCallback failed!");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    StartTraceAdapter("AbilityManagerAdapter StopUser");

    ErrCode code = InnerSendToAMSAccountStop(localId, osAccountStopUserCallback);
    if (code != ERR_OK) {
        ACCOUNT_LOGE("Failed to AbilityManagerAdapter stop after retries! errcode is %{public}d", code);
        ReportOsAccountOperationFail(localId, Constants::OPERATION_STOP, code,
            "AbilityManager failed to stop user");
        FinishTraceAdapter();
        return code;
    }
    std::unique_lock<std::mutex> lock(osAccountStopUserCallback->mutex_);
    osAccountStopUserCallback->onStopCondition_.wait(lock, [osAccountStopUserCallback] {
        return osAccountStopUserCallback->isCalled_;
    });
    FinishTraceAdapter();
    if (osAccountStopUserCallback->resultCode_ != ERR_OK) {
        ACCOUNT_LOGE("Failed to AbilityManagerService in call back");
        ReportOsAccountOperationFail(localId, Constants::OPERATION_STOP,
            osAccountStopUserCallback->resultCode_, "AbilityManager failed to stop user in callback");
        return ERR_OSACCOUNT_SERVICE_INTERFACE_TO_AM_ACCOUNT_START_ERROR;
    }
    ACCOUNT_LOGI("End, succeed %{public}d", localId);
    return code;
}

ErrCode InnerSendToAMSAccountDeactivate(int32_t localId, sptr<OsAccountUserCallback> callback)
{
    ErrCode code = ERR_OK;
    int32_t retryTimes = 0;
    while (retryTimes < MAX_RETRY_TIMES) {
        code = AbilityManagerAdapter::GetInstance()->LogoutUser(localId, callback);
        if (code == ERR_OK || (code != Constants::E_IPC_ERROR && code != Constants::E_IPC_SA_DIED)) {
            break;
        }
        ACCOUNT_LOGE("AbilityManagerAdapter LogoutUser failed! errcode is %{public}d, retry %{public}d",
            code, retryTimes + 1);
        retryTimes++;
        std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_EXCEPTION));
    }
    return code;
}

ErrCode OsAccountInterface::SendToAMSAccountDeactivate(OsAccountInfo &osAccountInfo)
{
    int32_t localId = osAccountInfo.GetLocalId();
    ACCOUNT_LOGI("Deactivate OS account %{public}d", localId);
    sptr<OsAccountUserCallback> deactivateUserCallback = new (std::nothrow) OsAccountUserCallback();
    if (deactivateUserCallback == nullptr) {
        ACCOUNT_LOGE("Alloc memory for deactivate user callback failed!");
        ReportOsAccountOperationFail(localId, Constants::OPERATION_STOP,
            ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR, "malloc for OsAccountUserCallback failed!");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }

    StartTraceAdapter("AbilityManagerAdapter LogoutUser");
    ErrCode code = InnerSendToAMSAccountDeactivate(localId, deactivateUserCallback);
    if (code != ERR_OK) {
        ACCOUNT_LOGE("Failed to AbilityManagerAdapter logout after retries! errcode is %{public}d", code);
        ReportOsAccountOperationFail(localId, Constants::OPERATION_STOP, code,
            "AbilityManager failed to logout user");
        FinishTraceAdapter();
        return code;
    }
    std::unique_lock<std::mutex> lock(deactivateUserCallback->mutex_);
    deactivateUserCallback->onLogoutCondition_.wait(lock, [deactivateUserCallback] {
        return deactivateUserCallback->isCalled_;
    });
    FinishTraceAdapter();
    if (deactivateUserCallback->resultCode_ != ERR_OK) {
        ACCOUNT_LOGE("Failed to logout user in call back");
        ReportOsAccountOperationFail(localId, Constants::OPERATION_STOP,
            deactivateUserCallback->resultCode_, "AbilityManager failed to logout user in callback");
        return deactivateUserCallback->resultCode_;
    }
    ACCOUNT_LOGI("Deactivate End, succeed %{public}d", localId);
    return code;
}

ErrCode OsAccountInterface::SendToBMSAccountCreate(
    OsAccountInfo &osAccountInfo, const std::vector<std::string> &disallowedHapList,
    const std::optional<std::vector<std::string>> &allowedHapList)
{
    ErrCode errCode = ERR_OK;
    int32_t retryTimes = 0;
    while (retryTimes < MAX_RETRY_TIMES) {
        errCode = BundleManagerAdapter::GetInstance()->CreateNewUser(osAccountInfo.GetLocalId(),
            disallowedHapList, allowedHapList);
        if ((errCode != Constants::E_IPC_ERROR) && (errCode != Constants::E_IPC_SA_DIED)) {
            break;
        }
        ACCOUNT_LOGE("Fail to SendToBMSAccountCreate, errCode %{public}d.", errCode);
        retryTimes++;
        std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_EXCEPTION));
    }
    return errCode;
}

ErrCode OsAccountInterface::IsBundleInstalled(
    const std::string &bundleName, int32_t userId, int32_t &appIndex, bool &isBundleInstalled)
{
    ErrCode errCode = ERR_OK;
    int32_t retryTimes = 0;
    while (retryTimes < MAX_RETRY_TIMES) {
        errCode = BundleManagerAdapter::GetInstance()->IsBundleInstalled(bundleName,
            userId, appIndex, isBundleInstalled);
        if ((errCode != Constants::E_IPC_ERROR) && (errCode != Constants::E_IPC_SA_DIED)) {
            break;
        }
        ACCOUNT_LOGE("Fail to IsBundleInstalled, errCode %{public}d.", errCode);
        retryTimes++;
        std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_EXCEPTION));
    }
    return errCode;
}

ErrCode OsAccountInterface::SendToBMSAccountDelete(OsAccountInfo &osAccountInfo)
{
    return BundleManagerAdapter::GetInstance()->RemoveUser(osAccountInfo.GetLocalId());
}

void OsAccountInterface::SendToBMSAccountUnlocked(const OsAccountInfo &osAccountInfo)
{
    auto localId = osAccountInfo.GetLocalId();
    ACCOUNT_LOGI("Begin, %{public}d", localId);
    auto startTime = std::chrono::high_resolution_clock::now();
    ErrCode res = BundleManagerAdapter::GetInstance()->CreateNewBundleEl5Dir(localId);
    auto endTime = std::chrono::high_resolution_clock::now();
    if (res != ERR_OK) {
        ACCOUNT_LOGE("Failed, %{public}d, errCode: %{public}d", localId, res);
        ReportOsAccountOperationFail(
            localId, Constants::OPERATION_SECOND_MOUNT, res, "Failed to create new bundle el5 dir");
        return;
    }
    int64_t durationTime = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    if (durationTime > MAX_BMS_UNLOCK_TIMES) {
        ReportOsAccountOperationFail(localId, Constants::OPERATION_SECOND_MOUNT, -1,
            "Notify bms unlock timeout, total ms: " + std::to_string(durationTime));
    }
    ReportOsAccountLifeCycle(localId, "notifyBmsUnlock");
    ACCOUNT_LOGI("End, %{public}d", localId);
}

void OsAccountInterface::SendToBMSAccountUnlockedWithTimeout(const OsAccountInfo &osAccountInfo)
{
    std::promise<bool> promise;
    std::future<bool> future = promise.get_future();
    std::thread([osAccountInfo, p = std::move(promise)]() mutable {
#ifdef HICOLLIE_ENABLE
        auto localId = osAccountInfo.GetLocalId();
        XCollieCallback callbackFunc = [localId](void *) {
            ACCOUNT_LOGE("XCollieCallback: SendToBMSAccountUnlocked timeout, %{public}d", localId);
            ReportOsAccountOperationFail(localId, Constants::OPERATION_SECOND_MOUNT, -1,
                "Create new bundle el5 dir time out");
        };
        int32_t timerId = HiviewDFX::XCollie::GetInstance().SetTimer(
            TIMER_NAME, WAIT_BMS_TIMEOUT, callbackFunc, nullptr, HiviewDFX::XCOLLIE_FLAG_LOG);
#endif // HICOLLIE_ENABLE
        SendToBMSAccountUnlocked(osAccountInfo);
#ifdef HICOLLIE_ENABLE
        HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
#endif // HICOLLIE_ENABLE
        p.set_value(true);
    }).detach();

    if (future.wait_for(std::chrono::seconds(WAIT_BMS_TIMEOUT)) == std::future_status::timeout) {
        ACCOUNT_LOGE("SendToBMSAccountUnlocked timeout, %{public}d", osAccountInfo.GetLocalId());
    }
}

#ifdef HAS_USER_IDM_PART
ErrCode OsAccountInterface::SendToIDMAccountDelete(OsAccountInfo &osAccountInfo)
{
    std::shared_ptr<OsAccountDeleteUserIdmCallback> callback = std::make_shared<OsAccountDeleteUserIdmCallback>();
    if (callback == nullptr) {
        ACCOUNT_LOGE("Get idm callback ptr failed! insufficient memory!");
        ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_REMOVE,
            ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR,
            "Failed to malloc for OsAccountDeleteUserIdmCallback");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    StartTraceAdapter("UserIDMClient EnforceDelUser");
    int32_t ret = UserIam::UserAuth::UserIdmClient::GetInstance().EraseUser(osAccountInfo.GetLocalId(), callback);
    if ((ret != UserIam::UserAuth::ResultCode::SUCCESS) &&
        (ret != UserIam::UserAuth::ResultCode::NOT_ENROLLED)) {
        ACCOUNT_LOGE("Idm enforce delete user failed! error %{public}d", ret);
        ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_REMOVE, ret,
            "Failed to call EraseUser");
        FinishTraceAdapter();
        return ERR_OSACCOUNT_SERVICE_IAM_ERASE_USER_FAILED;
    }

    // wait callback
    {
        std::unique_lock<std::mutex> lck(callback->mutex_);
        if (!callback->isCalled_) {
            callback->onResultCondition_.wait_for(lck, std::chrono::seconds(Constants::TIME_WAIT_TIME_OUT));
        }
        if (!callback->isCalled_) {
            ACCOUNT_LOGE("Idm did not call back! timeout!");
            ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_REMOVE, -1,
                "UserIDM erase user timeout");
            FinishTraceAdapter();
            return ERR_OSACCOUNT_SERVICE_IAM_ERASE_USER_FAILED;
        }
        if ((callback->resultCode_ != UserIam::UserAuth::ResultCode::SUCCESS) &&
            (callback->resultCode_ != UserIam::UserAuth::ResultCode::NOT_ENROLLED)) {
            ACCOUNT_LOGE("Idm enforce delete user failed! Callback error %{public}d", callback->resultCode_);
            ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_REMOVE,
                callback->resultCode_, "Failed to erase user credential");
            FinishTraceAdapter();
            return ERR_OSACCOUNT_SERVICE_IAM_ERASE_USER_FAILED;
        }
    }

    ACCOUNT_LOGI("Send to idm account delete and get callback succeed!");
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
        ReportOsAccountOperationFail(osAccountID, Constants::OPERATION_REMOVE, -1, "Failed to publish common event");
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

void OsAccountInterface::SendToCESAccountSwitched(int newId, int oldId, uint64_t displayId)
{
#ifdef HAS_CES_PART
    StartTraceAdapter("PublishCommonEvent account switched");
    OHOS::AAFwk::Want want;
    want.SetAction(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    want.SetParam("oldId", std::to_string(oldId));
    want.SetParam("displayId", std::to_string(displayId));
    OHOS::EventFwk::CommonEventData data;
    data.SetCode(newId);
    data.SetWant(want);
    if (!OHOS::EventFwk::CommonEventManager::PublishCommonEvent(data)) {
        ACCOUNT_LOGE("PublishCommonEvent failed, account switched:%{public}d->%{public}d displayId: %{public}llu",
            oldId, newId, static_cast<unsigned long long>(displayId));
        ReportOsAccountOperationFail(newId, Constants::OPERATION_SWITCH, -1, "PublishCommonEvent switched failed!");
    } else {
        ACCOUNT_LOGI("PublishCommonEvent successful, account switched:%{public}d->%{public}d displayId: %{public}llu",
            oldId, newId, static_cast<unsigned long long>(displayId));
    }
    FinishTraceAdapter();
#else // HAS_CES_PART
    ACCOUNT_LOGI("No common event part, do not publish for account switched:%{public}d->%{public}d", oldId, newId);
#endif // HAS_CES_PART
}

ErrCode OsAccountInterface::SendToStorageAccountCreate(OsAccountInfo &osAccountInfo)
{
    ErrCode errCode = ERR_OK;
    int32_t retryTimes = 0;
    while (retryTimes < MAX_RETRY_TIMES) {
        errCode = InnerSendToStorageAccountCreate(osAccountInfo);
        if (errCode != Constants::E_IPC_ERROR && errCode != Constants::E_IPC_SA_DIED) {
            break;
        }
        ACCOUNT_LOGE("Fail to SendToStorageAccountCreate,id=%{public}d, errCode %{public}d.",
            osAccountInfo.GetLocalId(), errCode);
        retryTimes++;
        std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_EXCEPTION));
    }
    return errCode;
}

#ifdef HAS_STORAGE_PART
static ErrCode PrepareAddUser(const sptr<StorageManager::IStorageManager> &proxy, int32_t userId)
{
    ErrCode err = proxy->PrepareAddUser(userId, CRYPTO_FLAG_EL1 | CRYPTO_FLAG_EL2);
    if (err == 0) {
        return ERR_OK;
    }
    ReportOsAccountOperationFail(userId, Constants::OPERATION_CREATE, err, "StorageManager failed to add user");
    if (err == -EEXIST) {
        return ERR_OK;
    }
    return err;
}
#endif

ErrCode OsAccountInterface::InnerSendToStorageAccountCreate(OsAccountInfo &osAccountInfo)
{
#ifdef HAS_STORAGE_PART
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    int32_t localId = osAccountInfo.GetLocalId();
    if (!systemAbilityManager) {
        ACCOUNT_LOGE("Failed to get system ability mgr.");
        ReportOsAccountOperationFail(localId, Constants::OPERATION_CREATE,
            ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER,
            "GetSystemAbilityManager for storage failed!");
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER;
    }
    auto remote = systemAbilityManager->CheckSystemAbility(STORAGE_MANAGER_MANAGER_ID);
    if (!remote) {
        ACCOUNT_LOGE("Failed to get STORAGE_MANAGER_MANAGER_ID service.");
        ReportOsAccountOperationFail(localId, Constants::OPERATION_CREATE,
            ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER,
            "CheckSystemAbility for storage failed!");
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER;
    }
    auto proxy = iface_cast<StorageManager::IStorageManager>(remote);
    if (!proxy) {
        ACCOUNT_LOGE("Failed to get STORAGE_MANAGER_MANAGER_ID proxy.");
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER;
    }
    StartTraceAdapter("StorageManager PrepareAddUser");

    ErrCode err = PrepareAddUser(proxy, localId);
    if (err == ERR_OK) {
        FinishTraceAdapter();
        return ERR_OK;
    }

    ACCOUNT_LOGI("PrepareAddUser Failed, start check and clean accounts.");
    auto &osAccountManager = IInnerOsAccountManager::GetInstance();
    if (osAccountManager.CleanGarbageOsAccounts(localId) <= 0) {
        FinishTraceAdapter();
        return err;
    }
    ACCOUNT_LOGI("Clean garbage account data, Retry Storage PrepareAddUser.");
    err = PrepareAddUser(proxy, localId);
    FinishTraceAdapter();
    return err;
#else
    return ERR_OK;
#endif
}

ErrCode OsAccountInterface::SendToStorageAccountRemove(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("Start");
#ifdef HAS_STORAGE_PART
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        ACCOUNT_LOGE("Failed to get system ability mgr.");
        ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_REMOVE,
            ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER,
            "Failed to get SystemAbilityManager");
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER;
    }
    auto remote = systemAbilityManager->GetSystemAbility(STORAGE_MANAGER_MANAGER_ID);
    if (!remote) {
        ACCOUNT_LOGE("Failed to get STORAGE_MANAGER_MANAGER_ID service.");
        ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_REMOVE,
            ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER,
            "Failed to get StorageManager service");
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER;
    }
    auto proxy = iface_cast<StorageManager::IStorageManager>(remote);
    if (!proxy) {
        ACCOUNT_LOGE("Failed to get STORAGE_MANAGER_MANAGER_ID proxy.");
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER;
    }

    StartTraceAdapter("StorageManager RemoveUser");
    int err = proxy->RemoveUser(osAccountInfo.GetLocalId(),
        CRYPTO_FLAG_EL1 | CRYPTO_FLAG_EL2);
    if (err != 0) {
        ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_REMOVE,
            err, "StorageManager failed to remove user");
        ACCOUNT_LOGE("Storage RemoveUser failed, ret %{public}d", err);
        FinishTraceAdapter();
        return err;
    }

    ACCOUNT_LOGI("End, Storage RemoveUser ret %{public}d.", err);
    FinishTraceAdapter();
#endif
    return ERR_OK;
}

#ifdef HAS_STORAGE_PART
static ErrCode GetStorageProxy(sptr<StorageManager::IStorageManager> &proxy)
{
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        ACCOUNT_LOGE("Failed to get system ability mgr.");
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER;
    }
    auto remote = systemAbilityManager->CheckSystemAbility(STORAGE_MANAGER_MANAGER_ID);
    if (!remote) {
        ACCOUNT_LOGE("Failed to get STORAGE_MANAGER_MANAGER_ID service.");
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER;
    }
    proxy = iface_cast<StorageManager::IStorageManager>(remote);
    return ERR_OK;
}

#ifdef HAS_USER_IDM_PART
void ReportDecryptionFaultAsync(const int localId)
{
    std::thread([localId]() {
        std::vector<UserIam::UserAuth::CredentialInfo> credentialInfoList;
        int32_t ret = UserIam::UserAuth::UserIdmClient::GetInstance().GetCredentialInfoSync(
            localId, UserIam::UserAuth::AuthType::PIN, credentialInfoList);
        if (ret != ERR_OK) {
            ACCOUNT_LOGE("Get credential info sync failed, ret=%{public}d, localId=%{public}d", ret, localId);
            ReportOsAccountOperationFail(localId, Constants::OPERATION_ACTIVATE,
                ret, "Get credential info sync failed");
            return;
        }
        if (credentialInfoList.empty()) {
            ACCOUNT_LOGE("EL2 decryption failed and no credential, localId=%{public}d", localId);
            ReportOsAccountOperationFail(localId, Constants::OPERATION_ACTIVATE,
                ErrNo::E_ACTIVE_EL2_FAILED, "EL2 decryption failed and no credential");
        }
    }).detach();
}
#endif

#ifdef HAS_USER_IDM_PART
static ErrCode GetPINCredentialInfo(int32_t userId, bool &isPINExist)
{
    int32_t retryTimes = 0;
    while (retryTimes < MAX_RETRY_TIMES) {
        auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if ((systemAbilityManager == nullptr) ||
            (systemAbilityManager->GetSystemAbility(SUBSYS_USERIAM_SYS_ABILITY_USERIDM) == nullptr)) {
            ACCOUNT_LOGE("Failed to get iam service, id:%{public}d, retry!", userId);
            retryTimes++;
            std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_EXCEPTION));
        } else {
            break;
        }
    }
    auto callback = std::make_shared<GetCredentialInfoSyncCallback>(userId);
    ACCOUNT_LOGI("Start get credential info, userId:%{public}d", userId);
    int32_t ret = UserIam::UserAuth::UserIdmClient::GetInstance().GetCredentialInfo(
        userId, UserIam::UserAuth::AuthType::PIN, callback);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("GetCredentialInfo failed, ret:%{public}d", ret);
        return ret;
    }
    std::unique_lock<std::mutex> lck(callback->secureMtx_);
    auto status = callback->secureCv_.wait_for(lck, std::chrono::seconds(Constants::TIME_WAIT_TIME_OUT), [callback] {
        return callback->isCalled_;
    });
    if (!status) {
        ACCOUNT_LOGE("Get credential info timed out");
        isPINExist = false; // Timeout defaults to false
        ReportOsAccountOperationFail(userId, "checkIAMFault", ERR_ACCOUNT_COMMON_OPERATION_TIMEOUT,
            "Get credential info timed out in the secret exception flag check process");
        return ERR_ACCOUNT_COMMON_OPERATION_TIMEOUT;
    }
    if ((callback->result_ == ERR_OK) || (callback->result_ == ERR_IAM_NOT_ENROLLED)) {
        isPINExist = callback->hasPIN_;
    }
    return callback->result_;
}

static bool IsSecretFlagExist(int32_t userId)
{
    std::string path = Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + std::to_string(userId) +
        Constants::PATH_SEPARATOR + Constants::USER_SECRET_FLAG_FILE_NAME;
    auto accountFileOperator = std::make_shared<AccountFileOperator>();
    bool isExist = accountFileOperator->IsExistFile(path);
    ACCOUNT_LOGI("The iam_fault file existence status:%{public}d, userId:%{public}d", isExist, userId);
    return isExist;
}

static void DeleteSecretFlag(int32_t userId)
{
    auto accountFileOperator = std::make_shared<AccountFileOperator>();
    std::string path = Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR + std::to_string(userId) +
        Constants::PATH_SEPARATOR + Constants::USER_SECRET_FLAG_FILE_NAME;
    ErrCode code = accountFileOperator->DeleteDirOrFile(path);
    if (code != ERR_OK) {
        ReportOsAccountOperationFail(userId, "startUser", code,
            "Failed to delete iam_fault file when PIN is not exist");
    }
}

bool IsExistPIN(int32_t userId)
{
    bool isExistPIN = false;
    ErrCode ret = GetPINCredentialInfo(userId, isExistPIN);
    if (ret == ERR_IAM_NOT_ENROLLED) {
        DeleteSecretFlag(userId);
        return false;
    }
    if (ret == ERR_OK) {
        if (isExistPIN) {
            return true;
        } else {
            DeleteSecretFlag(userId);
            return false;
        }
    }
    return false;
}

int32_t NeedSkipActiveUserKey(const int localId, bool &isNeedSkip)
{
    isNeedSkip = false;
    if (!IsSecretFlagExist(localId)) {
        return ERR_OK;
    }
    // Check if the storage is already unlocked
    sptr<StorageManager::IStorageManager> proxy = nullptr;
    if (GetStorageProxy(proxy) != ERR_OK) {
        ACCOUNT_LOGE("Failed to get storage manager proxy!");
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER;
    }
    bool isFileEncrypt = true;
    ErrCode errCode = proxy->GetFileEncryptStatus(localId, isFileEncrypt, true);
    ACCOUNT_LOGI("Get file encrypt ret = %{public}d, status = %{public}d, id = %{public}d",
        errCode, isFileEncrypt, localId);
    if (errCode != 0) {
        ReportOsAccountOperationFail(localId, Constants::OPERATION_ACTIVATE,
            errCode, "StorageManager failed to get file encrypt status.");
        return errCode;
    }
    if (!isFileEncrypt) {
        ACCOUNT_LOGW("The storage has been decrypted and does not need to be processed again.");
        isNeedSkip = true;
        return ERR_OK; // return ok to send unlock events
    }
    // Check if the IAM has PIN credential
    if (IsExistPIN(localId)) {
        ACCOUNT_LOGW("Secret operation flag and PIN exists, skip empty secret 'ActiveUserKey'!");
        isNeedSkip = true;
        return ERR_ACCOUNT_COMMON_SECRET_CHECK; // return err to not send unlock events
    }
    return ERR_OK;
}
#endif // HAS_USER_IDM_PART

int32_t OsAccountInterface::UnlockUser(const int localId, bool startUser)
{
    int32_t retryTimes = 0;
    int32_t errCode = 0;
    while (retryTimes < MAX_RETRY_TIMES) {
        sptr<StorageManager::IStorageManager> proxy = nullptr;
        if (GetStorageProxy(proxy) != ERR_OK) {
            ACCOUNT_LOGE("Failed to get STORAGE_MANAGER_MANAGER_ID proxy, retry!");
            errCode = ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER;
            retryTimes++;
            std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_EXCEPTION));
            continue;
        }
#ifdef HAS_USER_IDM_PART
        bool isNeedSkip = false;
        errCode = NeedSkipActiveUserKey(localId, isNeedSkip);
        if (isNeedSkip) {
            return errCode;
        }
#endif // HAS_USER_IDM_PART
        std::vector<uint8_t> emptyData;
        errCode = proxy->ActiveUserKey(localId, emptyData, emptyData);
        ACCOUNT_LOGI("ActiveUserKey end, ret %{public}d.", errCode);
        if (errCode != ErrNo::E_ACTIVE_EL2_FAILED) {
            errCode = startUser ? proxy->PrepareStartUser(localId) : 0;
            ACCOUNT_LOGI("PrepareStartUser end, errCode %{public}d.", errCode);
            if (errCode != 0) {
                ReportOsAccountOperationFail(localId, Constants::OPERATION_ACTIVATE,
                    errCode, "StorageManager failed to start user");
            }
#ifdef HAS_USER_IDM_PART
        } else {
            ReportDecryptionFaultAsync(localId);
#endif
        }
        if ((errCode == Constants::E_IPC_ERROR) || (errCode == Constants::E_IPC_SA_DIED)) {
            ACCOUNT_LOGE("Failed to PrepareStartUser, id:%{public}d, errCode:%{public}d, retry!", localId, errCode);
            retryTimes++;
            std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_EXCEPTION));
            continue;
        } else {
            break;
        }
    }
    return errCode;
}
#endif

ErrCode OsAccountInterface::SendToStorageAccountStart(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("Start");
    bool isUserUnlocked = false;
#ifdef HAS_STORAGE_PART
    int localId = osAccountInfo.GetLocalId();
    StartTraceAdapter("StorageManager PrepareStartUser");
    int32_t err = UnlockUser(localId, !osAccountInfo.GetIsVerified());
    if (err == ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER) {
        ReportOsAccountOperationFail(localId, Constants::OPERATION_ACTIVATE,
            ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER, "Failed to get StorageManager service");
        ACCOUNT_LOGE("Failed to get STORAGE_MANAGER_MANAGER_ID proxy.");
        return err;
    }
    if (err == ERR_OK) {
        isUserUnlocked = true;
    }
    ACCOUNT_LOGI("End, Storage PrepareStartUser ret %{public}d.", err);
    FinishTraceAdapter();
#else
    isUserUnlocked = true;
#endif
    if (!osAccountInfo.GetIsVerified() && isUserUnlocked) {
        ACCOUNT_LOGI("OS account:%{public}d is unlocked.", osAccountInfo.GetLocalId());
        osAccountInfo.SetIsVerified(true);
        bool hasCredential = osAccountInfo.GetCredentialId() > 0;
        if (!hasCredential) {
            ACCOUNT_LOGI("OS account:%{public}d is loggen in.", osAccountInfo.GetLocalId());
            osAccountInfo.SetIsLoggedIn(true);
            osAccountInfo.SetLastLoginTime(std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        }
    }
    ACCOUNT_LOGI("End, succeed!");
    return ERR_OK;
}

ErrCode OsAccountInterface::SendToStorageAccountStop(OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("Stop storage, account id = %{public}d", osAccountInfo.GetLocalId());
#ifdef HAS_STORAGE_PART
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        ACCOUNT_LOGE("Failed to get system ability mgr.");
        ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_STOP,
            ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER,
            "GetSystemAbilityManager for storage failed!");
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER;
    }
    auto remote = systemAbilityManager->GetSystemAbility(STORAGE_MANAGER_MANAGER_ID);
    if (!remote) {
        ACCOUNT_LOGE("Failed to get STORAGE_MANAGER_MANAGER_ID service.");
        ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_STOP,
            ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER,
            "GetSystemAbility for storage failed!");
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER;
    }
    auto proxy = iface_cast<StorageManager::IStorageManager>(remote);
    if (!proxy) {
        ACCOUNT_LOGE("Failed to get STORAGE_MANAGER_MANAGER_ID proxy.");
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER;
    }
    osAccountInfo.SetIsVerified(false);
    StartTraceAdapter("StorageManager StopUser");
    int localId = osAccountInfo.GetLocalId();
    int err = proxy->StopUser(localId);
    if (err != 0) {
        ACCOUNT_LOGE("StorageManager failed to stop user, err: %{public}d", err);
        ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_STOP,
            err, "StorageManager failed to stop user");
        FinishTraceAdapter();
        return ERR_OSACCOUNT_SERVICE_STORAGE_STOP_USER_FAILED;
    }
    err = proxy->InactiveUserKey(localId);
    if (err != 0) {
        ACCOUNT_LOGE("StorageManager failed to inactivate user key, err: %{public}d", err);
        ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_STOP,
            err, "StorageManager failed to inactivate user key");
        FinishTraceAdapter();
        return ERR_OSACCOUNT_SERVICE_STORAGE_STOP_USER_FAILED;
    }
    FinishTraceAdapter();
#else
    osAccountInfo.SetIsVerified(false);
#endif
    return ERR_OK;
}

ErrCode OsAccountInterface::SendToStorageAccountCreateComplete(int32_t localId)
{
    ErrCode errCode = ERR_OK;
    int32_t retryTimes = 0;
    while (retryTimes < MAX_RETRY_TIMES) {
        errCode = InnerSendToStorageAccountCreateComplete(localId);
        if (errCode == ERR_OK) {
            break;
        }
        ACCOUNT_LOGE("Fail to complete account, localId=%{public}d, errCode=%{public}d.", localId, errCode);
        retryTimes++;
        std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_EXCEPTION));
    }
    return errCode;
}

ErrCode OsAccountInterface::InnerSendToStorageAccountCreateComplete(int32_t localId)
{
#ifdef HAS_STORAGE_PART
    sptr<StorageManager::IStorageManager> proxy = nullptr;
    if (GetStorageProxy(proxy) != ERR_OK) {
        ACCOUNT_LOGE("Failed to get STORAGE_MANAGER_MANAGER_ID proxy.");
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER;
    }
    StartTraceAdapter("StorageManager CompleteAddUser");
    int errCode = proxy->CompleteAddUser(localId);
    if (errCode != 0) {
        ACCOUNT_LOGE("Failed to CompleteAddUser, localId=%{public}d, errCode=%{public}d", localId, errCode);
        ReportOsAccountOperationFail(localId, Constants::OPERATION_CREATE, errCode,
            "StorageManager failed to complete add user");
        return errCode;
    }
    FinishTraceAdapter();
#endif
    return ERR_OK;
}

void OsAccountInterface::SendToStorageAccountUnlocked(const OsAccountInfo &osAccountInfo)
{
#ifdef HAS_STORAGE_PART
    auto localId = osAccountInfo.GetLocalId();
    ACCOUNT_LOGI("Begin, %{public}d", localId);
    sptr<StorageManager::IStorageManager> proxy = nullptr;
    if (GetStorageProxy(proxy) != ERR_OK) {
        ACCOUNT_LOGE("Failed to get STORAGE_MANAGER_MANAGER_ID proxy.");
        ReportOsAccountOperationFail(localId, Constants::OPERATION_SECOND_MOUNT,
            ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER,
            "GetSystemAbility for storage failed!");
        return;
    }
#ifdef HICOLLIE_ENABLE
    XCollieCallback callbackFunc = [localId](void *) {
        ACCOUNT_LOGE("Notify storage unlock timeout, localId=%{public}d", localId);
        ReportOsAccountOperationFail(localId, Constants::OPERATION_SECOND_MOUNT, -1, "Notify storage unlock timeout");
    };
    int32_t timerId = HiviewDFX::XCollie::GetInstance().SetTimer(
        TIMER_NAME, STORAGE_TIMEOUT, callbackFunc, nullptr, HiviewDFX::XCOLLIE_FLAG_LOG);
#endif // HICOLLIE_ENABLE
    StartTraceAdapter("StorageManager NotifyUserChangedEvent");
    proxy->NotifyUserChangedEvent(localId, StorageService::EVENT_USER_UNLOCKED);
    FinishTraceAdapter();
#ifdef HICOLLIE_ENABLE
    HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
#endif // HICOLLIE_ENABLE
    ReportOsAccountLifeCycle(localId, "notifyStorageUnlock");
    ACCOUNT_LOGI("End, %{public}d", localId);
#endif
}

void OsAccountInterface::SendToStorageAccountSwitched(const OsAccountInfo &osAccountInfo)
{
#ifdef HAS_STORAGE_PART
    auto localId = osAccountInfo.GetLocalId();
    ACCOUNT_LOGI("Begin, %{public}d", localId);
    sptr<StorageManager::IStorageManager> proxy = nullptr;
    if (GetStorageProxy(proxy) != ERR_OK) {
        ACCOUNT_LOGE("Failed to get STORAGE_MANAGER_MANAGER_ID proxy.");
        ReportOsAccountOperationFail(localId, Constants::OPERATION_SWITCH,
            ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER,
            "GetSystemAbility for storage failed!");
        return;
    }
#ifdef HICOLLIE_ENABLE
    XCollieCallback callbackFunc = [localId](void *) {
        ACCOUNT_LOGE("Notify storage switch timeout, localId=%{public}d", localId);
        ReportOsAccountOperationFail(localId, Constants::OPERATION_SECOND_MOUNT, -1, "Notify storage switch timeout");
    };
    int32_t timerId = HiviewDFX::XCollie::GetInstance().SetTimer(
        TIMER_NAME, STORAGE_TIMEOUT, callbackFunc, nullptr, HiviewDFX::XCOLLIE_FLAG_LOG);
#endif // HICOLLIE_ENABLE
    StartTraceAdapter("StorageManager NotifyUserChangedEvent");
    proxy->NotifyUserChangedEvent(localId, StorageService::EVENT_USER_SWITCHED);
    FinishTraceAdapter();
#ifdef HICOLLIE_ENABLE
    HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
#endif // HICOLLIE_ENABLE
    ReportOsAccountLifeCycle(localId, "notifyStorageSwitched");
    ACCOUNT_LOGI("End, %{public}d", localId);
#endif
}

ErrCode OsAccountInterface::CheckAllAppDied(int32_t accountId)
{
    int32_t dealTimes = DEAL_TIMES;
    while (dealTimes > 0) {
        bool isAllDied = AbilityManagerAdapter::GetInstance()->IsAllAppDied(accountId);
        if (isAllDied) {
            return ERR_OK;
        }
        ACCOUNT_LOGE("IsAllAppDied check failed");
        usleep(GET_MSG_FREQ);
        dealTimes--;
    }
    return ERR_ACCOUNT_COMMON_OPERATION_TIMEOUT;
}
}  // namespace AccountSA
}  // namespace OHOS
