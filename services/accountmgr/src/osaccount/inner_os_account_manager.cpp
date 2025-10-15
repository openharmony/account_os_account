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
#include "iinner_os_account_manager.h"
#include "account_event_provider.h"
#include <chrono>
#include <dlfcn.h>
#include <poll.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include "account_constants.h"
#include "account_info.h"
#include "account_info_report.h"
#include "account_log_wrapper.h"
#include "os_account_info.h"
#ifdef HAS_CES_PART
#include "common_event_support.h"
#endif // HAS_CES_PART
#include "domain_account_callback_service.h"
#include "hitrace_adapter.h"
#include "account_hisysevent_adapter.h"
#include "data_size_report_adapter.h"
#include "account_permission_manager.h"
#include "app_account_control_manager.h"
#include "ohos_account_kits.h"
#include "os_account_constants.h"
#ifdef SUPPORT_DOMAIN_ACCOUNTS
#include "os_account_domain_account_callback.h"
#endif // SUPPORT_DOMAIN_ACCOUNTS
#include "os_account_static_subscriber_manager.h"
#include "os_account_subscribe_manager.h"
#include "parameter.h"
#include "parcel.h"
#include "string_ex.h"
#include <pthread.h>
#include <mutex>
#include <thread>
#include <unordered_set>
#ifdef HICOLLIE_ENABLE
#include "account_timer.h"
#include "xcollie/xcollie.h"
#endif // HICOLLIE_ENABLE
#ifdef ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS
#include "display_manager_lite.h"
#include <cstdint>
#endif // ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS

namespace OHOS {
namespace AccountSA {
namespace {
const char OPERATION_UPDATE[] = "update";
const char OPERATION_SET_TO_BE_REMOVED[] = "setToBeRemoved";
const char ADMIN_LOCAL_NAME[] = "admin";
#ifdef SUPPORT_LOCK_OS_ACCOUNT
const char OPERATION_LOCK[] = "lock";
#endif
#ifdef ENABLE_DEFAULT_ADMIN_NAME
const char STANDARD_LOCAL_NAME[] = "user";
#endif
const std::string CONSTRAINT_CREATE_ACCOUNT_DIRECTLY = "constraint.os.account.create.directly";
const char ACCOUNT_READY_EVENT[] = "bootevent.account.ready";
const char PARAM_LOGIN_NAME_MAX[] = "persist.account.login_name_max";
constexpr const char DEACTIVATION_ANIMATION_PATH[] = "/system/bin/deactivation_animation";
constexpr int32_t TOKEN_NATIVE = 1;
constexpr int32_t DELAY_FOR_EXCEPTION = 50;
constexpr int32_t MAX_RETRY_TIMES = 50;
constexpr int32_t MAX_INSERT_RETRY_TIMES = 3;
constexpr int32_t MAX_PRIVATE_TYPE_NUMBER = 1;
constexpr int32_t MAX_MAINTENANCE_TYPE_NUMBER = 1;
#ifndef ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS
constexpr int32_t DELAY_FOR_REMOVING_FOREGROUND_OS_ACCOUNT = 1500;
#endif // ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS
#ifdef ENABLE_MULTIPLE_ACTIVE_ACCOUNTS
constexpr int32_t DELAY_FOR_DEACTIVATE_OS_ACCOUNT = 3000;
#endif
constexpr int32_t MAX_WAIT_ANIMATION_MSG_BUFFER = 256;
constexpr int32_t MAX_WAIT_ANIMATION_READY_TIMEOUT = 1000;
constexpr int32_t PIPE_FD_COUNT = 2;
constexpr int32_t PIPE_READ_END = 0;
constexpr int32_t PIPE_WRITE_END = 1;
#ifdef SUPPORT_STOP_MAIN_OS_ACCOUNT
const std::vector<int32_t> NO_DESKTOP_OS_ACCOUNTS = {
#ifdef ENABLE_U1_ACCOUNT
    OHOS::AccountSA::Constants::U1_ID
#endif // ENABLE_U1_ACCOUNT
};
#endif // SUPPORT_STOP_MAIN_OS_ACCOUNT
}


static ErrCode ResetForegroundBeforeRemove(OsAccountInfo &osAccountInfo, int32_t id)
{
    if (osAccountInfo.GetIsForeground()) {
#ifndef ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS
        ACCOUNT_LOGI("Remove foreground account id=%{public}d.", id);
        if (IInnerOsAccountManager::GetInstance().ActivateOsAccount(Constants::START_USER_ID) != ERR_OK) {
            ACCOUNT_LOGE("RemoveOsAccount active base account failed");
            return ERR_OSACCOUNT_SERVICE_INNER_REMOVE_ACCOUNT_ACTIVED_ERROR;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_REMOVING_FOREGROUND_OS_ACCOUNT));
#else
        ACCOUNT_LOGI("Remove foreground account id=%{public}d.", id);
        ErrCode errCode = OsAccountInterface::SendToAMSAccountDeactivate(osAccountInfo);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("SendToAMSAccountDeactivate failed, id %{public}d, errCode %{public}d", id, errCode);
            return errCode;
        }
#endif // ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS
    }
    return ERR_OK;
}

#ifdef SUPPORT_DOMAIN_ACCOUNTS
static ErrCode GetDomainAccountStatus(OsAccountInfo &osAccountInfo)
{
    DomainAccountInfo domainAccountInfo;
    osAccountInfo.GetDomainInfo(domainAccountInfo);
    DomainAccountInfo resultInfo;
    ErrCode errCode = InnerDomainAccountManager::GetInstance().GetDomainAccountInfo(domainAccountInfo, resultInfo);
    if (errCode != ERR_OK) {
        return errCode;
    }
    if (!resultInfo.isAuthenticated) {
        domainAccountInfo.status_ = DomainAccountStatus::LOGOUT;
    } else {
        bool isActivated = false;
        (void)IInnerOsAccountManager::GetInstance().IsOsAccountActived(osAccountInfo.GetLocalId(), isActivated);
        domainAccountInfo.status_ = isActivated ? DomainAccountStatus::LOGIN : DomainAccountStatus::LOGIN_BACKGROUND;
    }
    osAccountInfo.SetDomainInfo(domainAccountInfo);
    return ERR_OK;
}
#endif // SUPPORT_DOMAIN_ACCOUNTS

IInnerOsAccountManager::IInnerOsAccountManager() : subscribeManager_(OsAccountSubscribeManager::GetInstance()),
#ifdef SUPPORT_LOCK_OS_ACCOUNT
    lockOsAccountPluginManager_(OsAccountLockOsAccountPluginManager::GetInstance()),
#endif
    activateLockPluginManager_(OsAccountActivateLockPluginManager::GetInstance())
{
    activeAccountId_.clear();
    operatingId_.clear();
    osAccountControl_ = std::make_shared<OsAccountControlFileManager>();
    osAccountControl_->Init();
    osAccountControl_->GetDeviceOwnerId(deviceOwnerId_);
    std::map<uint64_t, int32_t> activatedAccountsMap;
    osAccountControl_->GetAllDefaultActivatedOsAccounts(activatedAccountsMap);
    for (const auto &[displayId, localId] : activatedAccountsMap) {
        defaultActivatedIds_.EnsureInsert(displayId, localId);
    }
    osAccountControl_->GetOsAccountConfig(config_);
    SetParameter(PARAM_LOGIN_NAME_MAX, std::to_string(Constants::LOCAL_NAME_MAX_SIZE).c_str());
    ACCOUNT_LOGI("Init end, maxOsAccountNum: %{public}d, maxLoggedInOsAccountNum: %{public}d",
        config_.maxOsAccountNum, config_.maxLoggedInOsAccountNum);
}

IInnerOsAccountManager &IInnerOsAccountManager::GetInstance()
{
    static IInnerOsAccountManager *instance = new (std::nothrow) IInnerOsAccountManager();
    return *instance;
}

#ifdef FUZZ_TEST
// LCOV_EXCL_START
#endif
ErrCode IInnerOsAccountManager::RetryToInsertOsAccount(OsAccountInfo &osAccountInfo)
{
    int32_t retryTimes = 0;
    ErrCode result;
    while (retryTimes < MAX_INSERT_RETRY_TIMES) {
        result = osAccountControl_->InsertOsAccount(osAccountInfo);
        if (result == ERR_OK || result == ERR_OSACCOUNT_SERVICE_CONTROL_INSERT_FILE_EXISTS_ERROR) {
            return ERR_OK;
        }
        ACCOUNT_LOGE("Fail to insert account");
        retryTimes++;
        std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_EXCEPTION));
    }
    return result;
}
#ifdef FUZZ_TEST
// LCOV_EXCL_STOP
#endif

#ifdef FUZZ_TEST
// LCOV_EXCL_START
#endif
void IInnerOsAccountManager::CreateBaseAdminAccount()
{
    ACCOUNT_LOGI("Start to create admin account");
    bool isExistsAccount = false;
    osAccountControl_->IsOsAccountExists(Constants::ADMIN_LOCAL_ID, isExistsAccount);
    if (!isExistsAccount) {
        ReportOsAccountLifeCycle(Constants::ADMIN_LOCAL_ID, Constants::OPERATION_BOOT_CREATE);
        int64_t serialNumber =
            Constants::CARRY_NUM * Constants::SERIAL_NUMBER_NUM_START_FOR_ADMIN + Constants::ADMIN_LOCAL_ID;
        OsAccountInfo osAccountInfo(
            Constants::ADMIN_LOCAL_ID, ADMIN_LOCAL_NAME, OsAccountType::ADMIN, serialNumber);
        int64_t time =
            std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
                .count();
        osAccountInfo.SetCreateTime(time);
        osAccountInfo.SetIsCreateCompleted(true);
        osAccountInfo.SetIsActived(true);  // admin local account is always active
        osAccountControl_->InsertOsAccount(osAccountInfo);
        ReportOsAccountLifeCycle(osAccountInfo.GetLocalId(), Constants::OPERATION_CREATE);
        ACCOUNT_LOGI("OsAccountAccountMgr created admin account end");
    } else {
        ACCOUNT_LOGI("OsAccountAccountMgr admin account already exists");
    }
}
#ifdef FUZZ_TEST
// LCOV_EXCL_STOP
#endif

#ifdef FUZZ_TEST
// LCOV_EXCL_START
#endif
ErrCode IInnerOsAccountManager::SendMsgForAccountActivateInBackground(OsAccountInfo &osAccountInfo)
{
    // activate
    subscribeManager_.Publish(osAccountInfo.GetLocalId(), OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATING);
    (void)SendToStorageAccountStart(osAccountInfo);
    // StorageManager failture does not block boot, continue!
    ErrCode errCode = SendToAMSAccountStart(osAccountInfo, Constants::INVALID_DISPLAY_ID, true);
    if (errCode != ERR_OK) {
        return errCode;
    }
    subscribeManager_.Publish(osAccountInfo.GetLocalId(), OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATED);
    ReportOsAccountLifeCycle(osAccountInfo.GetLocalId(), Constants::OPERATION_ACTIVATE);
    OsAccountInterface::PublishCommonEvent(osAccountInfo,
        OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_BACKGROUND, Constants::OPERATION_ACTIVATE);
    ACCOUNT_LOGI("SendMsgForAccountActivateInBackground %{public}d ok", osAccountInfo.GetLocalId());
    return ERR_OK;
}
#ifdef FUZZ_TEST
// LCOV_EXCL_STOP
#endif

#ifdef FUZZ_TEST
// LCOV_EXCL_START
#endif
ErrCode IInnerOsAccountManager::ActivateOsAccountInBackground(const int32_t id)
{
    ACCOUNT_LOGI("Start to activate %{public}d account", id);

    OsAccountInfo osAccountInfo;
    // check account is exist or not
    ErrCode errCode = GetRealOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        REPORT_OS_ACCOUNT_FAIL(id, Constants::OPERATION_ACTIVATE, errCode, "Account not found.");
        ACCOUNT_LOGE("Account not found, localId: %{public}d, error: %{public}d", id, errCode);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    errCode = IsValidOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        REPORT_OS_ACCOUNT_FAIL(id, Constants::OPERATION_ACTIVATE, errCode, "Account is invalid.");
        ACCOUNT_LOGE("Account is invalid, localId: %{public}d, error: %{public}d", id, errCode);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    // activate
    errCode = SendMsgForAccountActivateInBackground(osAccountInfo);
    return errCode;
}
#ifdef FUZZ_TEST
// LCOV_EXCL_STOP
#endif

#ifdef FUZZ_TEST
// LCOV_EXCL_START
#endif
bool IInnerOsAccountManager::CreateBaseStandardAccount(OsAccountInfo &osAccountInfo)
{
    int32_t id = osAccountInfo.GetLocalId();
    ACCOUNT_LOGI("Start to create base account %{public}d", id);
    int64_t serialNumber = 0;
    ErrCode errCode = osAccountControl_->GetSerialNumber(serialNumber);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Get serialNumber failed, account:%{public}d, errCode:%{public}d.", id, errCode);
        ReportOsAccountOperationFail(id, Constants::OPERATION_BOOT_CREATE, errCode, "Get serialNumber failed");
    }
    osAccountInfo.SetSerialNumber(serialNumber);
    std::vector<std::string> constraints;
    errCode = osAccountControl_->GetConstraintsByType(osAccountInfo.GetType(), constraints);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Fail to get constraints by type for account %{public}d, errCode %{public}d.",
            osAccountInfo.GetLocalId(), errCode);
        ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_BOOT_CREATE, errCode,
            "Fail to get constraints by type for account");
        return false;
    }
    osAccountInfo.SetConstraints(constraints);
    int64_t time =
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();
    osAccountInfo.SetCreateTime(time);
    osAccountInfo.SetIsCreateCompleted(false);
    osAccountInfo.SetIsDataRemovable(false);
    errCode = RetryToInsertOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Fail to insert account %{public}d, errCode %{public}d.", osAccountInfo.GetLocalId(), errCode);
        ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_BOOT_CREATE, errCode,
            "Failed to insert start user OS account");
    }
    errCode = SendMsgForAccountCreate(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("OS account %{public}d not created completely, errCode %{public}d.",
            osAccountInfo.GetLocalId(), errCode);
        ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_BOOT_CREATE, errCode,
            "SendMsgForAccountCreate failed");
        return false;
    }
    ReportOsAccountLifeCycle(osAccountInfo.GetLocalId(), Constants::OPERATION_CREATE);
    ReportOsAccountLifeCycle(osAccountInfo.GetLocalId(), Constants::OPERATION_BOOT_CREATE);
    ACCOUNT_LOGI("OsAccountAccountMgr created base account end");
    return true;
}
#ifdef FUZZ_TEST
// LCOV_EXCL_STOP
#endif

void IInnerOsAccountManager::RetryToGetAccount(OsAccountInfo &osAccountInfo)
{
    int32_t retryTimes = 0;
    ErrCode errCode = ERR_OK;
    while (retryTimes < MAX_RETRY_TIMES) {
        std::vector<OsAccountInfo> osAccountInfos;
        errCode = QueryAllCreatedOsAccounts(osAccountInfos);
        if (!osAccountInfos.empty() && (IsValidOsAccount(osAccountInfos[0]) == ERR_OK)) {
            osAccountInfo = osAccountInfos[0];
            return;
        }
        ACCOUNT_LOGE("Fail to query accounts");
        retryTimes++;
        std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_EXCEPTION));
    }
    ACCOUNT_LOGE("Query all created osAccounts failed, error: %{public}d", errCode);
    REPORT_OS_ACCOUNT_FAIL(osAccountInfo.GetLocalId(), Constants::OPERATION_BOOT_ACTIVATING, errCode,
        "Query all created osAccounts failed");
    retryTimes = 0;
    while (retryTimes < MAX_RETRY_TIMES) {
#ifdef ENABLE_DEFAULT_ADMIN_NAME
        errCode = CreateOsAccount(STANDARD_LOCAL_NAME, ADMIN, osAccountInfo);
#else
        errCode = CreateOsAccount("", ADMIN, osAccountInfo);
#endif
        if (errCode == ERR_OK) {
            return;
        }
        ACCOUNT_LOGE("Fail to create account");
        retryTimes++;
        std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_EXCEPTION));
    }
    ACCOUNT_LOGE("Create osAccount failed, localId: %{public}d, error: %{public}d",
        osAccountInfo.GetLocalId(), errCode);
    REPORT_OS_ACCOUNT_FAIL(osAccountInfo.GetLocalId(), Constants::OPERATION_BOOT_ACTIVATING, errCode,
        "Create osAccount failed");
}

ErrCode IInnerOsAccountManager::GetRealOsAccountInfoById(const int id, OsAccountInfo &osAccountInfo)
{
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        return errCode;
    }

    bool isVerified = false;
    verifiedAccounts_.Find(id, isVerified);
    osAccountInfo.SetIsVerified(isVerified);

    bool isLoggedIn = false;
    loggedInAccounts_.Find(id, isLoggedIn);
    osAccountInfo.SetIsLoggedIn(isLoggedIn);

    bool isActivated = IsOsAccountIDInActiveList(id);
    osAccountInfo.SetIsActived(isActivated);
    if (!isActivated) {
        osAccountInfo.SetDisplayId(Constants::INVALID_DISPLAY_ID);
        osAccountInfo.SetIsForeground(false);
        return ERR_OK;
    }

    uint64_t displayId = Constants::INVALID_DISPLAY_ID;
    auto it = [&displayId, id](uint64_t dispId, int32_t localId) {
        if (localId == id) {
            displayId = dispId;
        }
    };
    foregroundAccountMap_.Iterate(it);
    osAccountInfo.SetDisplayId(displayId);
    osAccountInfo.SetIsForeground(displayId != Constants::INVALID_DISPLAY_ID);
    return ERR_OK;
}

#ifdef FUZZ_TEST
// LCOV_EXCL_START
#endif
ErrCode IInnerOsAccountManager::ActivateU1Account()
{
#ifdef ENABLE_U1_ACCOUNT
    if (!config_.isU1Enable) {
        return ERR_OK;
    }
    
    ErrCode errCode = ActivateOsAccountInBackground(Constants::U1_ID);
    if (errCode == ERR_OK) {
        ReportOsAccountLifeCycle(Constants::U1_ID, Constants::OPERATION_BOOT_ACTIVATED);
        return ERR_OK;
    }
    
    REPORT_OS_ACCOUNT_FAIL(Constants::U1_ID, Constants::OPERATION_BOOT_ACTIVATING, errCode,
        "ActivateOsAccountInBackground fail isBlockBoot:" + std::to_string(config_.isBlockBoot));
    if (config_.isBlockBoot && (errCode != ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR)) {
        return errCode;
    }
#endif // ENABLE_U1_ACCOUNT
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::PrepareForDefaultAccount(int32_t activatedId, OsAccountInfo &osAccountInfo)
{
    ErrCode errCode = GetRealOsAccountInfoById(activatedId, osAccountInfo);
    if ((errCode != ERR_OK) || (IsValidOsAccount(osAccountInfo) != ERR_OK)) {
        ACCOUNT_LOGE("Account not found, localId: %{public}d, error: %{public}d", activatedId, errCode);
        RetryToGetAccount(osAccountInfo);
        errCode = SetDefaultActivatedOsAccount(osAccountInfo.GetLocalId());
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("Set default activated osAccount failed, localId: %{public}d, error: %{public}d",
                osAccountInfo.GetLocalId(), errCode);
            REPORT_OS_ACCOUNT_FAIL(osAccountInfo.GetLocalId(), Constants::OPERATION_BOOT_ACTIVATING, errCode,
                "Set default activated osAccount failed");
        }
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::ActivateDefaultOsAccount()
{
    int32_t activatedId;
    if (!defaultActivatedIds_.Find(Constants::DEFAULT_DISPLAY_ID, activatedId)) {
        ACCOUNT_LOGE("Default activated account not found in default display.");
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
#ifdef HICOLLIE_ENABLE
    XCollieCallback callbackFunc = [&](void *) {
        ACCOUNT_LOGE("ActivateDefaultOsAccount failed due to timeout.");
        REPORT_OS_ACCOUNT_FAIL(activatedId, Constants::OPERATION_BOOT_ACTIVATING,
            ERR_ACCOUNT_COMMON_OPERATION_TIMEOUT, "Activate default os account over time.");
    };
    int timerId = HiviewDFX::XCollie::GetInstance().SetTimer(TIMER_NAME, TIMEOUT, callbackFunc, nullptr,
        HiviewDFX::XCOLLIE_FLAG_LOG);
#endif // HICOLLIE_ENABLE
    ACCOUNT_LOGI("Start to activate default account");
    // Activate U1 account if enabled
    ErrCode errCode = ActivateU1Account();
    if (errCode != ERR_OK) {
#ifdef HICOLLIE_ENABLE
        HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
#endif // HICOLLIE_ENABLE
        return errCode;
    }
    // Validate and prepare default account
    OsAccountInfo osAccountInfo;
    PrepareForDefaultAccount(activatedId, osAccountInfo);
    
    // Activate account and set parameters
    errCode = SendMsgForAccountActivate(osAccountInfo, true, Constants::DEFAULT_DISPLAY_ID, true);
    if (errCode == ERR_OK) {
        errCode = SetParameter(ACCOUNT_READY_EVENT, "true");
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("Set parameter failed, localId: %{public}d, error: %{public}d",
                osAccountInfo.GetLocalId(), errCode);
            REPORT_OS_ACCOUNT_FAIL(osAccountInfo.GetLocalId(), Constants::OPERATION_BOOT_ACTIVATING, errCode,
                "Set parameter bootevent.account.ready failed");
        } else {
            ReportOsAccountLifeCycle(osAccountInfo.GetLocalId(), Constants::OPERATION_BOOT_ACTIVATED);
        }
    }
#ifdef HICOLLIE_ENABLE
    HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
#endif // HICOLLIE_ENABLE
    return errCode;
}
#ifdef FUZZ_TEST
// LCOV_EXCL_STOP
#endif

void IInnerOsAccountManager::RestartActiveAccount()
{
    // query active account to restart and refresh into list
    std::vector<OsAccountInfo> osAccountInfos;
    if (QueryAllCreatedOsAccounts(osAccountInfos) != ERR_OK) {
        return;
    }
    for (const auto& osAccountInfo : osAccountInfos) {
        std::int32_t id = osAccountInfo.GetLocalId();
        std::uint64_t displayId = osAccountInfo.GetDisplayId();
        if (osAccountInfo.GetIsActived() && id != Constants::START_USER_ID &&
            displayId != Constants::INVALID_DISPLAY_ID) {
            // reactivate account state
            if (ActivateOsAccount(id, true, displayId) != ERR_OK) {
                ACCOUNT_LOGE("Active base account failed");
                return;
            }
        }
    }
}

void IInnerOsAccountManager::ResetAccountStatus(void)
{
    std::vector<int32_t> idList;
    (void) osAccountControl_->GetOsAccountIdList(idList);
    for (const auto id : idList) {
        DeactivateOsAccountById(id);
    }
}

ErrCode IInnerOsAccountManager::PrepareOsAccountInfo(const std::string &name, const OsAccountType &type,
    const DomainAccountInfo &domainInfo, OsAccountInfo &osAccountInfo)
{
    return PrepareOsAccountInfo(name, "", type, domainInfo, osAccountInfo);
}

ErrCode IInnerOsAccountManager::PrepareOsAccountInfo(const std::string &localName, const std::string &shortName,
    const OsAccountType &type, const DomainAccountInfo &domainInfo, OsAccountInfo &osAccountInfo)
{
    ErrCode errCode = FillOsAccountInfo(localName, shortName, type, domainInfo, osAccountInfo);
    if (errCode != ERR_OK) {
        return errCode;
    }
    errCode = ValidateOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Account name already exist, errCode %{public}d.", errCode);
        return errCode;
    }
    errCode = CheckTypeNumber(type);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Check type number failed.");
        return errCode;
    }
    if (!CheckAndAddLocalIdOperating(osAccountInfo.GetLocalId())) {
        ACCOUNT_LOGW("Account id = %{public}d already in operating", osAccountInfo.GetLocalId());
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_OPERATING_ERROR;
    }
    errCode = osAccountControl_->InsertOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Insert os account info err, errCode %{public}d.", errCode);
        return errCode;
    }
    errCode = osAccountControl_->UpdateAccountIndex(osAccountInfo, false);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Update account index failed, errCode = %{public}d", errCode);
    }

    errCode = osAccountControl_->UpdateBaseOAConstraints(std::to_string(osAccountInfo.GetLocalId()),
        osAccountInfo.GetConstraints(), true);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("UpdateBaseOAConstraints err");
        return errCode;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::FillOsAccountInfo(const std::string &localName, const std::string &shortName,
    const OsAccountType &type, const DomainAccountInfo &domainInfo, OsAccountInfo &osAccountInfo)
{
    int64_t serialNumber;
    ErrCode errCode = osAccountControl_->GetSerialNumber(serialNumber);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to GetSerialNumber, errCode %{public}d.", errCode);
        return errCode;
    }
    int id = 0;
    if (type == OsAccountType::MAINTENANCE) {
        id = Constants::MAINTENANCE_USER_ID;
    } else {
        errCode = osAccountControl_->GetAllowCreateId(id);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("Failed to GetAllowCreateId, errCode %{public}d.", errCode);
            return errCode;
        }
    }
    std::vector<std::string> constraints;
    constraints.clear();
    errCode = osAccountControl_->GetConstraintsByType(type, constraints);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to GetConstraintsByType, errCode %{public}d.", errCode);
        return errCode;
    }

    osAccountInfo = OsAccountInfo(id, localName, shortName, type, serialNumber);
    if (AccountPermissionManager::CheckSaCall()) {
        osAccountInfo.SetCreatorType(TOKEN_NATIVE);
    }
    osAccountInfo.SetConstraints(constraints);
    int64_t time =
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    osAccountInfo.SetCreateTime(time);
    if (!osAccountInfo.SetDomainInfo(domainInfo)) {
        ACCOUNT_LOGE("Failed to SetDomainInfo");
        return ERR_OSACCOUNT_KIT_CREATE_OS_ACCOUNT_FOR_DOMAIN_ERROR;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::PrepareOsAccountInfoWithFullInfo(OsAccountInfo &osAccountInfo)
{
    int64_t serialNumber;
    ErrCode errCode = osAccountControl_->GetSerialNumber(serialNumber);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to GetSerialNumber, errCode %{public}d.", errCode);
        return errCode;
    }
    osAccountInfo.SetSerialNumber(serialNumber);
    osAccountInfo.SetIsCreateCompleted(false);
    osAccountInfo.SetIsDataRemovable(false);
    errCode = osAccountControl_->SetNextLocalId(osAccountInfo.GetLocalId() + 1);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to SetNextLocalId, errCode %{public}d.", errCode);
        return errCode;
    }
    errCode = osAccountControl_->InsertOsAccount(osAccountInfo);
    if ((errCode != ERR_OK) && (errCode != ERR_OSACCOUNT_SERVICE_CONTROL_INSERT_FILE_EXISTS_ERROR)) {
        ACCOUNT_LOGE("Insert os account info err, errCode %{public}d.", errCode);
        return errCode;
    }

    errCode = osAccountControl_->UpdateAccountIndex(osAccountInfo, false);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Update account index failed, errCode = %{public}d", errCode);
    }

    std::vector<std::string> constraints;
    constraints.clear();
    OsAccountType type = static_cast<OsAccountType>(osAccountInfo.GetType());
    errCode = osAccountControl_->GetConstraintsByType(type, constraints);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to GetConstraintsByType, errCode %{public}d.", errCode);
        return errCode;
    }
    std::vector<std::string> constraintsExists = osAccountInfo.GetConstraints();
    std::vector<std::string> constraintsResult;
    std::merge(constraints.begin(), constraints.end(), constraintsExists.begin(), constraintsExists.end(),
        std::back_inserter(constraintsResult));
    osAccountInfo.SetConstraints(constraintsResult);
    errCode = osAccountControl_->UpdateBaseOAConstraints(
        std::to_string(osAccountInfo.GetLocalId()), constraintsResult, true);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("UpdateBaseOAConstraints err");
        return errCode;
    }
    return ERR_OK;
}

bool IInnerOsAccountManager::CheckAndCleanOsAccounts()
{
    unsigned int osAccountNum = 0;
    GetNonSACreatedOACount(osAccountNum);

    if (osAccountNum < config_.maxOsAccountNum) {
        return true;
    }

    ACCOUNT_LOGI("The number of OS accounts has oversize, attempting to clean garbage accounts.");
    if (CleanGarbageOsAccounts() <= 0) {
        ACCOUNT_LOGE("The number of OS accounts still oversize after cleaning, max num: %{public}d",
            config_.maxOsAccountNum);
        return false;
    }
    return true;
}

void IInnerOsAccountManager::RollbackOsAccount(OsAccountInfo &osAccountInfo, bool needDelStorage, bool needDelBms)
{
    if (!osAccountInfo.GetIsDataRemovable()) {
        (void)osAccountControl_->DelOsAccount(osAccountInfo.GetLocalId());
        return;
    }

    if (needDelBms) {
        ErrCode errCode = OsAccountInterface::SendToBMSAccountDelete(osAccountInfo);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("Send to bms account delete failed, errCode:%{public}d", errCode);
            return;
        }
    }
    if (needDelStorage) {
        ErrCode errCode = OsAccountInterface::SendToStorageAccountRemove(osAccountInfo);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("Send to storage account remove failed, errCode:%{public}d", errCode);
            return;
        }
    }

    DomainAccountInfo curDomainInfo;
    osAccountInfo.GetDomainInfo(curDomainInfo);
    if (curDomainInfo.accountName_.empty()) {
        (void)osAccountControl_->DelOsAccount(osAccountInfo.GetLocalId());
    }
}

ErrCode IInnerOsAccountManager::SendMsgForAccountCreate(
    OsAccountInfo &osAccountInfo, const CreateOsAccountOptions &options)
{
    ErrCode errCode = OsAccountInterface::SendToStorageAccountCreate(osAccountInfo);
    int32_t localId = osAccountInfo.GetLocalId();
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Create os account SendToStorageAccountCreate failed, errCode %{public}d.", errCode);
        RollbackOsAccount(osAccountInfo, false, false);
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER;
    }
    OsAccountStaticSubscriberManager::GetInstance().Publish(localId, OsAccountState::CREATING, localId);
    errCode = OsAccountInterface::SendToBMSAccountCreate(
        osAccountInfo, options.disallowedHapList, options.allowedHapList);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Create os account SendToBMSAccountCreate failed, errCode %{public}d.", errCode);
        RollbackOsAccount(osAccountInfo, true, false);
        return errCode;
    }
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
    AppAccountControlManager::GetInstance().SetOsAccountRemoved(osAccountInfo.GetLocalId(), false);
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS
    osAccountInfo.SetIsCreateCompleted(true);
    errCode = osAccountControl_->UpdateOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Create os account when update isCreateCompleted");
        ReportOsAccountOperationFail(localId, Constants::OPERATION_CREATE, errCode, "Failed to update OS account");
        RollbackOsAccount(osAccountInfo, true, true);
        return ERR_OSACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR;
    }
    errCode = OsAccountInterface::SendToStorageAccountCreateComplete(localId);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to send storage account create complete.");
        ReportOsAccountOperationFail(localId, Constants::OPERATION_CREATE, errCode,
            "Failed to send storage account create complete");
    }
    ReportOsAccountLifeCycle(localId, Constants::OPERATION_CREATE);
    OsAccountInterface::SendToCESAccountCreate(osAccountInfo);
    subscribeManager_.Publish(localId, OS_ACCOUNT_SUBSCRIBE_TYPE::CREATED);
    ACCOUNT_LOGI("OsAccountAccountMgr send to storage and bm for start success");
    // report data size when account created
    ReportUserDataSize(GetVerifiedAccountIds(verifiedAccounts_));
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::CreateOsAccount(
    const std::string &name, const OsAccountType &type, OsAccountInfo &osAccountInfo)
{
    if (!activateLockPluginManager_.IsCreationAllowed()) {
        ACCOUNT_LOGI("Not allow creation account.");
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_PLUGIN_NOT_ALLOWED_CREATION_ERROR;
    }
    std::lock_guard<std::mutex> createLock(createOsAccountMutex_);
#ifdef HICOLLIE_ENABLE
    AccountTimer timer;
#endif // HICOLLIE_ENABLE
    if (!AccountPermissionManager::CheckSaCall() && !CheckAndCleanOsAccounts()) {
        return ERR_OSACCOUNT_SERVICE_CONTROL_MAX_CAN_CREATE_ERROR;
    }
    DomainAccountInfo domainInfo;  // default empty domain info
    ErrCode errCode = PrepareOsAccountInfo(name, type, domainInfo, osAccountInfo);
    if (errCode != ERR_OK) {
        RemoveLocalIdToOperating(osAccountInfo.GetLocalId());
        return errCode;
    }
    errCode = SendMsgForAccountCreate(osAccountInfo);
    RemoveLocalIdToOperating(osAccountInfo.GetLocalId());
    return errCode;
}

ErrCode IInnerOsAccountManager::UpdateFirstOsAccountInfo(OsAccountInfo& accountInfoOld, OsAccountInfo& osAccountInfo)
{
    ErrCode code = osAccountControl_->UpdateOsAccount(accountInfoOld);
    if (code != ERR_OK) {
        ReportOsAccountOperationFail(Constants::START_USER_ID, Constants::OPERATION_CREATE, code,
            "Failed to update OS account");
        return code;
    }
    code = osAccountControl_->UpdateAccountIndex(accountInfoOld, false);
    if (code != ERR_OK) {
        ACCOUNT_LOGE("Update account index failed, errCode = %{public}d", code);
    }
    osAccountInfo = accountInfoOld;
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::CreateOsAccount(const std::string &localName, const std::string &shortName,
    const OsAccountType &type, OsAccountInfo &osAccountInfo, const CreateOsAccountOptions &options)
{
    if (!activateLockPluginManager_.IsCreationAllowed()) {
        ACCOUNT_LOGI("Not allow creation account.");
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_PLUGIN_NOT_ALLOWED_CREATION_ERROR;
    }
    std::lock_guard<std::mutex> createLock(createOsAccountMutex_);
#ifdef HICOLLIE_ENABLE
    AccountTimer timer;
#endif // HICOLLIE_ENABLE
    osAccountInfo.SetLocalName(localName);
    if (!AccountPermissionManager::CheckSaCall() && !CheckAndCleanOsAccounts()) {
        return ERR_OSACCOUNT_SERVICE_CONTROL_MAX_CAN_CREATE_ERROR;
    }
    DomainAccountInfo domainInfo;  // default empty domain info
    ErrCode errCode = PrepareOsAccountInfo(localName, shortName, type, domainInfo, osAccountInfo);
    if (errCode != ERR_OK) {
        RemoveLocalIdToOperating(osAccountInfo.GetLocalId());
        return errCode;
    }
    errCode = SendMsgForAccountCreate(osAccountInfo, options);
    RemoveLocalIdToOperating(osAccountInfo.GetLocalId());
    return errCode;
}

ErrCode IInnerOsAccountManager::CreateOsAccountWithFullInfo(OsAccountInfo &osAccountInfo,
    const CreateOsAccountOptions &options)
{
    if (!activateLockPluginManager_.IsCreationAllowed()) {
        ACCOUNT_LOGI("Not allow creation account.");
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_PLUGIN_NOT_ALLOWED_CREATION_ERROR;
    }
    std::lock_guard<std::mutex> createLock(createOsAccountMutex_);
#ifdef HICOLLIE_ENABLE
    AccountTimer timer;
#endif // HICOLLIE_ENABLE
    if (!CheckAndAddLocalIdOperating(osAccountInfo.GetLocalId())) {
        ACCOUNT_LOGW("Account id = %{public}d already in operating", osAccountInfo.GetLocalId());
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_OPERATING_ERROR;
    }

    OsAccountInfo oldInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(osAccountInfo.GetLocalId(), oldInfo);
    if (errCode != ERR_OK && errCode != ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR) {
        ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_CREATE, errCode,
            "Get account info failed when create osaccount with full info");
        RemoveLocalIdToOperating(osAccountInfo.GetLocalId());
        return errCode;
    }
    if (errCode == ERR_OK && oldInfo.GetIsCreateCompleted()) {
        if (oldInfo.GetToBeRemoved()) {
            ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_CREATE, errCode,
                "Remove garbage account before create osaccount with full info");
            ACCOUNT_LOGW("Account %{public}d is to be removed, remove it first.", osAccountInfo.GetLocalId());
            errCode = RemoveOsAccountOperate(osAccountInfo.GetLocalId(), osAccountInfo);
            if (errCode != ERR_OK) {
                RemoveLocalIdToOperating(osAccountInfo.GetLocalId());
                return errCode;
            }
        } else {
            ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), Constants::OPERATION_CREATE, errCode,
                "Account already exists when create osaccount with full info");
            ACCOUNT_LOGW("Account %{public}d already exists.", osAccountInfo.GetLocalId());
            RemoveLocalIdToOperating(osAccountInfo.GetLocalId());
            return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_ALREADY_EXIST_ERROR;
        }
    }

    errCode = PrepareOsAccountInfoWithFullInfo(osAccountInfo);
    if (errCode != ERR_OK) {
        RemoveLocalIdToOperating(osAccountInfo.GetLocalId());
        return errCode;
    }
    errCode = SendMsgForAccountCreate(osAccountInfo, options);
    RemoveLocalIdToOperating(osAccountInfo.GetLocalId());
    return errCode;
}

#ifdef SUPPORT_DOMAIN_ACCOUNTS
ErrCode IInnerOsAccountManager::UpdateAccountStatusForDomain(const int id, DomainAccountStatus status)
{
    OsAccountInfo accountInfo;
    DomainAccountInfo domainInfo;
    ErrCode errCode = GetOsAccountInfoById(id, accountInfo);
    if (errCode != ERR_OK) {
        return errCode;
    }
    accountInfo.GetDomainInfo(domainInfo);
    domainInfo.status_ = status;
    accountInfo.SetDomainInfo(domainInfo);

    errCode = osAccountControl_->UpdateOsAccount(accountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("update osaccount info error %{public}d, id: %{public}d", errCode, accountInfo.GetLocalId());
        return errCode;
    }
    return ERR_OK;
}
#endif // SUPPORT_DOMAIN_ACCOUNTS

ErrCode IInnerOsAccountManager::UpdateOsAccountWithFullInfo(OsAccountInfo &newInfo)
{
    int32_t localId = newInfo.GetLocalId();
    if (!CheckAndAddLocalIdOperating(localId)) {
        ACCOUNT_LOGE("The %{public}d already in operating", localId);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_OPERATING_ERROR;
    }
    OsAccountInfo oldInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(localId, oldInfo);
    if (errCode != ERR_OK) {
        RemoveLocalIdToOperating(localId);
        return errCode;
    }
    oldInfo.SetLocalName(newInfo.GetLocalName());
    oldInfo.SetType(newInfo.GetType());
    oldInfo.SetPhoto(newInfo.GetPhoto());
    oldInfo.SetConstraints(newInfo.GetConstraints());
    errCode = osAccountControl_->UpdateOsAccount(oldInfo);
    osAccountControl_->UpdateAccountIndex(oldInfo, false);
    newInfo = oldInfo;
    if (errCode != ERR_OK) {
        ReportOsAccountOperationFail(localId, OPERATION_UPDATE, errCode, "UpdateOsAccount failed!");
    } else {
        OsAccountInterface::PublishCommonEvent(oldInfo,
            OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_INFO_UPDATED, OPERATION_UPDATE);
    }
    RemoveLocalIdToOperating(localId);
    return errCode;
}

#ifdef SUPPORT_DOMAIN_ACCOUNTS
ErrCode IInnerOsAccountManager::GetOsAccountsByDomainInfo(const DomainAccountInfo &info,
    std::vector<OsAccountInfo> &osAccountInfos)
{
    std::vector<int32_t> allOsAccountIds;
    ErrCode errCode = osAccountControl_->GetOsAccountIdList(allOsAccountIds);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Get osaccount info list error, errCode %{public}d.", errCode);
        return errCode;
    }
    for (auto id : allOsAccountIds) {
        OsAccountInfo osAccountInfo;
        GetRealOsAccountInfoById(id, osAccountInfo);
        DomainAccountInfo curInfo;
        osAccountInfo.GetDomainInfo(curInfo);
        errCode = InnerDomainAccountManager::GetInstance().CheckAndRecoverBindDomainForUncomplete(osAccountInfo);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("Recover bind domain error, errCode = %{public}d.", errCode);
            REPORT_OS_ACCOUNT_FAIL(osAccountInfo.GetLocalId(), Constants::OPERATION_RECOVER_BIND_DOMAIN_ACCOUNT,
                errCode, "Recover bind domain error.");
            return errCode;
        }
        if ((!info.accountId_.empty() && curInfo.accountId_ == info.accountId_) ||
            ((curInfo.accountName_ == info.accountName_) && (curInfo.domain_ == info.domain_))) {
            osAccountInfos.emplace_back(osAccountInfo);
        }
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::CheckDomainAccountBound(const DomainAccountInfo &info, bool &isBound)
{
    std::vector<OsAccountInfo> osAccountInfos;
    ErrCode result = GetOsAccountsByDomainInfo(info, osAccountInfos);
    if (result != ERR_OK) {
        return result;
    }
    osAccountInfos.erase(std::remove_if(osAccountInfos.begin(), osAccountInfos.end(),
        [this](OsAccountInfo osAccountInfo) {
            if (osAccountInfo.GetIsCreateCompleted() && !osAccountInfo.GetToBeRemoved()) {
                ACCOUNT_LOGI("The domain account is already bound.");
                return false;
            }
            int32_t id = osAccountInfo.GetLocalId();
            if (!this->CheckAndAddLocalIdOperating(id)) {
                ACCOUNT_LOGE("Account id = %{public}d already in operating", id);
                return false;
            }
            ErrCode errCode = this->RemoveOsAccountOperate(id, osAccountInfo, true);
            this->RemoveLocalIdToOperating(id);
            if (errCode != ERR_OK) {
                REPORT_OS_ACCOUNT_FAIL(id, Constants::OPERATION_CLEAN,
                    errCode, "Clean garbage os accounts failed");
                ACCOUNT_LOGE("Remove account %{public}d failed! errCode %{public}d.", id, errCode);
                return false;
            }
            ACCOUNT_LOGI("Remove account %{public}d succeed!", id);
            return true;
        }), osAccountInfos.end());
    isBound = osAccountInfos.size() != 0;
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::BindDomainAccount(const OsAccountType &type,
    const DomainAccountInfo &domainAccountInfo, OsAccountInfo &osAccountInfo,
    const CreateOsAccountForDomainOptions &options)
{
    bool isBound = false;
    ErrCode errCode = CheckDomainAccountBound(domainAccountInfo, isBound);
    if (errCode != ERR_OK) {
        return errCode;
    }
    if (isBound) {
        ACCOUNT_LOGE("The domain account is already bound");
        return ERR_OSACCOUNT_SERVICE_INNER_DOMAIN_ALREADY_BIND_ERROR;
    }
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
    bool isEnabled = false;
    if (IsOsAccountConstraintEnable(Constants::START_USER_ID,
        CONSTRAINT_CREATE_ACCOUNT_DIRECTLY, isEnabled) != ERR_OK) {
        return ERR_OSACCOUNT_KIT_IS_OS_ACCOUNT_CONSTRAINT_ENABLE_ERROR;
    }
#else
    bool isEnabled = true;
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS
    std::vector<OsAccountInfo> osAccountInfos;
    errCode = QueryAllCreatedOsAccounts(osAccountInfos);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Query all created osAccount failed, errCode:%{public}d", errCode);
        return errCode;
    }
    if (isEnabled && (osAccountInfos.size() == 1) && (osAccountInfos[0].GetLocalId() == Constants::START_USER_ID)) {
        DomainAccountInfo curDomainInfo;
        osAccountInfos[0].GetDomainInfo(curDomainInfo);
        if (curDomainInfo.domain_.empty()) {
            osAccountInfos[0].SetLocalName(domainAccountInfo.accountName_);
            osAccountInfos[0].SetShortName(options.shortName);
            osAccountInfos[0].SetDomainInfo(domainAccountInfo);
            osAccountInfo = osAccountInfos[0];
        }
    }
    if (osAccountInfo.GetLocalId() != Constants::START_USER_ID) {
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
        errCode = PrepareOsAccountInfo(domainAccountInfo.accountName_, options.shortName,
            type, domainAccountInfo, osAccountInfo);
        RemoveLocalIdToOperating(osAccountInfo.GetLocalId());
        if (errCode != ERR_OK) {
            return errCode;
        }
#else
        ACCOUNT_LOGW("Multiple os accounts feature not enabled");
        return ERR_OSACCOUNT_SERVICE_MANAGER_NOT_ENABLE_MULTI_ERROR;
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS
    }
    errCode = osAccountControl_->UpdateAccountIndex(osAccountInfo, false);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Update account index failed, errCode = %{public}d", errCode);
        return errCode;
    }
    errCode = osAccountControl_->UpdateOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to update osaccount.");
    }
    return errCode;
}
#endif // SUPPORT_DOMAIN_ACCOUNTS

ErrCode IInnerOsAccountManager::CreateOsAccountForDomain(const OsAccountType &type, const DomainAccountInfo &domainInfo,
    const sptr<IDomainAccountCallback> &callback, const CreateOsAccountForDomainOptions &options)
{
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    std::lock_guard<std::mutex> lock(createOrBindDomainAccountMutex_);
    if (!activateLockPluginManager_.IsCreationAllowed()) {
        ACCOUNT_LOGI("Not allow creation account.");
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_PLUGIN_NOT_ALLOWED_CREATION_ERROR;
    }
    std::lock_guard<std::mutex> createLock(createOsAccountMutex_);
#ifdef HICOLLIE_ENABLE
    AccountTimer timer;
#endif // HICOLLIE_ENABLE
    bool isBound = false;
    ErrCode errCode = CheckDomainAccountBound(domainInfo, isBound);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("The domain account is already bound");
        return errCode;
    }
    if (isBound) {
        return ERR_OSACCOUNT_SERVICE_INNER_DOMAIN_ALREADY_BIND_ERROR;
    }
    std::vector<OsAccountInfo> osAccountInfos;
    errCode = QueryAllCreatedOsAccounts(osAccountInfos);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Query all created osAccount failed, errCode:%{public}d", errCode);
        return errCode;
    }
    unsigned int saCreatedNum = 0;
    for (const auto& it : osAccountInfos) {
        if (it.GetCreatorType() == TOKEN_NATIVE) {
            ++saCreatedNum;
        }
    }
    if (!AccountPermissionManager::CheckSaCall() && (osAccountInfos.size() - saCreatedNum) >= config_.maxOsAccountNum) {
        ACCOUNT_LOGE("The number of OS accounts has oversize, max num: %{public}d", config_.maxOsAccountNum);
        return ERR_OSACCOUNT_SERVICE_CONTROL_MAX_CAN_CREATE_ERROR;
    }
    if (!InnerDomainAccountManager::GetInstance().IsPluginAvailable()) {
        ACCOUNT_LOGE("Plugin is not available");
        return ERR_DOMAIN_ACCOUNT_SERVICE_PLUGIN_NOT_EXIST;
    }
    sptr<CheckAndCreateDomainAccountCallback> callbackWrapper =
        new (std::nothrow) CheckAndCreateDomainAccountCallback(osAccountControl_, type, callback, options);
    if (callbackWrapper == nullptr) {
        ACCOUNT_LOGE("New DomainCreateDomainCallback failed");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    return InnerDomainAccountManager::GetInstance().GetDomainAccountInfo(domainInfo, callbackWrapper);
#else
    return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT;
#endif // SUPPORT_DOMAIN_ACCOUNTS
}

void IInnerOsAccountManager::CheckAndRefreshLocalIdRecord(const int id)
{
    std::lock_guard<std::mutex> lock(operatingMutex_);
    std::vector<std::pair<uint64_t, int32_t>> updatesVec;

    auto it = [&](uint64_t displayId, int32_t localId) {
        if (id == localId) {
            if (displayId == Constants::DEFAULT_DISPLAY_ID) {
                updatesVec.emplace_back(displayId, Constants::START_USER_ID);
            } else {
                updatesVec.emplace_back(displayId, Constants::INVALID_OS_ACCOUNT_ID);
            }
        }
    };

    defaultActivatedIds_.Iterate(it);
    for (const auto& update : updatesVec) {
        uint64_t displayId = update.first;
        int32_t newId = update.second;
        osAccountControl_->SetDefaultActivatedOsAccount(displayId, newId);
        defaultActivatedIds_.EnsureInsert(displayId, newId);
    }

    if (id == deviceOwnerId_) {
        ErrCode errCode = osAccountControl_->UpdateDeviceOwnerId(-1);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("Update device owner id failed, errCode = %{public}d", errCode);
        }
    }
    return;
}

ErrCode IInnerOsAccountManager::PrepareRemoveOsAccount(OsAccountInfo &osAccountInfo, bool isCleanGarbage)
{
    int32_t id = osAccountInfo.GetLocalId();
    ErrCode errCode = ERR_OK;
#ifdef HAS_USER_IDM_PART
    errCode = OsAccountInterface::SendToIDMAccountDelete(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("SendToIDMAccountDelete failed, id %{public}d, errCode %{public}d",
            osAccountInfo.GetLocalId(), errCode);
        return errCode;
    }
#endif // HAS_USER_IDM_PART
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    DomainAccountInfo curDomainInfo;
    osAccountInfo.GetDomainInfo(curDomainInfo);
    if (!curDomainInfo.accountName_.empty()) {
        errCode = InnerDomainAccountManager::GetInstance().OnAccountUnBound(curDomainInfo, nullptr, id);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("On account unbound failed, errCode = %{public}d", errCode);
        }
        InnerDomainAccountManager::GetInstance().RemoveTokenFromMap(id);
    }
#endif // SUPPORT_DOMAIN_ACCOUNTS
    if (isCleanGarbage) {
        ACCOUNT_LOGI("Clean garbage account data, no need to deal foreground status.");
        return ERR_OK;
    }
    errCode = ResetForegroundBeforeRemove(osAccountInfo, id);
    if (errCode != ERR_OK) {
        return errCode;
    }
    loggedInAccounts_.Erase(id);
    verifiedAccounts_.Erase(id);
    // stop account
    OsAccountInterface::PublishCommonEvent(
        osAccountInfo, OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_STOPPING, Constants::OPERATION_STOP);
    subscribeManager_.Publish(id, OS_ACCOUNT_SUBSCRIBE_TYPE::STOPPING);
    errCode = SendMsgForAccountStop(osAccountInfo);
    if (errCode != ERR_OK) {
        ReportOsAccountOperationFail(id, "stop", errCode, "stop os account failed");
        return errCode;
    }

    OsAccountInterface::PublishCommonEvent(
        osAccountInfo, OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_STOPPED, Constants::OPERATION_STOP);
    subscribeManager_.Publish(id, OS_ACCOUNT_SUBSCRIBE_TYPE::STOPPED);
    ReportOsAccountLifeCycle(id, Constants::OPERATION_STOP);
    return errCode;
}

ErrCode IInnerOsAccountManager::RemoveOsAccountOperate(const int id, OsAccountInfo &osAccountInfo, bool isCleanGarbage)
{
    if (isCleanGarbage && (!osAccountInfo.GetIsCreateCompleted()) && (!osAccountInfo.GetIsDataRemovable())) {
        ACCOUNT_LOGI("Account cannot be removed id=%{public}d.", id);
        return ERR_OK;
    }
    ErrCode errCode = PrepareRemoveOsAccount(osAccountInfo, isCleanGarbage);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("PrepareRemoveOsAccount failed, errCode %{public}d.", errCode);
        return errCode;
    }
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    DomainAccountInfo domainAccountInfo;
    osAccountInfo.GetDomainInfo(domainAccountInfo);
    if (!domainAccountInfo.accountName_.empty()) {
        InnerDomainAccountManager::GetInstance().NotifyDomainAccountEvent(
            id, DomainAccountEvent::LOG_OUT, DomainAccountStatus::LOGOUT, domainAccountInfo);
    }
#endif // SUPPORT_DOMAIN_ACCOUNTS
    AccountInfo ohosInfo;
    (void)OhosAccountManager::GetInstance().GetAccountInfoByUserId(id, ohosInfo);
    if (ohosInfo.ohosAccountInfo_.name_ != DEFAULT_OHOS_ACCOUNT_NAME) {
#ifdef HAS_CES_PART
        AccountEventProvider::EventPublishAsUser(
            EventFwk::CommonEventSupport::COMMON_EVENT_HWID_LOGOUT, id);
        AccountEventProvider::EventPublishAsUser(
            EventFwk::CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOUT, id);
#else  // HAS_CES_PART
        ACCOUNT_LOGI("No common event part! Publish nothing!");
#endif // HAS_CES_PART
    }
    errCode = SendMsgForAccountRemove(osAccountInfo);
    if (errCode != ERR_OK) {
        return errCode;
    }

    errCode = osAccountControl_->RemoveOAConstraintsInfo(id);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("RemoveOsAccount failed to remove os account constraints info");
        return errCode;
    }
    CheckAndRefreshLocalIdRecord(id);
    subscribeManager_.Publish(id, OS_ACCOUNT_SUBSCRIBE_TYPE::REMOVED);
    return errCode;
}

ErrCode IInnerOsAccountManager::RemoveOsAccount(const int id)
{
    ACCOUNT_LOGI("Remove id is %{public}d", id);
    if (!CheckAndAddLocalIdOperating(id)) {
        ACCOUNT_LOGE("The %{public}d already in operating", id);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_OPERATING_ERROR;
    }

    OsAccountInfo osAccountInfo;
    ErrCode errCode = GetRealOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        RemoveLocalIdToOperating(id);
        ACCOUNT_LOGE("RemoveOsAccount cannot find os account info, errCode %{public}d.", errCode);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    errCode = OsAccountInterface::SendToStorageAccountCreateComplete(id);
    if (errCode != ERR_OK) {
        RemoveLocalIdToOperating(id);
        ACCOUNT_LOGE("SendToStorageAccountCreateComplete failed, errCode=%{public}d, id=%{public}d", errCode, id);
        return errCode;
    }
    // set remove flag first
    osAccountInfo.SetToBeRemoved(true);
    errCode = osAccountControl_->UpdateOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to update ToBeRemoved status, errCode=%{public}d.", errCode);
        ReportOsAccountOperationFail(id, Constants::OPERATION_REMOVE, errCode, "Failed to update ToBeRemoved status");
        return errCode;
    }

    // then remove account
    errCode = RemoveOsAccountOperate(id, osAccountInfo);
    RemoveLocalIdToOperating(id);
    return errCode;
}

ErrCode IInnerOsAccountManager::SendMsgForAccountStop(OsAccountInfo &osAccountInfo)
{
    ErrCode errCode = OsAccountInterface::SendToAMSAccountStop(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("SendToAMSAccountStop failed, id %{public}d, errCode %{public}d",
            osAccountInfo.GetLocalId(), errCode);
        return errCode;
    }
    errCode = OsAccountInterface::CheckAllAppDied(osAccountInfo.GetLocalId());
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("CheckAllAppDied failed, operation is timeout");
        return errCode;
    }
    errCode = OsAccountInterface::SendToStorageAccountStop(osAccountInfo);
    if (errCode != ERR_OK && errCode != ERR_OSACCOUNT_SERVICE_STORAGE_STOP_USER_FAILED) {
        ACCOUNT_LOGE("SendToStorageAccountStop failed, id %{public}d, errCode %{public}d",
            osAccountInfo.GetLocalId(), errCode);
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER;
    }
    return DeactivateOsAccountByInfo(osAccountInfo);
}

ErrCode IInnerOsAccountManager::SendMsgForAccountDeactivate(OsAccountInfo &osAccountInfo, bool isStopStorage)
{
    int32_t localId = osAccountInfo.GetLocalId();
    CleanForegroundAccountMap(osAccountInfo);
    ErrCode errCode = OsAccountInterface::SendToAMSAccountDeactivate(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("SendToAMSAccountDeactivate failed, id %{public}d, errCode %{public}d", localId, errCode);
        return errCode;
    }
    subscribeManager_.Publish(localId, OS_ACCOUNT_SUBSCRIBE_TYPE::STOPPING);
    if (isStopStorage) {
        errCode = OsAccountInterface::SendToStorageAccountStop(osAccountInfo);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("SendToStorageAccountStop failed, id %{public}d, errCode %{public}d", localId, errCode);
            return errCode;
        }
    }

    return DeactivateOsAccountByInfo(osAccountInfo);
}

bool IInnerOsAccountManager::IsToBeRemoved(int32_t localId)
{
    OsAccountInfo osAccountInfo;
    ErrCode ret = GetRealOsAccountInfoById(localId, osAccountInfo);
    if (ret == ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR) {
        return true;
    }
    return osAccountInfo.GetToBeRemoved();
}

ErrCode IInnerOsAccountManager::ValidateOsAccount(const OsAccountInfo &osAccountInfo)
{
    if (osAccountInfo.GetType() == OsAccountType::PRIVATE) {
        return ERR_OK;
    }
    auto accountIndexJson = CreateJson();
    ErrCode result = osAccountControl_->GetAccountIndexFromFile(accountIndexJson);
    if (result != ERR_OK) {
        return result;
    }
    int32_t id = osAccountInfo.GetLocalId();
    cJSON *element = nullptr;
    cJSON_ArrayForEach(element, accountIndexJson) {
        int32_t localId = 0;
        std::string key(element->string);
        if (!StrToInt(key, localId)) {
            ACCOUNT_LOGE("Convert localId failed");
            continue;
        }
        cJSON *nameObj = GetObjFromJson(accountIndexJson, key);
        std::string localName;
        if (GetStringFromJson(nameObj, Constants::LOCAL_NAME, localName) &&
            (osAccountInfo.GetLocalName() == localName) && (localId != id) && !IsToBeRemoved(localId)) {
                return ERR_ACCOUNT_COMMON_NAME_HAD_EXISTED;
        }
        if (!osAccountInfo.GetShortName().empty()) {
            std::string shortName;
            if (GetStringFromJson(nameObj, Constants::SHORT_NAME, shortName) &&
                (osAccountInfo.GetShortName() == shortName) && (localId != id) && !IsToBeRemoved(localId)) {
                    return ERR_ACCOUNT_COMMON_SHORT_NAME_HAD_EXISTED;
            }
        }
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::GetTypeNumber(const OsAccountType& type, int32_t& typeNumber)
{
    typeNumber = 0;
    std::vector<OsAccountInfo> osAccountList;
    ErrCode result = QueryAllCreatedOsAccounts(osAccountList);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Get os account list failed.");
        return result;
    }

    typeNumber = std::count_if(osAccountList.begin(), osAccountList.end(),
        [&type](const OsAccountInfo& info) { return info.GetType() == type; });
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::CheckTypeNumber(const OsAccountType& type)
{
    if (type != OsAccountType::PRIVATE && type != OsAccountType::MAINTENANCE) {
        return ERR_OK;
    }
    int32_t typeNumber = 0;
    ErrCode result = GetTypeNumber(type, typeNumber);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Count type number failed.");
        return result;
    }
    if (type == OsAccountType::PRIVATE && typeNumber >= MAX_PRIVATE_TYPE_NUMBER) {
        ACCOUNT_LOGE("Check type number failed, private type number=%{public}d", typeNumber);
        return ERR_OSACCOUNT_SERVICE_CONTROL_MAX_CAN_CREATE_ERROR;
    }
    if (type == OsAccountType::MAINTENANCE && typeNumber >= MAX_MAINTENANCE_TYPE_NUMBER) {
        ACCOUNT_LOGE("Check type number failed, maintenance type number=%{public}d", typeNumber);
        return ERR_OSACCOUNT_SERVICE_CONTROL_MAX_CAN_CREATE_ERROR;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::SendMsgForAccountRemove(OsAccountInfo &osAccountInfo)
{
    int32_t localId = osAccountInfo.GetLocalId();
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
    AppAccountControlManager::GetInstance().SetOsAccountRemoved(localId, true);
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS
    ErrCode errCode = OsAccountInterface::SendToBMSAccountDelete(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("SendToBMSAccountDelete failed, id %{public}d, errCode %{public}d", localId, errCode);
        return errCode;
    }
    errCode = OsAccountInterface::SendToStorageAccountRemove(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("SendToStorageAccountRemove failed, id %{public}d, errCode %{public}d", localId, errCode);
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER;
    }
    errCode = osAccountControl_->DelOsAccount(localId);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Remove osaccount info failed, id: %{public}d, errCode %{public}d", localId, errCode);
        return errCode;
    }
    OsAccountInterface::SendToCESAccountDelete(osAccountInfo);
    ReportOsAccountLifeCycle(localId, Constants::OPERATION_REMOVE);
    // report data size when account removed
    ReportUserDataSize(GetVerifiedAccountIds(verifiedAccounts_));
    return errCode;
}

bool IInnerOsAccountManager::Init(const std::set<int32_t> &initAccounts)
{
    ACCOUNT_LOGI("Start to create base os accounts");
    CreateBaseAdminAccount();
    // 100 need created
    bool isFirstBoot = initAccounts.find(Constants::START_USER_ID) != initAccounts.end();
#ifdef ENABLE_U1_ACCOUNT
    if (initAccounts.find(Constants::U1_ID) != initAccounts.end() && config_.isU1Enable) {
        OsAccountInfo osAccountInfo(Constants::U1_ID, config_.u1AccountName, config_.u1AccountType);
        bool result = CreateBaseStandardAccount(osAccountInfo);
        // create u1 fail and block boot and 100 has not created
        if (!result) {
            ACCOUNT_LOGE("Create u1 error, result:%{public}d, isBlockBoot:%{public}d, isFirstBoot:%{public}d.",
                result, config_.isBlockBoot, isFirstBoot);
            ReportOsAccountOperationFail(Constants::U1_ID, Constants::OPERATION_BOOT_CREATE,
                result, "Create u1 error, isBlockBoot:" +
                std::to_string(config_.isBlockBoot) + ", isFirstBoot:%{public}d." + std::to_string(isFirstBoot));
            if (config_.isBlockBoot && isFirstBoot) {
                return false;
            }
        }
    }
#endif // ENABLE_U1_ACCOUNT
    if (isFirstBoot) {
#ifdef ENABLE_DEFAULT_ADMIN_NAME
        OsAccountInfo osAccountInfo(Constants::START_USER_ID, STANDARD_LOCAL_NAME,
            OsAccountType::ADMIN);
#else
        OsAccountInfo osAccountInfo(Constants::START_USER_ID, "", OsAccountType::ADMIN);
#endif //ENABLE_DEFAULT_ADMIN_NAME
        CreateBaseStandardAccount(osAccountInfo);
        SetDefaultActivatedOsAccount(osAccountInfo.GetLocalId());
    }
    ACCOUNT_LOGI("End to create base os accounts");
    return true;
}

ErrCode IInnerOsAccountManager::IsOsAccountExists(const int id, bool &isOsAccountExits)
{
    isOsAccountExits = false;
    osAccountControl_->IsOsAccountExists(id, isOsAccountExits);
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::IsOsAccountActived(const int id, bool &isOsAccountActived)
{
    isOsAccountActived = false;

    // check if os account exists
    OsAccountInfo osAccountInfo;
    ErrCode errCode = GetRealOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Get osaccount info error, errCode %{public}d.", errCode);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    if (id == Constants::ADMIN_LOCAL_ID) {
        isOsAccountActived = true;
        return ERR_OK;
    }
    isOsAccountActived = osAccountInfo.GetIsActived();
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::IsOsAccountConstraintEnable(
    const int id, const std::string &constraint, bool &isOsAccountConstraintEnable)
{
    isOsAccountConstraintEnable = false;
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    std::vector<std::string> constraints;
    constraints = osAccountInfo.GetConstraints();
    if (std::find(constraints.begin(), constraints.end(), constraint) != constraints.end()) {
        isOsAccountConstraintEnable = true;
        return ERR_OK;
    }
    constraints.clear();
    if (osAccountControl_->GetGlobalOAConstraintsList(constraints) == ERR_OK) {
        if (std::find(constraints.begin(), constraints.end(), constraint) != constraints.end()) {
            isOsAccountConstraintEnable = true;
            return ERR_OK;
        }
    }
    constraints.clear();
    if (osAccountControl_->GetSpecificOAConstraintsList(id, constraints) == ERR_OK) {
        if (std::find(constraints.begin(), constraints.end(), constraint) != constraints.end()) {
            isOsAccountConstraintEnable = true;
            return ERR_OK;
        }
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::IsOsAccountVerified(const int id, bool &isVerified)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = GetRealOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Get osaccount fail, errCode=%{public}d, id=%{public}d", errCode, id);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    isVerified = osAccountInfo.GetIsVerified();
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::IsOsAccountDeactivating(const int id, bool &isDeactivating)
{
    isDeactivating = false;
    deactivatingAccounts_.Find(id, isDeactivating);
    return ERR_OK;
}

#ifdef FUZZ_TEST
// LCOV_EXCL_START
#endif
ErrCode IInnerOsAccountManager::GetCreatedOsAccountsCount(unsigned int &createdOsAccountCount)
{
    std::vector<int32_t> idList;
    ErrCode errCode = osAccountControl_->GetOsAccountIdList(idList);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Get osaccount info list error, errCode %{public}d.", errCode);
        return errCode;
    }
    createdOsAccountCount = idList.size();
    return ERR_OK;
}
#ifdef FUZZ_TEST
// LCOV_EXCL_STOP
#endif

#ifdef FUZZ_TEST
// LCOV_EXCL_START
#endif
ErrCode IInnerOsAccountManager::GetNonSACreatedOACount(unsigned int &nonSACreatedOACount) const
{
    std::vector<int32_t> idList;
    ErrCode errCode = osAccountControl_->GetOsAccountIdList(idList);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Get osaccount info list error, errCode %{public}d.", errCode);
        return errCode;
    }
    unsigned int saCreatedNum = 0;
    for (const auto& it : idList) {
        OsAccountInfo osAccountInfo;
        if (osAccountControl_->GetOsAccountInfoById(it, osAccountInfo) == ERR_OK &&
            osAccountInfo.GetCreatorType() == TOKEN_NATIVE) {
            ++saCreatedNum;
        }
    }
    nonSACreatedOACount = idList.size() - saCreatedNum;
    return ERR_OK;
}
#ifdef FUZZ_TEST
// LCOV_EXCL_STOP
#endif

#ifdef FUZZ_TEST
// LCOV_EXCL_START
#endif
ErrCode IInnerOsAccountManager::QueryMaxOsAccountNumber(uint32_t &maxOsAccountNumber)
{
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
    maxOsAccountNumber = config_.maxOsAccountNum;
#else
    maxOsAccountNumber = 1;
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS
    return ERR_OK;
}
#ifdef FUZZ_TEST
// LCOV_EXCL_STOP
#endif

#ifdef FUZZ_TEST
// LCOV_EXCL_START
#endif
ErrCode IInnerOsAccountManager::QueryMaxLoggedInOsAccountNumber(uint32_t &maxNum)
{
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
    maxNum = config_.maxLoggedInOsAccountNum;
#else
    maxNum = 1;
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS
    return ERR_OK;
}
#ifdef FUZZ_TEST
// LCOV_EXCL_STOP
#endif

#ifdef FUZZ_TEST
// LCOV_EXCL_START
#endif
ErrCode IInnerOsAccountManager::GetOsAccountAllConstraints(const int id, std::vector<std::string> &constraints)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    constraints = osAccountInfo.GetConstraints();
    std::vector<std::string> globalConstraints;
    errCode = osAccountControl_->GetGlobalOAConstraintsList(globalConstraints);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Get globalConstraints info error");
        return errCode;
    }
    for (auto it = globalConstraints.begin(); it != globalConstraints.end(); it++) {
        if (std::find(constraints.begin(), constraints.end(), *it) == constraints.end()) {
            constraints.push_back(*it);
        }
    }
    std::vector<std::string> specificConstraints;
    errCode = osAccountControl_->GetSpecificOAConstraintsList(id, specificConstraints);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Get specificConstraints info error");
        return errCode;
    }
    for (auto it = specificConstraints.begin(); it != specificConstraints.end(); it++) {
        if (std::find(constraints.begin(), constraints.end(), *it) == constraints.end()) {
            constraints.push_back(*it);
        }
    }
    return ERR_OK;
}
#ifdef FUZZ_TEST
// LCOV_EXCL_STOP
#endif

ErrCode IInnerOsAccountManager::QueryOsAccountConstraintSourceTypes(const int32_t id,
    const std::string &constraint, std::vector<ConstraintSourceTypeInfo> &constraintSourceTypeInfos)
{
    ACCOUNT_LOGD("Enter.");
    bool isOsAccountConstraintEnable = false;
    ErrCode errCode = IsOsAccountConstraintEnable(id, constraint, isOsAccountConstraintEnable);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Get os account constraint enable info error");
        return errCode;
    }
    if (!isOsAccountConstraintEnable) {
        ACCOUNT_LOGI("Constraint not exist");
        ConstraintSourceTypeInfo constraintSourceTypeInfo;
        constraintSourceTypeInfo.localId = -1;
        constraintSourceTypeInfo.typeInfo = ConstraintSourceType::CONSTRAINT_NOT_EXIST;
        constraintSourceTypeInfos.push_back(constraintSourceTypeInfo);
        return ERR_OK;
    }

    bool isExits;
    if (osAccountControl_->IsFromBaseOAConstraintsList(id, constraint, isExits) == ERR_OK) {
        if (isExits) {
            ACCOUNT_LOGI("Constraint is exist in base os account constraints list");
            ConstraintSourceTypeInfo constraintSourceTypeInfo;
            constraintSourceTypeInfo.localId = -1;
            constraintSourceTypeInfo.typeInfo = ConstraintSourceType::CONSTRAINT_TYPE_BASE;
            constraintSourceTypeInfos.push_back(constraintSourceTypeInfo);
        }
    }
    std::vector<ConstraintSourceTypeInfo> globalSourceList;
    errCode = osAccountControl_->IsFromGlobalOAConstraintsList(id, deviceOwnerId_, constraint, globalSourceList);
    if (errCode == ERR_OK && globalSourceList.size() != 0) {
        ACCOUNT_LOGI("Constraint is exist in global os account constraints list");
        constraintSourceTypeInfos.insert(
            constraintSourceTypeInfos.end(), globalSourceList.begin(), globalSourceList.end());
    }
    std::vector<ConstraintSourceTypeInfo> specificSourceList;
    errCode = osAccountControl_->IsFromSpecificOAConstraintsList(id, deviceOwnerId_, constraint, specificSourceList);
    if (errCode == ERR_OK && specificSourceList.size() != 0) {
        ACCOUNT_LOGI("Constraint is exist in specific os account constraints list");
        constraintSourceTypeInfos.insert(
            constraintSourceTypeInfos.end(), specificSourceList.begin(), specificSourceList.end());
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::SetBaseOsAccountConstraints(const int32_t id,
    const std::vector<std::string> &constraints, const bool enable)
{
    ErrCode errCode = SetOsAccountConstraints(id, constraints, enable);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Set os account %{public}d constraints failed! errCode %{public}d.", id, errCode);
        return errCode;
    }

    errCode = osAccountControl_->UpdateBaseOAConstraints(std::to_string(id), constraints, enable);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Update base os account %{public}d constraints failed! errCode %{public}d.", id, errCode);
        return errCode;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::SetGlobalOsAccountConstraints(const std::vector<std::string> &constraints,
    const bool enable, const int32_t enforcerId, const bool isDeviceOwner)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(enforcerId, osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    if (osAccountInfo.GetToBeRemoved()) {
        ACCOUNT_LOGE("Account %{public}d will be removed, cannot change constraints!", enforcerId);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_TO_BE_REMOVED_ERROR;
    }

    if (!osAccountControl_->CheckConstraints(constraints)) {
        ACCOUNT_LOGE("Invalid constraints");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    errCode = osAccountControl_->UpdateGlobalOAConstraints(std::to_string(enforcerId), constraints, enable);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Update global OA constraints failed, errCode = %{public}d", errCode);
    }

    errCode = DealWithDeviceOwnerId(isDeviceOwner, enforcerId);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Deal with device owner id error");
        return errCode;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::SetSpecificOsAccountConstraints(const std::vector<std::string> &constraints,
    const bool enable, const int32_t targetId, const int32_t enforcerId, const bool isDeviceOwner)
{
    OsAccountInfo enforcerOsAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(enforcerId, enforcerOsAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }

    OsAccountInfo targetOsAccountInfo;
    errCode = osAccountControl_->GetOsAccountInfoById(targetId, targetOsAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    if (targetOsAccountInfo.GetToBeRemoved() || enforcerOsAccountInfo.GetToBeRemoved()) {
        ACCOUNT_LOGE("Account %{public}d or %{public}d will be removed, cannot change constraints!",
            enforcerId, targetId);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_TO_BE_REMOVED_ERROR;
    }

    if (!osAccountControl_->CheckConstraints(constraints)) {
        ACCOUNT_LOGE("Invalid constraints");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    errCode = osAccountControl_->UpdateSpecificOAConstraints(
        std::to_string(enforcerId), std::to_string(targetId), constraints, enable);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Update specific OA constraints failed, errCode = %{public}d", errCode);
    }

    errCode = DealWithDeviceOwnerId(isDeviceOwner, enforcerId);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Deal with device owner id error");
        return errCode;
    }
    return ERR_OK;
}

#ifdef FUZZ_TEST
// LCOV_EXCL_START
#endif
ErrCode IInnerOsAccountManager::QueryAllCreatedOsAccounts(std::vector<OsAccountInfo> &createdOsAccounts)
{
    std::vector<int32_t> allOsAccountIds;
    ErrCode errCode = osAccountControl_->GetOsAccountIdList(allOsAccountIds);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Get osaccount info list error, errCode %{public}d.", errCode);
        return errCode;
    }
    for (auto id : allOsAccountIds) {
        OsAccountInfo osAccountInfo;
        GetRealOsAccountInfoById(id, osAccountInfo);
        if (osAccountInfo.GetIsCreateCompleted() && !osAccountInfo.GetToBeRemoved()) {
            std::string photo = osAccountInfo.GetPhoto();
            osAccountControl_->GetPhotoById(id, photo);
            osAccountInfo.SetPhoto(photo);
            createdOsAccounts.push_back(osAccountInfo);
        }
    }
    return ERR_OK;
}
#ifdef FUZZ_TEST
// LCOV_EXCL_STOP
#endif

ErrCode IInnerOsAccountManager::DealWithDeviceOwnerId(const bool isDeviceOwner, const int32_t localId)
{
    ACCOUNT_LOGD("Enter.");
    if (isDeviceOwner && localId != deviceOwnerId_) {
        ACCOUNT_LOGI("This device owner os account id is changed!");
        deviceOwnerId_ = localId;
        return osAccountControl_->UpdateDeviceOwnerId(localId);
    }
    if (isDeviceOwner == false && localId == deviceOwnerId_) {
        deviceOwnerId_ = -1;
        return osAccountControl_->UpdateDeviceOwnerId(-1);
    }
    return ERR_OK;
}

int32_t IInnerOsAccountManager::CleanGarbageOsAccounts(int32_t excludeId)
{
    ACCOUNT_LOGI("Enter");
    std::vector<int32_t> idList;
    if (osAccountControl_->GetOsAccountIdList(idList) != ERR_OK) {
        ACCOUNT_LOGI("GetOsAccountIdList failed.");
        return 0;
    }

    int32_t removeNum = 0;

    for (auto id : idList) {
        if (id == Constants::START_USER_ID || id == Constants::ADMIN_LOCAL_ID || id == Constants::U1_ID ||
            id == excludeId) {
            continue;
        }
        if (!CheckAndAddLocalIdOperating(id)) {
            ACCOUNT_LOGI("Account id = %{public}d already in operating", id);
            continue;
        }
        OsAccountInfo osAccountInfo;
        ErrCode ret = GetRealOsAccountInfoById(id, osAccountInfo);
        if (ret != ERR_OK && ret != ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR) {
            continue;
        }
        osAccountInfo.SetLocalId(id);

        if (!osAccountInfo.GetToBeRemoved() && osAccountInfo.GetIsCreateCompleted()) {
            RemoveLocalIdToOperating(id);
            continue;
        }
        ErrCode errCode = RemoveOsAccountOperate(id, osAccountInfo, true);
        RemoveLocalIdToOperating(id);
        if (errCode != ERR_OK) {
            REPORT_OS_ACCOUNT_FAIL(id, Constants::OPERATION_CLEAN,
                errCode, "Clean garbage os accounts failed");
            ACCOUNT_LOGE("Remove account %{public}d failed! errCode %{public}d.", id, errCode);
        } else {
            ACCOUNT_LOGI("Remove account %{public}d succeed!", id);
            ReportOsAccountLifeCycle(id, Constants::OPERATION_CLEAN);
            removeNum++;
        }
    }
    if (removeNum > 0) {
        ReportOsAccountLifeCycle(removeNum, Constants::OPERATION_CLEAN);
    }
    ACCOUNT_LOGI("Finished.");
    return removeNum;
}

#ifdef SUPPORT_DOMAIN_ACCOUNTS
bool IInnerOsAccountManager::IsSameAccount(
    const DomainAccountInfo &domainInfoSrc, const DomainAccountInfo &domainInfoTar)
{
    return (((!domainInfoSrc.accountId_.empty()) && (domainInfoSrc.accountId_ == domainInfoTar.accountId_)) ||
        ((!domainInfoSrc.accountName_.empty()) && (domainInfoSrc.accountName_ == domainInfoTar.accountName_) &&
        (!domainInfoSrc.domain_.empty()) && (domainInfoSrc.domain_ == domainInfoTar.domain_)));
}
#endif // SUPPORT_DOMAIN_ACCOUNTS

ErrCode IInnerOsAccountManager::GetOsAccountLocalIdFromDomain(const DomainAccountInfo &domainInfo, int &id)
{
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    if (domainInfo.domain_.size() > Constants::DOMAIN_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("Invalid domain name length %{public}zu.", domainInfo.domain_.size());
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    if (domainInfo.accountName_.size() > Constants::LOCAL_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("Invalid domain account name length %{public}zu.", domainInfo.accountName_.size());
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    id = -1;
    std::vector<OsAccountInfo> osAccountInfos;
    ErrCode errCode = osAccountControl_->GetOsAccountList(osAccountInfos);
    if (errCode != ERR_OK) {
        return errCode;
    }

    DomainAccountInfo curDomainInfo;
    for (auto osAccountInfosPtr = osAccountInfos.begin(); osAccountInfosPtr != osAccountInfos.end();
         ++osAccountInfosPtr) {
        osAccountInfosPtr->GetDomainInfo(curDomainInfo);
        if (IsSameAccount(curDomainInfo, domainInfo)) {
            id = osAccountInfosPtr->GetLocalId();
            return ERR_OK;
        }
    }
    return ERR_DOMAIN_ACCOUNT_SERVICE_NOT_DOMAIN_ACCOUNT;
#else
    return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT;
#endif // SUPPORT_DOMAIN_ACCOUNTS
}

ErrCode IInnerOsAccountManager::GetOsAccountShortName(const int id, std::string &shortName)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    shortName = osAccountInfo.GetShortName();
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::GetOsAccountName(const int id, std::string &name)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    name = osAccountInfo.GetLocalName();
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::QueryOsAccountById(const int id, OsAccountInfo &osAccountInfo)
{
    ErrCode errCode = GetRealOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Get osaccount info error, errCode %{public}d.", errCode);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }

    if (osAccountInfo.GetPhoto() != "") {
        std::string photo = osAccountInfo.GetPhoto();
        errCode = osAccountControl_->GetPhotoById(osAccountInfo.GetLocalId(), photo);
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("Get osaccount photo error, errCode %{public}d.", errCode);
            return errCode;
        }
        osAccountInfo.SetPhoto(photo);
    }
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    GetDomainAccountStatus(osAccountInfo);
#endif // SUPPORT_DOMAIN_ACCOUNTS
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::GetOsAccountType(const int id, OsAccountType &type)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    type = osAccountInfo.GetType();
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::GetOsAccountProfilePhoto(const int id, std::string &photo)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = QueryOsAccountById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("QueryOsAccountById return error, errCode %{public}d.", errCode);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    photo = osAccountInfo.GetPhoto();
    return ERR_OK;
}

#ifdef FUZZ_TEST
// LCOV_EXCL_START
#endif
ErrCode IInnerOsAccountManager::IsMultiOsAccountEnable(bool &isMultiOsAccountEnable)
{
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
    ErrCode errCode = osAccountControl_->GetIsMultiOsAccountEnable(isMultiOsAccountEnable);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("GetIsMultiOsAccountEnable error, errCode %{public}d.", errCode);
        return errCode;
    }
#else
    isMultiOsAccountEnable = false;
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS
    return ERR_OK;
}
#ifdef FUZZ_TEST
// LCOV_EXCL_STOP
#endif

ErrCode IInnerOsAccountManager::SetOsAccountName(const int id, const std::string &name)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }

    // to be removed, cannot change any thing
    if (osAccountInfo.GetToBeRemoved()) {
        ACCOUNT_LOGE("Account %{public}d will be removed, cannot change name!", id);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_TO_BE_REMOVED_ERROR;
    }

    std::string localName = osAccountInfo.GetLocalName();
    if (localName == name) {
        return ERR_OK;
    }

    osAccountInfo.SetLocalName(name);
    errCode = ValidateOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Account name already exist, errCode %{public}d.", errCode);
        return errCode;
    }

    errCode = osAccountControl_->UpdateOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Update osaccount info error %{public}d, id: %{public}d", errCode, osAccountInfo.GetLocalId());
        return ERR_OSACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR;
    }
    errCode = osAccountControl_->UpdateAccountIndex(osAccountInfo, false);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Update account index failed, errCode = %{public}d", errCode);
    }
    OsAccountInterface::PublishCommonEvent(
        osAccountInfo, OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_INFO_UPDATED, OPERATION_UPDATE);
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::SetOsAccountConstraints(
    const int id, const std::vector<std::string> &constraints, const bool enable)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }

    // to be removed, cannot change any thing
    if (osAccountInfo.GetToBeRemoved()) {
        ACCOUNT_LOGE("Account %{public}d will be removed, cannot change constraints!", id);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_TO_BE_REMOVED_ERROR;
    }

    if (!osAccountControl_->CheckConstraints(constraints)) {
        ACCOUNT_LOGE("Invalid constraints");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    std::vector<std::string> oldConstraints = osAccountInfo.GetConstraints();
    for (auto it = constraints.begin(); it != constraints.end(); it++) {
        if (enable) {
            if (std::find(oldConstraints.begin(), oldConstraints.end(), *it) == oldConstraints.end()) {
                oldConstraints.push_back(*it);
            }
        } else {
            oldConstraints.erase(
                std::remove(oldConstraints.begin(), oldConstraints.end(), *it), oldConstraints.end());
        }
    }
    osAccountInfo.SetConstraints(oldConstraints);
    errCode = osAccountControl_->UpdateOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Update osaccount info error %{public}d, id: %{public}d", errCode, osAccountInfo.GetLocalId());
        return ERR_OSACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::SetOsAccountProfilePhoto(const int id, const std::string &photo)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }

    // to be removed, cannot change any thing
    if (osAccountInfo.GetToBeRemoved()) {
        ACCOUNT_LOGE("Account %{public}d will be removed, cannot change photo!", id);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_TO_BE_REMOVED_ERROR;
    }

    if (osAccountInfo.GetPhoto() == photo) {
        return ERR_OK;
    }
    errCode = osAccountControl_->SetPhotoById(id, photo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Set photo error, code=%{public}d, id=%{public}d.", errCode, id);
        return errCode;
    }
    osAccountInfo.SetPhoto(Constants::USER_PHOTO_FILE_TXT_NAME);
    errCode = osAccountControl_->UpdateOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Update osaccount info faile code=%{public}d, id=%{public}d", errCode, osAccountInfo.GetLocalId());
        return ERR_OSACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR;
    }
    // report data size when profile photo updated
    ReportUserDataSize(GetVerifiedAccountIds(verifiedAccounts_));
    OsAccountInterface::PublishCommonEvent(
        osAccountInfo, OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_INFO_UPDATED, OPERATION_UPDATE);
    return ERR_OK;
}

void IInnerOsAccountManager::CleanForegroundAccountMap(const OsAccountInfo &osAccountInfo)
{
    if (!osAccountInfo.GetIsForeground()) {
        return;
    }
    
    int32_t localId = osAccountInfo.GetLocalId();
    uint64_t displayId = osAccountInfo.GetDisplayId();
    
    int32_t currentForegroundId = -1;
    if (foregroundAccountMap_.Find(displayId, currentForegroundId) && currentForegroundId == localId) {
        ACCOUNT_LOGI("Removing foreground account id=%{public}d from display %{public}llu",
            localId, static_cast<unsigned long long>(displayId));
        foregroundAccountMap_.Erase(displayId);
    }
}

ErrCode IInnerOsAccountManager::DeactivateOsAccountByInfo(OsAccountInfo &osAccountInfo)
{
    int localId = osAccountInfo.GetLocalId();
    loggedInAccounts_.Erase(localId);
    verifiedAccounts_.Erase(localId);
    CleanForegroundAccountMap(osAccountInfo);
    EraseIdFromActiveList(localId);

    DomainAccountInfo domainAccountInfo;
    osAccountInfo.GetDomainInfo(domainAccountInfo);
    domainAccountInfo.status_ = DomainAccountStatus::LOGOUT;
    osAccountInfo.SetDomainInfo(domainAccountInfo);
    ErrCode errCode = osAccountControl_->UpdateOsAccount(osAccountInfo);
    if (errCode != ERR_OK && errCode != ERR_ACCOUNT_COMMON_DATA_NO_SPACE) {
        ACCOUNT_LOGE("Update account failed, id=%{public}d, errCode=%{public}d.", osAccountInfo.GetLocalId(), errCode);
        return ERR_OSACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR;
    }

    AccountInfoReport::ReportSecurityInfo(osAccountInfo.GetLocalName(), localId,
                                          ReportEvent::EVENT_LOGOUT, 0);
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::DeactivateOsAccountById(const int id)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = GetRealOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Cannot get os account %{public}d info. error %{public}d.",
            id, errCode);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    return DeactivateOsAccountByInfo(osAccountInfo);
}

/**
 * This function sets the isAppRecovery flag to true in two scenarios:
 * 1. During boot stage (including fast boot) when activating the main account:
 *    - When the active account list only contains NO_DESKTOP_USER.
 * 2. When re-activating a user after it has been logged out:
 *    - When the same account is activated again after logout.
 *
 * NO_DESKTOP_OS_ACCOUNTS is a vector contains the no-desktop accounts.
 */
static void SetAppRecovery(bool &isAppRecovery,
    const std::vector<int32_t> &activeAccountId, std::int32_t id, std::int32_t defaultActivatedId)
{
#ifdef SUPPORT_STOP_MAIN_OS_ACCOUNT
    if (!isAppRecovery && (activeAccountId.size() <= NO_DESKTOP_OS_ACCOUNTS.size())) {
        isAppRecovery = true;
    }
#endif
}

bool IInnerOsAccountManager::IsLoggedInAccountsOversize()
{
    uint32_t logginAccountSize = static_cast<uint32_t>(loggedInAccounts_.Size());
#ifdef ENABLE_U1_ACCOUNT
    bool isLoggedIn = false;
    loggedInAccounts_.Find(Constants::U1_ID, isLoggedIn);
    if (isLoggedIn) {
        logginAccountSize = logginAccountSize - 1;
    }
#endif // ENABLE_U1_ACCOUNT
    if (logginAccountSize >= config_.maxLoggedInOsAccountNum) {
        return true;
    }
    return false;
}

#ifdef ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS
void IInnerOsAccountManager::QueryAllDisplayIds(std::vector<uint64_t> &displayIds)
{
    displayIds.clear();
    std::vector<Rosen::DisplayId> allDisplayIds = Rosen::DisplayManagerLite::GetInstance().GetAllDisplayIds();
    if (allDisplayIds.empty()) {
        ACCOUNT_LOGW("GetAllDisplayIds returned empty display list");
        ReportOsAccountOperationFail(-1, "queryDisplayIds", 0, "GetAllDisplayIds returned empty display list");
    }
    for (const auto &displayId : allDisplayIds) {
        displayIds.emplace_back(static_cast<uint64_t>(displayId));
    }
}

ErrCode IInnerOsAccountManager::ValidateDisplayId(const uint64_t displayId)
{
    if (displayId != Constants::DEFAULT_DISPLAY_ID) {
        std::vector<uint64_t> displayIds;
        QueryAllDisplayIds(displayIds);
        if (std::find(displayIds.begin(), displayIds.end(), displayId) == displayIds.end()) {
            ACCOUNT_LOGE("Display %{public}llu does not exist", static_cast<unsigned long long>(displayId));
            return ERR_ACCOUNT_COMMON_DISPLAY_ID_NOT_EXIST_ERROR;
        }
    }
    return ERR_OK;
}
#endif // ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS

#ifdef ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS
ErrCode IInnerOsAccountManager::ValidateDisplayForActivation(const int id, const uint64_t displayId)
{
    std::vector<uint64_t> displayIds;
    QueryAllDisplayIds(displayIds);
    bool displayIdExists = false;
    for (const auto &remoteDisId : displayIds) {
        if (remoteDisId == displayId || displayId == Constants::DEFAULT_DISPLAY_ID) {
            displayIdExists = true;
            break;
        }
    }
    if (!displayIdExists && (displayId != Constants::DEFAULT_DISPLAY_ID)) {
        ACCOUNT_LOGE("Display %{public}llu does not exist", static_cast<unsigned long long>(displayId));
        ReportOsAccountOperationFail(id, Constants::OPERATION_ACTIVATE,
            ERR_ACCOUNT_COMMON_DISPLAY_ID_NOT_EXIST_ERROR,
            "Target display does not exist");
        RemoveLocalIdToOperating(id);
        return ERR_ACCOUNT_COMMON_DISPLAY_ID_NOT_EXIST_ERROR;
    }
    // If this account is already foreground on any other display, disallow activation on target display
    bool isActiveCrossDisplay = false;
    auto it = [&isActiveCrossDisplay, displayId, id](uint64_t currentDisplayId, int32_t currentLocalId) {
        if ((currentLocalId == id) && (currentDisplayId != displayId)) {
            isActiveCrossDisplay = true;
        }
    };
    foregroundAccountMap_.Iterate(it);
    if (isActiveCrossDisplay) {
        ACCOUNT_LOGE("Failed to activate. Account %{public}d is already foreground on another display.", id);
        ReportOsAccountOperationFail(id, Constants::OPERATION_ACTIVATE,
            ERR_ACCOUNT_COMMON_CROSS_DISPLAY_ACTIVE_ERROR,
            "Account already foreground on another display");
        RemoveLocalIdToOperating(id);
        return ERR_ACCOUNT_COMMON_CROSS_DISPLAY_ACTIVE_ERROR;
    }
    return ERR_OK;
}
#endif // ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS

ErrCode IInnerOsAccountManager::PrepareActivateOsAccount(
    const int id, const uint64_t displayId, OsAccountInfo &osAccountInfo, int32_t &foregroundId)
{
    // Get account information
    ErrCode errCode = GetRealOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        RemoveLocalIdToOperating(id);
        ACCOUNT_LOGE("Cannot find os account info by id:%{public}d, errCode %{public}d.", id, errCode);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    
    // Validate display ID for activation
#ifdef ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS
    errCode = ValidateDisplayForActivation(id, displayId);
    if (errCode != ERR_OK) {
        return errCode;
    }
#else
    if (displayId != Constants::DEFAULT_DISPLAY_ID && displayId != Constants::INVALID_DISPLAY_ID) {
        ReportOsAccountOperationFail(id, Constants::OPERATION_ACTIVATE,
            ERR_ACCOUNT_COMMON_DISPLAY_ID_NOT_EXIST_ERROR,
            "Display not supported in non-multi-foreground environment");
        RemoveLocalIdToOperating(id);
        return ERR_ACCOUNT_COMMON_DISPLAY_ID_NOT_EXIST_ERROR;
    }
#endif // ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS
    
    foregroundId = -1;
    if (foregroundAccountMap_.Find(displayId, foregroundId) && (foregroundId == id) && osAccountInfo.GetIsVerified()) {
        ACCOUNT_LOGI("Account %{public}d already is foreground", id);
        RemoveLocalIdToOperating(id);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_ALREADY_ACTIVE_ERROR;
    }
    
    errCode = IsValidOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        RemoveLocalIdToOperating(id);
        return errCode;
    }
    
    if (!osAccountInfo.GetIsActived() && IsLoggedInAccountsOversize()) {
        RemoveLocalIdToOperating(id);
        ACCOUNT_LOGE("The number of logged in account reaches the upper limit, maxLoggedInNum: %{public}d",
            config_.maxLoggedInOsAccountNum);
        return ERR_OSACCOUNT_SERVICE_LOGGED_IN_ACCOUNTS_OVERSIZE;
    }
    
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::ActivateOsAccount
    (const int32_t id, const bool startStorage, const uint64_t displayId, bool isAppRecovery)
{
    // Check if account is already in operation
    if (!CheckAndAddLocalIdOperating(id)) {
        ACCOUNT_LOGE("The %{public}d already in operating", id);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_OPERATING_ERROR;
    }

    // acquire the exclusive lock
    std::lock_guard<std::mutex> lock(*GetOrInsertUpdateLock(id));
    
    // prepare to activate the account
    OsAccountInfo osAccountInfo;
    int32_t foregroundId = -1;
    ErrCode errCode = PrepareActivateOsAccount(id, displayId, osAccountInfo, foregroundId);
    if (errCode == ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_ALREADY_ACTIVE_ERROR) {
        return ERR_OK;
    }
    if (errCode != ERR_OK) {
        return errCode;
    }
    
    // publish activating event
    if (foregroundId != id) {
        subscribeManager_.Publish(id, OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATING);
    }
    
    // set the account as active
    int32_t activatedId;
    if (defaultActivatedIds_.Find(displayId, activatedId)) {
        SetAppRecovery(isAppRecovery, activeAccountId_, id, activatedId);
    }
    
    // main func to send message for account activation
    errCode = SendMsgForAccountActivate(osAccountInfo, startStorage, displayId, isAppRecovery);
    RemoveLocalIdToOperating(id);
    if (errCode != ERR_OK) {
        return errCode;
    }
    
    //domain account
    DomainAccountInfo domainInfo;
    osAccountInfo.GetDomainInfo(domainInfo);
    if (domainInfo.accountId_.empty() && (osAccountInfo.GetCredentialId() == 0)) {
        AccountInfoReport::ReportSecurityInfo(osAccountInfo.GetLocalName(), id, ReportEvent::EVENT_LOGIN, 0);
    }
    
    ACCOUNT_LOGI("Activate end");
    return ERR_OK;
}

#ifdef FUZZ_TEST
// LCOV_EXCL_START
#endif
void IInnerOsAccountManager::ExecuteDeactivationAnimation(int32_t pipeFd, const OsAccountInfo &osAccountInfo)
{
    std::string pipeFdStr = std::to_string(pipeFd);
    std::string displayIdStr = std::to_string(osAccountInfo.GetDisplayId());
    char *const args[] = { const_cast<char *>(DEACTIVATION_ANIMATION_PATH),
        const_cast<char *>(displayIdStr.c_str()), const_cast<char *>(pipeFdStr.c_str()), nullptr };
    if (execv(DEACTIVATION_ANIMATION_PATH, args) == -1) {
        int32_t err = errno;
        ACCOUNT_LOGE("Failed to execv animation: %{public}s", strerror(err));
        ReportOsAccountOperationFail(osAccountInfo.GetLocalId(), "deactivate", err,
            "Failed to launch deactivation animation, execv error");
        close(pipeFd);
        exit(EXIT_FAILURE);
    }
}
#ifdef FUZZ_TEST
// LCOV_EXCL_STOP
#endif

#ifdef FUZZ_TEST
// LCOV_EXCL_START
#endif
ErrCode IInnerOsAccountManager::WaitForAnimationReady(int32_t pipeFd)
{
    char buf[MAX_WAIT_ANIMATION_MSG_BUFFER];
    struct pollfd fds[1];
    fds[0].fd = pipeFd;
    fds[0].events = POLLIN;

    int ret = poll(fds, 1, MAX_WAIT_ANIMATION_READY_TIMEOUT);
    if (ret < 0) {
        ACCOUNT_LOGE("Error in poll: %{public}s", strerror(errno));
        return ERR_OSACCOUNT_SERVICE_INNER_ANIMATION_POLL_ERROR;
    }
    if (ret == 0) {
        ACCOUNT_LOGE("Timeout waiting for message from child process.");
        return ERR_OSACCOUNT_SERVICE_INNER_ANIMATION_TIMEOUT;
    }
    if (!(static_cast<uint16_t>(fds[0].revents) & POLLIN)) {
        ACCOUNT_LOGE("Unexpected event in poll: %{public}d", fds[0].revents);
        return ERR_OSACCOUNT_SERVICE_INNER_ANIMATION_UNEXPECTED_EVENT;
    }
    ssize_t bytesRead = read(pipeFd, buf, sizeof(buf));
    if (bytesRead <= 0) {
        ACCOUNT_LOGE("Error reading from pipe: %{public}s", strerror(errno));
        return ERR_OSACCOUNT_SERVICE_INNER_ANIMATION_READ_ERROR;
    }
    buf[bytesRead] = '\0';
    ACCOUNT_LOGI("Received message from child process: %{public}s", buf);
    return ERR_OK;
}
#ifdef FUZZ_TEST
// LCOV_EXCL_STOP
#endif

#ifdef FUZZ_TEST
// LCOV_EXCL_START
#endif
void IInnerOsAccountManager::LaunchDeactivationAnimation(const OsAccountInfo &osAccountInfo)
{
    int32_t localId = osAccountInfo.GetLocalId();
    ACCOUNT_LOGI("Start launching deactivation animation for account: %{public}d", localId);
    struct stat buffer;
    if (stat(DEACTIVATION_ANIMATION_PATH, &buffer) != 0) {
        ACCOUNT_LOGW("Animation launch file does not exist: %{public}s, %{public}s,",
            DEACTIVATION_ANIMATION_PATH, strerror(errno));
        return;
    }

    int pipeFd[PIPE_FD_COUNT];
    if (pipe(pipeFd) == -1) {
        int32_t err = errno;
        ACCOUNT_LOGE("Failed to create pipe: %{public}s", strerror(err));
        ReportOsAccountOperationFail(localId, "deactivate", err,
            "Failed to launch deactivation animation, create pipe error");
        return;
    }

    pid_t pid = fork();
    if (pid == 0) {
        close(pipeFd[PIPE_READ_END]);
        ExecuteDeactivationAnimation(pipeFd[PIPE_WRITE_END], osAccountInfo);
    } else if (pid > 0) {
        close(pipeFd[PIPE_WRITE_END]);
        ErrCode ret = WaitForAnimationReady(pipeFd[PIPE_READ_END]);
        if (ret != ERR_OK) {
            ReportOsAccountOperationFail(localId, "deactivate", ret,
                "Failed to launch deactivation animation, wait msg error");
        }
        close(pipeFd[PIPE_READ_END]);
    } else {
        int32_t err = errno;
        ACCOUNT_LOGE("Failed to fork deactivation animation process: %{public}s", strerror(err));
        ReportOsAccountOperationFail(localId, "deactivate", err,
            "Failed to launch deactivation animation, fork error");
        close(pipeFd[PIPE_READ_END]);
        close(pipeFd[PIPE_WRITE_END]);
    }
}
#ifdef FUZZ_TEST
// LCOV_EXCL_STOP
#endif

ErrCode IInnerOsAccountManager::DeactivateOsAccount(const int id, bool isStopStorage)
{
    if (!CheckAndAddLocalIdOperating(id)) {
        ACCOUNT_LOGW("The %{public}d already in operating", id);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_OPERATING_ERROR;
    }
    std::lock_guard<std::mutex> lock(*GetOrInsertUpdateLock(id));
    OsAccountInfo osAccountInfo;
    ErrCode errCode = GetRealOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        RemoveLocalIdToOperating(id);
        ACCOUNT_LOGW("Cannot find os account info by id:%{public}d, errCode %{public}d.", id, errCode);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }

    if ((!osAccountInfo.GetIsActived()) && (!osAccountInfo.GetIsVerified())) {
        RemoveLocalIdToOperating(id);
        ACCOUNT_LOGW("Account %{public}d is neither active nor verified, don't need to deactivate!", id);
        return ERR_OK;
    }
    errCode = IsValidOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        RemoveLocalIdToOperating(id);
        return errCode;
    }

    deactivatingAccounts_.EnsureInsert(id, true);

    OsAccountInterface::PublishCommonEvent(
        osAccountInfo, OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_STOPPING, Constants::OPERATION_STOP);

    if (osAccountInfo.GetIsForeground()) {
        LaunchDeactivationAnimation(osAccountInfo);
    }

    errCode = SendMsgForAccountDeactivate(osAccountInfo, isStopStorage);
    deactivatingAccounts_.Erase(id);
    if (errCode != ERR_OK) {
        RemoveLocalIdToOperating(id);
        ReportOsAccountOperationFail(id, "deactivate", errCode, "deactivate os account failed");
        return errCode;
    }

    OsAccountInterface::PublishCommonEvent(osAccountInfo, OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_STOPPED,
                                           Constants::OPERATION_STOP);
    subscribeManager_.Publish(id, OS_ACCOUNT_SUBSCRIBE_TYPE::STOPPED);
    ReportOsAccountLifeCycle(id, Constants::OPERATION_STOP);

    RemoveLocalIdToOperating(id);
    ACCOUNT_LOGI("Deactivate end");
    return ERR_OK;
}

#ifdef FUZZ_TEST
// LCOV_EXCL_START
#endif
void IInnerOsAccountManager::RollBackToEarlierAccount(int32_t fromId, int32_t toId, uint64_t displayId)
{
    ACCOUNT_LOGI("Enter.");
    if (fromId == toId) {
        return;
    }
    subscribeManager_.Publish(toId, OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHED, fromId, displayId);
    ReportOsAccountSwitch(fromId, toId);
    ACCOUNT_LOGI("End pushlishing pre switch event.");
    OsAccountInfo osAccountInfo;
    osAccountInfo.SetLocalId(toId);
    subscribeManager_.Publish(fromId, OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHING, toId, displayId);
    OsAccountInterface::PublishCommonEvent(osAccountInfo,
        OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_FOREGROUND, Constants::OPERATION_SWITCH);
    subscribeManager_.Publish(fromId, OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHED, toId, displayId);
    ReportOsAccountSwitch(toId, fromId);
    ACCOUNT_LOGI("End pushlishing post switch event.");
}
#ifdef FUZZ_TEST
// LCOV_EXCL_STOP
#endif

ErrCode IInnerOsAccountManager::SendToStorageAndAMSAccountStart(OsAccountInfo &osAccountInfo, const bool startStorage,
    const uint64_t displayId, const bool isAppRecovery, int32_t oldId)
{
    int32_t localId = static_cast<int32_t>(osAccountInfo.GetLocalId());

    if (startStorage) {
        ErrCode errCode = SendToStorageAccountStart(osAccountInfo);
        if (errCode != ERR_OK && !isAppRecovery) {
            RollBackToEarlierAccount(localId, oldId, displayId);
            return errCode;
        }
    }

    ErrCode errCode = SendToAMSAccountStart(osAccountInfo, displayId, isAppRecovery);
    if (errCode != ERR_OK) {
        RollBackToEarlierAccount(localId, oldId, displayId);
        return errCode;
    }

    return ERR_OK;
}

ErrCode IInnerOsAccountManager::SendMsgForAccountActivate(OsAccountInfo &osAccountInfo, const bool startStorage,
    const uint64_t displayId, const bool isAppRecovery)
{
    int32_t oldId = -1;
    bool oldIdExist = foregroundAccountMap_.Find(displayId, oldId);
    int32_t localId = static_cast<int32_t>(osAccountInfo.GetLocalId());
    bool preActivated = osAccountInfo.GetIsActived();
    bool switched = (oldId != localId);

    if (!preActivated) {
        OsAccountInterface::PublishCommonEvent(osAccountInfo,
            OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_STARTING, Constants::OPERATION_STARTING);
    }
    if (switched) {
        subscribeManager_.Publish(oldId, OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHING, localId, displayId);
    }
    ErrCode errCode = SendToStorageAndAMSAccountStart(osAccountInfo, startStorage, displayId, isAppRecovery, oldId);
    if (errCode != ERR_OK) {
        return errCode;
    }

    if (switched) {
        OsAccountInterface::PublishCommonEvent(osAccountInfo,
            OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_FOREGROUND, Constants::OPERATION_SWITCH);
    }

#ifdef ACTIVATE_LAST_LOGGED_IN_ACCOUNT
    if (osAccountInfo.GetIsLoggedIn()) {
        std::lock_guard<std::mutex> operatingLock(operatingMutex_);
        osAccountControl_->SetDefaultActivatedOsAccount(displayId, localId);
        defaultActivatedIds_.EnsureInsert(displayId, localId);
    }
#endif

    if (switched) {
        OsAccountInterface::SendToCESAccountSwitched(localId, oldId, displayId);
        subscribeManager_.Publish(localId, OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATED);
        subscribeManager_.Publish(oldId, OS_ACCOUNT_SUBSCRIBE_TYPE::SWITCHED, localId, displayId);
        ReportOsAccountSwitch(localId, oldId);
    }

    if (oldIdExist && switched) {
        errCode = UpdateAccountToBackground(oldId);
        if (errCode != ERR_OK) return errCode;
    }

    if (!preActivated) {
        OsAccountInterface::PublishCommonEvent(osAccountInfo,
            OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_STARTED, Constants::OPERATION_STARTED);
        int32_t activatedId = -1;
        if (defaultActivatedIds_.Find(displayId, activatedId))
            ReportOsAccountLifeCycle(activatedId, Constants::OPERATION_ACTIVATE);
    }

    ACCOUNT_LOGI("SendMsgForAccountActivate ok");
    return errCode;
}

ErrCode  IInnerOsAccountManager::SendToStorageAccountStart(OsAccountInfo &osAccountInfo)
{
    bool preVerified = osAccountInfo.GetIsVerified();
    int32_t localId = osAccountInfo.GetLocalId();
    ErrCode err = OsAccountInterface::SendToStorageAccountStart(osAccountInfo);
    if (err != ERR_OK) {
        ACCOUNT_LOGE("Failed to SendToStorageAccountStart, localId %{public}d, error: %{public}d.", localId, err);
        return ERR_ACCOUNT_COMMON_GET_SYSTEM_ABILITY_MANAGER;
    }
    if (osAccountInfo.GetIsVerified()) {
        verifiedAccounts_.EnsureInsert(osAccountInfo.GetLocalId(), true);
        // report data size when account without verification login
        ReportUserDataSize(GetVerifiedAccountIds(verifiedAccounts_));
    }
    if (osAccountInfo.GetIsLoggedIn()) {
        loggedInAccounts_.EnsureInsert(osAccountInfo.GetLocalId(), true);
    }

    if (!preVerified && osAccountInfo.GetIsVerified()) {
        OsAccountInterface::PublishCommonEvent(osAccountInfo,
            OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED, Constants::OPERATION_UNLOCK);
        subscribeManager_.Publish(localId, OS_ACCOUNT_SUBSCRIBE_TYPE::UNLOCKED);
        ReportOsAccountLifeCycle(localId, Constants::OPERATION_UNLOCK);

        err = osAccountControl_->UpdateOsAccount(osAccountInfo);
        if (err != ERR_OK) {
            ACCOUNT_LOGE("Update account info failed, errCode: %{public}d, id: %{public}d", err, localId);
            REPORT_OS_ACCOUNT_FAIL(
                localId, Constants::OPERATION_ACTIVATE, err, "Failed to update OS account");
        }
    }
    return ERR_OK;
}

ErrCode  IInnerOsAccountManager::SendToAMSAccountStart(OsAccountInfo &osAccountInfo,
    uint64_t displayId, const bool isAppRecovery)
{
    OsAccountStartCallbackFunc callbackFunc = [this, displayId](int32_t localId) {
#ifdef ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS
        if (displayId == Constants::DEFAULT_DISPLAY_ID) {
            this->PushIdIntoActiveList(localId);
        } else {
            activeAccountId_.push_back(localId);
        }
#else
        this->PushIdIntoActiveList(localId);
#endif // ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS
        if (displayId != Constants::INVALID_DISPLAY_ID) {
            this->foregroundAccountMap_.EnsureInsert(displayId, localId);
        }
    };
    ErrCode errCode = OsAccountInterface::SendToAMSAccountStart(osAccountInfo, displayId, callbackFunc, isAppRecovery);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to call SendToAMSAccountStart, localId: %{public}d, error: %{public}d.",
            osAccountInfo.GetLocalId(), errCode);
        return errCode;
    }

    return ERR_OK;
}

ErrCode IInnerOsAccountManager::StartOsAccount(const int id)
{
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::GetOsAccountLocalIdBySerialNumber(const int64_t serialNumber, int &id)
{
    if (serialNumber ==
        Constants::CARRY_NUM * Constants::SERIAL_NUMBER_NUM_START_FOR_ADMIN + Constants::ADMIN_LOCAL_ID) {
        id = Constants::ADMIN_LOCAL_ID;
        return ERR_OK;
    }
    std::vector<OsAccountInfo> osAccountInfos;
    id = -1;
    ErrCode errCode = osAccountControl_->GetOsAccountList(osAccountInfos);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Get osaccount info list error");
        return errCode;
    }
    for (auto it = osAccountInfos.begin(); it != osAccountInfos.end(); it++) {
        if (serialNumber == it->GetSerialNumber()) {
            id = it->GetLocalId();
            break;
        }
    }
    if (id == -1) {
        ACCOUNT_LOGE("Cannot find id by serialNumber");
        return ERR_OSACCOUNT_SERVICE_INNER_SELECT_ERROR;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::GetOsAccountInfoById(const int id, OsAccountInfo &osAccountInfo)
{
    ErrCode errCode = GetRealOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Get osaccount info error, errCode %{public}d.", errCode);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::GetSerialNumberByOsAccountLocalId(const int &id, int64_t &serialNumber)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    serialNumber = osAccountInfo.GetSerialNumber();
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::SubscribeOsAccount(
    const OsAccountSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &eventListener)
{
    auto subscribeInfoPtr = std::make_shared<OsAccountSubscribeInfo>(subscribeInfo);
    if (subscribeInfoPtr == nullptr) {
        ACCOUNT_LOGE("SubscribeInfoPtr is nullptr");
    }
    return subscribeManager_.SubscribeOsAccount(subscribeInfoPtr, eventListener);
}

ErrCode IInnerOsAccountManager::UnsubscribeOsAccount(const sptr<IRemoteObject> &eventListener)
{
    return subscribeManager_.UnsubscribeOsAccount(eventListener);
}

const std::shared_ptr<OsAccountSubscribeInfo> IInnerOsAccountManager::GetSubscribeRecordInfo(
    const sptr<IRemoteObject> &eventListener)
{
    return subscribeManager_.GetSubscribeRecordInfo(eventListener);
}

OS_ACCOUNT_SWITCH_MOD IInnerOsAccountManager::GetOsAccountSwitchMod()
{
    return Constants::NOW_OS_ACCOUNT_SWITCH_MOD;
}

ErrCode IInnerOsAccountManager::IsOsAccountCompleted(const int id, bool &isOsAccountCompleted)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        return errCode;
    }
    isOsAccountCompleted = osAccountInfo.GetIsCreateCompleted();
    return ERR_OK;
}

void IInnerOsAccountManager::CleanGarbageOsAccountsAsync()
{
    auto task = [] {
        IInnerOsAccountManager::GetInstance().CleanGarbageOsAccounts();
    #ifdef SUPPORT_DOMAIN_ACCOUNTS
        InnerDomainAccountManager::GetInstance().CleanUnbindDomainAccount();
    #endif // SUPPORT_DOMAIN_ACCOUNTS
    };
    std::thread cleanThread(task);
    pthread_setname_np(cleanThread.native_handle(), "CleanGarbage");
    cleanThread.detach();
}

ErrCode IInnerOsAccountManager::SetOsAccountIsVerified(const int id, const bool isVerified)
{
    std::lock_guard<std::mutex> lock(*GetOrInsertUpdateLock(id));
    OsAccountInfo osAccountInfo;
    ErrCode errCode = GetRealOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Get osaccount info error, errCode %{public}d.", errCode);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }

    // to be removed, cannot change any thing
    if (osAccountInfo.GetToBeRemoved()) {
        ACCOUNT_LOGE("Account %{public}d will be removed, cannot change verify state!", id);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_TO_BE_REMOVED_ERROR;
    }
    bool preVerified = osAccountInfo.GetIsVerified();

    if (isVerified) {
        verifiedAccounts_.EnsureInsert(id, true);
        // report data size when account with verification verified
        ReportUserDataSize(GetVerifiedAccountIds(verifiedAccounts_));
    } else {
        verifiedAccounts_.Erase(id);
    }
    if (isVerified && !preVerified) {
        OsAccountInterface::PublishCommonEvent(osAccountInfo,
            OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED, Constants::OPERATION_UNLOCK);
        subscribeManager_.Publish(id, OS_ACCOUNT_SUBSCRIBE_TYPE::UNLOCKED);
        ReportOsAccountLifeCycle(id, Constants::OPERATION_UNLOCK);

        CleanGarbageOsAccountsAsync();
    }

    return ERR_OK;
}

ErrCode IInnerOsAccountManager::SetOsAccountIsLoggedIn(const int32_t id, const bool isLoggedIn)
{
    std::lock_guard<std::mutex> lock(*GetOrInsertUpdateLock(id));
    OsAccountInfo osAccountInfo;
    ErrCode errCode = GetRealOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Get osaccount info error, errCode %{public}d.", errCode);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    if (osAccountInfo.GetToBeRemoved()) {
        ACCOUNT_LOGE("Account %{public}d will be removed, cannot change verify state!", id);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_TO_BE_REMOVED_ERROR;
    }
    if (isLoggedIn) {
        loggedInAccounts_.EnsureInsert(id, true);
    } else {
        loggedInAccounts_.Erase(id);
    }
    if (!osAccountInfo.GetIsLoggedIn()) {
#ifdef ACTIVATE_LAST_LOGGED_IN_ACCOUNT
        uint64_t displayId = osAccountInfo.GetDisplayId();
        if (displayId != Constants::INVALID_DISPLAY_ID) {
            std::lock_guard<std::mutex> operatingLock(operatingMutex_);
            osAccountControl_->SetDefaultActivatedOsAccount(displayId, id);
            defaultActivatedIds_.EnsureInsert(displayId, id);
        }
#endif // ACTIVATE_LAST_LOGGED_IN_ACCOUNT
        osAccountInfo.SetLastLoginTime(std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    }
    errCode = osAccountControl_->UpdateOsAccount(osAccountInfo);
    if (errCode != ERR_OK && errCode != ERR_ACCOUNT_COMMON_DATA_NO_SPACE) {
        ACCOUNT_LOGE("Update account info failed, errCode: %{public}d, id: %{public}d", errCode, id);
        return ERR_OSACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::GetOsAccountCredentialId(const int id, uint64_t &credentialId)
{
    credentialId = 0;
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode == ERR_OK) {
        credentialId = osAccountInfo.GetCredentialId();
    }
    return errCode;
}

ErrCode IInnerOsAccountManager::SetOsAccountCredentialId(const int id, uint64_t credentialId)
{
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }

    osAccountInfo.SetCredentialId(credentialId);
    errCode = osAccountControl_->UpdateOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Update osaccount info error %{public}d, id: %{public}d",
            errCode, osAccountInfo.GetLocalId());
        return ERR_OSACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::SetDefaultActivatedOsAccount(const int32_t id)
{
    return SetDefaultActivatedOsAccount(Constants::DEFAULT_DISPLAY_ID, id);
}

ErrCode IInnerOsAccountManager::SetDefaultActivatedOsAccount(const uint64_t displayId, const int32_t id)
{
    std::lock_guard<std::mutex> lock(operatingMutex_);
    int32_t activatedId;
    if (defaultActivatedIds_.Find(displayId, activatedId) && (activatedId == id)) {
        ACCOUNT_LOGW("No need to repeat set initial start id %{public}d", id);
        return ERR_OK;
    }
    if (displayId != Constants::DEFAULT_DISPLAY_ID) {
#ifdef ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS
        ErrCode errCode = ValidateDisplayId(displayId);
        if (errCode != ERR_OK) {
            ReportOsAccountOperationFail(id, "setDefaultActivated", errCode,
                "Failed to validate display ID for setting default activated account");
            return errCode;
        }
#else
        return ERR_ACCOUNT_COMMON_DISPLAY_ID_NOT_EXIST_ERROR;
#endif // ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS
    }
    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(id, osAccountInfo);
    if (errCode != ERR_OK) {
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }

    errCode = IsValidOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        return errCode;
    }
    errCode = osAccountControl_->SetDefaultActivatedOsAccount(displayId, id);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Set default activated account id error %{public}d, id: %{public}d", errCode, id);
        ReportOsAccountOperationFail(id, "setDefaultActivated", errCode,
            "Failed to set default activated account in storage");
        return errCode;
    }
    defaultActivatedIds_.EnsureInsert(displayId, id);
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::IsOsAccountForeground(const int32_t localId, const uint64_t displayId,
                                                      bool &isForeground)
{
    int32_t id;
    if (displayId == Constants::ANY_DISPLAY_ID) {
        isForeground = false;
        auto it = [&isForeground, localId](uint64_t dispId, int32_t userId) {
            if (userId == localId) {
                isForeground = true;
            }
        };
        foregroundAccountMap_.Iterate(it);
        return ERR_OK;
    }

    // Validate display ID exists
#ifdef ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS
    ErrCode errCode = ValidateDisplayId(displayId);
    if (errCode != ERR_OK) {
        return errCode;
    }
#else
    if (displayId != Constants::DEFAULT_DISPLAY_ID) {
        return ERR_ACCOUNT_COMMON_DISPLAY_ID_NOT_EXIST_ERROR;
    }
#endif // ENABLE_MULTI_FOREGROUND_OS_ACCOUNTS

    if (!foregroundAccountMap_.Find(displayId, id)) {
        return ERR_ACCOUNT_COMMON_ACCOUNT_IN_DISPLAY_ID_NOT_FOUND_ERROR;
    }
    isForeground = (id == localId);
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::GetForegroundOsAccountLocalId(const uint64_t displayId, int32_t &localId)
{
    if (!foregroundAccountMap_.Find(displayId, localId)) {
        return ERR_ACCOUNT_COMMON_ACCOUNT_IN_DISPLAY_ID_NOT_FOUND_ERROR;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::GetForegroundOsAccountDisplayId(const int32_t localId, uint64_t &displayId)
{
    displayId = Constants::INVALID_DISPLAY_ID;
    auto it = [&displayId, localId](uint64_t dispId, int32_t userId) {
        if (userId == localId) {
            displayId = dispId;
        }
    };
    foregroundAccountMap_.Iterate(it);
    if (displayId == Constants::INVALID_DISPLAY_ID) {
        return ERR_ACCOUNT_COMMON_ACCOUNT_IN_DISPLAY_ID_NOT_FOUND_ERROR;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::GetForegroundOsAccounts(std::vector<ForegroundOsAccount> &accounts)
{
    accounts.clear();
    auto it = [&](uint64_t displayId, int32_t localId) {
        ForegroundOsAccount foregroundOsAccount;
        foregroundOsAccount.displayId = displayId;
        foregroundOsAccount.localId = localId;
        accounts.emplace_back(foregroundOsAccount);
    };
    foregroundAccountMap_.Iterate(it);
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::GetBackgroundOsAccountLocalIds(std::vector<int32_t> &localIds)
{
    localIds.clear();
    std::vector<int32_t> activatedIds;
    CopyFromActiveList(activatedIds);

    std::vector<int32_t> foregroundIds;
    auto it = [&](uint64_t displayId, int32_t localId) {
        foregroundIds.emplace_back(localId);
    };
    foregroundAccountMap_.Iterate(it);
    std::unordered_set<int32_t> foregroundSet(foregroundIds.begin(), foregroundIds.end());
    for (const auto &id : activatedIds) {
        if (foregroundSet.find(id) == foregroundSet.end()) {
            localIds.emplace_back(id);
        }
    }
    ACCOUNT_LOGI("Get background list successful, total=%{public}zu.", localIds.size());
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::GetDefaultActivatedOsAccount(int32_t &id)
{
    return GetDefaultActivatedOsAccount(Constants::DEFAULT_DISPLAY_ID, id);
}

ErrCode IInnerOsAccountManager::GetDefaultActivatedOsAccount(const uint64_t displayId, int32_t &id)
{
    std::lock_guard<std::mutex> lock(operatingMutex_);
    if (!defaultActivatedIds_.Find(displayId, id)) {
        ACCOUNT_LOGE("Cannot find default activated account for display %{public}llu",
            static_cast<unsigned long long>(displayId));
        return ERR_ACCOUNT_COMMON_DISPLAY_ID_NOT_EXIST_ERROR;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::GetAllDefaultActivatedOsAccounts(std::map<uint64_t, int32_t> &activatedIds)
{
    std::lock_guard<std::mutex> lock(operatingMutex_);
    activatedIds.clear();
    auto it = [&activatedIds](uint64_t displayId, int32_t id) {
        activatedIds.emplace(displayId, id);
    };
    defaultActivatedIds_.Iterate(it);
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::IsAllowedCreateAdmin(bool &isAllowedCreateAdmin)
{
    return osAccountControl_->IsAllowedCreateAdmin(isAllowedCreateAdmin);
}

ErrCode IInnerOsAccountManager::GetCreatedOsAccountNumFromDatabase(const std::string& storeID,
    int &createdOsAccountNum)
{
    return osAccountControl_->GetCreatedOsAccountNumFromDatabase(storeID, createdOsAccountNum);
}

ErrCode IInnerOsAccountManager::GetSerialNumberFromDatabase(const std::string& storeID,
    int64_t &serialNumber)
{
    return osAccountControl_->GetSerialNumberFromDatabase(storeID, serialNumber);
}

ErrCode IInnerOsAccountManager::GetMaxAllowCreateIdFromDatabase(const std::string& storeID, int &id)
{
#ifdef ENABLE_MULTIPLE_OS_ACCOUNTS
    return osAccountControl_->GetMaxAllowCreateIdFromDatabase(storeID, id);
#else
    id = Constants::START_USER_ID;
    return ERR_OK;
#endif // ENABLE_MULTIPLE_OS_ACCOUNTS
}

ErrCode IInnerOsAccountManager::GetOsAccountFromDatabase(const std::string& storeID, const int id,
    OsAccountInfo &osAccountInfo)
{
    return osAccountControl_->GetOsAccountFromDatabase(storeID, id, osAccountInfo);
}

ErrCode IInnerOsAccountManager::GetOsAccountListFromDatabase(const std::string& storeID,
    std::vector<OsAccountInfo> &osAccountList)
{
    return osAccountControl_->GetOsAccountListFromDatabase(storeID, osAccountList);
}

void IInnerOsAccountManager::RemoveLocalIdToOperating(int32_t localId)
{
    std::lock_guard<std::mutex> lock(operatingMutex_);
    auto it = std::find(operatingId_.begin(), operatingId_.end(), localId);
    if (it != operatingId_.end()) {
        operatingId_.erase(it);
    }
}

bool IInnerOsAccountManager::CheckAndAddLocalIdOperating(int32_t localId)
{
    std::lock_guard<std::mutex> lock(operatingMutex_);
    if (std::find(operatingId_.begin(), operatingId_.end(), localId) != operatingId_.end()) {
        return false;
    }
    operatingId_.push_back(localId);
    return true;
}

#ifdef FUZZ_TEST
// LCOV_EXCL_START
#endif
ErrCode IInnerOsAccountManager::QueryActiveOsAccountIds(std::vector<int32_t>& ids)
{
    CopyFromActiveList(ids);
#ifdef ENABLE_U1_ACCOUNT
    if (ids.size() == 1 && ids[0] == Constants::U1_ID) {
        ids.clear();
    }
#endif // ENABLE_U1_ACCOUNT
    return ERR_OK;
}
#ifdef FUZZ_TEST
// LCOV_EXCL_STOP
#endif

ErrCode IInnerOsAccountManager::GetUnlockedOsAccountLocalIds(std::vector<int32_t>& ids)
{
    ids = GetVerifiedAccountIds(verifiedAccounts_);
    return ERR_OK;
}

void IInnerOsAccountManager::PushIdIntoActiveList(int32_t id)
{
    std::lock_guard<std::mutex> lock(ativeMutex_);
    if (std::find(activeAccountId_.begin(), activeAccountId_.end(), id) == activeAccountId_.end()) {
        CountTraceAdapter("activeId", (int64_t)id);
    }
#ifndef ENABLE_MULTIPLE_ACTIVE_ACCOUNTS
    activeAccountId_.clear();
#else
    activeAccountId_.erase(std::remove(activeAccountId_.begin(), activeAccountId_.end(), id), activeAccountId_.end());
#endif
    //Compatible with the QueryActiveOsAccountIds
    activeAccountId_.insert(activeAccountId_.begin(), id);
    return;
}

void IInnerOsAccountManager::EraseIdFromActiveList(int32_t id)
{
    std::lock_guard<std::mutex> lock(ativeMutex_);
    if (std::find(activeAccountId_.begin(), activeAccountId_.end(), id) != activeAccountId_.end()) {
        ACCOUNT_LOGE("EraseIdFromActiveList enter0");
        activeAccountId_.erase(
            std::remove(activeAccountId_.begin(), activeAccountId_.end(), id), activeAccountId_.end());
    } else {
        ACCOUNT_LOGI("Os account is not in active list, no need to erase!");
    }
    CountTraceAdapter("deActiveId", (int64_t)id);
}

bool IInnerOsAccountManager::IsOsAccountIDInActiveList(int32_t id)
{
    std::lock_guard<std::mutex> lock(ativeMutex_);
    auto it = std::find(activeAccountId_.begin(), activeAccountId_.end(), id);
    return (it != activeAccountId_.end());
}

void IInnerOsAccountManager::CopyFromActiveList(std::vector<int32_t>& idList)
{
    idList.clear();
    std::lock_guard<std::mutex> lock(ativeMutex_);
    for (auto it = activeAccountId_.begin(); it != activeAccountId_.end(); it++) {
        idList.push_back(*it);
    }
}

#ifdef SUPPORT_DOMAIN_ACCOUNTS
ErrCode IInnerOsAccountManager::UpdateAccountInfoByDomainAccountInfo(
    int32_t userId, const DomainAccountInfo &newDomainAccountInfo)
{
    if (!CheckAndAddLocalIdOperating(userId)) {
        ACCOUNT_LOGW("Account id = %{public}d already in operating", userId);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_OPERATING_ERROR;
    }
    OsAccountInfo accountInfo;
    ErrCode result = osAccountControl_->GetOsAccountInfoById(userId, accountInfo);
    if (result != ERR_OK) {
        RemoveLocalIdToOperating(userId);
        return result;
    }
    DomainAccountInfo oldDomainAccountInfo;
    accountInfo.GetDomainInfo(oldDomainAccountInfo);
    if (!newDomainAccountInfo.accountName_.empty()) {
        oldDomainAccountInfo.accountName_ = newDomainAccountInfo.accountName_;
    }
    if (!newDomainAccountInfo.accountId_.empty()) {
        oldDomainAccountInfo.accountId_ = newDomainAccountInfo.accountId_;
    }
    if (!newDomainAccountInfo.serverConfigId_.empty()) {
        oldDomainAccountInfo.serverConfigId_ = newDomainAccountInfo.serverConfigId_;
    }
    if (!newDomainAccountInfo.domain_.empty()) {
        oldDomainAccountInfo.domain_ = newDomainAccountInfo.domain_;
    }
    accountInfo.SetDomainInfo(oldDomainAccountInfo);
    result = osAccountControl_->UpdateOsAccount(accountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Update account info failed, result = %{public}d", result);
        ReportOsAccountOperationFail(userId, OPERATION_UPDATE, result,
            "Failed to update domain account info");
        RemoveLocalIdToOperating(userId);
        return result;
    }
    RemoveLocalIdToOperating(userId);
#ifdef HAS_CES_PART
    AccountEventProvider::EventPublish(EventFwk::CommonEventSupport::COMMON_EVENT_USER_INFO_UPDATED,
        userId, nullptr);
#endif // HAS_CES_PART
    return ERR_OK;
}
#endif // SUPPORT_DOMAIN_ACCOUNTS

ErrCode IInnerOsAccountManager::UpdateAccountToBackground(int32_t oldId)
{
    OsAccountInfo oldOsAccountInfo;
    {
        std::lock_guard<std::mutex> lock(*GetOrInsertUpdateLock(oldId));
        ErrCode errCode = osAccountControl_->GetOsAccountInfoById(oldId, oldOsAccountInfo);
        if (errCode != ERR_OK) {
            return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
        }
    }
    OsAccountInterface::PublishCommonEvent(oldOsAccountInfo,
        OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_BACKGROUND, Constants::OPERATION_SWITCH);
#ifdef ENABLE_MULTIPLE_ACTIVE_ACCOUNTS
#ifndef SUPPORT_STOP_MAIN_OS_ACCOUNT
    if (oldId == Constants::START_USER_ID) {
        return ERR_OK;
    }
#endif
    bool isLoggedIn = false;
    if ((oldOsAccountInfo.GetType() != OsAccountType::PRIVATE) && (!loggedInAccounts_.Find(oldId, isLoggedIn))) {
        std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_DEACTIVATE_OS_ACCOUNT));
        DeactivateOsAccount(oldId, false);
    }
#else
    DeactivateOsAccountByInfo(oldOsAccountInfo);
#endif // ENABLE_MULTIPLE_ACTIVE_ACCOUNTS
    return ERR_OK;
}

std::shared_ptr<std::mutex> IInnerOsAccountManager::GetOrInsertUpdateLock(int32_t id)
{
    std::lock_guard<std::mutex> lock(updateLockMutex_);
    auto it = updateLocks_.find(id);
    if (it == updateLocks_.end()) {
        auto mutexPtr = std::make_shared<std::mutex>();
        updateLocks_.insert(std::make_pair(id, mutexPtr));
        return mutexPtr;
    } else {
        return it->second;
    }
}

ErrCode IInnerOsAccountManager::SetOsAccountToBeRemoved(int32_t localId, bool toBeRemoved)
{
    if (!CheckAndAddLocalIdOperating(localId)) {
        ACCOUNT_LOGE("The account %{public}d already in operating", localId);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_OPERATING_ERROR;
    }

    OsAccountInfo osAccountInfo;
    ErrCode errCode = osAccountControl_->GetOsAccountInfoById(localId, osAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Get osaccount info error, errCode %{public}d.", errCode);
        ReportOsAccountOperationFail(localId, OPERATION_SET_TO_BE_REMOVED, errCode,
            "Get account info failed when set ToBeRemoved");
        RemoveLocalIdToOperating(localId);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }

    if (toBeRemoved) {
        errCode = ResetDefaultActivatedAccount(localId);
        if (errCode != ERR_OK) {
            RemoveLocalIdToOperating(localId);
            return errCode;
        }
    }

    osAccountInfo.SetToBeRemoved(toBeRemoved);
    errCode = osAccountControl_->UpdateOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        ReportOsAccountOperationFail(localId, OPERATION_SET_TO_BE_REMOVED, errCode,
            "Update ToBeRemoved flag failed");
        ACCOUNT_LOGE("Update ToBeRemoved flag failed, err=%{public}d", errCode);
    }

    RemoveLocalIdToOperating(localId);
    ReportOsAccountLifeCycle(localId, OPERATION_SET_TO_BE_REMOVED);
    return errCode;
}

ErrCode IInnerOsAccountManager::ResetDefaultActivatedAccount(int32_t localId)
{
    int32_t defaultActivatedId = -1;
    if (defaultActivatedIds_.Find(Constants::DEFAULT_DISPLAY_ID, defaultActivatedId) &&
        defaultActivatedId == localId) {
        ErrCode err = osAccountControl_->SetDefaultActivatedOsAccount(Constants::DEFAULT_DISPLAY_ID,
            Constants::START_USER_ID);
        if (err != ERR_OK) {
            ReportOsAccountOperationFail(localId, OPERATION_SET_TO_BE_REMOVED, err,
                "Persist defaultActivatedId to START_USER_ID failed for default display");
            ACCOUNT_LOGE("SetDefaultActivatedOsAccount persist failed for default display, err=%{public}d", err);
            return err;
        }
        defaultActivatedIds_.EnsureInsert(Constants::DEFAULT_DISPLAY_ID, Constants::START_USER_ID);
        ACCOUNT_LOGI("Successfully updated default activated account for default display");
    }
    
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::IsValidOsAccount(const OsAccountInfo &osAccountInfo)
{
    if (!osAccountInfo.GetIsCreateCompleted()) {
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_IS_UNCOMPLETED_ERROR;
    }

    if (osAccountInfo.GetToBeRemoved()) {
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_TO_BE_REMOVED_ERROR;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::GetOsAccountDomainInfo(const int32_t localId, DomainAccountInfo &domainInfo)
{
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    return InnerDomainAccountManager::GetInstance().GetDomainAccountInfoByUserId(localId, domainInfo);
#else
    OsAccountInfo accountInfo;
    ErrCode errCode = GetRealOsAccountInfoById(localId, accountInfo);
    if (errCode != ERR_OK) {
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    accountInfo.GetDomainInfo(domainInfo);
    if (domainInfo.accountName_.empty()) {
        return ERR_DOMAIN_ACCOUNT_SERVICE_NOT_DOMAIN_ACCOUNT;
    }
    return ERR_OK;
#endif // SUPPORT_DOMAIN_ACCOUNTS
}

ErrCode IInnerOsAccountManager::UpdateServerConfig(const std::string &configId,
    const DomainServerConfig &config)
{
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    std::vector<OsAccountInfo> osAccountInfos;
    ErrCode errCode = osAccountControl_->GetOsAccountList(osAccountInfos);
    if (errCode != ERR_OK) {
        REPORT_OS_ACCOUNT_FAIL(-1, Constants::OPERATION_UPDATE_SERVER_CONFIG,
            errCode, "Get osAcount list error");
        ACCOUNT_LOGE("GetOsAccountList error:%{public}d", errCode);
        return errCode;
    }
    errCode = ERR_OK;
    for (auto osAccountInfosPtr = osAccountInfos.begin(); osAccountInfosPtr != osAccountInfos.end();
         ++osAccountInfosPtr) {
        DomainAccountInfo curDomainInfo;
        osAccountInfosPtr->GetDomainInfo(curDomainInfo);
        if (curDomainInfo.IsSameServerConfigId(configId)) {
            curDomainInfo.SetServerConfigId(config.id_);
            curDomainInfo.SetDomain(config.domain_);
            osAccountInfosPtr->SetDomainInfo(curDomainInfo);
            ErrCode err = osAccountControl_->UpdateOsAccount(*osAccountInfosPtr);
            if (err != ERR_OK) {
                REPORT_OS_ACCOUNT_FAIL(osAccountInfosPtr->GetLocalId(), Constants::OPERATION_UPDATE_SERVER_CONFIG,
                    errCode, "Update serverConfig error.");
                ACCOUNT_LOGE("UpdateOsAccount localId:%{public}d error:%{public}d",
                    osAccountInfosPtr->GetLocalId(), errCode);
                errCode = err;
            }
        }
    }
    return errCode;
#else
    return ERR_OK;
#endif // SUPPORT_DOMAIN_ACCOUNTS
}

std::vector<int32_t> IInnerOsAccountManager::GetVerifiedAccountIds(const SafeMap<int32_t, bool> &verifiedAccounts)
{
    std::vector<int32_t> verifiedAccountIds;

    //find verified account id vector
    SafeMap<int32_t, bool>::SafeMapCallBack callback = [&](const int32_t key, bool& value) {
        if (value) {
            verifiedAccountIds.push_back(static_cast<int32_t>(key));
        }
    };

    (static_cast<SafeMap<int32_t, bool>>(verifiedAccounts)).Iterate(callback);
    return verifiedAccountIds;
}

#ifdef SUPPORT_LOCK_OS_ACCOUNT
ErrCode IInnerOsAccountManager::IsOsAccountLocking(const int id, bool &isLocking)
{
    isLocking = false;
    lockingAccounts_.Find(id, isLocking);
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::PublishOsAccountLockEvent(const int32_t localId, bool isLocking)
{
    if (isLocking) {
#ifdef HAS_CES_PART
        AccountEventProvider::EventPublishAsUser(
            EventFwk::CommonEventSupport::COMMON_EVENT_USER_LOCKING, localId);
#else  // HAS_CES_PART
        ACCOUNT_LOGI("No common event part! Publish nothing!");
#endif // HAS_CES_PART
        return subscribeManager_.Publish(localId, OS_ACCOUNT_SUBSCRIBE_TYPE::LOCKING);
    } else {
#ifdef HAS_CES_PART
        AccountEventProvider::EventPublishAsUser(
            EventFwk::CommonEventSupport::COMMON_EVENT_USER_LOCKED, localId);
#else  // HAS_CES_PART
        ACCOUNT_LOGI("No common event part! Publish nothing!");
#endif // HAS_CES_PART
        return subscribeManager_.Publish(localId, OS_ACCOUNT_SUBSCRIBE_TYPE::LOCKED);
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::LockOsAccount(const int32_t localId)
{
    if (!lockOsAccountPluginManager_.IsPluginAvailable()) {
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_PLUGIN_NOT_EXIST_ERROR;
    }

    if (!CheckAndAddLocalIdOperating(localId)) {
        ACCOUNT_LOGW("Account id = %{public}d already in operating", localId);
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_OPERATING_ERROR;
    }
    OsAccountInfo osAccountInfo;
    ErrCode errCode = GetRealOsAccountInfoById(localId, osAccountInfo);
    if (errCode != ERR_OK) {
        RemoveLocalIdToOperating(localId);
        ACCOUNT_LOGW("Cannot find os account info by id:%{public}d, errCode %{public}d.", localId, errCode);
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }

    errCode = IsValidOsAccount(osAccountInfo);
    if (errCode != ERR_OK) {
        RemoveLocalIdToOperating(localId);
        return errCode;
    }

    if (!osAccountInfo.GetIsVerified()) {
        RemoveLocalIdToOperating(localId);
        ACCOUNT_LOGW("Account %{public}d is neither active nor verified, don't need to lock!", localId);
        return ERR_OK;
    }

    lockingAccounts_.EnsureInsert(localId, true);

    int32_t ret = lockOsAccountPluginManager_.LockOsAccount(localId);
    if (ret != ERR_OK) {
        lockingAccounts_.Erase(localId);
        RemoveLocalIdToOperating(localId);
        ACCOUNT_LOGE("Failed to lock os account, ret is %{public}d", ret);
        ReportOsAccountOperationFail(localId, OPERATION_LOCK, ret, "Lock OsAccount failed!");
        return ERR_OSACCOUNT_SERVICE_INNER_ACCOUNT_LOCK_ERROR;
    }
    lockingAccounts_.Erase(localId);
    verifiedAccounts_.Erase(localId);

    RemoveLocalIdToOperating(localId);

    ReportOsAccountLifeCycle(localId, Constants::OPERATION_LOCKED);

    return ERR_OK;
}
#endif

OsAccountControlFileManager &IInnerOsAccountManager::GetFileController()
{
    return *std::reinterpret_pointer_cast<OsAccountControlFileManager>(osAccountControl_);
}
}  // namespace AccountSA
}  // namespace OHOS