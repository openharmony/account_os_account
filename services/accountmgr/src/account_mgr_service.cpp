/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "account_mgr_service.h"
#include <cerrno>
#include <thread>
#include "accesstoken_kit.h"
#include "account_dump_helper.h"
#include "account_hisysevent_adapter.h"
#ifdef HAS_USER_AUTH_PART
#include "account_iam_service.h"
#endif
#include "account_info.h"
#include "account_log_wrapper.h"
#ifdef HICOLLIE_ENABLE
#include "account_timer.h"
#endif // HICOLLIE_ENABLE
#ifdef HAS_APP_ACCOUNT_PART
#ifdef HAS_CES_PART
#include "app_account_common_event_observer.h"
#endif // HAS_CES_PART
#include "app_account_manager_service.h"
#endif
#include "datetime_ex.h"
#include "directory_ex.h"
#include "domain_account_manager_service.h"
#include "file_ex.h"
#include "hitrace_adapter.h"
#include "if_system_ability_manager.h"
#include "iinner_os_account_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "perf_stat.h"
#include "string_ex.h"
#include "system_ability_definition.h"
#ifdef HICOLLIE_ENABLE
#include "xcollie/xcollie.h"
#endif // HICOLLIE_ENABLE

namespace OHOS {
namespace AccountSA {
namespace {
const char PERMISSION_MANAGE_USERS[] = "ohos.permission.MANAGE_LOCAL_ACCOUNTS";
const char PERMISSION_GET_LOCAL_ACCOUNTS[] = "ohos.permission.GET_LOCAL_ACCOUNTS";
const char PERMISSION_MANAGE_DISTRIBUTED_ACCOUNTS[] = "ohos.permission.MANAGE_DISTRIBUTED_ACCOUNTS";
const char PERMISSION_GET_DISTRIBUTED_ACCOUNTS[] = "ohos.permission.GET_DISTRIBUTED_ACCOUNTS";
const char PERMISSION_DISTRIBUTED_DATASYNC[] = "ohos.permission.DISTRIBUTED_DATASYNC";
const char INTERACT_ACROSS_LOCAL_ACCOUNTS[] = "ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS";
const std::set<std::int32_t> WHITE_LIST = {
    3012, // DISTRIBUTED_KV_DATA_SA_UID
    3019, // DLP_UID
    3553, // DLP_CREDENTIAL_SA_UID
};
#ifdef USE_MUSL
constexpr std::int32_t DSOFTBUS_UID = 1024;
#else
constexpr std::int32_t DSOFTBUS_UID = 5533;
#endif
#ifndef IS_RELEASE_VERSION
constexpr std::int32_t ROOT_UID = 0;
#endif
#ifdef HICOLLIE_ENABLE
constexpr std::int32_t RECOVERY_TIMEOUT = 6; // timeout 6s
constexpr int32_t MAX_INIT_TIME = 120;
thread_local int32_t g_timerId = 0;
#endif // HICOLLIE_ENABLE
const std::set<int32_t> INIT_ACCOUNT_ID_SET = {
#ifdef ENABLE_U1_ACCOUNT
    Constants::U1_ID,
#endif // ENABLE_U1_ACCOUNT
    Constants::START_USER_ID,
};
const bool REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(&DelayedRefSingleton<AccountMgrService>::GetInstance());
const char DEVICE_OWNER_DIR[] = "/data/service/el1/public/account/0/";
void CreateDeviceDir()
{
    if (!OHOS::FileExists(DEVICE_OWNER_DIR)) {
        ACCOUNT_LOGI("Device owner dir not exist, create!");
        if (!OHOS::ForceCreateDirectory(DEVICE_OWNER_DIR)) {
            int32_t err = errno;
            ACCOUNT_LOGW("Create device owner dir failure! errno %{public}d.", err);
            ReportOsAccountOperationFail(0, OPERATION_FORCE_CREATE_DIRECTORY, err, DEVICE_OWNER_DIR);
        } else {
            if (!OHOS::ChangeModeDirectory(DEVICE_OWNER_DIR, S_IRWXU)) {
                int32_t err = errno;
                ReportOsAccountOperationFail(0, OPERATION_CHANGE_MODE_DIRECTORY, err, DEVICE_OWNER_DIR);
                ACCOUNT_LOGW("failed to create dir, path = %{public}s errno %{public}d.",
                    DEVICE_OWNER_DIR, err);
            }
        }
    }
}
}
IAccountContext *IAccountContext::instance_ = nullptr;

AccountMgrService::AccountMgrService() : SystemAbility(SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN, true)
{
    PerfStat::GetInstance().SetInstanceCreateTime(GetTickCount());
}

AccountMgrService::~AccountMgrService()
{}

std::int32_t AccountMgrService::GetCallingUserID()
{
    std::int32_t userId = IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR;
    if (userId <= 0) {
        std::vector<int32_t> userIds;
        (void)IInnerOsAccountManager::GetInstance().QueryActiveOsAccountIds(userIds);
        if (userIds.empty()) {
            return -1;  // invalid user id
        }
        userId = userIds[0];
    }
    return userId;
}

ErrCode AccountMgrService::UpdateOhosAccountInfo(
    const std::string &accountName, const std::string &uid, const std::string &eventStr)
{
    if (!HasAccountRequestPermission(PERMISSION_MANAGE_USERS)) {
        ACCOUNT_LOGE("Check permission failed");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    if (accountName.empty()) {
        ACCOUNT_LOGE("empty account name!");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    if (uid.empty()) {
        ACCOUNT_LOGE("empty uid!");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }

    ErrCode res = OhosAccountManager::GetInstance().OhosAccountStateChange(accountName, uid, eventStr);
    if (res != ERR_OK) {
        ACCOUNT_LOGE("Ohos account state change failed, res = %{public}d.", res);
    }

    return res;
}

ErrCode AccountMgrService::SetOhosAccountInfo(const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr)
{
    if (!HasAccountRequestPermission(PERMISSION_MANAGE_DISTRIBUTED_ACCOUNTS)) {
        ACCOUNT_LOGE("Check permission failed");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    if (!ohosAccountInfo.IsValid()) {
        ACCOUNT_LOGE("Check OhosAccountInfo failed");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    auto userId = AccountMgrService::GetInstance().GetCallingUserID();
    ErrCode res = OhosAccountManager::GetInstance().OhosAccountStateChange(userId, ohosAccountInfo, eventStr);
    if (res != ERR_OK) {
        ACCOUNT_LOGE("Ohos account state change failed");
    }

    return res;
}

ErrCode AccountMgrService::SetOsAccountDistributedInfo(
    const int32_t localId, const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr)
{
    std::int32_t ret = AccountPermissionManager::CheckSystemApp();
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("the caller is not system application, ret = %{public}d.", ret);
        return ret;
    }
    if (!HasAccountRequestPermission(PERMISSION_MANAGE_DISTRIBUTED_ACCOUNTS)) {
        ACCOUNT_LOGE("Check permission failed");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    if (!ohosAccountInfo.IsValid()) {
        ACCOUNT_LOGE("Check OhosAccountInfo failed");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    ret = CheckUserIdValid(localId);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("CheckUserIdValid failed, ret = %{public}d", ret);
        return ret;
    }
    ret = OhosAccountManager::GetInstance().OhosAccountStateChange(localId, ohosAccountInfo, eventStr);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Ohos account state change failed");
    }

    return ret;
}

ErrCode AccountMgrService::QueryDistributedVirtualDeviceId(std::string &dvid)
{
    if (!HasAccountRequestPermission(PERMISSION_MANAGE_USERS) &&
        !HasAccountRequestPermission(PERMISSION_DISTRIBUTED_DATASYNC)) {
        ACCOUNT_LOGE("Check permission failed");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    return OhosAccountManager::GetInstance().QueryDistributedVirtualDeviceId(dvid);
}

ErrCode AccountMgrService::QueryDistributedVirtualDeviceId(const std::string &bundleName, int32_t localId,
    std::string &dvid)
{
    ErrCode errCode = AccountPermissionManager::CheckSystemApp();
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("The caller is not system application, errCode = %{public}d.", errCode);
        return errCode;
    }
    if (!HasAccountRequestPermission(PERMISSION_MANAGE_DISTRIBUTED_ACCOUNTS) &&
        !HasAccountRequestPermission(PERMISSION_MANAGE_USERS) &&
        !HasAccountRequestPermission(PERMISSION_GET_DISTRIBUTED_ACCOUNTS)) {
        ACCOUNT_LOGE("Failed to check permission");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    return OhosAccountManager::GetInstance().QueryDistributedVirtualDeviceId(bundleName, localId, dvid);
}

ErrCode AccountMgrService::QueryOhosAccountInfo(std::string& accountName, std::string& uid, int32_t& status)
{
#ifdef HICOLLIE_ENABLE
    unsigned int flag = HiviewDFX::XCOLLIE_FLAG_LOG | HiviewDFX::XCOLLIE_FLAG_RECOVERY;
    XCollieCallback callbackFunc = [callingPid = IPCSkeleton::GetCallingPid(),
                                    callingUid = IPCSkeleton::GetCallingUid()](void*) {
        ACCOUNT_LOGE("InnerQueryOhosAccountInfo failed, callingPid: %{public}d, callingUid: %{public}d.", callingPid,
            callingUid);
        ReportOhosAccountOperationFail(callingUid, "watchDog", -1, "Query ohos account info time out");
    };
    int timerId = HiviewDFX::XCollie::GetInstance().SetTimer(TIMER_NAME, RECOVERY_TIMEOUT, callbackFunc, nullptr, flag);
#endif // HICOLLIE_ENABLE
    if (!HasAccountRequestPermission(PERMISSION_MANAGE_USERS) &&
        !HasAccountRequestPermission(PERMISSION_DISTRIBUTED_DATASYNC) &&
        !HasAccountRequestPermission(PERMISSION_GET_LOCAL_ACCOUNTS)) {
        ACCOUNT_LOGE("Check permission failed");
        REPORT_PERMISSION_FAIL();
#ifdef HICOLLIE_ENABLE
        HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
#endif // HICOLLIE_ENABLE
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    auto ret = QueryOsAccountDistributedInfo(GetCallingUserID(), accountName, uid, status);
#ifdef HICOLLIE_ENABLE
    HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
#endif // HICOLLIE_ENABLE
    return ret;
}

ErrCode AccountMgrService::GetOhosAccountInfo(OhosAccountInfo &info)
{
    if (!HasAccountRequestPermission(PERMISSION_MANAGE_DISTRIBUTED_ACCOUNTS) &&
        !HasAccountRequestPermission(PERMISSION_DISTRIBUTED_DATASYNC) &&
        !HasAccountRequestPermission(PERMISSION_GET_DISTRIBUTED_ACCOUNTS)) {
        ACCOUNT_LOGE("Check permission failed");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    auto ret = GetOsAccountDistributedInfoInner(GetCallingUserID(), info);
    info.SetRawUid("");
    return ret;
}

ErrCode AccountMgrService::GetOsAccountDistributedInfo(int32_t localId, OhosAccountInfo &info)
{
    ErrCode errCode = AccountPermissionManager::CheckSystemApp();
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("the caller is not system application, errCode = %{public}d.", errCode);
        return errCode;
    }
    if (!HasAccountRequestPermission(PERMISSION_MANAGE_DISTRIBUTED_ACCOUNTS) &&
        !(HasAccountRequestPermission(INTERACT_ACROSS_LOCAL_ACCOUNTS) &&
        HasAccountRequestPermission(PERMISSION_GET_DISTRIBUTED_ACCOUNTS))) {
        ACCOUNT_LOGE("Check permission failed");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    bool isOsAccountExits = false;
    errCode = IInnerOsAccountManager::GetInstance().IsOsAccountExists(localId, isOsAccountExits);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("IsOsAccountExists failed errCode is %{public}d", errCode);
        return errCode;
    }
    if (!isOsAccountExits) {
        ACCOUNT_LOGE("os account is not exit");
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    errCode = GetOsAccountDistributedInfoInner(localId, info);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Get ohos account info failed");
        return errCode;
    }
    int32_t uid = IPCSkeleton::GetCallingUid();
    if (WHITE_LIST.find(uid) == WHITE_LIST.end()) {
        info.SetRawUid("");
    }
    return ERR_OK;
}

ErrCode AccountMgrService::GetOsAccountDistributedInfoInner(int32_t localId, OhosAccountInfo &info)
{
    ErrCode ret = OhosAccountManager::GetInstance().GetOhosAccountDistributedInfo(localId, info);
    if (ret != ERR_OK) {
        return ret;
    }
    return ERR_OK;
}

ErrCode AccountMgrService::QueryOsAccountDistributedInfo(
    std::int32_t localId, std::string& accountName, std::string& uid, int32_t& status)
{
    if ((!HasAccountRequestPermission(PERMISSION_MANAGE_USERS)) &&
        (!HasAccountRequestPermission(PERMISSION_DISTRIBUTED_DATASYNC)) &&
        (IPCSkeleton::GetCallingUid() != DSOFTBUS_UID)) {
        ACCOUNT_LOGE("Check permission failed");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    if (localId < 0) {
        ACCOUNT_LOGE("negative userID %{public}d detected!", localId);
        return ERR_ACCOUNT_ZIDL_ACCOUNT_STUB_USERID_ERROR;
    }
    OhosAccountInfo ohosAccountInfo;
    ErrCode ret = OhosAccountManager::GetInstance().GetOhosAccountDistributedInfo(localId, ohosAccountInfo);
    if (ret != ERR_OK) {
        return ret;
    }
    accountName = ohosAccountInfo.name_;
    uid = ohosAccountInfo.uid_;
    status = ohosAccountInfo.status_;
    return ERR_OK;
}

ErrCode AccountMgrService::QueryDeviceAccountId(std::int32_t &accountId)
{
    const std::int32_t uid = IPCSkeleton::GetCallingUid();
    accountId = uid / UID_TRANSFORM_DIVISOR;
    return ERR_OK;
}

ErrCode AccountMgrService::SubscribeDistributedAccountEvent(int32_t typeInt, const sptr<IRemoteObject>& eventListener)
{
    if (eventListener == nullptr) {
        ACCOUNT_LOGE("eventListener is nullptr.");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    ErrCode res = AccountPermissionManager::CheckSystemApp(false);
    if (res != ERR_OK) {
        ACCOUNT_LOGE("Check systemApp failed.");
        return res;
    }
    auto type = static_cast<DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE>(typeInt);
    return OhosAccountManager::GetInstance().SubscribeDistributedAccountEvent(type, eventListener);
}

ErrCode AccountMgrService::UnsubscribeDistributedAccountEvent(int32_t typeInt, const sptr<IRemoteObject>& eventListener)
{
    if (eventListener == nullptr) {
        ACCOUNT_LOGE("eventListener is nullptr.");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    ErrCode res = AccountPermissionManager::CheckSystemApp(false);
    if (res != ERR_OK) {
        ACCOUNT_LOGE("Check systemApp failed.");
        return res;
    }
    auto type = static_cast<DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE>(typeInt);
    return OhosAccountManager::GetInstance().UnsubscribeDistributedAccountEvent(type, eventListener);
}

ErrCode AccountMgrService::GetAppAccountService(sptr<IRemoteObject>& funcResult)
{
#ifdef HAS_APP_ACCOUNT_PART
    std::lock_guard<std::mutex> lock(serviceMutex_);
    funcResult = appAccountManagerService_.promote();
    if (funcResult == nullptr) {
        funcResult = new (std::nothrow) AppAccountManagerService();
        appAccountManagerService_ = funcResult;
    }
    return ERR_OK;
#else
    funcResult = nullptr;
    return ERR_OK;
#endif
}

ErrCode AccountMgrService::GetOsAccountService(sptr<IRemoteObject>& funcResult)
{
    std::lock_guard<std::mutex> lock(serviceMutex_);
    funcResult = osAccountManagerService_.promote();
    if (funcResult == nullptr) {
        funcResult = new (std::nothrow) OsAccountManagerService();
        osAccountManagerService_ = funcResult;
    }
    return ERR_OK;
}

ErrCode AccountMgrService::GetAccountIAMService(sptr<IRemoteObject>& funcResult)
{
#ifdef HAS_USER_AUTH_PART
    std::lock_guard<std::mutex> lock(serviceMutex_);
    funcResult = accountIAMService_.promote();
    if (funcResult == nullptr) {
        funcResult = new (std::nothrow) AccountIAMService();
        accountIAMService_ = funcResult;
    }
    return ERR_OK;
#else
    funcResult = nullptr;
    return ERR_OK;
#endif // HAS_USER_AUTH_PART
}

ErrCode AccountMgrService::GetDomainAccountService(sptr<IRemoteObject>& funcResult)
{
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    std::lock_guard<std::mutex> lock(serviceMutex_);
    funcResult = domainAccountMgrService_.promote();
    if (funcResult == nullptr) {
        funcResult = new (std::nothrow) DomainAccountManagerService();
        domainAccountMgrService_ = funcResult;
    }
    return ERR_OK;
#else
    funcResult = nullptr;
    return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT;
#endif // SUPPORT_DOMAIN_ACCOUNTS
}

bool AccountMgrService::IsServiceStarted(void) const
{
    return (state_ == STATE_RUNNING);
}

void AccountMgrService::OnStart()
{
    if (state_ == ServiceRunningState::STATE_RUNNING) {
        ACCOUNT_LOGI("AccountMgrService has already started.");
        return;
    }
    UpdateTraceLabelAdapter();
    StartTraceAdapter("accountmgr service onstart");
    CountTraceAdapter("activeid", -1);

    PerfStat::GetInstance().SetInstanceStartTime(GetTickCount());
    ACCOUNT_LOGI("start is triggered");
    ReportOsAccountLifeCycle(Constants::INVALID_OS_ACCOUNT_ID, "AccountMgr service onstart finished.");
    if (!Init()) {
        ACCOUNT_LOGE("failed to init AccountMgrService");
        FinishTraceAdapter();
        return;
    }
    AddSystemAbilityListener(STORAGE_MANAGER_MANAGER_ID);
    AddSystemAbilityListener(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    AddSystemAbilityListener(ABILITY_MGR_SERVICE_ID);
#ifdef HAS_APP_ACCOUNT_PART
    AddSystemAbilityListener(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID);
#endif
    ACCOUNT_LOGI("AccountMgrService::OnStart start service finished.");
    FinishTraceAdapter();
}

void AccountMgrService::OnStop()
{
    PerfStat::GetInstance().SetInstanceStopTime(GetTickCount());
    ACCOUNT_LOGI("onstop is called");
    IAccountContext::SetInstance(nullptr);
    SelfClean();
}

#if defined(HAS_APP_ACCOUNT_PART) && defined(ENABLE_MULTIPLE_OS_ACCOUNTS)
void AccountMgrService::MoveAppAccountData()
{
    auto task = [] { AppAccountControlManager::GetInstance().MoveData(); };
    std::thread taskThread(task);
    pthread_setname_np(taskThread.native_handle(), "MoveData");
    taskThread.detach();
    ACCOUNT_LOGI("Move app account data to encrypted store");
}
#endif // defined(HAS_APP_ACCOUNT_PART) && defined(ENABLE_MULTIPLE_OS_ACCOUNTS)

bool AccountMgrService::IsDefaultOsAccountVerified()
{
    int32_t defaultAccountId = -1;
    ErrCode errCode = IInnerOsAccountManager::GetInstance().GetDefaultActivatedOsAccount(defaultAccountId);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed to get default activated OS account, errCode: %{public}d", errCode);
        return false;
    }

    bool isVerified = false;
    errCode = IInnerOsAccountManager::GetInstance().IsOsAccountVerified(defaultAccountId, isVerified);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Failed get default activated OS account verified info, errCode: %{public}d", errCode);
        return false;
    }
    return isVerified;
}

void AccountMgrService::GetUncreatedInitAccounts(std::set<int32_t> &initAccounts)
{
    ErrCode errCode = ERR_OK;
    for (int32_t id : INIT_ACCOUNT_ID_SET) {
        bool isAccountCompleted = false;
        errCode = IInnerOsAccountManager::GetInstance().IsOsAccountCompleted(id, isAccountCompleted);
        if (errCode == ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR || (errCode == ERR_OK && !isAccountCompleted)) {
            initAccounts.emplace(id);
        }
    }
}

void AccountMgrService::OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    std::lock_guard<std::mutex> lock(statusMutex_);
    ACCOUNT_LOGI("OnAddSystemAbility systemAbilityId %{public}d", systemAbilityId);
    switch (systemAbilityId) {
        case STORAGE_MANAGER_MANAGER_ID: {
            isStorageReady_ = true;
            break;
        }
        case ABILITY_MGR_SERVICE_ID: {
            isAmsReady_ = true;
            break;
        }
        case BUNDLE_MGR_SERVICE_SYS_ABILITY_ID: {
            isBmsReady_ = true;
            break;
        }
#if defined(HAS_APP_ACCOUNT_PART) && defined(ENABLE_MULTIPLE_OS_ACCOUNTS)
        case DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID: {
            MoveAppAccountData();
            return;
        }
#endif // defined(HAS_APP_ACCOUNT_PART) && defined(ENABLE_MULTIPLE_OS_ACCOUNTS)
        default:
            return;
    }
    if (!isStorageReady_) {
        return;
    }

    std::set<int32_t> initAccounts;
    GetUncreatedInitAccounts(initAccounts);
    if (!initAccounts.empty()) {
        if (!isBmsReady_) {
            return;
        }
        bool result = IInnerOsAccountManager::GetInstance().Init(initAccounts);
        if (!result) {
            return;
        }
    }

    if (!isDefaultOsAccountActivated_ && isAmsReady_) {
        ErrCode errCode = IInnerOsAccountManager::GetInstance().ActivateDefaultOsAccount();
        if (errCode == ERR_OK) {
            isDefaultOsAccountActivated_ = true;
        }
    }
    if (isBmsReady_ && IsDefaultOsAccountVerified()) {
        IInnerOsAccountManager::GetInstance().CleanGarbageOsAccountsAsync();
    }
}

bool AccountMgrService::Init()
{
    if (state_ == ServiceRunningState::STATE_RUNNING) {
        ACCOUNT_LOGW("Service is already running!");
        return false;
    }
#ifdef HICOLLIE_ENABLE
    AccountTimer timer(false);
    timer.Init(MAX_INIT_TIME);
#endif // HICOLLIE_ENABLE
    CreateDeviceDir();
    IAccountContext::SetInstance(this);
    if (!OhosAccountManager::GetInstance().OnInitialize()) {
        ACCOUNT_LOGE("Ohos account manager initialize failed");
        ReportServiceStartFail(ERR_ACCOUNT_MGR_OHOS_MGR_INIT_ERROR,
            "OhosAccountManager::OnInitialize failed, do not block sa startup!");
    }
#if defined(HAS_APP_ACCOUNT_PART) && defined(HAS_CES_PART)
    AppAccountCommonEventObserver::GetInstance();
#endif // defined(HAS_APP_ACCOUNT_PART) && defined(HAS_CES_PART)
    state_ = ServiceRunningState::STATE_RUNNING;
    if (!registerToService_) {
        if (!Publish(&DelayedRefSingleton<AccountMgrService>::GetInstance())) {
            ACCOUNT_LOGE("AccountMgrService::Init Publish failed!");
            ReportServiceStartFail(ERR_ACCOUNT_MGR_ADD_TO_SA_ERROR, "Publish service failed!");
            return false;
        }
        registerToService_ = true;
    }
    PerfStat::GetInstance().SetInstanceInitTime(GetTickCount());

    dumpHelper_ = std::make_unique<AccountDumpHelper>(osAccountManagerService_.GetRefPtr());
    ACCOUNT_LOGI("init end success");
    return true;
}

bool AccountMgrService::CreateOsAccountService()
{
    osAccountManagerService_ = new (std::nothrow) OsAccountManagerService();
    if (osAccountManagerService_ == nullptr) {
        ACCOUNT_LOGE("memory alloc failed for osAccountManagerService_!");
        ReportServiceStartFail(ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR,
            "Insufficient memory to create os account manager service");
        return false;
    }
    return true;
}

bool AccountMgrService::CreateAppAccountService()
{
#ifdef HAS_APP_ACCOUNT_PART
    appAccountManagerService_ = new (std::nothrow) AppAccountManagerService();
    if (appAccountManagerService_ == nullptr) {
        ACCOUNT_LOGE("memory alloc failed for appAccountManagerService!");
        ReportServiceStartFail(ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR,
            "Insufficient memory to create app account manager service");
        return false;
    }
#endif
    return true;
}

bool AccountMgrService::CreateIAMService()
{
#ifdef HAS_USER_AUTH_PART
    accountIAMService_ = new (std::nothrow) AccountIAMService();
    if (accountIAMService_ == nullptr) {
        ACCOUNT_LOGE("memory alloc for AccountIAMService failed!");
        ReportServiceStartFail(ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR,
            "Insufficient memory to create account iam service");
        return false;
    }
#endif
    return true;
}

bool AccountMgrService::CreateDomainService()
{
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    domainAccountMgrService_ = new (std::nothrow) DomainAccountManagerService();
    if (domainAccountMgrService_ == nullptr) {
        ACCOUNT_LOGE("memory alloc for DomainAccountManagerService failed!");
        ReportServiceStartFail(ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR,
            "Insufficient memory to create domain account manager service");
        return false;
    }
#endif // SUPPORT_DOMAIN_ACCOUNTS
    return true;
}

ErrCode AccountMgrService::Dump(std::int32_t fd, const std::vector<std::u16string> &args)
{
    if (fd < 0) {
        ACCOUNT_LOGE("dump fd invalid");
        return ERR_ACCOUNT_MGR_DUMP_ERROR;
    }

    if (dumpHelper_ == nullptr) {
        ACCOUNT_LOGE("dumpHelper_ is nullptr!");
        return ERR_ACCOUNT_MGR_DUMP_ERROR;
    }

    std::vector<std::string> argsInStr;
    std::transform(args.begin(), args.end(), std::back_inserter(argsInStr),
        [](const auto &arg) { return Str16ToStr8(arg); });

    std::string result;
    dumpHelper_->Dump(argsInStr, result);
    std::int32_t ret = dprintf(fd, "%s", result.c_str());
    if (ret < 0) {
        ACCOUNT_LOGE("dprintf to dump fd failed");
        return ERR_ACCOUNT_MGR_DUMP_ERROR;
    }
    return ERR_OK;
}

void AccountMgrService::SelfClean()
{
    state_ = ServiceRunningState::STATE_NOT_START;
    registerToService_ = false;
    ACCOUNT_LOGI("self-clean finished");
}

void AccountMgrService::HandleNotificationEvents(const std::string &eventStr)
{
    if (state_ == ServiceRunningState::STATE_NOT_START) {
        ACCOUNT_LOGW("service not running for handling event: %{public}s", eventStr.c_str());
        return;
    }
}

bool AccountMgrService::HasAccountRequestPermission(const std::string &permissionName)
{
#ifndef IS_RELEASE_VERSION
    std::int32_t uid = IPCSkeleton::GetCallingUid();
    // root check in none release version for test
    if (uid == ROOT_UID) {
        return true;
    }
#endif

    // check permission
    Security::AccessToken::AccessTokenID callingTokenID = IPCSkeleton::GetCallingTokenID();
    if (Security::AccessToken::AccessTokenKit::VerifyAccessToken(callingTokenID, permissionName) ==
        Security::AccessToken::TypePermissionState::PERMISSION_GRANTED) {
        return true;
    }

    return false;
}

int32_t AccountMgrService::CallbackEnter([[maybe_unused]] uint32_t code)
{
    ACCOUNT_LOGD("Received stub message: %{public}d, callingUid: %{public}d", code, IPCSkeleton::GetCallingUid());
    if (!IsServiceStarted()) {
        ACCOUNT_LOGE("account mgr not ready");
        return ERR_ACCOUNT_ZIDL_MGR_NOT_READY_ERROR;
    }
#ifdef HICOLLIE_ENABLE
    g_timerId =
        HiviewDFX::XCollie::GetInstance().SetTimer(TIMER_NAME, TIMEOUT, nullptr, nullptr, HiviewDFX::XCOLLIE_FLAG_LOG);
#endif // HICOLLIE_ENABLE
    return ERR_OK;
}

int32_t AccountMgrService::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
#ifdef HICOLLIE_ENABLE
    HiviewDFX::XCollie::GetInstance().CancelTimer(g_timerId);
#endif // HICOLLIE_ENABLE
    return ERR_OK;
}

int32_t AccountMgrService::CheckUserIdValid(int32_t userId)
{
    if ((userId >= 0) && (userId < Constants::START_USER_ID)) {
        ACCOUNT_LOGE("userId %{public}d is system reserved", userId);
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    bool isOsAccountExist = false;
    IInnerOsAccountManager::GetInstance().IsOsAccountExists(userId, isOsAccountExist);
    if (!isOsAccountExist) {
        ACCOUNT_LOGE("os account is not exist");
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS