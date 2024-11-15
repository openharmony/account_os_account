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

#include "account_mgr_service.h"
#include <cerrno>
#include "account_dump_helper.h"
#include "account_log_wrapper.h"
#ifdef HAS_APP_ACCOUNT_PART
#include "app_account_manager_service.h"
#endif
#include "datetime_ex.h"
#include "device_account_info.h"
#include "directory_ex.h"
#include "domain_account_manager_service.h"
#include "file_ex.h"
#include "account_hisysevent_adapter.h"
#include "hitrace_adapter.h"
#include "if_system_ability_manager.h"
#include "iinner_os_account_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "perf_stat.h"
#include "string_ex.h"
#include "system_ability_definition.h"
#include "account_info.h"
#ifdef HAS_USER_AUTH_PART
#include "account_iam_service.h"
#endif
#ifdef HICOLLIE_ENABLE
#include "account_timer.h"
#endif // HICOLLIE_ENABLE

namespace OHOS {
namespace AccountSA {
namespace {
#ifdef HICOLLIE_ENABLE
constexpr int32_t MAX_INIT_TIME = 120;
#endif // HICOLLIE_ENABLE
const bool REGISTER_RESULT =
    SystemAbility::MakeAndRegisterAbility(&DelayedRefSingleton<AccountMgrService>::GetInstance());
const std::string DEVICE_OWNER_DIR = "/data/service/el1/public/account/0/";
void CreateDeviceDir()
{
    if (!OHOS::FileExists(DEVICE_OWNER_DIR)) {
        ACCOUNT_LOGI("Device owner dir not exist, create!");
        if (!OHOS::ForceCreateDirectory(DEVICE_OWNER_DIR)) {
            ACCOUNT_LOGW("Create device owner dir failure! errno %{public}d.", errno);
            ReportOsAccountOperationFail(0, OPERATION_FORCE_CREATE_DIRECTORY, errno, DEVICE_OWNER_DIR);
        } else {
            if (!OHOS::ChangeModeDirectory(DEVICE_OWNER_DIR, S_IRWXU)) {
                ReportOsAccountOperationFail(0, OPERATION_CHANGE_MODE_DIRECTORY, errno, DEVICE_OWNER_DIR);
                ACCOUNT_LOGW("failed to create dir, path = %{public}s errno %{public}d.",
                    DEVICE_OWNER_DIR.c_str(), errno);
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
    ErrCode res = OhosAccountManager::GetInstance().OhosAccountStateChange(accountName, uid, eventStr);
    if (res != ERR_OK) {
        ACCOUNT_LOGE("Ohos account state change failed, res = %{public}d.", res);
    }

    return res;
}

ErrCode AccountMgrService::SetOhosAccountInfo(const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr)
{
    return ERR_OK;
}

ErrCode AccountMgrService::SetOhosAccountInfoByUserId(
    const int32_t userId, const OhosAccountInfo &ohosAccountInfo, const std::string &eventStr)
{
    ErrCode res = OhosAccountManager::GetInstance().OhosAccountStateChange(userId, ohosAccountInfo, eventStr);
    if (res != ERR_OK) {
        ACCOUNT_LOGE("Ohos account state change failed");
    }

    return res;
}

ErrCode AccountMgrService::QueryDistributedVirtualDeviceId(std::string &dvid)
{
    return OhosAccountManager::GetInstance().QueryDistributedVirtualDeviceId(dvid);
}

ErrCode AccountMgrService::QueryOhosAccountInfo(OhosAccountInfo &accountInfo)
{
    return QueryOhosAccountInfoByUserId(IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR, accountInfo);
}

ErrCode AccountMgrService::GetOhosAccountInfo(OhosAccountInfo &info)
{
    return GetOhosAccountInfoByUserId(IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR, info);
}

ErrCode AccountMgrService::GetOhosAccountInfoByUserId(int32_t userId, OhosAccountInfo &info)
{
    AccountInfo accountInfo;
    ErrCode ret = OhosAccountManager::GetInstance().GetAccountInfoByUserId(userId, accountInfo);
    if (ret != ERR_OK) {
        return ret;
    }
    info = accountInfo.ohosAccountInfo_;
    ACCOUNT_LOGI("Get login time %{public}s, status %{public}d.", std::to_string(accountInfo.bindTime_).c_str(),
                 info.status_);
    return ERR_OK;
}

ErrCode AccountMgrService::QueryOhosAccountInfoByUserId(std::int32_t userId, OhosAccountInfo &accountInfo)
{
    AccountInfo info;
    ErrCode ret = OhosAccountManager::GetInstance().GetAccountInfoByUserId(userId, info);
    if (ret != ERR_OK) {
        return ret;
    }
    accountInfo.name_ = info.ohosAccountInfo_.name_;
    accountInfo.uid_ = info.ohosAccountInfo_.uid_;
    accountInfo.status_ = info.ohosAccountInfo_.status_;
    return ERR_OK;
}

ErrCode AccountMgrService::QueryDeviceAccountId(std::int32_t &accountId)
{
    const std::int32_t uid = IPCSkeleton::GetCallingUid();
    accountId = uid / UID_TRANSFORM_DIVISOR;
    return ERR_OK;
}

ErrCode AccountMgrService::SubscribeDistributedAccountEvent(const DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type,
    const sptr<IRemoteObject> &eventListener)
{
    ErrCode res = AccountPermissionManager::CheckSystemApp(false);
    if (res != ERR_OK) {
        ACCOUNT_LOGE("Check systemApp failed.");
        return res;
    }
    return OhosAccountManager::GetInstance().SubscribeDistributedAccountEvent(type, eventListener);
}

ErrCode AccountMgrService::UnsubscribeDistributedAccountEvent(const DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE type,
    const sptr<IRemoteObject> &eventListener)
{
    ErrCode res = AccountPermissionManager::CheckSystemApp(false);
    if (res != ERR_OK) {
        ACCOUNT_LOGE("Check systemApp failed.");
        return res;
    }
    return OhosAccountManager::GetInstance().UnsubscribeDistributedAccountEvent(type, eventListener);
}

sptr<IRemoteObject> AccountMgrService::GetAppAccountService()
{
    return appAccountManagerService_;
}

sptr<IRemoteObject> AccountMgrService::GetOsAccountService()
{
    if (osAccountManagerService_ != nullptr) {
        return osAccountManagerService_->AsObject();
    }
    return nullptr;
}

sptr<IRemoteObject> AccountMgrService::GetAccountIAMService()
{
    return accountIAMService_;
}

sptr<IRemoteObject> AccountMgrService::GetDomainAccountService()
{
    return domainAccountMgrService_;
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

#ifdef HAS_APP_ACCOUNT_PART
void AccountMgrService::MoveAppAccountData()
{
    auto task = [] { AppAccountControlManager::GetInstance().MoveData(); };
    std::thread taskThread(task);
    pthread_setname_np(taskThread.native_handle(), "MoveData");
    taskThread.detach();
    ACCOUNT_LOGI("Move app account data to encrypted store");
}
#endif

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
#ifdef HAS_APP_ACCOUNT_PART
        case DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID: {
            MoveAppAccountData();
            return;
        }
#endif
        default:
            return;
    }

    if (!isStorageReady_) {
        return;
    }
    bool isAccountCompleted = false;
    ErrCode errCode =
        IInnerOsAccountManager::GetInstance().IsOsAccountCompleted(Constants::START_USER_ID, isAccountCompleted);
    if (errCode == ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR || (errCode == ERR_OK && !isAccountCompleted)) {
        if (!isBmsReady_) {
            return;
        }
        IInnerOsAccountManager::GetInstance().Init();
    }
    if (!isDefaultOsAccountActivated_ && isAmsReady_) {
        errCode = IInnerOsAccountManager::GetInstance().ActivateDefaultOsAccount();
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
    if ((!CreateOsAccountService()) || (!CreateAppAccountService()) || (!CreateIAMService()) ||
        (!CreateDomainService())) {
        appAccountManagerService_ = nullptr;
        osAccountManagerService_ = nullptr;
        accountIAMService_ = nullptr;
        domainAccountMgrService_ = nullptr;
        return false;
    }
    IInnerOsAccountManager::GetInstance().ResetAccountStatus();
    if (!OhosAccountManager::GetInstance().OnInitialize()) {
        ACCOUNT_LOGE("Ohos account manager initialize failed");
        ReportServiceStartFail(ERR_ACCOUNT_MGR_OHOS_MGR_INIT_ERROR, "OnInitialize failed!");
        return false;
    }
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
    domainAccountMgrService_ = new (std::nothrow) DomainAccountManagerService();
    if (domainAccountMgrService_ == nullptr) {
        ACCOUNT_LOGE("memory alloc for DomainAccountManagerService failed!");
        ReportServiceStartFail(ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR,
            "Insufficient memory to create domain account manager service");
        return false;
    }
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
}  // namespace AccountSA
}  // namespace OHOS