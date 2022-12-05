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

#include "account_mgr_service.h"
#include <cerrno>
#include "account_dump_helper.h"
#include "account_log_wrapper.h"
#include "app_account_manager_service.h"
#include "datetime_ex.h"
#include "device_account_info.h"
#include "directory_ex.h"
#include "file_ex.h"
#include "hisysevent_adapter.h"
#include "hitrace_meter.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "perf_stat.h"
#include "string_ex.h"
#include "system_ability_definition.h"
#include "account_info.h"

namespace OHOS {
namespace AccountSA {
namespace {
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

bool AccountMgrService::UpdateOhosAccountInfo(
    const std::string &accountName, const std::string &uid, const std::string &eventStr)
{
    if (!ohosAccountMgr_->OhosAccountStateChange(accountName, uid, eventStr)) {
        ACCOUNT_LOGE("Ohos account state change failed");
        return false;
    }

    return true;
}

std::int32_t AccountMgrService::SetOhosAccountInfo(const OhosAccountInfo &ohosAccountInfo,
    const std::string &eventStr)
{
    if (!ohosAccountMgr_->OhosAccountStateChange(ohosAccountInfo, eventStr)) {
        ACCOUNT_LOGE("Ohos account state change failed");
        return ERR_ACCOUNT_ZIDL_ACCOUNT_SERVICE_ERROR;
    }

    return ERR_OK;
}

std::pair<bool, OhosAccountInfo> AccountMgrService::QueryOhosAccountInfo(void)
{
    return QueryOhosAccountInfoByUserId(IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR);
}

ErrCode AccountMgrService::GetOhosAccountInfo(OhosAccountInfo &info)
{
    return GetOhosAccountInfoByUserId(IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR, info);
}

ErrCode AccountMgrService::GetOhosAccountInfoByUserId(int32_t userId, OhosAccountInfo &info)
{
    AccountInfo accountInfo;
    ErrCode ret = ohosAccountMgr_->GetAccountInfoByUserId(userId, accountInfo);
    if (ret != ERR_OK) {
        return ret;
    }
    info = accountInfo.ohosAccountInfo_;
    return ERR_OK;
}

std::pair<bool, OhosAccountInfo> AccountMgrService::QueryOhosAccountInfoByUserId(std::int32_t userId)
{
    AccountInfo accountInfo;
    ErrCode ret = ohosAccountMgr_->GetAccountInfoByUserId(userId, accountInfo);
    bool flag = true;
    if (ret != ERR_OK) {
        flag = false;
    }
    return std::make_pair(flag, OhosAccountInfo(
        accountInfo.ohosAccountInfo_.name_, accountInfo.ohosAccountInfo_.uid_, accountInfo.ohosAccountInfo_.status_));
}

std::int32_t AccountMgrService::QueryDeviceAccountId(std::int32_t &accountId)
{
    const std::int32_t uid = IPCSkeleton::GetCallingUid();
    accountId = uid / UID_TRANSFORM_DIVISOR;
    return ERR_OK;
}

sptr<IRemoteObject> AccountMgrService::GetAppAccountService()
{
    if (appAccountManagerService_ != nullptr) {
        return appAccountManagerService_->AsObject();
    }
    return nullptr;
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
#ifdef HAS_USER_AUTH_PART
    if (accountIAMService_ != nullptr) {
        return accountIAMService_->AsObject();
    }
#endif
    return nullptr;
}

sptr<IRemoteObject> AccountMgrService::GetDomainAccountService()
{
    if (domainAccountMgrService_ != nullptr) {
        return domainAccountMgrService_->AsObject();
    }
    return nullptr;
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

    UpdateTraceLabel();
    StartTrace(HITRACE_TAG_ACCOUNT_MANAGER, "accountmgr service onstart");
    CountTrace(HITRACE_TAG_ACCOUNT_MANAGER, "activeid", -1);

    PerfStat::GetInstance().SetInstanceStartTime(GetTickCount());
    ACCOUNT_LOGI("start is triggered");
    if (!Init()) {
        ACCOUNT_LOGE("failed to init AccountMgrService");
        FinishTrace(HITRACE_TAG_ACCOUNT_MANAGER);
        return;
    }
    state_ = ServiceRunningState::STATE_RUNNING;

    // create and start basic accounts
    osAccountManagerService_->CreateBasicAccounts();
    ACCOUNT_LOGI("AccountMgrService::OnStart start service finished.");
    FinishTrace(HITRACE_TAG_ACCOUNT_MANAGER);
}

void AccountMgrService::OnStop()
{
    PerfStat::GetInstance().SetInstanceStopTime(GetTickCount());
    ACCOUNT_LOGI("onstop is called");
    IAccountContext::SetInstance(nullptr);
    SelfClean();
}

bool AccountMgrService::Init()
{
    if (state_ == ServiceRunningState::STATE_RUNNING) {
        ACCOUNT_LOGW("Service is already running!");
        return false;
    }

    CreateDeviceDir();

    if (!registerToService_) {
        if (!Publish(&DelayedRefSingleton<AccountMgrService>::GetInstance())) {
            ReportServiceStartFail(ERR_ACCOUNT_MGR_ADD_TO_SA_ERROR, "Publish service failed!");
            ACCOUNT_LOGE("AccountMgrService::Init Publish failed!");
            return false;
        }
        registerToService_ = true;
    }
    PerfStat::GetInstance().SetInstanceInitTime(GetTickCount());
    ohosAccountMgr_ = std::make_shared<OhosAccountManager>();
    if (!ohosAccountMgr_->OnInitialize()) {
        ACCOUNT_LOGE("Ohos account manager initialize failed");
        ReportServiceStartFail(ERR_ACCOUNT_MGR_OHOS_MGR_INIT_ERROR, "OnInitialize failed!");
        return false;
    }

    IAccountContext::SetInstance(this);
    appAccountManagerService_ = new (std::nothrow) AppAccountManagerService();
    if (appAccountManagerService_ == nullptr) {
        ReportServiceStartFail(ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR,
            "Insufficient memory to create app account manager service");
        ACCOUNT_LOGE("memory alloc failed for appAccountManagerService!");
        return false;
    }
    osAccountManagerService_ = new (std::nothrow) OsAccountManagerService();
    if (osAccountManagerService_ == nullptr) {
        ACCOUNT_LOGE("memory alloc failed for osAccountManagerService_!");
        appAccountManagerService_ = nullptr;
        ReportServiceStartFail(ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR,
            "Insufficient memory to create os account manager service");
        return false;
    }
    if ((!CreateIAMService()) || (!CreateDomainService())) {
        appAccountManagerService_ = nullptr;
        osAccountManagerService_ = nullptr;
#ifdef HAS_USER_AUTH_PART
        accountIAMService_ = nullptr;
#endif
        return false;
    }
    dumpHelper_ = std::make_unique<AccountDumpHelper>(ohosAccountMgr_, osAccountManagerService_.GetRefPtr());
    ACCOUNT_LOGI("init end success");
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

std::int32_t AccountMgrService::Dump(std::int32_t fd, const std::vector<std::u16string> &args)
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