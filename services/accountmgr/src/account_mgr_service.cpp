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
#include "hitrace_adapter.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "perf_stat.h"
#include "string_ex.h"
#include "system_ability_definition.h"

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
            ReportFileOperationFail(errno, "ForceCreateDirectory", DEVICE_OWNER_DIR);
        } else {
            if (!OHOS::ChangeModeDirectory(DEVICE_OWNER_DIR, S_IRWXU)) {
                ReportFileOperationFail(errno, "ChangeModeDirectory", DEVICE_OWNER_DIR);
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

    ACCOUNT_LOGD("Successful");
    return true;
}

std::pair<bool, OhosAccountInfo> AccountMgrService::QueryOhosAccountInfo(void)
{
    AccountInfo accountInfo = ohosAccountMgr_->GetCurrentOhosAccountInfo();
    std::string name = accountInfo.ohosAccountName_;
    std::string id = accountInfo.ohosAccountUid_;
    std::int32_t status = accountInfo.ohosAccountStatus_;
    return std::make_pair(true, OhosAccountInfo(name, id, status));
}

std::pair<bool, OhosAccountInfo> AccountMgrService::QueryOhosAccountInfoByUserId(std::int32_t userId)
{
    AccountInfo accountInfo = ohosAccountMgr_->GetOhosAccountInfoByUserId(userId);
    std::string name = accountInfo.ohosAccountName_;
    std::string id = accountInfo.ohosAccountUid_;
    std::int32_t status = accountInfo.ohosAccountStatus_;
    return std::make_pair(true, OhosAccountInfo(name, id, status));
}

std::int32_t AccountMgrService::QueryDeviceAccountId(std::int32_t &accountId)
{
    const std::int32_t uid = IPCSkeleton::GetCallingUid();
    accountId = uid / UID_TRANSFORM_DIVISOR;
    return ERR_OK;
}

sptr<IRemoteObject> AccountMgrService::GetAppAccountService()
{
    ACCOUNT_LOGD("enter");

    return appAccountManagerService_;
}
sptr<IRemoteObject> AccountMgrService::GetOsAccountService()
{
    ACCOUNT_LOGD("enter");

    return osAccountManagerService_;
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

    InitHiTrace();
    HiTraceAdapterSyncTrace tracer("accountmgr service onstart");
    ValueTrace("activeid", -1);

    PerfStat::GetInstance().SetInstanceStartTime(GetTickCount());
    ACCOUNT_LOGI("start is triggered");
    if (!Init()) {
        ACCOUNT_LOGE("failed to init AccountMgrService");
        return;
    }
    state_ = ServiceRunningState::STATE_RUNNING;

    // create and start basic accounts
    osAccountManagerServiceOrg_->CreateBasicAccounts();
    ACCOUNT_LOGI("AccountMgrService::OnStart start service finished.");
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

    bool ret = false;
    if (!registerToService_) {
        ret = Publish(&DelayedRefSingleton<AccountMgrService>::GetInstance());
        if (!ret) {
            ReportServiceStartFail(ERR_ACCOUNT_MGR_ADD_TO_SA_ERROR, "Publish service failed!");
            ACCOUNT_LOGE("AccountMgrService::Init Publish failed!");
            return false;
        }
        registerToService_ = true;
    }
    PerfStat::GetInstance().SetInstanceInitTime(GetTickCount());
    ohosAccountMgr_ = std::make_shared<OhosAccountManager>();
    ret = ohosAccountMgr_->OnInitialize();
    if (!ret) {
        ACCOUNT_LOGE("Ohos account manager initialize failed");
        ReportServiceStartFail(ERR_ACCOUNT_MGR_OHOS_MGR_INIT_ERROR, "OnInitialize failed!");
        return ret;
    }

    IAccountContext::SetInstance(this);
    auto appAccountManagerService = new (std::nothrow) AppAccountManagerService();
    if (appAccountManagerService == nullptr) {
        ReportServiceStartFail(ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR,
            "Insufficient memory to create app account manager service");
        ACCOUNT_LOGE("memory alloc failed for appAccountManagerService!");
        return false;
    }
    osAccountManagerServiceOrg_ = new (std::nothrow) OsAccountManagerService();
    if (osAccountManagerServiceOrg_ == nullptr) {
        ACCOUNT_LOGE("memory alloc failed for osAccountManagerServiceOrg_!");
        delete appAccountManagerService;
        ReportServiceStartFail(ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR,
            "Insufficient memory to create os account manager service");
        return false;
    }
    dumpHelper_ = std::make_unique<AccountDumpHelper>(ohosAccountMgr_, osAccountManagerServiceOrg_);
    appAccountManagerService_ = appAccountManagerService->AsObject();
    osAccountManagerService_ = osAccountManagerServiceOrg_->AsObject();
    ACCOUNT_LOGI("init end success");
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
    for (const auto &arg : args) {
        argsInStr.emplace_back(Str16ToStr8(arg));
    }

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
