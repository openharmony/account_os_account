/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "account_dump_helper.h"
#include "account_log_wrapper.h"
#include "common_event_support.h"
#include "datetime_ex.h"
#include "device_account_info.h"
#include "directory_ex.h"
#include "file_ex.h"
#include "hisysevent.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "perf_stat.h"
#include "string_ex.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AccountSA {
const std::string DEVICE_OWNER_DIR = "/data/system/users/0/";

constexpr std::int32_t UID_TRANSFORM_DIVISOR = 100000;
IAccountContext *IAccountContext::instance_ = nullptr;

const bool REGISTER_RESULT = SystemAbility::MakeAndRegisterAbility(
    &DelayedRefSingleton<AccountMgrService>::GetInstance());

AccountMgrService::AccountMgrService() : SystemAbility(SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN, true)
{
    PerfStat::GetInstance().SetInstanceCreateTime(GetTickCount());
}

AccountMgrService::~AccountMgrService()
{
}

bool AccountMgrService::UpdateOhosAccountInfo(const std::string& accountName, const std::string& uid,
    const std::string& eventStr)
{
    ACCOUNT_LOGI("Account event %s", eventStr.c_str());
    if (!ohosAccountMgr_->OhosAccountStateChange(accountName, uid, eventStr)) {
        ACCOUNT_LOGE("Ohos account state change failed");
        return false;
    }

    ACCOUNT_LOGI("Successful");
    return true;
}

std::pair<bool, OhosAccountInfo> AccountMgrService::QueryOhosAccountInfo(void)
{
    AccountInfo accountInfo = ohosAccountMgr_->GetAccountInfo();
    if (accountInfo.ohosAccountUid_.empty()) {
        ACCOUNT_LOGE("invalid id");
        accountInfo.clear();
    }
    std::string name = accountInfo.ohosAccountName_;
    std::string id = accountInfo.ohosAccountUid_;
    std::int32_t status = accountInfo.ohosAccountStatus_;
    return std::make_pair(true, OhosAccountInfo(name, id, status));
}

std::int32_t AccountMgrService::QueryDeviceAccountIdFromUid(std::int32_t uid)
{
    return uid / UID_TRANSFORM_DIVISOR;
}

std::int32_t AccountMgrService::QueryDeviceAccountId(std::int32_t& accountId)
{
    accountId = DEVICE_ACCOUNT_OWNER;
    return ERR_OK;
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

    PerfStat::GetInstance().SetInstanceStartTime(GetTickCount());
    ACCOUNT_LOGI("start is triggered");
    if (!Init()) {
        ACCOUNT_LOGE("failed to init AccountMgrService");
        return;
    }
    state_ = ServiceRunningState::STATE_RUNNING;
    ACCOUNT_LOGI("AccountMgrService::OnStart start service success.");
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

    if (!OHOS::FileExists(DEVICE_OWNER_DIR)) {
        ACCOUNT_LOGI("Device owner dir not exist, create!");
        if (!OHOS::ForceCreateDirectory(DEVICE_OWNER_DIR)) {
            ACCOUNT_LOGW("Create device owner dir failure!");
        }
    }

    bool ret = false;
    if (!registerToService_) {
        ret = Publish(&DelayedRefSingleton<AccountMgrService>::GetInstance());
        if (!ret) {
            HiviewDFX::HiSysEvent::Write(HiviewDFX::HiSysEvent::Domain::ACCOUNT, "AccountServiceStartFailed",
                HiviewDFX::HiSysEvent::EventType::FAULT, "ERROR_TYPE", ERR_ACCOUNT_MGR_ADD_TO_SA_ERROR);
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
        HiviewDFX::HiSysEvent::Write(HiviewDFX::HiSysEvent::Domain::ACCOUNT, "AccountServiceStartFailed",
            HiviewDFX::HiSysEvent::EventType::FAULT, "ERROR_TYPE", ret);
        return ret;
    }
    dumpHelper_ = std::make_unique<AccountDumpHelper>(ohosAccountMgr_);
    IAccountContext::SetInstance(this);
    ACCOUNT_LOGI("init end success");
    return true;
}

int AccountMgrService::Dump(std::int32_t fd, const std::vector<std::u16string>& args)
{
    if (fd < 0) {
        ACCOUNT_LOGE("dump fd invalid");
        return ERR_ACCOUNT_MGR_DUMP_ERROR;
    }

    std::vector<std::string> argsInStr;
    for (const auto& arg : args) {
        ACCOUNT_LOGI("Dump args: %s", Str16ToStr8(arg).c_str());
        argsInStr.emplace_back(Str16ToStr8(arg));
    }

    std::string result;
    if (dumpHelper_ && dumpHelper_->Dump(argsInStr, result)) {
        ACCOUNT_LOGI("%s", result.c_str());
        std::int32_t ret = dprintf(fd, "%s", result.c_str());
        if (ret < 0) {
            ACCOUNT_LOGE("dprintf to dump fd failed");
            return ERR_ACCOUNT_MGR_DUMP_ERROR;
        }
        return ERR_OK;
    }

    ACCOUNT_LOGW("dumpHelper failed");
    return ERR_ACCOUNT_MGR_DUMP_ERROR;
}

void AccountMgrService::SelfClean()
{
    state_ = ServiceRunningState::STATE_NOT_START;
    registerToService_ = false;
    ACCOUNT_LOGI("selfclean finished");
}

void AccountMgrService::HandleNotificationEvents(const std::string &eventStr)
{
    if (state_ == ServiceRunningState::STATE_NOT_START) {
        ACCOUNT_LOGW("service not running for handling event: %{public}s", eventStr.c_str());
        return;
    }

    ACCOUNT_LOGI("Unhandled event: %{public}s", eventStr.c_str());
}
} // namespace AccountSA
} // namespace OHOS
