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

#include "account_dump_helper.h"
#include <regex>
#include <string>
#include "account_error_no.h"
#include "account_event_provider.h"
#include "account_info.h"
#include "account_log_wrapper.h"
#include "common_event_support.h"
#include "ohos_account_manager.h"
#include "perf_stat.h"
#include "string_ex.h"

namespace OHOS {
namespace AccountSA {
namespace {
const std::int32_t ARGS_SIZE_ONE = 1;
const std::int32_t ARGS_SIZE_TWO = 2;
const std::int32_t FIRST_PARAMETER = 0;
const std::int32_t SECOND_PARAMETER = 1;
const std::string ARGS_HELP = "-h";
const std::string ARGS_ACCOUNT_INFO = "-account_info";
const std::string ARGS_INPUT_SIMULATE = "-input_simulate";
const std::string ARGS_OUTPUT_SIMULATE = "-output_simulate";
const std::string ARGS_SHOW_LOG_LEVEL = "-show_log_level";
const std::string ARGS_SET_LOG_LEVEL = "-set_log_level";
const std::string ARGS_DUMP_PERF_STAT = "-perf_dump";
const std::string ILLEGAL_INFORMATION = "Ohos Account Manager service, enter '-h' for usage.\n";
const std::string SYSTEM_ERROR = "system error\n";
const std::string NO_INFORMATION = "no such information\n";
} // namespace

AccountDumpHelper::AccountDumpHelper(const std::shared_ptr<OhosAccountManager>& accountMgr)
{
    accountMgr_ = accountMgr;
}

bool AccountDumpHelper::Dump(const std::vector<std::string>& args, std::string& result) const
{
    result.clear();
    bool retRes = false;
    auto argsSize = args.size();
    if (argsSize == ARGS_SIZE_ONE) {
        retRes = ProcessOneParameter(args[FIRST_PARAMETER], result);
    } else if (argsSize == ARGS_SIZE_TWO) {
        retRes = ProcessTwoParameter(args[FIRST_PARAMETER], args[SECOND_PARAMETER], result);
    } else {
        ShowIllegalInformation(result);
    }

    return retRes;
}

void AccountDumpHelper::ShowHelp(std::string& result) const
{
    result.append("Usage:dump <command> [options]\n")
        .append("Description:\n")
        .append("-account_info          ")
        .append("dump all account information in the system\n")
        .append("-input_simulate <event>    ")
        .append("simulate event from ohos account, supported events: login/logout/token_invalid\n")
        .append("-output_simulate <event>    ")
        .append("simulate event output\n")
        .append("-show_log_level        ")
        .append("show account SA's log level\n")
        .append("-set_log_level <level>     ")
        .append("set account SA's log level\n")
        .append("-perf_dump         ")
        .append("dump performance statistics\n");
}

void AccountDumpHelper::ShowIllegalInformation(std::string& result) const
{
    result.append(ILLEGAL_INFORMATION);
}

void AccountDumpHelper::ShowAccountInfo(std::string& result) const
{
    auto lockPtr = accountMgr_.lock();
    if (lockPtr == nullptr) {
        ACCOUNT_LOGE("Invalid lockPtr");
        return;
    }

    AccountInfo accountInfo = lockPtr->GetAccountInfo();
    result.append("Ohos account name: ");
    result.append(accountInfo.ohosAccountName_.c_str());
    result.append(",    Ohos account uid: ");
    result.append(accountInfo.ohosAccountUid_.c_str());
    result.append(",    Local user Id: ");
    result.append(std::to_string(accountInfo.userId_));
    result.append(",    Ohos account status: ");
    result.append(std::to_string(accountInfo.ohosAccountStatus_));
    result.append(",    Ohos account bind time:  " + std::to_string(accountInfo.bindTime_));
    result.append("\n");
}

bool AccountDumpHelper::ProcessOneParameter(const std::string& arg, std::string& result) const
{
    if (accountMgr_.expired()) {
        result.append("Internal error!\n");
        return false;
    }
    bool retRes = true;
    if (arg == ARGS_HELP) {
        ShowHelp(result);
    } else if (arg == ARGS_ACCOUNT_INFO) {
        ShowAccountInfo(result);
    } else if (arg == ARGS_SHOW_LOG_LEVEL) {
        auto logLevel = static_cast<std::int32_t>(AccountLogWrapper::GetLogLevel());
        result.append("Current Log Level: " + std::to_string(logLevel) + "\n");
    } else if (arg == ARGS_DUMP_PERF_STAT) {
        PerfStat::GetInstance().Dump(result);
    } else {
        ShowHelp(result);
        retRes = false;
    }

    return retRes;
}

bool AccountDumpHelper::SimulateInputEvent(const std::string& eventStr, std::string& result) const
{
    auto lockPtr = accountMgr_.lock();
    if (lockPtr == nullptr) {
        return false;
    }

    bool retRes = lockPtr->HandleEvent(eventStr);
    if (retRes) {
        result.append("process event success");
    } else {
        result.append("process event failed");
    }

    return retRes;
}

bool AccountDumpHelper::SetLogLevel(const std::string& levelStr, std::string& result) const
{
    if (!regex_match(levelStr, std::regex("^\\d+$"))) {
        ACCOUNT_LOGE("Invalid format of log level");
        result.append("Invalid format of log level\n");
        return false;
    }
    auto level = std::stoi(levelStr);
    if ((level < static_cast<std::int32_t>(AccountLogLevel::DEBUG)) ||
        (level > static_cast<std::int32_t>(AccountLogLevel::FATAL))) {
        result.append("Invalid logLevel\n");
    } else {
        AccountLogLevel logLevel = static_cast<AccountLogLevel>(level);
        AccountLogWrapper::SetLogLevel(logLevel);
        result.append("Set logLevel success\n");
        return true;
    }
    return false;
}

bool AccountDumpHelper::ProcessTwoParameter(const std::string& arg1, const std::string& arg2, std::string& result) const
{
    if (accountMgr_.expired()) {
        result.append("Internal error!\n");
        return false;
    }
    bool retRes = false;
    if (arg1 == ARGS_INPUT_SIMULATE) {
        retRes = SimulateInputEvent(arg2, result);
        if (retRes) {
            result.append("handle input simulate event ok\n");
        }
    } else if (arg1 == ARGS_OUTPUT_SIMULATE) {
        bool errCode = AccountEventProvider::EventPublish(arg2);
        if (errCode == true) {
            result.append("Event outPut simulation success\n");
            retRes = true;
        } else {
            result.append("Event outPut simulation failed\n");
        }
    } else if (arg1 == ARGS_SET_LOG_LEVEL) {
        retRes = SetLogLevel(arg2, result);
    } else {
        ShowHelp(result);
    }

    return retRes;
}
} // namespace AccountSA
} // namespace OHOS
