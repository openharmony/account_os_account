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

#include "account_dump_helper.h"
#include <regex>
#include "account_error_no.h"
#include "account_info.h"
#include "account_log_wrapper.h"
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
const std::string ARGS_OHOS_ACCOUNT_INFOS = "-ohos_account_infos";
const std::string ARGS_OS_ACCOUNT_INFOS = "-os_account_infos";
const std::string ARGS_SHOW_LOG_LEVEL = "-show_log_level";
const std::string ARGS_SET_LOG_LEVEL = "-set_log_level";
const std::string ARGS_DUMP_TIME_INFO = "-time_info_dump";
const std::string ILLEGAL_INFORMATION = "Account Manager service, enter '-h' for usage.\n";
const std::string SYSTEM_ERROR = "System error: ";
const double ANONYMIZE_RATIO = 0.8;
const size_t MIN_ANONYMIZE_PART_LEN = 10;
const size_t MAX_INTERCEPT_PART_LEN = 4;
const size_t INTERCEPT_HEAD_PART_LEN_FOR_NAME = 1;
const std::string DEFAULT_ANON_STR = "**********";
std::string AnonymizeNameStr(const std::string& nameStr)
{
    if (nameStr == DEFAULT_OHOS_ACCOUNT_NAME || nameStr.empty()) {
        return nameStr;
    }
    std::string retStr = nameStr.substr(0, INTERCEPT_HEAD_PART_LEN_FOR_NAME) + DEFAULT_ANON_STR;
    return retStr;
}

std::string AnonymizeUidStr(const std::string& uidStr)
{
    if (uidStr == DEFAULT_OHOS_ACCOUNT_UID || uidStr.empty()) {
        return uidStr;
    }

    size_t anonymizeLen = static_cast<size_t>(static_cast<double>(uidStr.length()) * ANONYMIZE_RATIO);
    size_t interceptLen = (uidStr.length() - anonymizeLen) / 2;  // Half head and half tail
    if (anonymizeLen < MIN_ANONYMIZE_PART_LEN || interceptLen == 0) {
        return DEFAULT_ANON_STR;
    }
    interceptLen = (interceptLen > MAX_INTERCEPT_PART_LEN ? MAX_INTERCEPT_PART_LEN : interceptLen);

    std::string retStr = uidStr.substr(0, interceptLen);
    retStr += DEFAULT_ANON_STR;
    retStr += uidStr.substr(uidStr.length() - interceptLen);
    return retStr;
}
} // namespace

AccountDumpHelper::AccountDumpHelper(const std::shared_ptr<OhosAccountManager>& ohosAccountMgr,
    OsAccountManagerService *osAccountMgrService)
    : innerMgrService_(DelayedSingleton<IInnerOsAccountManager>::GetInstance())
{
    ohosAccountMgr_ = ohosAccountMgr;
    osAccountMgrService_ = osAccountMgrService;
}

void AccountDumpHelper::Dump(const std::vector<std::string>& args, std::string& result) const
{
    result.clear();
    auto argsSize = args.size();
    if (argsSize == ARGS_SIZE_ONE) {
        ProcessOneParameter(args[FIRST_PARAMETER], result);
    } else if (argsSize == ARGS_SIZE_TWO) {
        ProcessTwoParameter(args[FIRST_PARAMETER], args[SECOND_PARAMETER], result);
    } else {
        ShowIllegalInformation(result);
    }
}

void AccountDumpHelper::ShowHelp(std::string& result) const
{
    result.append("Usage:dump <command> [options]\n")
        .append("Description:\n")
        .append("-ohos_account_infos          :")
        .append("dump all distributed account information in the system\n")
        .append("-os_account_infos            :")
        .append("dump all os account information in the system\n")
        .append("-show_log_level              :")
        .append("show account SA's log level\n")
        .append("-set_log_level <level>       :")
        .append("set account SA's log level\n")
        .append("-time_info_dump              :")
        .append("dump some important time points\n");
}

void AccountDumpHelper::ShowIllegalInformation(std::string& result) const
{
    result.append(ILLEGAL_INFORMATION);
}

void AccountDumpHelper::ShowOhosAccountInfo(std::string& result) const
{
    auto lockPtr = ohosAccountMgr_.lock();
    if (lockPtr == nullptr || innerMgrService_ == nullptr) {
        result.append(SYSTEM_ERROR + "service ptr is null!\n");
        ACCOUNT_LOGE("service ptr is null!");
        return;
    }

    // check os account list
    std::vector<OsAccountInfo> osAccountInfos;
    ErrCode ret = innerMgrService_->QueryAllCreatedOsAccounts(osAccountInfos);
    if (ret != ERR_OK) {
        result.append("Cannot query os account list, error code ");
        result.append(std::to_string(ret));
        return;
    }

    if (osAccountInfos.empty()) {
        result.append(SYSTEM_ERROR + "os account list empty.\n");
        return;
    }

    result.append("OhosAccount info:\n");
    for (size_t i = 0; i < osAccountInfos.size(); ++i) {
        AccountInfo accountInfo;
        lockPtr->GetAccountInfoByUserId(osAccountInfos[i].GetLocalId(), accountInfo);
        result.append("     Bind local user id: ");
        result.append(std::to_string(accountInfo.userId_) + "\n");
        result.append("          OhosAccount name     : ");
        result.append(AnonymizeNameStr(accountInfo.ohosAccountInfo_.name_) + "\n");
        result.append("          OhosAccount uid      : ");
        result.append(AnonymizeUidStr(accountInfo.ohosAccountInfo_.uid_) + "\n");
        result.append("          OhosAccount status   : ");
        result.append(std::to_string(accountInfo.ohosAccountInfo_.status_) + "\n");
        result.append("          OhosAccount bind time: ");
        result.append(std::to_string(accountInfo.bindTime_) + "\n");
    }
}

void AccountDumpHelper::ShowOsAccountInfo(std::string& result) const
{
    if (osAccountMgrService_ == nullptr) {
        result.append(SYSTEM_ERROR + "service ptr is null!\n");
        ACCOUNT_LOGE("service ptr is null!");
        return;
    }

    std::vector<std::string> states;
    ErrCode ret = osAccountMgrService_->DumpOsAccountInfo(states);
    if (ret != ERR_OK) {
        result.append("Cannot query os account list, error code ");
        result.append(std::to_string(ret));
        return;
    }

    if (states.empty()) {
        result.append(SYSTEM_ERROR + "os account list empty.\n");
        return;
    }

    result.append("OsAccount info:\n");
    for (size_t i = 0; i < states.size(); ++i) {
        result.append("    " + states[i] + "\n");
    }
}

void AccountDumpHelper::ProcessOneParameter(const std::string& arg, std::string& result) const
{
    if (arg == ARGS_HELP) {
        ShowHelp(result);
    } else if (arg == ARGS_OHOS_ACCOUNT_INFOS) {
        ShowOhosAccountInfo(result);
    } else if (arg == ARGS_OS_ACCOUNT_INFOS) {
        ShowOsAccountInfo(result);
    } else if (arg == ARGS_SHOW_LOG_LEVEL) {
        auto logLevel = static_cast<std::int32_t>(AccountLogWrapper::GetLogLevel());
        result.append("Current Log Level: " + std::to_string(logLevel) + "\n");
    } else if (arg == ARGS_DUMP_TIME_INFO) {
        PerfStat::GetInstance().Dump(result);
    } else {
        ShowHelp(result);
    }
}

void AccountDumpHelper::SetLogLevel(const std::string& levelStr, std::string& result) const
{
    if (!regex_match(levelStr, std::regex("^\\-?\\d+$"))) {
        ACCOUNT_LOGE("Invalid format of log level");
        result.append("Invalid format of log level\n");
        return;
    }
    auto level = std::stoi(levelStr);
    if ((level < static_cast<std::int32_t>(AccountLogLevel::DEBUG)) ||
        (level > static_cast<std::int32_t>(AccountLogLevel::FATAL))) {
        result.append("Invalid logLevel\n");
    } else {
        AccountLogLevel logLevel = static_cast<AccountLogLevel>(level);
        AccountLogWrapper::SetLogLevel(logLevel);
        result.append("Set logLevel success\n");
    }
}

void AccountDumpHelper::ProcessTwoParameter(const std::string& arg1, const std::string& arg2, std::string& result) const
{
    if (arg1 == ARGS_SET_LOG_LEVEL) {
        SetLogLevel(arg2, result);
    } else {
        ShowHelp(result);
    }
}
} // namespace AccountSA
} // namespace OHOS
