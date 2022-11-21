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

#include "account_command_util.h"

#include <gtest/gtest.h>

#include "account_command.h"
#include "os_account_manager.h"
#include "tool_system_test.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AAFwk;

namespace OHOS {
namespace AccountSA {
namespace {
const std::string STRING_LOCAL_ACCOUNT_NAME = "local_account_name";
const std::string STRING_TYPE = "normal";
const std::string STRING_EMPTY = "";
}  // namespace

std::string AccountCommandUtil::CreateOsAccount()
{
    std::string command = TOOL_NAME + " create -n " + STRING_LOCAL_ACCOUNT_NAME + " -t " + STRING_TYPE;
    GTEST_LOG_(INFO) << "command = " << command;

    std::string commandResult = ToolSystemTest::ExecuteCommand(command);
    GTEST_LOG_(INFO) << "AccountCommandUtil::CreateOsAccount commandResult = " << commandResult;
    return commandResult;
}

std::string AccountCommandUtil::DeleteLastOsAccount()
{
    std::vector<OsAccountInfo> osAccounts;
    ErrCode result = OsAccountManager::QueryAllCreatedOsAccounts(osAccounts);
    GTEST_LOG_(INFO) << "AccountCommandUtil::DeleteLastOsAccount result = " << result;
    GTEST_LOG_(INFO) << "AccountCommandUtil::DeleteLastOsAccount osAccounts size = " << osAccounts.size();
    if (osAccounts.empty()) {
        return STRING_EMPTY;
    }

    std::string localAccountId = std::to_string(osAccounts.rbegin()->GetLocalId());

    std::string command = TOOL_NAME + " delete -i " + localAccountId;
    GTEST_LOG_(INFO) << "command = " << command;

    std::string commandResult = ToolSystemTest::ExecuteCommand(command);
    GTEST_LOG_(INFO) << "commandResult = " << commandResult;
    return commandResult;
}

std::string AccountCommandUtil::DumpLastOsAccount()
{
    std::vector<OsAccountInfo> osAccounts;
    ErrCode result = OsAccountManager::QueryAllCreatedOsAccounts(osAccounts);
    GTEST_LOG_(INFO) << "AccountCommandUtil::DumpLastOsAccount result = " << result;
    GTEST_LOG_(INFO) << "AccountCommandUtil::DumpLastOsAccount osAccounts size = " << osAccounts.size();

    if (osAccounts.empty()) {
        return STRING_EMPTY;
    }

    std::string localAccountId = std::to_string(osAccounts.rbegin()->GetLocalId());

    std::string command = TOOL_NAME + " dump -i " + localAccountId;
    GTEST_LOG_(INFO) << "command = " << command;

    std::string commandResult = ToolSystemTest::ExecuteCommand(command);
    GTEST_LOG_(INFO) << "AccountCommandUtil::DumpLastOsAccount commandResult " << commandResult;
    return commandResult;
}

std::string AccountCommandUtil::SwitchToFirstOsAccount()
{
    std::vector<OsAccountInfo> osAccounts;
    ErrCode result = OsAccountManager::QueryAllCreatedOsAccounts(osAccounts);
    GTEST_LOG_(INFO) << "AccountCommandUtil::SwitchToFirstOsAccount result = " << result;
    GTEST_LOG_(INFO) << "AccountCommandUtil::SwitchToFirstOsAccount osAccounts size = " << osAccounts.size();

    if (osAccounts.empty()) {
        return STRING_EMPTY;
    }

    std::string localAccountId = std::to_string(osAccounts.begin()->GetLocalId());

    std::string command = TOOL_NAME + " switch -i " + localAccountId;
    GTEST_LOG_(INFO) << "command = " << command;

    std::string commandResult = ToolSystemTest::ExecuteCommand(command);
    GTEST_LOG_(INFO) << "AccountCommandUtil::SwitchToFirstOsAccount commandResult = " << commandResult;
    return commandResult;
}

std::string AccountCommandUtil::SwitchToLastOsAccount()
{
    std::vector<OsAccountInfo> osAccounts;
    ErrCode result = OsAccountManager::QueryAllCreatedOsAccounts(osAccounts);
    GTEST_LOG_(INFO) << "AccountCommandUtil::SwitchToLastOsAccount result = " << result;
    GTEST_LOG_(INFO) << "AccountCommandUtil::SwitchToLastOsAccount osAccounts size = " << osAccounts.size();

    if (osAccounts.empty()) {
        return STRING_EMPTY;
    }

    std::string localAccountId = std::to_string(osAccounts.rbegin()->GetLocalId());

    std::string command = TOOL_NAME + " switch -i " + localAccountId;
    GTEST_LOG_(INFO) << "command = " << command;

    std::string commandResult = ToolSystemTest::ExecuteCommand(command);
    GTEST_LOG_(INFO) << "AccountCommandUtil::SwitchToLastOsAccount commandResult = " << commandResult;
    return commandResult;
}
}  // namespace AccountSA
}  // namespace OHOS
