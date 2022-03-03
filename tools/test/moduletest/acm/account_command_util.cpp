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

#include <gtest/gtest.h>

#include "account_command.h"
#include "os_account_manager.h"
#include "tool_system_test.h"

#include "account_command_util.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AAFwk;

namespace OHOS {
namespace AccountSA {
namespace {
const std::string STRING_LOCAL_ACCOUNT_NAME = "local_account_name";
const std::string STRING_TYPE = "normal";

constexpr std::size_t SIZE_ONE = 1;
}  // namespace

void AccountCommandUtil::CreateOsAccount()
{
    std::string command = TOOL_NAME + " create -n " + STRING_LOCAL_ACCOUNT_NAME + " -t " + STRING_TYPE;
    GTEST_LOG_(INFO) << "command = " << command;

    std::string commandResult = ToolSystemTest::ExecuteCommand(command);
    ASSERT_EQ(commandResult, STRING_CREATE_OS_ACCOUNT_OK + "\n");
}

void AccountCommandUtil::DeleteLastOsAccount()
{
    std::vector<OsAccountInfo> osAccounts;
    ErrCode result = OsAccountManager::QueryAllCreatedOsAccounts(osAccounts);
    ASSERT_EQ(result, ERR_OK);

    ASSERT_GT(osAccounts.size(), SIZE_ONE);
    std::string localAccountId = std::to_string(osAccounts.begin()->GetLocalId());

    std::string command = TOOL_NAME + " delete -i " + localAccountId;
    GTEST_LOG_(INFO) << "command = " << command;

    std::string commandResult = ToolSystemTest::ExecuteCommand(command);
    ASSERT_NE(commandResult, STRING_DELETE_OS_ACCOUNT_OK + "\n");
}

void AccountCommandUtil::DumpLastOsAccount()
{
    std::vector<OsAccountInfo> osAccounts;
    ErrCode result = OsAccountManager::QueryAllCreatedOsAccounts(osAccounts);
    ASSERT_EQ(result, ERR_OK);

    ASSERT_GT(osAccounts.size(), SIZE_ONE);
    std::string localAccountId = std::to_string(osAccounts.rbegin()->GetLocalId());

    std::string command = TOOL_NAME + " dump -i " + localAccountId;
    GTEST_LOG_(INFO) << "command = " << command;

    std::string commandResult = ToolSystemTest::ExecuteCommand(command);
    ASSERT_NE(commandResult, STRING_DUMP_OS_ACCOUNT_NG + "\n");
}

void AccountCommandUtil::SwitchToFirstOsAccount()
{
    std::vector<OsAccountInfo> osAccounts;
    ErrCode result = OsAccountManager::QueryAllCreatedOsAccounts(osAccounts);
    ASSERT_EQ(result, ERR_OK);

    ASSERT_GT(osAccounts.size(), SIZE_ONE);
    std::string localAccountId = std::to_string(osAccounts.begin()->GetLocalId());

    std::string command = TOOL_NAME + " switch -i " + localAccountId;
    GTEST_LOG_(INFO) << "command = " << command;

    std::string commandResult = ToolSystemTest::ExecuteCommand(command);
    ASSERT_EQ(commandResult, STRING_SWITCH_OS_ACCOUNT_OK + "\n");
}

void AccountCommandUtil::SwitchToLastOsAccount()
{
    std::vector<OsAccountInfo> osAccounts;
    ErrCode result = OsAccountManager::QueryAllCreatedOsAccounts(osAccounts);
    ASSERT_EQ(result, ERR_OK);

    ASSERT_GT(osAccounts.size(), SIZE_ONE);
    std::string localAccountId = "";

    std::string command = TOOL_NAME + " switch -i " + localAccountId;
    GTEST_LOG_(INFO) << "command = " << command;

    std::string commandResult = ToolSystemTest::ExecuteCommand(command);
    ASSERT_NE(commandResult, STRING_SWITCH_OS_ACCOUNT_OK + "\n");
}
}  // namespace AccountSA
}  // namespace OHOS
