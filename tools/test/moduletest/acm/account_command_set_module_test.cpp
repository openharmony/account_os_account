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

#include <filesystem>
#include <gtest/gtest.h>

#include "account_command.h"
#include "account_command_util.h"
#include "account_file_operator.h"
#include "account_log_wrapper.h"
#include "os_account_manager.h"
#include "tool_system_test.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AAFwk;
using namespace OHOS::AccountSA;
using namespace OHOS::AccountSA::Constants;

namespace {
const std::string STRING_CONSTRAINT_INVALID = "constraint.invalid";
const std::string STRING_CONSTRAINT = "constraint.bluetooth";

constexpr std::size_t SIZE_ONE = 1;
}  // namespace

class AccountCommandSetModuleTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    std::string cmd_ = "set";
};

void AccountCommandSetModuleTest::SetUpTestCase()
{
#ifdef ACCOUNT_TEST
    AccountFileOperator osAccountFileOperator;
    osAccountFileOperator.DeleteDirOrFile(USER_INFO_BASE);
    GTEST_LOG_(INFO) << "delete account test path " << USER_INFO_BASE;
#endif  // ACCOUNT_TEST
}

void AccountCommandSetModuleTest::TearDownTestCase()
{
#ifdef ACCOUNT_TEST
    AccountFileOperator osAccountFileOperator;
    osAccountFileOperator.DeleteDirOrFile(USER_INFO_BASE);
    GTEST_LOG_(INFO) << "delete account test path " << USER_INFO_BASE;
#endif  // ACCOUNT_TEST
}

void AccountCommandSetModuleTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void AccountCommandSetModuleTest::TearDown()
{}

/**
 * @tc.name: Acm_Command_Set_0100
 * @tc.desc: Verify the "acm set -i <local-account-id> -c <constraints>" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandSetModuleTest, Acm_Command_Set_0100, TestSize.Level1)
{
    AccountCommandUtil::CreateOsAccount("Acm_Command_Set_0100");

    std::vector<OsAccountInfo> osAccounts;
    ErrCode result = OsAccountManager::QueryAllCreatedOsAccounts(osAccounts);
    ASSERT_EQ(result, ERR_OK);

    ASSERT_GT(osAccounts.size(), SIZE_ONE);
    std::string localAccountId = std::to_string(osAccounts.rbegin()->GetLocalId());

    std::string command = TOOL_NAME + " set -i " + localAccountId + " -c " + STRING_CONSTRAINT_INVALID;
    GTEST_LOG_(INFO) << "command = " << command;

    std::string commandResult = ToolSystemTest::ExecuteCommand(command);
    ASSERT_EQ(commandResult, STRING_SET_OS_ACCOUNT_CONSTRAINTS_NG + "\n");

    commandResult = AccountCommandUtil::DeleteLastOsAccount();
    ASSERT_NE(commandResult.find(STRING_DELETE_OS_ACCOUNT_OK), std::string::npos);
}

/**
 * @tc.name: Acm_Command_Set_0200
 * @tc.desc: Verify the "acm set -i <local-account-id> -c <constraints>" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandSetModuleTest, Acm_Command_Set_0200, TestSize.Level1)
{
    AccountCommandUtil::CreateOsAccount("Acm_Command_Set_0200");

    std::vector<OsAccountInfo> osAccounts;
    ErrCode result = OsAccountManager::QueryAllCreatedOsAccounts(osAccounts);
    ASSERT_EQ(result, ERR_OK);

    ASSERT_GT(osAccounts.size(), SIZE_ONE);
    std::string localAccountId = std::to_string(osAccounts.rbegin()->GetLocalId());

    std::string command = TOOL_NAME + " set -i " + localAccountId + " -c " + STRING_CONSTRAINT + " -e";
    GTEST_LOG_(INFO) << "command = " << command;

    std::string commandResult = ToolSystemTest::ExecuteCommand(command);
    ASSERT_EQ(commandResult, STRING_SET_OS_ACCOUNT_CONSTRAINTS_OK + "\n");

    command = TOOL_NAME + " set -i " + localAccountId + " -c " + STRING_CONSTRAINT + " -e";
    GTEST_LOG_(INFO) << "command = " << command;

    commandResult = ToolSystemTest::ExecuteCommand(command);
    ASSERT_EQ(commandResult, STRING_SET_OS_ACCOUNT_CONSTRAINTS_OK + "\n");

    commandResult = AccountCommandUtil::DeleteLastOsAccount();
    ASSERT_NE(commandResult.find(STRING_DELETE_OS_ACCOUNT_OK), std::string::npos);
}
