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

#include <gtest/gtest.h>
#include <thread>
#include "account_command.h"
#include "account_command_util.h"
#include "account_log_wrapper.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AAFwk;
using namespace OHOS::AccountSA;

namespace {
const std::string STRING_LOCAL_ACCOUNT_ID_INVALID = "local_account_id_invalid";
const std::string STRING_LOCAL_ACCOUNT_ID_INVALID_TWO = "1024";
}  // namespace

class AccountCommandSwitchModuleTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    std::string cmd_ = "switch";
};

void AccountCommandSwitchModuleTest::SetUpTestCase()
{
    ASSERT_NE(GetAllAccountPermission(), 0);
}

void AccountCommandSwitchModuleTest::TearDownTestCase()
{}

void AccountCommandSwitchModuleTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void AccountCommandSwitchModuleTest::TearDown()
{}

static std::string ExecuteCommand(const std::string& command)
{
    std::string result = "";
    FILE* file = popen(command.c_str(), "r");

    if (file != nullptr) {
        char commandResult[1024] = { 0 };
        while ((fgets(commandResult, sizeof(commandResult), file)) != nullptr) {
            result.append(commandResult);
        }
        pclose(file);
        file = nullptr;
    }

    return result;
}

/**
 * @tc.name: Acm_Command_Switch_0100
 * @tc.desc: Verify the "acm delete -i <local-account-id>" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandSwitchModuleTest, Acm_Command_Switch_0100, TestSize.Level1)
{
    std::string command = TOOL_NAME + " " + cmd_ + " -i " + STRING_LOCAL_ACCOUNT_ID_INVALID;
    GTEST_LOG_(INFO) << "command = " << command;

    std::string commandResult = ExecuteCommand(command);
    EXPECT_EQ(commandResult, HELP_MSG_INVALID_ID_ARGUMENT + "\n" + HELP_MSG_SWITCH);
}

/**
 * @tc.name: Acm_Command_Switch_0200
 * @tc.desc: Verify the "acm delete -i <local-account-id>" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandSwitchModuleTest, Acm_Command_Switch_0200, TestSize.Level1)
{
    std::string command = TOOL_NAME + " " + cmd_ + " -i " + STRING_LOCAL_ACCOUNT_ID_INVALID_TWO;
    GTEST_LOG_(INFO) << "command = " << command;

    std::string commandResult = ExecuteCommand(command);
    EXPECT_EQ(commandResult, STRING_SWITCH_OS_ACCOUNT_NG + "\n");
}

/**
 * @tc.name: Acm_Command_Switch_0300
 * @tc.desc: Verify the "acm delete -i <local-account-id>" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandSwitchModuleTest, Acm_Command_Switch_0300, TestSize.Level1)
{
    std::string commandResult = AccountCommandUtil::CreateOsAccount("Acm_Command_Switch_0300");
    ASSERT_NE(commandResult.find(STRING_CREATE_OS_ACCOUNT_OK), std::string::npos);

    commandResult = AccountCommandUtil::DeleteLastOsAccount();
    ASSERT_NE(commandResult.find(STRING_DELETE_OS_ACCOUNT_OK), std::string::npos);
}
