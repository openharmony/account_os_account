/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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
#include "account_log_wrapper.h"
#include "account_test_common.h"
#include "os_account_constants.h"
#include "singleton.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AAFwk;
using namespace OHOS::AccountSA;
// using namespace OHOS::AccountSA::Constants;

namespace {
const std::string HELP_MSG_UNKNOWN_OPTION = "fail: unknown option.";

const std::string STRING_LOCAL_ACCOUNT_ID = "1024";
const std::string STRING_CONSTRAINT = "constraint.bluetooth";
const std::string STRING_CONSTRAINT1 = "constraint.bluetooth,constraint.bluetooth.set";

const int32_t START_USER_ID = 100;
}  // namespace

class AccountCommandSetTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    std::string cmd_ = "set";
};

void AccountCommandSetTest::SetUpTestCase()
{
    ASSERT_NE(GetAllAccountPermission(), 0);
}

void AccountCommandSetTest::TearDownTestCase()
{}

void AccountCommandSetTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());

    // reset optind to 0
    optind = 0;

    std::vector<OsAccountInfo> osAccountInfos;
    OsAccount::GetInstance().QueryAllCreatedOsAccounts(osAccountInfos);
    for (const auto &info : osAccountInfos) {
        if (info.GetLocalId() == START_USER_ID) {
            continue;
        }
        ACCOUNT_LOGI("[SetUp] remove account %{public}d", info.GetLocalId());
        OsAccount::GetInstance().RemoveOsAccount(info.GetLocalId());
    }
}

void AccountCommandSetTest::TearDown()
{}

/**
 * @tc.name: Acm_Command_Set_0100
 * @tc.desc: Verify the "acm set" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandSetTest, Acm_Command_Set_0100, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>(cmd_.c_str()),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_NO_OPTION + "\n" + HELP_MSG_SET);
}

/**
 * @tc.name: Acm_Command_Set_0200
 * @tc.desc: Verify the "acm set xxx" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandSetTest, Acm_Command_Set_0200, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>(cmd_.c_str()),
        const_cast<char *>("xxx"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_NO_OPTION + "\n" + HELP_MSG_SET);
}

/**
 * @tc.name: Acm_Command_Set_0300
 * @tc.desc: Verify the "acm set -x" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandSetTest, Acm_Command_Set_0300, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>(cmd_.c_str()),
        const_cast<char *>("-x"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_UNKNOWN_OPTION + "\n" + HELP_MSG_SET);
}

/**
 * @tc.name: Acm_Command_Set_0400
 * @tc.desc: Verify the "acm set -xxx" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandSetTest, Acm_Command_Set_0400, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>(cmd_.c_str()),
        const_cast<char *>("-xxx"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_UNKNOWN_OPTION + "\n" + HELP_MSG_SET);
}

/**
 * @tc.name: Acm_Command_Set_0500
 * @tc.desc: Verify the "acm set --x" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandSetTest, Acm_Command_Set_0500, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>(cmd_.c_str()),
        const_cast<char *>("--x"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_UNKNOWN_OPTION + "\n" + HELP_MSG_SET);
}

/**
 * @tc.name: Acm_Command_Set_0600
 * @tc.desc: Verify the "acm set --xxx" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandSetTest, Acm_Command_Set_0600, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>(cmd_.c_str()),
        const_cast<char *>("--xxx"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_UNKNOWN_OPTION + "\n" + HELP_MSG_SET);
}

/**
 * @tc.name: Acm_Command_Set_0700
 * @tc.desc: Verify the "acm set -h" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandSetTest, Acm_Command_Set_0700, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>(cmd_.c_str()),
        const_cast<char *>("-h"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_SET);
}

/**
 * @tc.name: Acm_Command_Set_0800
 * @tc.desc: Verify the "acm set --help" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandSetTest, Acm_Command_Set_0800, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>(cmd_.c_str()),
        const_cast<char *>("--help"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_SET);
}

/**
 * @tc.name: Acm_Command_Set_0900
 * @tc.desc: Verify the "acm set -i" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandSetTest, Acm_Command_Set_0900, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>(cmd_.c_str()),
        const_cast<char *>("-i"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_OPTION_REQUIRES_AN_ARGUMENT + "\n" + HELP_MSG_SET);
}

/**
 * @tc.name: Acm_Command_Set_1000
 * @tc.desc: Verify the "acm set -i <local-account-id>" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandSetTest, Acm_Command_Set_1000, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>(cmd_.c_str()),
        const_cast<char *>("-i"),
        const_cast<char *>(STRING_LOCAL_ACCOUNT_ID.c_str()),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_NO_CONSTRAINTS_OPTION + "\n" + HELP_MSG_SET);
}

/**
 * @tc.name: Acm_Command_Set_1100
 * @tc.desc: Verify the "acm set -c" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandSetTest, Acm_Command_Set_1100, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>(cmd_.c_str()),
        const_cast<char *>("-c"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_OPTION_REQUIRES_AN_ARGUMENT + "\n" + HELP_MSG_SET);
}

/**
 * @tc.name: Acm_Command_Set_1200
 * @tc.desc: Verify the "acm set -c <constraints>" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandSetTest, Acm_Command_Set_1200, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>(cmd_.c_str()),
        const_cast<char *>("-c"),
        const_cast<char *>(STRING_CONSTRAINT.c_str()),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_NO_ID_OPTION + "\n" + HELP_MSG_SET);
}

/**
 * @tc.name: Acm_Command_Set_1300
 * @tc.desc: Verify the "acm set -i <local-account-id> -c" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandSetTest, Acm_Command_Set_1300, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>(cmd_.c_str()),
        const_cast<char *>("-i"),
        const_cast<char *>(STRING_LOCAL_ACCOUNT_ID.c_str()),
        const_cast<char *>("-c"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_OPTION_REQUIRES_AN_ARGUMENT + "\n" + HELP_MSG_SET);
}

/**
 * @tc.name: Acm_Command_Set_1400
 * @tc.desc: Verify the "acm set -c <constraints> -i" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandSetTest, Acm_Command_Set_1400, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>(cmd_.c_str()),
        const_cast<char *>("-c"),
        const_cast<char *>(STRING_CONSTRAINT.c_str()),
        const_cast<char *>("-i"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_OPTION_REQUIRES_AN_ARGUMENT + "\n" + HELP_MSG_SET);
}

/**
 * @tc.name: Acm_Command_Set_1500
 * @tc.desc: Verify the "acm set -c <constraints> -i" command.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountCommandSetTest, Acm_Command_Set_1500, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    // create an os account
    EXPECT_EQ(ERR_OK, OsAccount::GetInstance().CreateOsAccount(TOOL_NAME, OsAccountType::NORMAL, osAccountInfo));

    std::string userId = std::to_string(osAccountInfo.GetLocalId());
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>(cmd_.c_str()),
        const_cast<char *>("-c"),
        const_cast<char *>(STRING_CONSTRAINT1.c_str()),
        const_cast<char *>("-i"),
        const_cast<char *>(userId.c_str()),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), STRING_SET_OS_ACCOUNT_CONSTRAINTS_OK + "\n");
    OsAccount::GetInstance().RemoveOsAccount(osAccountInfo.GetLocalId());
}
