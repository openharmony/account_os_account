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

#define private public
#include "account_command.h"
#undef private
#include "singleton.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AAFwk;
using namespace OHOS::AccountSA;

namespace {
const std::string HELP_MSG_UNKNOWN_OPTION = "error: unknown option.";
}  // namespace
class AccountCommandTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    std::string cmd_ = "stop";
};

void AccountCommandTest::SetUpTestCase()
{}

void AccountCommandTest::TearDownTestCase()
{}

void AccountCommandTest::SetUp()
{
    // reset optind to 0
    optind = 0;
}

void AccountCommandTest::TearDown()
{}

/**
 * @tc.name: Acm_Command_0100
 * @tc.desc: Verify the "acm" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_0100, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG);
}

/**
 * @tc.name: Acm_Command_0200
 * @tc.desc: Verify the "acm xxx" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_0200, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("xxx"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), cmd.GetCommandErrorMsg() + HELP_MSG);
}

/**
 * @tc.name: Acm_Command_0300
 * @tc.desc: Verify the "acm -xxx" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_0300, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("-xxx"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), cmd.GetCommandErrorMsg() + HELP_MSG);
}

/**
 * @tc.name: Acm_Command_0400
 * @tc.desc: Verify the "acm --xxx" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_0400, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("--xxx"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), cmd.GetCommandErrorMsg() + HELP_MSG);
}

/**
 * @tc.name: Acm_Command_0500
 * @tc.desc: Verify the "acm help" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandTest, Acm_Command_0500, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>("help"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG);
}

#ifdef ENABLE_MULTIPLE_ACTIVE_ACCOUNTS
/**
 * @tc.name: Acm_Command_0600
 * @tc.desc: Verify the "acm stop" command.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountCommandTest, Acm_Command_0600, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>(cmd_.c_str()),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_NO_OPTION + "\n" + HELP_MSG_STOP);
}

/**
 * @tc.name: Acm_Command_0700
 * @tc.desc: Verify the "acm stop xxx" command.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountCommandTest, Acm_Command_0700, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>(cmd_.c_str()),
        const_cast<char *>("xxx"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_NO_OPTION + "\n" + HELP_MSG_STOP);
}

/**
 * @tc.name: Acm_Command_0800
 * @tc.desc: Verify the "acm stop -x" command.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountCommandTest, Acm_Command_0800, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>(cmd_.c_str()),
        const_cast<char *>("-x"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_UNKNOWN_OPTION + "\n" + HELP_MSG_STOP);
}

/**
 * @tc.name: Acm_Command_0900
 * @tc.desc: Verify the "acm stop -xxx" command.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountCommandTest, Acm_Command_0900, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>(cmd_.c_str()),
        const_cast<char *>("-xxx"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_UNKNOWN_OPTION + "\n" + HELP_MSG_STOP);
}

/**
 * @tc.name: Acm_Command_1000
 * @tc.desc: Verify the "acm stop --x" command.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountCommandTest, Acm_Command_1000, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>(cmd_.c_str()),
        const_cast<char *>("--x"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_UNKNOWN_OPTION + "\n" + HELP_MSG_STOP);
}

/**
 * @tc.name: Acm_Command_1100
 * @tc.desc: Verify the "acm stop --xxx" command.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountCommandTest, Acm_Command_1100, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>(cmd_.c_str()),
        const_cast<char *>("--xxx"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_UNKNOWN_OPTION + "\n" + HELP_MSG_STOP);
}

/**
 * @tc.name: Acm_Command_1200
 * @tc.desc: Verify the "acm stop -h" command.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountCommandTest, Acm_Command_1200, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>(cmd_.c_str()),
        const_cast<char *>("-h"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_STOP);
}

/**
 * @tc.name: Acm_Command_1300
 * @tc.desc: Verify the "acm stop -help" command.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountCommandTest, Acm_Command_1300, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>(cmd_.c_str()),
        const_cast<char *>("--help"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_STOP);
}

/**
 * @tc.name: Acm_Command_1400
 * @tc.desc: Verify the "acm stop -i" command.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountCommandTest, Acm_Command_1400, TestSize.Level1)
{
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>(cmd_.c_str()),
        const_cast<char *>("-i"),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_OPTION_REQUIRES_AN_ARGUMENT + "\n" + HELP_MSG_STOP);
}

/**
 * @tc.name: Acm_Command_1500
 * @tc.desc: Verify the "acm stop -i" command.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountCommandTest, Acm_Command_1500, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    // create an os account
    EXPECT_EQ(ERR_OK, OsAccount::GetInstance().CreateOsAccount(TOOL_NAME, OsAccountType::NORMAL, osAccountInfo));

    std::string userId = std::to_string(osAccountInfo.GetLocalId());
    char *argv[] = {
        const_cast<char *>(TOOL_NAME.c_str()),
        const_cast<char *>(cmd_.c_str()),
        const_cast<char *>("-i"),
        const_cast<char *>(userId.c_str()),
        const_cast<char *>(""),
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), STRING_STOP_OS_ACCOUNT_OK + "\n");
}
#endif