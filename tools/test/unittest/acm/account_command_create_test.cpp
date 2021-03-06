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
#include "account_command.h"
#include "account_log_wrapper.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AAFwk;
using namespace OHOS::AccountSA;

namespace {
const std::string HELP_MSG_UNKNOWN_OPTION = "error: unknown option.";

const std::string STRING_LOCAL_ACCOUNT_NAME = "local_account_name";
const std::string STRING_TYPE = "normal";
const std::string STRING_TYPE_INVALID = "type_invalid";
}  // namespace

class AccountCommandCreateTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    std::string cmd_ = "create";
};

void AccountCommandCreateTest::SetUpTestCase()
{}

void AccountCommandCreateTest::TearDownTestCase()
{}

void AccountCommandCreateTest::SetUp()
{
    // reset optind to 0
    optind = 0;
}

void AccountCommandCreateTest::TearDown()
{}

/**
 * @tc.name: Acm_Command_Create_0100
 * @tc.desc: Verify the "acm create" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandCreateTest, Acm_Command_Create_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("Acm_Command_Create_0100");
    char *argv[] = {
        (char *)TOOL_NAME.c_str(),
        (char *)cmd_.c_str(),
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_NO_OPTION + "\n" + HELP_MSG_CREATE);
}

/**
 * @tc.name: Acm_Command_Create_0200
 * @tc.desc: Verify the "acm create xxx" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandCreateTest, Acm_Command_Create_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("Acm_Command_Create_0200");
    char *argv[] = {
        (char *)TOOL_NAME.c_str(),
        (char *)cmd_.c_str(),
        (char *)"xxx",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_NO_OPTION + "\n" + HELP_MSG_CREATE);
}

/**
 * @tc.name: Acm_Command_Create_0300
 * @tc.desc: Verify the "acm create -x" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandCreateTest, Acm_Command_Create_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("Acm_Command_Create_0300");
    char *argv[] = {
        (char *)TOOL_NAME.c_str(),
        (char *)cmd_.c_str(),
        (char *)"-x",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_UNKNOWN_OPTION + "\n" + HELP_MSG_CREATE);
}

/**
 * @tc.name: Acm_Command_Create_0400
 * @tc.desc: Verify the "acm create -xxx" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandCreateTest, Acm_Command_Create_0400, TestSize.Level1)
{
    ACCOUNT_LOGI("Acm_Command_Create_0400");
    char *argv[] = {
        (char *)TOOL_NAME.c_str(),
        (char *)cmd_.c_str(),
        (char *)"-xxx",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_UNKNOWN_OPTION + "\n" + HELP_MSG_CREATE);
}

/**
 * @tc.name: Acm_Command_Create_0500
 * @tc.desc: Verify the "acm create --x" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandCreateTest, Acm_Command_Create_0500, TestSize.Level1)
{
    ACCOUNT_LOGI("Acm_Command_Create_0500");
    char *argv[] = {
        (char *)TOOL_NAME.c_str(),
        (char *)cmd_.c_str(),
        (char *)"--x",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_UNKNOWN_OPTION + "\n" + HELP_MSG_CREATE);
}

/**
 * @tc.name: Acm_Command_Create_0600
 * @tc.desc: Verify the "acm create --xxx" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandCreateTest, Acm_Command_Create_0600, TestSize.Level1)
{
    ACCOUNT_LOGI("Acm_Command_Create_0600");
    char *argv[] = {
        (char *)TOOL_NAME.c_str(),
        (char *)cmd_.c_str(),
        (char *)"--xxx",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_UNKNOWN_OPTION + "\n" + HELP_MSG_CREATE);
}

/**
 * @tc.name: Acm_Command_Create_0700
 * @tc.desc: Verify the "acm create -h" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandCreateTest, Acm_Command_Create_0700, TestSize.Level1)
{
    ACCOUNT_LOGI("Acm_Command_Create_0700");
    char *argv[] = {
        (char *)TOOL_NAME.c_str(),
        (char *)cmd_.c_str(),
        (char *)"-h",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_CREATE);
}

/**
 * @tc.name: Acm_Command_Create_0800
 * @tc.desc: Verify the "acm create --help" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandCreateTest, Acm_Command_Create_0800, TestSize.Level1)
{
    ACCOUNT_LOGI("Acm_Command_Create_0800");
    char *argv[] = {
        (char *)TOOL_NAME.c_str(),
        (char *)cmd_.c_str(),
        (char *)"--help",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_CREATE);
}

/**
 * @tc.name: Acm_Command_Create_0900
 * @tc.desc: Verify the "acm create -n" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandCreateTest, Acm_Command_Create_0900, TestSize.Level1)
{
    ACCOUNT_LOGI("Acm_Command_Create_0900");
    char *argv[] = {
        (char *)TOOL_NAME.c_str(),
        (char *)cmd_.c_str(),
        (char *)"-n",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_OPTION_REQUIRES_AN_ARGUMENT + "\n" + HELP_MSG_CREATE);
}

/**
 * @tc.name: Acm_Command_Create_1000
 * @tc.desc: Verify the "acm create -n <local-account-name>" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandCreateTest, Acm_Command_Create_1000, TestSize.Level1)
{
    ACCOUNT_LOGI("Acm_Command_Create_1000");
    char *argv[] = {
        (char *)TOOL_NAME.c_str(),
        (char *)cmd_.c_str(),
        (char *)"-n",
        (char *)STRING_LOCAL_ACCOUNT_NAME.c_str(),
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_NO_TYPE_OPTION + "\n" + HELP_MSG_CREATE);
}

/**
 * @tc.name: Acm_Command_Create_1100
 * @tc.desc: Verify the "acm create -t" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandCreateTest, Acm_Command_Create_1100, TestSize.Level1)
{
    ACCOUNT_LOGI("Acm_Command_Create_1100");
    char *argv[] = {
        (char *)TOOL_NAME.c_str(),
        (char *)cmd_.c_str(),
        (char *)"-t",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_OPTION_REQUIRES_AN_ARGUMENT + "\n" + HELP_MSG_CREATE);
}

/**
 * @tc.name: Acm_Command_Create_1200
 * @tc.desc: Verify the "acm create -t <type>" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandCreateTest, Acm_Command_Create_1200, TestSize.Level1)
{
    ACCOUNT_LOGI("Acm_Command_Create_1200");
    char *argv[] = {
        (char *)TOOL_NAME.c_str(),
        (char *)cmd_.c_str(),
        (char *)"-t",
        (char *)STRING_TYPE_INVALID.c_str(),
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_INVALID_TYPE_ARGUMENT + "\n" + HELP_MSG_CREATE);
}

/**
 * @tc.name: Acm_Command_Create_1300
 * @tc.desc: Verify the "acm create -t <type>" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandCreateTest, Acm_Command_Create_1300, TestSize.Level1)
{
    ACCOUNT_LOGI("Acm_Command_Create_1300");
    char *argv[] = {
        (char *)TOOL_NAME.c_str(),
        (char *)cmd_.c_str(),
        (char *)"-t",
        (char *)STRING_TYPE.c_str(),
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_NO_NAME_OPTION + "\n" + HELP_MSG_CREATE);
}

/**
 * @tc.name: Acm_Command_Create_1400
 * @tc.desc: Verify the "acm create -n <local-account-name> -t" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandCreateTest, Acm_Command_Create_1400, TestSize.Level1)
{
    ACCOUNT_LOGI("Acm_Command_Create_1400");
    char *argv[] = {
        (char *)TOOL_NAME.c_str(),
        (char *)cmd_.c_str(),
        (char *)"-n",
        (char *)STRING_LOCAL_ACCOUNT_NAME.c_str(),
        (char *)"-t",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_OPTION_REQUIRES_AN_ARGUMENT + "\n" + HELP_MSG_CREATE);
}

/**
 * @tc.name: Acm_Command_Create_1500
 * @tc.desc: Verify the "acm create -n <local-account-name> -t <type>" command.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFO
 */
HWTEST_F(AccountCommandCreateTest, Acm_Command_Create_1500, TestSize.Level1)
{
    ACCOUNT_LOGI("Acm_Command_Create_1500");
    char *argv[] = {
        (char *)TOOL_NAME.c_str(),
        (char *)cmd_.c_str(),
        (char *)"-n",
        (char *)STRING_LOCAL_ACCOUNT_NAME.c_str(),
        (char *)"-t",
        (char *)STRING_TYPE_INVALID.c_str(),
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG_INVALID_TYPE_ARGUMENT + "\n" + HELP_MSG_CREATE);
}
