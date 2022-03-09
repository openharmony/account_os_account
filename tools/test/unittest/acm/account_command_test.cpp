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

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

class AccountCommandTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
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
        (char *)TOOL_NAME.c_str(),
        (char *)"",
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
        (char *)TOOL_NAME.c_str(),
        (char *)"xxx",
        (char *)"",
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
        (char *)TOOL_NAME.c_str(),
        (char *)"-xxx",
        (char *)"",
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
        (char *)TOOL_NAME.c_str(),
        (char *)"--xxx",
        (char *)"",
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
        (char *)TOOL_NAME.c_str(),
        (char *)"help",
        (char *)"",
    };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;

    AccountCommand cmd(argc, argv);
    EXPECT_EQ(cmd.ExecCommand(), HELP_MSG);
}
