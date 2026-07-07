/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "commands.h"

using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS::AccountSA::ACli;

class OhosAcmTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void OhosAcmTest::SetUpTestCase() {}

void OhosAcmTest::TearDownTestCase() {}

void OhosAcmTest::SetUp() {}

void OhosAcmTest::TearDown() {}

/**
 * @tc.number: Ohos_Acm_CommandMap_0001
 * @tc.name: CommandMap
 * @tc.desc: Verify command map contains expected entries (no --help subcommand)
 */
HWTEST_F(OhosAcmTest, Ohos_Acm_CommandMap_0001, Function | MediumTest | Level1)
{
    const auto& commands = GetCommands();
    EXPECT_GE(commands.size(), static_cast<size_t>(1));
    EXPECT_NE(commands.find("get-current-userid"), commands.end());
    EXPECT_EQ(commands.find("--help"), commands.end());
}

/**
 * @tc.number: Ohos_Acm_OutputSuccess_0001
 * @tc.name: OutputSuccess
 * @tc.desc: Test OutputSuccess with valid data returns 0
 */
HWTEST_F(OhosAcmTest, Ohos_Acm_OutputSuccess_0001, Function | MediumTest | Level1)
{
    auto data = CreateJson();
    ASSERT_NE(data, nullptr);
    AddIntToJson(data, "userId", 100);
    int ret = OutputSuccess(std::move(data));
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.number: Ohos_Acm_OutputSuccess_0002
 * @tc.name: OutputSuccess
 * @tc.desc: Test OutputSuccess with null data returns 1
 */
HWTEST_F(OhosAcmTest, Ohos_Acm_OutputSuccess_0002, Function | MediumTest | Level1)
{
    CJsonUnique nullData(nullptr);
    int ret = OutputSuccess(std::move(nullData));
    EXPECT_EQ(ret, 1);
}

/**
 * @tc.number: Ohos_Acm_OutputError_0001
 * @tc.name: OutputError
 * @tc.desc: Test OutputError returns 1
 */
HWTEST_F(OhosAcmTest, Ohos_Acm_OutputError_0001, Function | MediumTest | Level1)
{
    int ret = OutputError("ERR_TEST", "Test error message", "Test suggestion");
    EXPECT_EQ(ret, 1);
}

/**
 * @tc.number: Ohos_Acm_OutputError_0002
 * @tc.name: OutputError
 * @tc.desc: Test OutputError with empty code and message returns 1
 */
HWTEST_F(OhosAcmTest, Ohos_Acm_OutputError_0002, Function | MediumTest | Level1)
{
    int ret = OutputError("", "", "");
    EXPECT_EQ(ret, 1);
}

/**
 * @tc.number: Ohos_Acm_OutputError_0003
 * @tc.name: OutputError
 * @tc.desc: Test OutputError with special characters returns 1
 */
HWTEST_F(OhosAcmTest, Ohos_Acm_OutputError_0003, Function | MediumTest | Level1)
{
    int ret = OutputError("ERR_\"quote\"", "Msg with \\\" escape", "");
    EXPECT_EQ(ret, 1);
}

/**
 * @tc.number: Ohos_Acm_CmdHelp_0001
 * @tc.name: CmdHelp
 * @tc.desc: Test CmdHelp with empty args returns 0 (full help)
 */
HWTEST_F(OhosAcmTest, Ohos_Acm_CmdHelp_0001, Function | MediumTest | Level1)
{
    const char* testArgv[] = {"ohos-acm"};
    int argc = 1;
    char* argv[] = {const_cast<char*>(testArgv[0])};
    int ret = CmdHelp(argc, argv);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.number: Ohos_Acm_CmdHelp_0002
 * @tc.name: CmdHelp
 * @tc.desc: Test CmdHelp with command name returns 0 (subcommand help)
 */
HWTEST_F(OhosAcmTest, Ohos_Acm_CmdHelp_0002, Function | MediumTest | Level1)
{
    const char* testArgv[] = {"ohos-acm", "get-current-userid"};
    int argc = 2;
    char* argv[] = {const_cast<char*>(testArgv[0]), const_cast<char*>(testArgv[1])};
    int ret = CmdHelp(argc, argv);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.number: Ohos_Acm_CmdHelp_0003
 * @tc.name: CmdHelp
 * @tc.desc: Test CmdHelp with unknown command returns error
 */
HWTEST_F(OhosAcmTest, Ohos_Acm_CmdHelp_0003, Function | MediumTest | Level1)
{
    const char* testArgv[] = {"ohos-acm", "unknown-command"};
    int argc = 2;
    char* argv[] = {const_cast<char*>(testArgv[0]), const_cast<char*>(testArgv[1])};
    int ret = CmdHelp(argc, argv);
    EXPECT_EQ(ret, 1);
}

/**
 * @tc.number: Ohos_Acm_CmdHelp_0004
 * @tc.name: CmdHelp
 * @tc.desc: Test CmdHelp with --help flag as subcommand parameter dispatches correctly
 */
HWTEST_F(OhosAcmTest, Ohos_Acm_CmdHelp_0004, Function | MediumTest | Level1)
{
    const char* testArgv[] = {"ohos-acm", "get-current-userid", "--help"};
    int argc = 3;
    char* argv[] = {const_cast<char*>(testArgv[0]), const_cast<char*>(testArgv[1]),
        const_cast<char*>(testArgv[2])};
    int ret = CmdHelp(argc, argv);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.number: Ohos_Acm_CmdGetCurrentUserId_0001
 * @tc.name: CmdGetCurrentUserId
 * @tc.desc: Test CmdGetCurrentUserId basic invocation
 */
HWTEST_F(OhosAcmTest, Ohos_Acm_CmdGetCurrentUserId_0001, Function | MediumTest | Level1)
{
    const char* testArgv[] = {"ohos-acm", "get-current-userid"};
    int argc = 2;
    char* argv[] = {const_cast<char*>(testArgv[0]), const_cast<char*>(testArgv[1])};
    int ret = CmdGetCurrentUserId(argc, argv);
    EXPECT_EQ(ret, 0);
}
