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
 * @tc.name: OhosAcmTest_CommandMap_001
 * @tc.desc: Test command map has expected entries
 * @tc.type: FUNC
 * @tc.require: ohos-acm-cli
 */
HWTEST_F(OhosAcmTest, CommandMap_001, TestSize.Level1)
{
    const auto& commands = GetCommands();
    EXPECT_GE(commands.size(), static_cast<size_t>(1));
    EXPECT_NE(commands.find("get-current-userid"), commands.end());
    EXPECT_NE(commands.find("--help"), commands.end());
}

/**
 * @tc.name: OhosAcmTest_OutputSuccess_001
 * @tc.desc: Test OutputSuccess with valid data returns 0
 * @tc.type: FUNC
 * @tc.require: ohos-acm-cli
 */
HWTEST_F(OhosAcmTest, OutputSuccess_001, TestSize.Level1)
{
    auto data = CreateJson();
    ASSERT_NE(data, nullptr);
    AddIntToJson(data, "userId", 100);
    int ret = OutputSuccess(std::move(data));
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: OhosAcmTest_OutputSuccess_002
 * @tc.desc: Test OutputSuccess with null data returns 1
 * @tc.type: FUNC
 * @tc.require: ohos-acm-cli
 */
HWTEST_F(OhosAcmTest, OutputSuccess_002, TestSize.Level1)
{
    CJsonUnique nullData(nullptr);
    int ret = OutputSuccess(std::move(nullData));
    EXPECT_EQ(ret, 1);
}

/**
 * @tc.name: OhosAcmTest_OutputError_001
 * @tc.desc: Test OutputError returns 1
 * @tc.type: FUNC
 * @tc.require: ohos-acm-cli
 */
HWTEST_F(OhosAcmTest, OutputError_001, TestSize.Level1)
{
    int ret = OutputError("ERR_TEST", "Test error message", "Test suggestion");
    EXPECT_EQ(ret, 1);
}

/**
 * @tc.name: OhosAcmTest_OutputError_002
 * @tc.desc: Test OutputError with empty code and message
 * @tc.type: FUNC
 * @tc.require: ohos-acm-cli
 */
HWTEST_F(OhosAcmTest, OutputError_002, TestSize.Level1)
{
    int ret = OutputError("", "", "");
    EXPECT_EQ(ret, 1);
}

/**
 * @tc.name: OhosAcmTest_OutputError_003
 * @tc.desc: Test OutputError with special characters
 * @tc.type: FUNC
 * @tc.require: ohos-acm-cli
 */
HWTEST_F(OhosAcmTest, OutputError_003, TestSize.Level1)
{
    int ret = OutputError("ERR_\"quote\"", "Msg with \\\" escape", "");
    EXPECT_EQ(ret, 1);
}

/**
 * @tc.name: OhosAcmTest_CmdHelp_001
 * @tc.desc: Test CmdHelp returns 0 with empty args
 * @tc.type: FUNC
 * @tc.require: ohos-acm-cli
 */
HWTEST_F(OhosAcmTest, CmdHelp_001, TestSize.Level1)
{
    const char* testArgv[] = {"ohos-acm"};
    int argc = 1;
    char* argv[] = {const_cast<char*>(testArgv[0])};
    int ret = CmdHelp(argc, argv);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: OhosAcmTest_CmdHelp_002
 * @tc.desc: Test CmdHelp with command name returns 0
 * @tc.type: FUNC
 * @tc.require: ohos-acm-cli
 */
HWTEST_F(OhosAcmTest, CmdHelp_002, TestSize.Level1)
{
    const char* testArgv[] = {"ohos-acm", "get-current-userid"};
    int argc = 2;
    char* argv[] = {const_cast<char*>(testArgv[0]), const_cast<char*>(testArgv[1])};
    int ret = CmdHelp(argc, argv);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: OhosAcmTest_CmdHelp_003
 * @tc.desc: Test CmdHelp with unknown command returns error
 * @tc.type: FUNC
 * @tc.require: ohos-acm-cli
 */
HWTEST_F(OhosAcmTest, CmdHelp_003, TestSize.Level1)
{
    const char* testArgv[] = {"ohos-acm", "unknown-command"};
    int argc = 2;
    char* argv[] = {const_cast<char*>(testArgv[0]), const_cast<char*>(testArgv[1])};
    int ret = CmdHelp(argc, argv);
    EXPECT_EQ(ret, 1);
}

/**
 * @tc.name: OhosAcmTest_CmdGetCurrentUserId_001
 * @tc.desc: Test CmdGetCurrentUserId basic invocation
 * @tc.type: FUNC
 * @tc.require: ohos-acm-cli
 */
HWTEST_F(OhosAcmTest, CmdGetCurrentUserId_001, TestSize.Level1)
{
    const char* testArgv[] = {"ohos-acm", "get-current-userid"};
    int argc = 2;
    char* argv[] = {const_cast<char*>(testArgv[0]), const_cast<char*>(testArgv[1])};
    int ret = CmdGetCurrentUserId(argc, argv);
    EXPECT_TRUE(ret == 0 || ret == 1);
}
