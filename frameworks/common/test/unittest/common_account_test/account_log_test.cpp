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

#include "account_log_wrapper.h"

using namespace testing::ext;
using namespace OHOS::AccountSA;

class AccountLogTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AccountLogTest::SetUpTestCase() {}

void AccountLogTest::TearDownTestCase() {}

void AccountLogTest::SetUp() {}

void AccountLogTest::TearDown() {}

/**
 * @tc.name: AccountLogLevel001
 * @tc.desc: Dynamically control log print level
 * @tc.type: FUNC
 * @tc.require: AR000CUF6K
 */
HWTEST_F(AccountLogTest, AccountLogLevel001, TestSize.Level0)
{
    /**
     * @tc.steps: step1. Get default log level
     * @tc.expected: step1. The default log level is AccountLogLevel::INFO
     */
    EXPECT_EQ(AccountLogLevel::INFO, AccountLogWrapper::GetLogLevel());

    /**
     * @tc.steps: step2. Set log level with DEBUG
     * @tc.expected: step2. Get log level is AccountLogLevel::DEBUG
     */
    AccountLogWrapper::SetLogLevel(AccountLogLevel::DEBUG);
    EXPECT_EQ(AccountLogLevel::DEBUG, AccountLogWrapper::GetLogLevel());
}

/**
 * @tc.name: AccountLogFileName002
 * @tc.desc: splice filename
 * @tc.type: FUNC
 * @tc.require: AR000CUF6L
 */
HWTEST_F(AccountLogTest, AccountLogFileName002, TestSize.Level0)
{
    /**
     * @tc.steps: step1. Constructor fileName and execeptStr strings
     */
    std::string fileName = "../base/account/test.cpp";
    std::string exceptStr = "test.cpp";

    /**
     * @tc.steps: step2. Call the GetBriefFileName method to split the string
     * @tc.expected: step2. The result string is "test.cpp"
     */
    std::string result = AccountLogWrapper::GetBriefFileName(fileName);
    EXPECT_EQ(exceptStr, result);
}

/**
 * @tc.name: AccountLogFileName003
 * @tc.desc: splice filename
 * @tc.type: FUNC
 * @tc.require: AR000CUF6M
 */
HWTEST_F(AccountLogTest, AccountLogFileName003, TestSize.Level0)
{
    std::string fileName = "test.cpp";
    std::string result = AccountLogWrapper::GetBriefFileName(fileName);
    EXPECT_EQ(fileName, result);
    fileName = "";
    result = AccountLogWrapper::GetBriefFileName(fileName);
    EXPECT_EQ(fileName, result);
}

/**
 * @tc.name: AccountLogFileName004
 * @tc.desc: splice filename
 * @tc.type: FUNC
 * @tc.require: issueI5RWXN
 */
HWTEST_F(AccountLogTest, AccountLogFileName004, TestSize.Level0)
{
    /**
     * @tc.steps: step1. Constructor fileName and execeptStr strings
     */
    std::string fileName = "\\test.cpp";
    std::string exceptStr = "test.cpp";

    /**
     * @tc.steps: step2. Call the GetBriefFileName method to split the string
     * @tc.expected: step2. The result string is "test.cpp"
     */
    std::string result = AccountLogWrapper::GetBriefFileName(fileName);
    EXPECT_EQ(exceptStr, result);
}