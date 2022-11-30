/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <cstdint>
#include <iosfwd>
#include <string>

#include <gtest/gtest.h>
#include "gtest/gtest-message.h"
#include "gtest/gtest-test-part.h"
#include "gtest/hwext/gtest-ext.h"
#include "gtest/hwext/gtest-tag.h"
#include "account_file_operator.h"

using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS;

class AccountFileOperatorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AccountFileOperatorTest::SetUpTestCase() {}

void AccountFileOperatorTest::TearDownTestCase() {}

void AccountFileOperatorTest::SetUp()
{
}

void AccountFileOperatorTest::TearDown() {}

/**
 * @tc.name: AccountFileOperator001
 * @tc.desc: Test invalid path
 * @tc.type: FUNC
 * @tc.require: issueI5RWXN
 */
HWTEST_F(AccountFileOperatorTest, AccountFileOperator001, TestSize.Level0)
{
    auto accountFileOperator_ = std::make_shared<AccountFileOperator>();
    EXPECT_EQ(accountFileOperator_->DeleteDirOrFile("../../xx"), OHOS::ERR_OSACCOUNT_SERVICE_FILE_DELE_ERROR);
    EXPECT_EQ(accountFileOperator_->IsExistFile(""), false);
    EXPECT_EQ(accountFileOperator_->IsJsonFormat("../&*&"), false);
    EXPECT_EQ(accountFileOperator_->IsExistDir(""), false);
    EXPECT_EQ(
        accountFileOperator_->InputFileByPathAndContent("/test1", "test"), ERR_OSACCOUNT_SERVICE_FILE_FIND_DIR_ERROR);
}
