/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <memory>
#include <gtest/gtest.h>
#include "account_error_no.h"
#define private public
#include "account_file_operator.h"
#undef private

namespace OHOS {
namespace AccountSA {
using namespace testing::ext;
using namespace OHOS::AccountSA;
using namespace OHOS;
using namespace AccountSA;

class AccountFileOperatorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

public:
    AccountFileOperator  osAccountFileOperator_;
};

void AccountFileOperatorTest::SetUpTestCase(void)
{}

void AccountFileOperatorTest::TearDownTestCase(void)
{}

void AccountFileOperatorTest::SetUp(void)
{}

void AccountFileOperatorTest::TearDown(void)
{}

/**
 * @tc.name: AccountFileOperatorTest001
 * @tc.desc: Test AccountFileOperator  IsExistDir
 * @tc.type: FUNC
 * @tc.require: SR000GGVFI
 */
HWTEST_F(AccountFileOperatorTest, AccountFileOperatorTest001, TestSize.Level0)
{
    EXPECT_EQ(osAccountFileOperator_.IsExistDir("/system/etc/account"), true);
    EXPECT_EQ(osAccountFileOperator_.IsExistDir("/file"), false);
}

/**
 * @tc.name: AccountFileOperatorTest002
 * @tc.desc: Test AccountFileOperator  IsExistFile
 * @tc.type: FUNC
 * @tc.require: SR000GGVFI
 */
HWTEST_F(AccountFileOperatorTest, AccountFileOperatorTest002, TestSize.Level0)
{
    EXPECT_EQ(osAccountFileOperator_.IsExistFile("/system/etc/account/osaccount_constraints.json"), true);
    EXPECT_EQ(osAccountFileOperator_.IsExistFile("/osaccount_constraints.json"), false);
}

/**
 * @tc.name: AccountFileOperatorTest003
 * @tc.desc: Test CreateDir
 * @tc.type: FUNC
 * @tc.require: SR000GGVFI
 */
HWTEST_F(AccountFileOperatorTest, AccountFileOperatorTest003, TestSize.Level0)
{
    EXPECT_EQ(osAccountFileOperator_.CreateDir("/data/system/users/0"), ERR_OK);
    EXPECT_EQ(osAccountFileOperator_.CreateDir("/data/system/users/100/file/instr"), ERR_OK);
}

/**
 * @tc.name: AccountFileOperatorTest004
 * @tc.desc: Test LoadDataByLocalFuzzyQuery
 * @tc.type: FUNC
 * @tc.require: SR000GGVFI
 */
HWTEST_F(AccountFileOperatorTest, AccountFileOperatorTest004, TestSize.Level0)
{
    osAccountFileOperator_.CreateDir("/data/system/users/1");
    EXPECT_EQ(osAccountFileOperator_.InputFileByPathAndContent("/data/system/users/1/1.txt", "file"), ERR_OK);
    std::string str;
    EXPECT_EQ(osAccountFileOperator_.GetFileContentByPath("/data/system/users/1/1.txt", str), ERR_OK);
    EXPECT_EQ(str, "file");
}

/**
 * @tc.name: AccountFileOperatorTest005
 * @tc.desc: Test DeleteDirOrFile
 * @tc.type: FUNC
 * @tc.require: SR000GGVFI
 */
HWTEST_F(AccountFileOperatorTest, AccountFileOperatorTest005, TestSize.Level0)
{
    osAccountFileOperator_.CreateDir("/data/system/users/2");
    osAccountFileOperator_.InputFileByPathAndContent("/data/system/users/2/1.txt", "file");
    EXPECT_EQ(osAccountFileOperator_.DeleteDirOrFile("/data/system/users/2"), ERR_OK);
}

/**
 * @tc.name: AccountFileOperatorTest006
 * @tc.desc: Test GetFileContentByPath
 * @tc.type: FUNC
 * @tc.require: SR000GGVFI
 */
HWTEST_F(AccountFileOperatorTest, AccountFileOperatorTest006, TestSize.Level0)
{
    std::string str;
    EXPECT_EQ(
        osAccountFileOperator_.GetFileContentByPath("/system/etc/account/osaccount_constraints.json", str), ERR_OK);
    GTEST_LOG_(INFO) << str;
}
}  // namespace AccountSA
}  // namespace OHOS