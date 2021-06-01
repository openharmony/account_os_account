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

#include <gtest/gtest.h>

#include "account_proxy.h"
#include "iaccount.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "ohos_account_kits.h"
#include "system_ability_definition.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

class AccountMgrInnerSdkFuncTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AccountMgrInnerSdkFuncTest::SetUpTestCase(void)
{}

void AccountMgrInnerSdkFuncTest::TearDownTestCase(void)
{}

void AccountMgrInnerSdkFuncTest::SetUp(void)
{}

void AccountMgrInnerSdkFuncTest::TearDown(void)
{}

/**
 * @tc.name: GetDeviceAccountIdTest
 * @tc.desc: get device account info test
 * @tc.type: FUNC
 * @tc.require: AR000CUF64
*/
HWTEST_F(AccountMgrInnerSdkFuncTest, GetDeviceAccountIdTest, TestSize.Level0)
{
    std::int32_t id;
    auto ret = OhosAccountKits::GetInstance().QueryDeviceAccountId(id);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.name: GetOhosAccountInfoTest
 * @tc.desc: get ohos account info test
 * @tc.type: FUNC
 * @tc.require: AR000CUF64
 */
HWTEST_F(AccountMgrInnerSdkFuncTest, GetOhosAccountInfoTest, TestSize.Level0)
{
    auto ret = OhosAccountKits::GetInstance().QueryOhosAccountInfo();
    EXPECT_EQ(true, ret.first);
}

/**
 * @tc.name: GetDefaultOhosAccountInfoTest
 * @tc.desc: get default ohos account info test
 * @tc.type: FUNC
 * @tc.require: AR000DIJ27
 */
HWTEST_F(AccountMgrInnerSdkFuncTest, GetDefaultOhosAccountInfoTest, TestSize.Level1)
{
    std::unique_ptr<OhosAccountInfo> accountInfo = std::make_unique<OhosAccountInfo>();
    ASSERT_TRUE(accountInfo != nullptr);
}

/**
 * @tc.name: UidTranslateTest
 * @tc.desc: translate uid to deviceAccountId
 * @tc.type: FUNC
 * @tc.require: AR000CUF64
 */
HWTEST_F(AccountMgrInnerSdkFuncTest, UidTranslateTest, TestSize.Level0)
{
    std::int32_t uid = 1000000;
    auto ret = OhosAccountKits::GetInstance().GetDeviceAccountIdByUID(uid);
    EXPECT_EQ(10, ret);
}
