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

#include <gmock/gmock.h>
#include "ohos_account_kits.h"

namespace OHOS {
namespace AccountTest {
namespace {
const std::string TEST_ACCOUNT_NAME = "TestAccountNameOS";
const std::string TEST_ACCOUNT_UID = "123456789os";
}

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AccountSA;

class AccountOhosProxyMockTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

void AccountOhosProxyMockTest::SetUpTestCase(void)
{}

void AccountOhosProxyMockTest::TearDownTestCase(void)
{}

void AccountOhosProxyMockTest::SetUp(void)
{}

void AccountOhosProxyMockTest::TearDown(void)
{}

/**
 * @tc.name: GetOhosAccountInfoTest
 * @tc.desc: Test with proxy is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOhosProxyMockTest, GetOhosAccountInfoTest, TestSize.Level0)
{
    auto ret = OhosAccountKits::GetInstance().QueryOhosAccountInfo();
    ASSERT_EQ(false, ret.first);
}

/**
 * @tc.name: GetOhosAccountInfoByUserIdTest
 * @tc.desc: Test with proxy is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOhosProxyMockTest, GetOhosAccountInfoByUserIdTest, TestSize.Level0)
{
    OhosAccountInfo accountInfo;
    std::int32_t testUserId = 200; // 200 is test user id.
    ErrCode ret = OhosAccountKits::GetInstance().GetOhosAccountInfoByUserId(testUserId, accountInfo);
    ASSERT_EQ(ERR_ACCOUNT_ZIDL_ACCOUNT_PROXY_ERROR, ret);
}

/**
 * @tc.name: QueryOhosAccountInfoByUserIdTest
 * @tc.desc: Test with proxy is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOhosProxyMockTest, QueryOhosAccountInfoByUserIdTest, TestSize.Level0)
{
    std::int32_t testUserId = 200; // 200 is test user id.
    auto ret = OhosAccountKits::GetInstance().QueryOhosAccountInfoByUserId(testUserId);
    ASSERT_EQ(false, ret.first);
}

/**
 * @tc.name: UpdateOhosAccountInfoTest
 * @tc.desc: Test with proxy is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOhosProxyMockTest, UpdateOhosAccountInfoTest, TestSize.Level0)
{
    bool ret = OhosAccountKits::GetInstance().UpdateOhosAccountInfo(
        TEST_ACCOUNT_NAME, TEST_ACCOUNT_UID, OHOS_ACCOUNT_EVENT_LOGIN);
    ASSERT_EQ(false, ret);
}

/**
 * @tc.name: SetOhosAccountInfoTest
 * @tc.desc: Test with proxy is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOhosProxyMockTest, SetOhosAccountInfoTest, TestSize.Level0)
{
    OhosAccountInfo accountInfo;
    accountInfo.name_ = "TestAccountName";
    ErrCode ret = OhosAccountKits::GetInstance().SetOhosAccountInfo(accountInfo, OHOS_ACCOUNT_EVENT_LOGIN);
    ASSERT_EQ(ERR_ACCOUNT_ZIDL_ACCOUNT_PROXY_ERROR, ret);
}

/**
 * @tc.name: QueryDeviceAccountIdTest
 * @tc.desc: Test with proxy is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountOhosProxyMockTest, QueryDeviceAccountIdTest, TestSize.Level0)
{
    std::int32_t id;
    ErrCode ret = OhosAccountKits::GetInstance().QueryDeviceAccountId(id);
    ASSERT_EQ(ERR_ACCOUNT_ZIDL_ACCOUNT_PROXY_ERROR, ret);
}
}  // namespace AccountTest
}  // namespace OHOS