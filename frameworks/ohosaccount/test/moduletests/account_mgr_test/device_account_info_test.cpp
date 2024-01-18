/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "string_ex.h"
#include "message_parcel.h"
#include "device_account_info.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::int32_t TEST_ACCOUNT_ID = 11;
const std::string TEST_ACCOUNT_NAME = "test_name";
}

class DeviceAccountInfoTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DeviceAccountInfoTest::SetUpTestCase(void)
{}

void DeviceAccountInfoTest::TearDownTestCase(void)
{}

void DeviceAccountInfoTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void DeviceAccountInfoTest::TearDown(void)
{}

/**
 * @tc.name: DeviceAccountInfoTest_001
 * @tc.desc: test class DeviceAccountInfo
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(DeviceAccountInfoTest, DeviceAccountInfoTest_001, TestSize.Level0)
{
    DeviceAccountInfo deviceAccountInfoSrc;
    deviceAccountInfoSrc.id_ = TEST_ACCOUNT_ID;
    deviceAccountInfoSrc.type_ = DeviceAccountType::DEVICE_ACCOUNT_TYPE_OWNER;
    deviceAccountInfoSrc.name_ = TEST_ACCOUNT_NAME;
    deviceAccountInfoSrc.state_ = DeviceAccountState::DEVICE_ACCOUNT_STATE_INVALID;
    MessageParcel data;
    deviceAccountInfoSrc.WriteDataToParcel(data);

    DeviceAccountInfo deviceAccountInfoTar;
    deviceAccountInfoTar.ReadDataFromParcel(data);
    EXPECT_EQ(deviceAccountInfoTar.id_, TEST_ACCOUNT_ID);
    EXPECT_EQ(deviceAccountInfoTar.type_, DeviceAccountType::DEVICE_ACCOUNT_TYPE_OWNER);
    EXPECT_EQ(deviceAccountInfoTar.name_, TEST_ACCOUNT_NAME);
    EXPECT_EQ(deviceAccountInfoTar.state_, DeviceAccountState::DEVICE_ACCOUNT_STATE_INVALID);
}