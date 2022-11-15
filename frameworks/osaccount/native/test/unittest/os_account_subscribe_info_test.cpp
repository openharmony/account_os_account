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

#define private public
#include "os_account_subscribe_info.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string STRING_NAME = "account";
}  // namespace
class OsAccountSubscribeInfoTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

void OsAccountSubscribeInfoTest::SetUpTestCase(void)
{}

void OsAccountSubscribeInfoTest::TearDownTestCase(void)
{}

void OsAccountSubscribeInfoTest::SetUp(void)
{}

void OsAccountSubscribeInfoTest::TearDown(void)
{}

/**
 * @tc.name: OsAccountSubscribeInfoTestTest01
 * @tc.desc: Test osaccount subscribe info marshalling/unmarshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountSubscribeInfoTest, OsAccountSubscribeInfoTestTest01, TestSize.Level0)
{
    OsAccountSubscribeInfo osAccountSubscribeInfo(ACTIVED, STRING_NAME);

    Parcel parcel;
    EXPECT_EQ(true, osAccountSubscribeInfo.Marshalling(parcel));

    std::shared_ptr<OsAccountSubscribeInfo> readedData(OsAccountSubscribeInfo::Unmarshalling(parcel));
    EXPECT_NE(nullptr, readedData);

    EXPECT_EQ(osAccountSubscribeInfo.osAccountSubscribeType_, readedData->osAccountSubscribeType_);
    EXPECT_EQ(osAccountSubscribeInfo.name_, readedData->name_);
}