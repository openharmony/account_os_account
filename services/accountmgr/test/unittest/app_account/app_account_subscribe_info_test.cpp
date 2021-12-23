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

#define private public
#include "app_account_subscribe_info.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string STRING_OWNER = "com.example.owner";
}  // namespace

class AppAccountSubscribeInfoTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

void AppAccountSubscribeInfoTest::SetUpTestCase(void)
{}

void AppAccountSubscribeInfoTest::TearDownTestCase(void)
{}

void AppAccountSubscribeInfoTest::SetUp(void)
{}

void AppAccountSubscribeInfoTest::TearDown(void)
{}

/**
 * @tc.name: AppAccountSubscribeInfo_GetOwners_0100
 * @tc.desc: Get owners with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFT
 */
HWTEST_F(AppAccountSubscribeInfoTest, AppAccountSubscribeInfo_GetOwners_0100, TestSize.Level1)
{
    // make owners
    std::vector<std::string> owners;
    owners.emplace_back(STRING_OWNER);

    // make subscribe info with owners
    AppAccountSubscribeInfo subscribeInfo(owners);

    // get owners
    std::vector<std::string> ownersFromSubscribeInfo;
    ErrCode result = subscribeInfo.GetOwners(ownersFromSubscribeInfo);
    EXPECT_EQ(result, ERR_OK);

    // check size of owners
    EXPECT_EQ(owners.size(), ownersFromSubscribeInfo.size());
    // check the first owner name
    EXPECT_EQ(owners.front(), ownersFromSubscribeInfo.front());
}

/**
 * @tc.name: AppAccountSubscribeInfo_SetOwners_0100
 * @tc.desc: Set owners with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFT
 */
HWTEST_F(AppAccountSubscribeInfoTest, AppAccountSubscribeInfo_SetOwners_0100, TestSize.Level1)
{
    // make owners
    std::vector<std::string> owners;
    owners.emplace_back(STRING_OWNER);

    // make subscribe info
    AppAccountSubscribeInfo subscribeInfo;

    // set owners
    ErrCode result = subscribeInfo.SetOwners(owners);
    EXPECT_EQ(result, ERR_OK);

    // check size of owners
    EXPECT_EQ(owners.size(), subscribeInfo.owners_.size());
    // check the first owner name
    EXPECT_EQ(owners.front(), subscribeInfo.owners_.front());
}

/**
 * @tc.name: AppAccountSubscribeInfo_Marshalling_0100
 * @tc.desc: Marshalling Unmarshalling with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFT
 */
HWTEST_F(AppAccountSubscribeInfoTest, AppAccountSubscribeInfo_Marshalling_0100, TestSize.Level0)
{
    // make owners
    std::vector<std::string> owners;
    owners.emplace_back(STRING_OWNER);

    // make subscribe info with owners
    AppAccountSubscribeInfo subscribeInfo(owners);

    Parcel parcel;
    // marshalling
    EXPECT_EQ(subscribeInfo.Marshalling(parcel), true);

    // unmarshalling
    auto subscribeInfoPtr = AppAccountSubscribeInfo::Unmarshalling(parcel);
    EXPECT_NE(subscribeInfoPtr, nullptr);

    // get owners
    std::vector<std::string> ownersFromSubscribeInfo;
    ErrCode result = subscribeInfoPtr->GetOwners(ownersFromSubscribeInfo);
    EXPECT_EQ(result, ERR_OK);

    // check size of owners
    EXPECT_EQ(owners.size(), ownersFromSubscribeInfo.size());
    // check the first owner name
    EXPECT_EQ(owners.front(), ownersFromSubscribeInfo.front());
}
