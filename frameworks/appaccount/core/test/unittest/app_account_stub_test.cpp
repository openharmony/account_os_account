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

#include "account_error_no.h"
#include "mock_app_account_stub.h"
#include "iremote_object.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string STRING_EMPTY = "";
const std::string STRING_NAME = "name";
const std::string STRING_EXTRA_INFO = "extra_info";
const std::string STRING_NAME_OUT_OF_RANGE =
    "name_out_of_range_"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
const std::string STRING_EXTRA_INFO_OUT_OF_RANGE =
    "extra_info_out_of_range_"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
    "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
const std::string STRING_NAME_EMPTY = STRING_EMPTY;
const std::string STRING_EXTRA_INFO_EMPTY = STRING_EMPTY;
const std::string STRING_OWNER = "com.example.owner";
}  // namespace

class AppAccountStubTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;

    sptr<IRemoteObject> MakeMockObjects(void) const;

    sptr<IAppAccount> mockProxy_;
};

sptr<IRemoteObject> AppAccountStubTest::MakeMockObjects(void) const
{
    // mock a stub
    auto mockStub = sptr<IRemoteObject>(new MockAppAccountStub());

    return mockStub;
}

void AppAccountStubTest::SetUpTestCase(void)
{}

void AppAccountStubTest::TearDownTestCase(void)
{}

void AppAccountStubTest::SetUp(void)
{
    // mock a proxy
    mockProxy_ = iface_cast<IAppAccount>(MakeMockObjects());
}

void AppAccountStubTest::TearDown(void)
{}

/**
 * @tc.number: AppAccountStub_AddAccount_0100
 * @tc.name: AddAccount
 * @tc.desc: Add an app account with valid data.
 */
HWTEST_F(AppAccountStubTest, AppAccountStub_AddAccount_0100, Function | MediumTest | Level1)
{
    ErrCode result = mockProxy_->AddAccount(STRING_NAME, STRING_EXTRA_INFO);

    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccountStub_AddAccount_0200
 * @tc.name: AddAccount
 * @tc.desc: Add an app account with empty data.
 */
HWTEST_F(AppAccountStubTest, AppAccountStub_AddAccount_0200, Function | MediumTest | Level1)
{
    ErrCode result = mockProxy_->AddAccount(STRING_NAME_EMPTY, STRING_EXTRA_INFO);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_NAME_IS_EMPTY);
}

/**
 * @tc.number: AppAccountStub_AddAccount_0300
 * @tc.name: AddAccount
 * @tc.desc: Add an app account with empty data.
 */
HWTEST_F(AppAccountStubTest, AppAccountStub_AddAccount_0300, Function | MediumTest | Level1)
{
    ErrCode result = mockProxy_->AddAccount(STRING_NAME, STRING_EXTRA_INFO_EMPTY);

    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccountStub_AddAccount_0400
 * @tc.name: AddAccount
 * @tc.desc: Add an app account with invalid data.
 */
HWTEST_F(AppAccountStubTest, AppAccountStub_AddAccount_0400, Function | MediumTest | Level1)
{
    ErrCode result = mockProxy_->AddAccount(STRING_NAME_OUT_OF_RANGE, STRING_EXTRA_INFO);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_NAME_OUT_OF_RANGE);
}

/**
 * @tc.number: AppAccountStub_AddAccount_0500
 * @tc.name: AddAccount
 * @tc.desc: Add an app account with invalid data.
 */
HWTEST_F(AppAccountStubTest, AppAccountStub_AddAccount_0500, Function | MediumTest | Level1)
{
    ErrCode result = mockProxy_->AddAccount(STRING_NAME, STRING_EXTRA_INFO_OUT_OF_RANGE);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_EXTRA_INFO_OUT_OF_RANGE);
}

/**
 * @tc.number: AppAccountStub_DeleteAccount_0100
 * @tc.name: DeleteAccount
 * @tc.desc: Delete an app account with valid data.
 */
HWTEST_F(AppAccountStubTest, AppAccountStub_DeleteAccount_0100, Function | MediumTest | Level1)
{
    ErrCode result = mockProxy_->DeleteAccount(STRING_NAME);

    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccountStub_DeleteAccount_0200
 * @tc.name: DeleteAccount
 * @tc.desc: Delete an app account with empty data.
 */
HWTEST_F(AppAccountStubTest, AppAccountStub_DeleteAccount_0200, Function | MediumTest | Level1)
{
    ErrCode result = mockProxy_->DeleteAccount(STRING_NAME_EMPTY);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_NAME_IS_EMPTY);
}

/**
 * @tc.number: AppAccountStub_DeleteAccount_0300
 * @tc.name: DeleteAccount
 * @tc.desc: Delete an app account with invalid data.
 */
HWTEST_F(AppAccountStubTest, AppAccountStub_DeleteAccount_0300, Function | MediumTest | Level1)
{
    ErrCode result = mockProxy_->DeleteAccount(STRING_NAME_OUT_OF_RANGE);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_NAME_OUT_OF_RANGE);
}

/**
 * @tc.number: AppAccountStub_SubscribeAppAccount_0100
 * @tc.name: SubscribeAppAccount
 * @tc.desc: Subscribe app accounts with valid data.
 */
HWTEST_F(AppAccountStubTest, AppAccountStub_SubscribeAppAccount_0100, Function | MediumTest | Level1)
{
    ErrCode result = -1;

    // make owners
    vector<std::string> owners;
    owners.emplace_back(STRING_OWNER);

    // make subcribe info
    AppAccountSubscribeInfo subscribeInfo;
    result = subscribeInfo.SetOwners(owners);

    EXPECT_EQ(result, ERR_OK);

    sptr<IRemoteObject> appAccountEventListener = nullptr;
    result = mockProxy_->SubscribeAppAccount(subscribeInfo, appAccountEventListener);

    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.number: AppAccountStub_SubscribeAppAccount_0200
 * @tc.name: SubscribeAppAccount
 * @tc.desc: Subscribe app accounts with invalid data.
 */
HWTEST_F(AppAccountStubTest, AppAccountStub_SubscribeAppAccount_0200, Function | MediumTest | Level1)
{
    ErrCode result = -1;

    // make owners
    vector<std::string> owners;

    // make subcribe info
    AppAccountSubscribeInfo subscribeInfo;
    result = subscribeInfo.SetOwners(owners);

    EXPECT_EQ(result, ERR_OK);

    sptr<IRemoteObject> appAccountEventListener = nullptr;
    result = mockProxy_->SubscribeAppAccount(subscribeInfo, appAccountEventListener);

    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_OWNERS_ARE_EMPTY);
}
