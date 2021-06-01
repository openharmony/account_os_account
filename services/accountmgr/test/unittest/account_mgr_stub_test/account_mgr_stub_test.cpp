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
#include <ipc_types.h>

#include "mock_account_mgr_service.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;
class AccountMgrStubTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AccountMgrStubTest::SetUpTestCase() {}

void AccountMgrStubTest::TearDownTestCase() {}

void AccountMgrStubTest::SetUp() {}

void AccountMgrStubTest::TearDown() {}

/**
 * @tc.name: AccountStubQuitTipsTest001
 * @tc.desc: test QUERY_OHOS_ACCOUNT_QUIT_TIPS cmd process.
 * @tc.type: FUNC
 * @tc.require: AR000CVBCA SR000CVBC9
 */
HWTEST_F(AccountMgrStubTest, AccountStubQuitTipsTest001, TestSize.Level0)
{
    /**
     * @tc.steps: step1. create mock instance and send QUERY_OHOS_ACCOUNT_QUIT_TIPS cmd
     * @tc.expected: step1. result success, title and content are empty
     */
    MessageParcel inData;
    MessageParcel reply;
    MessageOption msgOption;
    MockAccountMgrService mockSrv{};
    inData.WriteInterfaceToken(AccountStub::GetDescriptor());
    auto ret = mockSrv.OnRemoteRequest(AccountStub::QUERY_OHOS_ACCOUNT_QUIT_TIPS, inData, reply, msgOption);
    EXPECT_EQ(ret, ERR_OK);
    std::u16string title = reply.ReadString16();
    std::u16string content = reply.ReadString16();
    EXPECT_EQ(true, title.empty());
    EXPECT_EQ(true, content.empty());
}

/**
 * @tc.name: AccountStubQueryOhosInfoTest002
 * @tc.desc: test QUERY_OHOS_ACCOUNT_INFO cmd process.
 * @tc.type: FUNC
 * @tc.require: AR000CVBCC SR000CVBCB
 */
HWTEST_F(AccountMgrStubTest, AccountStubQueryOhosInfoTest002, TestSize.Level0)
{
    /**
     * @tc.steps: step1. create mock instance and send QUERY_OHOS_ACCOUNT_QUIT_TIPS cmd
     * @tc.expected: step1. result success, title and content are not empty
     */
    MessageParcel data;
    MessageParcel reply;
    MessageOption msgOption;
    MockAccountMgrService mockSrv{};
    data.WriteInterfaceToken(AccountStub::GetDescriptor());
    auto ret = mockSrv.OnRemoteRequest(AccountStub::QUERY_OHOS_ACCOUNT_INFO, data, reply, msgOption);
    EXPECT_EQ(ret, ERR_OK);
    std::u16string name = reply.ReadString16();
    std::u16string uid = reply.ReadString16();
    std::int32_t status = reply.ReadInt32();
    EXPECT_EQ(Str16ToStr8(name), DEFAULT_OHOS_ACCOUNT_NAME);
    EXPECT_EQ(Str16ToStr8(uid), DEFAULT_OHOS_ACCOUNT_UID);
    EXPECT_EQ(status, ACCOUNT_STATE_UNBOUND);
}

/**
 * @tc.name: AccountStubQueryDeviceAccountIdTest003
 * @tc.desc: test QUERY_DEVICE_ACCOUNT_ID_FROM_UID cmd process.
 * @tc.type: FUNC
 * @tc.require: AR000CVBCE SR000CVBCD
 */
HWTEST_F(AccountMgrStubTest, AccountStubQueryDeviceAccountIdTest003, TestSize.Level0)
{
    /**
     * @tc.steps: step1. Init, create mock instance
     * @tc.expected: None
     */
    MockAccountMgrService mockSrv{};
    std::int32_t testUid = 1000000;
    std::int32_t expectedId = 10;

    MessageParcel inData;
    inData.WriteInterfaceToken(AccountStub::GetDescriptor());
    /**
     * @tc.steps: step2. write UID and send QUERY_DEVICE_ACCOUNT_ID_FROM_UID cmd
     * @tc.expected: result is ok, and expected device account id is 10:  expectedId = testUid/100000
     */
    inData.WriteInt32(testUid);
    MessageParcel outData;
    MessageOption option;
    auto ret = mockSrv.OnRemoteRequest(AccountStub::QUERY_DEVICE_ACCOUNT_ID_FROM_UID, inData, outData, option);
    EXPECT_EQ(ret, ERR_OK);
    auto result = outData.ReadInt32();
    EXPECT_EQ(result, expectedId);
}

/**
 * @tc.name: AccountStubInvalidCmdTest004
 * @tc.desc: test INVALID cmd process.
 * @tc.type: FUNC
 * @tc.require: AR000CUF5N SR000CUF5L
 */
HWTEST_F(AccountMgrStubTest, AccountStubInvalidCmdTest004, TestSize.Level0)
{
    /**
     * @tc.steps: step1. Init, create mock instance and send an invalid cmd
     * @tc.expected: result is failure
     */
    MessageParcel inData;
    MessageParcel outData;
    MessageOption msgOption;
    MockAccountMgrService mockSrv{};
    inData.WriteInterfaceToken(AccountStub::GetDescriptor());
    auto ret = mockSrv.OnRemoteRequest(0, inData, outData, msgOption);
    EXPECT_NE(ret, ERR_OK);
}
