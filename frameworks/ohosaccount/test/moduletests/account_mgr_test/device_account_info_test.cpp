/*
 * Copyright (c) 2023-2026 Huawei Device Co., Ltd.
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
#include "account_info.h"
#include "distributed_account_subscribe_callback.h"
#include "parcel.h"
#include "want.h"
#include "int_wrapper.h"

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
HWTEST_F(DeviceAccountInfoTest, DeviceAccountInfoTest_001, TestSize.Level3)
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

/**
 * @tc.name: DeviceAccountInfoTest_002
 * @tc.desc: test DeviceAccountInfo default constructor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceAccountInfoTest, DeviceAccountInfoTest_002, TestSize.Level3)
{
    DeviceAccountInfo deviceAccountInfo;
    EXPECT_EQ(deviceAccountInfo.id_, DEVICE_ACCOUNT_ID_INVALID);
    EXPECT_EQ(deviceAccountInfo.type_, DeviceAccountType::DEVICE_ACCOUNT_TYPE_INVALID);
    EXPECT_TRUE(deviceAccountInfo.name_.empty());
    EXPECT_TRUE(deviceAccountInfo.iconPath_.empty());
    EXPECT_EQ(deviceAccountInfo.state_, DeviceAccountState::DEVICE_ACCOUNT_STATE_INVALID);
    EXPECT_EQ(deviceAccountInfo.flags_, 0);
    EXPECT_EQ(deviceAccountInfo.creationTime_, 0);
    EXPECT_EQ(deviceAccountInfo.lastLoginTime_, 0);
    EXPECT_FALSE(deviceAccountInfo.guestToRemoved_);
}

/**
 * @tc.name: DeviceAccountInfoTest_003
 * @tc.desc: test DeviceAccountInfo constructor with 3 parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceAccountInfoTest, DeviceAccountInfoTest_003, TestSize.Level3)
{
    std::string testName = "test_account";
    std::string testPath = "/test/path";
    DeviceAccountInfo deviceAccountInfo(TEST_ACCOUNT_ID, DeviceAccountType::DEVICE_ACCOUNT_TYPE_OWNER, testName);
    EXPECT_EQ(deviceAccountInfo.id_, TEST_ACCOUNT_ID);
    EXPECT_EQ(deviceAccountInfo.type_, DeviceAccountType::DEVICE_ACCOUNT_TYPE_OWNER);
    EXPECT_EQ(deviceAccountInfo.name_, testName);
    EXPECT_TRUE(deviceAccountInfo.iconPath_.empty());
    EXPECT_EQ(deviceAccountInfo.state_, DeviceAccountState::DEVICE_ACCOUNT_STATE_INVALID);
    EXPECT_EQ(deviceAccountInfo.flags_, 0);
    EXPECT_EQ(deviceAccountInfo.creationTime_, 0);
    EXPECT_EQ(deviceAccountInfo.lastLoginTime_, 0);
    EXPECT_FALSE(deviceAccountInfo.guestToRemoved_);
}

/**
 * @tc.name: DeviceAccountInfoTest_004
 * @tc.desc: test DeviceAccountInfo constructor with 4 parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceAccountInfoTest, DeviceAccountInfoTest_004, TestSize.Level3)
{
    std::string testName = "test_account";
    std::string testPath = "/test/path";
    DeviceAccountInfo deviceAccountInfo(TEST_ACCOUNT_ID,
        DeviceAccountType::DEVICE_ACCOUNT_TYPE_OWNER, testName, testPath);
    EXPECT_EQ(deviceAccountInfo.id_, TEST_ACCOUNT_ID);
    EXPECT_EQ(deviceAccountInfo.type_, DeviceAccountType::DEVICE_ACCOUNT_TYPE_OWNER);
    EXPECT_EQ(deviceAccountInfo.name_, testName);
    EXPECT_EQ(deviceAccountInfo.iconPath_, testPath);
    EXPECT_EQ(deviceAccountInfo.state_, DeviceAccountState::DEVICE_ACCOUNT_STATE_INVALID);
    EXPECT_EQ(deviceAccountInfo.flags_, 0);
    EXPECT_EQ(deviceAccountInfo.creationTime_, 0);
    EXPECT_EQ(deviceAccountInfo.lastLoginTime_, 0);
    EXPECT_FALSE(deviceAccountInfo.guestToRemoved_);
}

/**
 * @tc.name: DeviceAccountInfoTest_005
 * @tc.desc: test DeviceAccountInfo operator==
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceAccountInfoTest, DeviceAccountInfoTest_005, TestSize.Level3)
{
    DeviceAccountInfo info1(TEST_ACCOUNT_ID, DeviceAccountType::DEVICE_ACCOUNT_TYPE_OWNER, TEST_ACCOUNT_NAME);
    DeviceAccountInfo info2(TEST_ACCOUNT_ID, DeviceAccountType::DEVICE_ACCOUNT_TYPE_NORMAL, "other_name");
    EXPECT_TRUE(info1 == info2);

    DeviceAccountInfo info3(999, DeviceAccountType::DEVICE_ACCOUNT_TYPE_OWNER, TEST_ACCOUNT_NAME);
    EXPECT_FALSE(info1 == info3);

    DeviceAccountInfo info4;
    EXPECT_FALSE(info1 == info4);
}

/**
 * @tc.name: OhosAccountInfoTest_001
 * @tc.desc: test OhosAccountInfo constructor with 3 parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceAccountInfoTest, OhosAccountInfoTest_001, TestSize.Level3)
{
    std::string testName = "test_name";
    std::string testUid = "test_uid";
    std::int32_t testStatus = ACCOUNT_STATE_LOGIN;
    OhosAccountInfo ohosAccountInfo(testName, testUid, testStatus);
    EXPECT_EQ(ohosAccountInfo.name_, testName);
    EXPECT_EQ(ohosAccountInfo.uid_, testUid);
    EXPECT_EQ(ohosAccountInfo.status_, testStatus);
    EXPECT_TRUE(ohosAccountInfo.nickname_.empty());
    EXPECT_TRUE(ohosAccountInfo.avatar_.empty());
}

/**
 * @tc.name: OhosAccountInfoTest_002
 * @tc.desc: test OhosAccountInfo default constructor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceAccountInfoTest, OhosAccountInfoTest_002, TestSize.Level3)
{
    OhosAccountInfo ohosAccountInfo;
    EXPECT_TRUE(ohosAccountInfo.name_.empty());
    EXPECT_TRUE(ohosAccountInfo.uid_.empty());
    EXPECT_EQ(ohosAccountInfo.status_, ACCOUNT_STATE_UNBOUND);
    EXPECT_TRUE(ohosAccountInfo.nickname_.empty());
    EXPECT_TRUE(ohosAccountInfo.avatar_.empty());
}

/**
 * @tc.name: OhosAccountInfoTest_003
 * @tc.desc: test OhosAccountInfo GetRawUid and SetRawUid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceAccountInfoTest, OhosAccountInfoTest_003, TestSize.Level3)
{
    OhosAccountInfo ohosAccountInfo;
    std::string testRawUid = "test_raw_uid";
    ohosAccountInfo.SetRawUid(testRawUid);
    EXPECT_EQ(ohosAccountInfo.GetRawUid(), testRawUid);
}

/**
 * @tc.name: OhosAccountInfoTest_004
 * @tc.desc: test OhosAccountInfo IsValid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceAccountInfoTest, OhosAccountInfoTest_004, TestSize.Level3)
{
    OhosAccountInfo ohosAccountInfo;
    ohosAccountInfo.nickname_ = "test_nickname";
    ohosAccountInfo.avatar_ = "test_avatar";
    EXPECT_TRUE(ohosAccountInfo.IsValid());

    std::string longNickname(2000, 'a');
    ohosAccountInfo.nickname_ = longNickname;
    EXPECT_FALSE(ohosAccountInfo.IsValid());
}

/**
 * @tc.name: OhosAccountInfoTest_005
 * @tc.desc: test OhosAccountInfo Marshalling and Unmarshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceAccountInfoTest, OhosAccountInfoTest_005, TestSize.Level3)
{
    OhosAccountInfo ohosAccountInfoSrc("test_name", "test_uid", ACCOUNT_STATE_LOGIN);
    ohosAccountInfoSrc.nickname_ = "test_nickname";
    ohosAccountInfoSrc.avatar_ = "test_avatar";
    ohosAccountInfoSrc.SetRawUid("test_raw_uid");
    {
        AAFwk::WantParams wantParams;
        wantParams.SetParam("age", AAFwk::Integer::Box(123));
        AAFwk::Want want;
        want.SetParams(wantParams);
        ohosAccountInfoSrc.scalableData_ = want.ToString();
    }

    MessageParcel parcel;
    EXPECT_TRUE(ohosAccountInfoSrc.Marshalling(parcel));

    OhosAccountInfo *ohosAccountInfoTar = OhosAccountInfo::Unmarshalling(parcel);
    EXPECT_NE(ohosAccountInfoTar, nullptr);
}

/**
 * @tc.name: AccountInfoTest_001
 * @tc.desc: test AccountInfo default constructor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceAccountInfoTest, AccountInfoTest_001, TestSize.Level3)
{
    AccountInfo accountInfo;
    EXPECT_EQ(accountInfo.bindTime_, 0);
    EXPECT_EQ(accountInfo.userId_, 0);
    EXPECT_TRUE(accountInfo.digest_.empty());
    EXPECT_EQ(accountInfo.version_, ACCOUNT_VERSION_DEFAULT);
}

/**
 * @tc.name: AccountInfoTest_002
 * @tc.desc: test AccountInfo constructor with OhosAccountInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceAccountInfoTest, AccountInfoTest_002, TestSize.Level3)
{
    OhosAccountInfo ohosAccountInfo("test_name", "test_uid", ACCOUNT_STATE_LOGIN);
    AccountInfo accountInfo(ohosAccountInfo);
    EXPECT_EQ(accountInfo.ohosAccountInfo_.name_, "test_name");
    EXPECT_EQ(accountInfo.ohosAccountInfo_.uid_, "test_uid");
    EXPECT_EQ(accountInfo.bindTime_, 0);
    EXPECT_EQ(accountInfo.userId_, 0);
    EXPECT_TRUE(accountInfo.digest_.empty());
    EXPECT_EQ(accountInfo.version_, ACCOUNT_VERSION_DEFAULT);
}

/**
 * @tc.name: AccountInfoTest_003
 * @tc.desc: test AccountInfo operator==
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceAccountInfoTest, AccountInfoTest_003, TestSize.Level3)
{
    OhosAccountInfo ohosAccountInfo1("test_name", "test_uid", ACCOUNT_STATE_LOGIN);
    AccountInfo accountInfo1(ohosAccountInfo1);

    OhosAccountInfo ohosAccountInfo2("other_name", "test_uid", ACCOUNT_STATE_LOGIN);
    AccountInfo accountInfo2(ohosAccountInfo2);
    EXPECT_TRUE(accountInfo1 == accountInfo2);

    OhosAccountInfo ohosAccountInfo3("test_name", "other_uid", ACCOUNT_STATE_LOGIN);
    AccountInfo accountInfo3(ohosAccountInfo3);
    EXPECT_FALSE(accountInfo1 == accountInfo3);
}

/**
 * @tc.name: AccountInfoTest_004
 * @tc.desc: test AccountInfo clear
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceAccountInfoTest, AccountInfoTest_004, TestSize.Level3)
{
    OhosAccountInfo ohosAccountInfo("test_name", "test_uid", ACCOUNT_STATE_LOGIN);
    AccountInfo accountInfo(ohosAccountInfo);
    accountInfo.clear(ACCOUNT_STATE_LOGOFF);

    EXPECT_EQ(accountInfo.ohosAccountInfo_.name_, DEFAULT_OHOS_ACCOUNT_NAME);
    EXPECT_EQ(accountInfo.ohosAccountInfo_.uid_, DEFAULT_OHOS_ACCOUNT_UID);
    EXPECT_EQ(accountInfo.ohosAccountInfo_.status_, ACCOUNT_STATE_LOGOFF);
    EXPECT_TRUE(accountInfo.ohosAccountInfo_.nickname_.empty());
    EXPECT_TRUE(accountInfo.ohosAccountInfo_.avatar_.empty());
    EXPECT_TRUE(accountInfo.digest_.empty());
    EXPECT_EQ(accountInfo.bindTime_, 0);
}

/**
 * @tc.name: DistributedAccountEventDataTest_001
 * @tc.desc: test DistributedAccountEventData Marshalling and Unmarshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceAccountInfoTest, DistributedAccountEventDataTest_001, TestSize.Level3)
{
    DistributedAccountEventData eventDataSrc;
    eventDataSrc.id_ = TEST_ACCOUNT_ID;
    eventDataSrc.type_ = DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN;

    Parcel parcel;
    EXPECT_TRUE(eventDataSrc.Marshalling(parcel));

    DistributedAccountEventData *eventDataTar =
        DistributedAccountEventData::Unmarshalling(parcel);
    EXPECT_NE(eventDataTar, nullptr);
}

/**
 * @tc.name: DistributedAccountEventDataTest_002
 * @tc.desc: test DistributedAccountEventData operator==
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceAccountInfoTest, DistributedAccountEventDataTest_002, TestSize.Level3)
{
    DistributedAccountEventData eventData1;
    eventData1.id_ = TEST_ACCOUNT_ID;
    eventData1.type_ = DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN;

    DistributedAccountEventData eventData2;
    eventData2.id_ = TEST_ACCOUNT_ID;
    eventData2.type_ = DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGOUT;

    EXPECT_FALSE(eventData1 == eventData2);

    DistributedAccountEventData eventData3;
    eventData3.id_ = 999;
    eventData3.type_ = DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN;

    EXPECT_FALSE(eventData1 == eventData3);

    DistributedAccountEventData eventData4;
    eventData4.id_ = TEST_ACCOUNT_ID;
    eventData4.type_ = DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN;

    EXPECT_TRUE(eventData1 == eventData4);
}

/**
 * @tc.name: DistributedAccountSubscribeCallbackTest_001
 * @tc.desc: test DistributedAccountSubscribeCallback OnAccountsChanged
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceAccountInfoTest, DistributedAccountSubscribeCallbackTest_001, TestSize.Level3)
{
    class TestDistributedAccountSubscribeCallback : public DistributedAccountSubscribeCallback {
    public:
        TestDistributedAccountSubscribeCallback() : called_(false) {}
        void OnAccountsChanged(const DistributedAccountEventData &eventData) override
        {
            called_ = true;
            eventData_ = eventData;
        }
        bool called_;
        DistributedAccountEventData eventData_;
    };

    TestDistributedAccountSubscribeCallback callback;
    DistributedAccountEventData eventData;
    eventData.id_ = TEST_ACCOUNT_ID;
    eventData.type_ = DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN;

    callback.OnAccountsChanged(eventData);
    EXPECT_TRUE(callback.called_);
    EXPECT_EQ(callback.eventData_.id_, TEST_ACCOUNT_ID);
}

/**
 * @tc.name: DistributedAccountSpaceEventDataTest_001
 * @tc.desc: test DistributedAccountSubProfileEventData Marshalling and Unmarshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceAccountInfoTest, DistributedAccountSpaceEventDataTest_001, TestSize.Level3)
{
    DistributedAccountSubProfileEventData eventDataSrc;
    eventDataSrc.type_ = DistributedAccountSubProfileEventType::CREATED;
    eventDataSrc.osAccountId_ = TEST_ACCOUNT_ID;
    eventDataSrc.subspaceId_ = 200;
    eventDataSrc.previousSubspaceId_ = 150;

    Parcel parcel;
    EXPECT_TRUE(eventDataSrc.Marshalling(parcel));

    DistributedAccountSubProfileEventData *eventDataTar =
        DistributedAccountSubProfileEventData::Unmarshalling(parcel);
    EXPECT_NE(eventDataTar, nullptr);
    EXPECT_EQ(eventDataTar->type_, DistributedAccountSubProfileEventType::CREATED);
    EXPECT_EQ(eventDataTar->osAccountId_, TEST_ACCOUNT_ID);
    EXPECT_EQ(eventDataTar->subspaceId_, 200);
    EXPECT_EQ(eventDataTar->previousSubspaceId_, 150);
    delete eventDataTar;
}

/**
 * @tc.name: DistributedAccountSpaceEventDataTest_002
 * @tc.desc: test DistributedAccountSubProfileEventData operator==
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceAccountInfoTest, DistributedAccountSpaceEventDataTest_002, TestSize.Level3)
{
    DistributedAccountSubProfileEventData eventData1;
    eventData1.type_ = DistributedAccountSubProfileEventType::CREATED;
    eventData1.osAccountId_ = TEST_ACCOUNT_ID;
    eventData1.subspaceId_ = 200;
    eventData1.previousSubspaceId_ = 150;

    DistributedAccountSubProfileEventData eventData2;
    eventData2.type_ = DistributedAccountSubProfileEventType::SWITCHED;
    eventData2.osAccountId_ = TEST_ACCOUNT_ID;
    eventData2.subspaceId_ = 200;
    eventData2.previousSubspaceId_ = 150;

    EXPECT_FALSE(eventData1 == eventData2);

    DistributedAccountSubProfileEventData eventData3;
    eventData3.type_ = DistributedAccountSubProfileEventType::CREATED;
    eventData3.osAccountId_ = 999;
    eventData3.subspaceId_ = 200;
    eventData3.previousSubspaceId_ = 150;

    EXPECT_FALSE(eventData1 == eventData3);

    DistributedAccountSubProfileEventData eventData4;
    eventData4.type_ = DistributedAccountSubProfileEventType::CREATED;
    eventData4.osAccountId_ = TEST_ACCOUNT_ID;
    eventData4.subspaceId_ = 200;
    eventData4.previousSubspaceId_ = 150;

    EXPECT_TRUE(eventData1 == eventData4);
}

/**
 * @tc.name: DistributedAccountSpaceEventDataTest_003
 * @tc.desc: test DistributedAccountSubProfileEventData Marshalling for all event types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceAccountInfoTest, DistributedAccountSpaceEventDataTest_003, TestSize.Level3)
{
    std::vector<DistributedAccountSubProfileEventType> allTypes = {
        DistributedAccountSubProfileEventType::CREATED,
        DistributedAccountSubProfileEventType::DELETED,
        DistributedAccountSubProfileEventType::SWITCHING,
        DistributedAccountSubProfileEventType::SWITCHED
    };

    for (const auto& eventType : allTypes) {
        DistributedAccountSubProfileEventData eventDataSrc;
        eventDataSrc.type_ = eventType;
        eventDataSrc.osAccountId_ = TEST_ACCOUNT_ID;
        eventDataSrc.subspaceId_ = 200;
        eventDataSrc.previousSubspaceId_ = 150;

        Parcel parcel;
        EXPECT_TRUE(eventDataSrc.Marshalling(parcel));

        DistributedAccountSubProfileEventData *eventDataTar =
            DistributedAccountSubProfileEventData::Unmarshalling(parcel);
        EXPECT_NE(eventDataTar, nullptr);
        EXPECT_EQ(eventDataTar->type_, eventType);
        EXPECT_EQ(eventDataTar->osAccountId_, TEST_ACCOUNT_ID);
        EXPECT_EQ(eventDataTar->subspaceId_, 200);
        EXPECT_EQ(eventDataTar->previousSubspaceId_, 150);
        delete eventDataTar;
    }
}

/**
 * @tc.name: DistributedAccountSpaceEventData_operatorEqual001
 * @tc.desc: Test DistributedAccountSubProfileEventData operator== with equal data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceAccountInfoTest, SpaceEventData_operatorEqual001, TestSize.Level3)
{
    DistributedAccountSubProfileEventData eventData1;
    eventData1.type_ = DistributedAccountSubProfileEventType::CREATED;
    eventData1.osAccountId_ = 100;
    eventData1.subspaceId_ = 200;
    eventData1.previousSubspaceId_ = 150;

    DistributedAccountSubProfileEventData eventData2;
    eventData2.type_ = DistributedAccountSubProfileEventType::CREATED;
    eventData2.osAccountId_ = 100;
    eventData2.subspaceId_ = 200;
    eventData2.previousSubspaceId_ = 150;

    EXPECT_TRUE(eventData1 == eventData2);
}

/**
 * @tc.name: DistributedAccountSpaceEventData_operatorEqual002
 * @tc.desc: Test DistributedAccountSubProfileEventData operator== with different type - cover line 107
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceAccountInfoTest, SpaceEventData_operatorEqual002, TestSize.Level3)
{
    DistributedAccountSubProfileEventData eventData1;
    eventData1.type_ = DistributedAccountSubProfileEventType::CREATED;
    eventData1.osAccountId_ = 100;
    eventData1.subspaceId_ = 200;
    eventData1.previousSubspaceId_ = 150;

    DistributedAccountSubProfileEventData eventData2;
    eventData2.type_ = DistributedAccountSubProfileEventType::SWITCHED;
    eventData2.osAccountId_ = 100;
    eventData2.subspaceId_ = 200;
    eventData2.previousSubspaceId_ = 150;

    EXPECT_FALSE(eventData1 == eventData2);
}

/**
 * @tc.name: DistributedAccountSpaceEventData_operatorEqual003
 * @tc.desc: Test operator== with different osAccountId - cover line 110
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceAccountInfoTest, SpaceEventData_operatorEqual003, TestSize.Level3)
{
    DistributedAccountSubProfileEventData eventData1;
    eventData1.type_ = DistributedAccountSubProfileEventType::CREATED;
    eventData1.osAccountId_ = 100;
    eventData1.subspaceId_ = 200;
    eventData1.previousSubspaceId_ = 150;

    DistributedAccountSubProfileEventData eventData2;
    eventData2.type_ = DistributedAccountSubProfileEventType::CREATED;
    eventData2.osAccountId_ = 200;
    eventData2.subspaceId_ = 200;
    eventData2.previousSubspaceId_ = 150;

    EXPECT_FALSE(eventData1 == eventData2);
}

/**
 * @tc.name: DistributedAccountSpaceEventData_operatorEqual004
 * @tc.desc: Test operator== with different subProfileId - cover line 110
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceAccountInfoTest, SpaceEventData_operatorEqual004, TestSize.Level3)
{
    DistributedAccountSubProfileEventData eventData1;
    eventData1.type_ = DistributedAccountSubProfileEventType::CREATED;
    eventData1.osAccountId_ = 100;
    eventData1.subspaceId_ = 200;
    eventData1.previousSubspaceId_ = 150;

    DistributedAccountSubProfileEventData eventData2;
    eventData2.type_ = DistributedAccountSubProfileEventType::CREATED;
    eventData2.osAccountId_ = 100;
    eventData2.subspaceId_ = 300;
    eventData2.previousSubspaceId_ = 150;

    EXPECT_FALSE(eventData1 == eventData2);
}

/**
 * @tc.name: DistributedAccountSpaceEventData_operatorEqual005
 * @tc.desc: Test operator== with different previousSubProfileId - cover line 110
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceAccountInfoTest, SpaceEventData_operatorEqual005, TestSize.Level3)
{
    DistributedAccountSubProfileEventData eventData1;
    eventData1.type_ = DistributedAccountSubProfileEventType::CREATED;
    eventData1.osAccountId_ = 100;
    eventData1.subspaceId_ = 200;
    eventData1.previousSubspaceId_ = 150;

    DistributedAccountSubProfileEventData eventData2;
    eventData2.type_ = DistributedAccountSubProfileEventType::CREATED;
    eventData2.osAccountId_ = 100;
    eventData2.subspaceId_ = 200;
    eventData2.previousSubspaceId_ = 250;

    EXPECT_FALSE(eventData1 == eventData2);
}

/**
 * @tc.name: DistributedAccountSpaceEventData_Unmarshalling001
 * @tc.desc: Test DistributedAccountSubProfileEventData Unmarshalling success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceAccountInfoTest, SpaceEventData_Unmarshalling001, TestSize.Level3)
{
    DistributedAccountSubProfileEventData eventData;
    eventData.type_ = DistributedAccountSubProfileEventType::CREATED;
    eventData.osAccountId_ = 100;
    eventData.subspaceId_ = 200;
    eventData.previousSubspaceId_ = 150;

    Parcel parcel;
    EXPECT_TRUE(eventData.Marshalling(parcel));

    DistributedAccountSubProfileEventData *result = DistributedAccountSubProfileEventData::Unmarshalling(parcel);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->type_, eventData.type_);
    EXPECT_EQ(result->osAccountId_, eventData.osAccountId_);
    EXPECT_EQ(result->subspaceId_, eventData.subspaceId_);
    EXPECT_EQ(result->previousSubspaceId_, eventData.previousSubspaceId_);
    delete result;
}

/**
 * @tc.name: DistributedAccountSpaceEventData_Unmarshalling002
 * @tc.desc: Test Unmarshalling with empty parcel - cover ReadFromParcel line 121
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceAccountInfoTest, SpaceEventData_Unmarshalling002, TestSize.Level3)
{
    Parcel parcel;

    DistributedAccountSubProfileEventData *result = DistributedAccountSubProfileEventData::Unmarshalling(parcel);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: DistributedAccountSpaceEventData_Unmarshalling003
 * @tc.desc: Test Unmarshalling read osAccountId fail - cover ReadFromParcel line 128
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceAccountInfoTest, SpaceEventData_Unmarshalling003, TestSize.Level3)
{
    Parcel parcel;
    parcel.WriteInt32(static_cast<int32_t>(DistributedAccountSubProfileEventType::CREATED));

    DistributedAccountSubProfileEventData *result = DistributedAccountSubProfileEventData::Unmarshalling(parcel);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: DistributedAccountSpaceEventData_Unmarshalling004
 * @tc.desc: Test Unmarshalling read spaceId fail - cover ReadFromParcel line 135
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceAccountInfoTest, SpaceEventData_Unmarshalling004, TestSize.Level3)
{
    Parcel parcel;
    parcel.WriteInt32(static_cast<int32_t>(DistributedAccountSubProfileEventType::CREATED));
    parcel.WriteInt32(100);

    DistributedAccountSubProfileEventData *result = DistributedAccountSubProfileEventData::Unmarshalling(parcel);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: DistributedAccountSpaceEventData_Unmarshalling005
 * @tc.desc: Test Unmarshalling read previousSpaceId fail - cover ReadFromParcel line 142
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceAccountInfoTest, SpaceEventData_Unmarshalling005, TestSize.Level3)
{
    Parcel parcel;
    parcel.WriteInt32(static_cast<int32_t>(DistributedAccountSubProfileEventType::CREATED));
    parcel.WriteInt32(100);
    parcel.WriteInt32(200);

    DistributedAccountSubProfileEventData *result = DistributedAccountSubProfileEventData::Unmarshalling(parcel);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: DistributedAccountEventData_Marshalling001
 * @tc.desc: Test DistributedAccountEventData Marshalling success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceAccountInfoTest, EventData_Marshalling001, TestSize.Level3)
{
    DistributedAccountEventData eventData;
    eventData.id_ = 100;
    eventData.type_ = DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN;

    Parcel parcel;
    EXPECT_TRUE(eventData.Marshalling(parcel));
}

/**
 * @tc.name: DistributedAccountEventData_Unmarshalling001
 * @tc.desc: Test DistributedAccountEventData Unmarshalling success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceAccountInfoTest, EventData_Unmarshalling001, TestSize.Level3)
{
    DistributedAccountEventData eventData;
    eventData.id_ = 100;
    eventData.type_ = DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN;

    Parcel parcel;
    EXPECT_TRUE(eventData.Marshalling(parcel));

    DistributedAccountEventData *result = DistributedAccountEventData::Unmarshalling(parcel);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->id_, eventData.id_);
    EXPECT_EQ(result->type_, eventData.type_);
    delete result;
}

/**
 * @tc.name: DistributedAccountEventData_Unmarshalling002
 * @tc.desc: Test DistributedAccountEventData Unmarshalling with empty parcel - cover ReadFromParcel line 56
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceAccountInfoTest, EventData_Unmarshalling002, TestSize.Level3)
{
    Parcel parcel;

    DistributedAccountEventData *result = DistributedAccountEventData::Unmarshalling(parcel);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: DistributedAccountEventData_Unmarshalling003
 * @tc.desc: Test Unmarshalling read type fail - cover ReadFromParcel line 62
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceAccountInfoTest, EventData_Unmarshalling003, TestSize.Level3)
{
    Parcel parcel;
    parcel.WriteInt32(100);

    DistributedAccountEventData *result = DistributedAccountEventData::Unmarshalling(parcel);
    EXPECT_EQ(result, nullptr);
    Parcel parcel2;
    parcel2.WriteInt32(100);
    parcel2.WriteInt32(0);

    DistributedAccountEventData *result2 = DistributedAccountEventData::Unmarshalling(parcel2);
    EXPECT_EQ(result2, nullptr);
}

/**
 * @tc.name: DistributedAccountEventData_operatorEqual001
 * @tc.desc: Test DistributedAccountEventData operator== with equal data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceAccountInfoTest, EventData_operatorEqual001, TestSize.Level3)
{
    DistributedAccountEventData eventData1;
    eventData1.id_ = 100;
    eventData1.type_ = DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN;

    DistributedAccountEventData eventData2;
    eventData2.id_ = 100;
    eventData2.type_ = DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN;

    EXPECT_TRUE(eventData1 == eventData2);
}

/**
 * @tc.name: DistributedAccountEventData_operatorEqual002
 * @tc.desc: Test DistributedAccountEventData operator== with different id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceAccountInfoTest, EventData_operatorEqual002, TestSize.Level3)
{
    DistributedAccountEventData eventData1;
    eventData1.id_ = 100;
    eventData1.type_ = DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN;

    DistributedAccountEventData eventData2;
    eventData2.id_ = 200;
    eventData2.type_ = DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN;

    EXPECT_FALSE(eventData1 == eventData2);
}

/**
 * @tc.name: DistributedAccountEventData_operatorEqual003
 * @tc.desc: Test DistributedAccountEventData operator== with different type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceAccountInfoTest, EventData_operatorEqual003, TestSize.Level3)
{
    DistributedAccountEventData eventData1;
    eventData1.id_ = 100;
    eventData1.type_ = DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN;

    DistributedAccountEventData eventData2;
    eventData2.id_ = 100;
    eventData2.type_ = DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGOUT;

    EXPECT_FALSE(eventData1 == eventData2);
}