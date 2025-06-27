/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "account_iam_info.h"
#include "account_info.h"
#undef private
#include "account_log_wrapper.h"
#include "iam_common_defines.h"
#include "message_parcel.h"
#include "test_common.h"

namespace OHOS {
namespace AccountTest {

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AccountSA;
namespace {
const int32_t TEST_USER_ID = 101;
const std::vector<uint8_t> TEST_CHALLENGE = {1, 2, 3, 4};
const int32_t TEST_TOKEN_SIZE = 4;
const int32_t TEST_TOKEN_PID = 5;
const std::string TEST_ACCOUNT_NAME = "TestAccountName";
const std::string TEST_NICKNAME = "NickName_Test";
const std::string TEST_AVATAR = "Avatar_Test";
const std::string TEST_ACCOUNT_UID = "123456789";
const std::string TEST_RAW_UID = "123456";
const int32_t TEST_ACCOUNT_STATUS = 0;
const std::string TEST_ACCOUNT_NICKNAME = TEST_NICKNAME;
const std::string KEY_ACCOUNT_INFO_SCALABLEDATA = "age";
}
class AccountIAMInfoTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

void AccountIAMInfoTest::SetUpTestCase(void)
{}

void AccountIAMInfoTest::TearDownTestCase(void)
{}

void AccountIAMInfoTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    EXPECT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    EXPECT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void AccountIAMInfoTest::TearDown(void)
{}

/**
 * @tc.name: AccountIAMInfo_WriteRemoteAuthParam_0100
 * @tc.desc: WriteRemoteAuthParam
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMInfoTest, AccountIAMInfo_WriteRemoteAuthParam_0100, TestSize.Level3)
{
    AccountSA::AuthParam authParam;
    Parcel parcel;
    EXPECT_TRUE(authParam.WriteRemoteAuthParam(parcel));
}

/**
 * @tc.name: AccountIAMInfo_WriteRemoteAuthParam_0200
 * @tc.desc: WriteRemoteAuthParam
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMInfoTest, AccountIAMInfo_WriteRemoteAuthParam_0200, TestSize.Level3)
{
    AccountSA::AuthParam authParam;
    Parcel parcel;
    std::optional<RemoteAuthParam> testremoteAuthParam = RemoteAuthParam();
    testremoteAuthParam.value().verifierNetworkId = "verifierNetworkId";
    testremoteAuthParam.value().collectorNetworkId = "collectorNetworkId";
    testremoteAuthParam.value().collectorTokenId = 1;
    authParam.remoteAuthParam = testremoteAuthParam;
    EXPECT_NE(authParam.remoteAuthParam, std::nullopt);
    EXPECT_EQ(authParam.remoteAuthParam.value().verifierNetworkId.value(), "verifierNetworkId");
    EXPECT_NE(authParam.remoteAuthParam.value().verifierNetworkId, std::nullopt);
    EXPECT_EQ(authParam.remoteAuthParam.value().collectorNetworkId.value(), "collectorNetworkId");
    EXPECT_NE(authParam.remoteAuthParam.value().collectorNetworkId, std::nullopt);
    EXPECT_EQ(authParam.remoteAuthParam.value().collectorTokenId.value(), 1);
    EXPECT_NE(authParam.remoteAuthParam.value().collectorTokenId, std::nullopt);
    EXPECT_TRUE(authParam.WriteRemoteAuthParam(parcel));
}

/**
 * @tc.name: AccountIAMInfo_Marshalling_0100
 * @tc.desc: Marshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMInfoTest, AccountIAMInfo_Marshalling_0100, TestSize.Level3)
{
    AccountSA::AuthParam authParam;
    Parcel parcel;
    EXPECT_TRUE(authParam.Marshalling(parcel));
}

/**
 * @tc.name: AccountIAMInfo_Unmarshalling_0100
 * @tc.desc: Unmarshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMInfoTest, AccountIAMInfo_Unmarshalling_0100, TestSize.Level3)
{
    AccountSA::AuthParam authParam;
    Parcel parcel;
    EXPECT_TRUE(authParam.Marshalling(parcel));
    EXPECT_NE(authParam.Unmarshalling(parcel), nullptr);
}

/**
 * @tc.name: AccountIAMInfo_Marshalling_0200
 * @tc.desc: Marshalling and Unmarshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMInfoTest, AccountIAMInfo_Marshalling_0200, TestSize.Level3)
{
    Parcel parcel;
    AccountSA::AuthParam authParam;
    authParam.userId = TEST_USER_ID;
    authParam.challenge = TEST_CHALLENGE;
    authParam.authType = AuthType::PIN;
    authParam.authTrustLevel = AuthTrustLevel::ATL1;
    authParam.authIntent = AuthIntent::DEFAULT;

    EXPECT_TRUE(authParam.Marshalling(parcel));
    AccountSA::AuthParam *authParam1 = authParam.Unmarshalling(parcel);
    EXPECT_NE(authParam1, nullptr);

    EXPECT_EQ(authParam.authIntent, authParam1->authIntent);
    EXPECT_EQ(authParam.authTrustLevel, authParam1->authTrustLevel);
    EXPECT_EQ(authParam.authType, authParam1->authType);
    EXPECT_EQ(authParam.challenge, authParam1->challenge);
    EXPECT_EQ(authParam.userId, authParam1->userId);
}

/**
 * @tc.name: AccountIAMInfo_ReadFromParcel_0100
 * @tc.desc: ReadFromParcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMInfoTest, AccountIAMInfo_ReadFromParcel_0100, TestSize.Level3)
{
    Parcel parcel;
    AccountSA::AuthParam authParam;
    authParam.userId = TEST_USER_ID;
    authParam.challenge = TEST_CHALLENGE;
    authParam.authType = AuthType::PIN;
    authParam.authTrustLevel = AuthTrustLevel::ATL1;
    authParam.authIntent = AuthIntent::DEFAULT;

    EXPECT_TRUE(authParam.Marshalling(parcel));
    EXPECT_TRUE(authParam.ReadFromParcel(parcel));
    EXPECT_EQ(authParam.userId, TEST_USER_ID);
    EXPECT_EQ(authParam.challenge, TEST_CHALLENGE);
    EXPECT_EQ(authParam.authType, AuthType::PIN);
    EXPECT_EQ(authParam.authTrustLevel, AuthTrustLevel::ATL1);
    EXPECT_EQ(authParam.authIntent, AuthIntent::DEFAULT);
}

/**
 * @tc.name: AccountIAMInfo_ReadRemoteAuthParam_0100
 * @tc.desc: ReadRemoteAuthParam
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMInfoTest, AccountIAMInfo_ReadRemoteAuthParam_0100, TestSize.Level3)
{
    AccountSA::AuthParam authParam;
    AccountSA::AuthParam readAuthParam;
    Parcel parcel;
    std::optional<RemoteAuthParam> testremoteAuthParam = RemoteAuthParam();
    testremoteAuthParam.value().verifierNetworkId = "verifierNetworkId";
    testremoteAuthParam.value().collectorNetworkId = "collectorNetworkId";
    testremoteAuthParam.value().collectorTokenId = 1;
    authParam.remoteAuthParam = testremoteAuthParam;
    EXPECT_NE(authParam.remoteAuthParam, std::nullopt);
    EXPECT_EQ(authParam.remoteAuthParam.value().verifierNetworkId.value(), "verifierNetworkId");
    EXPECT_NE(authParam.remoteAuthParam.value().verifierNetworkId, std::nullopt);
    EXPECT_EQ(authParam.remoteAuthParam.value().collectorNetworkId.value(), "collectorNetworkId");
    EXPECT_NE(authParam.remoteAuthParam.value().collectorNetworkId, std::nullopt);
    EXPECT_EQ(authParam.remoteAuthParam.value().collectorTokenId.value(), 1);
    EXPECT_NE(authParam.remoteAuthParam.value().collectorTokenId, std::nullopt);
    EXPECT_TRUE(authParam.WriteRemoteAuthParam(parcel));
    EXPECT_TRUE(readAuthParam.ReadRemoteAuthParam(parcel));
    EXPECT_TRUE(readAuthParam.remoteAuthParam.has_value());
    auto readValue = readAuthParam.remoteAuthParam.value();
    EXPECT_EQ(readValue.verifierNetworkId.value(), "verifierNetworkId");
    EXPECT_EQ(readValue.collectorNetworkId.value(), "collectorNetworkId");
    EXPECT_EQ(readValue.collectorTokenId.value(), 1);
}

/**
 * @tc.name: AccountIAMInfo_ConvertToCredentialInfoIamList_0100
 * @tc.desc: ConvertToCredentialInfoIamList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMInfoTest, AccountIAMInfo_ConvertToCredentialInfoIamList_0100, TestSize.Level3)
{
    std::vector<UserIam::UserAuth::CredentialInfo> infoList;
    UserIam::UserAuth::CredentialInfo credentialInfo;
    credentialInfo.authType = AuthType::PIN;
    credentialInfo.pinType = PinSubType::PIN_MAX;
    infoList.emplace_back(credentialInfo);
    std::vector<OHOS::AccountSA::CredentialInfoIam> infoIamList = ConvertToCredentialInfoIamList(infoList);
    EXPECT_EQ(infoList.size(), infoIamList.size());
}

/**
 * @tc.name: AccountIAMInfo_ConvertToCredentialInfoList_0100
 * @tc.desc: ConvertToCredentialInfoList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMInfoTest, AccountIAMInfo_ConvertToCredentialInfoList_0100, TestSize.Level3)
{
    std::vector<OHOS::AccountSA::CredentialInfoIam> infoIamList;
    OHOS::AccountSA::CredentialInfoIam credentialInfoIam;
    UserIam::UserAuth::CredentialInfo credentialInfo;
    credentialInfo.authType = AuthType::PIN;
    credentialInfo.pinType = PinSubType::PIN_MAX;
    credentialInfoIam.credentialInfo = credentialInfo;
    infoIamList.emplace_back(credentialInfoIam);
    std::vector<UserIam::UserAuth::CredentialInfo> infoList = ConvertToCredentialInfoList(infoIamList);
    EXPECT_EQ(infoList.size(), infoIamList.size());
}

/**
 * @tc.name: AccountIAMInfo_Marshalling_0300
 * @tc.desc: Marshalling and Unmarshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMInfoTest, AccountIAMInfo_Marshalling_0300, TestSize.Level3)
{
    Parcel parcel;
    OHOS::AccountSA::CredentialInfoIam credentialInfoIam;
    UserIam::UserAuth::CredentialInfo credentialInfo;
    credentialInfoIam.credentialInfo.authType = AuthType::PIN;
    credentialInfoIam.credentialInfo.credentialId = 1;
    credentialInfoIam.credentialInfo.templateId = 2;
    credentialInfoIam.credentialInfo.isAbandoned = true;
    credentialInfoIam.credentialInfo.validityPeriod = 3;
    credentialInfoIam.credentialInfo = credentialInfo;
    EXPECT_TRUE(credentialInfoIam.Marshalling(parcel));
    OHOS::AccountSA::CredentialInfoIam *credentialInfoIam1 = credentialInfoIam.Unmarshalling(parcel);
    EXPECT_NE(credentialInfoIam1, nullptr);

    EXPECT_EQ(credentialInfoIam.credentialInfo.authType, credentialInfoIam1->credentialInfo.authType);
    EXPECT_EQ(credentialInfoIam.credentialInfo.credentialId, credentialInfoIam1->credentialInfo.credentialId);
    EXPECT_EQ(credentialInfoIam.credentialInfo.templateId, credentialInfoIam1->credentialInfo.templateId);
    EXPECT_EQ(credentialInfoIam.credentialInfo.isAbandoned, credentialInfoIam1->credentialInfo.isAbandoned);
    EXPECT_EQ(credentialInfoIam.credentialInfo.validityPeriod, credentialInfoIam1->credentialInfo.validityPeriod);
}

/**
 * @tc.name: AccountIAMInfo_ReadFromParcel_0200
 * @tc.desc: ReadFromParcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMInfoTest, AccountIAMInfo_ReadFromParcel_0200, TestSize.Level3)
{
    Parcel parcel;
    OHOS::AccountSA::CredentialInfoIam credentialInfoIam;
    UserIam::UserAuth::CredentialInfo credentialInfo;
    credentialInfoIam.credentialInfo.authType = AuthType::ALL;
    credentialInfoIam.credentialInfo.credentialId = 0;
    credentialInfoIam.credentialInfo.templateId = 0;
    credentialInfoIam.credentialInfo.isAbandoned = false;
    credentialInfoIam.credentialInfo.validityPeriod = 0;
    credentialInfoIam.credentialInfo = credentialInfo;
    EXPECT_TRUE(credentialInfoIam.Marshalling(parcel));
    EXPECT_TRUE(credentialInfoIam.ReadFromParcel(parcel));
    EXPECT_EQ(credentialInfoIam.credentialInfo.authType, 0);
    EXPECT_EQ(credentialInfoIam.credentialInfo.credentialId, 0);
    EXPECT_EQ(credentialInfoIam.credentialInfo.templateId, 0);
    EXPECT_EQ(credentialInfoIam.credentialInfo.isAbandoned, false);
    EXPECT_EQ(credentialInfoIam.credentialInfo.validityPeriod, 0);
}

/**
 * @tc.name: AccountIAMInfo_CredentialParametersIam_Marshalling_0100
 * @tc.desc: Marshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMInfoTest, AccountIAMInfo_CredentialParametersIam_Marshalling_0100, TestSize.Level3)
{
    AccountSA::CredentialParametersIam credentialParametersIam;
    Parcel parcel;
    EXPECT_TRUE(credentialParametersIam.Marshalling(parcel));
}

/**
 * @tc.name: AccountIAMInfo_CredentialParametersIam_Unmarshalling_0100
 * @tc.desc: Unmarshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMInfoTest, AccountIAMInfo_CredentialParametersIam_Unmarshalling_0100, TestSize.Level3)
{
    AccountSA::CredentialParametersIam credentialParametersIam;
    Parcel parcel;
    EXPECT_TRUE(credentialParametersIam.Marshalling(parcel));
    EXPECT_NE(credentialParametersIam.Unmarshalling(parcel), nullptr);
}

/**
 * @tc.name: AccountIAMInfo_CredentialParametersIam_ReadFromParcel_0100
 * @tc.desc: ReadFromParcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMInfoTest, AccountIAMInfo_CredentialParametersIam_ReadFromParcel_0100, TestSize.Level3)
{
    AccountSA::CredentialParametersIam credentialParametersIam;
    Parcel parcel;
    EXPECT_TRUE(credentialParametersIam.Marshalling(parcel));
    EXPECT_TRUE(credentialParametersIam.ReadFromParcel(parcel));
}

/**
 * @tc.name: AccountIAMInfo_Marshalling_0400
 * @tc.desc: Marshalling and Unmarshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMInfoTest, AccountIAMInfo_Marshalling_0400, TestSize.Level3)
{
    Parcel parcel;
    OHOS::AccountSA::CredentialParametersIam credentialParametersIam;
    UserIam::UserAuth::CredentialParameters credentialParameters;
    std::vector<uint8_t> TEST_TOKEN;
    TEST_TOKEN.push_back(TEST_TOKEN_SIZE);
    TEST_TOKEN.push_back(TEST_TOKEN_PID);
    credentialParametersIam.credentialParameters.authType = AuthType::PIN;
    credentialParametersIam.credentialParameters.token = TEST_TOKEN;
    credentialParametersIam.credentialParameters = credentialParameters;
    EXPECT_TRUE(credentialParametersIam.Marshalling(parcel));
    OHOS::AccountSA::CredentialParametersIam *credential = credentialParametersIam.Unmarshalling(parcel);
    EXPECT_NE(credential, nullptr);

    EXPECT_EQ(credentialParametersIam.credentialParameters.authType, credential->credentialParameters.authType);
    EXPECT_EQ(credentialParametersIam.credentialParameters.token, credential->credentialParameters.token);
    EXPECT_EQ(credential->credentialParameters.token.size(), credentialParametersIam.credentialParameters.token.size());
}

/**
 * @tc.name: AccountIAMInfo_ReadFromParcel_0300
 * @tc.desc: ReadFromParcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMInfoTest, AccountIAMInfo_ReadFromParcel_0300, TestSize.Level3)
{
    Parcel parcel;
    OHOS::AccountSA::CredentialParametersIam credentialParametersIam;
    UserIam::UserAuth::CredentialParameters credentialParameters;
    std::vector<uint8_t> TEST_TOKEN;
    TEST_TOKEN.push_back(TEST_TOKEN_SIZE);
    TEST_TOKEN.push_back(TEST_TOKEN_PID);
    credentialParametersIam.credentialParameters.authType = AuthType::PIN;
    credentialParametersIam.credentialParameters.token = TEST_TOKEN;
    credentialParametersIam.credentialParameters = credentialParameters;
    EXPECT_TRUE(credentialParametersIam.Marshalling(parcel));
    EXPECT_TRUE(credentialParametersIam.ReadFromParcel(parcel));
    EXPECT_EQ(credentialParametersIam.credentialParameters.authType, 0);
}

/**
 * @tc.name: AccountIAMInfo_GetPropertyRequestIam_Marshalling_0100
 * @tc.desc: Marshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMInfoTest, AccountIAMInfo_GetPropertyRequestIam_Marshalling_0100, TestSize.Level3)
{
    AccountSA::GetPropertyRequestIam getPropertyRequestIam;
    UserIam::UserAuth::GetPropertyRequest getPropertyRequest;
    Parcel parcel;
    EXPECT_TRUE(getPropertyRequestIam.Marshalling(parcel));
}

/**
 * @tc.name: AccountIAMInfo_GetPropertyRequestIam_Unmarshalling_0100
 * @tc.desc: Unmarshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMInfoTest, AccountIAMInfo_GetPropertyRequestIam_Unmarshalling_0100, TestSize.Level3)
{
    AccountSA::GetPropertyRequestIam getPropertyRequestIam;
    UserIam::UserAuth::GetPropertyRequest getPropertyRequest;
    Parcel parcel;
    EXPECT_TRUE(getPropertyRequestIam.Marshalling(parcel));
    EXPECT_NE(getPropertyRequestIam.Unmarshalling(parcel), nullptr);
}

/**
 * @tc.name: AccountIAMInfo_GetPropertyRequestIam_ReadFromParcel_0100
 * @tc.desc: ReadFromParcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMInfoTest, AccountIAMInfo_GetPropertyRequestIam_ReadFromParcel_0100, TestSize.Level3)
{
    AccountSA::GetPropertyRequestIam getPropertyRequestIam;
    UserIam::UserAuth::GetPropertyRequest getPropertyRequest;
    Parcel parcel;
    EXPECT_TRUE(getPropertyRequestIam.Marshalling(parcel));
    EXPECT_TRUE(getPropertyRequestIam.ReadFromParcel(parcel));
}

/**
 * @tc.name: AccountIAMInfo_Marshalling_0500
 * @tc.desc: Marshalling and Unmarshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMInfoTest, AccountIAMInfo_Marshalling_0500, TestSize.Level3)
{
    Parcel parcel;
    OHOS::AccountSA::GetPropertyRequestIam getPropertyRequestIam;
    UserIam::UserAuth::GetPropertyRequest getPropertyRequest;
    std::vector<Attributes::AttributeKey> TEST_KEYS;
    TEST_KEYS.push_back(Attributes::AttributeKey::ATTR_AUTH_TOKEN);
    TEST_KEYS.push_back(Attributes::AttributeKey::ATTR_AUTH_TYPE);
    getPropertyRequestIam.getPropertyRequest.authType = AuthType::PIN;
    getPropertyRequestIam.getPropertyRequest.keys = TEST_KEYS;
    getPropertyRequestIam.getPropertyRequest = getPropertyRequest;
    EXPECT_TRUE(getPropertyRequestIam.Marshalling(parcel));
    OHOS::AccountSA::GetPropertyRequestIam *getPropertyRequestIam1 = getPropertyRequestIam.Unmarshalling(parcel);
    EXPECT_NE(getPropertyRequestIam1, nullptr);

    EXPECT_EQ(getPropertyRequestIam.getPropertyRequest.authType, getPropertyRequestIam1->getPropertyRequest.authType);
    EXPECT_EQ(getPropertyRequestIam.getPropertyRequest.keys, getPropertyRequestIam1->getPropertyRequest.keys);
    EXPECT_EQ(getPropertyRequestIam1->getPropertyRequest.keys.size(),
        getPropertyRequestIam.getPropertyRequest.keys.size());
}

/**
 * @tc.name: AccountIAMInfo_ReadFromParcel_0400
 * @tc.desc: ReadFromParcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMInfoTest, AccountIAMInfo_ReadFromParcel_0400, TestSize.Level3)
{
    Parcel parcel;
    OHOS::AccountSA::GetPropertyRequestIam getPropertyRequestIam;
    UserIam::UserAuth::GetPropertyRequest getPropertyRequest;
    std::vector<Attributes::AttributeKey> TEST_KEYS;
    TEST_KEYS.push_back(Attributes::AttributeKey::ATTR_AUTH_TOKEN);
    TEST_KEYS.push_back(Attributes::AttributeKey::ATTR_AUTH_TYPE);
    getPropertyRequestIam.getPropertyRequest.authType = AuthType::PIN;
    getPropertyRequestIam.getPropertyRequest.keys = TEST_KEYS;
    getPropertyRequestIam.getPropertyRequest = getPropertyRequest;
    EXPECT_TRUE(getPropertyRequestIam.Marshalling(parcel));
    EXPECT_TRUE(getPropertyRequestIam.ReadFromParcel(parcel));
    EXPECT_EQ(getPropertyRequestIam.getPropertyRequest.authType, 0);
}

/**
 * @tc.name: AccountIAMInfo_SetPropertyRequestIam_Marshalling_0100
 * @tc.desc: Marshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMInfoTest, AccountIAMInfo_SetPropertyRequestIam_Marshalling_0100, TestSize.Level3)
{
    AccountSA::SetPropertyRequestIam setPropertyRequestIam;
    UserIam::UserAuth::SetPropertyRequest setPropertyRequest;
    Parcel parcel;
    EXPECT_TRUE(setPropertyRequestIam.Marshalling(parcel));
}

/**
 * @tc.name: AccountIAMInfo_SetPropertyRequestIam_Unmarshalling_0100
 * @tc.desc: Unmarshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMInfoTest, AccountIAMInfo_SetPropertyRequestIam_Unmarshalling_0100, TestSize.Level3)
{
    AccountSA::SetPropertyRequestIam setPropertyRequestIam;
    UserIam::UserAuth::SetPropertyRequest setPropertyRequest;
    Parcel parcel;
    EXPECT_TRUE(setPropertyRequestIam.Marshalling(parcel));
    EXPECT_NE(setPropertyRequestIam.Unmarshalling(parcel), nullptr);
}

/**
 * @tc.name: AccountIAMInfo_SetPropertyRequestIam_ReadFromParcel_0100
 * @tc.desc: ReadFromParcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMInfoTest, AccountIAMInfo_SetPropertyRequestIam_ReadFromParcel_0100, TestSize.Level3)
{
    AccountSA::SetPropertyRequestIam setPropertyRequestIam;
    UserIam::UserAuth::SetPropertyRequest setPropertyRequest;
    Parcel parcel;
    EXPECT_TRUE(setPropertyRequestIam.Marshalling(parcel));
    EXPECT_TRUE(setPropertyRequestIam.ReadFromParcel(parcel));
}

/**
 * @tc.name: AccountIAMInfo_Marshalling_0600
 * @tc.desc: Marshalling and Unmarshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMInfoTest, AccountIAMInfo_Marshalling_0600, TestSize.Level3)
{
    Parcel parcel;
    OHOS::AccountSA::SetPropertyRequestIam setPropertyRequestIam;
    UserIam::UserAuth::SetPropertyRequest setPropertyRequest;
    setPropertyRequestIam.setPropertyRequest.authType = AuthType::PIN;
    EXPECT_TRUE(setPropertyRequestIam.Marshalling(parcel));
    OHOS::AccountSA::SetPropertyRequestIam *setPropertyRequestIam1 = setPropertyRequestIam.Unmarshalling(parcel);
    EXPECT_NE(setPropertyRequestIam1, nullptr);

    EXPECT_EQ(setPropertyRequestIam.setPropertyRequest.authType, setPropertyRequestIam1->setPropertyRequest.authType);
}

/**
 * @tc.name: AccountIAMInfo_ReadFromParcel_0500
 * @tc.desc: ReadFromParcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMInfoTest, AccountIAMInfo_ReadFromParcel_0500, TestSize.Level3)
{
    Parcel parcel;
    OHOS::AccountSA::SetPropertyRequestIam setPropertyRequestIam;
    UserIam::UserAuth::SetPropertyRequest setPropertyRequest;
    setPropertyRequestIam.setPropertyRequest.authType = AuthType::PIN;
    EXPECT_TRUE(setPropertyRequestIam.Marshalling(parcel));
    EXPECT_TRUE(setPropertyRequestIam.ReadFromParcel(parcel));
    EXPECT_EQ(setPropertyRequestIam.setPropertyRequest.authType, 1);
}

/**
 * @tc.name: AccountIAMInfo_Marshalling_0700
 * @tc.desc: Marshalling and Unmarshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountIAMInfoTest, AccountIAMInfo_Marshalling_0700, TestSize.Level3)
{
    MessageParcel parcel;
    AccountSA::OhosAccountInfo ohosAccountInfo;
    ohosAccountInfo.name_ = TEST_ACCOUNT_NAME;
    ohosAccountInfo.uid_ = TEST_ACCOUNT_UID;
    ohosAccountInfo.rawUid_ = TEST_RAW_UID;
    ohosAccountInfo.status_ = TEST_ACCOUNT_STATUS;
    ohosAccountInfo.nickname_ = TEST_ACCOUNT_NICKNAME;
    ohosAccountInfo.avatar_ = TEST_AVATAR;
    ohosAccountInfo.scalableData_.SetParam(KEY_ACCOUNT_INFO_SCALABLEDATA, 123);
    EXPECT_TRUE(ohosAccountInfo.Marshalling(parcel));
    AccountSA::OhosAccountInfo *ohosAccountInfo1 = ohosAccountInfo.Unmarshalling(parcel);
    EXPECT_NE(ohosAccountInfo1, nullptr);

    EXPECT_EQ(ohosAccountInfo.name_, ohosAccountInfo1->name_);
    EXPECT_EQ(ohosAccountInfo.uid_, ohosAccountInfo1->uid_);
    EXPECT_EQ(ohosAccountInfo.rawUid_, ohosAccountInfo1->rawUid_);
    EXPECT_EQ(ohosAccountInfo.status_, ohosAccountInfo1->status_);
    EXPECT_EQ(ohosAccountInfo.nickname_, ohosAccountInfo1->nickname_);
    EXPECT_EQ(ohosAccountInfo.avatar_, ohosAccountInfo1->avatar_);
    EXPECT_EQ(ohosAccountInfo.scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA),
        ohosAccountInfo1->scalableData_.GetStringParam(KEY_ACCOUNT_INFO_SCALABLEDATA));
}
}  // namespace AccountTest
}  // namespace OHOS