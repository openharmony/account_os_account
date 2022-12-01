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

#include "account_log_wrapper.h"
#define private public
#include "app_account_info.h"
#undef private

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string STRING_OWNER = "com.example.owner";
const std::string STRING_NAME = "name";
const std::string STRING_EXTRA_INFO = "extra_info";
const std::string STRING_BUNDLE_NAME = "com.example.third_party";
const std::string STRING_BUNDLE_NAME_TWO = "com.example.bundletwo";
const std::string STRING_ASSOCIATED_KEY = "associated_key";
const std::string STRING_ASSOCIATED_VALUE = "associated_value";
const std::string STRING_ASSOCIATED_DATA = "{\"associated_key\": \"associated_value\"}";
const std::string STRING_CREDENTIAL_TYPE = "password";
const std::string STRING_CREDENTIAL = "1024";
const std::string STRING_ACCOUNT_CREDENTIAL = "{\"password\": \"1024\"}";
const std::string STRING_TOKEN = "token123";
const std::string STRING_AUTH_TYPE = "getSocialData";
const std::string STRING_EMPTY = "";

const bool SYNC_ENABLE_TRUE = true;
const bool SYNC_ENABLE_FALSE = false;

constexpr std::size_t SIZE_ZERO = 0;
constexpr std::size_t SIZE_ONE = 1;
constexpr int32_t MAX_TOKEN_NUMBER = 128;
constexpr int32_t MAX_OAUTH_LIST_SIZE = 512;
constexpr int32_t OVERLOAD_MAX_TOKEN_NUMBER = 135;
}  // namespace

class AppAccountInfoTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
};

void AppAccountInfoTest::SetUpTestCase(void)
{}

void AppAccountInfoTest::TearDownTestCase(void)
{}

void AppAccountInfoTest::SetUp(void)
{}

void AppAccountInfoTest::TearDown(void)
{}

/**
 * @tc.name: AppAccountInfo_GetOwner_0100
 * @tc.desc: Get the owner with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI4M8FW
 */
HWTEST_F(AppAccountInfoTest, AppAccountInfo_GetOwner_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountInfo_GetOwner_0100");

    // make an owner
    std::string owner = STRING_OWNER;

    // make info with an owner
    AppAccountInfo appAccountInfo;
    appAccountInfo.owner_ = owner;

    // get the owner
    std::string ownerFromInfo;
    appAccountInfo.GetOwner(ownerFromInfo);

    // check the owner
    EXPECT_EQ(owner, ownerFromInfo);
}

/**
 * @tc.name: AppAccountInfo_SetOwner_0100
 * @tc.desc: Set the owner with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI4M8FW
 */
HWTEST_F(AppAccountInfoTest, AppAccountInfo_SetOwner_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountInfo_SetOwner_0100");

    // make an owner
    std::string owner = STRING_OWNER;

    // make info
    AppAccountInfo appAccountInfo;

    // set the owner
    appAccountInfo.SetOwner(owner);

    // check the owner
    EXPECT_EQ(owner, appAccountInfo.owner_);
}

/**
 * @tc.name: AppAccountInfo_GetName_0100
 * @tc.desc: Get the name with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI4M8FW
 */
HWTEST_F(AppAccountInfoTest, AppAccountInfo_GetName_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountInfo_GetName_0100");

    // make a name
    std::string name = STRING_NAME;

    // make info with a name
    AppAccountInfo appAccountInfo;
    appAccountInfo.name_ = name;

    // get the name
    std::string nameFromInfo;
    appAccountInfo.GetName(nameFromInfo);

    // check the name
    EXPECT_EQ(name, nameFromInfo);
}

/**
 * @tc.name: AppAccountInfo_SetName_0100
 * @tc.desc: Set the name with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI4M8FW
 */
HWTEST_F(AppAccountInfoTest, AppAccountInfo_SetName_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountInfo_SetName_0100");

    // make a name
    std::string name = STRING_NAME;

    // make info
    AppAccountInfo appAccountInfo;

    // set the name
    appAccountInfo.SetName(name);

    // check the name
    EXPECT_EQ(name, appAccountInfo.name_);
}

/**
 * @tc.name: AppAccountInfo_GetExtraInfo_0100
 * @tc.desc: Get the extra info with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI4M8FW
 */
HWTEST_F(AppAccountInfoTest, AppAccountInfo_GetExtraInfo_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountInfo_GetExtraInfo_0100");

    // make extra info
    std::string extraInfo = STRING_EXTRA_INFO;

    // make info with extra info
    AppAccountInfo appAccountInfo;
    appAccountInfo.extraInfo_ = extraInfo;

    // get the extra info
    std::string extraInfoFromInfo;
    appAccountInfo.GetExtraInfo(extraInfoFromInfo);

    // check the extra info
    EXPECT_EQ(extraInfo, extraInfoFromInfo);
}

/**
 * @tc.name: AppAccountInfo_SetExtraInfo_0100
 * @tc.desc: Set the extra info with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI4M8FW
 */
HWTEST_F(AppAccountInfoTest, AppAccountInfo_SetExtraInfo_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountInfo_SetExtraInfo_0100");

    // make extra info
    std::string extraInfo = STRING_EXTRA_INFO;

    // make info
    AppAccountInfo appAccountInfo;

    // set the extra info
    appAccountInfo.SetExtraInfo(extraInfo);

    // check the extra info
    EXPECT_EQ(extraInfo, appAccountInfo.extraInfo_);
}

/**
 * @tc.name: AppAccountInfo_EnableAppAccess_0100
 * @tc.desc: Enable the app access with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI4M8FW
 */
HWTEST_F(AppAccountInfoTest, AppAccountInfo_EnableAppAccess_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountInfo_EnableAppAccess_0100");

    // make a bundle name
    std::string bundleName = STRING_BUNDLE_NAME;

    // make info
    AppAccountInfo appAccountInfo;

    // enable the app access
    ErrCode result = appAccountInfo.EnableAppAccess(bundleName);
    EXPECT_EQ(result, ERR_OK);

    // check the app access
    EXPECT_EQ(appAccountInfo.authorizedApps_.size(), SIZE_ONE);
    EXPECT_EQ(bundleName, *(appAccountInfo.authorizedApps_.begin()));
}

/**
 * @tc.name: AppAccountInfo_DisableAppAccess_0100
 * @tc.desc: Disable the app access with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI4M8FW
 */
HWTEST_F(AppAccountInfoTest, AppAccountInfo_DisableAppAccess_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountInfo_DisableAppAccess_0100");

    // make a bundle name
    std::string bundleName = STRING_BUNDLE_NAME;

    // make info with a bundle name
    AppAccountInfo appAccountInfo;
    appAccountInfo.authorizedApps_.emplace(bundleName);

    // disable the app access
    ErrCode result = appAccountInfo.DisableAppAccess(bundleName);
    EXPECT_EQ(result, ERR_OK);

    // check the app access
    EXPECT_EQ(appAccountInfo.authorizedApps_.size(), SIZE_ZERO);
}

/**
 * @tc.name: AppAccountInfo_GetAuthorizedApps_0100
 * @tc.desc: Get the authorized apps with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI4M8FW
 */
HWTEST_F(AppAccountInfoTest, AppAccountInfo_GetAuthorizedApps_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountInfo_GetAuthorizedApps_0100");

    // make a bundle name
    std::string bundleName = STRING_BUNDLE_NAME;

    // make authorized apps
    std::set<std::string> apps;
    apps.emplace(bundleName);

    // make info with authorized apps
    AppAccountInfo appAccountInfo;
    appAccountInfo.authorizedApps_ = apps;

    // get the authorized apps
    std::set<std::string> appsFromInfo;
    appAccountInfo.GetAuthorizedApps(appsFromInfo);

    // check the authorized apps
    EXPECT_EQ(appsFromInfo.size(), SIZE_ONE);
    EXPECT_EQ(bundleName, *(appsFromInfo.begin()));
}

/**
 * @tc.name: AppAccountInfo_SetAuthorizedApps_0100
 * @tc.desc: Set the authorized apps with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI4M8FW
 */
HWTEST_F(AppAccountInfoTest, AppAccountInfo_SetAuthorizedApps_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountInfo_SetAuthorizedApps_0100");

    // make a bundle name
    std::string bundleName = STRING_BUNDLE_NAME;

    // make authorized apps
    std::set<std::string> apps;
    apps.emplace(bundleName);

    // make info
    AppAccountInfo appAccountInfo;

    // set the authorized apps
    appAccountInfo.SetAuthorizedApps(apps);

    // check the authorized apps
    EXPECT_EQ(appAccountInfo.authorizedApps_.size(), SIZE_ONE);
    EXPECT_EQ(bundleName, *(appAccountInfo.authorizedApps_.begin()));
}

/**
 * @tc.name: AppAccountInfo_GetSyncEnable_0100
 * @tc.desc: Get the sync enable with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI4M8FW
 */
HWTEST_F(AppAccountInfoTest, AppAccountInfo_GetSyncEnable_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountInfo_GetSyncEnable_0100");

    // make sync enable
    bool syncEnable = SYNC_ENABLE_TRUE;

    // make info with sync enable
    AppAccountInfo appAccountInfo;
    appAccountInfo.syncEnable_ = syncEnable;

    // get the sync enable
    bool syncEnableFromInfo = SYNC_ENABLE_FALSE;
    appAccountInfo.GetSyncEnable(syncEnableFromInfo);

    // check the sync enable
    EXPECT_EQ(syncEnable, syncEnableFromInfo);
}

/**
 * @tc.name: AppAccountInfo_SetSyncEnable_0100
 * @tc.desc: Set the sync enable with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI4M8FW
 */
HWTEST_F(AppAccountInfoTest, AppAccountInfo_SetSyncEnable_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountInfo_SetSyncEnable_0100");

    // make sync enable
    bool syncEnable = SYNC_ENABLE_TRUE;

    // make info
    AppAccountInfo appAccountInfo;

    // set the sync enable
    appAccountInfo.SetSyncEnable(syncEnable);

    // check the sync enable
    EXPECT_EQ(syncEnable, appAccountInfo.syncEnable_);
}

/**
 * @tc.name: AppAccountInfo_InitCustomData_0100
 * @tc.desc: Set the custom data with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI5RWXN
 */
HWTEST_F(AppAccountInfoTest, AppAccountInfo_InitCustomData_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountInfo_InitCustomData_0100");

    // make custom data
    std::map<std::string, std::string> customData;
    customData.emplace(STRING_ASSOCIATED_KEY, STRING_ASSOCIATED_VALUE);

    // make info
    AppAccountInfo appAccountInfo;

    ErrCode result = appAccountInfo.InitCustomData(customData);
    EXPECT_EQ(result, ERR_OK);

    std::string test_value;
    appAccountInfo.GetAssociatedData(STRING_ASSOCIATED_KEY, test_value);

    EXPECT_EQ(STRING_ASSOCIATED_VALUE, test_value);
}

/**
 * @tc.name: AppAccountInfo_GetAssociatedData_0100
 * @tc.desc: Get the associated data with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI4M8FW
 */
HWTEST_F(AppAccountInfoTest, AppAccountInfo_GetAssociatedData_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountInfo_GetAssociatedData_0100");

    // make associated data
    std::string associatedData = STRING_ASSOCIATED_DATA;

    // make info with associated data
    AppAccountInfo appAccountInfo;
    appAccountInfo.associatedData_ = associatedData;

    // get the associated data
    std::string value;
    ErrCode result = appAccountInfo.GetAssociatedData(STRING_ASSOCIATED_KEY, value);
    EXPECT_EQ(result, ERR_OK);

    // check the associated value
    EXPECT_EQ(value, STRING_ASSOCIATED_VALUE);
}

/**
 * @tc.name: AppAccountInfo_SetAssociatedData_0100
 * @tc.desc: Set the associated data with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI4M8FW
 */
HWTEST_F(AppAccountInfoTest, AppAccountInfo_SetAssociatedData_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountInfo_SetAssociatedData_0100");

    // make associated data
    std::string key = STRING_ASSOCIATED_KEY;
    std::string value = STRING_ASSOCIATED_VALUE;

    // make info
    AppAccountInfo appAccountInfo;

    // set the associated data
    ErrCode result = appAccountInfo.SetAssociatedData(key, value);
    EXPECT_EQ(result, ERR_OK);

    // check the associated data
    auto jsonObject = Json::parse(appAccountInfo.associatedData_);
    if (jsonObject.is_discarded()) {
        jsonObject = Json::object();
    }
    EXPECT_NE(jsonObject.find(key), jsonObject.end());
    EXPECT_EQ(value, jsonObject[key]);
}

/**
 * @tc.name: AppAccountInfo_GetAccountCredential_0100
 * @tc.desc: Get the account credential with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI4M8FW
 */
HWTEST_F(AppAccountInfoTest, AppAccountInfo_GetAccountCredential_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountInfo_GetAccountCredential_0100");

    // make account credential
    std::string accountCredential = STRING_ACCOUNT_CREDENTIAL;

    // make info with account credential
    AppAccountInfo appAccountInfo;
    appAccountInfo.accountCredential_ = accountCredential;

    // get the credential
    std::string credential;
    ErrCode result = appAccountInfo.GetAccountCredential(STRING_CREDENTIAL_TYPE, credential);
    EXPECT_EQ(result, ERR_OK);

    // check the credential
    EXPECT_EQ(credential, STRING_CREDENTIAL);
}

/**
 * @tc.name: AppAccountInfo_SetAccountCredential_0100
 * @tc.desc: Set the account credential with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI4M8FW
 */
HWTEST_F(AppAccountInfoTest, AppAccountInfo_SetAccountCredential_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountInfo_SetAccountCredential_0100");

    // make account credential
    std::string type = STRING_CREDENTIAL_TYPE;
    std::string credential = STRING_CREDENTIAL;

    // make info
    AppAccountInfo appAccountInfo;

    // set the account credential
    ErrCode result = appAccountInfo.SetAccountCredential(type, credential);
    EXPECT_EQ(result, ERR_OK);

    // check the account credential
    auto jsonObject = Json::parse(appAccountInfo.accountCredential_);
    if (jsonObject.is_discarded()) {
        jsonObject = Json::object();
    }
    EXPECT_NE(jsonObject.find(type), jsonObject.end());
    EXPECT_EQ(credential, jsonObject[type]);
}

/**
 * @tc.name: AppAccountInfo_GetOAuthList_0100
 * @tc.desc: Get a oauth list with non-existent auth type.
 * @tc.type: FUNC
 * @tc.require: issueI4M8FW
 */
HWTEST_F(AppAccountInfoTest, AppAccountInfo_GetOAuthList_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountInfo_GetOAuthList_0100");
    AppAccountInfo appAccountInfo;
    std::set<std::string> oauthList;
    ErrCode result = appAccountInfo.GetOAuthList(STRING_AUTH_TYPE, oauthList);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_TRUE(oauthList.empty());
}

/**
 * @tc.name: AppAccountInfo_GetOAuthList_0200
 * @tc.desc: Get a oauth list with existent auth type.
 * @tc.type: FUNC
 * @tc.require: issueI4M8FW
 */
HWTEST_F(AppAccountInfoTest, AppAccountInfo_GetOAuthList_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountInfo_GetOAuthList_0200");
    AppAccountInfo appAccountInfo;
    std::set<std::string> oauthList;
    ErrCode result = appAccountInfo.SetOAuthTokenVisibility(STRING_AUTH_TYPE, STRING_BUNDLE_NAME, true);
    EXPECT_EQ(result, ERR_OK);
    result = appAccountInfo.GetOAuthList(STRING_AUTH_TYPE, oauthList);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_FALSE(oauthList.empty());
}

/**
 * @tc.name: AppAccountInfo_GetAllOAuthTokens_0100
 * @tc.desc: Get a oauth list with existent auth type.
 * @tc.type: FUNC
 * @tc.require: issueI4M8FW
 */
HWTEST_F(AppAccountInfoTest, AppAccountInfo_GetAllOAuthTokens_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountInfo_GetAllOAuthTokens_0100");
    AppAccountInfo appAccountInfo;
    std::vector<OAuthTokenInfo> tokens;
    ErrCode result = appAccountInfo.SetOAuthToken(STRING_AUTH_TYPE, STRING_TOKEN);
    EXPECT_EQ(result, ERR_OK);
    result = appAccountInfo.GetAllOAuthTokens(tokens);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(tokens.size(), 1);
    EXPECT_EQ(tokens[0].token, STRING_TOKEN);
}

/**
 * @tc.name: AppAccountInfo_ReadTokenInfos_0100
 * @tc.desc: ReadTokenInfos abnormal branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountInfoTest, AppAccountInfo_ReadTokenInfos_0100, TestSize.Level1)
{
    AppAccountInfo appAccountInfo;
    std::map<std::string, OAuthTokenInfo> tokenInfos;
    for (int32_t i = 0; i < OVERLOAD_MAX_TOKEN_NUMBER; ++i) {
        std::string key = STRING_AUTH_TYPE + std::to_string(i);
        OAuthTokenInfo testOAuthTokenInfo;
        testOAuthTokenInfo.authType = std::to_string(i);
        tokenInfos[key] = testOAuthTokenInfo;
    }
    Parcel data;
    EXPECT_EQ(appAccountInfo.WriteTokenInfos(tokenInfos, data), true);
    EXPECT_EQ(appAccountInfo.ReadTokenInfos(tokenInfos, data), false);
}

/**
 * @tc.name: AppAccountInfo_ReadTokenInfos_0200
 * @tc.desc: ReadTokenInfos normal branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountInfoTest, AppAccountInfo_ReadTokenInfos_0200, TestSize.Level1)
{
    AppAccountInfo appAccountInfo;
    std::map<std::string, OAuthTokenInfo> tokenInfos;
    Parcel data;
    std::set<std::string> authList;
    authList.insert(STRING_NAME);
    uint32_t size = 1;
    ASSERT_EQ(data.WriteUint32(size), true);
    ASSERT_EQ(data.WriteString(STRING_AUTH_TYPE), true);
    ASSERT_EQ(data.WriteString(STRING_TOKEN), true);
    ASSERT_EQ(appAccountInfo.WriteStringSet(authList, data), true);
    bool result = appAccountInfo.ReadTokenInfos(tokenInfos, data);
    ASSERT_EQ(result, true);
    ASSERT_EQ(tokenInfos.empty(), false);
    ASSERT_EQ(tokenInfos[STRING_AUTH_TYPE].authType, STRING_AUTH_TYPE);
    ASSERT_EQ(tokenInfos[STRING_AUTH_TYPE].token, STRING_TOKEN);
}

/**
 * @tc.name: AppAccountInfo_SetOAuthTokenVisibility_0100
 * @tc.desc: Set oauth token visibility with non-existent auth type.
 * @tc.type: FUNC
 * @tc.require: issueI4M8FW
 */
HWTEST_F(AppAccountInfoTest, AppAccountInfo_SetOAuthTokenVisibility_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountInfo_SetOAuthTokenVisibility_0100");
    AppAccountInfo appAccountInfo;
    bool isVisible = true;
    for (int32_t i = 0; i < MAX_TOKEN_NUMBER; ++i) {
        std::string key = STRING_AUTH_TYPE + std::to_string(i);
        appAccountInfo.SetOAuthTokenVisibility(key, STRING_BUNDLE_NAME, true);
        appAccountInfo.CheckOAuthTokenVisibility(key, STRING_BUNDLE_NAME, isVisible);
        EXPECT_TRUE(isVisible);
    }
    ErrCode result = appAccountInfo.SetOAuthTokenVisibility(STRING_AUTH_TYPE, STRING_BUNDLE_NAME, true);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_MAX_SIZE);
    appAccountInfo.CheckOAuthTokenVisibility(STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible);
    EXPECT_FALSE(isVisible);
}

/**
 * @tc.name: AppAccountInfo_SetOAuthTokenVisibility_0200
 * @tc.desc: Set oauth token visibility with non-existent auth type.
 * @tc.type: FUNC
 * @tc.require: issueI4M8FW
 */
HWTEST_F(AppAccountInfoTest, AppAccountInfo_SetOAuthTokenVisibility_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountInfo_SetOAuthTokenVisibility_0200");
    AppAccountInfo appAccountInfo;
    bool isVisible = true;
    for (int32_t i = 0; i < MAX_OAUTH_LIST_SIZE; ++i) {
        std::string key = STRING_BUNDLE_NAME + std::to_string(i);
        appAccountInfo.SetOAuthTokenVisibility(STRING_AUTH_TYPE, key, true);
        appAccountInfo.CheckOAuthTokenVisibility(STRING_AUTH_TYPE, key, isVisible);
        EXPECT_TRUE(isVisible);
    }
    ErrCode result = appAccountInfo.SetOAuthTokenVisibility(STRING_AUTH_TYPE, STRING_BUNDLE_NAME, true);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_OAUTH_LIST_MAX_SIZE);
    result = appAccountInfo.CheckOAuthTokenVisibility(STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible);
    EXPECT_FALSE(isVisible);
}

/**
 * @tc.name: AppAccountInfo_SetOAuthTokenVisibility_0300
 * @tc.desc: Set oauth token visibility with existent auth type.
 * @tc.type: FUNC
 * @tc.require: issueI4M8FW
 */
HWTEST_F(AppAccountInfoTest, AppAccountInfo_SetOAuthTokenVisibility_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountInfo_SetOAuthTokenVisibility_0300");
    AppAccountInfo appAccountInfo;
    appAccountInfo.SetOAuthTokenVisibility(STRING_AUTH_TYPE, STRING_BUNDLE_NAME, true);
    bool isVisible = false;
    appAccountInfo.CheckOAuthTokenVisibility(STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible);
    EXPECT_TRUE(isVisible);
    appAccountInfo.SetOAuthTokenVisibility(STRING_AUTH_TYPE, STRING_BUNDLE_NAME_TWO, true);
    appAccountInfo.CheckOAuthTokenVisibility(STRING_AUTH_TYPE, STRING_BUNDLE_NAME_TWO, isVisible);
    EXPECT_TRUE(isVisible);
}

/**
 * @tc.name: AppAccountInfo_SetOAuthTokenVisibility_0400
 * @tc.desc: Setoauthtokenvisibility success with bundlename is owner.
 * @tc.type: FUNC
 * @tc.require: issueI4M8FW
 */
HWTEST_F(AppAccountInfoTest, AppAccountInfo_SetOAuthTokenVisibility_0400, TestSize.Level1)
{
    AppAccountInfo appAccountInfo;
    appAccountInfo.owner_ = STRING_OWNER;
    bool isVisible = false;
    ErrCode result = appAccountInfo.SetOAuthTokenVisibility(STRING_AUTH_TYPE, STRING_OWNER, isVisible);
    ASSERT_EQ(result, ERR_OK);
    appAccountInfo.CheckOAuthTokenVisibility(STRING_AUTH_TYPE, STRING_OWNER, isVisible);
    EXPECT_TRUE(isVisible);
}

/**
 * @tc.name: AppAccountInfo_SetOAuthTokenVisibility_0500
 * @tc.desc: Setoauthtokenvisibility success with isVisible is false.
 * @tc.type: FUNC
 * @tc.require: issueI4M8FW
 */
HWTEST_F(AppAccountInfoTest, AppAccountInfo_SetOAuthTokenVisibility_0500, TestSize.Level1)
{
    AppAccountInfo appAccountInfo;
    bool isVisible = false;
    ErrCode result = appAccountInfo.SetOAuthTokenVisibility(STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible);
    ASSERT_EQ(result, ERR_OK);
    appAccountInfo.CheckOAuthTokenVisibility(STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible);
    EXPECT_FALSE(isVisible);
}

/**
 * @tc.name: AppAccountInfo_OAuthToken_0100
 * @tc.desc: Get, set, delete oauth token.
 * @tc.type: FUNC
 * @tc.require: issueI4M8FW
 */
HWTEST_F(AppAccountInfoTest, AppAccountInfo_OAuthToken_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountInfo_GetOAuthToken_0100");
    AppAccountInfo appAccountInfo;
    std::string token;
    ErrCode result = appAccountInfo.GetOAuthToken(STRING_AUTH_TYPE, token);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_NOT_EXIST);
    token = STRING_TOKEN;
    result = appAccountInfo.SetOAuthToken(STRING_AUTH_TYPE, token);
    EXPECT_EQ(result, ERR_OK);
    token = STRING_EMPTY;
    result = appAccountInfo.GetOAuthToken(STRING_AUTH_TYPE, token);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(token, STRING_TOKEN);
    result = appAccountInfo.DeleteOAuthToken(STRING_AUTH_TYPE, token);
    EXPECT_EQ(result, ERR_OK);
    result = appAccountInfo.GetOAuthToken(STRING_AUTH_TYPE, token);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_NOT_EXIST);
}

/**
 * @tc.name: AppAccountInfo SetOAuthToken test
 * @tc.desc: Func SetOAuthToken success with authType is in oauthTokens.
 * @tc.type: FUNC
 * @tc.require
 */
HWTEST_F(AppAccountInfoTest, SetOAuthToken002, TestSize.Level0)
{
    AppAccountInfo appAccountInfo;
    OAuthTokenInfo oauthTokenInfo;
    oauthTokenInfo.token = STRING_TOKEN;
    std::string token = STRING_TOKEN;
    appAccountInfo.oauthTokens_[STRING_AUTH_TYPE] = oauthTokenInfo;
    ErrCode result = appAccountInfo.SetOAuthToken(STRING_AUTH_TYPE, token);
    ASSERT_EQ(result, ERR_OK);
    ASSERT_EQ(appAccountInfo.oauthTokens_[STRING_AUTH_TYPE].token, token);
}

/**
 * @tc.name: AppAccountInfo SetOAuthToken test
 * @tc.desc: Func SetOAuthToken falied with oauthTokens oversize.
 * @tc.type: FUNC
 * @tc.require
 */
HWTEST_F(AppAccountInfoTest, SetOAuthToken003, TestSize.Level0)
{
    AppAccountInfo appAccountInfo;
    OAuthTokenInfo oauthTokenInfo;
    for (int i = 0; i <= MAX_TOKEN_NUMBER; i++) {
        std::string key = STRING_AUTH_TYPE + std::to_string(i);
        appAccountInfo.oauthTokens_[key] = oauthTokenInfo;
    }
    std::string token;
    ErrCode result = appAccountInfo.SetOAuthToken(STRING_AUTH_TYPE, token);
    ASSERT_EQ(result, ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_MAX_SIZE);
}

/**
 * @tc.name: AppAccountInfo_Marshalling_0100
 * @tc.desc: Marshalling Unmarshalling with valid data.
 * @tc.type: FUNC
 * @tc.require: issueI4M8FW
 */
HWTEST_F(AppAccountInfoTest, AppAccountInfo_Marshalling_0100, TestSize.Level0)
{
    ACCOUNT_LOGI("AppAccountInfo_Marshalling_0100");

    // make some data
    std::string owner = STRING_OWNER;
    std::string name = STRING_NAME;
    std::string extraInfo = STRING_EXTRA_INFO;
    std::set<std::string> authorizedApps;
    authorizedApps.emplace(STRING_OWNER);
    bool syncEnable = SYNC_ENABLE_TRUE;
    std::string associatedData = STRING_ASSOCIATED_DATA;
    std::string accountCredential = STRING_ACCOUNT_CREDENTIAL;

    // make info with an owner
    AppAccountInfo appAccountInfo;

    appAccountInfo.owner_ = owner;
    appAccountInfo.name_ = name;
    appAccountInfo.extraInfo_ = extraInfo;
    appAccountInfo.authorizedApps_ = authorizedApps;
    appAccountInfo.syncEnable_ = syncEnable;
    appAccountInfo.associatedData_ = associatedData;
    appAccountInfo.accountCredential_ = accountCredential;

    // marshalling
    Parcel parcel;
    EXPECT_EQ(appAccountInfo.Marshalling(parcel), true);

    // unmarshalling
    auto infoPtr = AppAccountInfo::Unmarshalling(parcel);
    EXPECT_NE(infoPtr, nullptr);

    // check the data
    EXPECT_EQ(owner, infoPtr->owner_);
    EXPECT_EQ(name, infoPtr->name_);
    EXPECT_EQ(extraInfo, infoPtr->extraInfo_);
    EXPECT_EQ(authorizedApps.size(), infoPtr->authorizedApps_.size());
    EXPECT_EQ(*(authorizedApps.begin()), *(infoPtr->authorizedApps_.begin()));
    EXPECT_EQ(syncEnable, infoPtr->syncEnable_);
    EXPECT_EQ(associatedData, infoPtr->associatedData_);
    EXPECT_EQ(accountCredential, infoPtr->accountCredential_);
}

/**
 * @tc.name: AppAccountInfo GetName test
 * @tc.desc: Func GetName.
 * @tc.type: FUNC
 * @tc.require
 */
HWTEST_F(AppAccountInfoTest, GetName001, TestSize.Level0)
{
    AppAccountInfo testInfo;
    testInfo.SetName("test");
    EXPECT_EQ(testInfo.GetName(), "test");
    testInfo.SetOwner("test");
    EXPECT_EQ(testInfo.GetOwner(), "test");
}

/**
 * @tc.name: AppAccountInfo WriteStringMap test
 * @tc.desc: Func WriteStringMap.
 * @tc.type: FUNC
 * @tc.require
 */
HWTEST_F(AppAccountInfoTest, WriteStringMap001, TestSize.Level0)
{
    AppAccountInfo testInfo;
    Parcel data;
    std::map<std::string, std::string> stringSet;
    std::map<std::string, std::string> stringMap;
    stringSet["testkey"] = "testvalue";
    EXPECT_EQ(testInfo.WriteStringMap(stringSet, data), true);
    EXPECT_EQ(testInfo.ReadStringMap(stringMap, data), true);
    EXPECT_EQ(stringMap["testkey"], "testvalue");
}

/**
 * @tc.name: AppAccountInfo_SetOAuthTokenVisibility_0600
 * @tc.desc: Setoauthtokenvisibility failed with authType is not exist of func api9.
 * @tc.type: FUNC
 * @tc.require: issueI4M8FW
 */
HWTEST_F(AppAccountInfoTest, AppAccountInfo_SetOAuthTokenVisibility_0600, TestSize.Level1)
{
    AppAccountInfo appAccountInfo;
    bool isVisible = false;
    int32_t apiVersion = 9;
    ErrCode result = appAccountInfo.SetOAuthTokenVisibility(
        STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible, apiVersion);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_OAUTH_TYPE_NOT_EXIST);
    result = appAccountInfo.CheckOAuthTokenVisibility(STRING_AUTH_TYPE, STRING_BUNDLE_NAME, isVisible, apiVersion);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_OAUTH_TYPE_NOT_EXIST);
}

/**
 * @tc.name: AppAccountInfo_OAuthToken_0200
 * @tc.desc: Get, set, delete oauth token with api9 func, and test delete self token.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountInfoTest, AppAccountInfo_OAuthToken_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountInfo_OAuthToken_0200");
    AppAccountInfo appAccountInfo;
    std::string token;
    int32_t apiVersion = 9;
    ErrCode result = appAccountInfo.GetOAuthToken(STRING_AUTH_TYPE, token);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_NOT_EXIST);
    token = STRING_TOKEN;
    result = appAccountInfo.SetOAuthToken(STRING_AUTH_TYPE, token);
    EXPECT_EQ(result, ERR_OK);
    token = STRING_EMPTY;
    result = appAccountInfo.GetOAuthToken(STRING_AUTH_TYPE, token, apiVersion);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(token, STRING_TOKEN);
    result = appAccountInfo.DeleteAuthToken(STRING_AUTH_TYPE, token, true);
    EXPECT_EQ(result, ERR_OK);
    result = appAccountInfo.GetOAuthToken(STRING_AUTH_TYPE, token, apiVersion);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_NOT_EXIST);
}

/**
 * @tc.name: AppAccountInfo_OAuthToken_0300
 * @tc.desc: Get, set, delete oauth token with api9 func, and test delete other token.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountInfoTest, AppAccountInfo_OAuthToken_0300, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountInfo_OAuthToken_0300");
    AppAccountInfo appAccountInfo;
    std::string token;
    int32_t apiVersion = 9;
    ErrCode result = appAccountInfo.GetOAuthToken(STRING_AUTH_TYPE, token);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_NOT_EXIST);
    token = STRING_TOKEN;
    result = appAccountInfo.SetOAuthToken(STRING_AUTH_TYPE, token);
    EXPECT_EQ(result, ERR_OK);
    token = STRING_EMPTY;
    result = appAccountInfo.GetOAuthToken(STRING_AUTH_TYPE, token, apiVersion);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(token, STRING_TOKEN);
    result = appAccountInfo.DeleteAuthToken(STRING_AUTH_TYPE, token, false);
    EXPECT_EQ(result, ERR_OK);
    result = appAccountInfo.GetOAuthToken(STRING_AUTH_TYPE, token, apiVersion);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_NOT_EXIST);
}

/**
 * @tc.name: AppAccountInfo_OAuthToken_0400
 * @tc.desc: Get, set, delete oauth token with api9 func, and test delete self invalid token.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountInfoTest, AppAccountInfo_OAuthToken_0400, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountInfo_OAuthToken_0400");
    AppAccountInfo appAccountInfo;
    std::string token;
    int32_t apiVersion = 9;
    ErrCode result = appAccountInfo.GetOAuthToken(STRING_AUTH_TYPE, token);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_NOT_EXIST);
    token = STRING_TOKEN;
    result = appAccountInfo.SetOAuthToken(STRING_AUTH_TYPE, token);
    EXPECT_EQ(result, ERR_OK);
    std::string newToken = "test_new_token";
    result = appAccountInfo.SetOAuthToken(STRING_AUTH_TYPE, newToken);
    EXPECT_EQ(result, ERR_OK);
    token = STRING_EMPTY;
    result = appAccountInfo.GetOAuthToken(STRING_AUTH_TYPE, token, apiVersion);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(token, newToken);
    result = appAccountInfo.DeleteAuthToken(STRING_AUTH_TYPE, token, true);
    EXPECT_EQ(result, ERR_OK);
    result = appAccountInfo.GetOAuthToken(STRING_AUTH_TYPE, token, apiVersion);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_NOT_EXIST);
}

/**
 * @tc.name: AppAccountInfo_OAuthToken_0500
 * @tc.desc: Get, set, delete oauth token with api9 func, and test delete other invalid token.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountInfoTest, AppAccountInfo_OAuthToken_0500, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountInfo_OAuthToken_0500");
    AppAccountInfo appAccountInfo;
    std::string token;
    int32_t apiVersion = 9;
    ErrCode result = appAccountInfo.GetOAuthToken(STRING_AUTH_TYPE, token);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_NOT_EXIST);
    token = STRING_TOKEN;
    result = appAccountInfo.SetOAuthToken(STRING_AUTH_TYPE, token);
    EXPECT_EQ(result, ERR_OK);
    std::string newToken = "test_new_token";
    result = appAccountInfo.SetOAuthToken(STRING_AUTH_TYPE, newToken);
    EXPECT_EQ(result, ERR_OK);
    token = STRING_EMPTY;
    result = appAccountInfo.GetOAuthToken(STRING_AUTH_TYPE, token, apiVersion);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(token, newToken);
    result = appAccountInfo.DeleteAuthToken(STRING_AUTH_TYPE, token, false);
    EXPECT_EQ(result, ERR_OK);
    result = appAccountInfo.GetOAuthToken(STRING_AUTH_TYPE, token, apiVersion);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_NOT_EXIST);
}
