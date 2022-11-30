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

#include <thread>

#include "account_log_wrapper.h"
#include "app_account_constants.h"
#define private public
#include "app_account_control_manager.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string STRING_NAME = "name";
const std::string STRING_NAME_BACK = "end";
const std::string STRING_EXTRA_INFO = "extra_info";
const std::string STRING_OWNER = "com.example.owner";
const std::string AUTHORIZED_APP = "authorizedApp";
const std::string BUNDLE_NAME = "bundlename";

const std::size_t ACCOUNT_MAX_SIZE = 1000;
const std::int32_t DELAY_FOR_OPERATION = 250;

constexpr std::int32_t UID = 10000;
}  // namespace

class AppAccountControlManagerModuleTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override;
    void TearDown(void) override;
    std::shared_ptr<AppAccountControlManager> controlManagerPtr_ = AppAccountControlManager::GetInstance();
};

void AppAccountControlManagerModuleTest::SetUpTestCase(void)
{}

void AppAccountControlManagerModuleTest::TearDownTestCase(void)
{
    GTEST_LOG_(INFO) << "TearDownTestCase enter";
    DelayedSingleton<AppAccountControlManager>::DestroyInstance();
}

void AppAccountControlManagerModuleTest::SetUp(void)
{}

void AppAccountControlManagerModuleTest::TearDown(void)
{}

/**
 * @tc.name: AppAccountControlManager_AccountMaxSize_0100
 * @tc.desc: Check account max size with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountControlManagerModuleTest, AppAccountControlManager_AccountMaxSize_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountControlManager_AccountMaxSize_0100");

    ASSERT_NE(controlManagerPtr_, nullptr);

    EXPECT_EQ(controlManagerPtr_->ACCOUNT_MAX_SIZE, ACCOUNT_MAX_SIZE);
}

/**
 * @tc.name: AppAccountControlManager_AccountMaxSize_0200
 * @tc.desc: Check account max size with valid data.
 * @tc.type: FUNC
 * @tc.require: SR000GGVFV
 */
HWTEST_F(AppAccountControlManagerModuleTest, AppAccountControlManager_AccountMaxSize_0200, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountControlManager_AccountMaxSize_0200");

    ASSERT_NE(controlManagerPtr_, nullptr);

    ErrCode result;
    std::string name;
    for (std::size_t index = 0; index < ACCOUNT_MAX_SIZE; index++) {
        name = STRING_NAME + std::to_string(index);
        ACCOUNT_LOGI("before AddAccount, index = %{public}zu", index);
        GTEST_LOG_(INFO) << "before AddAccount, index = " << index;

        AppAccountInfo appAccountInfo(name, STRING_OWNER);
        result = controlManagerPtr_->AddAccount(name, STRING_EXTRA_INFO, UID, STRING_OWNER, appAccountInfo);
        ASSERT_EQ(result, ERR_OK);

        std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_OPERATION));
    }

    AppAccountInfo appAccountInfo(STRING_NAME, STRING_OWNER);
    result = controlManagerPtr_->AddAccount(STRING_NAME, STRING_EXTRA_INFO, UID, STRING_OWNER, appAccountInfo);
    EXPECT_EQ(result, ERR_APPACCOUNT_SERVICE_ACCOUNT_MAX_SIZE);

    for (std::size_t index = 0; index < ACCOUNT_MAX_SIZE; index++) {
        name = STRING_NAME + std::to_string(index);
        ACCOUNT_LOGI("before DeleteAccount, index = %{public}zu", index);
        GTEST_LOG_(INFO) << "before DeleteAccount, index = " << index;

        AppAccountInfo appAccountInfo(name, STRING_OWNER);
        result = controlManagerPtr_->DeleteAccount(name, UID, STRING_OWNER, appAccountInfo);
        ASSERT_EQ(result, ERR_OK);

        std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_FOR_OPERATION));
    }
}

/**
 * @tc.name: AppAccountControlManager_dataStoragePtrIsNull_0100
 * @tc.desc: dataStoragePtrIsNull test app account control manager dataStoragePtr is null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountControlManagerModuleTest, AppAccountControlManager_dataStoragePtrIsNull_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountControlManager_RemoveAuthorizedAccountFromDataStorage_0100");

    ASSERT_NE(controlManagerPtr_, nullptr);
    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = nullptr;
    AppAccountInfo appAccountInfo;
    ErrCode result =
        controlManagerPtr_->RemoveAuthorizedAccountFromDataStorage(AUTHORIZED_APP, appAccountInfo, dataStoragePtr);
    ASSERT_EQ(result, ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR);

    result = controlManagerPtr_->SaveAuthorizedAccountIntoDataStorage(AUTHORIZED_APP, appAccountInfo, dataStoragePtr);
    ASSERT_EQ(result, ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR);

    result = controlManagerPtr_->RemoveAuthorizedAccount(BUNDLE_NAME, appAccountInfo, dataStoragePtr, UID);
    ASSERT_EQ(result, ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR);

    result = controlManagerPtr_->SaveAuthorizedAccount(BUNDLE_NAME, appAccountInfo, dataStoragePtr, UID);
    ASSERT_EQ(result, ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR);

    result = controlManagerPtr_->DeleteAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr, UID);
    ASSERT_EQ(result, ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR);

    result = controlManagerPtr_->SaveAccountInfoIntoDataStorage(appAccountInfo, dataStoragePtr, UID);
    ASSERT_EQ(result, ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR);

    result = controlManagerPtr_->AddAccountInfoIntoDataStorage(appAccountInfo, dataStoragePtr, UID);
    ASSERT_EQ(result, ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR);

    result = controlManagerPtr_->GetAccountInfoFromDataStorage(appAccountInfo, dataStoragePtr);
    ASSERT_EQ(result, ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR);

    std::vector<AppAccountInfo> appAccounts;
    result = controlManagerPtr_->GetAllAccessibleAccountsFromDataStorage(appAccounts, BUNDLE_NAME, dataStoragePtr, 0);
    ASSERT_EQ(result, ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR);
}

/**
 * @tc.name: AppAccountControlManager_NeedSyncDataStorage_0100
 * @tc.desc: NeedSyncDataStorage abnormal branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountControlManagerModuleTest, AppAccountControlManager_NeedSyncDataStorage_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountControlManager_GNeedSyncDataStorage_0100");

    ASSERT_NE(controlManagerPtr_, nullptr);

    AppAccountInfo appAccountInfo;
    bool syncEnable = false;
    appAccountInfo.SetSyncEnable(syncEnable);
    syncEnable = true;
    appAccountInfo.GetSyncEnable(syncEnable);
    ASSERT_EQ(syncEnable, false);
    bool result = controlManagerPtr_->NeedSyncDataStorage(appAccountInfo);
    ASSERT_EQ(result, false);
}

/**
 * @tc.name: AppAccountControlManager_GetAllAccountsFromDataStorage_0100
 * @tc.desc: GetAllAccountsFromDataStorage abnormal branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(
    AppAccountControlManagerModuleTest, AppAccountControlManager_GetAllAccountsFromDataStorage_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountControlManager_GetAllAccountsFromDataStorage_0100");

    ASSERT_NE(controlManagerPtr_, nullptr);

    AppExecFwk::AbilityStateData abilityStateData;
    abilityStateData.abilityState = static_cast<int32_t>(AppExecFwk::AbilityState::ABILITY_STATE_TERMINATED);
    controlManagerPtr_->OnAbilityStateChanged(abilityStateData);
    ASSERT_EQ(controlManagerPtr_->associatedDataCache_.empty(), true);

    abilityStateData.abilityState = static_cast<int32_t>(AppExecFwk::AbilityState::ABILITY_STATE_BACKGROUND);
    controlManagerPtr_->OnAbilityStateChanged(abilityStateData);
    std::vector<AppAccountInfo> appAccounts;

    std::shared_ptr<AppAccountDataStorage> dataStoragePtr = nullptr;
    ErrCode result =
        controlManagerPtr_->GetAllAccountsFromDataStorage(STRING_OWNER, appAccounts, BUNDLE_NAME, dataStoragePtr);
    ASSERT_EQ(result, ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR);
}

/**
 * @tc.name: AppAccountControlManager_GetAllOAuthTokens_0100
 * @tc.desc: GetAllOAuthTokens abnormal branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppAccountControlManagerModuleTest, AppAccountControlManager_GetAllOAuthTokens_0100, TestSize.Level1)
{
    ACCOUNT_LOGI("AppAccountControlManager_GetAllOAuthTokens_0100");

    ASSERT_NE(controlManagerPtr_, nullptr);

    AuthenticatorSessionRequest request;
    request.name = STRING_NAME;
    request.owner = STRING_OWNER;
    request.callerBundleName = BUNDLE_NAME;
    request.appIndex = 0;
    request.callerUid = 0;
    std::vector<OAuthTokenInfo> tokenInfos;
    AppAccountInfo appAccountInfo(request.name, request.owner);
    std::string authTypeOne = "test_authType1";
    std::string authTokenOne = "test_authToken1";
    std::string authTypeTwo = "test_authType2";
    std::string authTokenTwo = "test_authToken2";
    std::string authTypeThree = "test_authType3";
    std::string authTokenThree = "";
    appAccountInfo.SetOAuthToken(authTypeOne, authTokenOne);
    appAccountInfo.SetOAuthToken(authTypeTwo, authTokenTwo);
    appAccountInfo.SetOAuthToken(authTypeThree, authTokenThree);
    appAccountInfo.SetOAuthTokenVisibility(authTypeOne, BUNDLE_NAME, true, Constants::API_VERSION8);
    appAccountInfo.SetSyncEnable(true);
    bool isSyncEnable = false;
    appAccountInfo.GetSyncEnable(isSyncEnable);
    ASSERT_NE(isSyncEnable, false);
    auto dataStoragePtr = controlManagerPtr_->GetDataStorage(request.callerUid, false);
    ASSERT_NE(dataStoragePtr, nullptr);
    ErrCode result =
        controlManagerPtr_->AddAccountInfoIntoDataStorage(appAccountInfo, dataStoragePtr, request.callerUid);
    ASSERT_EQ(result, ERR_OK);
    result = controlManagerPtr_->GetAllOAuthTokens(request, tokenInfos);
    ASSERT_EQ(result, ERR_OK);
    EXPECT_EQ(tokenInfos.size(), 1);
}
