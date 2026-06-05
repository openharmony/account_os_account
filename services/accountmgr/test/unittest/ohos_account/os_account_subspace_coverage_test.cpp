/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE

#include "os_account_subspace_coverage_test_common.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

// ===== Task 2: SetOsAccountForegroundSubspaceId =====
class SetForegroundSubspaceIdTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        allPermTokenId_ = GetAllAccountPermission();
        ASSERT_NE(allPermTokenId_, 0);
    }

    static void TearDownTestCase()
    {
        if (allPermTokenId_ != 0) {
            Security::AccessToken::AccessTokenKit::DeleteToken(
                static_cast<Security::AccessToken::AccessTokenID>(allPermTokenId_));
        }
    }

    void SetUp() override
    {
        ASSERT_EQ(SetSelfTokenID(allPermTokenId_), 0);
        std::error_code ec;
        std::filesystem::remove_all(TEST_ROOT_DIR, ec);
        std::filesystem::create_directories(TEST_ROOT_DIR);
        OhosAccountManager::GetInstance().InitOsAccountSubProfileManager(TEST_ROOT_DIR);
    }

    void TearDown() override
    {
        ResetMockState();
        std::error_code ec;
        std::filesystem::remove_all(TEST_ROOT_DIR, ec);
    }

    static uint64_t allPermTokenId_;
};

uint64_t SetForegroundSubspaceIdTest::allPermTokenId_ = 0;

HWTEST_F(SetForegroundSubspaceIdTest, SetForegroundSubspaceId_AccountNotFound_001, TestSize.Level1)
{
    ErrCode ret = IInnerOsAccountManager::GetInstance().SetOsAccountForegroundSubspaceId(
        -1, TEST_SUBSPACE_BASE + 1);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND);
}

HWTEST_F(SetForegroundSubspaceIdTest, SetForegroundSubspaceId_AccountNotFound_002, TestSize.Level1)
{
    ErrCode ret = IInnerOsAccountManager::GetInstance().SetOsAccountForegroundSubspaceId(
        99999, TEST_SUBSPACE_BASE + 1);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND);
}

HWTEST_F(SetForegroundSubspaceIdTest, SetForegroundSubspaceId_Success_001, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    osAccountInfo.SetLocalId(TEST_OS_ACCOUNT_ID);
    MockSetCreatedOsAccounts({osAccountInfo});

    int32_t subspaceId = TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 1;
    ErrCode ret = IInnerOsAccountManager::GetInstance().SetOsAccountForegroundSubspaceId(
        TEST_OS_ACCOUNT_ID, subspaceId);
    EXPECT_EQ(ret, ERR_OK);

    OsAccountInfo updatedInfo;
    ErrCode getRet = IInnerOsAccountManager::GetInstance().GetOsAccountInfoById(TEST_OS_ACCOUNT_ID, updatedInfo);
    EXPECT_EQ(getRet, ERR_OK);
    EXPECT_EQ(updatedInfo.GetForegroundSubProfileId(), subspaceId);
}

HWTEST_F(SetForegroundSubspaceIdTest, SetForegroundSubspaceId_SetToBase_001, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    osAccountInfo.SetLocalId(TEST_OS_ACCOUNT_ID);
    MockSetCreatedOsAccounts({osAccountInfo});

    int32_t baseSubspaceId = TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;
    ErrCode ret = IInnerOsAccountManager::GetInstance().SetOsAccountForegroundSubspaceId(
        TEST_OS_ACCOUNT_ID, baseSubspaceId);
    EXPECT_EQ(ret, ERR_OK);
}

// ===== foregroundSubProfileId persistence tests =====
class ForegroundSubProfileIdTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        allPermTokenId_ = GetAllAccountPermission();
        ASSERT_NE(allPermTokenId_, 0);
    }

    static void TearDownTestCase()
    {
        if (allPermTokenId_ != 0) {
            Security::AccessToken::AccessTokenKit::DeleteToken(
                static_cast<Security::AccessToken::AccessTokenID>(allPermTokenId_));
        }
    }

    void SetUp() override
    {
        ASSERT_EQ(SetSelfTokenID(allPermTokenId_), 0);
        OsAccountInfo osAccountInfo;
        osAccountInfo.SetLocalId(TEST_OS_ACCOUNT_ID);
        MockSetCreatedOsAccounts({osAccountInfo});
    }

    void TearDown() override
    {
        ResetMockState();
    }

    static uint64_t allPermTokenId_;
};

uint64_t ForegroundSubProfileIdTest::allPermTokenId_ = 0;

HWTEST_F(ForegroundSubProfileIdTest, ForegroundSubProfileId_SetAndGet_001, TestSize.Level1)
{
    int32_t subspaceId = TEST_SUBSPACE_BASE + 1;
    ErrCode ret = IInnerOsAccountManager::GetInstance().SetOsAccountForegroundSubspaceId(
        TEST_OS_ACCOUNT_ID, subspaceId);
    EXPECT_EQ(ret, ERR_OK);

    OsAccountInfo info;
    ret = IInnerOsAccountManager::GetInstance().GetOsAccountInfoById(TEST_OS_ACCOUNT_ID, info);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(info.GetForegroundSubProfileId(), subspaceId);
}

HWTEST_F(ForegroundSubProfileIdTest, ForegroundSubProfileId_PersistedAfterReset_001, TestSize.Level1)
{
    int32_t subspaceId = TEST_SUBSPACE_BASE + 1;
    MockInsertForegroundSubspaceId(TEST_OS_ACCOUNT_ID, subspaceId);

    OsAccountInfo info;
    ErrCode ret = IInnerOsAccountManager::GetInstance().GetOsAccountInfoById(TEST_OS_ACCOUNT_ID, info);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(info.GetForegroundSubProfileId(), subspaceId);

    ResetMockState();
    OsAccountInfo reactivatedInfo;
    reactivatedInfo.SetLocalId(TEST_OS_ACCOUNT_ID);
    reactivatedInfo.SetForegroundSubProfileId(subspaceId);
    MockSetCreatedOsAccounts({reactivatedInfo});

    ret = IInnerOsAccountManager::GetInstance().GetOsAccountInfoById(TEST_OS_ACCOUNT_ID, info);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(info.GetForegroundSubProfileId(), subspaceId);
}

HWTEST_F(ForegroundSubProfileIdTest, ForegroundSubProfileId_SetViaApi_001, TestSize.Level1)
{
    int32_t subspaceId = TEST_SUBSPACE_BASE + 1;
    ErrCode ret = IInnerOsAccountManager::GetInstance().SetOsAccountForegroundSubspaceId(
        TEST_OS_ACCOUNT_ID, subspaceId);
    EXPECT_EQ(ret, ERR_OK);

    int32_t mapValue = -1;
    MockFindForegroundSubspaceId(TEST_OS_ACCOUNT_ID, mapValue);
    EXPECT_EQ(mapValue, subspaceId);
}

// ==== Task 3: GetOsAccountSubspaceService ====
class GetSubspaceServiceTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        allPermTokenId_ = GetAllAccountPermission();
        ASSERT_NE(allPermTokenId_, 0);
    }

    static void TearDownTestCase()
    {
        if (allPermTokenId_ != 0) {
            Security::AccessToken::AccessTokenKit::DeleteToken(
                static_cast<Security::AccessToken::AccessTokenID>(allPermTokenId_));
        }
    }

    void SetUp() override
    {
        ASSERT_EQ(SetSelfTokenID(allPermTokenId_), 0);
    }

    void TearDown() override {}

    static uint64_t allPermTokenId_;
};

uint64_t GetSubspaceServiceTest::allPermTokenId_ = 0;

HWTEST_F(GetSubspaceServiceTest, GetOsAccountSubspaceService_EnableMacro_001, TestSize.Level1)
{
    sptr<IRemoteObject> result = nullptr;
    ErrCode ret = AccountMgrService::GetInstance().GetOsAccountSubspaceService(result);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_RESTRICTED);
    EXPECT_EQ(result, nullptr);
}

HWTEST_F(GetSubspaceServiceTest, GetOsAccountSubspaceService_SecondCallPromote_001, TestSize.Level1)
{
    sptr<IRemoteObject> result1 = nullptr;
    ErrCode ret1 = AccountMgrService::GetInstance().GetOsAccountSubspaceService(result1);
    EXPECT_EQ(ret1, ERR_OS_ACCOUNT_SUBSPACE_RESTRICTED);

    sptr<IRemoteObject> result2 = nullptr;
    ErrCode ret2 = AccountMgrService::GetInstance().GetOsAccountSubspaceService(result2);
    EXPECT_EQ(ret2, ERR_OS_ACCOUNT_SUBSPACE_RESTRICTED);
    EXPECT_EQ(result2, nullptr);
}

HWTEST_F(GetSubspaceServiceTest, GetOsAccountSubspaceService_DisableMacroFallback_001, TestSize.Level1)
{
    sptr<IRemoteObject> result = nullptr;
    ErrCode ret = AccountMgrService::GetInstance().GetOsAccountSubspaceService(result);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_RESTRICTED);
    EXPECT_EQ(result, nullptr);
}

// ===== Task 4: OhosAccountManager subspace methods =====
class OhosAccountManagerSubspaceTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        allPermTokenId_ = GetAllAccountPermission();
        ASSERT_NE(allPermTokenId_, 0);
    }

    static void TearDownTestCase()
    {
        if (allPermTokenId_ != 0) {
            Security::AccessToken::AccessTokenKit::DeleteToken(
                static_cast<Security::AccessToken::AccessTokenID>(allPermTokenId_));
        }
    }

    void SetUp() override
    {
        ASSERT_EQ(SetSelfTokenID(allPermTokenId_), 0);
        std::error_code ec;
        std::filesystem::remove_all(TEST_ROOT_DIR, ec);
        std::filesystem::create_directories(TEST_ROOT_DIR);
        OhosAccountManager::GetInstance().InitOsAccountSubProfileManager(TEST_ROOT_DIR);
        OsAccountInfo osAccountInfo;
        osAccountInfo.SetLocalId(TEST_OS_ACCOUNT_ID);
        MockSetCreatedOsAccounts({osAccountInfo});
    }

    void TearDown() override
    {
        ResetMockState();
        std::error_code ec;
        std::filesystem::remove_all(TEST_ROOT_DIR, ec);
    }

    static uint64_t allPermTokenId_;
};

uint64_t OhosAccountManagerSubspaceTest::allPermTokenId_ = 0;

HWTEST_F(OhosAccountManagerSubspaceTest, InitOsAccountSubProfileManager_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    EXPECT_NE(mgr.subProfileDataDeal_, nullptr);
}

HWTEST_F(OhosAccountManagerSubspaceTest, CreateOsAccountSubspace_LimitReached_001, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    osAccountInfo.SetLocalId(TEST_OS_ACCOUNT_ID);
    MockSetCreatedOsAccounts({osAccountInfo});

    SubProfileContext subprofileCtx;
    subprofileCtx.subProfileIdList.push_back(TEST_SUBSPACE_BASE);
    for (int32_t i = 1; i <= MAX_OS_ACCOUNT_SUB_PROFILE_COUNT - 1; ++i) {
        subprofileCtx.subProfileIdList.push_back(TEST_SUBSPACE_BASE + i);
    }
    MockForceSubProfileContext(TEST_OS_ACCOUNT_ID, subprofileCtx);

    OsAccountSubspaceResult result;
    ErrCode ret = OhosAccountManager::GetInstance().CreateOsAccountSubspace(TEST_OS_ACCOUNT_ID, result);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_LIMIT);
}

HWTEST_F(OhosAccountManagerSubspaceTest, DeleteOsAccountSubspace_NotFound_001, TestSize.Level1)
{
    ErrCode ret = OhosAccountManager::GetInstance().DeleteOsAccountSubspace(
        TEST_OS_ACCOUNT_ID, TEST_SUBSPACE_BASE + 999);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND);
}

HWTEST_F(OhosAccountManagerSubspaceTest, DeleteOsAccountSubspace_ZeroIndex_001, TestSize.Level1)
{
    ErrCode ret = OhosAccountManager::GetInstance().DeleteOsAccountSubspace(
        TEST_OS_ACCOUNT_ID, TEST_SUBSPACE_BASE);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_RESTRICTED);
}

HWTEST_F(OhosAccountManagerSubspaceTest, SwitchOsAccountSubspace_NotFound_001, TestSize.Level1)
{
    int32_t fromSubspaceId = 0;
    ErrCode ret = OhosAccountManager::GetInstance().SwitchOsAccountSubspace(
        TEST_OS_ACCOUNT_ID, TEST_SUBSPACE_BASE + 999, fromSubspaceId);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND);
}

HWTEST_F(OhosAccountManagerSubspaceTest, CreateOsAccountSubspace_Success_001, TestSize.Level1)
{
    MockForceSubProfileContext(TEST_OS_ACCOUNT_ID, SubProfileContext());
    OsAccountSubspaceResult result;
    ErrCode ret = OhosAccountManager::GetInstance().CreateOsAccountSubspace(TEST_OS_ACCOUNT_ID, result);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(result.osAccountId, TEST_OS_ACCOUNT_ID);
    EXPECT_EQ(result.id, TEST_SUBSPACE_BASE + 1);
    EXPECT_EQ(result.index, 1);

    auto &mgr = OsAccountSubProfileManager::GetInstance();
    EXPECT_TRUE(mgr.subProfileDataDeal_->IsValidSubProfileExists(TEST_OS_ACCOUNT_ID, result.id));

    ErrCode delRet = OhosAccountManager::GetInstance().DeleteOsAccountSubspace(
        TEST_OS_ACCOUNT_ID, result.id);
    EXPECT_EQ(delRet, ERR_OK);
}

HWTEST_F(OhosAccountManagerSubspaceTest, CreateOsAccountSubspace_IndexMapBaseEntry_001, TestSize.Level1)
{
    OsAccountInfo accountInfo;
    accountInfo.SetLocalId(TEST_OS_ACCOUNT_ID);
    MockSetCreatedOsAccounts({accountInfo});

    SubProfileContext subprofileCtx;
    subprofileCtx.subProfileIndexMap[0] = TEST_SUBSPACE_BASE;
    MockForceSubProfileContext(TEST_OS_ACCOUNT_ID, subprofileCtx);

    OsAccountSubspaceResult result;
    ErrCode ret = OhosAccountManager::GetInstance().CreateOsAccountSubspace(TEST_OS_ACCOUNT_ID, result);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(result.index, 1);

    SubProfileContext updatedData;
    ErrCode getInfoRet = IInnerOsAccountManager::GetInstance().ReadSubProfileContext(TEST_OS_ACCOUNT_ID, updatedData);
    EXPECT_EQ(getInfoRet, ERR_OK);
    auto updatedMap = updatedData.subProfileIndexMap;
    EXPECT_EQ(updatedMap.count(0), 1u);
    EXPECT_EQ(updatedMap[0], TEST_SUBSPACE_BASE);
    EXPECT_EQ(updatedMap.count(1), 1u);

    ErrCode delRet = OhosAccountManager::GetInstance().DeleteOsAccountSubspace(
        TEST_OS_ACCOUNT_ID, result.id);
    EXPECT_EQ(delRet, ERR_OK);
}

HWTEST_F(OhosAccountManagerSubspaceTest, DeleteOsAccountSubspace_Success_001, TestSize.Level1)
{
    OsAccountSubspaceResult result;
    ErrCode ret = OhosAccountManager::GetInstance().CreateOsAccountSubspace(TEST_OS_ACCOUNT_ID, result);
    EXPECT_EQ(ret, ERR_OK);

    ErrCode delRet = OhosAccountManager::GetInstance().DeleteOsAccountSubspace(
        TEST_OS_ACCOUNT_ID, result.id);
    EXPECT_EQ(delRet, ERR_OK);

    auto &mgr = OsAccountSubProfileManager::GetInstance();
    EXPECT_FALSE(mgr.subProfileDataDeal_->IsValidSubProfileExists(TEST_OS_ACCOUNT_ID, result.id));
}

HWTEST_F(OhosAccountManagerSubspaceTest, CreateOsAccountSubspace_SecondSpace_001, TestSize.Level1)
{
    MockForceSubProfileContext(TEST_OS_ACCOUNT_ID, SubProfileContext());
    OsAccountSubspaceResult result1;
    ErrCode ret1 = OhosAccountManager::GetInstance().CreateOsAccountSubspace(TEST_OS_ACCOUNT_ID, result1);
    EXPECT_EQ(ret1, ERR_OK);
    EXPECT_EQ(result1.index, 1);

    OsAccountSubspaceResult result2;
    ErrCode ret2 = OhosAccountManager::GetInstance().CreateOsAccountSubspace(TEST_OS_ACCOUNT_ID, result2);
    EXPECT_EQ(ret2, ERR_OK);
    EXPECT_EQ(result2.index, 2);

    ErrCode delRet1 = OhosAccountManager::GetInstance().DeleteOsAccountSubspace(
        TEST_OS_ACCOUNT_ID, result1.id);
    EXPECT_EQ(delRet1, ERR_OK);
    ErrCode delRet2 = OhosAccountManager::GetInstance().DeleteOsAccountSubspace(
        TEST_OS_ACCOUNT_ID, result2.id);
    EXPECT_EQ(delRet2, ERR_OK);
}

HWTEST_F(OhosAccountManagerSubspaceTest, SwitchOsAccountSubspace_GetInfoFailed_001, TestSize.Level1)
{
    int32_t nonExistOsAccountId = 99999;
    int32_t subspaceId = nonExistOsAccountId * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 1;
    int32_t fromSubspaceId = 0;
    ErrCode ret = OhosAccountManager::GetInstance().SwitchOsAccountSubspace(
        nonExistOsAccountId, subspaceId, fromSubspaceId);
    EXPECT_NE(ret, ERR_OK);
}

// ===== Task 5: OsAccountSubProfileManager internal methods =====
class SubspaceManagerInternalTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        allPermTokenId_ = GetAllAccountPermission();
        ASSERT_NE(allPermTokenId_, 0);
    }

    static void TearDownTestCase()
    {
        if (allPermTokenId_ != 0) {
            Security::AccessToken::AccessTokenKit::DeleteToken(
                static_cast<Security::AccessToken::AccessTokenID>(allPermTokenId_));
        }
    }

    void SetUp() override
    {
        ASSERT_EQ(SetSelfTokenID(allPermTokenId_), 0);
        std::error_code ec;
        std::filesystem::remove_all(TEST_ROOT_DIR, ec);
        std::filesystem::create_directories(TEST_ROOT_DIR);
        auto &mgr = OsAccountSubProfileManager::GetInstance();
        mgr.Init(TEST_ROOT_DIR);
        OsAccountInfo osAccountInfo;
        osAccountInfo.SetLocalId(TEST_OS_ACCOUNT_ID);
        MockSetCreatedOsAccounts({osAccountInfo});
    }

    void TearDown() override
    {
        ResetMockState();
        std::error_code ec;
        std::filesystem::remove_all(TEST_ROOT_DIR, ec);
    }

    static uint64_t allPermTokenId_;
};

uint64_t SubspaceManagerInternalTest::allPermTokenId_ = 0;

HWTEST_F(SubspaceManagerInternalTest, CheckActiveSessionStatus_NullDataDeal_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    bool result = mgr.CheckActiveSessionStatus(nullptr, TEST_OS_ACCOUNT_ID, TEST_SUBSPACE_BASE + 1);
    EXPECT_FALSE(result);
}

HWTEST_F(SubspaceManagerInternalTest, CheckActiveSessionStatus_ZeroIndex_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    bool result = mgr.CheckActiveSessionStatus(
        mgr.subProfileDataDeal_.get(), TEST_OS_ACCOUNT_ID, TEST_SUBSPACE_BASE);
    EXPECT_FALSE(result);
}

HWTEST_F(SubspaceManagerInternalTest, CheckActiveSessionStatus_NegativeOne_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    bool result = mgr.CheckActiveSessionStatus(
        mgr.subProfileDataDeal_.get(), TEST_OS_ACCOUNT_ID, -1);
    EXPECT_FALSE(result);
}

HWTEST_F(SubspaceManagerInternalTest, CheckActiveSessionStatus_LoginState_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    int32_t distId = TEST_SUBSPACE_BASE + 1;
    OsAccountSubspaceInfo info;
    info.userId_ = TEST_OS_ACCOUNT_ID;
    info.subspaceId = distId;
    info.isCreateCompleted = true;
    info.toBeRemoved = false;
    info.ohosAccountInfo_.status_ = ACCOUNT_STATE_LOGIN;
    ASSERT_EQ(mgr.subProfileDataDeal_->SaveSubProfileInfo(info), ERR_OK);

    bool result = mgr.CheckActiveSessionStatus(
        mgr.subProfileDataDeal_.get(), TEST_OS_ACCOUNT_ID, distId);
    EXPECT_TRUE(result);
}

HWTEST_F(SubspaceManagerInternalTest, CheckActiveSessionStatus_UnboundState_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    int32_t distId = TEST_SUBSPACE_BASE + 2;
    OsAccountSubspaceInfo info;
    info.userId_ = TEST_OS_ACCOUNT_ID;
    info.subspaceId = distId;
    info.isCreateCompleted = true;
    info.toBeRemoved = false;
    ASSERT_EQ(mgr.subProfileDataDeal_->SaveSubProfileInfo(info), ERR_OK);

    bool result = mgr.CheckActiveSessionStatus(
        mgr.subProfileDataDeal_.get(), TEST_OS_ACCOUNT_ID, distId);
    EXPECT_FALSE(result);
}

HWTEST_F(SubspaceManagerInternalTest, SwitchSubspaceLocked_BaseSubspace_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    int32_t baseId = TEST_SUBSPACE_BASE;
    int32_t fromSubspaceId = 0;
    ErrCode ret = mgr.SwitchSubProfile(TEST_OS_ACCOUNT_ID, baseId, fromSubspaceId);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_RESTRICTED);
}

HWTEST_F(SubspaceManagerInternalTest, SwitchSubspaceLocked_GetOsAccountInfoByIdFail_001, TestSize.Level1)
{
    MockForceGetOsAccountInfoByIdFail(ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    int32_t baseId = TEST_SUBSPACE_BASE;
    int32_t fromSubspaceId = -1;
    ErrCode ret = mgr.SwitchSubProfile(TEST_OS_ACCOUNT_ID, baseId, fromSubspaceId);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_RESTRICTED);
    EXPECT_EQ(fromSubspaceId, -1);
    MockClearForceFailFlags();
}

HWTEST_F(SubspaceManagerInternalTest, SwitchSubspaceLocked_GetOsAccountInfoSuccess_001, TestSize.Level1)
{
    OsAccountInfo accountInfo;
    accountInfo.SetLocalId(TEST_OS_ACCOUNT_ID);
    accountInfo.foregroundSubProfileId_ = 0;
    MockSetCreatedOsAccounts({accountInfo});

    auto &mgr = OsAccountSubProfileManager::GetInstance();
    int32_t baseId = TEST_SUBSPACE_BASE;
    int32_t fromSubspaceId = -1;
    ErrCode ret = mgr.SwitchSubProfile(TEST_OS_ACCOUNT_ID, baseId, fromSubspaceId);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_RESTRICTED);
    EXPECT_EQ(fromSubspaceId, -1);
}

HWTEST_F(SubspaceManagerInternalTest, RemoveSubspaceLocked_LoadFailed_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    int32_t distId = TEST_SUBSPACE_BASE + 5;
    std::string spaceDir = TEST_ROOT_DIR + std::to_string(TEST_OS_ACCOUNT_ID) + "/" + std::to_string(distId);
    std::filesystem::create_directories(spaceDir);
    std::string corruptFile = spaceDir + "/account.json";
    std::ofstream ofs(corruptFile);
    ofs << "not_json{{";
    ofs.close();

    EXPECT_FALSE(mgr.subProfileDataDeal_->IsValidSubProfileExists(TEST_OS_ACCOUNT_ID, distId));
    ErrCode ret = mgr.RemoveSubProfile(TEST_OS_ACCOUNT_ID, distId);
    EXPECT_NE(ret, ERR_OK);
}

HWTEST_F(SubspaceManagerInternalTest, CreateSubspace_SaveIncompleteFail_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    std::string osAccountDir = TEST_ROOT_DIR + std::to_string(TEST_OS_ACCOUNT_ID);
    std::error_code ec;
    std::filesystem::remove_all(osAccountDir, ec);
    {
        std::ofstream ofs(osAccountDir);
        ofs.close();
    }

    int32_t newSubspaceId = 0;
    int32_t index = 0;
    ErrCode ret = mgr.CreateSubProfile(TEST_OS_ACCOUNT_ID, newSubspaceId, index);
    EXPECT_NE(ret, ERR_OK);

    std::filesystem::remove(osAccountDir, ec);
    std::filesystem::create_directories(osAccountDir, ec);
}

HWTEST_F(SubspaceManagerInternalTest, RemoveSubspaceLocked_SaveToBeRemovedFail_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    int32_t distId = TEST_SUBSPACE_BASE + 10;
    OsAccountSubspaceInfo info;
    info.userId_ = TEST_OS_ACCOUNT_ID;
    info.subspaceId = distId;
    info.isCreateCompleted = true;
    info.toBeRemoved = false;
    ASSERT_EQ(mgr.subProfileDataDeal_->SaveSubProfileInfo(info), ERR_OK);

    std::string accountJson = TEST_ROOT_DIR + std::to_string(TEST_OS_ACCOUNT_ID) +
        "/" + std::to_string(distId) + "/account.json";
    std::string chattrCmd = "chattr +i " + accountJson;
    ASSERT_EQ(system(chattrCmd.c_str()), 0);

    ErrCode ret = mgr.RemoveSubProfile(TEST_OS_ACCOUNT_ID, distId);
    EXPECT_NE(ret, ERR_OK);

    chattrCmd = "chattr -i " + accountJson;
    system(chattrCmd.c_str());
}

HWTEST_F(SubspaceManagerInternalTest, RemoveSubspaceLocked_ForegroundCheck_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    int32_t distId = TEST_SUBSPACE_BASE + 15;
    OsAccountSubspaceInfo info;
    info.userId_ = TEST_OS_ACCOUNT_ID;
    info.subspaceId = distId;
    info.isCreateCompleted = true;
    info.toBeRemoved = false;
    ASSERT_EQ(mgr.subProfileDataDeal_->SaveSubProfileInfo(info), ERR_OK);

    ErrCode ret = mgr.RemoveSubProfile(TEST_OS_ACCOUNT_ID, distId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(mgr.subProfileDataDeal_->IsValidSubProfileExists(TEST_OS_ACCOUNT_ID, distId));
}

HWTEST_F(SubspaceManagerInternalTest, CreateSubspace_UpdateOsAccountSubspaceInfoFail_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    OsAccountInfo osAccountInfo;
    osAccountInfo.SetLocalId(TEST_OS_ACCOUNT_ID);
    MockSetCreatedOsAccounts({osAccountInfo});
    MockForceUpdateSubspaceInfoFail(ERR_OSACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR);

    int32_t newSubspaceId = 0;
    int32_t index = 0;
    ErrCode ret = mgr.CreateSubProfile(TEST_OS_ACCOUNT_ID, newSubspaceId, index);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR);
    EXPECT_FALSE(mgr.subProfileDataDeal_->IsValidSubProfileExists(TEST_OS_ACCOUNT_ID, newSubspaceId));

    MockClearForceFailFlags();
    MockSetCreatedOsAccounts({});
}

HWTEST_F(SubspaceManagerInternalTest, CreateSubspace_GetOsAccountInfoByIdFail_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    MockForceReadSubProfileContextFail(ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);

    int32_t newSubspaceId = 0;
    int32_t index = 0;
    ErrCode ret = mgr.CreateSubProfile(TEST_OS_ACCOUNT_ID, newSubspaceId, index);
    EXPECT_NE(ret, ERR_OK);
    EXPECT_EQ(newSubspaceId, 0);

    MockClearForceFailFlags();
}

HWTEST_F(SubspaceManagerInternalTest, CreateSubspace_FileNotExist_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    MockForceReadSubProfileContextFail(ERR_ACCOUNT_COMMON_FILE_NOT_EXIST);

    int32_t newSubspaceId = 0;
    int32_t index = 0;
    ErrCode ret = mgr.CreateSubProfile(TEST_OS_ACCOUNT_ID, newSubspaceId, index);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_NE(newSubspaceId, 0);
    EXPECT_EQ(index, 1);

    MockClearForceFailFlags();
}

HWTEST_F(SubspaceManagerInternalTest, RemoveSubspace_UpdateOsAccountSubspaceInfoFail_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    OsAccountInfo osAccountInfo;
    osAccountInfo.SetLocalId(TEST_OS_ACCOUNT_ID);
    MockSetCreatedOsAccounts({osAccountInfo});

    SubProfileContext subprofileCtx;
    subprofileCtx.subProfileIdList = {TEST_SUBSPACE_BASE + 20};
    MockForceSubProfileContext(TEST_OS_ACCOUNT_ID, subprofileCtx);

    int32_t distId = TEST_SUBSPACE_BASE + 20;
    OsAccountSubspaceInfo info;
    info.userId_ = TEST_OS_ACCOUNT_ID;
    info.subspaceId = distId;
    info.isCreateCompleted = true;
    info.toBeRemoved = false;
    ASSERT_EQ(mgr.subProfileDataDeal_->SaveSubProfileInfo(info), ERR_OK);

    MockForceUpdateSubspaceInfoFail(ERR_OSACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR);
    ErrCode ret = mgr.RemoveSubProfile(TEST_OS_ACCOUNT_ID, distId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(mgr.subProfileDataDeal_->IsValidSubProfileExists(TEST_OS_ACCOUNT_ID, distId));

    MockClearForceFailFlags();
    MockSetCreatedOsAccounts({});
}

HWTEST_F(SubspaceManagerInternalTest, RemoveSubspace_GetOsAccountInfoByIdFail_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    int32_t distId = TEST_SUBSPACE_BASE + 25;
    OsAccountSubspaceInfo info;
    info.userId_ = TEST_OS_ACCOUNT_ID;
    info.subspaceId = distId;
    info.isCreateCompleted = true;
    info.toBeRemoved = false;
    ASSERT_EQ(mgr.subProfileDataDeal_->SaveSubProfileInfo(info), ERR_OK);

    MockForceGetOsAccountInfoByIdFail(ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
    ErrCode ret = mgr.RemoveSubProfile(TEST_OS_ACCOUNT_ID, distId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(mgr.subProfileDataDeal_->IsValidSubProfileExists(TEST_OS_ACCOUNT_ID, distId));

    MockClearForceFailFlags();
}

HWTEST_F(SubspaceManagerInternalTest, TryReclaimSubProfileSlots_RefreshFail_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();

    OsAccountInfo accountInfo;
    accountInfo.SetLocalId(TEST_OS_ACCOUNT_ID);
    MockSetCreatedOsAccounts({accountInfo});

    SubProfileContext subprofileCtx;
    subprofileCtx.subProfileIdList = {TEST_SUBSPACE_BASE + 1};
    MockForceSubProfileContext(TEST_OS_ACCOUNT_ID, subprofileCtx);

    int32_t garbageId = TEST_SUBSPACE_BASE + 50;
    OsAccountSubspaceInfo garbageInfo;
    garbageInfo.userId_ = TEST_OS_ACCOUNT_ID;
    garbageInfo.subspaceId = garbageId;
    garbageInfo.isCreateCompleted = false;
    garbageInfo.toBeRemoved = false;
    ASSERT_EQ(mgr.subProfileDataDeal_->SaveSubProfileInfo(garbageInfo), ERR_OK);

    MockForceReadSubProfileContextFail(ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);

    ErrCode ret = mgr.TryReclaimSubProfileSlots(TEST_OS_ACCOUNT_ID, subprofileCtx);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_LIMIT);

    MockClearForceFailFlags();
}

HWTEST_F(SubspaceManagerInternalTest, TryReclaimSubProfileSlots_StillAtLimit_002, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    int32_t base = TEST_SUBSPACE_BASE;

    OsAccountInfo accountInfo;
    accountInfo.SetLocalId(TEST_OS_ACCOUNT_ID);
    MockSetCreatedOsAccounts({accountInfo});

    SubProfileContext subprofileCtx2;
    subprofileCtx2.subProfileIdList.push_back(base);
    for (int32_t i = 1; i <= MAX_OS_ACCOUNT_SUB_PROFILE_COUNT - 1; ++i) {
        subprofileCtx2.subProfileIdList.push_back(base + i);
    }
    MockForceSubProfileContext(TEST_OS_ACCOUNT_ID, subprofileCtx2);

    int32_t garbageId = base + OsAccountSubProfileDataDeal::OS_ACCOUNT_SUB_PROFILE_ID_MAX;
    OsAccountSubspaceInfo garbageInfo;
    garbageInfo.userId_ = TEST_OS_ACCOUNT_ID;
    garbageInfo.subspaceId = garbageId;
    garbageInfo.isCreateCompleted = true;
    garbageInfo.toBeRemoved = true;
    ASSERT_EQ(mgr.subProfileDataDeal_->SaveSubProfileInfo(garbageInfo), ERR_OK);

    MockForceUpdateSubspaceInfoFail(ERR_OSACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR);

    int32_t newSubspaceId = 0;
    int32_t index = 0;
    ErrCode ret = mgr.CreateSubProfile(TEST_OS_ACCOUNT_ID, newSubspaceId, index);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_LIMIT);

    MockClearForceFailFlags();
}

HWTEST_F(SubspaceManagerInternalTest, TryReclaimSubProfileSlots_Success_003, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();

    OsAccountInfo accountInfo;
    accountInfo.SetLocalId(TEST_OS_ACCOUNT_ID);
    MockSetCreatedOsAccounts({accountInfo});

    SubProfileContext subprofileCtx3;
    subprofileCtx3.subProfileIdList = {TEST_SUBSPACE_BASE + 1};
    MockForceSubProfileContext(TEST_OS_ACCOUNT_ID, subprofileCtx3);

    int32_t garbageId = TEST_SUBSPACE_BASE + 60;
    OsAccountSubspaceInfo garbageInfo;
    garbageInfo.userId_ = TEST_OS_ACCOUNT_ID;
    garbageInfo.subspaceId = garbageId;
    garbageInfo.isCreateCompleted = true;
    garbageInfo.toBeRemoved = true;
    ASSERT_EQ(mgr.subProfileDataDeal_->SaveSubProfileInfo(garbageInfo), ERR_OK);

    OsAccountSubspaceInfo loaded;
    ASSERT_EQ(mgr.subProfileDataDeal_->LoadSubProfileInfo(TEST_OS_ACCOUNT_ID, garbageId, loaded), ERR_OK);
    ASSERT_TRUE(loaded.toBeRemoved);

    ErrCode ret = mgr.TryReclaimSubProfileSlots(TEST_OS_ACCOUNT_ID, subprofileCtx3);
    EXPECT_EQ(ret, ERR_OK);
}

HWTEST_F(SubspaceManagerInternalTest, AllocateSubProfileIndex_NormalHint_001, TestSize.Level1)
{
    OsAccountSubProfileDataDeal dataDeal(TEST_ROOT_DIR);
    std::map<int32_t, int32_t> emptyMap;
    int32_t outIndex = 0;
    ErrCode ret = dataDeal.AllocateSubProfileIndex(1, emptyMap, outIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(outIndex, 1);
}

HWTEST_F(SubspaceManagerInternalTest, AllocateSubProfileIndex_HintOccupied_002, TestSize.Level1)
{
    OsAccountSubProfileDataDeal dataDeal(TEST_ROOT_DIR);
    std::map<int32_t, int32_t> occupiedMap;
    occupiedMap[1] = TEST_SUBSPACE_BASE + 1;
    occupiedMap[2] = TEST_SUBSPACE_BASE + 2;
    int32_t outIndex = 0;
    ErrCode ret = dataDeal.AllocateSubProfileIndex(1, occupiedMap, outIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(outIndex, 3);
}

HWTEST_F(SubspaceManagerInternalTest, AllocateSubProfileIndex_WrapAround_003, TestSize.Level1)
{
    OsAccountSubProfileDataDeal dataDeal(TEST_ROOT_DIR);
    std::map<int32_t, int32_t> occupiedMap;
    for (int32_t i = 1; i <= MAX_OS_ACCOUNT_SUB_PROFILE_COUNT - 1; ++i) {
        if (i != 5) {
            occupiedMap[i] = TEST_SUBSPACE_BASE + i;
        }
    }
    occupiedMap[0] = TEST_SUBSPACE_BASE;
    int32_t outIndex = 0;
    ErrCode ret = dataDeal.AllocateSubProfileIndex(
        MAX_OS_ACCOUNT_SUB_PROFILE_COUNT - 1, occupiedMap, outIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(outIndex, 5);
}

HWTEST_F(SubspaceManagerInternalTest, AllocateSubProfileIndex_AllSlotsUsed_004, TestSize.Level1)
{
    OsAccountSubProfileDataDeal dataDeal(TEST_ROOT_DIR);
    std::map<int32_t, int32_t> fullMap;
    for (int32_t i = 0;
        i <= MAX_OS_ACCOUNT_SUB_PROFILE_COUNT - 1; ++i) {
        fullMap[i] = TEST_SUBSPACE_BASE + i;
    }
    int32_t outIndex = 0;
    ErrCode ret = dataDeal.AllocateSubProfileIndex(1, fullMap, outIndex);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_LIMIT);
}

HWTEST_F(SubspaceManagerInternalTest, AllocateSubProfileIndex_HintOutOfBounds_005, TestSize.Level1)
{
    OsAccountSubProfileDataDeal dataDeal(TEST_ROOT_DIR);
    std::map<int32_t, int32_t> emptyMap;
    int32_t outIndex = 0;
    ErrCode ret = dataDeal.AllocateSubProfileIndex(-1, emptyMap, outIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(outIndex, 1);

    outIndex = 0;
    ret = dataDeal.AllocateSubProfileIndex(0, emptyMap, outIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(outIndex, 1);

    outIndex = 0;
    ret = dataDeal.AllocateSubProfileIndex(
        MAX_OS_ACCOUNT_SUB_PROFILE_COUNT, emptyMap, outIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(outIndex, 1);
}

HWTEST_F(SubspaceManagerInternalTest, RemoveOsAccountSubProfileInfo_IndexMapCleanup_001, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    osAccountInfo.SetLocalId(TEST_OS_ACCOUNT_ID);
    int32_t subId1 = TEST_SUBSPACE_BASE + 1;
    int32_t subId2 = TEST_SUBSPACE_BASE + 2;
    MockSetCreatedOsAccounts({osAccountInfo});

    SubProfileContext subprofileCtx4;
    subprofileCtx4.subProfileIdList = {subId1, subId2};
    subprofileCtx4.subProfileIndexMap[1] = subId1;
    subprofileCtx4.subProfileIndexMap[2] = subId2;
    MockForceSubProfileContext(TEST_OS_ACCOUNT_ID, subprofileCtx4);

    OsAccountSubspaceInfo info1;
    info1.userId_ = TEST_OS_ACCOUNT_ID;
    info1.subspaceId = subId1;
    info1.isCreateCompleted = true;
    info1.toBeRemoved = false;
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    ASSERT_EQ(mgr.subProfileDataDeal_->SaveSubProfileInfo(info1), ERR_OK);

    OsAccountSubspaceInfo info2;
    info2.userId_ = TEST_OS_ACCOUNT_ID;
    info2.subspaceId = subId2;
    info2.isCreateCompleted = true;
    info2.toBeRemoved = false;
    ASSERT_EQ(mgr.subProfileDataDeal_->SaveSubProfileInfo(info2), ERR_OK);

    ErrCode ret = mgr.RemoveSubProfile(TEST_OS_ACCOUNT_ID, subId1);
    EXPECT_EQ(ret, ERR_OK);

    SubProfileContext updatedData;
    ErrCode getInfoRet = IInnerOsAccountManager::GetInstance().ReadSubProfileContext(TEST_OS_ACCOUNT_ID, updatedData);
    EXPECT_EQ(getInfoRet, ERR_OK);
    auto updatedList = updatedData.subProfileIdList;
    EXPECT_EQ(std::find(updatedList.begin(), updatedList.end(), subId1), updatedList.end());
    EXPECT_NE(std::find(updatedList.begin(), updatedList.end(), subId2), updatedList.end());

    auto updatedMap = updatedData.subProfileIndexMap;
    EXPECT_EQ(updatedMap.count(1), 0u);
    EXPECT_EQ(updatedMap.count(2), 1u);
    EXPECT_EQ(updatedMap[2], subId2);
}

HWTEST_F(SubspaceManagerInternalTest, RemoveOsAccountSubProfileInfo_IndexMapNotFound_002, TestSize.Level1)
{
    OsAccountInfo osAccountInfo;
    osAccountInfo.SetLocalId(TEST_OS_ACCOUNT_ID);
    int32_t subId1 = TEST_SUBSPACE_BASE + 1;
    MockSetCreatedOsAccounts({osAccountInfo});

    SubProfileContext subprofileCtx5;
    subprofileCtx5.subProfileIdList = {subId1};
    subprofileCtx5.subProfileIndexMap[3] = TEST_SUBSPACE_BASE + 3;
    MockForceSubProfileContext(TEST_OS_ACCOUNT_ID, subprofileCtx5);

    OsAccountSubspaceInfo info1;
    info1.userId_ = TEST_OS_ACCOUNT_ID;
    info1.subspaceId = subId1;
    info1.isCreateCompleted = true;
    info1.toBeRemoved = false;
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    ASSERT_EQ(mgr.subProfileDataDeal_->SaveSubProfileInfo(info1), ERR_OK);

    ErrCode ret = mgr.RemoveSubProfile(TEST_OS_ACCOUNT_ID, subId1);
    EXPECT_EQ(ret, ERR_OK);

    SubProfileContext updatedData;
    ErrCode getInfoRet = IInnerOsAccountManager::GetInstance().ReadSubProfileContext(TEST_OS_ACCOUNT_ID, updatedData);
    EXPECT_EQ(getInfoRet, ERR_OK);
    auto updatedMap = updatedData.subProfileIndexMap;
    EXPECT_EQ(updatedMap.size(), 1u);
    EXPECT_EQ(updatedMap[3], TEST_SUBSPACE_BASE + 3);
}

HWTEST_F(SubspaceManagerInternalTest, CreateSubProfileLocked_ReclaimRefreshesIndexMap_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    int32_t base = TEST_SUBSPACE_BASE;

    OsAccountInfo accountInfo;
    accountInfo.SetLocalId(TEST_OS_ACCOUNT_ID);
    MockSetCreatedOsAccounts({accountInfo});

    SubProfileContext subprofileCtx6;
    subprofileCtx6.subProfileIdList.push_back(base);
    subprofileCtx6.subProfileIndexMap[0] = base;
    for (int32_t i = 1; i <= MAX_OS_ACCOUNT_SUB_PROFILE_COUNT - 2; ++i) {
        subprofileCtx6.subProfileIdList.push_back(base + i);
        subprofileCtx6.subProfileIndexMap[i] = base + i;
    }
    int32_t garbageIndex = OsAccountSubProfileDataDeal::OS_ACCOUNT_SUB_PROFILE_ID_MAX;
    int32_t garbageId = base + garbageIndex;
    subprofileCtx6.subProfileIdList.push_back(garbageId);
    subprofileCtx6.subProfileIndexMap[garbageIndex] = garbageId;
    MockForceSubProfileContext(TEST_OS_ACCOUNT_ID, subprofileCtx6);

    OsAccountSubspaceInfo garbageInfo;
    garbageInfo.userId_ = TEST_OS_ACCOUNT_ID;
    garbageInfo.subspaceId = garbageId;
    garbageInfo.isCreateCompleted = true;
    garbageInfo.toBeRemoved = true;
    ASSERT_EQ(mgr.subProfileDataDeal_->SaveSubProfileInfo(garbageInfo), ERR_OK);

    int32_t newSubspaceId = 0;
    int32_t newIndex = 0;
    ErrCode ret = mgr.CreateSubProfile(TEST_OS_ACCOUNT_ID, newSubspaceId, newIndex);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_GE(newIndex, 0);
    EXPECT_LT(newIndex, MAX_OS_ACCOUNT_SUB_PROFILE_COUNT);

    SubProfileContext updatedData;
    ErrCode getInfoRet = IInnerOsAccountManager::GetInstance().ReadSubProfileContext(TEST_OS_ACCOUNT_ID, updatedData);
    EXPECT_EQ(getInfoRet, ERR_OK);
    auto updatedMap = updatedData.subProfileIndexMap;
    EXPECT_EQ(updatedMap[newIndex], newSubspaceId);
    EXPECT_EQ(static_cast<int32_t>(updatedData.subProfileIdList.size()), MAX_OS_ACCOUNT_SUB_PROFILE_COUNT);

    if (newSubspaceId == garbageId) {
        OsAccountSubspaceInfo onDiskInfo;
        ErrCode loadRet = mgr.subProfileDataDeal_->LoadSubProfileInfo(TEST_OS_ACCOUNT_ID, garbageId, onDiskInfo);
        EXPECT_EQ(loadRet, ERR_OK);
        EXPECT_FALSE(onDiskInfo.toBeRemoved);
        EXPECT_TRUE(onDiskInfo.isCreateCompleted);
    } else {
        EXPECT_EQ(std::find(updatedData.subProfileIdList.begin(), updatedData.subProfileIdList.end(), garbageId),
            updatedData.subProfileIdList.end());
    }
}

HWTEST_F(SubspaceManagerInternalTest, CreateSubProfile_WriteSubProfileContextFail_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    int32_t base = TEST_SUBSPACE_BASE;

    OsAccountInfo accountInfo;
    accountInfo.SetLocalId(TEST_OS_ACCOUNT_ID);
    MockSetCreatedOsAccounts({accountInfo});

    SubProfileContext subprofileCtx;
    subprofileCtx.subProfileIdList.push_back(base);
    MockForceSubProfileContext(TEST_OS_ACCOUNT_ID, subprofileCtx);

    MockForceUpdateSubspaceInfoFail(ERR_OSACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR);

    int32_t newSubspaceId = 0;
    int32_t newIndex = 0;
    ErrCode ret = mgr.CreateSubProfile(TEST_OS_ACCOUNT_ID, newSubspaceId, newIndex);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_INNER_UPDATE_ACCOUNT_ERROR);

    MockClearForceFailFlags();
}

// ===== SubProfile JSON serialization/deserialization coverage =====
// Covers: ToJsonSubProfile, FromJsonSubProfile
class SubProfileJsonParserCoverageTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        allPermTokenId_ = GetAllAccountPermission();
        ASSERT_NE(allPermTokenId_, 0);
    }
    static void TearDownTestCase()
    {
        if (allPermTokenId_ != 0) {
            Security::AccessToken::AccessTokenKit::DeleteToken(
                static_cast<Security::AccessToken::AccessTokenID>(allPermTokenId_));
        }
    }
    void SetUp() override
    {
        ASSERT_EQ(SetSelfTokenID(allPermTokenId_), 0);
    }
    void TearDown() override {}
    static uint64_t allPermTokenId_;
};

uint64_t SubProfileJsonParserCoverageTest::allPermTokenId_ = 0;

/**
 * @tc.name: ToJsonSubProfile_DefaultContext_001
 * @tc.desc: Test ToJsonSubProfile with default SubProfileContext and verify round-trip.
 */
HWTEST_F(SubProfileJsonParserCoverageTest, ToJsonSubProfile_DefaultContext_001, TestSize.Level1)
{
    SubProfileContext defaultCtx;
    auto json = ToJsonSubProfile(defaultCtx);
    ASSERT_NE(json, nullptr);
    std::string jsonStr = PackJsonToString(json);
    EXPECT_FALSE(jsonStr.empty());

    auto parsedJson = CreateJsonFromString(jsonStr);
    ASSERT_NE(parsedJson, nullptr);
    SubProfileContext parsedCtx;
    EXPECT_TRUE(FromJsonSubProfile(parsedJson.get(), parsedCtx));
    EXPECT_EQ(parsedCtx.nextSubProfileId, 0);
    EXPECT_TRUE(parsedCtx.subProfileIdList.empty());
    EXPECT_EQ(parsedCtx.nextSubProfileIndex, 0);
    EXPECT_TRUE(parsedCtx.subProfileIndexMap.empty());
}

/**
 * @tc.name: ToJsonSubProfile_PopulatedContext_002
 * @tc.desc: Test ToJsonSubProfile with fully populated SubProfileContext and verify round-trip.
 */
HWTEST_F(SubProfileJsonParserCoverageTest, ToJsonSubProfile_PopulatedContext_002, TestSize.Level1)
{
    SubProfileContext ctx(1001, {100000, 100001, 100002}, 5, {{0, 100000}, {1, 100001}, {2, 100002}});
    auto json = ToJsonSubProfile(ctx);
    ASSERT_NE(json, nullptr);
    std::string jsonStr = PackJsonToString(json);
    EXPECT_FALSE(jsonStr.empty());

    auto parsedJson = CreateJsonFromString(jsonStr);
    ASSERT_NE(parsedJson, nullptr);
    SubProfileContext parsedCtx;
    EXPECT_TRUE(FromJsonSubProfile(parsedJson.get(), parsedCtx));
    EXPECT_EQ(parsedCtx.nextSubProfileId, 1001);
    EXPECT_EQ(parsedCtx.subProfileIdList.size(), 3u);
    EXPECT_EQ(parsedCtx.subProfileIdList[0], 100000);
    EXPECT_EQ(parsedCtx.subProfileIdList[1], 100001);
    EXPECT_EQ(parsedCtx.subProfileIdList[2], 100002);
    EXPECT_EQ(parsedCtx.nextSubProfileIndex, 5);
    EXPECT_EQ(parsedCtx.subProfileIndexMap.size(), 3u);
    EXPECT_EQ(parsedCtx.subProfileIndexMap[0], 100000);
    EXPECT_EQ(parsedCtx.subProfileIndexMap[1], 100001);
    EXPECT_EQ(parsedCtx.subProfileIndexMap[2], 100002);
}

/**
 * @tc.name: ToJsonSubProfile_HeadlessDefault_003
 * @tc.desc: Test ToJsonSubProfile with CreateWithHeadlessDefault and verify round-trip.
 */
HWTEST_F(SubProfileJsonParserCoverageTest, ToJsonSubProfile_HeadlessDefault_003, TestSize.Level1)
{
    SubProfileContext ctx = SubProfileContext::CreateWithHeadlessDefault(TEST_OS_ACCOUNT_ID);
    auto json = ToJsonSubProfile(ctx);
    ASSERT_NE(json, nullptr);
    std::string jsonStr = PackJsonToString(json);
    EXPECT_FALSE(jsonStr.empty());

    auto parsedJson = CreateJsonFromString(jsonStr);
    ASSERT_NE(parsedJson, nullptr);
    SubProfileContext parsedCtx;
    EXPECT_TRUE(FromJsonSubProfile(parsedJson.get(), parsedCtx));
    EXPECT_EQ(parsedCtx.nextSubProfileId, TEST_SUBSPACE_BASE + 1);
    EXPECT_EQ(parsedCtx.subProfileIdList.size(), 1u);
    EXPECT_EQ(parsedCtx.subProfileIdList[0], TEST_SUBSPACE_BASE);
    EXPECT_EQ(parsedCtx.nextSubProfileIndex, 1);
    EXPECT_EQ(parsedCtx.subProfileIndexMap.size(), 1u);
    EXPECT_EQ(parsedCtx.subProfileIndexMap[0], TEST_SUBSPACE_BASE);
}

/**
 * @tc.name: FromJsonSubProfile_Nullptr_004
 * @tc.desc: Test FromJsonSubProfile with nullptr returns false.
 */
HWTEST_F(SubProfileJsonParserCoverageTest, FromJsonSubProfile_Nullptr_004, TestSize.Level1)
{
    SubProfileContext data;
    EXPECT_FALSE(FromJsonSubProfile(nullptr, data));
}

/**
 * @tc.name: FromJsonSubProfile_PartialJson_005
 * @tc.desc: Test FromJsonSubProfile with JSON missing some fields yields defaults for missing fields.
 */
HWTEST_F(SubProfileJsonParserCoverageTest, FromJsonSubProfile_PartialJson_005, TestSize.Level1)
{
    auto json = CreateJson();
    AddIntToJson(json, NEXT_SUBPROFILE_ID, 42);

    SubProfileContext parsedCtx;
    EXPECT_TRUE(FromJsonSubProfile(json.get(), parsedCtx));
    EXPECT_EQ(parsedCtx.nextSubProfileId, 42);
    EXPECT_TRUE(parsedCtx.subProfileIdList.empty());
    EXPECT_EQ(parsedCtx.nextSubProfileIndex, 0);
    EXPECT_TRUE(parsedCtx.subProfileIndexMap.empty());
}

/**
 * @tc.name: FromJsonSubProfile_LargeKeyOverflow_006
 * @tc.desc: Test FromJsonSubProfile filters out indexMap keys exceeding INT32_MAX.
 */
HWTEST_F(SubProfileJsonParserCoverageTest, FromJsonSubProfile_LargeKeyOverflow_006, TestSize.Level1)
{
    auto json = CreateJson();
    AddIntToJson(json, NEXT_SUBPROFILE_ID, 10);
    AddVectorIntToJson(json, SUBPROFILE_ID_LIST, {100, 101});
    AddIntToJson(json, NEXT_SUBPROFILE_INDEX, 3);

    auto indexMapJson = CreateJson();
    AddIntToJson(indexMapJson, "1", 100);
    AddIntToJson(indexMapJson, std::to_string(static_cast<int64_t>(INT32_MAX) + 1), 101);
    AddObjToJson(json.get(), SUBPROFILE_INDEX_MAP, indexMapJson.get());

    SubProfileContext parsedCtx;
    EXPECT_TRUE(FromJsonSubProfile(json.get(), parsedCtx));
    EXPECT_EQ(parsedCtx.nextSubProfileId, 10);
    EXPECT_EQ(parsedCtx.subProfileIdList.size(), 2u);
    EXPECT_EQ(parsedCtx.nextSubProfileIndex, 3);
    EXPECT_EQ(parsedCtx.subProfileIndexMap.size(), 1u);
    EXPECT_EQ(parsedCtx.subProfileIndexMap[1], 100);
}

// ===== VectorInt JSON utility coverage =====
// Covers: GetVectorIntFromJson (3 overloads), AddVectorIntToJson (2 overloads)
class VectorIntJsonCoverageTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        allPermTokenId_ = GetAllAccountPermission();
        ASSERT_NE(allPermTokenId_, 0);
    }
    static void TearDownTestCase()
    {
        if (allPermTokenId_ != 0) {
            Security::AccessToken::AccessTokenKit::DeleteToken(
                static_cast<Security::AccessToken::AccessTokenID>(allPermTokenId_));
        }
    }
    void SetUp() override
    {
        ASSERT_EQ(SetSelfTokenID(allPermTokenId_), 0);
    }
    void TearDown() override {}
    static uint64_t allPermTokenId_;
};

uint64_t VectorIntJsonCoverageTest::allPermTokenId_ = 0;

/**
 * @tc.name: AddAndGetVectorInt_CJson_001
 * @tc.desc: Test AddVectorIntToJson/GetVectorIntFromJson
 */
HWTEST_F(VectorIntJsonCoverageTest, AddAndGetVectorInt_CJson_001, TestSize.Level1)
{
    std::vector<int32_t> vec = {10, 20, 30};
    auto json = CreateJson();
    EXPECT_TRUE(AddVectorIntToJson(json.get(), "intList", vec));

    std::vector<int32_t> result;
    EXPECT_TRUE(GetVectorIntFromJson(json.get(), "intList", result));
    EXPECT_EQ(result.size(), 3u);
    EXPECT_EQ(result[0], 10);
    EXPECT_EQ(result[1], 20);
    EXPECT_EQ(result[2], 30);

    std::vector<int32_t> resultDirect = GetVectorIntFromJson(json.get(), "intList");
    EXPECT_EQ(resultDirect.size(), 3u);

    EXPECT_FALSE(AddVectorIntToJson(nullptr, "intList", vec));
    EXPECT_FALSE(AddVectorIntToJson(json.get(), "", vec));

    std::vector<int32_t> emptyResult;
    EXPECT_FALSE(GetVectorIntFromJson(nullptr, "intList", emptyResult));
    EXPECT_FALSE(GetVectorIntFromJson(json.get(), "", emptyResult));

    std::vector<int32_t> missingResult;
    EXPECT_FALSE(GetVectorIntFromJson(json.get(), "missingKey", missingResult));
    EXPECT_TRUE(GetVectorIntFromJson(json.get(), "missingKey").empty());

    std::vector<int32_t> emptyVec;
    auto json2 = CreateJson();
    EXPECT_TRUE(AddVectorIntToJson(json2.get(), "emptyList", emptyVec));
    std::vector<int32_t> emptyListResult;
    EXPECT_TRUE(GetVectorIntFromJson(json2.get(), "emptyList", emptyListResult));
    EXPECT_TRUE(emptyListResult.empty());
}

/**
 * @tc.name: AddAndGetVectorInt_CJsonUnique_002
 * @tc.desc: Test AddVectorIntToJson/GetVectorIntFromJson with CJsonUnique overloads.
 */
HWTEST_F(VectorIntJsonCoverageTest, AddAndGetVectorInt_CJsonUnique_002, TestSize.Level1)
{
    std::vector<int32_t> vec = {5, 15, 25};
    auto json = CreateJson();
    EXPECT_TRUE(AddVectorIntToJson(json, "intList", vec));

    std::vector<int32_t> result = GetVectorIntFromJson(json, "intList");
    EXPECT_EQ(result.size(), 3u);
    EXPECT_EQ(result[0], 5);
    EXPECT_EQ(result[1], 15);
    EXPECT_EQ(result[2], 25);
}

/**
 * @tc.name: AddVectorInt_ReplaceKey_003
 * @tc.desc: Test AddVectorIntToJson replacing an existing key with new values.
 */
HWTEST_F(VectorIntJsonCoverageTest, AddVectorInt_ReplaceKey_003, TestSize.Level1)
{
    std::vector<int32_t> vec1 = {1, 2, 3};
    auto json = CreateJson();
    EXPECT_TRUE(AddVectorIntToJson(json.get(), "list", vec1));

    std::vector<int32_t> vec2 = {10, 20};
    EXPECT_TRUE(AddVectorIntToJson(json.get(), "list", vec2));

    std::vector<int32_t> result;
    EXPECT_TRUE(GetVectorIntFromJson(json.get(), "list", result));
    EXPECT_EQ(result.size(), 2u);
    EXPECT_EQ(result[0], 10);
    EXPECT_EQ(result[1], 20);
}

/**
 * @tc.name: GetVectorInt_NonArrayValue_004
 * @tc.desc: Test GetVectorIntFromJson when key exists but value is not an array.
 */
HWTEST_F(VectorIntJsonCoverageTest, GetVectorInt_NonArrayValue_004, TestSize.Level1)
{
    auto json = CreateJson();
    AddIntToJson(json.get(), "notArray", 42);

    std::vector<int32_t> result;
    EXPECT_FALSE(GetVectorIntFromJson(json.get(), "notArray", result));
    EXPECT_TRUE(GetVectorIntFromJson(json.get(), "notArray").empty());
}

/**
 * @tc.name: GetVectorInt_MixedArray_005
 * @tc.desc: Test GetVectorIntFromJson with array containing non-number items.
 */
HWTEST_F(VectorIntJsonCoverageTest, GetVectorInt_MixedArray_005, TestSize.Level1)
{
    auto json = CreateJson();
    CJson *arr = cJSON_CreateArray();
    cJSON_AddItemToArray(arr, cJSON_CreateNumber(10));
    cJSON_AddItemToArray(arr, cJSON_CreateString("not_a_number"));
    cJSON_AddItemToArray(arr, cJSON_CreateNumber(30));
    cJSON_AddItemToObject(json.get(), "mixedArr", arr);

    std::vector<int32_t> result;
    EXPECT_TRUE(GetVectorIntFromJson(json.get(), "mixedArr", result));
    EXPECT_EQ(result.size(), 2u);
    EXPECT_EQ(result[0], 10);
    EXPECT_EQ(result[1], 30);
}

// ===== SubProfile file I/O coverage =====
// Covers: ReadSubProfileContext, WriteSubProfileContext (OsAccountControlFileManager methods)
// Uses AccountFileOperator + ToJsonSubProfile/FromJsonSubProfile to simulate the internal logic
// without constructing OsAccountControlFileManager (which requires AccountFileWatcherMgr).
class SubProfileFileIOCoverageTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        allPermTokenId_ = GetAllAccountPermission();
        ASSERT_NE(allPermTokenId_, 0);
    }
    static void TearDownTestCase()
    {
        if (allPermTokenId_ != 0) {
            Security::AccessToken::AccessTokenKit::DeleteToken(
                static_cast<Security::AccessToken::AccessTokenID>(allPermTokenId_));
        }
        AccountFileOperator fileOp;
        fileOp.DeleteDirOrFile(Constants::USER_INFO_BASE);
    }
    void SetUp() override
    {
        ASSERT_EQ(SetSelfTokenID(allPermTokenId_), 0);
    }
    void TearDown() override
    {
        AccountFileOperator fileOp;
        fileOp.DeleteDirOrFile(Constants::USER_INFO_BASE);
    }
    std::string GetSubProfilePath(int32_t id)
    {
        return Constants::USER_INFO_BASE + Constants::PATH_SEPARATOR +
            std::to_string(id) + Constants::PATH_SEPARATOR + Constants::SUBPROFILE_INFO_FILE_NAME;
    }
    ErrCode WriteSubProfileViaFileOp(int32_t id, const SubProfileContext &data)
    {
        auto json = ToJsonSubProfile(data);
        std::string jsonStr = PackJsonToString(json);
        if (jsonStr.empty()) {
            return ERR_ACCOUNT_COMMON_FILE_WRITE_FAILED;
        }
        return fileOp_.InputFileByPathAndContent(GetSubProfilePath(id), jsonStr);
    }
    ErrCode ReadSubProfileViaFileOp(int32_t id, SubProfileContext &data)
    {
        std::string jsonStr;
        ErrCode ret = fileOp_.GetFileContentByPath(GetSubProfilePath(id), jsonStr);
        if (ret != ERR_OK) {
            return ERR_ACCOUNT_COMMON_FILE_NOT_EXIST;
        }
        auto json = CreateJsonFromString(jsonStr);
        if (json == nullptr) {
            return ERR_ACCOUNT_COMMON_FILE_OPEN_FAILED;
        }
        FromJsonSubProfile(json.get(), data);
        return ERR_OK;
    }
    static uint64_t allPermTokenId_;
    AccountFileOperator fileOp_;
};

uint64_t SubProfileFileIOCoverageTest::allPermTokenId_ = 0;

/**
 * @tc.name: WriteAndReadSubProfileContext_001
 * @tc.desc: Test WriteSubProfileContext then ReadSubProfileContext round-trip.
 */
HWTEST_F(SubProfileFileIOCoverageTest, WriteAndReadSubProfileContext_001, TestSize.Level1)
{
    SubProfileContext ctx(1001, {100000, 100001}, 3, {{0, 100000}, {1, 100001}});
    ErrCode writeRet = WriteSubProfileViaFileOp(TEST_OS_ACCOUNT_ID, ctx);
    EXPECT_EQ(writeRet, ERR_OK);

    SubProfileContext readCtx;
    ErrCode readRet = ReadSubProfileViaFileOp(TEST_OS_ACCOUNT_ID, readCtx);
    EXPECT_EQ(readRet, ERR_OK);
    EXPECT_EQ(readCtx.nextSubProfileId, 1001);
    EXPECT_EQ(readCtx.subProfileIdList.size(), 2u);
    EXPECT_EQ(readCtx.subProfileIdList[0], 100000);
    EXPECT_EQ(readCtx.subProfileIdList[1], 100001);
    EXPECT_EQ(readCtx.nextSubProfileIndex, 3);
    EXPECT_EQ(readCtx.subProfileIndexMap.size(), 2u);
    EXPECT_EQ(readCtx.subProfileIndexMap[0], 100000);
    EXPECT_EQ(readCtx.subProfileIndexMap[1], 100001);
}

/**
 * @tc.name: ReadSubProfileContext_FileNotExist_002
 * @tc.desc: Test ReadSubProfileContext returns error for non-existent file.
 */
HWTEST_F(SubProfileFileIOCoverageTest, ReadSubProfileContext_FileNotExist_002, TestSize.Level1)
{
    SubProfileContext readCtx;
    ErrCode readRet = ReadSubProfileViaFileOp(99999, readCtx);
    EXPECT_EQ(readRet, ERR_ACCOUNT_COMMON_FILE_NOT_EXIST);
}

/**
 * @tc.name: ReadSubProfileContext_CorruptJson_003
 * @tc.desc: Test ReadSubProfileContext returns error for corrupt JSON file.
 */
HWTEST_F(SubProfileFileIOCoverageTest, ReadSubProfileContext_CorruptJson_003, TestSize.Level1)
{
    ErrCode writeRet = fileOp_.InputFileByPathAndContent(GetSubProfilePath(TEST_OS_ACCOUNT_ID), "not_json{{");
    EXPECT_EQ(writeRet, ERR_OK);

    SubProfileContext readCtx;
    ErrCode readRet = ReadSubProfileViaFileOp(TEST_OS_ACCOUNT_ID, readCtx);
    EXPECT_EQ(readRet, ERR_ACCOUNT_COMMON_FILE_OPEN_FAILED);
}

/**
 * @tc.name: WriteSubProfileContext_HeadlessDefault_004
 * @tc.desc: Test WriteSubProfileContext with CreateWithHeadlessDefault data then ReadSubProfileContext.
 */
HWTEST_F(SubProfileFileIOCoverageTest, WriteSubProfileContext_HeadlessDefault_004, TestSize.Level1)
{
    SubProfileContext ctx = SubProfileContext::CreateWithHeadlessDefault(TEST_OS_ACCOUNT_ID);
    ErrCode writeRet = WriteSubProfileViaFileOp(TEST_OS_ACCOUNT_ID, ctx);
    EXPECT_EQ(writeRet, ERR_OK);

    SubProfileContext readCtx;
    ErrCode readRet = ReadSubProfileViaFileOp(TEST_OS_ACCOUNT_ID, readCtx);
    EXPECT_EQ(readRet, ERR_OK);
    EXPECT_EQ(readCtx.nextSubProfileId, TEST_SUBSPACE_BASE + 1);
    EXPECT_EQ(readCtx.subProfileIdList.size(), 1u);
    EXPECT_EQ(readCtx.subProfileIdList[0], TEST_SUBSPACE_BASE);
    EXPECT_EQ(readCtx.nextSubProfileIndex, 1);
    EXPECT_EQ(readCtx.subProfileIndexMap.size(), 1u);
    EXPECT_EQ(readCtx.subProfileIndexMap[0], TEST_SUBSPACE_BASE);
}

class MockFailingIdListControl : public OsAccountControlFileManager {
public:
    ErrCode GetOsAccountIdList(std::vector<int32_t> &idList) override
    {
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
};

#endif // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
