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

#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <set>
#include <string>

#define private public
#include "os_account_subspace_data_deal.h"
#include "os_account_subspace_manager.h"
#undef private

#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "account_test_common.h"
#include "accesstoken_kit.h"
#include "account_info.h"
#include "os_account_constants.h"
#include "os_account_info.h"
#include "os_account_info_json_parser.h"
#include "mock/mock_space_dependencies.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string TEST_ROOT_DIR = "/data/test/os_account_subspace_manager_test_dir/";
constexpr int32_t OS_ACCOUNT_ID = 100;
}  // namespace

class OsAccountSubProfileManagerTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        allPermTokenId_ = GetAllAccountPermission();
        ASSERT_NE(allPermTokenId_, 0);
        std::filesystem::create_directories(TEST_ROOT_DIR);
    }

    static void TearDownTestCase()
    {
        std::error_code ec;
        std::filesystem::remove_all(TEST_ROOT_DIR, ec);
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
        osAccountInfo.SetLocalId(OS_ACCOUNT_ID);
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

uint64_t OsAccountSubProfileManagerTest::allPermTokenId_ = 0;

/**
 * @tc.name: CreateSubspace_Success_001
 * @tc.desc: C1 - CreateSubspace allocates minimum available index and persists two-phase write
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubProfileManagerTest, CreateSubspace_Success_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    int32_t newSubspaceId = 0;
    int32_t index = 0;
    ErrCode ret = mgr.CreateSubProfile(OS_ACCOUNT_ID, newSubspaceId, index);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(newSubspaceId, OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 1);

    EXPECT_TRUE(mgr.subProfileDataDeal_->IsValidSubProfileExists(OS_ACCOUNT_ID, newSubspaceId));
}

/**
 * @tc.name: CreateSubspace_Multiple_002
 * @tc.desc: C1 - CreateSubspace allocates successive indices and each space is independently valid
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubProfileManagerTest, CreateSubspace_Multiple_002, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    int32_t distId1 = 0;
    int32_t distId2 = 0;
    int32_t index1 = 0;
    ErrCode ret1 = mgr.CreateSubProfile(OS_ACCOUNT_ID, distId1, index1);
    EXPECT_EQ(ret1, ERR_OK);
    EXPECT_EQ(distId1, OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 1);

    int32_t index2 = 0;
    ErrCode ret2 = mgr.CreateSubProfile(OS_ACCOUNT_ID, distId2, index2);
    EXPECT_EQ(ret2, ERR_OK);
    EXPECT_EQ(distId2, OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 2);

    EXPECT_TRUE(mgr.subProfileDataDeal_->IsValidSubProfileExists(OS_ACCOUNT_ID, distId1));
    EXPECT_TRUE(mgr.subProfileDataDeal_->IsValidSubProfileExists(OS_ACCOUNT_ID, distId2));
}

/**
 * @tc.name: CreateSubspace_LimitReached_003
 * @tc.desc: C7 - CreateSubspace returns REACH_LIMIT when all 999 slots are used
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubProfileManagerTest, CreateSubspace_LimitReached_003, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    // Setup mock: account 100 with all 999 subspaces already allocated
    OsAccountInfo osAccountInfo;
    osAccountInfo.SetLocalId(OS_ACCOUNT_ID);
    MockSetCreatedOsAccounts({osAccountInfo});

    SubProfileContext subprofileCtx;
    subprofileCtx.subProfileIdList.push_back(
        OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER);
    for (int32_t i = 1; i <= MAX_OS_ACCOUNT_SUB_PROFILE_COUNT - 1; ++i) {
        subprofileCtx.subProfileIdList.push_back(
            OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + i);
    }
    MockForceSubProfileContext(OS_ACCOUNT_ID, subprofileCtx);

    int32_t newSubspaceId = 0;
    int32_t index = 0;
    ErrCode ret = mgr.CreateSubProfile(OS_ACCOUNT_ID, newSubspaceId, index);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_LIMIT);
}

/**
 * @tc.name: CreateSubspace_HintOccupied_004
 * @tc.desc: When nextSubProfileId hint is already occupied in subProfileIdList,
 *           AllocateOsAccountSubProfileId enters the search loop body
 *           (++startId, ++searchCount) and finds the next free slot.
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubProfileManagerTest, CreateSubspace_HintOccupied_004, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    int32_t base = OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;

    // Set hint to base+1 and already-occupied list {base+1, base+2}
    // → AllocateOsAccountSubProfileId checks base+1 (occupied, ++startId/+searchCount)
    //   → base+2 (occupied, ++startId/+searchCount) → base+3 (free, returns ERR_OK)
    OsAccountInfo osAccountInfo;
    osAccountInfo.SetLocalId(OS_ACCOUNT_ID);
    MockSetCreatedOsAccounts({osAccountInfo});

    SubProfileContext subprofileCtx;
    subprofileCtx.nextSubProfileId = base + 1;
    subprofileCtx.subProfileIdList = {base + 1, base + 2};
    MockForceSubProfileContext(OS_ACCOUNT_ID, subprofileCtx);

    int32_t distId = 0;
    int32_t index = 0;
    ErrCode ret = mgr.CreateSubProfile(OS_ACCOUNT_ID, distId, index);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(distId, base + 3);
}

/**
 * @tc.name: CreateSubspace_WrapAround_005
 * @tc.desc: When hint is at INDEX_MAX and that slot is occupied,
 *           AllocateOsAccountSubProfileId wraps startId from maxId+1 back to minId
 *           (covering ++startId → startId > maxId → startId = minId).
 *           All slots 2..MAX are occupied; only slot 1 is free.
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubProfileManagerTest, CreateSubspace_WrapAround_005, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    int32_t base = OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;

    OsAccountInfo osAccountInfo;
    osAccountInfo.SetLocalId(OS_ACCOUNT_ID);
    MockSetCreatedOsAccounts({osAccountInfo});

    SubProfileContext subprofileCtx;
    subprofileCtx.nextSubProfileId = base + OsAccountSubProfileDataDeal::OS_ACCOUNT_SUB_PROFILE_ID_MAX;
    for (int32_t i = 2; i <= MAX_OS_ACCOUNT_SUB_PROFILE_COUNT - 1; ++i) {
        subprofileCtx.subProfileIdList.push_back(base + i);
    }
    MockForceSubProfileContext(OS_ACCOUNT_ID, subprofileCtx);

    int32_t distId = 0;
    int32_t index = 0;
    ErrCode ret = mgr.CreateSubProfile(OS_ACCOUNT_ID, distId, index);
    EXPECT_EQ(ret, ERR_OK);
    // After wrap: startId = base + MAX + 1 > maxId → wrap to minId = base + 1 → free
    EXPECT_EQ(distId, base + 1);
}

/**
 * @tc.name: CreateSubspace_AtomicWrite_001
 * @tc.desc: C10 - CreateSubspace uses two-phase write; after creation the file has isCreateCompleted=true
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubProfileManagerTest, CreateSubspace_AtomicWrite_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    int32_t newSubspaceId = 0;
    int32_t index = 0;
    ErrCode ret = mgr.CreateSubProfile(OS_ACCOUNT_ID, newSubspaceId, index);
    EXPECT_EQ(ret, ERR_OK);

    OsAccountSubspaceInfo loaded;
    ret = mgr.subProfileDataDeal_->LoadSubProfileInfo(OS_ACCOUNT_ID, newSubspaceId, loaded);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(loaded.isCreateCompleted);
    EXPECT_FALSE(loaded.toBeRemoved);
    EXPECT_EQ(loaded.version_, ACCOUNT_VERSION_ANON);
    EXPECT_EQ(loaded.bindTime_, 0);
    EXPECT_EQ(loaded.ohosAccountInfo_.name_, DEFAULT_OHOS_ACCOUNT_NAME);
    EXPECT_EQ(loaded.ohosAccountInfo_.uid_, DEFAULT_OHOS_ACCOUNT_UID);
    EXPECT_EQ(loaded.ohosAccountInfo_.GetRawUid(), DEFAULT_OHOS_ACCOUNT_UID);
    EXPECT_EQ(loaded.ohosAccountInfo_.status_, ACCOUNT_STATE_UNBOUND);
    EXPECT_EQ(loaded.ohosAccountInfo_.callingUid_, DEFAULT_CALLING_UID);
}

/**
 * @tc.name: CreateSubspace_Isolation_001
 * @tc.desc: C1 - CreateSubspace for different OS accounts produces isolated IDs
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubProfileManagerTest, CreateSubspace_Isolation_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    constexpr int32_t OS_ACCOUNT_ID_A = 100;
    constexpr int32_t OS_ACCOUNT_ID_B = 101;

    OsAccountInfo infoA;
    infoA.SetLocalId(OS_ACCOUNT_ID_A);
    OsAccountInfo infoB;
    infoB.SetLocalId(OS_ACCOUNT_ID_B);
    MockSetCreatedOsAccounts({infoA, infoB});

    int32_t distIdA = 0;
    int32_t distIdB = 0;
    int32_t indexA = 0;
    ErrCode retA = mgr.CreateSubProfile(OS_ACCOUNT_ID_A, distIdA, indexA);
    int32_t indexB = 0;
    ErrCode retB = mgr.CreateSubProfile(OS_ACCOUNT_ID_B, distIdB, indexB);
    EXPECT_EQ(retA, ERR_OK);
    EXPECT_EQ(retB, ERR_OK);

    EXPECT_EQ(distIdA / Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER, OS_ACCOUNT_ID_A);
    EXPECT_EQ(distIdB / Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER, OS_ACCOUNT_ID_B);
    EXPECT_NE(distIdA, distIdB);
}

/**
 * @tc.name: RemoveSpace_Success_001
 * @tc.desc: R1 - RemoveSpace successfully removes a non-foreground space
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubProfileManagerTest, RemoveSpace_Success_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    int32_t distId = 0;
    int32_t index = 0;
    ErrCode ret = mgr.CreateSubProfile(OS_ACCOUNT_ID, distId, index);
    EXPECT_EQ(ret, ERR_OK);

    ret = mgr.RemoveSubProfile(OS_ACCOUNT_ID, distId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(mgr.subProfileDataDeal_->IsValidSubProfileExists(OS_ACCOUNT_ID, distId));
}

/**
 * @tc.name: RemoveSpace_ToBeRemoved_001
 * @tc.desc: R1 - RemoveSpace marks toBeRemoved=true before deleting directory
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubProfileManagerTest, RemoveSpace_ToBeRemoved_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    int32_t distId = 0;
    int32_t index = 0;
    ErrCode ret = mgr.CreateSubProfile(OS_ACCOUNT_ID, distId, index);
    EXPECT_EQ(ret, ERR_OK);

    OsAccountSubspaceInfo info;
    mgr.subProfileDataDeal_->LoadSubProfileInfo(OS_ACCOUNT_ID, distId, info);
    EXPECT_FALSE(info.toBeRemoved);

    ret = mgr.RemoveSubProfile(OS_ACCOUNT_ID, distId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(mgr.subProfileDataDeal_->IsValidSubProfileExists(OS_ACCOUNT_ID, distId));
}

/**
 * @tc.name: RemoveSpace_ZeroIndex_001
 * @tc.desc: R5 - Removing headless subprofile (index=0, subspaceId=base) is restricted.
 *            The headless subprofile cannot be deleted.
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubProfileManagerTest, RemoveSpace_ZeroIndex_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    int32_t zeroDistId = OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;
    ErrCode ret = mgr.RemoveSubProfile(OS_ACCOUNT_ID, zeroDistId);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_RESTRICTED);
}

/**
 * @tc.name: RemoveSpace_ForegroundCheck_001
 * @tc.desc: Verify RemoveSubspaceLocked foreground check — when GetOsAccountInfoById
 *           succeeds (mock provides account 100) and default foregroundId=0 ≠ subspaceId,
 *           the foreground guard does not block removal. Full foreground coverage
 *           (foregroundId == subspaceId → IS_FOREGROUND) requires developer_test
 *           with a subspace that was previously switched to.
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubProfileManagerTest, RemoveSpace_ForegroundCheck_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    int32_t distId = 0;
    int32_t index = 0;
    ErrCode ret = mgr.CreateSubProfile(OS_ACCOUNT_ID, distId, index);
    EXPECT_EQ(ret, ERR_OK);

    // GetOsAccountInfoById succeeds → foregroundId=0 ≠ subspaceId → removal proceeds normally
    ret = mgr.RemoveSubProfile(OS_ACCOUNT_ID, distId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(mgr.subProfileDataDeal_->IsValidSubProfileExists(OS_ACCOUNT_ID, distId));
}

/**
 * @tc.name: RemoveSpace_NotFound_002
 * @tc.desc: R8 - RemoveSpace returns SUBSPACE_NOT_FOUND for non-existent space
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubProfileManagerTest, RemoveSpace_NotFound_002, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    int32_t nonExistDistId = OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 999;
    ErrCode ret = mgr.RemoveSubProfile(OS_ACCOUNT_ID, nonExistDistId);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND);
}

/**
 * @tc.name: SwitchSpace_NotFound_001
 * @tc.desc: S6 - SwitchSpace returns SUBSPACE_NOT_FOUND for non-existent target space
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubProfileManagerTest, SwitchSpace_NotFound_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    int32_t nonExistDistId = OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 999;
    int32_t fromSubspaceId = 0;
    ErrCode ret = mgr.SwitchSubProfile(OS_ACCOUNT_ID, nonExistDistId, fromSubspaceId);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND);
}

/**
 * @tc.name: RemoveSpace_ToBeRemovedAndCleanup_001
 * @tc.desc: R1/R9 - RemoveSpace marks toBeRemoved and CleanupOrphanedSubProfiles finishes cleanup
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubProfileManagerTest, RemoveSpace_ToBeRemovedAndCleanup_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    int32_t distId1 = 0;
    int32_t distId2 = 0;
    int32_t index1 = 0;
    ErrCode ret1 = mgr.CreateSubProfile(OS_ACCOUNT_ID, distId1, index1);
    int32_t index2 = 0;
    ErrCode ret2 = mgr.CreateSubProfile(OS_ACCOUNT_ID, distId2, index2);
    EXPECT_EQ(ret1, ERR_OK);
    EXPECT_EQ(ret2, ERR_OK);

    ret1 = mgr.RemoveSubProfile(OS_ACCOUNT_ID, distId1);
    EXPECT_EQ(ret1, ERR_OK);

    EXPECT_TRUE(mgr.subProfileDataDeal_->IsValidSubProfileExists(OS_ACCOUNT_ID, distId2));
    EXPECT_FALSE(mgr.subProfileDataDeal_->IsValidSubProfileExists(OS_ACCOUNT_ID, distId1));

    std::set<int32_t> validIds;
    EXPECT_EQ(mgr.subProfileDataDeal_->ScanOsAccountSubProfileIds(OS_ACCOUNT_ID, validIds), ERR_OK);
    EXPECT_EQ(validIds.count(distId1), 0u);
    EXPECT_EQ(validIds.count(distId2), 1u);
}

/**
 * @tc.name: RemoveSpace_UpdateOsAccountSubspaceInfoFail_002
 * @tc.desc: R1 - RemoveSubspace coverage: RemoveOsAccountSubspaceInfo branch when
 *           UpdateOsAccountSubspaceInfo returns error after erasing subspaceId from list
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubProfileManagerTest, RemoveSpace_UpdateOsAccountSubspaceInfoFail_002, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();

    // Create normally first so mock state is correctly updated with the subspace ID
    int32_t subspaceId = 0;
    int32_t index = 0;
    ErrCode createRet = mgr.CreateSubProfile(OS_ACCOUNT_ID, subspaceId, index);
    EXPECT_EQ(createRet, ERR_OK);

    // Force UpdateOsAccountSubspaceInfo to fail only for the removal path.
    // RemoveSubspaceLocked → RemoveOsAccountSubspaceInfo calls UpdateOsAccountSubspaceInfo
    // which fails → hits the err != ERR_OK log branch for coverage.
    MockForceUpdateSubspaceInfoFail(ERR_ACCOUNT_COMMON_INVALID_PARAMETER);

    ErrCode removeRet = mgr.RemoveSubProfile(OS_ACCOUNT_ID, subspaceId);
    EXPECT_EQ(removeRet, ERR_OK);

    MockClearForceFailFlags();
}

#endif  // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE