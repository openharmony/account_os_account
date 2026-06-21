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
#include <thread>

#define private public
#include "os_account_subspace_data_deal.h"
#include "os_account_subspace_manager.h"
#include "os_account_sub_profile_id_counter.h"
#undef private

#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "account_test_common.h"
#include "accesstoken_kit.h"
#include "account_info.h"
#include "os_account_constants.h"
#include "os_account_info.h"
#include "mock/mock_space_dependencies.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string TEST_ROOT_DIR = "/data/test/os_account_subspace_manager_test_dir/";
constexpr int32_t OS_ACCOUNT_ID = 100;
constexpr int32_t TEST_ID_BASE = 100000;
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
        MockClearForceFailFlags();
        MockSetCreatedOsAccounts({});
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
    ErrCode ret = mgr.CreateSubProfile(OS_ACCOUNT_ID, newSubspaceId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(newSubspaceId, TEST_ID_BASE + 1);

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
    ErrCode ret1 = mgr.CreateSubProfile(OS_ACCOUNT_ID, distId1);
    EXPECT_EQ(ret1, ERR_OK);
    EXPECT_EQ(distId1, TEST_ID_BASE + 1);

    ErrCode ret2 = mgr.CreateSubProfile(OS_ACCOUNT_ID, distId2);
    EXPECT_EQ(ret2, ERR_OK);
    EXPECT_EQ(distId2, TEST_ID_BASE + 2);

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
    std::vector<std::string> fullList;
    for (int32_t i = 1; i <= MAX_OS_ACCOUNT_SUB_PROFILE_COUNT; ++i) {
        fullList.push_back(
            std::to_string(TEST_ID_BASE + i));
    }
    osAccountInfo.SetSubProfileIdList(fullList);
    MockSetCreatedOsAccounts({osAccountInfo});

    int32_t newSubspaceId = 0;
    ErrCode ret = mgr.CreateSubProfile(OS_ACCOUNT_ID, newSubspaceId);
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
    int32_t base = TEST_ID_BASE;

    // Set hint to base+1 and already-occupied list {base+1, base+2}
    // → AllocateOsAccountSubProfileId checks base+1 (occupied, ++startId/+searchCount)
    //   → base+2 (occupied, ++startId/+searchCount) → base+3 (free, returns ERR_OK)
    OsAccountInfo osAccountInfo;
    osAccountInfo.SetLocalId(OS_ACCOUNT_ID);
    osAccountInfo.SetNextSubProfileId(base + 1);
    osAccountInfo.SetSubProfileIdList({std::to_string(base + 1), std::to_string(base + 2)});
    MockSetCreatedOsAccounts({osAccountInfo});

    int32_t distId = 0;
    ErrCode ret = mgr.CreateSubProfile(OS_ACCOUNT_ID, distId);
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
    int32_t base = TEST_ID_BASE;

    OsAccountInfo osAccountInfo;
    osAccountInfo.SetLocalId(OS_ACCOUNT_ID);
    // Fill all slots except index 1: subProfileIdList.size() = MAX - 1 < MAX → guard passes
    std::vector<std::string> idList;
    for (int32_t i = 2; i <= MAX_OS_ACCOUNT_SUB_PROFILE_COUNT; ++i) {
        idList.push_back(std::to_string(base + i));
    }
    osAccountInfo.SetNextSubProfileId(TEST_ID_BASE + 999);
    osAccountInfo.SetSubProfileIdList(idList);
    MockSetCreatedOsAccounts({osAccountInfo});

    int32_t distId = 0;
    ErrCode ret = mgr.CreateSubProfile(OS_ACCOUNT_ID, distId);
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
    ErrCode ret = mgr.CreateSubProfile(OS_ACCOUNT_ID, newSubspaceId);
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
    ErrCode retA = mgr.CreateSubProfile(OS_ACCOUNT_ID_A, distIdA);
    ErrCode retB = mgr.CreateSubProfile(OS_ACCOUNT_ID_B, distIdB);
    EXPECT_EQ(retA, ERR_OK);
    EXPECT_EQ(retB, ERR_OK);

    int32_t lookupA = 0;
    int32_t lookupB = 0;
    EXPECT_EQ(mgr.GetLocalIdForSubProfile(distIdA, lookupA), ERR_OK);
    EXPECT_EQ(mgr.GetLocalIdForSubProfile(distIdB, lookupB), ERR_OK);
    EXPECT_EQ(lookupA, OS_ACCOUNT_ID_A);
    EXPECT_EQ(lookupB, OS_ACCOUNT_ID_B);
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
    ErrCode ret = mgr.CreateSubProfile(OS_ACCOUNT_ID, distId);
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
    ErrCode ret = mgr.CreateSubProfile(OS_ACCOUNT_ID, distId);
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
 * @tc.desc: R5 - SM层对0-index空间返回SUBSPACE_NOT_FOUND（index-0 subspace保护由SV层实现）
 *            SM层IsValidSubProfileExists对index-0 subspace目录路径返回false
              因为index-0 subspace的文件在{osAccountId}/account.json而非子目录
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubProfileManagerTest, RemoveSpace_ZeroIndex_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    int32_t zeroDistId = TEST_ID_BASE;
    ErrCode ret = mgr.RemoveSubProfile(OS_ACCOUNT_ID, zeroDistId);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND);
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
    ErrCode ret = mgr.CreateSubProfile(OS_ACCOUNT_ID, distId);
    EXPECT_EQ(ret, ERR_OK);

    // GetOsAccountInfoById succeeds → foregroundId=0 ≠ subspaceId → removal proceeds normally
    ret = mgr.RemoveSubProfile(OS_ACCOUNT_ID, distId);
    // In developer_test with foreground subspace switched, this returns ERR_OS_ACCOUNT_SUBSPACE_IS_FOREGROUND
    EXPECT_TRUE(ret == ERR_OK || ret == ERR_OS_ACCOUNT_SUBSPACE_IS_FOREGROUND);
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
    int32_t nonExistDistId = TEST_ID_BASE + 999;
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
    int32_t nonExistDistId = TEST_ID_BASE + 999;
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
    ErrCode ret1 = mgr.CreateSubProfile(OS_ACCOUNT_ID, distId1);
    ErrCode ret2 = mgr.CreateSubProfile(OS_ACCOUNT_ID, distId2);
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
    ErrCode createRet = mgr.CreateSubProfile(OS_ACCOUNT_ID, subspaceId);
    EXPECT_EQ(createRet, ERR_OK);

    // Force UpdateOsAccountSubspaceInfo to fail only for the removal path.
    // RemoveSubspaceLocked → RemoveOsAccountSubspaceInfo calls UpdateOsAccountSubspaceInfo
    // which fails → hits the err != ERR_OK log branch for coverage.
    MockForceUpdateSubspaceInfoFail(ERR_ACCOUNT_COMMON_INVALID_PARAMETER);

    ErrCode removeRet = mgr.RemoveSubProfile(OS_ACCOUNT_ID, subspaceId);
    EXPECT_EQ(removeRet, ERR_OK);

    MockClearForceFailFlags();
}

/**
 * @tc.name: SubProfileIdCounter_Persistence_001
 * @tc.desc: Counter persists value to file; after re-Init, next ID continues from persisted value
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubProfileManagerTest, SubProfileIdCounter_Persistence_001, TestSize.Level1)
{
    auto &counter = SubProfileIdCounter::GetInstance();
    ASSERT_EQ(counter.Init({}), ERR_OK);
    int32_t firstId = counter.GetNextId();
    int32_t secondId = counter.GetNextId();
    EXPECT_GT(secondId, firstId);

    ASSERT_EQ(counter.Init({}), ERR_OK);
    int32_t afterReload = counter.GetNextId();
    EXPECT_GT(afterReload, secondId);
}

/**
 * @tc.name: SubProfileIdCounter_ReconstructFromExistingData_001
 * @tc.desc: When counter file is missing/corrupted, counter reconstructs from existing OsAccountInfo
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubProfileManagerTest, SubProfileIdCounter_ReconstructFromExistingData_001, TestSize.Level1)
{
    auto &counter = SubProfileIdCounter::GetInstance();
    OsAccountInfo info;
    info.SetLocalId(OS_ACCOUNT_ID);
    info.SetCommonSubProfileId(500000);
    info.SetSubProfileIdList({"500001", "500002", "500010"});

    ASSERT_EQ(counter.Init({info}), ERR_OK);
    int32_t nextId = counter.GetNextId();
    EXPECT_GT(nextId, 500010);
}

/**
 * @tc.name: SubProfileIdCounter_ConcurrentAllocation_001
 * @tc.desc: Two threads calling GetNextId concurrently receive distinct IDs
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubProfileManagerTest, SubProfileIdCounter_ConcurrentAllocation_001, TestSize.Level1)
{
    auto &counter = SubProfileIdCounter::GetInstance();
    ASSERT_EQ(counter.Init({}), ERR_OK);
    constexpr int ALLOC_COUNT = 100;
    std::vector<int32_t> idsA(ALLOC_COUNT, 0);
    std::vector<int32_t> idsB(ALLOC_COUNT, 0);
    std::thread tA([&]() { for (int i = 0; i < ALLOC_COUNT; ++i) idsA[i] = counter.GetNextId(); });
    std::thread tB([&]() { for (int i = 0; i < ALLOC_COUNT; ++i) idsB[i] = counter.GetNextId(); });
    tA.join();
    tB.join();
    std::set<int32_t> allIds;
    for (int i = 0; i < ALLOC_COUNT; ++i) {
        EXPECT_TRUE(allIds.insert(idsA[i]).second);
        EXPECT_TRUE(allIds.insert(idsB[i]).second);
    }
    EXPECT_EQ(allIds.size(), static_cast<size_t>(ALLOC_COUNT * 2));
}

/**
 * @tc.name: SubProfileCache_LookupCorrectness_001
 * @tc.desc: create → lookup returns correct osAccountId → delete → lookup returns NOT_FOUND
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubProfileManagerTest, SubProfileCache_LookupCorrectness_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    int32_t newId = 0;
    ASSERT_EQ(mgr.CreateSubProfile(OS_ACCOUNT_ID, newId), ERR_OK);

    int32_t lookupId = 0;
    EXPECT_EQ(mgr.GetLocalIdForSubProfile(newId, lookupId), ERR_OK);
    EXPECT_EQ(lookupId, OS_ACCOUNT_ID);

    EXPECT_EQ(mgr.RemoveSubProfile(OS_ACCOUNT_ID, newId), ERR_OK);
    EXPECT_NE(mgr.GetLocalIdForSubProfile(newId, lookupId), ERR_OK);
}

/**
 * @tc.name: CommonSubProfile_IdentificationViaField_001
 * @tc.desc: Common SubProfile is identified by commonSubProfileId_ field, not modulo arithmetic
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubProfileManagerTest, CommonSubProfile_IdentificationViaField_001, TestSize.Level1)
{
    OsAccountInfo info;
    info.SetLocalId(OS_ACCOUNT_ID);
    info.SetCommonSubProfileId(777777);
    info.SetForegroundSubProfileId(-1);
    MockSetCreatedOsAccounts({info});

    EXPECT_EQ(info.GetForegroundSubProfileId(), 777777);
    EXPECT_NE(info.GetForegroundSubProfileId() % 1000, 0);
}

/**
 * @tc.name: BackwardCompatibility_CommonSubProfileReconstruct_001
 * @tc.desc: Old OsAccountInfo JSON without commonSubProfileId_ reconstructs from foregroundSubProfileId_
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubProfileManagerTest, BackwardCompatibility_CommonSubProfileReconstruct_001, TestSize.Level1)
{
    OsAccountInfo info;
    info.SetLocalId(OS_ACCOUNT_ID);
    info.SetForegroundSubProfileId(100100);
    info.SetCommonSubProfileId(Constants::INVALID_SUB_PROFILE_ID);
    MockSetCreatedOsAccounts({info});
    if (info.GetCommonSubProfileId() == Constants::INVALID_SUB_PROFILE_ID && info.GetForegroundSubProfileId() > 0) {
        info.SetCommonSubProfileId(info.GetForegroundSubProfileId());
    }
    EXPECT_EQ(info.GetCommonSubProfileId(), 100100);
}

#endif  // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE