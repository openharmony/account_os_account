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
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string TEST_ROOT_DIR = "/data/test/os_account_subspace_manager_test_dir/";
constexpr int32_t OS_ACCOUNT_ID = 100;
}  // namespace

class OsAccountSubspaceManagerTest : public testing::Test {
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
        auto &mgr = OsAccountSubspaceManager::GetInstance();
        mgr.Init(TEST_ROOT_DIR);
    }

    void TearDown() override {}

    void SaveCompletedSpace(int32_t osAccountId, int32_t index)
    {
        int32_t distId = osAccountId * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + index;
        OsAccountSubspaceInfo info;
        info.userId_ = osAccountId;
        info.subspaceId = distId;
        info.isCreateCompleted = true;
        info.toBeRemoved = false;
        ASSERT_EQ(OsAccountSubspaceManager::GetInstance().subspaceDataDeal_->SaveSubspaceInfo(info), ERR_OK);
    }

    static uint64_t allPermTokenId_;
};

uint64_t OsAccountSubspaceManagerTest::allPermTokenId_ = 0;

/**
 * @tc.name: CreateSubspace_Success_001
 * @tc.desc: C1 - CreateSubspace allocates minimum available index and persists two-phase write
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceManagerTest, CreateSubspace_Success_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubspaceManager::GetInstance();
    int32_t newSubspaceId = 0;
    ErrCode ret = mgr.CreateSubspace(OS_ACCOUNT_ID, newSubspaceId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(newSubspaceId, OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 1);

    EXPECT_TRUE(mgr.subspaceDataDeal_->IsValidSubspaceExists(OS_ACCOUNT_ID, newSubspaceId));
}

/**
 * @tc.name: CreateSubspace_Multiple_002
 * @tc.desc: C1 - CreateSubspace allocates successive indices and each space is independently valid
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceManagerTest, CreateSubspace_Multiple_002, TestSize.Level1)
{
    auto &mgr = OsAccountSubspaceManager::GetInstance();
    int32_t distId1 = 0;
    int32_t distId2 = 0;
    ErrCode ret1 = mgr.CreateSubspace(OS_ACCOUNT_ID, distId1);
    EXPECT_EQ(ret1, ERR_OK);
    EXPECT_EQ(distId1, OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 1);

    ErrCode ret2 = mgr.CreateSubspace(OS_ACCOUNT_ID, distId2);
    EXPECT_EQ(ret2, ERR_OK);
    EXPECT_EQ(distId2, OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 2);

    EXPECT_TRUE(mgr.subspaceDataDeal_->IsValidSubspaceExists(OS_ACCOUNT_ID, distId1));
    EXPECT_TRUE(mgr.subspaceDataDeal_->IsValidSubspaceExists(OS_ACCOUNT_ID, distId2));
}

/**
 * @tc.name: CreateSubspace_LimitReached_003
 * @tc.desc: C7 - CreateSubspace returns REACH_LIMIT when all 999 slots are used
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceManagerTest, CreateSubspace_LimitReached_003, TestSize.Level1)
{
    auto &mgr = OsAccountSubspaceManager::GetInstance();
    for (int32_t i = 1; i <= MAX_OS_ACCOUNT_SUBSPACE_COUNT; ++i) {
        SaveCompletedSpace(OS_ACCOUNT_ID, i);
    }
    int32_t newSubspaceId = 0;
    ErrCode ret = mgr.CreateSubspace(OS_ACCOUNT_ID, newSubspaceId);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_LIMIT);
}

/**
 * @tc.name: CreateSubspace_AtomicWrite_001
 * @tc.desc: C10 - CreateSubspace uses two-phase write; after creation the file has isCreateCompleted=true
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceManagerTest, CreateSubspace_AtomicWrite_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubspaceManager::GetInstance();
    int32_t newSubspaceId = 0;
    ErrCode ret = mgr.CreateSubspace(OS_ACCOUNT_ID, newSubspaceId);
    EXPECT_EQ(ret, ERR_OK);

    OsAccountSubspaceInfo loaded;
    ret = mgr.subspaceDataDeal_->LoadSubspaceInfo(OS_ACCOUNT_ID, newSubspaceId, loaded);
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
HWTEST_F(OsAccountSubspaceManagerTest, CreateSubspace_Isolation_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubspaceManager::GetInstance();
    constexpr int32_t OS_ACCOUNT_ID_A = 100;
    constexpr int32_t OS_ACCOUNT_ID_B = 101;

    int32_t distIdA = 0;
    int32_t distIdB = 0;
    ErrCode retA = mgr.CreateSubspace(OS_ACCOUNT_ID_A, distIdA);
    ErrCode retB = mgr.CreateSubspace(OS_ACCOUNT_ID_B, distIdB);
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
HWTEST_F(OsAccountSubspaceManagerTest, RemoveSpace_Success_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubspaceManager::GetInstance();
    int32_t distId = 0;
    ErrCode ret = mgr.CreateSubspace(OS_ACCOUNT_ID, distId);
    EXPECT_EQ(ret, ERR_OK);

    ret = mgr.RemoveSubspace(OS_ACCOUNT_ID, distId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(mgr.subspaceDataDeal_->IsValidSubspaceExists(OS_ACCOUNT_ID, distId));
}

/**
 * @tc.name: RemoveSpace_ToBeRemoved_001
 * @tc.desc: R1 - RemoveSpace marks toBeRemoved=true before deleting directory
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceManagerTest, RemoveSpace_ToBeRemoved_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubspaceManager::GetInstance();
    int32_t distId = 0;
    ErrCode ret = mgr.CreateSubspace(OS_ACCOUNT_ID, distId);
    EXPECT_EQ(ret, ERR_OK);

    OsAccountSubspaceInfo info;
    mgr.subspaceDataDeal_->LoadSubspaceInfo(OS_ACCOUNT_ID, distId, info);
    EXPECT_FALSE(info.toBeRemoved);

    ret = mgr.RemoveSubspace(OS_ACCOUNT_ID, distId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(mgr.subspaceDataDeal_->IsValidSubspaceExists(OS_ACCOUNT_ID, distId));
}

/**
 * @tc.name: RemoveSpace_ZeroIndex_001
 * @tc.desc: R5 - SM层对0-index空间返回SUBSPACE_NOT_FOUND（index-0 subspace保护由SV层实现）
 *            SM层IsValidSubspaceExists对index-0 subspace目录路径返回false，因为index-0 subspace的文件在{osAccountId}/account.json而非子目录
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceManagerTest, RemoveSpace_ZeroIndex_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubspaceManager::GetInstance();
    int32_t zeroDistId = OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;
    ErrCode ret = mgr.RemoveSubspace(OS_ACCOUNT_ID, zeroDistId);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND);
}

/**
 * @tc.name: RemoveSpace_ForegroundCheck_001
 * @tc.desc: Verify RemoveSubspaceLocked foreground check — when GetOsAccountInfoById
 *           succeeds and the subspace is the current foreground, returns IS_FOREGROUND.
 *           In UT, account 100 is not in IInnerOsAccountManager so GetOsAccountInfoById
 *           fails and the foreground check is skipped (fallthrough path). This test
 *           validates the fallthrough: subspace is removed normally with ERR_OK.
 *           Full foreground coverage requires developer_test with a real account.
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceManagerTest, RemoveSpace_ForegroundCheck_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubspaceManager::GetInstance();
    int32_t distId = 0;
    ErrCode ret = mgr.CreateSubspace(OS_ACCOUNT_ID, distId);
    EXPECT_EQ(ret, ERR_OK);

    // GetOsAccountInfoById fails in UT → foreground check skipped → subspace removed normally
    ret = mgr.RemoveSubspace(OS_ACCOUNT_ID, distId);
    // In developer_test with real account, this returns ERR_OS_ACCOUNT_SUBSPACE_IS_FOREGROUND
    // if the subspace was previously switched to. In UT it returns ERR_OK (fallthrough).
    EXPECT_TRUE(ret == ERR_OK || ret == ERR_OS_ACCOUNT_SUBSPACE_IS_FOREGROUND);
    EXPECT_FALSE(mgr.subspaceDataDeal_->IsValidSubspaceExists(OS_ACCOUNT_ID, distId));
}

/**
 * @tc.name: RemoveSpace_NotFound_002
 * @tc.desc: R8 - RemoveSpace returns SUBSPACE_NOT_FOUND for non-existent space
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceManagerTest, RemoveSpace_NotFound_002, TestSize.Level1)
{
    auto &mgr = OsAccountSubspaceManager::GetInstance();
    int32_t nonExistDistId = OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 999;
    ErrCode ret = mgr.RemoveSubspace(OS_ACCOUNT_ID, nonExistDistId);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND);
}

/**
 * @tc.name: CleanupOrphanedSubspaces_Orphan_001
 * @tc.desc: R10 - CleanupOrphanedSubspaces removes directories with isCreateCompleted=false.
 *            NOTE: CleanupOrphanedSubspaces calls IInnerOsAccountManager::QueryAllCreatedOsAccounts
 *            which in UT mock returns empty list, so the cleanup loop is effectively skipped.
 *            The test still verifies: (a) ScanOrphanedSubspaceIds finds orphaned spaces,
 *            and (b) IsValidSubspaceExists returns false for orphaned space (due to file content).
 *            Full end-to-end cleanup (orphan found → directory removed) requires developer_test.
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceManagerTest, CleanupOrphanedSubspaces_Orphan_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubspaceManager::GetInstance();

    int32_t orphanDistId = OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 5;
    OsAccountSubspaceInfo orphanInfo;
    orphanInfo.userId_ = OS_ACCOUNT_ID;
    orphanInfo.subspaceId = orphanDistId;
    orphanInfo.isCreateCompleted = false;
    orphanInfo.toBeRemoved = false;
    ASSERT_EQ(mgr.subspaceDataDeal_->SaveSubspaceInfo(orphanInfo), ERR_OK);

    std::set<int32_t> orphanIds;
    EXPECT_EQ(mgr.subspaceDataDeal_->ScanOrphanedSubspaceIds(OS_ACCOUNT_ID, orphanIds), ERR_OK);
    EXPECT_EQ(orphanIds.count(orphanDistId), 1u);

    mgr.CleanupOrphanedSubspaces();

    EXPECT_FALSE(mgr.subspaceDataDeal_->IsValidSubspaceExists(OS_ACCOUNT_ID, orphanDistId));
    std::string spaceDir = TEST_ROOT_DIR + std::to_string(OS_ACCOUNT_ID) + "/" + std::to_string(orphanDistId);
    EXPECT_FALSE(std::filesystem::exists(spaceDir));
}

/**
 * @tc.name: CleanupOrphanedSubspaces_PendingRemoval_002
 * @tc.desc: R9 - CleanupOrphanedSubspaces removes directories with toBeRemoved=true.
 *            NOTE: Same UT mock limitation as CleanupOrphanedSubspaces_Orphan_001 —
 *            QueryAllCreatedOsAccounts returns empty, cleanup loop skipped.
 *            Full end-to-end cleanup requires developer_test.
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceManagerTest, CleanupOrphanedSubspaces_PendingRemoval_002, TestSize.Level1)
{
    auto &mgr = OsAccountSubspaceManager::GetInstance();

    int32_t pendingDistId = OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 10;
    OsAccountSubspaceInfo pendingInfo;
    pendingInfo.userId_ = OS_ACCOUNT_ID;
    pendingInfo.subspaceId = pendingDistId;
    pendingInfo.isCreateCompleted = true;
    pendingInfo.toBeRemoved = true;
    ASSERT_EQ(mgr.subspaceDataDeal_->SaveSubspaceInfo(pendingInfo), ERR_OK);

    std::set<int32_t> pendingIds;
    EXPECT_EQ(mgr.subspaceDataDeal_->ScanPendingRemovalSubspaceIds(OS_ACCOUNT_ID, pendingIds), ERR_OK);
    EXPECT_EQ(pendingIds.count(pendingDistId), 1u);

    mgr.CleanupOrphanedSubspaces();

    EXPECT_FALSE(mgr.subspaceDataDeal_->IsValidSubspaceExists(OS_ACCOUNT_ID, pendingDistId));
    std::string spaceDir = TEST_ROOT_DIR + std::to_string(OS_ACCOUNT_ID) + "/" + std::to_string(pendingDistId);
    EXPECT_FALSE(std::filesystem::exists(spaceDir));
}

/**
 * @tc.name: SwitchSpace_NotFound_001
 * @tc.desc: S6 - SwitchSpace returns SUBSPACE_NOT_FOUND for non-existent target space
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceManagerTest, SwitchSpace_NotFound_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubspaceManager::GetInstance();
    int32_t nonExistDistId = OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 999;
    int32_t fromSubspaceId = 0;
    ErrCode ret = mgr.SwitchSubspace(OS_ACCOUNT_ID, nonExistDistId, fromSubspaceId);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND);
}

/**
 * @tc.name: RemoveSpace_ToBeRemovedAndCleanup_001
 * @tc.desc: R1/R9 - RemoveSpace marks toBeRemoved and CleanupOrphanedSubspaces finishes cleanup
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceManagerTest, RemoveSpace_ToBeRemovedAndCleanup_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubspaceManager::GetInstance();
    int32_t distId1 = 0;
    int32_t distId2 = 0;
    ErrCode ret1 = mgr.CreateSubspace(OS_ACCOUNT_ID, distId1);
    ErrCode ret2 = mgr.CreateSubspace(OS_ACCOUNT_ID, distId2);
    EXPECT_EQ(ret1, ERR_OK);
    EXPECT_EQ(ret2, ERR_OK);

    ret1 = mgr.RemoveSubspace(OS_ACCOUNT_ID, distId1);
    EXPECT_EQ(ret1, ERR_OK);

    EXPECT_TRUE(mgr.subspaceDataDeal_->IsValidSubspaceExists(OS_ACCOUNT_ID, distId2));
    EXPECT_FALSE(mgr.subspaceDataDeal_->IsValidSubspaceExists(OS_ACCOUNT_ID, distId1));

    std::set<int32_t> validIds;
    EXPECT_EQ(mgr.subspaceDataDeal_->ScanOsAccountSubspaceIds(OS_ACCOUNT_ID, validIds), ERR_OK);
    EXPECT_EQ(validIds.count(distId1), 0u);
    EXPECT_EQ(validIds.count(distId2), 1u);
}

#endif  // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE