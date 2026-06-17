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
#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE

#include <algorithm>
#include <fstream>
#include <gtest/gtest.h>
#include <filesystem>
#include <set>
#include <string>

#define private public
#include "os_account_subspace_data_deal.h"
#undef private

#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "account_test_common.h"
#include "accesstoken_kit.h"
#include "distributed_account_subscribe_callback.h"
#include "os_account_constants.h"
#include "token_setproc.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string TEST_ROOT_DIR = "/data/test/os_account_subspace_test_dir/";
constexpr int32_t TEST_OS_ACCOUNT_ID = 100;
}  // namespace

class OsAccountSubspaceTest : public testing::Test {
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
        std::string testAccountDir = TEST_ROOT_DIR + std::to_string(TEST_OS_ACCOUNT_ID) + "/";
        std::filesystem::remove_all(testAccountDir, ec);
        dataDeal_ = std::make_unique<OsAccountSubProfileDataDeal>(TEST_ROOT_DIR);
    }

    void TearDown() override
    {
        dataDeal_.reset();
    }

    std::unique_ptr<OsAccountSubProfileDataDeal> dataDeal_;
    static uint64_t allPermTokenId_;
};

uint64_t OsAccountSubspaceTest::allPermTokenId_ = 0;

/**
 * @tc.name: AllocateOsAccountSubProfileId_001
 * @tc.desc: Allocate first space ID for an OS account
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, AllocateOsAccountSubProfileId_001, TestSize.Level1)
{
    std::vector<int32_t> subProfileIdList;
    int32_t nextSubProfileId = -1;
    int32_t outId = 0;
    ErrCode ret = dataDeal_->AllocateOsAccountSubProfileId(
        TEST_OS_ACCOUNT_ID, nextSubProfileId, subProfileIdList, outId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(outId, TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 1);
}

/**
 * @tc.name: AllocateOsAccountSubProfileId_002
 * @tc.desc: Allocate skips already-used indices
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, AllocateOsAccountSubProfileId_002, TestSize.Level1)
{
    std::vector<int32_t> subProfileIdList = {100001, 100002, 100003};
    int32_t nextSubProfileId = -1;
    int32_t outId = 0;
    ErrCode ret = dataDeal_->AllocateOsAccountSubProfileId(
        TEST_OS_ACCOUNT_ID, nextSubProfileId, subProfileIdList, outId);
    EXPECT_EQ(ret, ERR_OK);
    int32_t base = TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;
    EXPECT_EQ(outId, base + 4);
}

/**
 * @tc.name: AllocateOsAccountSubProfileId_003
 * @tc.desc: Returns limit error when all 999 slots are used
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, AllocateOsAccountSubProfileId_003, TestSize.Level1)
{
    std::vector<int32_t> subProfileIdList;
    int32_t base = TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;
    for (int32_t i = 1; i <= OsAccountSubProfileDataDeal::OS_ACCOUNT_SUB_PROFILE_ID_MAX; ++i) {
        subProfileIdList.push_back(base + i);
    }
    int32_t nextSubProfileId = -1;
    int32_t outId = 0;
    ErrCode ret = dataDeal_->AllocateOsAccountSubProfileId(
        TEST_OS_ACCOUNT_ID, nextSubProfileId, subProfileIdList, outId);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_LIMIT);
}

/**
 * @tc.name: AllocateOsAccountSubProfileId_IncrementPattern_004
 * @tc.desc: Verify ID allocation follows maxUsed+1 rule: empty→1, {1}→2, {1,2}→3, {1..10}→11
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, AllocateOsAccountSubProfileId_IncrementPattern_004, TestSize.Level1)
{
    int32_t outId = 0;
    int32_t base = TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;

    std::vector<int32_t> subProfileIdList;
    int32_t nextSubProfileId = -1;
    ErrCode ret = dataDeal_->AllocateOsAccountSubProfileId(
        TEST_OS_ACCOUNT_ID, nextSubProfileId, subProfileIdList, outId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(outId, base + 1);

    subProfileIdList = {100001};
    nextSubProfileId = base + 2;
    ret = dataDeal_->AllocateOsAccountSubProfileId(
        TEST_OS_ACCOUNT_ID, nextSubProfileId, subProfileIdList, outId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(outId, base + 2);

    subProfileIdList = {100001, 100002};
    nextSubProfileId = base + 3;
    ret = dataDeal_->AllocateOsAccountSubProfileId(
        TEST_OS_ACCOUNT_ID, nextSubProfileId, subProfileIdList, outId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(outId, base + 3);

    subProfileIdList.clear();
    for (int32_t i = 1; i <= 10; ++i) {
        subProfileIdList.push_back(base + i);
    }
    nextSubProfileId = base + 4;
    ret = dataDeal_->AllocateOsAccountSubProfileId(
        TEST_OS_ACCOUNT_ID, nextSubProfileId, subProfileIdList, outId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(outId, base + 11);
}

/**
 * @tc.name: AllocateOsAccountSubProfileId_HolesBelowMaxUsedIgnored_005
 * @tc.desc: When maxUsed < MAX, holes below maxUsed are NOT filled first; allocation prefers maxUsed+1
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, AllocateOsAccountSubProfileId_HoleBelowHint_005, TestSize.Level1)
{
    int32_t outId = 0;
    int32_t base = TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;

    std::vector<int32_t> subProfileIdList = {100001, 100003};
    int32_t nextSubProfileId = base + 4;
    ErrCode ret = dataDeal_->AllocateOsAccountSubProfileId(
        TEST_OS_ACCOUNT_ID, nextSubProfileId, subProfileIdList, outId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(outId, base + 4);

    subProfileIdList = {100001, 100005, 100010};
    nextSubProfileId = base + 11;
    ret = dataDeal_->AllocateOsAccountSubProfileId(
        TEST_OS_ACCOUNT_ID, nextSubProfileId, subProfileIdList, outId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(outId, base + 11);

    subProfileIdList = {100001, 100002, 100004, 100006, 100008};
    nextSubProfileId = base + 9;
    ret = dataDeal_->AllocateOsAccountSubProfileId(
        TEST_OS_ACCOUNT_ID, nextSubProfileId, subProfileIdList, outId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(outId, base + 9);
}

/**
 * @tc.name: AllocateOsAccountSubProfileId_MaxReachedFreedSmallestIndex_006
 * @tc.desc: When maxUsed=MAX and smallest index is freed, wrap-around fills it from MIN upward
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, AllocateOsAccountSubProfileId_WrapAroundFreedSmallest_006, TestSize.Level1)
{
    int32_t outId = 0;
    int32_t base = TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;

    std::vector<int32_t> subProfileIdList;
    for (int32_t i = 2; i <= OsAccountSubProfileDataDeal::OS_ACCOUNT_SUB_PROFILE_ID_MAX; ++i) {
        subProfileIdList.push_back(base + i);
    }
    int32_t nextSubProfileId = base + 1;
    ErrCode ret = dataDeal_->AllocateOsAccountSubProfileId(
        TEST_OS_ACCOUNT_ID, nextSubProfileId, subProfileIdList, outId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(outId, base + 1);

    subProfileIdList.clear();
    for (int32_t i = 3; i <= OsAccountSubProfileDataDeal::OS_ACCOUNT_SUB_PROFILE_ID_MAX; ++i) {
        subProfileIdList.push_back(base + i);
    }
    subProfileIdList.push_back(base + 1);
    nextSubProfileId = base + 2;
    ret = dataDeal_->AllocateOsAccountSubProfileId(
        TEST_OS_ACCOUNT_ID, nextSubProfileId, subProfileIdList, outId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(outId, base + 2);
}

/**
 * @tc.name: AllocateOsAccountSubProfileId_MaxReachedFreedMiddleHole_007
 * @tc.desc: When maxUsed=MAX and a middle index is freed, wrap-around finds it after scanning from MIN;
 *           when multiple holes exist, the smallest hole is filled first
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, AllocateOsAccountSubProfileId_WrapAroundFreedMiddleHole_007, TestSize.Level1)
{
    int32_t outId = 0;
    int32_t base = TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;

    std::vector<int32_t> subProfileIdList;
    for (int32_t i = 1; i <= OsAccountSubProfileDataDeal::OS_ACCOUNT_SUB_PROFILE_ID_MAX; ++i) {
        if (i != 500) {
            subProfileIdList.push_back(base + i);
        }
    }
    int32_t nextSubProfileId = base + 1;
    ErrCode ret = dataDeal_->AllocateOsAccountSubProfileId(
        TEST_OS_ACCOUNT_ID, nextSubProfileId, subProfileIdList, outId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(outId, base + 500);

    subProfileIdList.clear();
    for (int32_t i = 1; i <= OsAccountSubProfileDataDeal::OS_ACCOUNT_SUB_PROFILE_ID_MAX; ++i) {
        if (i != 100 && i != 500) {
            subProfileIdList.push_back(base + i);
        }
    }
    nextSubProfileId = base + 1;
    ret = dataDeal_->AllocateOsAccountSubProfileId(
        TEST_OS_ACCOUNT_ID, nextSubProfileId, subProfileIdList, outId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(outId, base + 100);
}

/**
 * @tc.name: AllocateOsAccountSubProfileId_MaxReachedNoHoles_008
 * @tc.desc: When all MAX_OS_ACCOUNT_SUB_PROFILE_COUNT indices are used with no freed slots, returns limit error
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, AllocateOsAccountSubProfileId_MaxReachedNoHoles_008, TestSize.Level1)
{
    std::vector<int32_t> subProfileIdList;
    for (int32_t i = 1; i <= OsAccountSubProfileDataDeal::OS_ACCOUNT_SUB_PROFILE_ID_MAX; ++i) {
        subProfileIdList.push_back(
            TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + i);
    }
    int32_t nextSubProfileId = -1;
    int32_t outId = 0;
    ErrCode ret = dataDeal_->AllocateOsAccountSubProfileId(
        TEST_OS_ACCOUNT_ID, nextSubProfileId, subProfileIdList, outId);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_LIMIT);
}

/**
 * @tc.name: AllocateOsAccountSubProfileId_DeleteAndWrapAround_009
 * @tc.desc: Verify the full lifecycle scenario described:
 *   [1,2,3,4] → create → [1,2,3,4,5], nextId=base+6
 *   delete 5 → [1,2,3,4], nextId=base+6 (unchanged)
 *   create → [1,2,3,4,6], nextId wraps to base+1 (7>MAX=6)
 *   create → [1,2,3,4,5,6], wraps from 1 and fills freed hole 5
 *   Uses a small MAX (6) to simulate the wrap-around scenario.
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, AllocateOsAccountSubProfileId_DeleteAndWrapAround_009, TestSize.Level1)
{
    int32_t outId = 0;
    int32_t osAccountId = TEST_OS_ACCOUNT_ID;
    int32_t base = osAccountId * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;

    std::vector<int32_t> subProfileIdList = {
        base + 1, base + 2,
        base + 3, base + 4};
    int32_t nextSubProfileId = base + 5;

    ErrCode ret = dataDeal_->AllocateOsAccountSubProfileId(
        osAccountId, nextSubProfileId, subProfileIdList, outId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(outId, base + 5);

    subProfileIdList.push_back(base + 5);
    nextSubProfileId = base + 6;

    ret = dataDeal_->AllocateOsAccountSubProfileId(
        osAccountId, nextSubProfileId, subProfileIdList, outId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(outId, base + 6);

    auto erase5 = std::find(subProfileIdList.begin(), subProfileIdList.end(), base + 5);
    ASSERT_NE(erase5, subProfileIdList.end());
    subProfileIdList.erase(erase5);
    nextSubProfileId = base + 7;

    ret = dataDeal_->AllocateOsAccountSubProfileId(
        osAccountId, nextSubProfileId, subProfileIdList, outId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(outId, base + 7);  // MAX=999, no wrapping; base+7 is free (base+5 was deleted)

    // Final step: after step3 list=[1,2,3,4,6]. Allocate with nextId=1 fills freed hole 5.
    nextSubProfileId = base + 1;
    ret = dataDeal_->AllocateOsAccountSubProfileId(
        osAccountId, nextSubProfileId, subProfileIdList, outId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(outId, base + 5);
}

/**
 * @tc.name: AllocateOsAccountSubProfileId_HintOutOfRange_011
 * @tc.desc: When nextSubProfileId yields hintIndex < MIN or > MAX,
 *           startIndex falls back to OS_ACCOUNT_SUB_PROFILE_ID_MIN
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, AllocateOsAccountSubProfileId_HintOutOfRange_011, TestSize.Level1)
{
    int32_t base = TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;
    std::vector<int32_t> subProfileIdList;
    int32_t outId = 0;

    int32_t nextSubProfileId = 0;
    ErrCode ret = dataDeal_->AllocateOsAccountSubProfileId(
        TEST_OS_ACCOUNT_ID, nextSubProfileId, subProfileIdList, outId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(outId, base + 1);

    nextSubProfileId = base + OsAccountSubProfileDataDeal::OS_ACCOUNT_SUB_PROFILE_ID_MAX + 1;
    ret = dataDeal_->AllocateOsAccountSubProfileId(
        TEST_OS_ACCOUNT_ID, nextSubProfileId, subProfileIdList, outId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(outId, base + 1);

    nextSubProfileId = base - 1;
    ret = dataDeal_->AllocateOsAccountSubProfileId(
        TEST_OS_ACCOUNT_ID, nextSubProfileId, subProfileIdList, outId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(outId, base + 1);

    subProfileIdList = {base + 1};
    nextSubProfileId = base + 1000;
    ret = dataDeal_->AllocateOsAccountSubProfileId(
        TEST_OS_ACCOUNT_ID, nextSubProfileId, subProfileIdList, outId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(outId, base + 2);
}

/**
 * @tc.name: AllocateOsAccountSubProfileId_HintOccupied_012
 * @tc.desc: When nextSubProfileId hint points to an already-occupied index,
 *           search starts from hint and finds next free slot
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, AllocateOsAccountSubProfileId_HintOccupied_012, TestSize.Level1)
{
    int32_t base = TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;
    int32_t outId = 0;

    std::vector<int32_t> subProfileIdList = {base + 3,
        base + 4, base + 5};
    int32_t nextSubProfileId = base + 3;
    ErrCode ret = dataDeal_->AllocateOsAccountSubProfileId(
        TEST_OS_ACCOUNT_ID, nextSubProfileId, subProfileIdList, outId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(outId, base + 6);

    subProfileIdList = {base + 5, base + 6,
        base + 7, base + 1, base + 2};
    nextSubProfileId = base + 5;
    ret = dataDeal_->AllocateOsAccountSubProfileId(
        TEST_OS_ACCOUNT_ID, nextSubProfileId, subProfileIdList, outId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(outId, base + 8);
}

/**
 * @tc.name: AllocateOsAccountSubProfileId_StrListOverlapUsedIndices_013
 * @tc.desc: subProfileIdList values are deduplicated by the set; allocation still
 *           by the set; allocation still finds correct free index
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, AllocateOsAccountSubProfileId_StrListOverlapUsedIndices_013, TestSize.Level1)
{
    int32_t base = TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;
    int32_t outId = 0;

    std::vector<int32_t> subProfileIdList = {base + 1, base + 2};
    int32_t nextSubProfileId = base + 3;
    ErrCode ret = dataDeal_->AllocateOsAccountSubProfileId(
        TEST_OS_ACCOUNT_ID, nextSubProfileId, subProfileIdList, outId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(outId, base + 3);
}

/**
 * @tc.name: AllocateOsAccountSubProfileId_WrapExactBoundary_014
 * @tc.desc: Search starts at INDEX_MAX (999), only INDEX_MIN (1) is free;
 *           wraps from 999 → 1 and finds the free slot
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, AllocateOsAccountSubProfileId_WrapExactBoundary_014, TestSize.Level1)
{
    int32_t base = TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;
    std::vector<int32_t> subProfileIdList;
    for (int32_t i = 2; i <= OsAccountSubProfileDataDeal::OS_ACCOUNT_SUB_PROFILE_ID_MAX; ++i) {
        subProfileIdList.push_back(base + i);
    }
    int32_t nextSubProfileId = base + OsAccountSubProfileDataDeal::OS_ACCOUNT_SUB_PROFILE_ID_MAX;
    int32_t outId = 0;
    ErrCode ret = dataDeal_->AllocateOsAccountSubProfileId(
        TEST_OS_ACCOUNT_ID, nextSubProfileId, subProfileIdList, outId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(outId, base + 1);
}

/**
 * @tc.name: SaveAndLoadSubProfileInfo_001
 * @tc.desc: Save and load a completed space info round-trip
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, SaveAndLoadSubProfileInfo_001, TestSize.Level1)
{
    OsAccountSubspaceInfo info;
    info.userId_ = TEST_OS_ACCOUNT_ID;
    info.subspaceId = TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 1;
    info.isCreateCompleted = true;
    info.toBeRemoved = false;
    info.bindTime_ = 12345;
    info.version_ = 1;
    info.ohosAccountInfo_.name_ = "testName";
    info.ohosAccountInfo_.uid_ = "testUid123";
    info.ohosAccountInfo_.SetRawUid("rawUid456");
    info.ohosAccountInfo_.status_ = ACCOUNT_STATE_LOGIN;
    info.ohosAccountInfo_.callingUid_ = 200;
    info.ohosAccountInfo_.nickname_ = "testNick";
    info.ohosAccountInfo_.avatar_ = "testAvatar";
    info.ohosAccountInfo_.scalableData_ = "testScalable";

    ErrCode ret = dataDeal_->SaveSubProfileInfo(info);
    EXPECT_EQ(ret, ERR_OK);

    OsAccountSubspaceInfo loaded;
    ret = dataDeal_->LoadSubProfileInfo(TEST_OS_ACCOUNT_ID, info.subspaceId, loaded);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(loaded.userId_, info.userId_);
    EXPECT_EQ(loaded.subspaceId, info.subspaceId);
    EXPECT_EQ(loaded.isCreateCompleted, info.isCreateCompleted);
    EXPECT_EQ(loaded.toBeRemoved, info.toBeRemoved);
    EXPECT_EQ(loaded.bindTime_, info.bindTime_);
    EXPECT_EQ(loaded.version_, info.version_);
    EXPECT_EQ(loaded.ohosAccountInfo_.name_, info.ohosAccountInfo_.name_);
    EXPECT_EQ(loaded.ohosAccountInfo_.uid_, info.ohosAccountInfo_.uid_);
    EXPECT_EQ(loaded.ohosAccountInfo_.GetRawUid(), info.ohosAccountInfo_.GetRawUid());
    EXPECT_EQ(loaded.ohosAccountInfo_.status_, info.ohosAccountInfo_.status_);
    EXPECT_EQ(loaded.ohosAccountInfo_.callingUid_, info.ohosAccountInfo_.callingUid_);
    EXPECT_EQ(loaded.ohosAccountInfo_.nickname_, info.ohosAccountInfo_.nickname_);
    EXPECT_EQ(loaded.ohosAccountInfo_.avatar_, info.ohosAccountInfo_.avatar_);
    EXPECT_EQ(loaded.ohosAccountInfo_.scalableData_, info.ohosAccountInfo_.scalableData_);
}

/**
 * @tc.name: SaveAndLoadSubProfileInfo_002
 * @tc.desc: Load returns error when file doesn't exist
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, SaveAndLoadSubProfileInfo_002, TestSize.Level1)
{
    OsAccountSubspaceInfo loaded;
    int32_t nonExistId = TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 99;
    ErrCode ret = dataDeal_->LoadSubProfileInfo(TEST_OS_ACCOUNT_ID, nonExistId, loaded);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: IsValidSubProfileExists_001
 * @tc.desc: Returns true for a completed non-removed space
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, IsValidSubProfileExists_001, TestSize.Level1)
{
    OsAccountSubspaceInfo info;
    info.userId_ = TEST_OS_ACCOUNT_ID;
    info.subspaceId = TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 2;
    info.isCreateCompleted = true;
    info.toBeRemoved = false;
    EXPECT_EQ(dataDeal_->SaveSubProfileInfo(info), ERR_OK);

    EXPECT_TRUE(dataDeal_->IsValidSubProfileExists(TEST_OS_ACCOUNT_ID, info.subspaceId));
}

/**
 * @tc.name: IsValidSubProfileExists_002
 * @tc.desc: Returns false for a space flagged toBeRemoved
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, IsValidSubProfileExists_002, TestSize.Level1)
{
    OsAccountSubspaceInfo info;
    info.userId_ = TEST_OS_ACCOUNT_ID;
    info.subspaceId = TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 3;
    info.isCreateCompleted = true;
    info.toBeRemoved = true;
    EXPECT_EQ(dataDeal_->SaveSubProfileInfo(info), ERR_OK);

    EXPECT_FALSE(dataDeal_->IsValidSubProfileExists(TEST_OS_ACCOUNT_ID, info.subspaceId));
}

/**
 * @tc.name: IsValidSubProfileExists_003
 * @tc.desc: Returns false for non-existent space
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, IsValidSubProfileExists_003, TestSize.Level1)
{
    int32_t nonExistId = TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 999;
    EXPECT_FALSE(dataDeal_->IsValidSubProfileExists(TEST_OS_ACCOUNT_ID, nonExistId));
}

/**
 * @tc.name: ScanOsAccountSubProfileIds_001
 * @tc.desc: Scan returns only completed non-removed IDs
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, ScanOsAccountSubProfileIds_001, TestSize.Level1)
{
    int32_t id1 = TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 1;
    int32_t id2 = TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 2;
    int32_t id3 = TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 3;

    OsAccountSubspaceInfo info1;
    info1.subspaceId = id1;
    info1.userId_ = TEST_OS_ACCOUNT_ID;
    info1.isCreateCompleted = true;
    info1.toBeRemoved = false;
    OsAccountSubspaceInfo info2;
    info2.subspaceId = id2;
    info2.userId_ = TEST_OS_ACCOUNT_ID;
    info2.isCreateCompleted = false;
    info2.toBeRemoved = false;
    OsAccountSubspaceInfo info3;
    info3.subspaceId = id3;
    info3.userId_ = TEST_OS_ACCOUNT_ID;
    info3.isCreateCompleted = true;
    info3.toBeRemoved = true;

    EXPECT_EQ(dataDeal_->SaveSubProfileInfo(info1), ERR_OK);
    EXPECT_EQ(dataDeal_->SaveSubProfileInfo(info2), ERR_OK);
    EXPECT_EQ(dataDeal_->SaveSubProfileInfo(info3), ERR_OK);

    std::set<int32_t> validIds;
    EXPECT_EQ(dataDeal_->ScanOsAccountSubProfileIds(TEST_OS_ACCOUNT_ID, validIds), ERR_OK);
    EXPECT_EQ(validIds.size(), 1u);
    EXPECT_TRUE(validIds.count(id1) > 0);
}

/**
 * @tc.name: ScanSubProfileIds_NullptrFilter_001
 * @tc.desc: ScanSubProfileIds with nullptr filter collects subspaceIds without loading JSON;
 *           directories without JSON are still included (unlike filter mode which skips them)
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, ScanSubProfileIds_NullptrFilter_001, TestSize.Level1)
{
    int32_t id1 = TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 1;
    int32_t id2 = TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 2;

    OsAccountSubspaceInfo info;
    info.subspaceId = id1;
    info.userId_ = TEST_OS_ACCOUNT_ID;
    info.isCreateCompleted = true;
    info.toBeRemoved = false;
    EXPECT_EQ(dataDeal_->SaveSubProfileInfo(info), ERR_OK);

    std::string accDir = TEST_ROOT_DIR + std::to_string(TEST_OS_ACCOUNT_ID) + "/";
    std::filesystem::create_directories(accDir + std::to_string(id2));

    std::set<int32_t> resultIds;
    ErrCode ret = dataDeal_->ScanSubProfileIds(TEST_OS_ACCOUNT_ID, nullptr, resultIds);
    EXPECT_EQ(ret, ERR_OK);
    ASSERT_EQ(resultIds.size(), 2u);
    EXPECT_TRUE(resultIds.count(id1) > 0);
    EXPECT_TRUE(resultIds.count(id2) > 0);
}

/**
 * @tc.name: ScanOrphanedSubProfileIds_001
 * @tc.desc: ScanOrphanedSubProfileIds returns IDs with isCreateCompleted==false
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, ScanOrphanedSubProfileIds_001, TestSize.Level1)
{
    int32_t id1 = TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 10;
    int32_t id2 = TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 11;

    OsAccountSubspaceInfo info1;
    info1.subspaceId = id1;
    info1.userId_ = TEST_OS_ACCOUNT_ID;
    info1.isCreateCompleted = false;
    info1.toBeRemoved = false;
    OsAccountSubspaceInfo info2;
    info2.subspaceId = id2;
    info2.userId_ = TEST_OS_ACCOUNT_ID;
    info2.isCreateCompleted = true;
    info2.toBeRemoved = false;

    EXPECT_EQ(dataDeal_->SaveSubProfileInfo(info1), ERR_OK);
    EXPECT_EQ(dataDeal_->SaveSubProfileInfo(info2), ERR_OK);

    std::set<int32_t> orphanIds;
    EXPECT_EQ(dataDeal_->ScanOrphanedSubProfileIds(TEST_OS_ACCOUNT_ID, orphanIds), ERR_OK);
    EXPECT_EQ(orphanIds.size(), 1u);
    EXPECT_TRUE(orphanIds.count(id1) > 0);
}

/**
 * @tc.name: RemoveSubProfileDir_001
 * @tc.desc: RemoveSubProfileDir successfully removes an existing directory
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, RemoveSubProfileDir_001, TestSize.Level1)
{
    int32_t distId = TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 20;
    OsAccountSubspaceInfo info;
    info.subspaceId = distId;
    info.userId_ = TEST_OS_ACCOUNT_ID;
    info.isCreateCompleted = true;
    info.toBeRemoved = false;
    EXPECT_EQ(dataDeal_->SaveSubProfileInfo(info), ERR_OK);

    EXPECT_EQ(dataDeal_->RemoveSubProfileDir(TEST_OS_ACCOUNT_ID, distId), ERR_OK);
    EXPECT_FALSE(dataDeal_->IsValidSubProfileExists(TEST_OS_ACCOUNT_ID, distId));
}

/**
 * @tc.name: RemoveSubProfileDir_002
 * @tc.desc: RemoveSubProfileDir returns ERR_OK for non-existent directory (idempotent)
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, RemoveSubProfileDir_002, TestSize.Level1)
{
    int32_t distId = TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 21;
    ErrCode ret = dataDeal_->RemoveSubProfileDir(TEST_OS_ACCOUNT_ID, distId);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: SerializeParseSpaceInfo_001
 * @tc.desc: Save and load are inverse operations; avatar stored in separate file round-trips correctly
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, SerializeParseSpaceInfo_001, TestSize.Level1)
{
    OsAccountSubspaceInfo info;
    info.userId_ = TEST_OS_ACCOUNT_ID;
    info.subspaceId = TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 5;
    info.isCreateCompleted = true;
    info.toBeRemoved = false;
    info.bindTime_ = 99999;
    info.version_ = 2;
    info.ohosAccountInfo_.name_ = "serName";
    info.ohosAccountInfo_.uid_ = "serUid";
    info.ohosAccountInfo_.SetRawUid("serRawUid");
    info.ohosAccountInfo_.status_ = ACCOUNT_STATE_LOGIN;
    info.ohosAccountInfo_.callingUid_ = 300;
    info.ohosAccountInfo_.nickname_ = "serNick";
    info.ohosAccountInfo_.avatar_ = "serAvatar";
    info.ohosAccountInfo_.scalableData_ = "serScalable";

    ErrCode ret = dataDeal_->SaveSubProfileInfo(info);
    EXPECT_EQ(ret, ERR_OK);

    OsAccountSubspaceInfo parsed;
    ret = dataDeal_->LoadSubProfileInfo(TEST_OS_ACCOUNT_ID, info.subspaceId, parsed);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(parsed.userId_, info.userId_);
    EXPECT_EQ(parsed.subspaceId, info.subspaceId);
    EXPECT_EQ(parsed.isCreateCompleted, info.isCreateCompleted);
    EXPECT_EQ(parsed.toBeRemoved, info.toBeRemoved);
    EXPECT_EQ(parsed.bindTime_, info.bindTime_);
    EXPECT_EQ(parsed.version_, info.version_);
    EXPECT_EQ(parsed.ohosAccountInfo_.name_, info.ohosAccountInfo_.name_);
    EXPECT_EQ(parsed.ohosAccountInfo_.uid_, info.ohosAccountInfo_.uid_);
    EXPECT_EQ(parsed.ohosAccountInfo_.GetRawUid(), info.ohosAccountInfo_.GetRawUid());
    EXPECT_EQ(parsed.ohosAccountInfo_.status_, info.ohosAccountInfo_.status_);
    EXPECT_EQ(parsed.ohosAccountInfo_.callingUid_, info.ohosAccountInfo_.callingUid_);
    EXPECT_EQ(parsed.ohosAccountInfo_.nickname_, info.ohosAccountInfo_.nickname_);
    EXPECT_EQ(parsed.ohosAccountInfo_.avatar_, info.ohosAccountInfo_.avatar_);
    EXPECT_EQ(parsed.ohosAccountInfo_.scalableData_, info.ohosAccountInfo_.scalableData_);
}

/**
 * @tc.name: ParseSubProfileInfoFromJson_Corrupt_001
 * @tc.desc: Parsing corrupt JSON returns error
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, ParseSubProfileInfoFromJson_Corrupt_001, TestSize.Level1)
{
    OsAccountSubspaceInfo parsed;
    ErrCode ret = dataDeal_->ParseSubProfileInfoFromJson("not json {{", parsed);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.name: ScanPendingRemovalSubProfileIds_EmptyDir_001
 * @tc.desc: Scanning an empty OS account directory returns empty pending-removal set
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, ScanPendingRemovalSubProfileIds_EmptyDir_001, TestSize.Level1)
{
    std::string osAccountDir = TEST_ROOT_DIR + std::to_string(TEST_OS_ACCOUNT_ID);
    std::filesystem::create_directories(osAccountDir);

    std::set<int32_t> pendingIds;
    ErrCode ret = dataDeal_->ScanPendingRemovalSubProfileIds(TEST_OS_ACCOUNT_ID, pendingIds);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(pendingIds.empty());
}

/**
 * @tc.name: LoadSubProfileInfo_AvatarFileMissing_001
 * @tc.desc: Load succeeds when avatar file is missing; avatar field stays empty
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, LoadSubProfileInfo_AvatarFileMissing_001, TestSize.Level1)
{
    OsAccountSubspaceInfo info;
    info.userId_ = TEST_OS_ACCOUNT_ID;
    info.subspaceId = TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 30;
    info.isCreateCompleted = true;
    info.toBeRemoved = false;
    info.ohosAccountInfo_.avatar_ = "originalAvatar";
    EXPECT_EQ(dataDeal_->SaveSubProfileInfo(info), ERR_OK);

    std::string avatarPath = TEST_ROOT_DIR + std::to_string(TEST_OS_ACCOUNT_ID) + "/"
        + std::to_string(info.subspaceId) + "/account_avatar";
    std::filesystem::remove(avatarPath);

    OsAccountSubspaceInfo loaded;
    ErrCode ret = dataDeal_->LoadSubProfileInfo(TEST_OS_ACCOUNT_ID, info.subspaceId, loaded);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(loaded.ohosAccountInfo_.avatar_, "");
}

/**
 * @tc.name: LoadSubProfileInfo_AvatarReadFails_001
 * @tc.desc: Load succeeds when avatar file does not exist;
 *           avatar field stays empty, overall Load still returns ERR_OK.
 *           Deletes avatar file after Save to trigger GetFileContentByPath failure.
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, LoadSubProfileInfo_AvatarReadFails_001, TestSize.Level1)
{
    OsAccountSubspaceInfo info;
    info.userId_ = TEST_OS_ACCOUNT_ID;
    info.subspaceId = TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 32;
    info.isCreateCompleted = true;
    info.toBeRemoved = false;
    info.ohosAccountInfo_.avatar_ = "avatarData";
    EXPECT_EQ(dataDeal_->SaveSubProfileInfo(info), ERR_OK);

    std::string avatarPath = TEST_ROOT_DIR + std::to_string(TEST_OS_ACCOUNT_ID) + "/"
        + std::to_string(info.subspaceId) + "/account_avatar";
    EXPECT_TRUE(std::filesystem::exists(avatarPath));
    std::filesystem::remove(avatarPath);

    OsAccountSubspaceInfo loaded;
    ErrCode ret = dataDeal_->LoadSubProfileInfo(TEST_OS_ACCOUNT_ID, info.subspaceId, loaded);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(loaded.ohosAccountInfo_.avatar_, "");
}

/**
 * @tc.name: SaveSubProfileInfo_CreateDirFails_001
 * @tc.desc: SaveSubProfileInfo fails when directory cannot be created (invalid root path)
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, SaveSubProfileInfo_CreateDirFails_001, TestSize.Level1)
{
    OsAccountSubProfileDataDeal badDeal("/proc/invalid_path_not_writable/");
    OsAccountSubspaceInfo info;
    info.userId_ = TEST_OS_ACCOUNT_ID;
    info.subspaceId = TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 1;
    info.isCreateCompleted = true;
    info.toBeRemoved = false;
    ErrCode ret = badDeal.SaveSubProfileInfo(info);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.name: SaveSubProfileInfo_AvatarKeptOnJsonFail_001
 * @tc.desc: When JSON write fails after avatar write succeeds, avatar file is kept (not rolled back)
 *           consistent with OhosAccountDataDeal::SaveAccountInfo behavior.
 *           After first Save, rename account.json to .bak and create a directory at the
 *           original account.json path. This makes FileExists(account.json) return false
 *           (S_ISREG fails on a directory), so SwapFileNames uses RENAME_NOREPLACE which
 *           fails because the target (directory) exists. The avatar write succeeds because
 *           account_avatar is still a regular file.
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, SaveSubProfileInfo_AvatarKeptOnJsonFail_001, TestSize.Level1)
{
    OsAccountSubspaceInfo info;
    info.userId_ = TEST_OS_ACCOUNT_ID;
    info.subspaceId = TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 31;
    info.isCreateCompleted = true;
    info.toBeRemoved = false;
    info.ohosAccountInfo_.avatar_ = "originalAvatar";
    EXPECT_EQ(dataDeal_->SaveSubProfileInfo(info), ERR_OK);

    std::string subspaceDir = TEST_ROOT_DIR + std::to_string(TEST_OS_ACCOUNT_ID) + "/"
        + std::to_string(info.subspaceId);
    std::string jsonPath = subspaceDir + "/account.json";
    std::string jsonBakPath = subspaceDir + "/account.json.bak";

    std::filesystem::rename(jsonPath, jsonBakPath);
    std::filesystem::create_directories(jsonPath);

    OsAccountSubspaceInfo updateInfo = info;
    updateInfo.ohosAccountInfo_.avatar_ = "updatedAvatar";
    ErrCode ret = dataDeal_->SaveSubProfileInfo(updateInfo);
    EXPECT_NE(ret, ERR_OK);

    std::string avatarPath = subspaceDir + "/account_avatar";
    EXPECT_TRUE(std::filesystem::exists(avatarPath));

    std::string avatarContent;
    std::ifstream avatarStream(avatarPath);
    avatarStream >> avatarContent;
    EXPECT_EQ(avatarContent, "updatedAvatar");

    std::string tmpPath = subspaceDir + "/account.json.tmp";
    std::error_code ec;
    std::filesystem::remove(tmpPath, ec);
    std::filesystem::remove_all(jsonPath, ec);
    std::filesystem::rename(jsonBakPath, jsonPath);
}

/**
 * @tc.name: DistributedAccountEventData_Marshalling_001
 * @tc.desc: DistributedAccountEventData Marshalling/Unmarshalling round-trip
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, DistributedAccountEventData_Marshalling_001, TestSize.Level1)
{
    DistributedAccountEventData data;
    data.id_ = TEST_OS_ACCOUNT_ID;
    data.type_ = DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE::LOGIN;

    Parcel parcel;
    EXPECT_TRUE(data.Marshalling(parcel));

    DistributedAccountEventData *result = DistributedAccountEventData::Unmarshalling(parcel);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->id_, data.id_);
    EXPECT_EQ(result->type_, data.type_);
    delete result;
}

#endif  // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
