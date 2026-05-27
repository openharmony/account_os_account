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
const std::string TEST_ROOT_DIR = "/data/test/os_account_subspace_test/";
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
        dataDeal_ = std::make_unique<OsAccountSubspaceDataDeal>(TEST_ROOT_DIR);
    }

    void TearDown() override
    {
        dataDeal_.reset();
    }

    std::unique_ptr<OsAccountSubspaceDataDeal> dataDeal_;
    static uint64_t allPermTokenId_;
};

uint64_t OsAccountSubspaceTest::allPermTokenId_ = 0;

/**
 * @tc.name: AllocateOsAccountSubspaceId_001
 * @tc.desc: Allocate first space ID for an OS account
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, AllocateOsAccountSubspaceId_001, TestSize.Level1)
{
    std::set<int32_t> usedIndices;
    int32_t outId = 0;
    ErrCode ret = dataDeal_->AllocateOsAccountSubspaceId(TEST_OS_ACCOUNT_ID, usedIndices, outId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(outId, TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 1);
}

/**
 * @tc.name: AllocateOsAccountSubspaceId_002
 * @tc.desc: Allocate skips already-used indices
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, AllocateOsAccountSubspaceId_002, TestSize.Level1)
{
    std::set<int32_t> usedIndices = {1, 2, 3};
    int32_t outId = 0;
    ErrCode ret = dataDeal_->AllocateOsAccountSubspaceId(TEST_OS_ACCOUNT_ID, usedIndices, outId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(outId, TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 4);
}

/**
 * @tc.name: AllocateOsAccountSubspaceId_003
 * @tc.desc: Returns limit error when all 999 slots are used
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, AllocateOsAccountSubspaceId_003, TestSize.Level1)
{
    std::set<int32_t> usedIndices;
    for (int32_t i = OsAccountSubspaceDataDeal::OS_ACCOUNT_SUBSPACE_INDEX_MIN;
         i <= OsAccountSubspaceDataDeal::OS_ACCOUNT_SUBSPACE_INDEX_MAX; ++i) {
        usedIndices.insert(i);
    }
    int32_t outId = 0;
    ErrCode ret = dataDeal_->AllocateOsAccountSubspaceId(TEST_OS_ACCOUNT_ID, usedIndices, outId);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_LIMIT);
}

/**
 * @tc.name: SaveAndLoadSubspaceInfo_001
 * @tc.desc: Save and load a completed space info round-trip
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, SaveAndLoadSubspaceInfo_001, TestSize.Level1)
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

    ErrCode ret = dataDeal_->SaveSubspaceInfo(info);
    EXPECT_EQ(ret, ERR_OK);

    OsAccountSubspaceInfo loaded;
    ret = dataDeal_->LoadSubspaceInfo(TEST_OS_ACCOUNT_ID, info.subspaceId, loaded);
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
 * @tc.name: SaveAndLoadSubspaceInfo_002
 * @tc.desc: Load returns error when file doesn't exist
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, SaveAndLoadSubspaceInfo_002, TestSize.Level1)
{
    OsAccountSubspaceInfo loaded;
    int32_t nonExistId = TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 99;
    ErrCode ret = dataDeal_->LoadSubspaceInfo(TEST_OS_ACCOUNT_ID, nonExistId, loaded);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

/**
 * @tc.name: IsValidSubspaceExists_001
 * @tc.desc: Returns true for a completed non-removed space
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, IsValidSubspaceExists_001, TestSize.Level1)
{
    OsAccountSubspaceInfo info;
    info.userId_ = TEST_OS_ACCOUNT_ID;
    info.subspaceId = TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 2;
    info.isCreateCompleted = true;
    info.toBeRemoved = false;
    EXPECT_EQ(dataDeal_->SaveSubspaceInfo(info), ERR_OK);

    EXPECT_TRUE(dataDeal_->IsValidSubspaceExists(TEST_OS_ACCOUNT_ID, info.subspaceId));
}

/**
 * @tc.name: IsValidSubspaceExists_002
 * @tc.desc: Returns false for a space flagged toBeRemoved
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, IsValidSubspaceExists_002, TestSize.Level1)
{
    OsAccountSubspaceInfo info;
    info.userId_ = TEST_OS_ACCOUNT_ID;
    info.subspaceId = TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 3;
    info.isCreateCompleted = true;
    info.toBeRemoved = true;
    EXPECT_EQ(dataDeal_->SaveSubspaceInfo(info), ERR_OK);

    EXPECT_FALSE(dataDeal_->IsValidSubspaceExists(TEST_OS_ACCOUNT_ID, info.subspaceId));
}

/**
 * @tc.name: IsValidSubspaceExists_003
 * @tc.desc: Returns false for non-existent space
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, IsValidSubspaceExists_003, TestSize.Level1)
{
    int32_t nonExistId = TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 999;
    EXPECT_FALSE(dataDeal_->IsValidSubspaceExists(TEST_OS_ACCOUNT_ID, nonExistId));
}

/**
 * @tc.name: ScanOsAccountSubspaceIds_001
 * @tc.desc: Scan returns only completed non-removed IDs
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, ScanOsAccountSubspaceIds_001, TestSize.Level1)
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

    EXPECT_EQ(dataDeal_->SaveSubspaceInfo(info1), ERR_OK);
    EXPECT_EQ(dataDeal_->SaveSubspaceInfo(info2), ERR_OK);
    EXPECT_EQ(dataDeal_->SaveSubspaceInfo(info3), ERR_OK);

    std::set<int32_t> validIds;
    EXPECT_EQ(dataDeal_->ScanOsAccountSubspaceIds(TEST_OS_ACCOUNT_ID, validIds), ERR_OK);
    EXPECT_EQ(validIds.size(), 1u);
    EXPECT_TRUE(validIds.count(id1) > 0);
}

/**
 * @tc.name: ScanOrphanedSubspaceIds_001
 * @tc.desc: ScanOrphanedSubspaceIds returns IDs with isCreateCompleted==false
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, ScanOrphanedSubspaceIds_001, TestSize.Level1)
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

    EXPECT_EQ(dataDeal_->SaveSubspaceInfo(info1), ERR_OK);
    EXPECT_EQ(dataDeal_->SaveSubspaceInfo(info2), ERR_OK);

    std::set<int32_t> orphanIds;
    EXPECT_EQ(dataDeal_->ScanOrphanedSubspaceIds(TEST_OS_ACCOUNT_ID, orphanIds), ERR_OK);
    EXPECT_EQ(orphanIds.size(), 1u);
    EXPECT_TRUE(orphanIds.count(id1) > 0);
}

/**
 * @tc.name: RemoveSubspaceDir_001
 * @tc.desc: RemoveSubspaceDir successfully removes an existing directory
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, RemoveSubspaceDir_001, TestSize.Level1)
{
    int32_t distId = TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 20;
    OsAccountSubspaceInfo info;
    info.subspaceId = distId;
    info.userId_ = TEST_OS_ACCOUNT_ID;
    info.isCreateCompleted = true;
    info.toBeRemoved = false;
    EXPECT_EQ(dataDeal_->SaveSubspaceInfo(info), ERR_OK);

    EXPECT_EQ(dataDeal_->RemoveSubspaceDir(TEST_OS_ACCOUNT_ID, distId), ERR_OK);
    EXPECT_FALSE(dataDeal_->IsValidSubspaceExists(TEST_OS_ACCOUNT_ID, distId));
}

/**
 * @tc.name: RemoveSubspaceDir_002
 * @tc.desc: RemoveSubspaceDir returns ERR_OK for non-existent directory (idempotent)
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, RemoveSubspaceDir_002, TestSize.Level1)
{
    int32_t distId = TEST_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 21;
    ErrCode ret = dataDeal_->RemoveSubspaceDir(TEST_OS_ACCOUNT_ID, distId);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: SerializeParseSpaceInfo_001
 * @tc.desc: Serialize and parse are inverse operations; ohosAccountInfo defaults preserved
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

    std::string json = dataDeal_->SerializeSubspaceInfoToJson(info);
    EXPECT_FALSE(json.empty());

    OsAccountSubspaceInfo parsed;
    ErrCode ret = dataDeal_->ParseSubspaceInfoFromJson(json, parsed);
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
 * @tc.name: ParseSubspaceInfoFromJson_Corrupt_001
 * @tc.desc: Parsing corrupt JSON returns error
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, ParseSubspaceInfoFromJson_Corrupt_001, TestSize.Level1)
{
    OsAccountSubspaceInfo parsed;
    ErrCode ret = dataDeal_->ParseSubspaceInfoFromJson("not json {{", parsed);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.name: ScanPendingRemovalSubspaceIds_EmptyDir_001
 * @tc.desc: Scanning an empty OS account directory returns empty pending-removal set
 * @tc.type: FUNC
 */
HWTEST_F(OsAccountSubspaceTest, ScanPendingRemovalSubspaceIds_EmptyDir_001, TestSize.Level1)
{
    std::string osAccountDir = TEST_ROOT_DIR + std::to_string(TEST_OS_ACCOUNT_ID);
    std::filesystem::create_directories(osAccountDir);

    std::set<int32_t> pendingIds;
    ErrCode ret = dataDeal_->ScanPendingRemovalSubspaceIds(TEST_OS_ACCOUNT_ID, pendingIds);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(pendingIds.empty());
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
