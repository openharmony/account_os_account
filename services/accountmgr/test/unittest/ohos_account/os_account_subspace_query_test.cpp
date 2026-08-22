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
#include "ohos_account_data_deal.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

// ===== ScanSubProfileIds branch coverage =====
class ScanSubProfileIdsTest : public testing::Test {
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
        std::filesystem::remove_all(SCAN_TEST_DIR, ec);
        std::filesystem::create_directories(SCAN_TEST_DIR);
    }

    void TearDown() override
    {
        std::error_code ec;
        std::filesystem::remove_all(SCAN_TEST_DIR, ec);
    }

    bool CreateFile(const std::string &name)
    {
        std::string path = SCAN_USER_DIR + "/" + name;
        std::ofstream ofs(path);
        return ofs.good();
    }

    bool CreateDir(const std::string &name)
    {
        std::error_code ec;
        std::string path = SCAN_USER_DIR + "/" + name;
        return std::filesystem::create_directory(path, ec);
    }

    bool CreateValidJson(int32_t subspaceId)
    {
        std::string dirPath = SCAN_USER_DIR + "/" + std::to_string(subspaceId);
        std::error_code ec;
        std::filesystem::create_directory(dirPath, ec);
        std::string jsonPath = dirPath + "/account.json";
        std::ofstream ofs(jsonPath);
        if (!ofs) {
            return false;
        }
        ofs << R"({"version":1,"subspaceId":)" << subspaceId
            << R"(,"isCreateCompleted":true,"toBeRemoved":false,)"
            << R"("user_id":)" << SCAN_OS_ACCOUNT_ID
            << R"(,"bind_time":0,"account_name":"test",)"
            << R"("raw_uid":"test","open_id":"test","bind_status":1})";
        return true;
    }

    static const std::string SCAN_TEST_DIR;
    static const std::string SCAN_USER_DIR;
    static constexpr int32_t SCAN_OS_ACCOUNT_ID = 200;
    static constexpr int32_t SCAN_BASE = SCAN_OS_ACCOUNT_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;
    static uint64_t allPermTokenId_;
};

const std::string ScanSubProfileIdsTest::SCAN_TEST_DIR =
    "/data/test/os_account_scan_subspace_test/";
const std::string ScanSubProfileIdsTest::SCAN_USER_DIR =
    ScanSubProfileIdsTest::SCAN_TEST_DIR + std::to_string(ScanSubProfileIdsTest::SCAN_OS_ACCOUNT_ID);

uint64_t ScanSubProfileIdsTest::allPermTokenId_ = 0;

HWTEST_F(ScanSubProfileIdsTest, AllContinueBranches_001, TestSize.Level1)
{
    std::filesystem::create_directories(SCAN_USER_DIR);
    ASSERT_TRUE(CreateFile("somefile.txt"));
    ASSERT_TRUE(CreateDir("abc"));
    int32_t baseDirId = SCAN_BASE;
    ASSERT_TRUE(CreateDir(std::to_string(baseDirId)));
    ASSERT_TRUE(CreateDir(std::to_string(SCAN_BASE + 1)));

    OsAccountSubProfileDataDeal dataDeal(SCAN_TEST_DIR);
    std::set<int32_t> resultIds;
    auto alwaysTrue = [](const OsAccountSubspaceInfo &) { return true; };
    ErrCode ret = dataDeal.ScanSubProfileIds(SCAN_OS_ACCOUNT_ID, alwaysTrue, resultIds);

    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(resultIds.empty());
}

HWTEST_F(ScanSubProfileIdsTest, NullptrFilter_001, TestSize.Level1)
{
    std::filesystem::create_directories(SCAN_USER_DIR);
    ASSERT_TRUE(CreateDir(std::to_string(SCAN_BASE)));
    ASSERT_TRUE(CreateDir(std::to_string(SCAN_BASE + 1)));
    ASSERT_TRUE(CreateDir(std::to_string(SCAN_BASE + 2)));

    OsAccountSubProfileDataDeal dataDeal(SCAN_TEST_DIR);
    std::set<int32_t> resultIds;
    ErrCode ret = dataDeal.ScanSubProfileIds(SCAN_OS_ACCOUNT_ID, nullptr, resultIds);

    EXPECT_EQ(ret, ERR_OK);
    ASSERT_EQ(resultIds.size(), 3u);
    EXPECT_TRUE(resultIds.count(SCAN_BASE) > 0);
    EXPECT_TRUE(resultIds.count(SCAN_BASE + 1) > 0);
    EXPECT_TRUE(resultIds.count(SCAN_BASE + 2) > 0);
}

HWTEST_F(ScanSubProfileIdsTest, FilterFalse_Continue_001, TestSize.Level1)
{
    std::filesystem::create_directories(SCAN_USER_DIR);
    ASSERT_TRUE(CreateValidJson(SCAN_BASE + 1));

    OsAccountSubProfileDataDeal dataDeal(SCAN_TEST_DIR);
    std::set<int32_t> resultIds;
    auto alwaysFalse = [](const OsAccountSubspaceInfo &) { return false; };
    ErrCode ret = dataDeal.ScanSubProfileIds(SCAN_OS_ACCOUNT_ID, alwaysFalse, resultIds);

    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(resultIds.empty());
}

HWTEST_F(ScanSubProfileIdsTest, Success_001, TestSize.Level1)
{
    std::filesystem::create_directories(SCAN_USER_DIR);
    ASSERT_TRUE(CreateValidJson(SCAN_BASE + 1));

    OsAccountSubProfileDataDeal dataDeal(SCAN_TEST_DIR);
    std::set<int32_t> resultIds;
    auto alwaysTrue = [](const OsAccountSubspaceInfo &) { return true; };
    ErrCode ret = dataDeal.ScanSubProfileIds(SCAN_OS_ACCOUNT_ID, alwaysTrue, resultIds);

    EXPECT_EQ(ret, ERR_OK);
    ASSERT_EQ(resultIds.size(), 1u);
    EXPECT_EQ(*resultIds.begin(), SCAN_BASE + 1);
}

HWTEST_F(ScanSubProfileIdsTest, StrtolError_Return_001, TestSize.Level1)
{
    std::filesystem::create_directories(SCAN_USER_DIR);
    ASSERT_TRUE(CreateDir("3000000000"));

    OsAccountSubProfileDataDeal dataDeal(SCAN_TEST_DIR);
    std::set<int32_t> resultIds;
    auto alwaysTrue = [](const OsAccountSubspaceInfo &) { return true; };
    ErrCode ret = dataDeal.ScanSubProfileIds(SCAN_OS_ACCOUNT_ID, alwaysTrue, resultIds);

    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(resultIds.empty());
}

HWTEST_F(ScanSubProfileIdsTest, DirNotFound_Return_001, TestSize.Level1)
{
    OsAccountSubProfileDataDeal dataDeal(SCAN_TEST_DIR);
    std::set<int32_t> resultIds;
    auto alwaysTrue = [](const OsAccountSubspaceInfo &) { return true; };
    ErrCode ret = dataDeal.ScanSubProfileIds(SCAN_OS_ACCOUNT_ID, alwaysTrue, resultIds);

    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(resultIds.empty());
}

// ===== Task 10: OsAccountSubProfileManager query methods =====
class SubProfileQuerySubspaceMgrTest : public testing::Test {
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
        std::filesystem::remove_all(QUERY_TEST_DIR, ec);
        std::filesystem::create_directories(QUERY_TEST_DIR);
        auto &mgr = OsAccountSubProfileManager::GetInstance();
        mgr.Init(QUERY_TEST_DIR);
    }

    void TearDown() override
    {
        ResetMockState();
        std::error_code ec;
        std::filesystem::remove_all(QUERY_TEST_DIR, ec);
    }

    bool CreateValidSubspace(int32_t distId, int32_t userId)
    {
        OsAccountSubspaceInfo info;
        info.subspaceId = distId;
        info.userId_ = userId;
        info.isCreateCompleted = true;
        info.toBeRemoved = false;
        info.version_ = 1;
        info.bindTime_ = 0;
        info.ohosAccountInfo_.name_ = "test_name";
        info.ohosAccountInfo_.uid_ = "test_uid";
        info.ohosAccountInfo_.status_ = ACCOUNT_STATE_UNBOUND;
        auto &mgr = OsAccountSubProfileManager::GetInstance();
        return mgr.subProfileDataDeal_->SaveSubProfileInfo(info) == ERR_OK;
    }

    static const std::string QUERY_TEST_DIR;
    static constexpr int32_t QUERY_USER_ID = 100;
    static constexpr int32_t QUERY_BASE = QUERY_USER_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;
    static uint64_t allPermTokenId_;
};

const std::string SubProfileQuerySubspaceMgrTest::QUERY_TEST_DIR =
    "/data/test/os_account_subprofile_query_test/";
uint64_t SubProfileQuerySubspaceMgrTest::allPermTokenId_ = 0;

HWTEST_F(SubProfileQuerySubspaceMgrTest, GetSubProfileIds_MultipleSubspaces_001, TestSize.Level1)
{
    ASSERT_TRUE(CreateValidSubspace(QUERY_BASE + 1, QUERY_USER_ID));
    ASSERT_TRUE(CreateValidSubspace(QUERY_BASE + 3, QUERY_USER_ID));

    SubProfileContext ctx;
    ctx.subProfileIndexMap[0] = QUERY_BASE;
    ctx.subProfileIndexMap[1] = QUERY_BASE + 1;
    ctx.subProfileIndexMap[3] = QUERY_BASE + 3;
    ctx.subProfileIdList = {QUERY_BASE, QUERY_BASE + 1, QUERY_BASE + 3};
    ctx.nextSubProfileId = QUERY_BASE + 4;
    ctx.nextSubProfileIndex = 4;
    MockForceSubProfileContext(QUERY_USER_ID, ctx);

    auto &mgr = OsAccountSubProfileManager::GetInstance();
    std::vector<int32_t> subProfileIds;
    ErrCode ret = mgr.GetSubProfileIds(QUERY_USER_ID, subProfileIds);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_GE(subProfileIds.size(), 3u);
    EXPECT_NE(std::find(subProfileIds.begin(), subProfileIds.end(), QUERY_BASE), subProfileIds.end());
    EXPECT_NE(std::find(subProfileIds.begin(), subProfileIds.end(), QUERY_BASE + 1), subProfileIds.end());
    EXPECT_NE(std::find(subProfileIds.begin(), subProfileIds.end(), QUERY_BASE + 3), subProfileIds.end());
}

HWTEST_F(SubProfileQuerySubspaceMgrTest, GetSubProfileIds_OnlyBaseSubspace_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    std::vector<int32_t> subProfileIds;
    ErrCode ret = mgr.GetSubProfileIds(QUERY_USER_ID, subProfileIds);
    EXPECT_EQ(ret, ERR_OK);
    ASSERT_EQ(subProfileIds.size(), 1u);
    EXPECT_EQ(subProfileIds[0], QUERY_BASE);
}

HWTEST_F(SubProfileQuerySubspaceMgrTest, GetSubProfileIds_ContextReadFail_001, TestSize.Level1)
{
    MockForceReadSubProfileContextFail(ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    std::vector<int32_t> subProfileIds;
    ErrCode ret = mgr.GetSubProfileIds(QUERY_USER_ID, subProfileIds);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
    MockClearForceFailFlags();
}

HWTEST_F(SubProfileQuerySubspaceMgrTest, GetLocalIdForSubProfile_BaseSubspace_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    int32_t osAccountId = -1;
    ErrCode ret = mgr.GetLocalIdForSubProfile(QUERY_BASE, osAccountId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(osAccountId, QUERY_USER_ID);
}

HWTEST_F(SubProfileQuerySubspaceMgrTest, GetLocalIdForSubProfile_NonBaseSubspace_001, TestSize.Level1)
{
    int32_t distId = QUERY_BASE + 5;
    ASSERT_TRUE(CreateValidSubspace(distId, QUERY_USER_ID));

    auto &mgr = OsAccountSubProfileManager::GetInstance();
    int32_t osAccountId = -1;
    ErrCode ret = mgr.GetLocalIdForSubProfile(distId, osAccountId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(osAccountId, QUERY_USER_ID);
}

HWTEST_F(SubProfileQuerySubspaceMgrTest, GetLocalIdForSubProfile_NotFound_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    int32_t osAccountId = -1;
    int32_t invalidId = QUERY_BASE + 999;
    ErrCode ret = mgr.GetLocalIdForSubProfile(invalidId, osAccountId);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBPROFILE_NOT_FOUND);
}

HWTEST_F(SubProfileQuerySubspaceMgrTest, GetSubProfileIdByLocalIdAndAppIndex_OnlyBase_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    int32_t subProfileId = -1;
    ErrCode ret = mgr.GetSubProfileIdByLocalIdAndAppIndex(QUERY_USER_ID, 1, subProfileId);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBPROFILE_NOT_FOUND);
}

HWTEST_F(SubProfileQuerySubspaceMgrTest, GetSubProfileIdByLocalIdAndAppIndex_NoMatch_001, TestSize.Level1)
{
    ASSERT_TRUE(CreateValidSubspace(QUERY_BASE + 1, QUERY_USER_ID));

    auto &mgr = OsAccountSubProfileManager::GetInstance();
    int32_t subProfileId = -1;
    ErrCode ret = mgr.GetSubProfileIdByLocalIdAndAppIndex(QUERY_USER_ID, 5, subProfileId);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBPROFILE_NOT_FOUND);
}

HWTEST_F(SubProfileQuerySubspaceMgrTest, GetSubProfile_HeadlessSuccess_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();

    SubProfileContext ctx;
    ctx.subProfileIndexMap[0] = QUERY_BASE;
    ctx.subProfileIdList.push_back(QUERY_BASE);
    ctx.nextSubProfileId = QUERY_BASE + 1;
    ctx.nextSubProfileIndex = 1;
    MockForceSubProfileContext(QUERY_USER_ID, ctx);

    OsAccountSubspaceResult subspaceResult;
    OhosAccountInfo distributedInfo;
    ErrCode ret = mgr.GetSubProfile(QUERY_USER_ID, QUERY_BASE, subspaceResult, distributedInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(subspaceResult.id, QUERY_BASE);
    EXPECT_EQ(subspaceResult.osAccountId, QUERY_USER_ID);
    EXPECT_EQ(subspaceResult.index, 0);
    EXPECT_EQ(distributedInfo.name_, "");
    EXPECT_EQ(distributedInfo.uid_, "");
}

HWTEST_F(SubProfileQuerySubspaceMgrTest, GetSubProfile_HeadlessFileNotExist_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    OsAccountSubspaceResult subspaceResult;
    OhosAccountInfo distributedInfo;
    ErrCode ret = mgr.GetSubProfile(QUERY_USER_ID, QUERY_BASE, subspaceResult, distributedInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(subspaceResult.id, QUERY_BASE);
    EXPECT_EQ(subspaceResult.osAccountId, QUERY_USER_ID);
    EXPECT_EQ(subspaceResult.index, 0);
}

HWTEST_F(SubProfileQuerySubspaceMgrTest, GetSubProfile_NonBaseSuccess_001, TestSize.Level1)
{
    int32_t distId = QUERY_BASE + 2;
    SubProfileContext ctx;
    ctx.subProfileIndexMap[OsAccountSubProfileDataDeal::HEADLESS_SUBPROFILE_INDEX] = QUERY_BASE;
    ctx.subProfileIndexMap[2] = distId;
    ctx.subProfileIdList = {QUERY_BASE, distId};
    ctx.nextSubProfileId = QUERY_BASE + 3;
    ctx.nextSubProfileIndex = 3;
    MockForceSubProfileContext(QUERY_USER_ID, ctx);

    OsAccountSubspaceInfo info;
    info.subspaceId = distId;
    info.userId_ = QUERY_USER_ID;
    info.index = 2;
    info.isCreateCompleted = true;
    info.toBeRemoved = false;
    info.version_ = 1;
    info.bindTime_ = 0;
    info.ohosAccountInfo_.name_ = "test_name";
    info.ohosAccountInfo_.uid_ = "test_uid";
    info.ohosAccountInfo_.status_ = ACCOUNT_STATE_UNBOUND;
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    ASSERT_EQ(mgr.subProfileDataDeal_->SaveSubProfileInfo(info), ERR_OK);

    OsAccountSubspaceResult subspaceResult;
    OhosAccountInfo distributedInfo;
    ErrCode ret = mgr.GetSubProfile(QUERY_USER_ID, distId, subspaceResult, distributedInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(subspaceResult.id, distId);
    EXPECT_EQ(subspaceResult.osAccountId, QUERY_USER_ID);
    EXPECT_EQ(subspaceResult.index, 2);
    EXPECT_EQ(distributedInfo.name_, "test_name");
}

HWTEST_F(SubProfileQuerySubspaceMgrTest, GetSubProfile_NotFound_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    OsAccountSubspaceResult subspaceResult;
    OhosAccountInfo distributedInfo;
    int32_t invalidId = QUERY_BASE + 999;
    ErrCode ret = mgr.GetSubProfile(QUERY_USER_ID, invalidId, subspaceResult, distributedInfo);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBPROFILE_NOT_FOUND);
}

HWTEST_F(SubProfileQuerySubspaceMgrTest, GetSubProfile_ContextReadFail_001, TestSize.Level1)
{
    int32_t distId = QUERY_BASE + 2;
    OsAccountSubspaceInfo info;
    info.subspaceId = distId;
    info.userId_ = QUERY_USER_ID;
    info.index = 2;
    info.isCreateCompleted = true;
    info.toBeRemoved = false;
    info.version_ = 1;
    info.bindTime_ = 0;
    info.ohosAccountInfo_.name_ = "test_name";
    info.ohosAccountInfo_.uid_ = "test_uid";
    info.ohosAccountInfo_.status_ = ACCOUNT_STATE_UNBOUND;
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    ASSERT_EQ(mgr.subProfileDataDeal_->SaveSubProfileInfo(info), ERR_OK);

    MockForceReadSubProfileContextFail(ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);

    OsAccountSubspaceResult subspaceResult;
    OhosAccountInfo distributedInfo;
    ErrCode ret = mgr.GetSubProfile(QUERY_USER_ID, distId, subspaceResult, distributedInfo);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);

    MockClearForceFailFlags();
}

HWTEST_F(SubProfileQuerySubspaceMgrTest, GetSubProfile_IndexNotInContextMap_001, TestSize.Level1)
{
    int32_t distId = QUERY_BASE + 5;
    SubProfileContext ctx;
    ctx.subProfileIndexMap[OsAccountSubProfileDataDeal::HEADLESS_SUBPROFILE_INDEX] = QUERY_BASE;
    ctx.subProfileIdList = {QUERY_BASE};
    ctx.nextSubProfileId = QUERY_BASE + 6;
    ctx.nextSubProfileIndex = 1;
    MockForceSubProfileContext(QUERY_USER_ID, ctx);

    OsAccountSubspaceInfo info;
    info.subspaceId = distId;
    info.userId_ = QUERY_USER_ID;
    info.index = 5;
    info.isCreateCompleted = true;
    info.toBeRemoved = false;
    info.version_ = 1;
    info.bindTime_ = 0;
    info.ohosAccountInfo_.name_ = "test_name";
    info.ohosAccountInfo_.uid_ = "test_uid";
    info.ohosAccountInfo_.status_ = ACCOUNT_STATE_UNBOUND;
    auto &mgr = OsAccountSubProfileManager::GetInstance();
    ASSERT_EQ(mgr.subProfileDataDeal_->SaveSubProfileInfo(info), ERR_OK);

    OsAccountSubspaceResult subspaceResult;
    OhosAccountInfo distributedInfo;
    ErrCode ret = mgr.GetSubProfile(QUERY_USER_ID, distId, subspaceResult, distributedInfo);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBPROFILE_NOT_FOUND);
}

HWTEST_F(SubProfileQuerySubspaceMgrTest, GetSubProfile_HeadlessIndexNotFoundInMap_001, TestSize.Level1)
{
    auto &mgr = OsAccountSubProfileManager::GetInstance();

    SubProfileContext ctx;
    ctx.subProfileIdList.push_back(QUERY_BASE);
    ctx.nextSubProfileId = QUERY_BASE + 1;
    ctx.nextSubProfileIndex = 1;
    MockForceSubProfileContext(QUERY_USER_ID, ctx);

    OsAccountSubspaceResult subspaceResult;
    OhosAccountInfo distributedInfo;
    ErrCode ret = mgr.GetSubProfile(QUERY_USER_ID, QUERY_BASE, subspaceResult, distributedInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(subspaceResult.id, QUERY_BASE);
    EXPECT_EQ(subspaceResult.osAccountId, QUERY_USER_ID);
    EXPECT_EQ(subspaceResult.index, 0);
}

// ===== Task 11: OhosAccountManager query methods =====
class SubProfileQueryOhosMgrTest : public testing::Test {
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
        std::filesystem::remove_all(OHOS_QUERY_TEST_DIR, ec);
        std::filesystem::create_directories(OHOS_QUERY_TEST_DIR);
        OhosAccountManager::GetInstance().InitOsAccountSubProfileManager(OHOS_QUERY_TEST_DIR);
    }

    void TearDown() override
    {
        std::error_code ec;
        std::filesystem::remove_all(OHOS_QUERY_TEST_DIR, ec);
    }

    static const std::string OHOS_QUERY_TEST_DIR;
    static constexpr int32_t OHOS_QUERY_USER_ID = 100;
    static constexpr int32_t OHOS_QUERY_BASE = OHOS_QUERY_USER_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;
    static uint64_t allPermTokenId_;
};

const std::string SubProfileQueryOhosMgrTest::OHOS_QUERY_TEST_DIR =
    "/data/test/os_account_ohos_query_test/";
uint64_t SubProfileQueryOhosMgrTest::allPermTokenId_ = 0;

HWTEST_F(SubProfileQueryOhosMgrTest, GetOsAccountForegroundSubProfileId_AccountNotFound_001, TestSize.Level1)
{
    int32_t subProfileId = -1;
    ErrCode ret = OhosAccountManager::GetInstance().GetOsAccountForegroundSubProfileId(
        OHOS_QUERY_USER_ID, subProfileId);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

HWTEST_F(SubProfileQueryOhosMgrTest, GetOsAccountSubProfileIds_Success_001, TestSize.Level1)
{
    std::vector<int32_t> subProfileIds;
    ErrCode ret = OhosAccountManager::GetInstance().GetOsAccountSubProfileIds(
        OHOS_QUERY_USER_ID, subProfileIds);
    EXPECT_EQ(ret, ERR_OK);
    ASSERT_EQ(subProfileIds.size(), 1u);
    EXPECT_EQ(subProfileIds[0], OHOS_QUERY_BASE);
}

HWTEST_F(SubProfileQueryOhosMgrTest, GetOsAccountLocalIdForSubProfile_ValidSubProfileID, TestSize.Level1)
{
    int32_t osAccountId = -1;
    ErrCode ret = OhosAccountManager::GetInstance().GetOsAccountLocalIdForSubProfile(
        OHOS_QUERY_BASE, osAccountId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(osAccountId, OHOS_QUERY_USER_ID);
}

HWTEST_F(SubProfileQueryOhosMgrTest, GetOsAccountLocalIdForSubProfile_NotFound_001, TestSize.Level1)
{
    int32_t osAccountId = -1;
    int32_t invalidId = OHOS_QUERY_BASE + 999;
    ErrCode ret = OhosAccountManager::GetInstance().GetOsAccountLocalIdForSubProfile(
        invalidId, osAccountId);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBPROFILE_NOT_FOUND);
}

HWTEST_F(SubProfileQueryOhosMgrTest, GetOsAccountSubProfile_BaseSubspace_NoJson_001, TestSize.Level1)
{
    OsAccountSubspaceResult subspaceResult;
    OhosAccountInfo distributedInfo;
    ErrCode ret = OhosAccountManager::GetInstance().GetOsAccountSubProfile(
        OHOS_QUERY_USER_ID, OHOS_QUERY_BASE, subspaceResult, distributedInfo);
    EXPECT_NE(ret, ERR_OS_ACCOUNT_SUBPROFILE_NOT_FOUND);
    EXPECT_EQ(subspaceResult.id, OHOS_QUERY_BASE);
    EXPECT_EQ(subspaceResult.osAccountId, OHOS_QUERY_USER_ID);
    EXPECT_EQ(subspaceResult.index, 0);
    EXPECT_GE(subspaceResult.createTime, 0);
}

HWTEST_F(SubProfileQueryOhosMgrTest, GetOsAccountSubProfile_NonBaseSuccess_001, TestSize.Level1)
{
    int32_t distId = OHOS_QUERY_BASE + 3;
    SubProfileContext ctx;
    ctx.subProfileIndexMap[OsAccountSubProfileDataDeal::HEADLESS_SUBPROFILE_INDEX] = OHOS_QUERY_BASE;
    ctx.subProfileIndexMap[3] = distId;
    ctx.subProfileIdList = {OHOS_QUERY_BASE, distId};
    ctx.nextSubProfileId = OHOS_QUERY_BASE + 4;
    ctx.nextSubProfileIndex = 4;
    MockForceSubProfileContext(OHOS_QUERY_USER_ID, ctx);

    OsAccountSubspaceInfo info;
    info.subspaceId = distId;
    info.userId_ = OHOS_QUERY_USER_ID;
    info.index = 3;
    info.subspaceOffset = 3;
    info.isCreateCompleted = true;
    info.toBeRemoved = false;
    info.version_ = 1;
    info.bindTime_ = 0;
    info.createTime = 1234567890000;
    info.ohosAccountInfo_.name_ = "test_profile";
    info.ohosAccountInfo_.uid_ = "test_uid";
    info.ohosAccountInfo_.SetRawUid("test_raw_uid");
    info.ohosAccountInfo_.status_ = ACCOUNT_STATE_UNBOUND;
    auto &subspaceMgr = OsAccountSubProfileManager::GetInstance();
    ASSERT_EQ(subspaceMgr.subProfileDataDeal_->SaveSubProfileInfo(info), ERR_OK);

    OsAccountSubspaceResult subspaceResult;
    OhosAccountInfo distributedInfo;
    ErrCode ret = OhosAccountManager::GetInstance().GetOsAccountSubProfile(
        OHOS_QUERY_USER_ID, distId, subspaceResult, distributedInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(subspaceResult.id, distId);
    EXPECT_EQ(subspaceResult.osAccountId, OHOS_QUERY_USER_ID);
    EXPECT_EQ(subspaceResult.index, 3);
    EXPECT_EQ(subspaceResult.createTime, 1234567890000);
}

HWTEST_F(SubProfileQueryOhosMgrTest, GetOsAccountSubProfile_NonBaseNotFound_001, TestSize.Level1)
{
    OsAccountSubspaceResult subspaceResult;
    OhosAccountInfo distributedInfo;
    int32_t invalidId = OHOS_QUERY_BASE + 999;
    ErrCode ret = OhosAccountManager::GetInstance().GetOsAccountSubProfile(
        OHOS_QUERY_USER_ID, invalidId, subspaceResult, distributedInfo);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBPROFILE_NOT_FOUND);
}

HWTEST_F(SubProfileQueryOhosMgrTest, GetOsAccountSubProfile_DefaultUid_NoAnonymize_001, TestSize.Level1)
{
    int32_t distId = OHOS_QUERY_BASE + 4;
    SubProfileContext ctx;
    ctx.subProfileIndexMap[OsAccountSubProfileDataDeal::HEADLESS_SUBPROFILE_INDEX] = OHOS_QUERY_BASE;
    ctx.subProfileIndexMap[4] = distId;
    ctx.subProfileIdList = {OHOS_QUERY_BASE, distId};
    ctx.nextSubProfileId = OHOS_QUERY_BASE + 5;
    ctx.nextSubProfileIndex = 5;
    MockForceSubProfileContext(OHOS_QUERY_USER_ID, ctx);

    OsAccountSubspaceInfo info;
    info.subspaceId = distId;
    info.userId_ = OHOS_QUERY_USER_ID;
    info.index = 4;
    info.subspaceOffset = 4;
    info.isCreateCompleted = true;
    info.toBeRemoved = false;
    info.version_ = 1;
    info.ohosAccountInfo_.name_ = "test_default";
    info.ohosAccountInfo_.uid_ = DEFAULT_OHOS_ACCOUNT_UID;
    info.ohosAccountInfo_.SetRawUid(DEFAULT_OHOS_ACCOUNT_UID);
    info.ohosAccountInfo_.status_ = ACCOUNT_STATE_UNBOUND;
    auto &subspaceMgr = OsAccountSubProfileManager::GetInstance();
    ASSERT_EQ(subspaceMgr.subProfileDataDeal_->SaveSubProfileInfo(info), ERR_OK);

    OsAccountSubspaceResult subspaceResult;
    OhosAccountInfo distributedInfo;
    ErrCode ret = OhosAccountManager::GetInstance().GetOsAccountSubProfile(
        OHOS_QUERY_USER_ID, distId, subspaceResult, distributedInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(distributedInfo.GetRawUid(), DEFAULT_OHOS_ACCOUNT_UID);
}

HWTEST_F(SubProfileQueryOhosMgrTest, GetOsAccountSubProfileId_AppIndex0_001, TestSize.Level1)
{
    int32_t subProfileId = -1;
    ErrCode ret = OhosAccountManager::GetInstance().GetOsAccountSubProfileId(
        OHOS_QUERY_USER_ID, 0, subProfileId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(subProfileId, OHOS_QUERY_BASE);
}

HWTEST_F(SubProfileQueryOhosMgrTest, GetOsAccountSubProfileId_NotFound_001, TestSize.Level1)
{
    int32_t subProfileId = -1;
    ErrCode ret = OhosAccountManager::GetInstance().GetOsAccountSubProfileId(
        OHOS_QUERY_USER_ID, 1, subProfileId);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBPROFILE_NOT_FOUND);
}

// ===== Task 12: AccountMgrService query methods =====
class SubProfileQueryServiceTest : public testing::Test {
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
    static constexpr int32_t SVC_TEST_USER_ID = 100;
    static constexpr int32_t SVC_TEST_BASE = SVC_TEST_USER_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;
};

uint64_t SubProfileQueryServiceTest::allPermTokenId_ = 0;

class SubProfileQueryServiceNoPermTest : public testing::Test {
public:
    void SetUp() override {}
    void TearDown() override {}

    static constexpr int32_t SVC_TEST_USER_ID = 100;
    static constexpr int32_t SVC_TEST_BASE = SVC_TEST_USER_ID * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;
};

HWTEST_F(SubProfileQueryServiceNoPermTest, GetOsAccountFgSubProfileId_NoArg_PermDenied_001, TestSize.Level1)
{
    int32_t subProfileId = -1;
    auto ret = AccountMgrService::GetInstance().GetOsAccountForegroundSubProfileId(subProfileId);
    EXPECT_NE(ret, ERR_OK);
}

HWTEST_F(SubProfileQueryServiceTest, GetOsAccountFgSubProfileId_NoArg_RestrictedAccount_001, TestSize.Level1)
{
    int32_t subProfileId = -1;
    auto ret = AccountMgrService::GetInstance().GetOsAccountForegroundSubProfileId(subProfileId);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBPROFILE_NOT_FOUND);
}

HWTEST_F(SubProfileQueryServiceTest, GetOsAccountFgSubProfileId_WithId_AccountNotFound_001, TestSize.Level1)
{
    MockSetCreatedOsAccounts({});
    int32_t subProfileId = -1;
    auto ret = OhosAccountManager::GetInstance().GetOsAccountForegroundSubProfileId(
        SVC_TEST_USER_ID, subProfileId);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

HWTEST_F(SubProfileQueryServiceTest, GetOsAccountSubProfileIds_NoArg_RestrictedAccount_001, TestSize.Level1)
{
    std::vector<int32_t> subProfileIds;
    auto ret = AccountMgrService::GetInstance().GetOsAccountSubProfileIds(subProfileIds);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(subProfileIds.empty());
}

HWTEST_F(SubProfileQueryServiceTest, GetOsAccountSubProfileIds_WithId_AccountNotFound_001, TestSize.Level1)
{
    std::vector<int32_t> subProfileIds;
    auto ret = OhosAccountManager::GetInstance().GetOsAccountSubProfileIds(
        SVC_TEST_USER_ID, subProfileIds);
    EXPECT_EQ(ret, ERR_OK);
    ASSERT_GE(subProfileIds.size(), 1u);
    EXPECT_EQ(subProfileIds[0], SVC_TEST_BASE);
}

HWTEST_F(SubProfileQueryServiceTest, GetOsAccountSubProfileIds_WithId_Restricted_001, TestSize.Level1)
{
    std::vector<int32_t> subProfileIds;
    auto ret = AccountMgrService::GetInstance().GetOsAccountSubProfileIds(0, subProfileIds);
    EXPECT_TRUE(ret == ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR || ret == ERR_OK);
    if (ret == ERR_OK) {
        EXPECT_TRUE(subProfileIds.empty());
    }
}

HWTEST_F(SubProfileQueryServiceTest, GetOsAccountLocalIdForSubProfile_Success_001, TestSize.Level1)
{
    MockSetCreatedOsAccounts({});
    int32_t osAccountId = -1;
    auto ret = OhosAccountManager::GetInstance().GetOsAccountLocalIdForSubProfile(
        SVC_TEST_BASE, osAccountId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(osAccountId, SVC_TEST_USER_ID);
}

HWTEST_F(SubProfileQueryServiceNoPermTest, GetOsAccountSubProfile_SingleArg_PermDenied_001, TestSize.Level1)
{
    OsAccountSubspaceResult subspaceResult;
    OhosAccountInfo distributedInfo;
    auto ret = AccountMgrService::GetInstance().GetOsAccountSubProfile(
        SVC_TEST_BASE, subspaceResult, distributedInfo);
    EXPECT_NE(ret, ERR_OK);
}

HWTEST_F(SubProfileQueryServiceTest, GetOsAccountSubProfile_SingleArg_OwnershipMismatch_001, TestSize.Level1)
{
    OsAccountSubspaceResult subspaceResult;
    OhosAccountInfo distributedInfo;
    auto ret = AccountMgrService::GetInstance().GetOsAccountSubProfile(
        SVC_TEST_BASE, subspaceResult, distributedInfo);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBPROFILE_NOT_FOUND);
}

HWTEST_F(SubProfileQueryServiceNoPermTest, GetOsAccountSubProfile_DualArg_PermDenied_001, TestSize.Level1)
{
    OsAccountSubspaceResult subspaceResult;
    OhosAccountInfo distributedInfo;
    auto ret = AccountMgrService::GetInstance().GetOsAccountSubProfile(
        SVC_TEST_USER_ID, SVC_TEST_BASE, subspaceResult, distributedInfo);
    EXPECT_NE(ret, ERR_OK);
}

HWTEST_F(SubProfileQueryServiceTest, GetOsAccountSubProfile_DualArg_OwnershipMismatch_001, TestSize.Level1)
{
    OsAccountSubspaceResult subspaceResult;
    OhosAccountInfo distributedInfo;
    auto ret = AccountMgrService::GetInstance().GetOsAccountSubProfile(
        200, SVC_TEST_BASE, subspaceResult, distributedInfo);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBPROFILE_NOT_FOUND);
}

HWTEST_F(SubProfileQueryServiceTest, GetOsAccountSubProfile_DualArg_SubProfileMismatch_001, TestSize.Level1)
{
    OsAccountSubspaceResult subspaceResult;
    OhosAccountInfo distributedInfo;
    int32_t subProfileId = 200 * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;
    auto ret = AccountMgrService::GetInstance().GetOsAccountSubProfile(
        SVC_TEST_USER_ID, subProfileId, subspaceResult, distributedInfo);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBPROFILE_NOT_FOUND);
}

// ===== createTime fault-injection tests =====

HWTEST_F(SubProfileQueryOhosMgrTest, CreateTime_Marshalling_RoundTrip_001, TestSize.Level1)
{
    OsAccountSubspaceResult result;
    result.id = 100;
    result.osAccountId = 200;
    result.index = 3;
    result.createTime = 1234567890123;
    Parcel parcel;
    ASSERT_TRUE(result.Marshalling(parcel));
    auto *unmarshalled = OsAccountSubspaceResult::Unmarshalling(parcel);
    ASSERT_NE(unmarshalled, nullptr);
    EXPECT_EQ(unmarshalled->id, 100);
    EXPECT_EQ(unmarshalled->osAccountId, 200);
    EXPECT_EQ(unmarshalled->index, 3);
    EXPECT_EQ(unmarshalled->createTime, 1234567890123);
    delete unmarshalled;
}

HWTEST_F(SubProfileQueryOhosMgrTest, CreateTime_OldFileUpgrade_DefaultZero_001, TestSize.Level1)
{
    int32_t distId = OHOS_QUERY_BASE + 5;
    SubProfileContext ctx;
    ctx.subProfileIndexMap[OsAccountSubProfileDataDeal::HEADLESS_SUBPROFILE_INDEX] = OHOS_QUERY_BASE;
    ctx.subProfileIndexMap[5] = distId;
    ctx.subProfileIdList = {OHOS_QUERY_BASE, distId};
    ctx.nextSubProfileId = OHOS_QUERY_BASE + 6;
    ctx.nextSubProfileIndex = 6;
    MockForceSubProfileContext(OHOS_QUERY_USER_ID, ctx);

    std::string oldJson = R"({"subspaceId":)" + std::to_string(distId) +
        R"(,"osAccountId":)" + std::to_string(OHOS_QUERY_USER_ID) +
        R"(,"is_create_completed":true,"to_be_removed":false,"bind_time":0,"version":1,)"
        R"("account_name":"old","raw_uid":"","open_id":"","bind_status":0,"calling_uid":0,)"
        R"("account_nickname":"","account_scalableData":"","subspaceIndex":5,"subspaceOffset":5})";
    auto &subspaceMgr = OsAccountSubProfileManager::GetInstance();
    std::string filePath = subspaceMgr.subProfileDataDeal_->GetSubProfileFilePath(OHOS_QUERY_USER_ID, distId);
    ASSERT_EQ(subspaceMgr.subProfileDataDeal_->SaveSubProfileFiles(
        OsAccountSubspaceInfo(OHOS_QUERY_USER_ID, distId, 5, 5), oldJson), ERR_OK);

    OsAccountSubspaceInfo info;
    ASSERT_EQ(subspaceMgr.subProfileDataDeal_->LoadSubProfileInfo(OHOS_QUERY_USER_ID, distId, info), ERR_OK);
    EXPECT_EQ(info.createTime, 0);
}

HWTEST_F(SubProfileQueryOhosMgrTest, CreateTime_CreateSubProfile_Positive_001, TestSize.Level1)
{
    auto &subspaceMgr = OsAccountSubProfileManager::GetInstance();
    OsAccountSubspaceInfo createdInfo;
    ErrCode ret = subspaceMgr.CreateSubProfile(OHOS_QUERY_USER_ID, createdInfo);
    ASSERT_EQ(ret, ERR_OK);
    OsAccountSubspaceInfo info;
    ASSERT_EQ(subspaceMgr.subProfileDataDeal_->LoadSubProfileInfo(
        OHOS_QUERY_USER_ID, createdInfo.subspaceId, info), ERR_OK);
    EXPECT_GT(info.createTime, 0);
}

// AccountInfo::clear() must reset bindTime_ but NOT createTime_ — createTime
// persists across login/logout (design §3.2 / §9 compatibility table).
HWTEST_F(SubProfileQueryOhosMgrTest, CreateTime_AccountInfoClear_NoReset_001, TestSize.Level1)
{
    AccountInfo info;
    info.createTime_ = 1700000000000;
    info.bindTime_ = 999;
    info.clear();
    EXPECT_EQ(info.createTime_, 1700000000000);
    EXPECT_EQ(info.bindTime_, 0);
}

// Headless sub-profile (base ID) must return accountInfo.createTime_ read from
// {userId}/account.json (design §6 source matrix). The default test fixture only inits
// the sub-profile data deal, not the main dataDealer_ — so reset dataDealer_ to the test
// directory, call Init() (sets initOk_=true, reads our pre-written file), then query.
HWTEST_F(SubProfileQueryOhosMgrTest, CreateTime_Headless_ReadsAccountInfoCreateTime_001, TestSize.Level1)
{
    auto &manager = OhosAccountManager::GetInstance();
    // Reset main dataDealer_ to the test dir. The ctor pulls accountFileOperator_ from the
    // watcher-mgr singleton (null in unit-test env), so give it a fresh AccountFileOperator,
    // otherwise Init()->IsExistFile() derefs null -> SIGSEGV.
    manager.dataDealer_ = std::make_unique<OhosAccountDataDeal>(OHOS_QUERY_TEST_DIR);
    manager.dataDealer_->accountFileOperator_ = std::make_shared<AccountFileOperator>();

    // Pre-write account.json with a known createTime so the headless path reads it
    // (rather than BuildJsonFileFromScratch stamping "now").
    std::string userDir = OHOS_QUERY_TEST_DIR + std::to_string(OHOS_QUERY_USER_ID);
    std::error_code ec;
    std::filesystem::create_directories(userDir, ec);
    ASSERT_TRUE(std::filesystem::exists(userDir, ec));
    const int64_t knownCreateTime = 1700000000000;
    std::string accountJson = R"({"version":1,"bind_time":0,"createTime":)" +
        std::to_string(knownCreateTime) + R"(,"user_id":)" + std::to_string(OHOS_QUERY_USER_ID) +
        R"(,"account_name":"","raw_uid":"","open_id":"","bind_status":0,)"
        R"("calling_uid":0,"account_nickname":"","account_scalableData":""})";
    std::string jsonPath = userDir + "/account.json";
    std::ofstream ofs(jsonPath);
    ASSERT_TRUE(ofs.good());
    ofs << accountJson;
    ofs.close();
    // Mock the post-Init() state directly: Init() would call
    // IInnerOsAccountManager::QueryAllCreatedOsAccounts (pure-virtual, crashes in unit-test
    // env). initOk_=true is all AccountInfoFromJson checks; GetAccountInfo only needs
    // accountFileOperator_ + the pre-written file on disk.
    manager.dataDealer_->initOk_ = true;

    OsAccountSubspaceResult subspaceResult;
    OhosAccountInfo distributedInfo;
    ErrCode ret = manager.GetOsAccountSubProfile(
        OHOS_QUERY_USER_ID, OHOS_QUERY_BASE, subspaceResult, distributedInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(subspaceResult.id, OHOS_QUERY_BASE);
    EXPECT_EQ(subspaceResult.index, 0);
    EXPECT_EQ(subspaceResult.createTime, knownCreateTime);
}

#endif // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
