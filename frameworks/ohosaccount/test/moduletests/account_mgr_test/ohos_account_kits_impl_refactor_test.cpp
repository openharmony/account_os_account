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

#include <gtest/gtest.h>

#include "access_token.h"
#include "accesstoken_kit.h"
#include "account_error_no.h"
#include "account_info.h"
#include "account_test_common.h"
#define private public
#include "ohos_account_kits.h"
#include "ohos_account_kits_impl.h"
#undef private
#include "os_account_subspace_client.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;
using namespace OHOS::AccountSA::Constants;
using namespace OHOS::Security::AccessToken;

namespace {
const std::string TEST_ACCOUNT_NAME = "TestAccountName";
const std::string TEST_ACCOUNT_UID = "123456789";
const std::string TEST_EXPECTED_UID = "15E2B0D3C33891EBB0F1EF609EC419420C20E320CE94C65FBC8C3312448EB225";
const std::string TEST_NICKNAME = "NickName_Test";
const std::string TEST_AVATAR = "Avatar_Test";
const std::string TEST_SCALABLE_DATA = R"({"age":123})";
const std::string TEST_EMPTY_STR;
const std::int32_t DEFAULT_USER_ID = 100;
const std::int32_t UID_USER_0 = 0;
const std::int32_t UID_USER_100 = DEFAULT_USER_ID * 200000;

// dvid = PBKDF2-HMAC-SHA256(password=rawUid, salt=bundleName, iter=1000, dkLen=32) hex uppercase
// rawUid = "123456789"
// device-level: bundleName from GetAllAccountPermission() = "account_test_setup"
const std::string DEVICE_DVID = "866C945A383F2D9BC97BF50E69D75316E0EB15E626E469986AD3745EF08931EC";
// bundle+user:  bundleName = "com.test.bundle"
const std::string BUNDLE_USER_DVID = "F520E84109A560EF21B563F469A50A361EE8AD094630A95268A7294DCCFB47F3";
// non-system-app anonymized dvid: bundleName = "com.ohos.sceneboard" (AllocPermission default)
const std::string NON_SYS_ANON_DVID = "A084C754637A0C8EE02599AC553FF44DB2BFEB6EE030CE7F9BABD5F3471070B3";
constexpr int32_t TEST_OS_ACCOUNT_ID = 100;
constexpr int32_t TEST_SUB_PROFILE_ID_BASE = TEST_OS_ACCOUNT_ID * 1000;  // 100000
constexpr int32_t TEST_SUB_PROFILE_ID_MISMATCH = 200 * 1000;             // 200000
constexpr int32_t TEST_NON_EXIST_ACCOUNT_ID = 200;

OhosAccountInfo BuildTestAccountInfo()
{
    OhosAccountInfo info;
    info.name_ = TEST_ACCOUNT_NAME;
    info.uid_ = TEST_ACCOUNT_UID;
    info.status_ = ACCOUNT_STATE_UNBOUND;
    info.nickname_ = TEST_NICKNAME;
    info.avatar_ = TEST_AVATAR;
    info.scalableData_ = TEST_SCALABLE_DATA;
    return info;
}
} // namespace

// ======================================================================
// Test fixture — login in SetUpTestCase, logoff in TearDownTestCase
// ======================================================================
class OhosAccountKitsImplRefactorTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        ASSERT_TRUE(GetAllAccountPermission());
        OhosAccountInfo loginInfo = BuildTestAccountInfo();
        ASSERT_EQ(ERR_OK, OhosAccountKits::GetInstance().SetOsAccountDistributedInfo(
            DEFAULT_USER_ID, loginInfo, OHOS_ACCOUNT_EVENT_LOGIN));
    }

    static void TearDownTestCase()
    {
        ASSERT_TRUE(GetAllAccountPermission());
        OhosAccountInfo logoffInfo;
        logoffInfo.name_ = TEST_ACCOUNT_NAME;
        logoffInfo.uid_ = TEST_ACCOUNT_UID;
        EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().SetOsAccountDistributedInfo(
            DEFAULT_USER_ID, logoffInfo, OHOS_ACCOUNT_EVENT_LOGOUT));
    }

    void SetUp() override {}
    void TearDown() override {}
};

// ======================================================================
// Logged-in scenarios — User 0 (UID=0, system app via GetAllAccountPermission)
// ======================================================================

HWTEST_F(OhosAccountKitsImplRefactorTest, User0_GetOhosAccountInfo_AllFields, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_0));
    OhosAccountInfo result;
    ASSERT_EQ(ERR_OK, OhosAccountKits::GetInstance().GetOhosAccountInfo(result));
    EXPECT_EQ(result.name_, TEST_ACCOUNT_NAME);
    EXPECT_EQ(result.uid_, TEST_EXPECTED_UID);
    EXPECT_EQ(result.status_, ACCOUNT_STATE_LOGIN);
    EXPECT_EQ(result.nickname_, TEST_NICKNAME);
    EXPECT_EQ(result.avatar_, TEST_AVATAR);
    EXPECT_EQ(result.scalableData_, TEST_SCALABLE_DATA);
    // account_mgr_service.cpp:L311: GetOhosAccountInfo always clears rawUid
    EXPECT_EQ(result.GetRawUid(), TEST_EMPTY_STR);
}

HWTEST_F(OhosAccountKitsImplRefactorTest, User0_QueryOhosAccountInfo_Pair, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_0));
    auto ret = OhosAccountKits::GetInstance().QueryOhosAccountInfo();
    EXPECT_TRUE(ret.first);
    EXPECT_EQ(ret.second.name_, TEST_ACCOUNT_NAME);
    EXPECT_EQ(ret.second.uid_, TEST_EXPECTED_UID);
    EXPECT_EQ(ret.second.status_, ACCOUNT_STATE_LOGIN);
}

HWTEST_F(OhosAccountKitsImplRefactorTest, User0_QueryOhosAccountInfo_ErrCode, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_0));
    OhosAccountInfo info;
    ASSERT_EQ(ERR_OK, OhosAccountKitsImpl::GetInstance().QueryOhosAccountInfo(info));
    EXPECT_EQ(info.name_, TEST_ACCOUNT_NAME);
    EXPECT_EQ(info.uid_, TEST_EXPECTED_UID);
    EXPECT_EQ(info.status_, ACCOUNT_STATE_LOGIN);
}

HWTEST_F(OhosAccountKitsImplRefactorTest, User0_QueryDistributedVirtualDeviceId_Single, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_0));
    std::string dvid;
    ASSERT_EQ(ERR_OK,
        OhosAccountKitsImpl::GetInstance().QueryDistributedVirtualDeviceId(dvid));
    EXPECT_EQ(DEVICE_DVID, dvid);
}

HWTEST_F(OhosAccountKitsImplRefactorTest, User0_GetOsAccountDistributedInfo, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_0));
    OhosAccountInfo result;
    ASSERT_EQ(ERR_OK, OhosAccountKits::GetInstance().GetOsAccountDistributedInfo(
        DEFAULT_USER_ID, result));
    EXPECT_EQ(result.name_, TEST_ACCOUNT_NAME);
    EXPECT_EQ(result.uid_, TEST_EXPECTED_UID);
    EXPECT_EQ(result.status_, ACCOUNT_STATE_LOGIN);
    EXPECT_EQ(result.nickname_, TEST_NICKNAME);
    EXPECT_EQ(result.avatar_, TEST_AVATAR);
    EXPECT_EQ(result.scalableData_, TEST_SCALABLE_DATA);
}

HWTEST_F(OhosAccountKitsImplRefactorTest, User0_QueryOsAccountDistributedInfo_Pair, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_0));
    auto ret = OhosAccountKits::GetInstance().QueryOsAccountDistributedInfo(DEFAULT_USER_ID);
    EXPECT_TRUE(ret.first);
    EXPECT_EQ(ret.second.name_, TEST_ACCOUNT_NAME);
    EXPECT_EQ(ret.second.uid_, TEST_EXPECTED_UID);
    EXPECT_EQ(ret.second.status_, ACCOUNT_STATE_LOGIN);
}

HWTEST_F(OhosAccountKitsImplRefactorTest, User0_QueryOsAccountDistributedInfo_ErrCode, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_0));
    OhosAccountInfo info;
    ASSERT_EQ(ERR_OK, OhosAccountKitsImpl::GetInstance().QueryOsAccountDistributedInfo(
        DEFAULT_USER_ID, info));
    EXPECT_EQ(info.name_, TEST_ACCOUNT_NAME);
    EXPECT_EQ(info.uid_, TEST_EXPECTED_UID);
    EXPECT_EQ(info.status_, ACCOUNT_STATE_LOGIN);
}

HWTEST_F(OhosAccountKitsImplRefactorTest, User0_QueryDeviceAccountId, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_0));
    std::int32_t accountId = -1;
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().QueryDeviceAccountId(accountId));
    EXPECT_EQ(0, accountId);
}

// QueryDistributedVirtualDeviceId(bundleName, localId, dvid) — explicit params, User0 caller
HWTEST_F(OhosAccountKitsImplRefactorTest, User0_QueryDistributedVirtualDeviceId_WithParams, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_0));
    std::string dvid;
    ASSERT_EQ(ERR_OK,
        OhosAccountKitsImpl::GetInstance().QueryDistributedVirtualDeviceId(
            "com.test.bundle", DEFAULT_USER_ID, dvid));
    EXPECT_EQ(BUNDLE_USER_DVID, dvid);
}

// ======================================================================
// Logged-in scenarios — User 100 (UID=20000000)
// ======================================================================

HWTEST_F(OhosAccountKitsImplRefactorTest, User100_GetOhosAccountInfo_AllFields, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_100));
    OhosAccountInfo result;
    ASSERT_EQ(ERR_OK, OhosAccountKits::GetInstance().GetOhosAccountInfo(result));
    EXPECT_EQ(result.name_, TEST_ACCOUNT_NAME);
    EXPECT_EQ(result.uid_, TEST_EXPECTED_UID);
    EXPECT_EQ(result.status_, ACCOUNT_STATE_LOGIN);
    EXPECT_EQ(result.nickname_, TEST_NICKNAME);
    EXPECT_EQ(result.avatar_, TEST_AVATAR);
    EXPECT_EQ(result.scalableData_, TEST_SCALABLE_DATA);
}

HWTEST_F(OhosAccountKitsImplRefactorTest, User100_QueryOhosAccountInfo_Pair, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_100));
    auto ret = OhosAccountKits::GetInstance().QueryOhosAccountInfo();
    EXPECT_TRUE(ret.first);
    EXPECT_EQ(ret.second.name_, TEST_ACCOUNT_NAME);
    EXPECT_EQ(ret.second.uid_, TEST_EXPECTED_UID);
    EXPECT_EQ(ret.second.status_, ACCOUNT_STATE_LOGIN);
}

HWTEST_F(OhosAccountKitsImplRefactorTest, User100_QueryOhosAccountInfo_ErrCode, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_100));
    OhosAccountInfo info;
    ASSERT_EQ(ERR_OK, OhosAccountKitsImpl::GetInstance().QueryOhosAccountInfo(info));
    EXPECT_EQ(info.name_, TEST_ACCOUNT_NAME);
    EXPECT_EQ(info.uid_, TEST_EXPECTED_UID);
    EXPECT_EQ(info.status_, ACCOUNT_STATE_LOGIN);
}

HWTEST_F(OhosAccountKitsImplRefactorTest, User100_GetOsAccountDistributedInfo, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_100));
    OhosAccountInfo result;
    ASSERT_EQ(ERR_OK, OhosAccountKits::GetInstance().GetOsAccountDistributedInfo(
        DEFAULT_USER_ID, result));
    EXPECT_EQ(result.name_, TEST_ACCOUNT_NAME);
    EXPECT_EQ(result.uid_, TEST_EXPECTED_UID);
    EXPECT_EQ(result.status_, ACCOUNT_STATE_LOGIN);
    EXPECT_EQ(result.nickname_, TEST_NICKNAME);
    EXPECT_EQ(result.avatar_, TEST_AVATAR);
    EXPECT_EQ(result.scalableData_, TEST_SCALABLE_DATA);
}

HWTEST_F(OhosAccountKitsImplRefactorTest, User100_QueryOsAccountDistributedInfo_Pair, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_100));
    auto ret = OhosAccountKits::GetInstance().QueryOsAccountDistributedInfo(DEFAULT_USER_ID);
    EXPECT_TRUE(ret.first);
    EXPECT_EQ(ret.second.name_, TEST_ACCOUNT_NAME);
    EXPECT_EQ(ret.second.uid_, TEST_EXPECTED_UID);
    EXPECT_EQ(ret.second.status_, ACCOUNT_STATE_LOGIN);
}

HWTEST_F(OhosAccountKitsImplRefactorTest, User100_QueryOsAccountDistributedInfo_ErrCode, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_100));
    OhosAccountInfo info;
    ASSERT_EQ(ERR_OK, OhosAccountKitsImpl::GetInstance().QueryOsAccountDistributedInfo(
        DEFAULT_USER_ID, info));
    EXPECT_EQ(info.name_, TEST_ACCOUNT_NAME);
    EXPECT_EQ(info.uid_, TEST_EXPECTED_UID);
    EXPECT_EQ(info.status_, ACCOUNT_STATE_LOGIN);
}

HWTEST_F(OhosAccountKitsImplRefactorTest, User100_QueryDeviceAccountId, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_100));
    std::int32_t accountId = -1;
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().QueryDeviceAccountId(accountId));
    EXPECT_EQ(100, accountId);
}

HWTEST_F(OhosAccountKitsImplRefactorTest, User100_QueryDistributedVirtualDeviceId_WithParams, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_100));
    std::string dvid;
    ASSERT_EQ(ERR_OK,
        OhosAccountKitsImpl::GetInstance().QueryDistributedVirtualDeviceId(
            "com.test.bundle", DEFAULT_USER_ID, dvid));
    EXPECT_EQ(BUNDLE_USER_DVID, dvid);
}

// QueryDistributedVirtualDeviceId single-param: GetCallingUserID()=100 vs active account for User0
HWTEST_F(OhosAccountKitsImplRefactorTest, User100_QueryDistributedVirtualDeviceId_Single, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_100));
    std::string dvid;
    ASSERT_EQ(ERR_OK,
        OhosAccountKitsImpl::GetInstance().QueryDistributedVirtualDeviceId(dvid));
    EXPECT_EQ(DEVICE_DVID, dvid);
}

// ======================================================================
// Non-system-app anonymization: AnonymizeOhosAccountInfo applies
//   uid → GenerateDVID(bundleName, rawUid)
//   name → firstChar + "**********"
// ======================================================================

HWTEST_F(OhosAccountKitsImplRefactorTest, NonSystemApp_GetOhosAccountInfo_Anonymized, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_0));
    // AllocPermission with isSystemApp=false → AnonymizeOhosAccountInfo applies
    uint64_t selfTokenId = IPCSkeleton::GetSelfTokenID();
    uint64_t tokenId = 0;
    ASSERT_TRUE(AllocPermission(
        {"ohos.permission.GET_DISTRIBUTED_ACCOUNTS"}, tokenId, false));

    OhosAccountInfo result;
    ASSERT_EQ(ERR_OK, OhosAccountKits::GetInstance().GetOhosAccountInfo(result));
    // uid_    → GenerateDVID(bundleName, rawUid)
    EXPECT_EQ(NON_SYS_ANON_DVID, result.uid_);
    // name_   → first UTF-8 char + DEFAULT_ANON_STR
    EXPECT_EQ(std::string("T**********"), result.name_);
    // nickname_ → first UTF-8 char + DEFAULT_ANON_STR
    EXPECT_EQ(std::string("N**********"), result.nickname_);
    // avatar_ → DEFAULT_ANON_STR
    EXPECT_EQ(std::string("**********"), result.avatar_);
    // scalableData_ → cleared
    EXPECT_EQ(TEST_EMPTY_STR, result.scalableData_);
    // status_ unchanged
    EXPECT_EQ(result.status_, ACCOUNT_STATE_LOGIN);

    ASSERT_TRUE(RecoveryPermission(tokenId, selfTokenId));
}

// ======================================================================
// Not-logged-in scenarios: logoff first so uid_ == DEFAULT_OHOS_ACCOUNT_UID
// ======================================================================

class OhosAccountKitsImplNotLoggedInTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        ASSERT_TRUE(GetAllAccountPermission());
        // Ensure clean state — no distributed account logged in
    }

    void SetUp() override {}
    void TearDown() override {}
};

HWTEST_F(OhosAccountKitsImplNotLoggedInTest, User0_NotLoggedIn_GetOhosAccountInfo_Default, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_0));
    OhosAccountInfo result;
    ASSERT_EQ(ERR_OK, OhosAccountKits::GetInstance().GetOhosAccountInfo(result));
    EXPECT_EQ(result.uid_, DEFAULT_OHOS_ACCOUNT_UID);
    EXPECT_EQ(result.name_, DEFAULT_OHOS_ACCOUNT_NAME);
    EXPECT_EQ(result.status_, ACCOUNT_STATE_UNBOUND);
    EXPECT_EQ(result.nickname_, TEST_EMPTY_STR);
    EXPECT_EQ(result.avatar_, TEST_EMPTY_STR);
    EXPECT_EQ(result.scalableData_, TEST_EMPTY_STR);
}

HWTEST_F(OhosAccountKitsImplNotLoggedInTest, User0_NotLoggedIn_QueryOhosAccountInfo, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_0));
    auto ret = OhosAccountKits::GetInstance().QueryOhosAccountInfo();
    EXPECT_TRUE(ret.first);
    EXPECT_EQ(ret.second.uid_, DEFAULT_OHOS_ACCOUNT_UID);
    EXPECT_EQ(ret.second.name_, DEFAULT_OHOS_ACCOUNT_NAME);
    EXPECT_EQ(ret.second.status_, ACCOUNT_STATE_UNBOUND);
}

HWTEST_F(OhosAccountKitsImplNotLoggedInTest, User0_NotLoggedIn_DvidEmpty, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_0));
    std::string dvid;
    ASSERT_EQ(ERR_OK,
        OhosAccountKitsImpl::GetInstance().QueryDistributedVirtualDeviceId(dvid));
    // uid == DEFAULT_OHOS_ACCOUNT_UID → service returns ERR_OK with empty dvid
    EXPECT_TRUE(dvid.empty());
}

HWTEST_F(OhosAccountKitsImplNotLoggedInTest, User0_NotLoggedIn_QueryDeviceAccountId, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_0));
    std::int32_t accountId = -1;
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().QueryDeviceAccountId(accountId));
    EXPECT_EQ(0, accountId);
}

HWTEST_F(OhosAccountKitsImplNotLoggedInTest, User100_NotLoggedIn_GetOhosAccountInfo_Default, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_100));
    OhosAccountInfo result;
    ASSERT_EQ(ERR_OK, OhosAccountKits::GetInstance().GetOhosAccountInfo(result));
    EXPECT_EQ(result.uid_, DEFAULT_OHOS_ACCOUNT_UID);
    EXPECT_EQ(result.name_, DEFAULT_OHOS_ACCOUNT_NAME);
    EXPECT_EQ(result.status_, ACCOUNT_STATE_UNBOUND);
    EXPECT_EQ(result.nickname_, TEST_EMPTY_STR);
    EXPECT_EQ(result.avatar_, TEST_EMPTY_STR);
    EXPECT_EQ(result.scalableData_, TEST_EMPTY_STR);
}

HWTEST_F(OhosAccountKitsImplNotLoggedInTest, User100_NotLoggedIn_QueryOhosAccountInfo, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_100));
    auto ret = OhosAccountKits::GetInstance().QueryOhosAccountInfo();
    EXPECT_TRUE(ret.first);
    EXPECT_EQ(ret.second.uid_, DEFAULT_OHOS_ACCOUNT_UID);
    EXPECT_EQ(ret.second.name_, DEFAULT_OHOS_ACCOUNT_NAME);
    EXPECT_EQ(ret.second.status_, ACCOUNT_STATE_UNBOUND);
}

HWTEST_F(OhosAccountKitsImplNotLoggedInTest, User100_NotLoggedIn_DvidEmpty, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_100));
    std::string dvid;
    ASSERT_EQ(ERR_OK,
        OhosAccountKitsImpl::GetInstance().QueryDistributedVirtualDeviceId(dvid));
    EXPECT_TRUE(dvid.empty());
}

HWTEST_F(OhosAccountKitsImplNotLoggedInTest, User100_NotLoggedIn_QueryDeviceAccountId, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_100));
    std::int32_t accountId = -1;
    EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().QueryDeviceAccountId(accountId));
    EXPECT_EQ(100, accountId);
}

// ======================================================================
// Not-logged-in — User 100 补充: GetOsAccountDistributedInfo, QueryOsAccountDistributedInfo,
// Not-logged-in — 补充: QueryDistributedVirtualDeviceId_WithParams
// ======================================================================

HWTEST_F(OhosAccountKitsImplNotLoggedInTest, User100_NotLoggedIn_GetOsAccountDistributedInfo, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_100));
    OhosAccountInfo result;
    ASSERT_EQ(ERR_OK, OhosAccountKits::GetInstance().GetOsAccountDistributedInfo(
        DEFAULT_USER_ID, result));
    EXPECT_EQ(result.uid_, DEFAULT_OHOS_ACCOUNT_UID);
    EXPECT_EQ(result.name_, DEFAULT_OHOS_ACCOUNT_NAME);
    EXPECT_EQ(result.status_, ACCOUNT_STATE_UNBOUND);
    EXPECT_EQ(result.nickname_, TEST_EMPTY_STR);
    EXPECT_EQ(result.avatar_, TEST_EMPTY_STR);
    EXPECT_EQ(result.scalableData_, TEST_EMPTY_STR);
}

HWTEST_F(OhosAccountKitsImplNotLoggedInTest, User100_NotLoggedIn_QueryOsAccountDistributedInfo_Pair, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_100));
    auto ret = OhosAccountKits::GetInstance().QueryOsAccountDistributedInfo(DEFAULT_USER_ID);
    EXPECT_TRUE(ret.first);
    EXPECT_EQ(ret.second.uid_, DEFAULT_OHOS_ACCOUNT_UID);
    EXPECT_EQ(ret.second.name_, DEFAULT_OHOS_ACCOUNT_NAME);
    EXPECT_EQ(ret.second.status_, ACCOUNT_STATE_UNBOUND);
}

HWTEST_F(OhosAccountKitsImplNotLoggedInTest, User100_NotLoggedIn_QueryOsAccountDistributedInfo_ErrCode, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_100));
    OhosAccountInfo info;
    ASSERT_EQ(ERR_OK, OhosAccountKitsImpl::GetInstance().QueryOsAccountDistributedInfo(
        DEFAULT_USER_ID, info));
    EXPECT_EQ(info.uid_, DEFAULT_OHOS_ACCOUNT_UID);
    EXPECT_EQ(info.name_, DEFAULT_OHOS_ACCOUNT_NAME);
    EXPECT_EQ(info.status_, ACCOUNT_STATE_UNBOUND);
}

HWTEST_F(OhosAccountKitsImplNotLoggedInTest, User100_NotLoggedIn_Dvid_WithParams_Empty, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_100));
    std::string dvid;
    ASSERT_EQ(ERR_OK,
        OhosAccountKitsImpl::GetInstance().QueryDistributedVirtualDeviceId(
            "com.test.bundle", DEFAULT_USER_ID, dvid));
    EXPECT_TRUE(dvid.empty());
}

// rawUid == DEFAULT_OHOS_ACCOUNT_UID → GetOhosAccountDistributedInfo returns early,
// anonymization is skipped even for non-system apps.
HWTEST_F(OhosAccountKitsImplNotLoggedInTest, NonSystemApp_NotLoggedIn_NoAnonymization, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_0));
    uint64_t selfTokenId = IPCSkeleton::GetSelfTokenID();
    uint64_t tokenId = 0;
    ASSERT_TRUE(AllocPermission(
        {"ohos.permission.GET_DISTRIBUTED_ACCOUNTS"}, tokenId, false));

    OhosAccountInfo result;
    ASSERT_EQ(ERR_OK, OhosAccountKits::GetInstance().GetOhosAccountInfo(result));
    EXPECT_EQ(result.uid_, DEFAULT_OHOS_ACCOUNT_UID);
    EXPECT_EQ(result.name_, DEFAULT_OHOS_ACCOUNT_NAME);
    EXPECT_EQ(result.status_, ACCOUNT_STATE_UNBOUND);
    EXPECT_EQ(result.nickname_, TEST_EMPTY_STR);
    EXPECT_EQ(result.avatar_, TEST_EMPTY_STR);
    EXPECT_EQ(result.scalableData_, TEST_EMPTY_STR);

    ASSERT_TRUE(RecoveryPermission(tokenId, selfTokenId));
}

// ======================================================================
// Not-logged-in — User 0 补充: GetOsAccountDistributedInfo, QueryOsAccountDistributedInfo,
// Not-logged-in — 补充: QueryDistributedVirtualDeviceId_WithParams
// ======================================================================

HWTEST_F(OhosAccountKitsImplNotLoggedInTest, User0_NotLoggedIn_GetOsAccountDistributedInfo, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_0));
    OhosAccountInfo result;
    ASSERT_EQ(ERR_OK, OhosAccountKits::GetInstance().GetOsAccountDistributedInfo(
        DEFAULT_USER_ID, result));
    EXPECT_EQ(result.uid_, DEFAULT_OHOS_ACCOUNT_UID);
    EXPECT_EQ(result.name_, DEFAULT_OHOS_ACCOUNT_NAME);
    EXPECT_EQ(result.status_, ACCOUNT_STATE_UNBOUND);
    EXPECT_EQ(result.nickname_, TEST_EMPTY_STR);
    EXPECT_EQ(result.avatar_, TEST_EMPTY_STR);
    EXPECT_EQ(result.scalableData_, TEST_EMPTY_STR);
}

HWTEST_F(OhosAccountKitsImplNotLoggedInTest, User0_NotLoggedIn_QueryOsAccountDistributedInfo_Pair, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_0));
    auto ret = OhosAccountKits::GetInstance().QueryOsAccountDistributedInfo(DEFAULT_USER_ID);
    EXPECT_TRUE(ret.first);
    EXPECT_EQ(ret.second.uid_, DEFAULT_OHOS_ACCOUNT_UID);
    EXPECT_EQ(ret.second.name_, DEFAULT_OHOS_ACCOUNT_NAME);
    EXPECT_EQ(ret.second.status_, ACCOUNT_STATE_UNBOUND);
}

HWTEST_F(OhosAccountKitsImplNotLoggedInTest, User0_NotLoggedIn_QueryOsAccountDistributedInfo_ErrCode, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_0));
    OhosAccountInfo info;
    ASSERT_EQ(ERR_OK, OhosAccountKitsImpl::GetInstance().QueryOsAccountDistributedInfo(
        DEFAULT_USER_ID, info));
    EXPECT_EQ(info.uid_, DEFAULT_OHOS_ACCOUNT_UID);
    EXPECT_EQ(info.name_, DEFAULT_OHOS_ACCOUNT_NAME);
    EXPECT_EQ(info.status_, ACCOUNT_STATE_UNBOUND);
}


HWTEST_F(OhosAccountKitsImplNotLoggedInTest, User0_NotLoggedIn_Dvid_WithParams_Empty, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_0));
    std::string dvid;
    ASSERT_EQ(ERR_OK,
        OhosAccountKitsImpl::GetInstance().QueryDistributedVirtualDeviceId(
            "com.test.bundle", DEFAULT_USER_ID, dvid));
    EXPECT_TRUE(dvid.empty());
}

// ======================================================================
// OsAccountSubProfileClient — newly added interfaces test
// ======================================================================

class OsAccountSubProfileClientTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        ASSERT_TRUE(GetAllAccountPermission());
        OhosAccountInfo loginInfo = BuildTestAccountInfo();
        ASSERT_EQ(ERR_OK, OhosAccountKits::GetInstance().SetOsAccountDistributedInfo(
            DEFAULT_USER_ID, loginInfo, OHOS_ACCOUNT_EVENT_LOGIN));
    }

    static void TearDownTestCase()
    {
        OhosAccountInfo logoffInfo;
        logoffInfo.name_ = TEST_ACCOUNT_NAME;
        logoffInfo.uid_ = TEST_ACCOUNT_UID;
        EXPECT_EQ(ERR_OK, OhosAccountKits::GetInstance().SetOsAccountDistributedInfo(
            DEFAULT_USER_ID, logoffInfo, OHOS_ACCOUNT_EVENT_LOGOUT));
    }

    void SetUp() override {}
    void TearDown() override {}
};

// ===== A. GetOsAccountForegroundSubProfileId =====

HWTEST_F(OsAccountSubProfileClientTest, FgSubProfileId_NoParam_NotSystemApp, TestSize.Level0)
{
    uint64_t tokenId = 0;
    uint64_t selfTokenId = IPCSkeleton::GetSelfTokenID();
    ASSERT_TRUE(AllocPermission({}, tokenId, false));
    int32_t subProfileId = -1;
    ErrCode ret = OsAccountSubProfileClient::GetInstance().GetOsAccountForegroundSubProfileId(subProfileId);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR);
    ASSERT_TRUE(RecoveryPermission(tokenId, selfTokenId));
}

HWTEST_F(OsAccountSubProfileClientTest, FgSubProfileId_NoParam_Success, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_100));
    int32_t subProfileId = -1;
    ErrCode ret = OsAccountSubProfileClient::GetInstance().GetOsAccountForegroundSubProfileId(subProfileId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(subProfileId, TEST_SUB_PROFILE_ID_BASE);
}

HWTEST_F(OsAccountSubProfileClientTest, FgSubProfileId_WithParam_NotSystemApp, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_0));
    uint64_t tokenId = 0;
    uint64_t selfTokenId = IPCSkeleton::GetSelfTokenID();
    ASSERT_TRUE(AllocPermission({}, tokenId, false));
    int32_t subProfileId = -1;
    ErrCode ret = OsAccountSubProfileClient::GetInstance().GetOsAccountForegroundSubProfileId(
        TEST_OS_ACCOUNT_ID, subProfileId);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR);
    ASSERT_TRUE(RecoveryPermission(tokenId, selfTokenId));
}

HWTEST_F(OsAccountSubProfileClientTest, FgSubProfileId_WithParam_AccountNotExist, TestSize.Level0)
{
    int32_t subProfileId = -1;
    ErrCode ret = OsAccountSubProfileClient::GetInstance().GetOsAccountForegroundSubProfileId(
        TEST_NON_EXIST_ACCOUNT_ID, subProfileId);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

HWTEST_F(OsAccountSubProfileClientTest, FgSubProfileId_WithParam_U0, TestSize.Level0)
{
    int32_t subProfileId = -1;
    ErrCode ret = OsAccountSubProfileClient::GetInstance().GetOsAccountForegroundSubProfileId(
        0, subProfileId);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND);
}

HWTEST_F(OsAccountSubProfileClientTest, FgSubProfileId_WithParam_Success, TestSize.Level0)
{
    int32_t subProfileId = -1;
    ErrCode ret = OsAccountSubProfileClient::GetInstance().GetOsAccountForegroundSubProfileId(
        TEST_OS_ACCOUNT_ID, subProfileId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(subProfileId, TEST_SUB_PROFILE_ID_BASE);
}

// ===== B. GetOsAccountSubProfileIds =====

HWTEST_F(OsAccountSubProfileClientTest, SubProfileIds_NoParam_NotSystemApp, TestSize.Level0)
{
    uint64_t tokenId = 0;
    uint64_t selfTokenId = IPCSkeleton::GetSelfTokenID();
    ASSERT_TRUE(AllocPermission({}, tokenId, false));
    std::vector<int32_t> subProfileIds;
    ErrCode ret = OsAccountSubProfileClient::GetInstance().GetOsAccountSubProfileIds(subProfileIds);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR);
    ASSERT_TRUE(RecoveryPermission(tokenId, selfTokenId));
}

HWTEST_F(OsAccountSubProfileClientTest, SubProfileIds_NoParam_NoPermission, TestSize.Level0)
{
    uint64_t tokenId = 0;
    uint64_t selfTokenId = IPCSkeleton::GetSelfTokenID();
    ASSERT_TRUE(AllocPermission({"ohos.permission.GET_LOCAL_ACCOUNTS"}, tokenId, true));
    ASSERT_EQ(0, setuid(UID_USER_100));
    std::vector<int32_t> subProfileIds;
    ErrCode ret = OsAccountSubProfileClient::GetInstance().GetOsAccountSubProfileIds(subProfileIds);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    ASSERT_EQ(0, setuid(UID_USER_0));
    ASSERT_TRUE(RecoveryPermission(tokenId, selfTokenId));
}

HWTEST_F(OsAccountSubProfileClientTest, SubProfileIds_NoParam_Success, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_100));
    std::vector<int32_t> subProfileIds;
    ErrCode ret = OsAccountSubProfileClient::GetInstance().GetOsAccountSubProfileIds(subProfileIds);
    EXPECT_EQ(ret, ERR_OK);
    ASSERT_EQ(0, setuid(UID_USER_0));
}

HWTEST_F(OsAccountSubProfileClientTest, SubProfileIds_WithParam_NotSystemApp, TestSize.Level0)
{
    uint64_t tokenId = 0;
    uint64_t selfTokenId = IPCSkeleton::GetSelfTokenID();
    ASSERT_TRUE(AllocPermission({}, tokenId, false));
    std::vector<int32_t> subProfileIds;
    ErrCode ret = OsAccountSubProfileClient::GetInstance().GetOsAccountSubProfileIds(TEST_OS_ACCOUNT_ID, subProfileIds);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR);
    ASSERT_TRUE(RecoveryPermission(tokenId, selfTokenId));
}

HWTEST_F(OsAccountSubProfileClientTest, SubProfileIds_WithParam_NoPermission, TestSize.Level0)
{
    uint64_t tokenId = 0;
    uint64_t selfTokenId = IPCSkeleton::GetSelfTokenID();
    ASSERT_TRUE(AllocPermission({"ohos.permission.GET_LOCAL_ACCOUNTS"}, tokenId, true));
    std::vector<int32_t> subProfileIds;
    ErrCode ret = OsAccountSubProfileClient::GetInstance().GetOsAccountSubProfileIds(TEST_OS_ACCOUNT_ID, subProfileIds);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    ASSERT_TRUE(RecoveryPermission(tokenId, selfTokenId));
}

HWTEST_F(OsAccountSubProfileClientTest, SubProfileIds_WithParam_AccountNotExist, TestSize.Level0)
{
    std::vector<int32_t> subProfileIds;
    ErrCode ret = OsAccountSubProfileClient::GetInstance().GetOsAccountSubProfileIds(
        TEST_NON_EXIST_ACCOUNT_ID, subProfileIds);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
}

HWTEST_F(OsAccountSubProfileClientTest, SubProfileIds_WithParam_AccountRestricted, TestSize.Level0)
{
    std::vector<int32_t> subProfileIds;
    ErrCode ret = OsAccountSubProfileClient::GetInstance().GetOsAccountSubProfileIds(
        0, subProfileIds);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(subProfileIds.empty());
}

HWTEST_F(OsAccountSubProfileClientTest, SubProfileIds_WithParam_Success, TestSize.Level0)
{
    std::vector<int32_t> subProfileIds;
    ErrCode ret = OsAccountSubProfileClient::GetInstance().GetOsAccountSubProfileIds(TEST_OS_ACCOUNT_ID, subProfileIds);
    EXPECT_EQ(ret, ERR_OK);
}

// ===== C. GetOsAccountLocalIdForSubProfile =====

HWTEST_F(OsAccountSubProfileClientTest, LocalIdForSubProfile_NotSystemApp, TestSize.Level0)
{
    uint64_t tokenId = 0;
    uint64_t selfTokenId = IPCSkeleton::GetSelfTokenID();
    ASSERT_TRUE(AllocPermission({}, tokenId, false));
    int32_t osAccountId = -1;
    ErrCode ret = OsAccountSubProfileClient::GetInstance().GetOsAccountLocalIdForSubProfile(
        TEST_SUB_PROFILE_ID_BASE, osAccountId);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR);
    ASSERT_TRUE(RecoveryPermission(tokenId, selfTokenId));
}

HWTEST_F(OsAccountSubProfileClientTest, LocalIdForSubProfile_Success, TestSize.Level0)
{
    int32_t osAccountId = -1;
    ErrCode ret = OsAccountSubProfileClient::GetInstance().GetOsAccountLocalIdForSubProfile(
        TEST_SUB_PROFILE_ID_BASE, osAccountId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(osAccountId, TEST_OS_ACCOUNT_ID);
}

HWTEST_F(OsAccountSubProfileClientTest, LocalIdForSubProfile_NotExistSubProfileID, TestSize.Level0)
{
    int32_t osAccountId = -1;
    ErrCode ret = OsAccountSubProfileClient::GetInstance().GetOsAccountLocalIdForSubProfile(
        TEST_SUB_PROFILE_ID_MISMATCH, osAccountId);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND);
}

HWTEST_F(OsAccountSubProfileClientTest, LocalIdForSubProfile_RestrictedAccount, TestSize.Level0)
{
    int32_t osAccountId = -1;
    ErrCode ret = OsAccountSubProfileClient::GetInstance().GetOsAccountLocalIdForSubProfile(0, osAccountId);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND);
}

// ===== D. GetOsAccountSubProfile (2-param overload) =====

HWTEST_F(OsAccountSubProfileClientTest, SubProfile_TwoParam_NotSystemApp, TestSize.Level0)
{
    uint64_t tokenId = 0;
    uint64_t selfTokenId = IPCSkeleton::GetSelfTokenID();
    ASSERT_TRUE(AllocPermission({}, tokenId, false));
    OsAccountSubspaceResult subspaceResult;
    OhosAccountInfo distributedInfo;
    ErrCode ret = OsAccountSubProfileClient::GetInstance().GetOsAccountSubProfile(
        TEST_SUB_PROFILE_ID_BASE, subspaceResult, distributedInfo);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR);
    ASSERT_TRUE(RecoveryPermission(tokenId, selfTokenId));
}

HWTEST_F(OsAccountSubProfileClientTest, SubProfile_TwoParam_NoPermission, TestSize.Level0)
{
    uint64_t tokenId = 0;
    uint64_t selfTokenId = IPCSkeleton::GetSelfTokenID();
    ASSERT_TRUE(AllocPermission({"ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS"}, tokenId, true));
    ASSERT_EQ(0, setuid(UID_USER_100));
    OsAccountSubspaceResult subspaceResult;
    OhosAccountInfo distributedInfo;
    ErrCode ret = OsAccountSubProfileClient::GetInstance().GetOsAccountSubProfile(
        TEST_SUB_PROFILE_ID_BASE, subspaceResult, distributedInfo);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    ASSERT_EQ(0, setuid(UID_USER_0));
    ASSERT_TRUE(RecoveryPermission(tokenId, selfTokenId));
}

HWTEST_F(OsAccountSubProfileClientTest, SubProfile_TwoParam_OwnershipMismatch, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_100));
    OsAccountSubspaceResult subspaceResult;
    OhosAccountInfo distributedInfo;
    ErrCode ret = OsAccountSubProfileClient::GetInstance().GetOsAccountSubProfile(
        TEST_SUB_PROFILE_ID_MISMATCH, subspaceResult, distributedInfo);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND);
    ASSERT_EQ(0, setuid(UID_USER_0));
}

HWTEST_F(OsAccountSubProfileClientTest, SubProfile_TwoParam_SubProfileZeroOwnershipMismatch, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_100));
    OsAccountSubspaceResult subspaceResult;
    OhosAccountInfo distributedInfo;
    ErrCode ret = OsAccountSubProfileClient::GetInstance().GetOsAccountSubProfile(0, subspaceResult, distributedInfo);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND);
    ASSERT_EQ(0, setuid(UID_USER_0));
}

HWTEST_F(OsAccountSubProfileClientTest, SubProfile_TwoParam_Success, TestSize.Level0)
{
    ASSERT_EQ(0, setuid(UID_USER_100));
    OsAccountSubspaceResult subspaceResult;
    OhosAccountInfo distributedInfo;
    ErrCode ret = OsAccountSubProfileClient::GetInstance().GetOsAccountSubProfile(
        TEST_SUB_PROFILE_ID_BASE, subspaceResult, distributedInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(subspaceResult.id, TEST_SUB_PROFILE_ID_BASE);
    EXPECT_EQ(subspaceResult.osAccountId, TEST_OS_ACCOUNT_ID);
    EXPECT_EQ(subspaceResult.index, 0);
    EXPECT_EQ(distributedInfo.name_, TEST_ACCOUNT_NAME);
    EXPECT_EQ(distributedInfo.uid_, TEST_EXPECTED_UID);
    EXPECT_EQ(distributedInfo.status_, ACCOUNT_STATE_LOGIN);
    ASSERT_EQ(0, setuid(UID_USER_0));
}

// ===== D. GetOsAccountSubProfile (4-param overload) =====

HWTEST_F(OsAccountSubProfileClientTest, SubProfile_FourParam_NotSystemApp, TestSize.Level0)
{
    uint64_t tokenId = 0;
    uint64_t selfTokenId = IPCSkeleton::GetSelfTokenID();
    ASSERT_TRUE(AllocPermission({}, tokenId, false));
    OsAccountSubspaceResult subspaceResult;
    OhosAccountInfo distributedInfo;
    ErrCode ret = OsAccountSubProfileClient::GetInstance().GetOsAccountSubProfile(
        TEST_OS_ACCOUNT_ID, TEST_SUB_PROFILE_ID_BASE, subspaceResult, distributedInfo);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_NOT_SYSTEM_APP_ERROR);
    ASSERT_TRUE(RecoveryPermission(tokenId, selfTokenId));
}

HWTEST_F(OsAccountSubProfileClientTest, SubProfile_FourParam_BothPermsDenied, TestSize.Level0)
{
    uint64_t tokenId = 0;
    uint64_t selfTokenId = IPCSkeleton::GetSelfTokenID();
    ASSERT_TRUE(AllocPermission({}, tokenId, true));
    OsAccountSubspaceResult subspaceResult;
    OhosAccountInfo distributedInfo;
    ErrCode ret = OsAccountSubProfileClient::GetInstance().GetOsAccountSubProfile(
        TEST_OS_ACCOUNT_ID, TEST_SUB_PROFILE_ID_BASE, subspaceResult, distributedInfo);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    ASSERT_TRUE(RecoveryPermission(tokenId, selfTokenId));
}

HWTEST_F(OsAccountSubProfileClientTest, SubProfile_FourParam_OnlyGetLocalAccounts, TestSize.Level0)
{
    uint64_t tokenId = 0;
    uint64_t selfTokenId = IPCSkeleton::GetSelfTokenID();
    ASSERT_TRUE(AllocPermission({"ohos.permission.GET_LOCAL_ACCOUNTS"}, tokenId, true));
    OsAccountSubspaceResult subspaceResult;
    OhosAccountInfo distributedInfo;
    ErrCode ret = OsAccountSubProfileClient::GetInstance().GetOsAccountSubProfile(
        TEST_OS_ACCOUNT_ID, TEST_SUB_PROFILE_ID_BASE, subspaceResult, distributedInfo);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    ASSERT_TRUE(RecoveryPermission(tokenId, selfTokenId));
}

HWTEST_F(OsAccountSubProfileClientTest, SubProfile_FourParam_OnlyInteractAcross, TestSize.Level0)
{
    uint64_t tokenId = 0;
    uint64_t selfTokenId = IPCSkeleton::GetSelfTokenID();
    ASSERT_TRUE(AllocPermission({"ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS"}, tokenId, true));
    OsAccountSubspaceResult subspaceResult;
    OhosAccountInfo distributedInfo;
    ErrCode ret = OsAccountSubProfileClient::GetInstance().GetOsAccountSubProfile(
        TEST_OS_ACCOUNT_ID, TEST_SUB_PROFILE_ID_BASE, subspaceResult, distributedInfo);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    ASSERT_TRUE(RecoveryPermission(tokenId, selfTokenId));
}

HWTEST_F(OsAccountSubProfileClientTest, SubProfile_FourParam_OwnershipMismatch, TestSize.Level0)
{
    OsAccountSubspaceResult subspaceResult;
    OhosAccountInfo distributedInfo;
    ErrCode ret = OsAccountSubProfileClient::GetInstance().GetOsAccountSubProfile(
        TEST_OS_ACCOUNT_ID, TEST_SUB_PROFILE_ID_MISMATCH, subspaceResult, distributedInfo);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND);
}

HWTEST_F(OsAccountSubProfileClientTest, SubProfile_FourParam_AccountRestricted, TestSize.Level0)
{
    OsAccountSubspaceResult subspaceResult;
    OhosAccountInfo distributedInfo;
    ErrCode ret = OsAccountSubProfileClient::GetInstance().GetOsAccountSubProfile(0, 0,
        subspaceResult, distributedInfo);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND);
}

HWTEST_F(OsAccountSubProfileClientTest, SubProfile_FourParam_Success, TestSize.Level0)
{
    OsAccountSubspaceResult subspaceResult;
    OhosAccountInfo distributedInfo;
    ErrCode ret = OsAccountSubProfileClient::GetInstance().GetOsAccountSubProfile(
        TEST_OS_ACCOUNT_ID, TEST_SUB_PROFILE_ID_BASE, subspaceResult, distributedInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(subspaceResult.id, TEST_SUB_PROFILE_ID_BASE);
    EXPECT_EQ(subspaceResult.osAccountId, TEST_OS_ACCOUNT_ID);
    EXPECT_EQ(subspaceResult.index, 0);
    EXPECT_EQ(distributedInfo.name_, TEST_ACCOUNT_NAME);
    EXPECT_EQ(distributedInfo.uid_, TEST_EXPECTED_UID);
    EXPECT_EQ(distributedInfo.status_, ACCOUNT_STATE_LOGIN);
}
