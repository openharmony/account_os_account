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

#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "account_test_common.h"
#include <gtest/gtest.h>
#include "authorization_client.h"
#include "authorization_common.h"
#include "ipc_skeleton.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
const std::string ADMIN_NAME = "admin";
const std::string EMPTY_STRING = "";
}

class MockAdminAuthorizationCallback : public AdminAuthorizationCallback {
public:
    MockAdminAuthorizationCallback() = default;
    virtual ~MockAdminAuthorizationCallback() = default;
    int32_t OnResult(const AdminAuthorizationResult &result) override
    {
        result_ = result;
        callbackCalled_ = true;
        return ERR_OK;
    }

    bool IsCallbackCalled() const
    {
        return callbackCalled_;
    }

    const AdminAuthorizationResult &GetResult() const
    {
        return result_;
    }

    void Reset()
    {
        callbackCalled_ = false;
        result_ = AdminAuthorizationResult();
    }

private:
    bool callbackCalled_ = false;
    AdminAuthorizationResult result_;
};

class AcquireAdminAuthorizationTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AcquireAdminAuthorizationTest::SetUpTestCase(void)
{}

void AcquireAdminAuthorizationTest::TearDownTestCase(void)
{}

void AcquireAdminAuthorizationTest::SetUp(void) __attribute__((no_sanitize("cfi")))
{
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testinfo = test->current_test_info();
    ASSERT_NE(testinfo, nullptr);
    string testCaseName = string(testinfo->name());
    ACCOUNT_LOGI("[SetUp] %{public}s start", testCaseName.c_str());
}

void AcquireAdminAuthorizationTest::TearDown(void)
{}

#ifdef SUPPORT_AUTHORIZATION
/**
 * @tc.name: AcquireAdminAuthorization001
 * @tc.desc: Acquire admin authorization with null callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AcquireAdminAuthorizationTest, AcquireAdminAuthorization001, TestSize.Level0)
{
    std::string adminName = ADMIN_NAME;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    std::shared_ptr<AdminAuthorizationCallback> callback = nullptr;
    
    ErrCode errCode = AuthorizationClient::GetInstance().AcquireAdminAuthorization(
        adminName, challenge, callback);
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: AcquireAdminAuthorization002
 * @tc.desc: Acquire admin authorization with empty admin name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AcquireAdminAuthorizationTest, AcquireAdminAuthorization002, TestSize.Level0)
{
    std::string adminName = EMPTY_STRING;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    auto callback = std::make_shared<MockAdminAuthorizationCallback>();
    
    ErrCode errCode = AuthorizationClient::GetInstance().AcquireAdminAuthorization(
        adminName, challenge, callback);
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: AcquireAdminAuthorization003
 * @tc.desc: Acquire admin authorization with null callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AcquireAdminAuthorizationTest, AcquireAdminAuthorization003, TestSize.Level0)
{
    std::string adminName = ADMIN_NAME;
    std::vector<uint8_t> challenge = {};
    
    ErrCode errCode = AuthorizationClient::GetInstance().AcquireAdminAuthorization(
        adminName, challenge, nullptr);
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
}

/**
 * @tc.name: AcquireAdminAuthorization004
 * @tc.desc: Acquire admin authorization with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AcquireAdminAuthorizationTest, AcquireAdminAuthorization004, TestSize.Level0)
{
    std::string adminName = ADMIN_NAME;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    auto callback = std::make_shared<MockAdminAuthorizationCallback>();
    
    ErrCode errCode = AuthorizationClient::GetInstance().AcquireAdminAuthorization(
        adminName, challenge, callback);
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
}

/**
 * @tc.name: AcquireAdminAuthorization005
 * @tc.desc: Acquire admin authorization with PERMISSION_ACQUIRE_AUTHORIZATION
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AcquireAdminAuthorizationTest, AcquireAdminAuthorization005, TestSize.Level0)
{
    std::string adminName = ADMIN_NAME;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    auto callback = std::make_shared<MockAdminAuthorizationCallback>();

    std::vector<std::string> permissionList {
        "ohos.permission.ACQUIRE_LOCAL_ACCOUNT_AUTHORIZATION"
    };
    uint64_t selfTokenId = IPCSkeleton::GetSelfTokenID();
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission(permissionList, tokenID, false));

    ErrCode errCode = AuthorizationClient::GetInstance().AcquireAdminAuthorization(
        adminName, challenge, callback);
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    ASSERT_TRUE(RecoveryPermission(tokenID, selfTokenId));
}

/**
 * @tc.name: AcquireAdminAuthorization006
 * @tc.desc: Acquire admin authorization with PERMISSION_ACCESS_USER_AUTH_INTERNAL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AcquireAdminAuthorizationTest, AcquireAdminAuthorization006, TestSize.Level0)
{
    std::string adminName = ADMIN_NAME;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    auto callback = std::make_shared<MockAdminAuthorizationCallback>();

    std::vector<std::string> permissionList {
        "ohos.permission.ACCESS_USER_AUTH_INTERNAL"
    };
    uint64_t selfTokenId = IPCSkeleton::GetSelfTokenID();
    uint64_t tokenID;
    ASSERT_TRUE(AllocPermission(permissionList, tokenID, false));

    ErrCode errCode = AuthorizationClient::GetInstance().AcquireAdminAuthorization(
        adminName, challenge, callback);
    EXPECT_EQ(errCode, ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
    ASSERT_TRUE(RecoveryPermission(tokenID, selfTokenId));
}

#else
/**
 * @tc.name: AcquireAdminAuthorization001
 * @tc.desc: Acquire admin authorization without SUPPORT_AUTHORIZATION
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AcquireAdminAuthorizationTest, AcquireAdminAuthorization001, TestSize.Level0)
{
    std::string adminName = ADMIN_NAME;
    std::vector<uint8_t> challenge = {1, 2, 3, 4};
    auto callback = std::make_shared<MockAdminAuthorizationCallback>();
    
    ErrCode errCode = AuthorizationClient::GetInstance().AcquireAdminAuthorization(
        adminName, challenge, callback);
    EXPECT_EQ(errCode, ERR_AUTHORIZATION_NOT_SUPPORT);
}
#endif // SUPPORT_AUTHORIZATION

/**
 * @tc.name: AdminAuthorizationResult001
 * @tc.desc: Test AdminAuthorizationResult Marshalling and Unmarshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AcquireAdminAuthorizationTest, AdminAuthorizationResult001, TestSize.Level3)
{
    AdminAuthorizationResult result1;
    result1.resultCode = ERR_OK;
    result1.token = {0xFF, 0x00, 0xAA, 0x55};
    AdminAuthorizationResult result2 = result1;

    Parcel parcel;
    bool ret = result2.Marshalling(parcel);
    EXPECT_TRUE(ret);

    AdminAuthorizationResult* result = result2.Unmarshalling(parcel);
    ASSERT_NE(result, nullptr);
    std::shared_ptr<AdminAuthorizationResult> resultPtr(result);
    EXPECT_EQ(result->resultCode, ERR_OK);
    EXPECT_EQ(result->token.size(), 4);
    EXPECT_EQ(result->token[0], 0xFF);
    EXPECT_EQ(result->token[3], 0x55);
}

/**
 * @tc.name: AdminAuthorizationResult002
 * @tc.desc: Test AdminAuthorizationResult with empty token
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AcquireAdminAuthorizationTest, AdminAuthorizationResult002, TestSize.Level3)
{
    AdminAuthorizationResult result1;
    result1.resultCode = 12300301;
    result1.token = {};
    AdminAuthorizationResult result2 = result1;

    Parcel parcel;
    bool ret = result2.Marshalling(parcel);
    EXPECT_TRUE(ret);

    AdminAuthorizationResult* result = result2.Unmarshalling(parcel);
    ASSERT_NE(result, nullptr);
    std::shared_ptr<AdminAuthorizationResult> resultPtr(result);
    EXPECT_EQ(result->resultCode, 12300301);
    EXPECT_TRUE(result->token.empty());
}

/**
 * @tc.name: AdminAuthorizationResult003
 * @tc.desc: Test AdminAuthorizationResult with large token
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AcquireAdminAuthorizationTest, AdminAuthorizationResult003, TestSize.Level3)
{
    AdminAuthorizationResult result1;
    result1.resultCode = ERR_OK;
    result1.token = std::vector<uint8_t>(1000, 0xAB);
    AdminAuthorizationResult result2 = result1;

    Parcel parcel;
    bool ret = result2.Marshalling(parcel);
    EXPECT_TRUE(ret);

    AdminAuthorizationResult* result = result2.Unmarshalling(parcel);
    ASSERT_NE(result, nullptr);
    std::shared_ptr<AdminAuthorizationResult> resultPtr(result);
    EXPECT_EQ(result->resultCode, ERR_OK);
    EXPECT_EQ(result->token.size(), 1000);
    EXPECT_EQ(result->token[0], 0xAB);
    EXPECT_EQ(result->token[999], 0xAB);
}

/**
 * @tc.name: AdminAuthorizationResult004
 * @tc.desc: Test AdminAuthorizationResult ReadFromParcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AcquireAdminAuthorizationTest, AdminAuthorizationResult004, TestSize.Level3)
{
    AdminAuthorizationResult result1;
    result1.resultCode = ERR_OK;
    result1.token = {0x01, 0x02, 0x03, 0x04};

    Parcel parcel;
    bool ret = result1.Marshalling(parcel);
    EXPECT_TRUE(ret);

    AdminAuthorizationResult result2;
    ret = result2.ReadFromParcel(parcel);
    EXPECT_TRUE(ret);
    EXPECT_EQ(result2.resultCode, ERR_OK);
    EXPECT_EQ(result2.token.size(), 4);
    EXPECT_EQ(result2.token[0], 0x01);
    EXPECT_EQ(result2.token[3], 0x04);
}

/**
 * @tc.name: MockAdminAuthorizationCallback001
 * @tc.desc: Test MockAdminAuthorizationCallback basic functionality
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AcquireAdminAuthorizationTest, MockAdminAuthorizationCallback001, TestSize.Level3)
{
    auto callback = std::make_shared<MockAdminAuthorizationCallback>();
    
    EXPECT_FALSE(callback->IsCallbackCalled());
    
    AdminAuthorizationResult result;
    result.resultCode = ERR_OK;
    result.token = {0xFF, 0x00, 0xAA, 0x55};
    
    callback->OnResult(result);
    
    EXPECT_TRUE(callback->IsCallbackCalled());
    const AdminAuthorizationResult& callbackResult = callback->GetResult();
    EXPECT_EQ(callbackResult.resultCode, ERR_OK);
    EXPECT_EQ(callbackResult.token.size(), 4);
}

/**
 * @tc.name: MockAdminAuthorizationCallback002
 * @tc.desc: Test MockAdminAuthorizationCallback reset functionality
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AcquireAdminAuthorizationTest, MockAdminAuthorizationCallback002, TestSize.Level3)
{
    auto callback = std::make_shared<MockAdminAuthorizationCallback>();
    
    AdminAuthorizationResult result;
    result.resultCode = ERR_OK;
    result.token = {0xFF};
    
    callback->OnResult(result);
    EXPECT_TRUE(callback->IsCallbackCalled());
    
    callback->Reset();
    EXPECT_FALSE(callback->IsCallbackCalled());
    
    const AdminAuthorizationResult& callbackResult = callback->GetResult();
    EXPECT_EQ(callbackResult.resultCode, 0);
    EXPECT_TRUE(callbackResult.token.empty());
}

/**
 * @tc.name: MockAdminAuthorizationCallback003
 * @tc.desc: Test MockAdminAuthorizationCallback with multiple calls
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AcquireAdminAuthorizationTest, MockAdminAuthorizationCallback003, TestSize.Level3)
{
    auto callback = std::make_shared<MockAdminAuthorizationCallback>();
    
    AdminAuthorizationResult result1;
    result1.resultCode = ERR_OK;
    result1.token = {0x01};
    
    AdminAuthorizationResult result2;
    result2.resultCode = 12300301;
    result2.token = {0x02};
    
    callback->OnResult(result1);
    EXPECT_TRUE(callback->IsCallbackCalled());
    EXPECT_EQ(callback->GetResult().resultCode, ERR_OK);
    
    callback->Reset();
    callback->OnResult(result2);
    EXPECT_TRUE(callback->IsCallbackCalled());
    EXPECT_EQ(callback->GetResult().resultCode, 12300301);
}
