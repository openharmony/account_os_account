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

#include <gtest/gtest.h>

#define private public
#include "os_account_subprofile_client.h"
#undef private

#include "account_error_no.h"
#include "os_account_sub_profile_stub.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
constexpr int32_t TEST_OS_ACCOUNT_ID = 100;
constexpr int32_t TEST_SUBSPACE_ID = 100001;
constexpr ErrCode ERR_EXPECTED_FAILURE = ERR_ACCOUNT_COMMON_INVALID_PARAMETER;

// Mock IOsAccountSubProfile that overrides all three subspace operations.
// Inherits OsAccountSubProfileStub to provide valid AsObject() and IRemoteObject semantics.
class MockOsAccountSubProfileStub : public OsAccountSubProfileStub {
public:
    ErrCode CreateOsAccountSubProfile(int32_t osAccountId, OsAccountSubspaceResult &result) override
    {
        lastCreateOsAccountId = osAccountId;
        result = createResult_;
        return createRet_;
    }

    ErrCode DeleteOsAccountSubProfile(int32_t osAccountId, int32_t subspaceId) override
    {
        lastDeleteOsAccountId = osAccountId;
        lastDeleteSubspaceId = subspaceId;
        return deleteRet_;
    }

    ErrCode SwitchOsAccountSubProfile(int32_t osAccountId, int32_t subspaceId) override
    {
        lastSwitchOsAccountId = osAccountId;
        lastSwitchSubspaceId = subspaceId;
        return switchRet_;
    }

    ErrCode createRet_ = ERR_OK;
    ErrCode deleteRet_ = ERR_OK;
    ErrCode switchRet_ = ERR_OK;

    OsAccountSubspaceResult createResult_;
    int32_t lastCreateOsAccountId = -1;
    int32_t lastDeleteOsAccountId = -1;
    int32_t lastDeleteSubspaceId = -1;
    int32_t lastSwitchOsAccountId = -1;
    int32_t lastSwitchSubspaceId = -1;
};
} // namespace

// ===== OsAccountSubProfileClientTest =====
class OsAccountSubProfileClientTest : public testing::Test {
public:
    void SetUp() override
    {
        OsAccountSubProfileClient::GetInstance().proxy_ = nullptr;
        OsAccountSubProfileClient::GetInstance().deathRecipient_ = nullptr;
    }
    void TearDown() override
    {
        OsAccountSubProfileClient::GetInstance().proxy_ = nullptr;
        OsAccountSubProfileClient::GetInstance().deathRecipient_ = nullptr;
    }
};

/**
 * @tc.name: OsAccountSubProfileClientTest_GetInstance_Singleton_001
 * @tc.desc: GetInstance returns the same instance on multiple calls.
 */
HWTEST_F(OsAccountSubProfileClientTest, GetInstance_Singleton_001, TestSize.Level1)
{
    OsAccountSubProfileClient &instance1 = OsAccountSubProfileClient::GetInstance();
    OsAccountSubProfileClient &instance2 = OsAccountSubProfileClient::GetInstance();
    EXPECT_EQ(&instance1, &instance2);
}

/**
 * @tc.name: OsAccountSubProfileClientTest_NoPermission_001
 * @tc.desc: OsAccountSubProfileClient::CreateOsAccountSubProfile returns PERMISSION_DENIED from proxy
 *           when the service denies access due to missing permission.
 */
HWTEST_F(OsAccountSubProfileClientTest, NoPermission_001, TestSize.Level1)
{
    sptr<MockOsAccountSubProfileStub> mockProxy = new (std::nothrow) MockOsAccountSubProfileStub();
    ASSERT_NE(mockProxy, nullptr);
    mockProxy->createRet_ = ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    OsAccountSubProfileClient::GetInstance().proxy_ = mockProxy;

    OsAccountSubspaceResult result;
    ErrCode ret = OsAccountSubProfileClient::GetInstance().CreateOsAccountSubProfile(
        TEST_OS_ACCOUNT_ID, result);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    EXPECT_EQ(mockProxy->lastCreateOsAccountId, TEST_OS_ACCOUNT_ID);
}

/**
 * @tc.name: OsAccountSubProfileClientTest_CreateOsAccountSubProfile_Success_001
 * @tc.desc: CreateOsAccountSubProfile delegates to proxy when proxy is valid.
 */
HWTEST_F(OsAccountSubProfileClientTest, CreateOsAccountSubProfile_Success_001, TestSize.Level1)
{
    sptr<MockOsAccountSubProfileStub> mockProxy = new (std::nothrow) MockOsAccountSubProfileStub();
    ASSERT_NE(mockProxy, nullptr);

    mockProxy->createRet_ = ERR_OK;
    mockProxy->createResult_.id = TEST_SUBSPACE_ID;
    mockProxy->createResult_.osAccountId = TEST_OS_ACCOUNT_ID;
    mockProxy->createResult_.index = 1;

    OsAccountSubProfileClient::GetInstance().proxy_ = mockProxy;

    OsAccountSubspaceResult result;
    ErrCode ret = OsAccountSubProfileClient::GetInstance().CreateOsAccountSubProfile(
        TEST_OS_ACCOUNT_ID, result);

    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(mockProxy->lastCreateOsAccountId, TEST_OS_ACCOUNT_ID);
    EXPECT_EQ(result.id, TEST_SUBSPACE_ID);
    EXPECT_EQ(result.osAccountId, TEST_OS_ACCOUNT_ID);
    EXPECT_EQ(result.index, 1);
}

/**
 * @tc.name: OsAccountSubProfileClientTest_CreateOsAccountSubProfile_ProxyError_001
 * @tc.desc: OsAccountSubProfileClient::CreateOsAccountSubProfile returns proxy error when proxy fails.
 */
HWTEST_F(OsAccountSubProfileClientTest, CreateOsAccountSubProfile_ProxyError_001, TestSize.Level1)
{
    sptr<MockOsAccountSubProfileStub> mockProxy = new (std::nothrow) MockOsAccountSubProfileStub();
    ASSERT_NE(mockProxy, nullptr);

    mockProxy->createRet_ = ERR_EXPECTED_FAILURE;
    OsAccountSubProfileClient::GetInstance().proxy_ = mockProxy;

    OsAccountSubspaceResult result;
    ErrCode ret = OsAccountSubProfileClient::GetInstance().CreateOsAccountSubProfile(
        TEST_OS_ACCOUNT_ID, result);

    EXPECT_EQ(ret, ERR_EXPECTED_FAILURE);
    EXPECT_EQ(mockProxy->lastCreateOsAccountId, TEST_OS_ACCOUNT_ID);
}

/**
 * @tc.name: OsAccountSubProfileClientTest_DeleteOsAccountSubProfile_Success_001
 * @tc.desc: DeleteOsAccountSubProfile delegates to proxy when proxy is valid.
 */
HWTEST_F(OsAccountSubProfileClientTest, DeleteOsAccountSubProfile_Success_001, TestSize.Level1)
{
    sptr<MockOsAccountSubProfileStub> mockProxy = new (std::nothrow) MockOsAccountSubProfileStub();
    ASSERT_NE(mockProxy, nullptr);

    mockProxy->deleteRet_ = ERR_OK;
    OsAccountSubProfileClient::GetInstance().proxy_ = mockProxy;

    ErrCode ret = OsAccountSubProfileClient::GetInstance().DeleteOsAccountSubProfile(
        TEST_OS_ACCOUNT_ID, TEST_SUBSPACE_ID);

    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(mockProxy->lastDeleteOsAccountId, TEST_OS_ACCOUNT_ID);
    EXPECT_EQ(mockProxy->lastDeleteSubspaceId, TEST_SUBSPACE_ID);
}

/**
 * @tc.name: OsAccountSubProfileClientTest_DeleteOsAccountSubProfile_ProxyError_001
 * @tc.desc: DeleteOsAccountSubProfile returns proxy error when proxy fails.
 */
HWTEST_F(OsAccountSubProfileClientTest, DeleteOsAccountSubProfile_ProxyError_001, TestSize.Level1)
{
    sptr<MockOsAccountSubProfileStub> mockProxy = new (std::nothrow) MockOsAccountSubProfileStub();
    ASSERT_NE(mockProxy, nullptr);

    mockProxy->deleteRet_ = ERR_EXPECTED_FAILURE;
    OsAccountSubProfileClient::GetInstance().proxy_ = mockProxy;

    ErrCode ret = OsAccountSubProfileClient::GetInstance().DeleteOsAccountSubProfile(
        TEST_OS_ACCOUNT_ID, TEST_SUBSPACE_ID);

    EXPECT_EQ(ret, ERR_EXPECTED_FAILURE);
    EXPECT_EQ(mockProxy->lastDeleteOsAccountId, TEST_OS_ACCOUNT_ID);
    EXPECT_EQ(mockProxy->lastDeleteSubspaceId, TEST_SUBSPACE_ID);
}

/**
 * @tc.name: OsAccountSubProfileClientTest_SwitchOsAccountSubProfile_Success_001
 * @tc.desc: SwitchOsAccountSubProfile delegates to proxy when proxy is valid.
 */
HWTEST_F(OsAccountSubProfileClientTest, SwitchOsAccountSubProfile_Success_001, TestSize.Level1)
{
    sptr<MockOsAccountSubProfileStub> mockProxy = new (std::nothrow) MockOsAccountSubProfileStub();
    ASSERT_NE(mockProxy, nullptr);

    mockProxy->switchRet_ = ERR_OK;
    OsAccountSubProfileClient::GetInstance().proxy_ = mockProxy;

    ErrCode ret = OsAccountSubProfileClient::GetInstance().SwitchOsAccountSubProfile(
        TEST_OS_ACCOUNT_ID, TEST_SUBSPACE_ID);

    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(mockProxy->lastSwitchOsAccountId, TEST_OS_ACCOUNT_ID);
    EXPECT_EQ(mockProxy->lastSwitchSubspaceId, TEST_SUBSPACE_ID);
}

/**
 * @tc.name: OsAccountSubProfileClientTest_SwitchOsAccountSubProfile_ProxyError_001
 * @tc.desc: SwitchOsAccountSubProfile returns proxy error when proxy fails.
 */
HWTEST_F(OsAccountSubProfileClientTest, SwitchOsAccountSubProfile_ProxyError_001, TestSize.Level1)
{
    sptr<MockOsAccountSubProfileStub> mockProxy = new (std::nothrow) MockOsAccountSubProfileStub();
    ASSERT_NE(mockProxy, nullptr);

    mockProxy->switchRet_ = ERR_EXPECTED_FAILURE;
    OsAccountSubProfileClient::GetInstance().proxy_ = mockProxy;

    ErrCode ret = OsAccountSubProfileClient::GetInstance().SwitchOsAccountSubProfile(
        TEST_OS_ACCOUNT_ID, TEST_SUBSPACE_ID);

    EXPECT_EQ(ret, ERR_EXPECTED_FAILURE);
    EXPECT_EQ(mockProxy->lastSwitchOsAccountId, TEST_OS_ACCOUNT_ID);
    EXPECT_EQ(mockProxy->lastSwitchSubspaceId, TEST_SUBSPACE_ID);
}

/**
 * @tc.name: OsAccountSubProfileClientTest_GetOsAccountSubProfileProxy_CacheHit_001
 * @tc.desc: GetOsAccountSubProfileProxy returns cached proxy without creating a new one.
 */
HWTEST_F(OsAccountSubProfileClientTest, GetOsAccountSubProfileProxy_CacheHit_001, TestSize.Level1)
{
    sptr<MockOsAccountSubProfileStub> mockProxy = new (std::nothrow) MockOsAccountSubProfileStub();
    ASSERT_NE(mockProxy, nullptr);

    OsAccountSubProfileClient::GetInstance().proxy_ = mockProxy;

    auto result = OsAccountSubProfileClient::GetInstance().GetOsAccountSubProfileProxy();
    EXPECT_EQ(result.GetRefPtr(), mockProxy.GetRefPtr());
}

/**
 * @tc.name: OsAccountSubProfileClientTest_GetOsAccountSubProfileProxy_CacheMiss_001
 * @tc.desc: GetOsAccountSubProfileProxy returns nullptr on cache miss when
 *           the real service is not available (unit test environment).
 */
HWTEST_F(OsAccountSubProfileClientTest, GetOsAccountSubProfileProxy_CacheMiss_001, TestSize.Level1)
{
    // proxy_ is null after SetUp reset; no service running → nullptr returned
    auto result = OsAccountSubProfileClient::GetInstance().GetOsAccountSubProfileProxy();
    EXPECT_EQ(result, nullptr);
}
#endif // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
