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
#include "os_account_subspace_client.h"
#undef private

#include "account_error_no.h"
#include "os_account_subspace_stub.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace {
constexpr int32_t TEST_OS_ACCOUNT_ID = 100;
constexpr int32_t TEST_SUBSPACE_ID = 100001;
constexpr ErrCode ERR_EXPECTED_FAILURE = ERR_ACCOUNT_COMMON_INVALID_PARAMETER;

// Mock IOsAccountSubspace that overrides all three subspace operations.
// Inherits OsAccountSubspaceStub to provide valid AsObject() and IRemoteObject semantics.
class MockOsAccountSubspaceStub : public OsAccountSubspaceStub {
public:
    ErrCode CreateOsAccountSubspace(int32_t osAccountId, OsAccountSubspaceResult &result) override
    {
        lastCreateOsAccountId = osAccountId;
        result = createResult_;
        return createRet_;
    }

    ErrCode DeleteOsAccountSubspace(int32_t osAccountId, int32_t subspaceId) override
    {
        lastDeleteOsAccountId = osAccountId;
        lastDeleteSubspaceId = subspaceId;
        return deleteRet_;
    }

    ErrCode SwitchOsAccountSubspace(int32_t osAccountId, int32_t subspaceId) override
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

// ===== OsAccountSubspaceClientTest =====
class OsAccountSubspaceClientTest : public testing::Test {
public:
    void SetUp() override
    {
        OsAccountSubspaceClient::GetInstance().proxy_ = nullptr;
        OsAccountSubspaceClient::GetInstance().deathRecipient_ = nullptr;
    }
    void TearDown() override
    {
        OsAccountSubspaceClient::GetInstance().proxy_ = nullptr;
        OsAccountSubspaceClient::GetInstance().deathRecipient_ = nullptr;
    }
};

/**
 * @tc.name: OsAccountSubspaceClientTest_GetInstance_Singleton_001
 * @tc.desc: GetInstance returns the same instance on multiple calls.
 */
HWTEST_F(OsAccountSubspaceClientTest, GetInstance_Singleton_001, TestSize.Level1)
{
    OsAccountSubspaceClient &instance1 = OsAccountSubspaceClient::GetInstance();
    OsAccountSubspaceClient &instance2 = OsAccountSubspaceClient::GetInstance();
    EXPECT_EQ(&instance1, &instance2);
}

/**
 * @tc.name: OsAccountSubspaceClientTest_NoPermission_001
 * @tc.desc: CreateOsAccountSubspace returns PERMISSION_DENIED from proxy
 *           when the service denies access due to missing permission.
 */
HWTEST_F(OsAccountSubspaceClientTest, NoPermission_001, TestSize.Level1)
{
    sptr<MockOsAccountSubspaceStub> mockProxy = new (std::nothrow) MockOsAccountSubspaceStub();
    ASSERT_NE(mockProxy, nullptr);
    mockProxy->createRet_ = ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    OsAccountSubspaceClient::GetInstance().proxy_ = mockProxy;

    OsAccountSubspaceResult result;
    ErrCode ret = OsAccountSubspaceClient::GetInstance().CreateOsAccountSubspace(
        TEST_OS_ACCOUNT_ID, result);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    EXPECT_EQ(mockProxy->lastCreateOsAccountId, TEST_OS_ACCOUNT_ID);
}

/**
 * @tc.name: OsAccountSubspaceClientTest_CreateOsAccountSubspace_Success_001
 * @tc.desc: CreateOsAccountSubspace delegates to proxy when proxy is valid.
 */
HWTEST_F(OsAccountSubspaceClientTest, CreateOsAccountSubspace_Success_001, TestSize.Level1)
{
    sptr<MockOsAccountSubspaceStub> mockProxy = new (std::nothrow) MockOsAccountSubspaceStub();
    ASSERT_NE(mockProxy, nullptr);

    mockProxy->createRet_ = ERR_OK;
    mockProxy->createResult_.id = TEST_SUBSPACE_ID;
    mockProxy->createResult_.osAccountId = TEST_OS_ACCOUNT_ID;
    mockProxy->createResult_.index = 1;

    OsAccountSubspaceClient::GetInstance().proxy_ = mockProxy;

    OsAccountSubspaceResult result;
    ErrCode ret = OsAccountSubspaceClient::GetInstance().CreateOsAccountSubspace(
        TEST_OS_ACCOUNT_ID, result);

    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(mockProxy->lastCreateOsAccountId, TEST_OS_ACCOUNT_ID);
    EXPECT_EQ(result.id, TEST_SUBSPACE_ID);
    EXPECT_EQ(result.osAccountId, TEST_OS_ACCOUNT_ID);
    EXPECT_EQ(result.index, 1);
}

/**
 * @tc.name: OsAccountSubspaceClientTest_CreateOsAccountSubspace_ProxyError_001
 * @tc.desc: CreateOsAccountSubspace returns proxy error when proxy fails.
 */
HWTEST_F(OsAccountSubspaceClientTest, CreateOsAccountSubspace_ProxyError_001, TestSize.Level1)
{
    sptr<MockOsAccountSubspaceStub> mockProxy = new (std::nothrow) MockOsAccountSubspaceStub();
    ASSERT_NE(mockProxy, nullptr);

    mockProxy->createRet_ = ERR_EXPECTED_FAILURE;
    OsAccountSubspaceClient::GetInstance().proxy_ = mockProxy;

    OsAccountSubspaceResult result;
    ErrCode ret = OsAccountSubspaceClient::GetInstance().CreateOsAccountSubspace(
        TEST_OS_ACCOUNT_ID, result);

    EXPECT_EQ(ret, ERR_EXPECTED_FAILURE);
    EXPECT_EQ(mockProxy->lastCreateOsAccountId, TEST_OS_ACCOUNT_ID);
}

/**
 * @tc.name: OsAccountSubspaceClientTest_DeleteOsAccountSubspace_Success_001
 * @tc.desc: DeleteOsAccountSubspace delegates to proxy when proxy is valid.
 */
HWTEST_F(OsAccountSubspaceClientTest, DeleteOsAccountSubspace_Success_001, TestSize.Level1)
{
    sptr<MockOsAccountSubspaceStub> mockProxy = new (std::nothrow) MockOsAccountSubspaceStub();
    ASSERT_NE(mockProxy, nullptr);

    mockProxy->deleteRet_ = ERR_OK;
    OsAccountSubspaceClient::GetInstance().proxy_ = mockProxy;

    ErrCode ret = OsAccountSubspaceClient::GetInstance().DeleteOsAccountSubspace(
        TEST_OS_ACCOUNT_ID, TEST_SUBSPACE_ID);

    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(mockProxy->lastDeleteOsAccountId, TEST_OS_ACCOUNT_ID);
    EXPECT_EQ(mockProxy->lastDeleteSubspaceId, TEST_SUBSPACE_ID);
}

/**
 * @tc.name: OsAccountSubspaceClientTest_DeleteOsAccountSubspace_ProxyError_001
 * @tc.desc: DeleteOsAccountSubspace returns proxy error when proxy fails.
 */
HWTEST_F(OsAccountSubspaceClientTest, DeleteOsAccountSubspace_ProxyError_001, TestSize.Level1)
{
    sptr<MockOsAccountSubspaceStub> mockProxy = new (std::nothrow) MockOsAccountSubspaceStub();
    ASSERT_NE(mockProxy, nullptr);

    mockProxy->deleteRet_ = ERR_EXPECTED_FAILURE;
    OsAccountSubspaceClient::GetInstance().proxy_ = mockProxy;

    ErrCode ret = OsAccountSubspaceClient::GetInstance().DeleteOsAccountSubspace(
        TEST_OS_ACCOUNT_ID, TEST_SUBSPACE_ID);

    EXPECT_EQ(ret, ERR_EXPECTED_FAILURE);
    EXPECT_EQ(mockProxy->lastDeleteOsAccountId, TEST_OS_ACCOUNT_ID);
    EXPECT_EQ(mockProxy->lastDeleteSubspaceId, TEST_SUBSPACE_ID);
}

/**
 * @tc.name: OsAccountSubspaceClientTest_SwitchOsAccountSubspace_Success_001
 * @tc.desc: SwitchOsAccountSubspace delegates to proxy when proxy is valid.
 */
HWTEST_F(OsAccountSubspaceClientTest, SwitchOsAccountSubspace_Success_001, TestSize.Level1)
{
    sptr<MockOsAccountSubspaceStub> mockProxy = new (std::nothrow) MockOsAccountSubspaceStub();
    ASSERT_NE(mockProxy, nullptr);

    mockProxy->switchRet_ = ERR_OK;
    OsAccountSubspaceClient::GetInstance().proxy_ = mockProxy;

    ErrCode ret = OsAccountSubspaceClient::GetInstance().SwitchOsAccountSubspace(
        TEST_OS_ACCOUNT_ID, TEST_SUBSPACE_ID);

    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(mockProxy->lastSwitchOsAccountId, TEST_OS_ACCOUNT_ID);
    EXPECT_EQ(mockProxy->lastSwitchSubspaceId, TEST_SUBSPACE_ID);
}

/**
 * @tc.name: OsAccountSubspaceClientTest_SwitchOsAccountSubspace_ProxyError_001
 * @tc.desc: SwitchOsAccountSubspace returns proxy error when proxy fails.
 */
HWTEST_F(OsAccountSubspaceClientTest, SwitchOsAccountSubspace_ProxyError_001, TestSize.Level1)
{
    sptr<MockOsAccountSubspaceStub> mockProxy = new (std::nothrow) MockOsAccountSubspaceStub();
    ASSERT_NE(mockProxy, nullptr);

    mockProxy->switchRet_ = ERR_EXPECTED_FAILURE;
    OsAccountSubspaceClient::GetInstance().proxy_ = mockProxy;

    ErrCode ret = OsAccountSubspaceClient::GetInstance().SwitchOsAccountSubspace(
        TEST_OS_ACCOUNT_ID, TEST_SUBSPACE_ID);

    EXPECT_EQ(ret, ERR_EXPECTED_FAILURE);
    EXPECT_EQ(mockProxy->lastSwitchOsAccountId, TEST_OS_ACCOUNT_ID);
    EXPECT_EQ(mockProxy->lastSwitchSubspaceId, TEST_SUBSPACE_ID);
}

/**
 * @tc.name: OsAccountSubspaceClientTest_DeathRecipient_NullRemote_001
 * @tc.desc: OnRemoteDied with null remote returns early without crash.
 */
HWTEST_F(OsAccountSubspaceClientTest, DeathRecipient_NullRemote_001, TestSize.Level1)
{
    OsAccountSubspaceClient::OsAccountSubspaceDeathRecipient recipient;
    wptr<IRemoteObject> nullRemote = nullptr;
    EXPECT_NO_FATAL_FAILURE(recipient.OnRemoteDied(nullRemote));
}

/**
 * @tc.name: OsAccountSubspaceClientTest_GetOsAccountSubspaceProxy_CacheHit_001
 * @tc.desc: GetOsAccountSubspaceProxy returns cached proxy without creating a new one.
 */
HWTEST_F(OsAccountSubspaceClientTest, GetOsAccountSubspaceProxy_CacheHit_001, TestSize.Level1)
{
    sptr<MockOsAccountSubspaceStub> mockProxy = new (std::nothrow) MockOsAccountSubspaceStub();
    ASSERT_NE(mockProxy, nullptr);

    OsAccountSubspaceClient::GetInstance().proxy_ = mockProxy;

    auto result = OsAccountSubspaceClient::GetInstance().GetOsAccountSubspaceProxy();
    EXPECT_EQ(result.GetRefPtr(), mockProxy.GetRefPtr());
}

/**
 * @tc.name: OsAccountSubspaceClientTest_GetOsAccountSubspaceProxy_CacheMiss_001
 * @tc.desc: GetOsAccountSubspaceProxy returns nullptr on cache miss when
 *           the real service is not available (unit test environment).
 */
HWTEST_F(OsAccountSubspaceClientTest, GetOsAccountSubspaceProxy_CacheMiss_001, TestSize.Level1)
{
    // proxy_ is null after SetUp reset; no service running → nullptr returned
    auto result = OsAccountSubspaceClient::GetInstance().GetOsAccountSubspaceProxy();
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: OsAccountSubspaceClientTest_ResetProxy_NullProxy_001
 * @tc.desc: ResetProxy with proxy_ already null returns early without explosion.
 */
HWTEST_F(OsAccountSubspaceClientTest, ResetProxy_NullProxy_001, TestSize.Level1)
{
    wptr<IRemoteObject> remote = nullptr;
    EXPECT_NO_FATAL_FAILURE(
        OsAccountSubspaceClient::GetInstance().ResetProxy(remote));
    EXPECT_EQ(OsAccountSubspaceClient::GetInstance().proxy_, nullptr);
    EXPECT_EQ(OsAccountSubspaceClient::GetInstance().deathRecipient_, nullptr);
}

/**
 * @tc.name: OsAccountSubspaceClientTest_ResetProxy_ValidProxy_NoMatch_001
 * @tc.desc: ResetProxy clears proxy and deathRecipient even when remote does not match.
 */
HWTEST_F(OsAccountSubspaceClientTest, ResetProxy_ValidProxy_NoMatch_001, TestSize.Level1)
{
    sptr<MockOsAccountSubspaceStub> mockProxy = new (std::nothrow) MockOsAccountSubspaceStub();
    ASSERT_NE(mockProxy, nullptr);

    OsAccountSubspaceClient &client = OsAccountSubspaceClient::GetInstance();
    client.proxy_ = mockProxy;

    // Pass a null remote; AsObject() is not null but remote.promote() is null → no match,
    // but proxy and deathRecipient should still be cleared.
    wptr<IRemoteObject> remote = nullptr;
    EXPECT_NO_FATAL_FAILURE(client.ResetProxy(remote));
    EXPECT_EQ(client.proxy_, nullptr);
    EXPECT_EQ(client.deathRecipient_, nullptr);
}

#endif // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
