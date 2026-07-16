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
#include "os_account_sub_profile_subscribe_manager.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

// ===== Task 6: OsAccountSubProfileClient methods =====
class SubspaceClientTest : public testing::Test {
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
};

uint64_t SubspaceClientTest::allPermTokenId_ = 0;

HWTEST_F(SubspaceClientTest, GetOsAccountSubProfileProxy_ExistingProxy_001, TestSize.Level1)
{
    auto &client = OsAccountSubProfileClient::GetInstance();
    sptr<IRemoteObject> mockObj = new (std::nothrow) MockAccountMgrService();
    client.proxy_ = iface_cast<IOsAccountSubProfile>(mockObj);
    if (client.proxy_ != nullptr) {
        sptr<IOsAccountSubProfile> result = client.GetOsAccountSubProfileProxy();
        EXPECT_EQ(result, client.proxy_);
        client.proxy_ = nullptr;
        client.deathRecipient_ = nullptr;
    }
}

// ===== Task 7: OsAccountSubProfileManagerService supplement =====
class SubProfileManagerServiceTest : public testing::Test {
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
};

uint64_t SubProfileManagerServiceTest::allPermTokenId_ = 0;

HWTEST_F(SubProfileManagerServiceTest, CreateOsAccountSubProfile_RestrictedAccount_001, TestSize.Level1)
{
    OsAccountSubspaceResult result;
    auto service = std::make_shared<OsAccountSubProfileManagerService>();
    ErrCode ret = service->CreateOsAccountSubProfile(0, result);
    EXPECT_EQ(ret, ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR);
}

HWTEST_F(SubProfileManagerServiceTest, DeleteOsAccountSubProfile_RestrictedAccount_001, TestSize.Level1)
{
    auto service = std::make_shared<OsAccountSubProfileManagerService>();
    ErrCode ret = service->DeleteOsAccountSubProfile(0, 0 * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 1);
    EXPECT_NE(ret, ERR_OK);
}

HWTEST_F(SubProfileManagerServiceTest, SwitchOsAccountSubProfile_RestrictedAccount_001, TestSize.Level1)
{
    auto service = std::make_shared<OsAccountSubProfileManagerService>();
    ErrCode ret = service->SwitchOsAccountSubProfile(0, 0 * Constants::OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER + 1);
    EXPECT_NE(ret, ERR_OK);
}

HWTEST_F(SubProfileManagerServiceTest, DeleteOsAccountSubProfile_InvalidSubspaceId_001, TestSize.Level1)
{
    auto service = std::make_shared<OsAccountSubProfileManagerService>();
    ErrCode ret = service->DeleteOsAccountSubProfile(TEST_OS_ACCOUNT_ID, -1);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND);
}

HWTEST_F(SubProfileManagerServiceTest, SwitchOsAccountSubProfile_InvalidSubspaceId_001, TestSize.Level1)
{
    auto service = std::make_shared<OsAccountSubProfileManagerService>();
    ErrCode ret = service->SwitchOsAccountSubProfile(TEST_OS_ACCOUNT_ID, -1);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_NOT_FOUND);
}

HWTEST_F(SubProfileManagerServiceTest, CreateOsAccountSubProfile_Success_001, TestSize.Level1)
{
    const std::string testDir = "/data/test/os_account_subspace_coverage_test_svc/";
    std::error_code ec;
    std::filesystem::remove_all(testDir, ec);
    std::filesystem::create_directories(testDir);
    OsAccountSubProfileManager::GetInstance().Init(testDir);

    auto service = std::make_shared<OsAccountSubProfileManagerService>();
    OsAccountSubspaceResult result;
    ErrCode ret = service->CreateOsAccountSubProfile(TEST_OS_ACCOUNT_ID, result);
    EXPECT_EQ(ret, ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR);
    EXPECT_EQ(result.osAccountId, 0);
    EXPECT_EQ(result.index, -1);

    std::filesystem::remove_all(testDir, ec);
}

HWTEST_F(SubProfileManagerServiceTest, DeleteOsAccountSubProfile_Success_001, TestSize.Level1)
{
    ResetMockState();
    OsAccountInfo osAccountInfo;
    osAccountInfo.SetLocalId(TEST_OS_ACCOUNT_ID);
    MockSetCreatedOsAccounts({osAccountInfo});

    const std::string testDir = "/data/test/os_account_subspace_coverage_test_svc/";
    std::error_code ec;
    std::filesystem::remove_all(testDir, ec);
    std::filesystem::create_directories(testDir);
    OsAccountSubProfileManager::GetInstance().Init(testDir);

    OsAccountSubspaceResult createResult;
    ErrCode subRet = OhosAccountManager::GetInstance().CreateOsAccountSubspace(
        TEST_OS_ACCOUNT_ID, createResult);
    ASSERT_EQ(subRet, ERR_OK);
    ASSERT_NE(createResult.id, 0);

    auto service = std::make_shared<OsAccountSubProfileManagerService>();
    ErrCode ret = service->DeleteOsAccountSubProfile(TEST_OS_ACCOUNT_ID, createResult.id);
    EXPECT_EQ(ret, ERR_OK);

    MockSetCreatedOsAccounts({});
    std::filesystem::remove_all(testDir, ec);
}

HWTEST_F(SubProfileManagerServiceTest, SwitchOsAccountSubProfile_Success_001, TestSize.Level1)
{
    const std::string testDir = "/data/test/os_account_subspace_coverage_test_svc/";
    std::error_code ec;
    std::filesystem::remove_all(testDir, ec);
    std::filesystem::create_directories(testDir);
    OsAccountSubProfileManager::GetInstance().Init(testDir);

    auto service = std::make_shared<OsAccountSubProfileManagerService>();
    int32_t baseId = TEST_SUBSPACE_BASE;
    ErrCode ret = service->SwitchOsAccountSubProfile(TEST_OS_ACCOUNT_ID, baseId);
    EXPECT_EQ(ret, ERR_OS_ACCOUNT_SUBSPACE_RESTRICTED);

    std::filesystem::remove_all(testDir, ec);
}

class MockIRemoteForDeathTest : public IRemoteObject {
public:
    explicit MockIRemoteForDeathTest() : IRemoteObject(u"") {}
    bool IsProxyObject() const override
    {
        return true;
    }
    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        return false;
    }
    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        return false;
    }
    int32_t GetObjectRefCount() override
    {
        return 1;
    }
    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option) override
    {
        return 0;
    }
    int Dump(int fd, const std::vector<std::u16string> &args) override
    {
        return 0;
    }
};

class MockAccountProxyForSubspaceDeath : public AccountStub {
public:
    sptr<IRemoteObject> mockSubspaceService_ = nullptr;

    ErrCode GetOsAccountSubspaceService(sptr<IRemoteObject> &funcResult) override
    {
        funcResult = mockSubspaceService_;
        return ERR_OK;
    }

    ErrCode UpdateOhosAccountInfo(const std::string &accountName, const std::string &uid,
        const std::string &eventStr) override { return ERR_OK; }

    ErrCode SetOhosAccountInfo(const OhosAccountInfo &ohosAccountInfo,
        const std::string &eventStr) override { return ERR_OK; }

    ErrCode SetOsAccountDistributedInfo(int32_t localId, const OhosAccountInfo &ohosAccountInfo,
        const std::string &eventStr) override { return ERR_OK; }

    ErrCode QueryOhosAccountInfo(std::string &accountName, std::string &uid,
        int32_t &status) override { return ERR_OK; }

    ErrCode QueryDistributedVirtualDeviceId(std::string &dvid) override { return ERR_OK; }

    ErrCode QueryDistributedVirtualDeviceId(const std::string &bundleName, int32_t localId,
        std::string &dvid) override { return ERR_OK; }

    ErrCode QueryOsAccountDistributedInfo(int32_t localId, std::string &accountName,
        std::string &uid, int32_t &status) override { return ERR_OK; }

    ErrCode GetOhosAccountInfo(OhosAccountInfo &accountInfo) override { return ERR_OK; }

    ErrCode GetOsAccountDistributedInfo(int32_t localId,
        OhosAccountInfo &info) override { return ERR_OK; }

    ErrCode QueryDeviceAccountId(int32_t &accountId) override { return ERR_OK; }

    ErrCode SubscribeDistributedAccountEvent(int32_t typeInt,
        const sptr<IRemoteObject> &eventListener) override { return ERR_OK; }

    ErrCode UnsubscribeDistributedAccountEvent(int32_t typeInt,
        const sptr<IRemoteObject> &eventListener) override { return ERR_OK; }

    ErrCode GetAppAccountService(sptr<IRemoteObject> &funcResult) override
    {
        funcResult = nullptr;
        return ERR_OK;
    }
    ErrCode GetOsAccountService(sptr<IRemoteObject> &funcResult) override
    {
        funcResult = nullptr;
        return ERR_OK;
    }
    ErrCode GetAccountIAMService(sptr<IRemoteObject> &funcResult) override
    {
        funcResult = nullptr;
        return ERR_OK;
    }
    ErrCode GetDomainAccountService(sptr<IRemoteObject> &funcResult) override
    {
        funcResult = nullptr;
        return ERR_OK;
    }
    ErrCode GetAuthorizationService(sptr<IRemoteObject> &funcResult) override
    {
        funcResult = nullptr;
        return ERR_OK;
    }
    bool IsServiceStarted() const { return true; }
    int32_t CallbackEnter(uint32_t code) override { return ERR_OK; }
    int32_t CallbackExit(uint32_t code, int32_t result) override { return ERR_OK; }

    ErrCode GetOsAccountForegroundSubProfileId(int32_t& subProfileId) override
    {
        subProfileId = 0;
        return ERR_OK;
    }

    ErrCode GetOsAccountForegroundSubProfileId(int32_t osAccountId, int32_t& subProfileId) override
    {
        subProfileId = 0;
        return ERR_OK;
    }

    ErrCode GetOsAccountSubProfileIds(std::vector<int32_t>& subProfileIds) override
    {
        return ERR_OK;
    }

    ErrCode GetOsAccountSubProfileIds(int32_t osAccountId, std::vector<int32_t>& subProfileIds) override
    {
        return ERR_OK;
    }

    ErrCode GetOsAccountLocalIdForSubProfile(int32_t subProfileId, int32_t& osAccountId) override
    {
        osAccountId = 0;
        return ERR_OK;
    }

    ErrCode GetOsAccountSubProfile(int32_t subProfileId,
        OsAccountSubspaceResult& subspaceResult, OhosAccountInfo& distributedInfo) override
    {
        return ERR_OK;
    }

    ErrCode GetOsAccountSubProfile(int32_t osAccountId, int32_t subProfileId,
        OsAccountSubspaceResult& subspaceResult, OhosAccountInfo& distributedInfo) override
    {
        return ERR_OK;
    }

    int32_t GetOsAccountSubProfileId(
        int32_t osAccountId, int32_t appIndex, int32_t &subProfileId) override
    {
        subProfileId = 0;
        return ERR_OK;
    }

    int32_t GetOsAccountSubProfileId(
        uint32_t tokenId, int32_t &subProfileId) override
    {
        subProfileId = 0;
        return ERR_OK;
    }

    int32_t GetOsAccountSubProfileIndex(
        int32_t osAccountId, int32_t subProfileId, int32_t &index) override
    {
        index = 0;
        return ERR_OK;
    }
};

class SubspaceProxyDeathTest : public testing::Test {
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

protected:
    void SetUp() override
    {
        ASSERT_EQ(SetSelfTokenID(allPermTokenId_), 0);

        mockAccountProxy_ = new (std::nothrow) MockAccountProxyForSubspaceDeath();
        ASSERT_NE(mockAccountProxy_, nullptr);

        savedAccountProxy_ = OhosAccountKitsImpl::GetInstance().accountProxy_;
        OhosAccountKitsImpl::GetInstance().accountProxy_ = mockAccountProxy_;

        OsAccountSubProfileClient::GetInstance().proxy_ = nullptr;
        OsAccountSubProfileClient::GetInstance().deathRecipient_ = nullptr;
    }

    void TearDown() override
    {
        OsAccountSubProfileClient::GetInstance().proxy_ = nullptr;
        OsAccountSubProfileClient::GetInstance().deathRecipient_ = nullptr;

        OhosAccountKitsImpl::GetInstance().accountProxy_ = savedAccountProxy_;
    }

    static uint64_t allPermTokenId_;
    sptr<MockAccountProxyForSubspaceDeath> mockAccountProxy_ = nullptr;
    sptr<IAccount> savedAccountProxy_ = nullptr;
};

uint64_t SubspaceProxyDeathTest::allPermTokenId_ = 0;

HWTEST_F(SubspaceProxyDeathTest, ObjectNullReturn_001, TestSize.Level1)
{
    auto result = OsAccountSubProfileClient::GetInstance().GetOsAccountSubProfileProxy();
    EXPECT_EQ(result, nullptr);
}

namespace {
bool g_forceNothrowNewFailure = false;
} // namespace

void* operator new(std::size_t size, const std::nothrow_t&) noexcept
{
    if (g_forceNothrowNewFailure) {
        return nullptr;
    }
    return std::malloc(size);
}

HWTEST_F(SubspaceProxyDeathTest, DeathRecipientNull_001, TestSize.Level1)
{
    sptr<MockIRemoteForDeathTest> mockRemoteObj = new MockIRemoteForDeathTest();
    ASSERT_NE(mockRemoteObj, nullptr);
    mockAccountProxy_->mockSubspaceService_ = mockRemoteObj;

    g_forceNothrowNewFailure = true;
    auto result = OsAccountSubProfileClient::GetInstance().GetOsAccountSubProfileProxy();
    g_forceNothrowNewFailure = false;

    EXPECT_EQ(result, nullptr);
}

// ===== Client+Service Integration Tests for Subscribe/Publish (T-001) =====

static constexpr int32_t TEST_UID = 200000; // localId = 1

class IntegrationTestCallback : public OsAccountSubProfileSubscribeCallback {
public:
    void OnSubProfileChanged(const SubProfileEventData &eventData) override {}
};

class IntegrationSubProfileStub : public OsAccountSubProfileStub {
public:
    ErrCode CreateOsAccountSubProfile(
        int32_t osAccountId,
        OsAccountSubspaceResult& subspaceResult) override
    {
        return ERR_OK;
    }
    ErrCode DeleteOsAccountSubProfile(
        int32_t osAccountId,
        int32_t subspaceId) override
    {
        return ERR_OK;
    }
    ErrCode SwitchOsAccountSubProfile(
        int32_t osAccountId,
        int32_t subspaceId) override
    {
        return ERR_OK;
    }
    ErrCode SubscribeOsAccountSubProfileEvents(
        const std::vector<int32_t> &types,
        const sptr<IRemoteObject> &eventListener) override
    {
        std::set<OsAccountSubProfileEventType> typeSet;
        for (auto t : types) {
            typeSet.insert(static_cast<OsAccountSubProfileEventType>(t));
        }
        return OsAccountSubProfileSubscribeManager::GetInstance().SubscribeOsAccountSubProfileEvents(
            typeSet, eventListener);
    }
    ErrCode UnsubscribeOsAccountSubProfileEvents(
        const std::vector<int32_t> &types,
        const sptr<IRemoteObject> &eventListener) override
    {
        std::set<OsAccountSubProfileEventType> typeSet;
        for (auto t : types) {
            typeSet.insert(static_cast<OsAccountSubProfileEventType>(t));
        }
        return OsAccountSubProfileSubscribeManager::GetInstance().UnsubscribeOsAccountSubProfileEvents(
            typeSet, eventListener);
    }
};

class OsAccountSubProfileIntegrationTest : public testing::Test {
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
        MockSetCallingUid(TEST_UID);
        ResetMockState();

        OsAccountSubProfileClient::GetInstance().proxy_ = nullptr;
        OsAccountSubProfileClient::GetInstance().deathRecipient_ = nullptr;

        stub_ = sptr<IntegrationSubProfileStub>(new (std::nothrow) IntegrationSubProfileStub());
        ASSERT_NE(stub_, nullptr);
        OsAccountSubProfileClient::GetInstance().proxy_ = stub_;
    }

    void TearDown() override
    {
        OsAccountSubProfileClient::GetInstance().proxy_ = nullptr;
        OsAccountSubProfileClient::GetInstance().deathRecipient_ = nullptr;
        stub_ = nullptr;
    }

    static uint64_t allPermTokenId_;
    sptr<IntegrationSubProfileStub> stub_;
};

uint64_t OsAccountSubProfileIntegrationTest::allPermTokenId_ = 0;

/**
 * @tc.name: OsAccountSubProfileIntegrationTest_SubscribeThenUnsubscribe_Integration
 * @tc.desc: Subscribe via full client→stub→manager stack, then unsubscribe.
 */
HWTEST_F(OsAccountSubProfileIntegrationTest, SubscribeThenUnsubscribe_Integration, TestSize.Level1)
{
    auto cb = std::make_shared<IntegrationTestCallback>();
    std::set<OsAccountSubProfileEventType> types = {OsAccountSubProfileEventType::CREATED};

    ErrCode ret = OsAccountSubProfileClient::GetInstance().SubscribeOsAccountSubProfileEvents(types, cb);
    EXPECT_EQ(ret, ERR_OK);

    ret = OsAccountSubProfileClient::GetInstance().UnsubscribeOsAccountSubProfileEvents(cb);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: OsAccountSubProfileIntegrationTest_Subscribe_MultipleTypes_Integration
 * @tc.desc: Subscribe with multiple event types through full stack.
 */
HWTEST_F(OsAccountSubProfileIntegrationTest, Subscribe_MultipleTypes_Integration, TestSize.Level1)
{
    auto cb = std::make_shared<IntegrationTestCallback>();
    std::set<OsAccountSubProfileEventType> types = {
        OsAccountSubProfileEventType::CREATED,
        OsAccountSubProfileEventType::DELETED,
        OsAccountSubProfileEventType::SWITCHED
    };

    ErrCode ret = OsAccountSubProfileClient::GetInstance().SubscribeOsAccountSubProfileEvents(types, cb);
    EXPECT_EQ(ret, ERR_OK);

    ret = OsAccountSubProfileClient::GetInstance().UnsubscribeOsAccountSubProfileEvents(cb);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: OsAccountSubProfileIntegrationTest_Subscribe_Deduplicate_Integration
 * @tc.desc: Subscribe with same types twice, verify dedup via return codes.
 */
HWTEST_F(OsAccountSubProfileIntegrationTest, Subscribe_Deduplicate_Integration, TestSize.Level1)
{
    auto cb = std::make_shared<IntegrationTestCallback>();
    std::set<OsAccountSubProfileEventType> types = {OsAccountSubProfileEventType::CREATED};

    ErrCode ret1 = OsAccountSubProfileClient::GetInstance().SubscribeOsAccountSubProfileEvents(types, cb);
    EXPECT_EQ(ret1, ERR_OK);

    ret1 = OsAccountSubProfileClient::GetInstance().SubscribeOsAccountSubProfileEvents(types, cb);
    EXPECT_EQ(ret1, ERR_OK);

    ErrCode ret = OsAccountSubProfileClient::GetInstance().UnsubscribeOsAccountSubProfileEvents(cb);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: OsAccountSubProfileIntegrationTest_Publish_AfterClientSubscribe
 * @tc.desc: Subscribe via full stack, then publish via manager.
 */
HWTEST_F(OsAccountSubProfileIntegrationTest, Publish_AfterClientSubscribe, TestSize.Level1)
{
    auto cb = std::make_shared<IntegrationTestCallback>();
    std::set<OsAccountSubProfileEventType> types = {OsAccountSubProfileEventType::CREATED};

    ErrCode ret = OsAccountSubProfileClient::GetInstance().SubscribeOsAccountSubProfileEvents(types, cb);
    EXPECT_EQ(ret, ERR_OK);

    auto &mgr = OsAccountSubProfileSubscribeManager::GetInstance();
    ret = mgr.Publish(OsAccountSubProfileEventType::CREATED, 1, TEST_SUBSPACE_BASE, -1);
    EXPECT_EQ(ret, ERR_OK);
}

#endif // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
