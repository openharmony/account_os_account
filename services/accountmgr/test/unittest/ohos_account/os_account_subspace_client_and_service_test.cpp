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

HWTEST_F(SubspaceClientTest, ResetProxy_MatchingRemote_001, TestSize.Level1)
{
    auto &client = OsAccountSubProfileClient::GetInstance();
    sptr<IRemoteObject> serviceObj = new (std::nothrow) MockAccountMgrService();
    client.proxy_ = iface_cast<IOsAccountSubProfile>(serviceObj);
    client.deathRecipient_ = new (std::nothrow) OsAccountSubProfileClient::OsAccountSubProfileDeathRecipient();
    if (client.proxy_ != nullptr) {
        wptr<IRemoteObject> remote = serviceObj;
        client.ResetProxy(remote);
        EXPECT_EQ(client.proxy_, nullptr);
        EXPECT_EQ(client.deathRecipient_, nullptr);
    } else {
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

// ===== Task 8: OsAccountInfo subspace methods =====
class OsAccountInfoSubspaceTest : public testing::Test {
public:
    void SetUp() override {}
    void TearDown() override {}
};

HWTEST_F(OsAccountInfoSubspaceTest, GetForegroundSubspaceId_Default_001, TestSize.Level1)
{
    OsAccountInfo info;
    info.localId_ = TEST_OS_ACCOUNT_ID;
    info.foregroundSubProfileId_ = -1;
    EXPECT_EQ(info.GetForegroundSubProfileId(), -1);
}

HWTEST_F(OsAccountInfoSubspaceTest, GetForegroundSubspaceId_SetValue_001, TestSize.Level1)
{
    OsAccountInfo info;
    info.localId_ = TEST_OS_ACCOUNT_ID;
    int32_t expectedId = TEST_SUBSPACE_BASE + 5;
    info.SetForegroundSubProfileId(expectedId);
    EXPECT_EQ(info.GetForegroundSubProfileId(), expectedId);
}

HWTEST_F(OsAccountInfoSubspaceTest, GetForegroundSubspaceId_SetToBase_001, TestSize.Level1)
{
    OsAccountInfo info;
    info.localId_ = TEST_OS_ACCOUNT_ID;
    info.SetForegroundSubProfileId(TEST_SUBSPACE_BASE);
    EXPECT_EQ(info.GetForegroundSubProfileId(), TEST_SUBSPACE_BASE);
}

HWTEST_F(OsAccountInfoSubspaceTest, SetForegroundSubspaceId_Negative_001, TestSize.Level1)
{
    OsAccountInfo info;
    info.localId_ = TEST_OS_ACCOUNT_ID;
    info.SetForegroundSubProfileId(-1);
    EXPECT_EQ(info.GetForegroundSubProfileId(), -1);
}

// ===== Task 9: OsAccountSubspaceResult Marshalling =====
class SubspaceResultMarshallingTest : public testing::Test {
public:
    void SetUp() override {}
    void TearDown() override {}
};

HWTEST_F(SubspaceResultMarshallingTest, Marshalling_Success_001, TestSize.Level1)
{
    OsAccountSubspaceResult result;
    result.id = TEST_SUBSPACE_BASE + 1;
    result.osAccountId = TEST_OS_ACCOUNT_ID;
    result.index = 1;

    Parcel parcel;
    EXPECT_TRUE(result.Marshalling(parcel));

    EXPECT_TRUE(parcel.ReadInt32());
    EXPECT_TRUE(parcel.ReadInt32());
    EXPECT_TRUE(parcel.ReadInt32());
}

HWTEST_F(SubspaceResultMarshallingTest, Unmarshalling_Success_001, TestSize.Level1)
{
    OsAccountSubspaceResult original;
    original.id = TEST_SUBSPACE_BASE + 2;
    original.osAccountId = TEST_OS_ACCOUNT_ID;
    original.index = 2;

    Parcel parcel;
    ASSERT_TRUE(original.Marshalling(parcel));

    OsAccountSubspaceResult *unmarshalled = OsAccountSubspaceResult::Unmarshalling(parcel);
    ASSERT_NE(unmarshalled, nullptr);
    EXPECT_EQ(unmarshalled->id, original.id);
    EXPECT_EQ(unmarshalled->osAccountId, original.osAccountId);
    EXPECT_EQ(unmarshalled->index, original.index);
    delete unmarshalled;
}

HWTEST_F(SubspaceResultMarshallingTest, Unmarshalling_EmptyParcel_001, TestSize.Level1)
{
    Parcel emptyParcel;
    OsAccountSubspaceResult *result = OsAccountSubspaceResult::Unmarshalling(emptyParcel);
    EXPECT_EQ(result, nullptr);
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
    ErrCode SubscribeDistributedAccountSpaceEvents(
        const std::vector<int32_t>& typeInts, const sptr<IRemoteObject>& eventListener) override
    {
        return ERR_OK;
    }
    ErrCode UnsubscribeDistributedAccountSpaceEvents(
        const std::vector<int32_t>& typeInts, const sptr<IRemoteObject>& eventListener) override
    {
        return ERR_OK;
    }

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

HWTEST_F(SubspaceProxyDeathTest, AddDeathRecipientFailure_001, TestSize.Level1)
{
    sptr<MockIRemoteForDeathTest> mockRemoteObj = new (std::nothrow) MockIRemoteForDeathTest();
    ASSERT_NE(mockRemoteObj, nullptr);
    mockAccountProxy_->mockSubspaceService_ = mockRemoteObj;

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

#endif // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
