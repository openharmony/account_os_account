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

#include "errors.h"
#include "if_system_ability_manager.h"
#include "ipc_object_stub.h"
#include "mock/iservice_registry_mock_helper.h"
#include "os_account_manager_lite.h"
#include "system_ability_definition.h"

namespace {
constexpr uint32_t COMMAND_GET_OS_ACCOUNT_SERVICE = 14;
constexpr uint32_t COMMAND_GET_FOREGROUND_OS_ACCOUNT_LOCAL_ID_OUT_INT = 77;
constexpr int32_t TEST_LOCAL_ID = 101;
}

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AccountSA;

namespace OHOS {
namespace AccountTest {
class MockOsAccountService final : public IPCObjectStub {
public:
    explicit MockOsAccountService(ErrCode replyErrCode = ERR_OK, int32_t localId = TEST_LOCAL_ID,
        int sendRequestResult = ERR_NONE, bool writeReplyErrCode = true, bool writeLocalId = true)
        : replyErrCode_(replyErrCode), localId_(localId), sendRequestResult_(sendRequestResult),
          writeReplyErrCode_(writeReplyErrCode), writeLocalId_(writeLocalId)
    {}

    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        if (code != COMMAND_GET_FOREGROUND_OS_ACCOUNT_LOCAL_ID_OUT_INT) {
            return sendRequestResult_;
        }
        if (sendRequestResult_ != ERR_NONE) {
            return sendRequestResult_;
        }
        if (writeReplyErrCode_) {
            reply.WriteInt32(replyErrCode_);
        }
        if (writeReplyErrCode_ && replyErrCode_ == ERR_OK && writeLocalId_) {
            reply.WriteInt32(localId_);
        }
        return ERR_NONE;
    }

private:
    ErrCode replyErrCode_;
    int32_t localId_;
    int sendRequestResult_;
    bool writeReplyErrCode_;
    bool writeLocalId_;
};

class MockAccountMgrService final : public IPCObjectStub {
public:
    explicit MockAccountMgrService(const sptr<IRemoteObject> &osAccountService = nullptr, ErrCode replyErrCode = ERR_OK,
        int sendRequestResult = ERR_NONE, bool writeRemoteObject = true, bool writeReplyErrCode = true)
        : osAccountService_(osAccountService), replyErrCode_(replyErrCode), sendRequestResult_(sendRequestResult),
          writeRemoteObject_(writeRemoteObject), writeReplyErrCode_(writeReplyErrCode)
    {}

    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        if (code != COMMAND_GET_OS_ACCOUNT_SERVICE) {
            return sendRequestResult_;
        }
        if (sendRequestResult_ != ERR_NONE) {
            return sendRequestResult_;
        }
        if (writeReplyErrCode_) {
            reply.WriteInt32(replyErrCode_);
        }
        if (writeReplyErrCode_ && replyErrCode_ == ERR_OK && writeRemoteObject_) {
            reply.WriteRemoteObject(osAccountService_);
        }
        return ERR_NONE;
    }

private:
    sptr<IRemoteObject> osAccountService_;
    ErrCode replyErrCode_;
    int sendRequestResult_;
    bool writeRemoteObject_;
    bool writeReplyErrCode_;
};

class MockSystemAbilityManager final : public IPCObjectStub, public ISystemAbilityManager {
public:
    explicit MockSystemAbilityManager(const sptr<IRemoteObject> &accountMgrService = nullptr)
        : accountMgrService_(accountMgrService)
    {}

    sptr<IRemoteObject> AsObject() override
    {
        return this;
    }

    std::vector<std::u16string> ListSystemAbilities(unsigned int dumpFlags = DUMP_FLAG_PRIORITY_ALL) override
    {
        (void)dumpFlags;
        return {};
    }

    sptr<IRemoteObject> GetSystemAbility(int32_t systemAbilityId) override
    {
        if (systemAbilityId != SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN) {
            return nullptr;
        }
        return accountMgrService_;
    }

    sptr<IRemoteObject> CheckSystemAbility(int32_t systemAbilityId) override
    {
        return GetSystemAbility(systemAbilityId);
    }

    int32_t RemoveSystemAbility(int32_t systemAbilityId) override
    {
        (void)systemAbilityId;
        return ERR_INVALID_VALUE;
    }

    int32_t SubscribeSystemAbility(int32_t systemAbilityId,
        const sptr<ISystemAbilityStatusChange> &listener) override
    {
        (void)systemAbilityId;
        (void)listener;
        return ERR_INVALID_VALUE;
    }

    int32_t UnSubscribeSystemAbility(int32_t systemAbilityId,
        const sptr<ISystemAbilityStatusChange> &listener) override
    {
        (void)systemAbilityId;
        (void)listener;
        return ERR_INVALID_VALUE;
    }

    sptr<IRemoteObject> GetSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override
    {
        (void)deviceId;
        return GetSystemAbility(systemAbilityId);
    }

    sptr<IRemoteObject> CheckSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override
    {
        (void)deviceId;
        return GetSystemAbility(systemAbilityId);
    }

    int32_t AddOnDemandSystemAbilityInfo(int32_t systemAbilityId,
        const std::u16string &localAbilityManagerName) override
    {
        (void)systemAbilityId;
        (void)localAbilityManagerName;
        return ERR_INVALID_VALUE;
    }

    sptr<IRemoteObject> CheckSystemAbility(int32_t systemAbilityId, bool &isExist) override
    {
        isExist = (GetSystemAbility(systemAbilityId) != nullptr);
        return GetSystemAbility(systemAbilityId);
    }

    int32_t AddSystemAbility(int32_t systemAbilityId, const sptr<IRemoteObject> &ability,
        const SAExtraProp &extraProp = SAExtraProp(false, DUMP_FLAG_PRIORITY_DEFAULT, u"", u"")) override
    {
        (void)systemAbilityId;
        (void)ability;
        (void)extraProp;
        return ERR_INVALID_VALUE;
    }

    int32_t AddSystemProcess(const std::u16string &procName, const sptr<IRemoteObject> &procObject) override
    {
        (void)procName;
        (void)procObject;
        return ERR_INVALID_VALUE;
    }

    sptr<IRemoteObject> LoadSystemAbility(int32_t systemAbilityId, int32_t timeout) override
    {
        (void)timeout;
        return GetSystemAbility(systemAbilityId);
    }

    int32_t LoadSystemAbility(int32_t systemAbilityId, const sptr<ISystemAbilityLoadCallback> &callback) override
    {
        (void)systemAbilityId;
        (void)callback;
        return ERR_INVALID_VALUE;
    }

    int32_t LoadSystemAbility(int32_t systemAbilityId, const std::string &deviceId,
        const sptr<ISystemAbilityLoadCallback> &callback) override
    {
        (void)systemAbilityId;
        (void)deviceId;
        (void)callback;
        return ERR_INVALID_VALUE;
    }

    int32_t UnloadSystemAbility(int32_t systemAbilityId) override
    {
        (void)systemAbilityId;
        return ERR_INVALID_VALUE;
    }

    int32_t CancelUnloadSystemAbility(int32_t systemAbilityId) override
    {
        (void)systemAbilityId;
        return ERR_INVALID_VALUE;
    }

    int32_t UnloadAllIdleSystemAbility() override
    {
        return ERR_INVALID_VALUE;
    }

    int32_t GetSystemProcessInfo(int32_t systemAbilityId, SystemProcessInfo &systemProcessInfo) override
    {
        (void)systemAbilityId;
        (void)systemProcessInfo;
        return ERR_INVALID_VALUE;
    }

    int32_t GetRunningSystemProcess(std::list<SystemProcessInfo> &systemProcessInfos) override
    {
        (void)systemProcessInfos;
        return ERR_INVALID_VALUE;
    }

    int32_t SubscribeSystemProcess(const sptr<ISystemProcessStatusChange> &listener) override
    {
        (void)listener;
        return ERR_INVALID_VALUE;
    }

    int32_t SendStrategy(int32_t type, std::vector<int32_t> &systemAbilityIds,
        int32_t level, std::string &action) override
    {
        (void)type;
        (void)systemAbilityIds;
        (void)level;
        (void)action;
        return ERR_INVALID_VALUE;
    }

    int32_t UnSubscribeSystemProcess(const sptr<ISystemProcessStatusChange> &listener) override
    {
        (void)listener;
        return ERR_INVALID_VALUE;
    }

    int32_t GetExtensionSaIds(const std::string &extension, std::vector<int32_t> &saIds) override
    {
        (void)extension;
        (void)saIds;
        return ERR_INVALID_VALUE;
    }

    int32_t GetExtensionRunningSaList(const std::string &extension,
        std::vector<sptr<IRemoteObject>> &saList) override
    {
        (void)extension;
        (void)saList;
        return ERR_INVALID_VALUE;
    }

    int32_t GetRunningSaExtensionInfoList(const std::string &extension,
        std::vector<SaExtensionInfo> &infoList) override
    {
        (void)extension;
        (void)infoList;
        return ERR_INVALID_VALUE;
    }

    int32_t GetCommonEventExtraDataIdlist(int32_t saId, std::vector<int64_t> &extraDataIdList,
        const std::string &eventName = "") override
    {
        (void)saId;
        (void)extraDataIdList;
        (void)eventName;
        return ERR_INVALID_VALUE;
    }

    int32_t GetOnDemandReasonExtraData(int64_t extraDataId, MessageParcel &extraDataParcel) override
    {
        (void)extraDataId;
        (void)extraDataParcel;
        return ERR_INVALID_VALUE;
    }

    int32_t GetOnDemandPolicy(int32_t systemAbilityId, OnDemandPolicyType type,
        std::vector<SystemAbilityOnDemandEvent> &abilityOnDemandEvents) override
    {
        (void)systemAbilityId;
        (void)type;
        (void)abilityOnDemandEvents;
        return ERR_INVALID_VALUE;
    }

    int32_t UpdateOnDemandPolicy(int32_t systemAbilityId, OnDemandPolicyType type,
        const std::vector<SystemAbilityOnDemandEvent> &abilityOnDemandEvents) override
    {
        (void)systemAbilityId;
        (void)type;
        (void)abilityOnDemandEvents;
        return ERR_INVALID_VALUE;
    }

    int32_t GetOnDemandSystemAbilityIds(std::vector<int32_t> &systemAbilityIds) override
    {
        (void)systemAbilityIds;
        return ERR_INVALID_VALUE;
    }

private:
    sptr<IRemoteObject> accountMgrService_;
};

class OsAccountManagerLiteProxyMockTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void TearDown(void) override;
};

void OsAccountManagerLiteProxyMockTest::SetUpTestCase(void)
{}

void OsAccountManagerLiteProxyMockTest::TearDownTestCase(void)
{}

void OsAccountManagerLiteProxyMockTest::TearDown(void)
{
    ResetMockSystemAbilityManager();
}

/**
 * @tc.name: GetForegroundOsAccountLocalIdProxyMock001
 * @tc.desc: Test GetForegroundOsAccountLocalId returns get proxy error when proxy is unavailable.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerLiteProxyMockTest, GetForegroundOsAccountLocalIdProxyMock001, TestSize.Level3)
{
    int32_t localId = -1;
    EXPECT_EQ(OsAccountManagerLite::GetForegroundOsAccountLocalId(localId), ERR_ACCOUNT_COMMON_GET_PROXY);
    EXPECT_EQ(localId, -1);
}

/**
 * @tc.name: GetForegroundOsAccountLocalIdProxyMock002
 * @tc.desc: Test GetForegroundOsAccountLocalId returns get proxy error when account mgr service is unavailable.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerLiteProxyMockTest, GetForegroundOsAccountLocalIdProxyMock002, TestSize.Level3)
{
    SetMockSystemAbilityManager(new MockSystemAbilityManager(nullptr));

    int32_t localId = -1;
    EXPECT_EQ(OsAccountManagerLite::GetForegroundOsAccountLocalId(localId), ERR_ACCOUNT_COMMON_GET_PROXY);
    EXPECT_EQ(localId, -1);
}

/**
 * @tc.name: GetForegroundOsAccountLocalIdProxyMock003
 * @tc.desc: Test GetForegroundOsAccountLocalId returns get proxy error when account service request fails.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerLiteProxyMockTest, GetForegroundOsAccountLocalIdProxyMock003, TestSize.Level3)
{
    SetMockSystemAbilityManager(new MockSystemAbilityManager(
        new MockAccountMgrService(nullptr, ERR_OK, ERR_INVALID_VALUE)));

    int32_t localId = -1;
    EXPECT_EQ(OsAccountManagerLite::GetForegroundOsAccountLocalId(localId), ERR_ACCOUNT_COMMON_GET_PROXY);
    EXPECT_EQ(localId, -1);
}

/**
 * @tc.name: GetForegroundOsAccountLocalIdProxyMock004
 * @tc.desc: Test GetForegroundOsAccountLocalId returns get proxy error when account service reply is not ok.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerLiteProxyMockTest, GetForegroundOsAccountLocalIdProxyMock004, TestSize.Level3)
{
    SetMockSystemAbilityManager(new MockSystemAbilityManager(
        new MockAccountMgrService(nullptr, ERR_ACCOUNT_COMMON_PERMISSION_DENIED)));

    int32_t localId = -1;
    EXPECT_EQ(OsAccountManagerLite::GetForegroundOsAccountLocalId(localId), ERR_ACCOUNT_COMMON_GET_PROXY);
    EXPECT_EQ(localId, -1);
}

/**
 * @tc.name: GetForegroundOsAccountLocalIdProxyMock005
 * @tc.desc: Test GetForegroundOsAccountLocalId returns remote died when os account request fails.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerLiteProxyMockTest, GetForegroundOsAccountLocalIdProxyMock005, TestSize.Level3)
{
    sptr<IRemoteObject> osAccountService = new MockOsAccountService(ERR_OK, TEST_LOCAL_ID, ERR_INVALID_VALUE);
    SetMockSystemAbilityManager(new MockSystemAbilityManager(new MockAccountMgrService(osAccountService)));

    int32_t localId = -1;
    EXPECT_EQ(OsAccountManagerLite::GetForegroundOsAccountLocalId(localId), ERR_ACCOUNT_COMMON_REMOTE_DIED);
    EXPECT_EQ(localId, -1);
}

/**
 * @tc.name: GetForegroundOsAccountLocalIdProxyMock006
 * @tc.desc: Test GetForegroundOsAccountLocalId converts invalid value to write descriptor error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerLiteProxyMockTest, GetForegroundOsAccountLocalIdProxyMock006, TestSize.Level3)
{
    sptr<IRemoteObject> osAccountService = new MockOsAccountService(ERR_INVALID_VALUE);
    SetMockSystemAbilityManager(new MockSystemAbilityManager(new MockAccountMgrService(osAccountService)));

    int32_t localId = -1;
    EXPECT_EQ(
        OsAccountManagerLite::GetForegroundOsAccountLocalId(localId), ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR);
    EXPECT_EQ(localId, -1);
}

/**
 * @tc.name: GetForegroundOsAccountLocalIdProxyMock007
 * @tc.desc: Test GetForegroundOsAccountLocalId converts invalid data to write parcel error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerLiteProxyMockTest, GetForegroundOsAccountLocalIdProxyMock007, TestSize.Level3)
{
    sptr<IRemoteObject> osAccountService = new MockOsAccountService(ERR_INVALID_DATA);
    SetMockSystemAbilityManager(new MockSystemAbilityManager(new MockAccountMgrService(osAccountService)));

    int32_t localId = -1;
    EXPECT_EQ(OsAccountManagerLite::GetForegroundOsAccountLocalId(localId), ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR);
    EXPECT_EQ(localId, -1);
}

/**
 * @tc.name: GetForegroundOsAccountLocalIdProxyMock008
 * @tc.desc: Test GetForegroundOsAccountLocalId transparently returns other service errors.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerLiteProxyMockTest, GetForegroundOsAccountLocalIdProxyMock008, TestSize.Level3)
{
    sptr<IRemoteObject> osAccountService = new MockOsAccountService(ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    SetMockSystemAbilityManager(new MockSystemAbilityManager(new MockAccountMgrService(osAccountService)));

    int32_t localId = -1;
    EXPECT_EQ(OsAccountManagerLite::GetForegroundOsAccountLocalId(localId), ERR_ACCOUNT_COMMON_PERMISSION_DENIED);
    EXPECT_EQ(localId, -1);
}

/**
 * @tc.name: GetForegroundOsAccountLocalIdProxyMock009
 * @tc.desc: Test GetForegroundOsAccountLocalId returns local id when mocked services succeed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerLiteProxyMockTest, GetForegroundOsAccountLocalIdProxyMock009, TestSize.Level3)
{
    sptr<IRemoteObject> osAccountService = new MockOsAccountService(ERR_OK, TEST_LOCAL_ID);
    SetMockSystemAbilityManager(new MockSystemAbilityManager(new MockAccountMgrService(osAccountService)));

    int32_t localId = -1;
    EXPECT_EQ(OsAccountManagerLite::GetForegroundOsAccountLocalId(localId), ERR_OK);
    EXPECT_EQ(localId, TEST_LOCAL_ID);
}

/**
 * @tc.name: GetForegroundOsAccountLocalIdProxyMock010
 * @tc.desc: Test GetForegroundOsAccountLocalId returns get proxy error when account service returns null proxy.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerLiteProxyMockTest, GetForegroundOsAccountLocalIdProxyMock010, TestSize.Level3)
{
    SetMockSystemAbilityManager(new MockSystemAbilityManager(
        new MockAccountMgrService(nullptr, ERR_OK, ERR_NONE, false)));

    int32_t localId = -1;
    EXPECT_EQ(OsAccountManagerLite::GetForegroundOsAccountLocalId(localId), ERR_ACCOUNT_COMMON_GET_PROXY);
    EXPECT_EQ(localId, -1);
}

/**
 * @tc.name: GetForegroundOsAccountLocalIdProxyMock011
 * @tc.desc: Test GetForegroundOsAccountLocalId returns get proxy error when account service reply misses result.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerLiteProxyMockTest, GetForegroundOsAccountLocalIdProxyMock011, TestSize.Level3)
{
    SetMockSystemAbilityManager(new MockSystemAbilityManager(
        new MockAccountMgrService(nullptr, ERR_OK, ERR_NONE, true, false)));

    int32_t localId = -1;
    EXPECT_EQ(OsAccountManagerLite::GetForegroundOsAccountLocalId(localId), ERR_ACCOUNT_COMMON_GET_PROXY);
    EXPECT_EQ(localId, -1);
}

/**
 * @tc.name: GetForegroundOsAccountLocalIdProxyMock012
 * @tc.desc: Test GetForegroundOsAccountLocalId returns read parcel error when os account reply misses err code.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerLiteProxyMockTest, GetForegroundOsAccountLocalIdProxyMock012, TestSize.Level3)
{
    sptr<IRemoteObject> osAccountService = new MockOsAccountService(ERR_OK, TEST_LOCAL_ID, ERR_NONE, false);
    SetMockSystemAbilityManager(new MockSystemAbilityManager(new MockAccountMgrService(osAccountService)));

    int32_t localId = -1;
    EXPECT_EQ(OsAccountManagerLite::GetForegroundOsAccountLocalId(localId), ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR);
    EXPECT_EQ(localId, -1);
}

/**
 * @tc.name: GetForegroundOsAccountLocalIdProxyMock013
 * @tc.desc: Test GetForegroundOsAccountLocalId returns read parcel error when os account reply misses local id.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OsAccountManagerLiteProxyMockTest, GetForegroundOsAccountLocalIdProxyMock013, TestSize.Level3)
{
    sptr<IRemoteObject> osAccountService = new MockOsAccountService(ERR_OK, TEST_LOCAL_ID, ERR_NONE, true, false);
    SetMockSystemAbilityManager(new MockSystemAbilityManager(new MockAccountMgrService(osAccountService)));

    int32_t localId = -1;
    EXPECT_EQ(OsAccountManagerLite::GetForegroundOsAccountLocalId(localId), ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR);
    EXPECT_EQ(localId, -1);
}
}  // namespace AccountTest
}  // namespace OHOS
