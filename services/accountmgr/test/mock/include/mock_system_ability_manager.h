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

#ifndef OS_ACCOUNT_TEST_MOCK_INCLUDE_IF_SYSTEM_ABILITY_MANAGER_H
#define OS_ACCOUNT_TEST_MOCK_INCLUDE_IF_SYSTEM_ABILITY_MANAGER_H

#include <cstdint>
#include "if_system_ability_manager.h"
#include "iremote_object.h"
#include "iremote_stub.h"

namespace OHOS {
class MockSystemAbilityManager : public IRemoteStub<ISystemAbilityManager> {
public:
    MockSystemAbilityManager() = default;
    virtual ~MockSystemAbilityManager() = default;

    int32_t OnUserStateChanged(int32_t userId, SamgrUserState userState) override
    {
        return mockResult_;
    }

    void SetMockResult(int32_t result)
    {
        mockResult_ = result;
    }

    static MockSystemAbilityManager& GetInstance()
    {
        static MockSystemAbilityManager instance;
        return instance;
    }

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
        return nullptr;
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
    int32_t mockResult_ = ERR_OK;
};

}  // namespace OHOS

#endif  // OS_ACCOUNT_TEST_MOCK_INCLUDE_IF_SYSTEM_ABILITY_MANAGER_H