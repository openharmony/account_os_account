/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "system_ability_manager_proxy.h"

namespace OHOS {

SystemAbilityManagerClient& SystemAbilityManagerClient::GetInstance()
{
    static auto instance = new SystemAbilityManagerClient();
    return *instance;
}

sptr<ISystemAbilityManager> SystemAbilityManagerClient::GetSystemAbilityManager()
{
    GTEST_LOG_(INFO) << "GetSystemAbilityManager: return nullptr";
    return nullptr;
}

sptr<IRemoteObject> SystemAbilityManagerProxy::GetSystemAbility(int32_t systemAbilityId)
{
    GTEST_LOG_(INFO) << "GetSystemAbility(" << systemAbilityId << "): return nullptr";
    return nullptr;
}

sptr<IRemoteObject> SystemAbilityManagerProxy::GetSystemAbility(int32_t systemAbilityId,
    const std::string& deviceId)
{
    return GetSystemAbility(systemAbilityId);
}

sptr<IRemoteObject> SystemAbilityManagerProxy::CheckSystemAbilityWrapper(int32_t code, MessageParcel& data)
{
    return nullptr;
}

sptr<IRemoteObject> SystemAbilityManagerProxy::CheckSystemAbility(int32_t systemAbilityId)
{
    return nullptr;
}

sptr<IRemoteObject> SystemAbilityManagerProxy::CheckSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    return nullptr;
}

sptr<IRemoteObject> SystemAbilityManagerProxy::CheckSystemAbility(int32_t systemAbilityId, bool& isExist)
{
    return nullptr;
}

int32_t SystemAbilityManagerProxy::AddOnDemandSystemAbilityInfo(int32_t systemAbilityId,
    const std::u16string& localAbilityManagerName)
{
    return ERR_INVALID_VALUE;
}

int32_t SystemAbilityManagerProxy::RemoveSystemAbilityWrapper(int32_t code, MessageParcel& data)
{
    return ERR_INVALID_VALUE;
}

int32_t SystemAbilityManagerProxy::RemoveSystemAbility(int32_t systemAbilityId)
{
    return ERR_INVALID_VALUE;
}

std::vector<std::u16string> SystemAbilityManagerProxy::ListSystemAbilities(unsigned int dumpFlags)
{
    std::vector<std::u16string> saNames;

    return saNames;
}

int32_t SystemAbilityManagerProxy::SubscribeSystemAbility(int32_t systemAbilityId,
    const sptr<ISystemAbilityStatusChange>& listener)
{
    return ERR_INVALID_VALUE;
}

int32_t SystemAbilityManagerProxy::UnSubscribeSystemAbility(int32_t systemAbilityId,
    const sptr<ISystemAbilityStatusChange>& listener)
{
    return ERR_INVALID_VALUE;
}

int32_t SystemAbilityManagerProxy::LoadSystemAbility(int32_t systemAbilityId,
    const sptr<ISystemAbilityLoadCallback>& callback)
{
    return ERR_INVALID_VALUE;
}

int32_t SystemAbilityManagerProxy::LoadSystemAbility(int32_t systemAbilityId, const std::string& deviceId,
    const sptr<ISystemAbilityLoadCallback>& callback)
{
    return ERR_INVALID_VALUE;
}

int32_t SystemAbilityManagerProxy::AddSystemAbility(int32_t systemAbilityId, const sptr<IRemoteObject>& ability,
    const SAExtraProp& extraProp)
{
    return ERR_INVALID_VALUE;
}

int32_t SystemAbilityManagerProxy::AddSystemAbilityWrapper(int32_t code, MessageParcel& data)
{
    return ERR_INVALID_VALUE;
}

int32_t SystemAbilityManagerProxy::AddSystemProcess(
    const std::u16string& procName, const sptr<IRemoteObject>& procObject)
{
    return ERR_INVALID_VALUE;
}
}