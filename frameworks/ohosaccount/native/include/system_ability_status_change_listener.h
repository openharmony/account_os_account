/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_SYSTEM_ABILITY_STATUS_CHANGE_LISTENER
#define OS_ACCOUNT_SYSTEM_ABILITY_STATUS_CHANGE_LISTENER

#include "iservice_registry.h"
#include "ohos_account_kits_impl.h"
#include "system_ability_definition.h"
#include "system_ability_status_change_stub.h"

namespace OHOS {
namespace AccountSA {
class SystemAbilityStatusChangeListener : public OHOS::SystemAbilityStatusChangeStub {
public:
    SystemAbilityStatusChangeListener(const DomainAccountSubscribeSACallbackFunc &callback);
    ~SystemAbilityStatusChangeListener() = default;
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;

private:
    DomainAccountSubscribeSACallbackFunc domainCallback_ = nullptr;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // SYSTEM_ABILITY_STATUS_CHANGE_LISTENER
