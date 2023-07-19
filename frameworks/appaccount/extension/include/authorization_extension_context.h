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

#ifndef OHOS_ABILITY_RUNTIME_AUTHORIZATION_EXTENSION_CONTEXT_H
#define OHOS_ABILITY_RUNTIME_AUTHORIZATION_EXTENSION_CONTEXT_H

#include "ability_connect_callback.h"
#include "connection_manager.h"
#include "extension_context.h"
#include "local_call_container.h"
#include "start_options.h"
#include "want.h"

namespace OHOS {
namespace AbilityRuntime {
/**
 * @brief context supply for service
 *
 */
class AuthorizationExtensionContext : public ExtensionContext {
public:
    AuthorizationExtensionContext() = default;
    virtual ~AuthorizationExtensionContext() = default;
    ErrCode ConnectAbility(const AAFwk::Want &want, const sptr<AbilityConnectCallback> &connectCallback) const;
    ErrCode DisconnectAbility(const AAFwk::Want &want, const sptr<AbilityConnectCallback> &connectCallback) const;

    using SelfType = AuthorizationExtensionContext;
    static const size_t CONTEXT_TYPE_ID;

private:
    /**
     * @brief Get Current Ability Type
     *
     * @return Current Ability Type
     */
    OHOS::AppExecFwk::AbilityType GetAbilityInfoType() const;
    std::map<int, RuntimeTask> resultCallbacks_;
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_AUTHORIZATION_EXTENSION_CONTEXT_H
