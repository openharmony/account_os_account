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

#ifndef OHOS_ABILITY_RUNTIME_AUTHENTICATION_EXTENSION_CONTEXT_H
#define OHOS_ABILITY_RUNTIME_AUTHENTICATION_EXTENSION_CONTEXT_H

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
class AuthenticationExtensionContext : public ExtensionContext {
public:
    AuthenticationExtensionContext() = default;
    virtual ~AuthenticationExtensionContext() = default;

    ErrCode StartModalDialogForResult(const AAFwk::Want &want) const;

    using SelfType = AuthenticationExtensionContext;
    static const size_t CONTEXT_TYPE_ID;

private:
    static int ILLEGAL_REQUEST_CODE;

    /**
     * @brief Get Current Ability Type
     *
     * @return Current Ability Type
     */
    OHOS::AppExecFwk::AbilityType GetAbilityInfoType() const;
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_AUTHENTICATION_EXTENSION_CONTEXT_H
