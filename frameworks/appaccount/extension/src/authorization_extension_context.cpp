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

#include "authorization_extension_context.h"

#include "ability_connection.h"
#include "ability_manager_client.h"
#include "account_log_wrapper.h"

using namespace OHOS::AccountSA;
namespace OHOS {
namespace AbilityRuntime {
const size_t AuthorizationExtensionContext::CONTEXT_TYPE_ID(
    std::hash<const char *>{}("AuthorizationExtensionContext"));

ErrCode AuthorizationExtensionContext::ConnectAbility(
    const AAFwk::Want &want, const sptr<AbilityConnectCallback> &connectCallback) const
{
    ErrCode ret =
        ConnectionManager::GetInstance().ConnectAbility(token_, want, connectCallback);
    ACCOUNT_LOGI("AuthorizationExtensionContext::ConnectAbility ErrorCode = %{public}d", ret);
    return ret;
}

ErrCode AuthorizationExtensionContext::DisconnectAbility(
    const AAFwk::Want &want, const sptr<AbilityConnectCallback> &connectCallback) const
{
    ErrCode ret =
        ConnectionManager::GetInstance().DisconnectAbility(token_, want.GetElement(), connectCallback);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("%{public}s end DisconnectAbility error, ret=%{public}d", __func__, ret);
    }
    return ret;
}
} // namespace AbilityRuntime
} // namespace OHOS