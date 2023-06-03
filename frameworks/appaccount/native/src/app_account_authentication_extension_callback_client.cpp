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

#include "app_account_authentication_extension_callback_client.h"

#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "app_account_authentication_extension_callback_proxy.h"

namespace OHOS {
namespace AccountSA {
AppAccountAuthenticationExtensionCallbackClient::AppAccountAuthenticationExtensionCallbackClient(
    const sptr<IAppAccountAuthenticationExtensionCallback>& proxy)
    : proxy_(proxy)
{}

AppAccountAuthenticationExtensionCallbackClient::~AppAccountAuthenticationExtensionCallbackClient()
{}

void AppAccountAuthenticationExtensionCallbackClient::OnResult(
    const int32_t errCode, const AAFwk::WantParams& parameters)
{
    if (proxy_ != nullptr) {
        proxy_->OnResult(errCode, parameters);
    }
}
} // namespace AccountSA
} // namespace OHOS
