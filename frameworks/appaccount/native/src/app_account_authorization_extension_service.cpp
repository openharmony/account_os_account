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

#include "app_account_authorization_extension_service.h"

#include "account_log_wrapper.h"
#include "app_account_authorization_extension_callback_client.h"

namespace OHOS {
namespace AccountSA {
AppAccountAuthorizationExtensionService::AppAccountAuthorizationExtensionService(
    const AuthorizationExtensionServiceFunc &func)
    : func_(func)
{}

AppAccountAuthorizationExtensionService::~AppAccountAuthorizationExtensionService()
{}

ErrCode AppAccountAuthorizationExtensionService::StartAuthorization(const AuthorizationRequest &request)
{
    if (func_ == nullptr) {
        ACCOUNT_LOGE("func_ is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    if (request.callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    auto callback = std::make_shared<AppAccountAuthorizationExtensionCallbackClient>(request.callback);
    func_(request, callback);
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS