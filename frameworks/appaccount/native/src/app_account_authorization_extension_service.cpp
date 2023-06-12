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
    const std::shared_ptr<AccountJsKit::JsAuthorizationExtension> &extension)
    : innerExtension_(extension)
{}

AppAccountAuthorizationExtensionService::~AppAccountAuthorizationExtensionService()
{}

ErrCode AppAccountAuthorizationExtensionService::CheckAndInitExecEnv(
    const sptr<IAppAccountAuthorizationExtensionCallback> &callback,
    AppAccountAuthorizationExtensionCallbackClient **callbackClient)
{
    if (innerExtension_ == nullptr) {
        ACCOUNT_LOGE("innerExtension_ is nullptr");
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    *callbackClient = new (std::nothrow) AppAccountAuthorizationExtensionCallbackClient(callback);
    if (*callbackClient == nullptr) {
        ACCOUNT_LOGE("failed to create app account authorization extension callback client");
        return ERR_ACCOUNT_COMMON_INSUFFICIENT_MEMORY_ERROR;
    }
    return ERR_OK;
}

ErrCode AppAccountAuthorizationExtensionService::StartAuthorization(const AuthorizationRequest &request)
{
    AppAccountAuthorizationExtensionCallbackClient *callbackClient = nullptr;
    ErrCode errCode = CheckAndInitExecEnv(request.callback, &callbackClient);
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_ptr<AppAccountAuthorizationExtensionCallbackClient> callbackPtr(callbackClient);
    innerExtension_->StartAuthorization(request, callbackPtr, innerExtension_);
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS