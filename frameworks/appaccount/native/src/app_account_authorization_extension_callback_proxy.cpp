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

#include "app_account_authorization_extension_callback_proxy.h"

#include <securec.h>
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "want.h"

namespace OHOS {
namespace AccountSA {
AppAccountAuthorizationExtensionCallbackProxy::AppAccountAuthorizationExtensionCallbackProxy(
    const sptr<IRemoteObject> &object)
    : IRemoteProxy<IAppAccountAuthorizationExtensionCallback>(object)
{}

AppAccountAuthorizationExtensionCallbackProxy::~AppAccountAuthorizationExtensionCallbackProxy()
{}

ErrCode AppAccountAuthorizationExtensionCallbackProxy::SendRequest(
    AppAccountAuthorizationExtensionCallbackInterfaceCode code, MessageParcel &data)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ACCOUNT_LOGE("remote is nullptr, code = %{public}d", code);
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    return remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
}

void AppAccountAuthorizationExtensionCallbackProxy::OnResult(
    const AsyncCallbackError &businessError, const AAFwk::WantParams &parameters)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor");
        return;
    }
    if (!data.WriteInt32(businessError.code)) {
        ACCOUNT_LOGE("failed to write error code");
        return;
    }
    if (!data.WriteString(businessError.message)) {
        ACCOUNT_LOGE("failed to write error message");
        return;
    }
    if (!data.WriteParcelable(&businessError.data)) {
        ACCOUNT_LOGE("failed to write error data");
        return;
    }
    if (!data.WriteParcelable(&parameters)) {
        ACCOUNT_LOGE("failed to write request parameters");
        return;
    }
    ErrCode result = SendRequest(AppAccountAuthorizationExtensionCallbackInterfaceCode::ON_RESULT, data);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to send request, error code: %{public}d", result);
    }
}

void AppAccountAuthorizationExtensionCallbackProxy::OnRequestRedirected(const AAFwk::Want& request)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor");
        return;
    }
    if (!data.WriteParcelable(&request)) {
        ACCOUNT_LOGE("failed to write request");
        return;
    }
    ErrCode result = SendRequest(AppAccountAuthorizationExtensionCallbackInterfaceCode::ON_REQUEST_REDIRECTED, data);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to send request, error code: %{public}d", result);
    }
}
} // namespace AccountSA
} // namespace OHOS
