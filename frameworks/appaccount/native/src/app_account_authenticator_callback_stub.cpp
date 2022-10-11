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

#include "app_account_authenticator_callback_stub.h"

#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "app_account_common.h"

namespace OHOS {
namespace AccountSA {
AppAccountAuthenticatorCallbackStub::AppAccountAuthenticatorCallbackStub()
{}

AppAccountAuthenticatorCallbackStub::~AppAccountAuthenticatorCallbackStub()
{}

int AppAccountAuthenticatorCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ACCOUNT_LOGE("failed to check descriptor! code %{public}u.", code);
        return ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR;
    }

    ErrCode errCode = ERR_OK;
    switch (code) {
        case static_cast<uint32_t>(IAppAccountAuthenticatorCallback::Message::ACCOUNT_RESULT): {
            int32_t resultCode = data.ReadInt32();
            std::shared_ptr<AAFwk::Want> resultPtr(data.ReadParcelable<AAFwk::Want>());
            if (resultPtr == nullptr) {
                AAFwk::Want result;
                OnResult(ERR_JS_ACCOUNT_AUTHENTICATOR_SERVICE_EXCEPTION, result);
                errCode = ERR_APPACCOUNT_SERVICE_OAUTH_INVALID_RESPONSE;
            } else {
                OnResult(resultCode, *resultPtr);
            }
            if (!reply.WriteInt32(errCode)) {
                ACCOUNT_LOGE("failed to write reply");
                return IPC_STUB_WRITE_PARCEL_ERR;
            }
            break;
        }
        case static_cast<uint32_t>(IAppAccountAuthenticatorCallback::Message::ACCOUNT_REQUEST_REDIRECTED): {
            std::shared_ptr<AAFwk::Want> requestPtr(data.ReadParcelable<AAFwk::Want>());
            if (requestPtr == nullptr) {
                AAFwk::Want request;
                OnRequestRedirected(request);
                errCode = ERR_APPACCOUNT_SERVICE_OAUTH_INVALID_RESPONSE;
            } else {
                OnRequestRedirected(*requestPtr);
            }
            if (!reply.WriteInt32(errCode)) {
                ACCOUNT_LOGE("failed to write reply");
                return IPC_STUB_WRITE_PARCEL_ERR;
            }
            break;
        }
        case static_cast<uint32_t>(IAppAccountAuthenticatorCallback::Message::ACCOUNT_REQUEST_CONTINUED): {
            OnRequestContinued();
            break;
        }
        default:
            ACCOUNT_LOGI("default, code = %{public}u, flags = %{public}u", code, option.GetFlags());
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return ERR_NONE;
}
}  // namespace AccountSA
}  // namespace OHOS
