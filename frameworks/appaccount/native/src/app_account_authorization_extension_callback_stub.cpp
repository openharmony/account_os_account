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

#include "app_account_authorization_extension_callback_stub.h"

#include <securec.h>
#include "account_log_wrapper.h"
#include "app_account_common.h"
#include "ipc_skeleton.h"
#include "want.h"

namespace OHOS {
namespace AccountSA {

AppAccountAuthorizationExtensionCallbackStub::AppAccountAuthorizationExtensionCallbackStub()
{}

AppAccountAuthorizationExtensionCallbackStub::~AppAccountAuthorizationExtensionCallbackStub()
{}

int32_t AppAccountAuthorizationExtensionCallbackStub::OnRemoteRequest(
    std::uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ACCOUNT_LOGE("check descriptor failed!");
        return ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR;
    }
    switch (code) {
        case static_cast<uint32_t>(AppAccountAuthorizationExtensionCallbackInterfaceCode::ON_RESULT):
            return ProcOnResult(data, reply);
        case static_cast<uint32_t>(AppAccountAuthorizationExtensionCallbackInterfaceCode::ON_REQUEST_REDIRECTED):
            return ProcOnRequestRedirected(data, reply);
        default:
            break;
    }
    ACCOUNT_LOGW("remote request unhandled: %{public}d", code);
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t AppAccountAuthorizationExtensionCallbackStub::ProcOnResult(MessageParcel &data, MessageParcel &reply)
{
    AsyncCallbackError businessError;
    if (!data.ReadInt32(businessError.code)) {
        ACCOUNT_LOGE("failed to read code");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    if (!data.ReadString(businessError.message)) {
        ACCOUNT_LOGE("failed to read message");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::shared_ptr<AAFwk::WantParams> errParameters(data.ReadParcelable<AAFwk::WantParams>());
    if (errParameters == nullptr) {
        ACCOUNT_LOGE("failed to read errParameters");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    businessError.data = *(errParameters);
    std::shared_ptr<AAFwk::WantParams> parameters(data.ReadParcelable<AAFwk::WantParams>());
    if (parameters == nullptr) {
        ACCOUNT_LOGE("failed to read extension parameters");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    OnResult(businessError, (*parameters));
    return ERR_NONE;
}

int32_t AppAccountAuthorizationExtensionCallbackStub::ProcOnRequestRedirected(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<AAFwk::Want> requestPtr(data.ReadParcelable<AAFwk::Want>());
    if (requestPtr == nullptr) {
        ACCOUNT_LOGE("failed to read extension requestPtr");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    OnRequestRedirected(*requestPtr);
    return ERR_NONE;
}
}  // namespace AccountSA
}  // namespace OHOS
