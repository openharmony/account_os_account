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
    return ProcOnResult(data, reply);
}

int32_t AppAccountAuthorizationExtensionCallbackStub::ProcOnResult(MessageParcel &data, MessageParcel &reply)
{
    int32_t result;
    if (!data.ReadInt32(result)) {
        ACCOUNT_LOGE("failed to read result");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::shared_ptr<AAFwk::WantParams> parameters(data.ReadParcelable<AAFwk::WantParams>());
    if (parameters == nullptr) {
        ACCOUNT_LOGE("failed to read extension parameters");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    OnResult(result, (*parameters));
    return ERR_NONE;
}
}  // namespace AccountSA
}  // namespace OHOS
