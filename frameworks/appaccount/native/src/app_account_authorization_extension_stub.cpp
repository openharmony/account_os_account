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

#include "app_account_authorization_extension_stub.h"

#include <securec.h>
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "app_account_common.h"
#include "ipc_skeleton.h"
#include "want.h"

namespace OHOS {
namespace AccountSA {
AppAccountAuthorizationExtensionStub::AppAccountAuthorizationExtensionStub()
{
    messageProcMap_[static_cast<uint32_t>(AppAccountAuthorizationExtensionInterfaceCode::START_AUTHENTICATION)] =
        &AppAccountAuthorizationExtensionStub::ProcStartAuthorization;
}

AppAccountAuthorizationExtensionStub::~AppAccountAuthorizationExtensionStub()
{}

int AppAccountAuthorizationExtensionStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    ACCOUNT_LOGD("Received stub message: %{public}d, callingUid: %{public}d", code, IPCSkeleton::GetCallingUid());
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ACCOUNT_LOGE("check descriptor failed!");
        return ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR;
    }
    const auto &itFunc = messageProcMap_.find(code);
    if (itFunc != messageProcMap_.end()) {
        return (this->*(itFunc->second))(data, reply);
    }
    ACCOUNT_LOGD("Code is not find");
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

static ErrCode ReadRequest(MessageParcel &data, AuthorizationRequest &request)
{
    if (!data.ReadBool(request.isEnableContext)) {
        ACCOUNT_LOGE("failed to write request isEnableContext");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.ReadInt32(request.callerUid)) {
        ACCOUNT_LOGE("failed to write request callerUid");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    std::shared_ptr<AAFwk::WantParams> parameters(data.ReadParcelable<AAFwk::WantParams>());
    if (parameters == nullptr) {
        ACCOUNT_LOGE("failed to read request parameters");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    request.parameters = (*parameters);
    auto callback = iface_cast<IAppAccountAuthorizationExtensionCallback>(data.ReadRemoteObject());
    if (callback == nullptr) {
        ACCOUNT_LOGE("failed to read domain callback");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    request.callback = callback;
    return ERR_OK;
}

ErrCode AppAccountAuthorizationExtensionStub::ProcStartAuthorization(MessageParcel &data, MessageParcel &reply)
{
    AuthorizationRequest request;
    ErrCode result = ReadRequest(data, request);
    if (result != ERR_OK) {
        return result;
    }
    result = StartAuthorization(request);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write result");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return ERR_NONE;
}
}  // namespace AccountSA
}  // namespace OHOS