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

#include "app_account_authorization_extension_proxy.h"

#include "account_error_no.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
AppAccountAuthorizationExtensionProxy::AppAccountAuthorizationExtensionProxy(const sptr<IRemoteObject> &object)
    : IRemoteProxy<IAppAccountAuthorizationExtension>(object)
{}

AppAccountAuthorizationExtensionProxy::~AppAccountAuthorizationExtensionProxy()
{}

ErrCode AppAccountAuthorizationExtensionProxy::SendRequest(
    AppAccountAuthorizationExtensionInterfaceCode code, MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ACCOUNT_LOGE("remote is nullptr, code = %{public}d", code);
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }
    MessageOption option(MessageOption::TF_SYNC);
    ErrCode result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("fail to send request, result: %{public}d", result);
        return result;
    }
    if (!reply.ReadInt32(result)) {
        ACCOUNT_LOGE("fail to read result");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    return result;
}

static ErrCode WriteRequest(MessageParcel &data, const AuthorizationRequest &request)
{
    if (!data.WriteInt32(request.isEnableContext)) {
        ACCOUNT_LOGE("failed to write request isEnableContext");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt32(request.callerUid)) {
        ACCOUNT_LOGE("failed to write request callerUid");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&request.parameters)) {
        ACCOUNT_LOGE("fail to write write request parameters");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if ((request.callback == nullptr) || (!data.WriteRemoteObject(request.callback->AsObject()))) {
        ACCOUNT_LOGE("fail to write request callback");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode AppAccountAuthorizationExtensionProxy::StartAuthorization(const AuthorizationRequest &request)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("fail to write descriptor");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    ErrCode result = WriteRequest(data, request);
    if (result != ERR_OK) {
        return result;
    }
    MessageParcel reply;
    return SendRequest(
        AppAccountAuthorizationExtensionInterfaceCode::START_AUTHENTICATION, data, reply);
}
}  // namespace AccountSA
}  // namespace OHOS
