/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "domain_account_plugin_stub.h"

#include <securec.h>
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "ipc_skeleton.h"
#include "want.h"

namespace OHOS {
namespace AccountSA {
const std::map<DomainAccountPluginInterfaceCode, DomainAccountPluginStub::MessageProcFunction>
    messageProcMap = {
    {
        DomainAccountPluginInterfaceCode::DOMAIN_PLUGIN_AUTH,
        &DomainAccountPluginStub::ProcAuthCommonInterface
    },
    {
        DomainAccountPluginInterfaceCode::DOMAIN_PLUGIN_GET_AUTH_STATUS_INFO,
        &DomainAccountPluginStub::ProcGetAuthStatusInfo
    },
    {
        DomainAccountPluginInterfaceCode::DOMAIN_PLUGIN_GET_DOMAIN_ACCOUNT_INFO,
        &DomainAccountPluginStub::ProcGetDomainAccountInfo
    },
    {
        DomainAccountPluginInterfaceCode::DOMAIN_PLUGIN_ON_ACCOUNT_BOUND,
        &DomainAccountPluginStub::ProcOnAccountBound
    },
    {
        DomainAccountPluginInterfaceCode::DOMAIN_PLUGIN_ON_ACCOUNT_UNBOUND,
        &DomainAccountPluginStub::ProcOnAccountUnBound
    },
    {
        DomainAccountPluginInterfaceCode::DOMAIN_PLUGIN_IS_ACCOUNT_TOKEN_VALID,
        &DomainAccountPluginStub::ProcIsAccountTokenValid
    },
    {
        DomainAccountPluginInterfaceCode::DOMAIN_PLUGIN_GET_ACCESS_TOKEN,
        &DomainAccountPluginStub::ProcGetAccessToken
    }
};

DomainAccountPluginStub::DomainAccountPluginStub()
{
    messageProcMap_ = messageProcMap;
}

DomainAccountPluginStub::~DomainAccountPluginStub()
{}

int DomainAccountPluginStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    ACCOUNT_LOGD("Received stub message: %{public}d, callingUid: %{public}d", code, IPCSkeleton::GetCallingUid());
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ACCOUNT_LOGE("check descriptor failed! code %{public}u.", code);
        return ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR;
    }
    const auto &itFunc = messageProcMap_.find(static_cast<DomainAccountPluginInterfaceCode>(code));
    if (itFunc != messageProcMap_.end()) {
        return (this->*(itFunc->second))(data, reply);
    }
    ACCOUNT_LOGW("remote request unhandled: %{public}d", code);
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

ErrCode DomainAccountPluginStub::ProcAuthCommonInterface(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<DomainAccountInfo> info(data.ReadParcelable<DomainAccountInfo>());
    if (info == nullptr) {
        ACCOUNT_LOGE("failed to read domain account info");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::vector<uint8_t> authData;
    if (!data.ReadUInt8Vector(&authData)) {
        ACCOUNT_LOGE("failed to read password");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    sptr<IDomainAccountCallback> callbackProxy = iface_cast<IDomainAccountCallback>(data.ReadRemoteObject());
    int32_t mode = -1;
    if (!data.ReadInt32(mode)) {
        ACCOUNT_LOGE("failed to read authMode");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    AuthMode authMode = static_cast<AuthMode>(mode);
    ErrCode result = ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    if (callbackProxy == nullptr) {
        ACCOUNT_LOGE("invalid callback");
    } else {
        switch (authMode) {
            case AUTH_WITH_CREDENTIAL_MODE: {
                result = Auth(*info, authData, callbackProxy);
                break;
            }
            case AUTH_WITH_POPUP_MODE: {
                result = AuthWithPopup(*info, callbackProxy);
                break;
            }
            case AUTH_WITH_TOKEN_MODE: {
                result = AuthWithToken(*info, authData, callbackProxy);
                break;
            }
            default: {
                ACCOUNT_LOGE("invalid case");
                result = ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
            }
        }
    }
    (void)memset_s(authData.data(), authData.size(), 0, authData.size());
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write result");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode DomainAccountPluginStub::ProcGetAuthStatusInfo(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<DomainAccountInfo> info(data.ReadParcelable<DomainAccountInfo>());
    if (info == nullptr) {
        ACCOUNT_LOGE("failed to read domain account info");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    sptr<IDomainAccountCallback> callback = iface_cast<IDomainAccountCallback>(data.ReadRemoteObject());
    if (callback == nullptr) {
        ACCOUNT_LOGE("failed to read domain account callback");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    ErrCode result = GetAuthStatusInfo(*info, callback);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write result");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return ERR_NONE;
}

ErrCode DomainAccountPluginStub::ProcIsAccountTokenValid(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<DomainAccountInfo> info(data.ReadParcelable<DomainAccountInfo>());
    if (info == nullptr) {
        ACCOUNT_LOGE("failed to read domain account info");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::vector<uint8_t> token;
    if (!data.ReadUInt8Vector(&token)) {
        ACCOUNT_LOGE("failed to read token");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    auto callback = iface_cast<IDomainAccountCallback>(data.ReadRemoteObject());
    if (callback == nullptr) {
        ACCOUNT_LOGE("failed to read callback");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    ErrCode result = IsAccountTokenValid(*info, token, callback);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write result");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return ERR_NONE;
}

ErrCode DomainAccountPluginStub::ProcGetAccessToken(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<DomainAccountInfo> domainInfo(data.ReadParcelable<DomainAccountInfo>());
    if (domainInfo == nullptr) {
        ACCOUNT_LOGE("failed to read domain account info");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::vector<uint8_t> accountToken;
    if (!data.ReadUInt8Vector(&accountToken)) {
        ACCOUNT_LOGE("failed to read user token");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::shared_ptr<GetAccessTokenOptions> option(data.ReadParcelable<GetAccessTokenOptions>());
    if (option == nullptr) {
        ACCOUNT_LOGE("failed to read option");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    auto callback = iface_cast<IDomainAccountCallback>(data.ReadRemoteObject());
    if (callback == nullptr) {
        ACCOUNT_LOGE("failed to read callback");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    ErrCode result = GetAccessToken(*domainInfo, accountToken, *option, callback);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write result");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return ERR_NONE;
}

ErrCode DomainAccountPluginStub::ProcGetDomainAccountInfo(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<GetDomainAccountInfoOptions> options(data.ReadParcelable<GetDomainAccountInfoOptions>());
    if (options == nullptr) {
        ACCOUNT_LOGE("failed to read option");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    auto callback = iface_cast<IDomainAccountCallback>(data.ReadRemoteObject());
    if (callback == nullptr) {
        ACCOUNT_LOGE("failed to read callback");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    ErrCode result = GetDomainAccountInfo(*options, callback);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write result");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return ERR_NONE;
}

ErrCode DomainAccountPluginStub::ProcOnAccountBound(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<DomainAccountInfo> info(data.ReadParcelable<DomainAccountInfo>());
    if (info == nullptr) {
        ACCOUNT_LOGE("failed to read domain account info");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("fail to read localId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    auto callback = iface_cast<IDomainAccountCallback>(data.ReadRemoteObject());
    if (callback == nullptr) {
        ACCOUNT_LOGE("failed to read callback");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    ErrCode result = OnAccountBound(*info, localId, callback);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write result");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return ERR_NONE;
}

ErrCode DomainAccountPluginStub::ProcOnAccountUnBound(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<DomainAccountInfo> info(data.ReadParcelable<DomainAccountInfo>());
    if (info == nullptr) {
        ACCOUNT_LOGE("failed to read domain account info");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    auto callback = iface_cast<IDomainAccountCallback>(data.ReadRemoteObject());
    if (callback == nullptr) {
        ACCOUNT_LOGE("failed to read callback");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    ErrCode result = OnAccountUnBound(*info, callback);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write result");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return ERR_NONE;
}
}  // namespace AccountSA
}  // namespace OHOS