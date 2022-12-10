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

#include "domain_account_plugin_stub.h"

#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AccountSA {
namespace {
const size_t MAX_PASSWORD_SIZE = 4096;
}

DomainAccountPluginStub::DomainAccountPluginStub()
{}

DomainAccountPluginStub::~DomainAccountPluginStub()
{}

const std::map<std::uint32_t, DomainAccountPluginStub::MessageProcFunction> DomainAccountPluginStub::messageProcMap_ = {
    {
        IDomainAccountPlugin::Message::DOMAIN_PLUGIN_AUTH,
        &DomainAccountPluginStub::ProcAuth
    },
    {
        IDomainAccountPlugin::Message::DOMAIN_PLUGIN_GET_AUTH_PROPERTY,
        &DomainAccountPluginStub::ProcGetAuthProperty
    }
};

int DomainAccountPluginStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    ACCOUNT_LOGD("Received stub message: %{public}d, callingUid: %{public}d", code, IPCSkeleton::GetCallingUid());
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ACCOUNT_LOGE("check descriptor failed! code %{public}u.", code);
        return ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR;
    }
    const auto &itFunc = messageProcMap_.find(code);
    if (itFunc != messageProcMap_.end()) {
        return (this->*(itFunc->second))(data, reply);
    }
    ACCOUNT_LOGW("remote request unhandled: %{public}d", code);
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

ErrCode DomainAccountPluginStub::ProcAuth(MessageParcel &data, MessageParcel &reply)
{
    DomainAccountInfo info;
    if (!data.ReadString(info.accountName_)) {
        ACCOUNT_LOGE("failed to read domain account name");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    if (!data.ReadString(info.domain_)) {
        ACCOUNT_LOGE("failed to read domain");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::vector<uint8_t> password;
    if (!data.ReadUInt8Vector(&password)) {
        ACCOUNT_LOGE("failed to read password");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    sptr<IDomainAuthCallback> callbackProxy = iface_cast<IDomainAuthCallback>(data.ReadRemoteObject());
    size_t passwordSize = password.size();
    ErrCode result = ERR_ACCOUNT_COMMON_INVALID_PARAMTER;
    if (passwordSize > MAX_PASSWORD_SIZE) {
        ACCOUNT_LOGE("password is too large");
    } else if (callbackProxy == nullptr) {
        ACCOUNT_LOGE("invalid callback");
    } else {
        result = Auth(info, password, callbackProxy);
    }
    for (size_t i = 0; i < passwordSize; ++i) {
        password[i] = 0;
    }
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write result");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}


ErrCode DomainAccountPluginStub::ProcGetAuthProperty(MessageParcel &data, MessageParcel &reply)
{
    DomainAccountInfo info;
    if (!data.ReadString(info.accountName_)) {
        ACCOUNT_LOGE("failed to read domain account name");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    if (!data.ReadString(info.domain_)) {
        ACCOUNT_LOGE("failed to read domain");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    DomainAuthProperty prop;
    ErrCode result = GetAuthProperty(info, prop);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write result");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!reply.WriteInt32(prop.remainingTimes)) {
        ACCOUNT_LOGE("failed to write remaining times");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!reply.WriteInt32(prop.freezingTime)) {
        ACCOUNT_LOGE("failed to write freezing time");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return ERR_NONE;
}
}  // namespace AccountSA
}  // namespace OHOS