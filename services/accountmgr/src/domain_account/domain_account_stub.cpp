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

#include "domain_account_stub.h"

#include "account_log_wrapper.h"
#include "account_permission_manager.h"
#include "domain_auth_callback_proxy.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AccountSA {
namespace {
const size_t MAX_PASSWORD_SIZE = 4096;
}

DomainAccountStub::DomainAccountStub()
{}

DomainAccountStub::~DomainAccountStub()
{}

const std::map<uint32_t, DomainAccountStub::DomainAccountStubFunc> DomainAccountStub::stubFuncMap_ = {
    {
        IDomainAccount::Message::REGISTER_PLUGIN,
        &DomainAccountStub::ProcRegisterPlugin
    },
    {
        IDomainAccount::Message::UNREGISTER_PLUGIN,
        &DomainAccountStub::ProcUnregisterPlugin
    },
    {
        IDomainAccount::Message::DOMAIN_AUTH,
        &DomainAccountStub::ProcAuth
    },
    {
        IDomainAccount::Message::DOMAIN_AUTH_USER,
        &DomainAccountStub::ProcAuthUser
    }
};

int32_t DomainAccountStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int32_t uid = IPCSkeleton::GetCallingUid();
    ACCOUNT_LOGD("Received stub message: %{public}d, callingUid: %{public}d", code, uid);
    ErrCode errCode = CheckPermission(code, uid);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("check permission failed");
        return errCode;
    }
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ACCOUNT_LOGE("check descriptor failed! code %{public}u.", code);
        return ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR;
    }
    const auto &itFunc = stubFuncMap_.find(code);
    if (itFunc != stubFuncMap_.end()) {
        return (this->*(itFunc->second))(data, reply);
    }
    ACCOUNT_LOGW("remote request unhandled: %{public}d", code);
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

ErrCode DomainAccountStub::ProcRegisterPlugin(MessageParcel &data, MessageParcel &reply)
{
    auto plugin = iface_cast<IDomainAccountPlugin>(data.ReadRemoteObject());
    ErrCode result = RegisterPlugin(plugin);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write result");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode DomainAccountStub::ProcUnregisterPlugin(MessageParcel &data, MessageParcel &reply)
{
    ErrCode result = UnregisterPlugin();
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("fail to write result");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode DomainAccountStub::ProcAuth(MessageParcel &data, MessageParcel &reply)
{
    DomainAccountInfo info;
    if (!data.ReadString(info.accountName_)) {
        ACCOUNT_LOGE("fail to read name");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    if (!data.ReadString(info.domain_)) {
        ACCOUNT_LOGE("fail to read domain");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::vector<uint8_t> password;
    if (!data.ReadUInt8Vector(&password)) {
        ACCOUNT_LOGE("fail to read password");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    auto callback = iface_cast<IDomainAuthCallback>(data.ReadRemoteObject());
    size_t passwordSize = password.size();
    ErrCode result = ERR_ACCOUNT_COMMON_INVALID_PARAMTER;
    if (passwordSize > MAX_PASSWORD_SIZE) {
        ACCOUNT_LOGE("password is too large");
    } else if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
    } else {
        result = Auth(info, password, callback);
    }
    for (size_t i = 0; i < passwordSize; ++i) {
        password[i] = 0;
    }
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write auth result");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode DomainAccountStub::ProcAuthUser(MessageParcel &data, MessageParcel &reply)
{
    int32_t userId = 0;
    if (!data.ReadInt32(userId)) {
        ACCOUNT_LOGE("fail to read userId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::vector<uint8_t> password;
    if (!data.ReadUInt8Vector(&password)) {
        ACCOUNT_LOGE("fail to read password");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    auto callback = iface_cast<IDomainAuthCallback>(data.ReadRemoteObject());
    size_t passwordSize = password.size();
    ErrCode result = ERR_ACCOUNT_COMMON_INVALID_PARAMTER;
    if (passwordSize > MAX_PASSWORD_SIZE) {
        ACCOUNT_LOGE("password is too large");
    } else if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
    } else {
        result = AuthUser(userId, password, callback);
    }
    for (size_t i = 0; i < passwordSize; ++i) {
        password[i] = 0;
    }
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write authUser result");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode DomainAccountStub::CheckPermission(uint32_t code, int32_t uid)
{
    if (uid == 0) {
        return ERR_OK;
    }
    std::string permissionName;
    switch (code) {
        case IDomainAccount::Message::REGISTER_PLUGIN:
        case IDomainAccount::Message::UNREGISTER_PLUGIN:
            permissionName = AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS;
            break;
        case IDomainAccount::Message::DOMAIN_AUTH:
        case IDomainAccount::Message::DOMAIN_AUTH_USER:
            permissionName = AccountPermissionManager::ACCESS_USER_AUTH_INTERNAL;
            break;
        default:
            break;
    }
    if (permissionName.empty()) {
        return ERR_OK;
    }
    return AccountPermissionManager::GetInstance()->VerifyPermission(permissionName);
}
}  // namespace AccountSA
}  // namespace OHOS
