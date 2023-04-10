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

#include "domain_account_stub.h"

#include <securec.h>
#include "account_log_wrapper.h"
#include "account_permission_manager.h"
#include "domain_account_callback_proxy.h"
#include "domain_auth_callback_proxy.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AccountSA {
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
    },
    {
        IDomainAccount::Message::DOMAIN_ACCOUNT_STATUS_ENQUIRY,
        &DomainAccountStub::ProcGetAccountStatus
    },
    {
        IDomainAccount::Message::DOMAIN_ACCOUNT_STATUS_LISTENER_REGISTER,
        &DomainAccountStub::ProcRegisterAccountStatusListener
    },
    {
        IDomainAccount::Message::DOMAIN_ACCOUNT_STATUS_LISTENER_UNREGISTER,
        &DomainAccountStub::ProcUnregisterAccountStatusListener
    },
    {
        IDomainAccount::Message::DOMAIN_AUTH_WITH_POPUP,
        &DomainAccountStub::ProcAuthWithPopup
    },
    {
        IDomainAccount::Message::DOMAIN_HAS_DOMAIN_ACCOUNT,
        &DomainAccountStub::ProcHasDomainAccount
    },
    {
        IDomainAccount::Message::DOMAIN_UPDATE_ACCOUNT_TOKEN,
        &DomainAccountStub::ProcUpdateAccountToken
    },
    {
        IDomainAccount::Message::DOMAIN_GET_ACCESS_TOKEN,
        &DomainAccountStub::ProcGetDomainAccessToken
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

ErrCode DomainAccountStub::ProcHasDomainAccount(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<DomainAccountInfo> info(data.ReadParcelable<DomainAccountInfo>());
    if (info == nullptr) {
        ACCOUNT_LOGE("failed to read domain account info");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    auto callback = iface_cast<IDomainAccountCallback>(data.ReadRemoteObject());
    if (callback == nullptr) {
        ACCOUNT_LOGE("failed to read domain callback");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    ErrCode result = HasDomainAccount(*info, callback);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode DomainAccountStub::ProcUpdateAccountToken(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<DomainAccountInfo> info(data.ReadParcelable<DomainAccountInfo>());
    if (info == nullptr) {
        ACCOUNT_LOGE("failed to read domain account info");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::vector<uint8_t> token;
    if (!data.ReadUInt8Vector(&token)) {
        ACCOUNT_LOGE("fail to read token");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    ErrCode result = UpdateAccountToken(*info, token);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
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
    ErrCode result = ERR_ACCOUNT_COMMON_INVALID_PARAMTER;
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
    } else {
        result = Auth(info, password, callback);
    }
    (void)memset_s(password.data(), password.size(), 0, password.size());
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write auth result");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode DomainAccountStub::ProcGetAccountStatus(MessageParcel &data, MessageParcel &reply)
{
    std::string domain;
    if (!data.ReadString(domain)) {
        ACCOUNT_LOGE("fail to read userId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::string accountName;
    if (!data.ReadString(accountName)) {
        ACCOUNT_LOGE("fail to read accountName");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    DomainAccountStatus status;
    ErrCode result = GetAccountStatus(domain, accountName, status);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write result");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteInt32(status)) {
        ACCOUNT_LOGE("failed to write status");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode DomainAccountStub::ProcRegisterAccountStatusListener(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<DomainAccountInfo> info(data.ReadParcelable<DomainAccountInfo>());
    if (info == nullptr) {
        ACCOUNT_LOGE("failed to read domain account info");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    auto callback = iface_cast<IDomainAccountCallback>(data.ReadRemoteObject());
    if (callback == nullptr) {
        ACCOUNT_LOGE("failed to read domain callback");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    ErrCode result = RegisterAccountStatusListener(*info, callback);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    return ERR_OK;
}

ErrCode DomainAccountStub::ProcUnregisterAccountStatusListener(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<DomainAccountInfo> info(data.ReadParcelable<DomainAccountInfo>());
    if (info == nullptr) {
        ACCOUNT_LOGE("failed to read domain account info");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    ErrCode result = UnregisterAccountStatusListener(*info);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_OK;
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
    ErrCode result = ERR_ACCOUNT_COMMON_INVALID_PARAMTER;
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
    } else {
        result = AuthUser(userId, password, callback);
    }
    (void)memset_s(password.data(), password.size(), 0, password.size());
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write authUser result");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode DomainAccountStub::ProcAuthWithPopup(MessageParcel &data, MessageParcel &reply)
{
    int32_t userId = 0;
    if (!data.ReadInt32(userId)) {
        ACCOUNT_LOGE("fail to read userId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    auto callback = iface_cast<IDomainAuthCallback>(data.ReadRemoteObject());
    ErrCode result = ERR_ACCOUNT_COMMON_INVALID_PARAMTER;
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
    } else {
        result = AuthWithPopup(userId, callback);
    }
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write authUser result");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode DomainAccountStub::ProcGetDomainAccessToken(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<DomainAccountInfo> info(data.ReadParcelable<DomainAccountInfo>());
    if (info == nullptr) {
        ACCOUNT_LOGE("failed to read domain account info");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::shared_ptr<AAFwk::WantParams> parameters(data.ReadParcelable<AAFwk::WantParams>());
    if (parameters == nullptr) {
        ACCOUNT_LOGE("failed to read domain parameters");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    auto callback = iface_cast<IDomainAccountCallback>(data.ReadRemoteObject());
    if (callback == nullptr) {
        ACCOUNT_LOGE("failed to read domain callback");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    ErrCode result = GetAccessToken(*info, *parameters, callback);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode DomainAccountStub::CheckPermission(uint32_t code, int32_t uid)
{
    ErrCode errCode = AccountPermissionManager::CheckSystemApp();
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("the caller is not system application, errCode = %{public}d.", errCode);
        return errCode;
    }
    if (uid == 0) {
        return ERR_OK;
    }
    std::string permissionName;
    switch (code) {
        case IDomainAccount::Message::REGISTER_PLUGIN:
        case IDomainAccount::Message::UNREGISTER_PLUGIN:
        case IDomainAccount::Message::DOMAIN_HAS_DOMAIN_ACCOUNT:
        case IDomainAccount::Message::DOMAIN_UPDATE_ACCOUNT_TOKEN:
            permissionName = AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS;
            break;
        case IDomainAccount::Message::DOMAIN_ACCOUNT_STATUS_ENQUIRY:
        case IDomainAccount::Message::DOMAIN_ACCOUNT_STATUS_LISTENER_REGISTER:
        case IDomainAccount::Message::DOMAIN_ACCOUNT_STATUS_LISTENER_UNREGISTER:
            permissionName = AccountPermissionManager::GET_LOCAL_ACCOUNTS;
            break;
        case IDomainAccount::Message::DOMAIN_AUTH:
        case IDomainAccount::Message::DOMAIN_AUTH_USER:
        case IDomainAccount::Message::DOMAIN_AUTH_WITH_POPUP:
            permissionName = AccountPermissionManager::ACCESS_USER_AUTH_INTERNAL;
            break;
        default:
            break;
    }
    if (code == IDomainAccount::Message::DOMAIN_GET_ACCESS_TOKEN) {
        errCode = AccountPermissionManager::VerifyPermission(AccountPermissionManager::MANAGE_LOCAL_ACCOUNTS);
        if (errCode != ERR_OK) {
            return AccountPermissionManager::VerifyPermission(AccountPermissionManager::GET_LOCAL_ACCOUNTS);
        }
        return ERR_OK;
    }
    if (permissionName.empty()) {
        return ERR_OK;
    }
    return AccountPermissionManager::VerifyPermission(permissionName);
}
}  // namespace AccountSA
}  // namespace OHOS
