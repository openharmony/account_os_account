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
#include "ipc_skeleton.h"
#include "memory_guard.h"

namespace OHOS {
namespace AccountSA {
namespace {
const std::string MANAGE_LOCAL_ACCOUNTS = "ohos.permission.MANAGE_LOCAL_ACCOUNTS";
const std::string GET_LOCAL_ACCOUNTS = "ohos.permission.GET_LOCAL_ACCOUNTS";
const std::string ACCESS_USER_AUTH_INTERNAL = "ohos.permission.ACCESS_USER_AUTH_INTERNAL";
const std::string GET_DOMAIN_ACCOUNTS = "ohos.permission.GET_DOMAIN_ACCOUNTS";
}

const std::map<DomainAccountInterfaceCode, DomainAccountStub::DomainAccountStubFunc> stubFuncMap = {
    {
        DomainAccountInterfaceCode::REGISTER_PLUGIN,
        &DomainAccountStub::ProcRegisterPlugin
    },
    {
        DomainAccountInterfaceCode::UNREGISTER_PLUGIN,
        &DomainAccountStub::ProcUnregisterPlugin
    },
    {
        DomainAccountInterfaceCode::DOMAIN_AUTH,
        &DomainAccountStub::ProcAuth
    },
    {
        DomainAccountInterfaceCode::DOMAIN_AUTH_USER,
        &DomainAccountStub::ProcAuthUser
    },
    {
        DomainAccountInterfaceCode::DOMAIN_ACCOUNT_STATUS_ENQUIRY,
        &DomainAccountStub::ProcGetAccountStatus
    },
    {
        DomainAccountInterfaceCode::DOMAIN_ACCOUNT_STATUS_LISTENER_REGISTER,
        &DomainAccountStub::ProcRegisterAccountStatusListener
    },
    {
        DomainAccountInterfaceCode::DOMAIN_ACCOUNT_STATUS_LISTENER_UNREGISTER,
        &DomainAccountStub::ProcUnregisterAccountStatusListener
    },
    {
        DomainAccountInterfaceCode::DOMAIN_AUTH_WITH_POPUP,
        &DomainAccountStub::ProcAuthWithPopup
    },
    {
        DomainAccountInterfaceCode::DOMAIN_HAS_DOMAIN_ACCOUNT,
        &DomainAccountStub::ProcHasDomainAccount
    },
    {
        DomainAccountInterfaceCode::DOMAIN_UPDATE_ACCOUNT_TOKEN,
        &DomainAccountStub::ProcUpdateAccountToken
    },
    {
        DomainAccountInterfaceCode::DOMAIN_GET_ACCESS_TOKEN,
        &DomainAccountStub::ProcGetDomainAccessToken
    },
    {
        DomainAccountInterfaceCode::DOMAIN_GET_ACCOUNT_INFO,
        &DomainAccountStub::ProcGetDomainAccountInfo
    },
};

DomainAccountStub::DomainAccountStub()
{
    stubFuncMap_ = stubFuncMap;
}

DomainAccountStub::~DomainAccountStub()
{}

int32_t DomainAccountStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    MemoryGuard cacheGuard;
    int32_t uid = IPCSkeleton::GetCallingUid();
    ACCOUNT_LOGD("Received stub message: %{public}d, callingUid: %{public}d", code, uid);
    ErrCode errCode = CheckPermission(static_cast<DomainAccountInterfaceCode>(code), uid);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("check permission failed");
        return errCode;
    }
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ACCOUNT_LOGE("check descriptor failed! code %{public}u.", code);
        return ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR;
    }
    const auto &itFunc = stubFuncMap_.find(static_cast<DomainAccountInterfaceCode>(code));
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
    auto callback = iface_cast<IDomainAccountCallback>(data.ReadRemoteObject());
    ErrCode result = ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
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
    std::shared_ptr<DomainAccountInfo> info(data.ReadParcelable<DomainAccountInfo>());
    if (info == nullptr) {
        ACCOUNT_LOGE("failed to read domain account info");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    DomainAccountStatus status;
    ErrCode result = GetAccountStatus(*info, status);
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

ErrCode DomainAccountStub::ProcGetDomainAccountInfo(MessageParcel &data, MessageParcel &reply)
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
    ErrCode result = GetDomainAccountInfo(*info, callback);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode DomainAccountStub::ProcRegisterAccountStatusListener(MessageParcel &data, MessageParcel &reply)
{
    auto callback = iface_cast<IDomainAccountCallback>(data.ReadRemoteObject());
    if (callback == nullptr) {
        ACCOUNT_LOGE("failed to read domain callback");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    ErrCode result = RegisterAccountStatusListener(callback);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    return ERR_OK;
}

ErrCode DomainAccountStub::ProcUnregisterAccountStatusListener(MessageParcel &data, MessageParcel &reply)
{
    auto callback = iface_cast<IDomainAccountCallback>(data.ReadRemoteObject());
    if (callback == nullptr) {
        ACCOUNT_LOGE("failed to read domain callback");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    ErrCode result = UnregisterAccountStatusListener(callback);
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
    auto callback = iface_cast<IDomainAccountCallback>(data.ReadRemoteObject());
    ErrCode result = ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
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
    auto callback = iface_cast<IDomainAccountCallback>(data.ReadRemoteObject());
    ErrCode result = ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
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

ErrCode DomainAccountStub::CheckPermission(DomainAccountInterfaceCode code, int32_t uid)
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
        case DomainAccountInterfaceCode::REGISTER_PLUGIN:
        case DomainAccountInterfaceCode::UNREGISTER_PLUGIN:
        case DomainAccountInterfaceCode::DOMAIN_HAS_DOMAIN_ACCOUNT:
        case DomainAccountInterfaceCode::DOMAIN_UPDATE_ACCOUNT_TOKEN:
            permissionName = MANAGE_LOCAL_ACCOUNTS;
            break;
        case DomainAccountInterfaceCode::DOMAIN_ACCOUNT_STATUS_ENQUIRY:
        case DomainAccountInterfaceCode::DOMAIN_ACCOUNT_STATUS_LISTENER_REGISTER:
        case DomainAccountInterfaceCode::DOMAIN_ACCOUNT_STATUS_LISTENER_UNREGISTER:
            permissionName = GET_LOCAL_ACCOUNTS;
            break;
        case DomainAccountInterfaceCode::DOMAIN_AUTH:
        case DomainAccountInterfaceCode::DOMAIN_AUTH_USER:
        case DomainAccountInterfaceCode::DOMAIN_AUTH_WITH_POPUP:
            permissionName = ACCESS_USER_AUTH_INTERNAL;
            break;
        case DomainAccountInterfaceCode::DOMAIN_GET_ACCOUNT_INFO:
            permissionName = GET_DOMAIN_ACCOUNTS;
            break;
        default:
            break;
    }
    if (code == DomainAccountInterfaceCode::DOMAIN_GET_ACCESS_TOKEN) {
        errCode = AccountPermissionManager::VerifyPermission(MANAGE_LOCAL_ACCOUNTS);
        if (errCode != ERR_OK) {
            return AccountPermissionManager::VerifyPermission(GET_LOCAL_ACCOUNTS);
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
