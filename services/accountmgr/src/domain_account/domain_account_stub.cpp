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
#include <set>
#include "account_log_wrapper.h"
#include "account_permission_manager.h"
#include "domain_account_callback_proxy.h"
#include "ipc_skeleton.h"
#include "memory_guard.h"

namespace OHOS {
namespace AccountSA {
namespace {
const char MANAGE_LOCAL_ACCOUNTS[] = "ohos.permission.MANAGE_LOCAL_ACCOUNTS";
const char MANAGE_DOMAIN_ACCOUNTS[] = "ohos.permission.MANAGE_DOMAIN_ACCOUNTS";
const char GET_LOCAL_ACCOUNTS[] = "ohos.permission.GET_LOCAL_ACCOUNTS";
const char ACCESS_USER_AUTH_INTERNAL[] = "ohos.permission.ACCESS_USER_AUTH_INTERNAL";
const char GET_DOMAIN_ACCOUNTS[] = "ohos.permission.GET_DOMAIN_ACCOUNTS";
const char INTERACT_ACROSS_LOCAL_ACCOUNTS[] = "ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS";
const char MANAGE_DOMAIN_ACCOUNT_SERVER_CONFIGS[] = "ohos.permission.MANAGE_DOMAIN_ACCOUNT_SERVER_CONFIGS";
}

static const std::set<DomainAccountInterfaceCode> NON_SYSTEM_API_SET = {
    DomainAccountInterfaceCode::DOMAIN_UPDATE_ACCOUNT_INFO,
    DomainAccountInterfaceCode::UPDATE_SERVER_CONFIG,
    DomainAccountInterfaceCode::GET_SERVER_CONFIG,
    DomainAccountInterfaceCode::GET_ALL_SERVER_CONFIGS,
    DomainAccountInterfaceCode::ADD_SERVER_CONFIG,
    DomainAccountInterfaceCode::REMOVE_SERVER_CONFIG,
    DomainAccountInterfaceCode::GET_ACCOUNT_SERVER_CONFIG,
};

static const std::map<DomainAccountInterfaceCode, DomainAccountStub::DomainAccountStubFunc> stubFuncMap = {
    {
        DomainAccountInterfaceCode::REGISTER_PLUGIN,
        [] (DomainAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
            return ptr->ProcRegisterPlugin(data, reply); }
    },
    {
        DomainAccountInterfaceCode::UNREGISTER_PLUGIN,
        [] (DomainAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
            return ptr->ProcUnregisterPlugin(data, reply); }
    },
    {
        DomainAccountInterfaceCode::DOMAIN_AUTH,
        [] (DomainAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
            return ptr->ProcAuth(data, reply); }
    },
    {
        DomainAccountInterfaceCode::DOMAIN_AUTH_USER,
        [] (DomainAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
            return ptr->ProcAuthUser(data, reply); }
    },
    {
        DomainAccountInterfaceCode::DOMAIN_ACCOUNT_STATUS_ENQUIRY,
        [] (DomainAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
            return ptr->ProcGetAccountStatus(data, reply); }
    },
    {
        DomainAccountInterfaceCode::DOMAIN_ACCOUNT_STATUS_LISTENER_REGISTER,
        [] (DomainAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
            return ptr->ProcRegisterAccountStatusListener(data, reply); }
    },
    {
        DomainAccountInterfaceCode::DOMAIN_ACCOUNT_STATUS_LISTENER_UNREGISTER,
        [] (DomainAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
            return ptr->ProcUnregisterAccountStatusListener(data, reply); }
    },
    {
        DomainAccountInterfaceCode::DOMAIN_AUTH_WITH_POPUP,
        [] (DomainAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
            return ptr->ProcAuthWithPopup(data, reply); }
    },
    {
        DomainAccountInterfaceCode::DOMAIN_HAS_DOMAIN_ACCOUNT,
        [] (DomainAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
            return ptr->ProcHasDomainAccount(data, reply); }
    },
    {
        DomainAccountInterfaceCode::DOMAIN_UPDATE_ACCOUNT_TOKEN,
        [] (DomainAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
            return ptr->ProcUpdateAccountToken(data, reply); }
    },
    {
        DomainAccountInterfaceCode::DOMAIN_IS_AUTHENTICATION_EXPIRED,
        [] (DomainAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
            return ptr->ProcIsAuthenticationExpired(data, reply); }
    },
    {
        DomainAccountInterfaceCode::DOMAIN_SET_ACCOUNT_POLICY,
        [] (DomainAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
            return ptr->ProcSetAccountPolicy(data, reply); }
    },
    {
        DomainAccountInterfaceCode::DOMAIN_GET_ACCESS_TOKEN,
        [] (DomainAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
            return ptr->ProcGetDomainAccessToken(data, reply); }
    },
    {
        DomainAccountInterfaceCode::DOMAIN_GET_ACCOUNT_INFO,
        [] (DomainAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
            return ptr->ProcGetDomainAccountInfo(data, reply); }
    },
    {
        DomainAccountInterfaceCode::ADD_SERVER_CONFIG,
        [] (DomainAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
            return ptr->ProcAddServerConfig(data, reply); }
    },
    {
        DomainAccountInterfaceCode::REMOVE_SERVER_CONFIG,
        [] (DomainAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
            return ptr->ProcRemoveServerConfig(data, reply); }
    },
    {
        DomainAccountInterfaceCode::UPDATE_SERVER_CONFIG,
        [] (DomainAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
            return ptr->ProcUpdateServerConfig(data, reply); }
    },
    {
        DomainAccountInterfaceCode::GET_SERVER_CONFIG,
        [] (DomainAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
            return ptr->ProcGetServerConfig(data, reply); }
    },
    {
        DomainAccountInterfaceCode::GET_ALL_SERVER_CONFIGS,
        [] (DomainAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
            return ptr->ProcGetAllServerConfigs(data, reply); }
    },
    {
        DomainAccountInterfaceCode::GET_ACCOUNT_SERVER_CONFIG,
        [] (DomainAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
            return ptr->ProcGetAccountServerConfig(data, reply); }
    },
    {
        DomainAccountInterfaceCode::DOMAIN_UPDATE_ACCOUNT_INFO,
        [] (DomainAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
            return ptr->ProcUpdateAccountInfo(data, reply); }
    },
    {
        DomainAccountInterfaceCode::DOMAIN_GET_ACCOUNT_POLICY,
        [] (DomainAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
            return ptr->ProcGetAccountPolicy(data, reply); }
    },
};

DomainAccountStub::DomainAccountStub()
{}

DomainAccountStub::~DomainAccountStub()
{}

int32_t DomainAccountStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    MemoryGuard cacheGuard;
    int32_t uid = IPCSkeleton::GetCallingUid();
    ACCOUNT_LOGI("Received stub message: %{public}d, callingUid: %{public}d, callingPid: %{public}d", code, uid,
                 IPCSkeleton::GetCallingRealPid());
    ErrCode errCode = CheckPermission(static_cast<DomainAccountInterfaceCode>(code), uid);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("check permission failed");
        return errCode;
    }
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ACCOUNT_LOGE("check descriptor failed! code %{public}u.", code);
        return ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR;
    }
    const auto &itFunc = stubFuncMap.find(static_cast<DomainAccountInterfaceCode>(code));
    if (itFunc != stubFuncMap.end()) {
        return (itFunc->second)(this, data, reply);
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

ErrCode DomainAccountStub::ProcIsAuthenticationExpired(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<DomainAccountInfo> info(data.ReadParcelable<DomainAccountInfo>());
    if (info == nullptr) {
        ACCOUNT_LOGE("Read DomainAccountInfo failed.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    bool isExpired = true;
    ErrCode result = IsAuthenticationExpired(*info, isExpired);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Write reply failed.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (result != ERR_OK) {
        ACCOUNT_LOGE("IsAuthenticationExpired failed %{public}d.", result);
        return result;
    }
    if (!reply.WriteBool(isExpired)) {
        ACCOUNT_LOGE("Write isExpired failed.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode DomainAccountStub::ProcSetAccountPolicy(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<DomainAccountInfo> info(data.ReadParcelable<DomainAccountInfo>());
    if (info == nullptr) {
        ACCOUNT_LOGE("failed to read domain account info");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::string policy;
    if (!data.ReadString(policy)) {
        ACCOUNT_LOGE("Read threshold failed.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    ErrCode result = SetAccountPolicy(*info, policy);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Write reply failed.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode DomainAccountStub::ProcGetAccountPolicy(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<DomainAccountInfo> info(data.ReadParcelable<DomainAccountInfo>());
    if (info == nullptr) {
        ACCOUNT_LOGE("failed to read domain account info");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::string policy;
    ErrCode result = GetAccountPolicy(*info, policy);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Write reply failed.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (result != ERR_OK) {
        ACCOUNT_LOGE("GetAccountPolicy failed %{public}d.", result);
        return result;
    }
    if (!reply.WriteString(policy)) {
        ACCOUNT_LOGE("Write reply policy failed.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode DomainAccountStub::ProcRegisterPlugin(MessageParcel &data, MessageParcel &reply)
{
    auto plugin = iface_cast<IDomainAccountPlugin>(data.ReadRemoteObject());
    if (plugin == nullptr) {
        ACCOUNT_LOGE("Failed to read plugin");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
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
    if (!data.ReadString(info.serverConfigId_)) {
        ACCOUNT_LOGE("fail to read serverConfigId");
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

ErrCode DomainAccountStub::ProcUpdateAccountInfo(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<DomainAccountInfo> oldAccountInfo(data.ReadParcelable<DomainAccountInfo>());
    if (oldAccountInfo == nullptr) {
        ACCOUNT_LOGE("Failed to read oldAccountInfo");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::shared_ptr<DomainAccountInfo> newAccountInfo(data.ReadParcelable<DomainAccountInfo>());
    if (newAccountInfo == nullptr) {
        ACCOUNT_LOGE("Failed to read newAccountInfo");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    ErrCode result = UpdateAccountInfo(*oldAccountInfo, *newAccountInfo);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply, result %{public}d.", result);
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

ErrCode DomainAccountStub::ProcAddServerConfig(MessageParcel &data, MessageParcel &reply)
{
    std::string parameters;
    if (!data.ReadString(parameters)) {
        ACCOUNT_LOGE("Failed to read domain server config.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    DomainServerConfig config;
    ErrCode result = AddServerConfig(parameters, config);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply, result=%{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (result != ERR_OK) {
        return result;
    }
    if (!reply.WriteParcelable(&config)) {
        ACCOUNT_LOGE("Failed to write identifier.");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode DomainAccountStub::ProcRemoveServerConfig(MessageParcel &data, MessageParcel &reply)
{
    std::string configId;
    if (!data.ReadString(configId)) {
        ACCOUNT_LOGE("Fail to configId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    ErrCode result = RemoveServerConfig(configId);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply, result=%{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return result;
}

ErrCode DomainAccountStub::ProcUpdateServerConfig(MessageParcel &data, MessageParcel &reply)
{
    std::string configId;
    if (!data.ReadString(configId)) {
        ACCOUNT_LOGE("Fail to configId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::string parameters;
    if (!data.ReadString(parameters)) {
        ACCOUNT_LOGE("Failed to read domain server config.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    DomainServerConfig config;
    ErrCode result = UpdateServerConfig(configId, parameters, config);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply, result=%{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (result != ERR_OK) {
        return result;
    }
    if (!reply.WriteParcelable(&config)) {
        ACCOUNT_LOGE("Failed to write identifier.");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return result;
}

ErrCode DomainAccountStub::ProcGetServerConfig(MessageParcel &data, MessageParcel &reply)
{
    std::string configId;
    if (!data.ReadString(configId)) {
        ACCOUNT_LOGE("Fail to configId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    DomainServerConfig config;
    ErrCode result = GetServerConfig(configId, config);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply, result=%{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (result != ERR_OK) {
        return result;
    }
    if (!reply.WriteParcelable(&config)) {
        ACCOUNT_LOGE("Failed to write identifier.");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return result;
}

ErrCode DomainAccountStub::ProcGetAllServerConfigs(MessageParcel &data, MessageParcel &reply)
{
    std::vector<DomainServerConfig> configs;
    ErrCode result = GetAllServerConfigs(configs);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply, result=%{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (result != ERR_OK) {
        return result;
    }
    if (!reply.WriteInt32(static_cast<uint32_t>(configs.size()))) {
        ACCOUNT_LOGE("Failed to write config count.");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    for (const auto &config : configs) {
        if (!reply.WriteParcelable(&config)) {
            ACCOUNT_LOGE("Failed to write config.");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
    }
    return result;
}

ErrCode DomainAccountStub::ProcGetAccountServerConfig(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<DomainAccountInfo> info(data.ReadParcelable<DomainAccountInfo>());
    if (info == nullptr) {
        ACCOUNT_LOGE("Failed to read domain server config.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    DomainServerConfig config;
    ErrCode result = GetAccountServerConfig(*info, config);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply, result=%{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (result != ERR_OK) {
        return result;
    }
    if (!reply.WriteParcelable(&config)) {
        ACCOUNT_LOGE("Failed to write identifier.");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

static const std::map<DomainAccountInterfaceCode, std::vector<std::string>> permissionMap = {
    {DomainAccountInterfaceCode::REGISTER_PLUGIN, {MANAGE_LOCAL_ACCOUNTS}},
    {DomainAccountInterfaceCode::UNREGISTER_PLUGIN, {MANAGE_LOCAL_ACCOUNTS}},
    {DomainAccountInterfaceCode::DOMAIN_SET_ACCOUNT_POLICY, {MANAGE_LOCAL_ACCOUNTS}},
    {DomainAccountInterfaceCode::DOMAIN_GET_ACCOUNT_POLICY, {MANAGE_LOCAL_ACCOUNTS}},
    {DomainAccountInterfaceCode::DOMAIN_HAS_DOMAIN_ACCOUNT, {MANAGE_LOCAL_ACCOUNTS}},
    {DomainAccountInterfaceCode::DOMAIN_UPDATE_ACCOUNT_TOKEN, {MANAGE_LOCAL_ACCOUNTS}},
    {DomainAccountInterfaceCode::DOMAIN_UPDATE_ACCOUNT_INFO, {MANAGE_LOCAL_ACCOUNTS, MANAGE_DOMAIN_ACCOUNTS}},
    {DomainAccountInterfaceCode::DOMAIN_ACCOUNT_STATUS_ENQUIRY, {GET_LOCAL_ACCOUNTS}},
    {DomainAccountInterfaceCode::DOMAIN_ACCOUNT_STATUS_LISTENER_REGISTER, {GET_LOCAL_ACCOUNTS}},
    {DomainAccountInterfaceCode::DOMAIN_ACCOUNT_STATUS_LISTENER_UNREGISTER, {GET_LOCAL_ACCOUNTS}},
    {DomainAccountInterfaceCode::DOMAIN_AUTH, {ACCESS_USER_AUTH_INTERNAL}},
    {DomainAccountInterfaceCode::DOMAIN_AUTH_USER, {ACCESS_USER_AUTH_INTERNAL}},
    {DomainAccountInterfaceCode::DOMAIN_GET_ACCOUNT_INFO, {GET_DOMAIN_ACCOUNTS}},
    {DomainAccountInterfaceCode::DOMAIN_IS_AUTHENTICATION_EXPIRED,
        {MANAGE_LOCAL_ACCOUNTS, INTERACT_ACROSS_LOCAL_ACCOUNTS}},
    {DomainAccountInterfaceCode::ADD_SERVER_CONFIG,
        {MANAGE_LOCAL_ACCOUNTS, MANAGE_DOMAIN_ACCOUNT_SERVER_CONFIGS}},
    {DomainAccountInterfaceCode::REMOVE_SERVER_CONFIG,
        {MANAGE_LOCAL_ACCOUNTS, MANAGE_DOMAIN_ACCOUNT_SERVER_CONFIGS}},
    {DomainAccountInterfaceCode::GET_ACCOUNT_SERVER_CONFIG,
        {MANAGE_LOCAL_ACCOUNTS, MANAGE_DOMAIN_ACCOUNT_SERVER_CONFIGS}},
    {DomainAccountInterfaceCode::UPDATE_SERVER_CONFIG, {MANAGE_DOMAIN_ACCOUNT_SERVER_CONFIGS}},
    {DomainAccountInterfaceCode::GET_SERVER_CONFIG, {MANAGE_DOMAIN_ACCOUNT_SERVER_CONFIGS}},
    {DomainAccountInterfaceCode::GET_ALL_SERVER_CONFIGS, {MANAGE_DOMAIN_ACCOUNT_SERVER_CONFIGS}}
};

ErrCode DomainAccountStub::CheckPermission(DomainAccountInterfaceCode code, int32_t uid)
{
    if (NON_SYSTEM_API_SET.find(code) == NON_SYSTEM_API_SET.end()) {
        ErrCode errCode = AccountPermissionManager::CheckSystemApp();
        if (errCode != ERR_OK) {
            ACCOUNT_LOGE("the caller is not system application, errCode = %{public}d.", errCode);
            return errCode;
        }
    }
    if (uid == 0) {
        return ERR_OK;
    }
    const auto& it = permissionMap.find(code);
    if (it == permissionMap.end()) {
        ACCOUNT_LOGW("No specific permission defined for code %{public}d, returning OK", static_cast<int>(code));
        return ERR_OK;
    }
    const auto& requiredPermissions = it->second;
    if (requiredPermissions.empty()) {
        return ERR_OK;
    }
    bool hasAnyPermission = std::any_of(requiredPermissions.begin(), requiredPermissions.end(),
        [](const std::string& permission) {
            return AccountPermissionManager::VerifyPermission(permission) == ERR_OK;
        });
    if (!hasAnyPermission) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS
