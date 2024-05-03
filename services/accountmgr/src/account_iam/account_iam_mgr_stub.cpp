/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "account_iam_mgr_stub.h"

#include "access_token.h"
#include "account_log_wrapper.h"
#include "account_permission_manager.h"
#include "iaccount_iam_callback.h"
#include "ipc_skeleton.h"
#include "memory_guard.h"
#include "token_setproc.h"

namespace OHOS {
namespace AccountSA {
namespace {
const std::string ACCESS_USER_AUTH_INTERNAL = "ohos.permission.ACCESS_USER_AUTH_INTERNAL";
const std::string MANAGE_USER_IDM = "ohos.permission.MANAGE_USER_IDM";
const std::string USE_USER_IDM = "ohos.permission.USE_USER_IDM";
}

const std::map<uint32_t, AccountIAMMgrStub::AccountIAMMessageProc> messageProcMap = {
    {
        static_cast<uint32_t>(AccountIAMInterfaceCode::OPEN_SESSION),
        {
            .messageProcFunction = &AccountIAMMgrStub::ProcOpenSession,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(AccountIAMInterfaceCode::CLOSE_SESSION),
        {
            .messageProcFunction = &AccountIAMMgrStub::ProcCloseSession,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(AccountIAMInterfaceCode::ADD_CREDENTIAL),
        {
            .messageProcFunction = &AccountIAMMgrStub::ProcAddCredential,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(AccountIAMInterfaceCode::UPDATE_CREDENTIAL),
        {
            .messageProcFunction = &AccountIAMMgrStub::ProcUpdateCredential,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(AccountIAMInterfaceCode::DEL_CRED),
        {
            .messageProcFunction = &AccountIAMMgrStub::ProcDelCred,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(AccountIAMInterfaceCode::DEL_USER),
        {
            .messageProcFunction = &AccountIAMMgrStub::ProcDelUser,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(AccountIAMInterfaceCode::CANCEL),
        {
            .messageProcFunction = &AccountIAMMgrStub::ProcCancel,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(AccountIAMInterfaceCode::GET_CREDENTIAL_INFO),
        {
            .messageProcFunction = &AccountIAMMgrStub::ProcGetCredentialInfo,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(AccountIAMInterfaceCode::PREPARE_REMOTE_AUTH),
        {
            .messageProcFunction = &AccountIAMMgrStub::ProcPrepareRemoteAuth,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(AccountIAMInterfaceCode::AUTH_USER),
        {
            .messageProcFunction = &AccountIAMMgrStub::ProcAuthUser,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(AccountIAMInterfaceCode::CANCEL_AUTH),
        {
            .messageProcFunction = &AccountIAMMgrStub::ProcCancelAuth,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(AccountIAMInterfaceCode::GET_AVAILABLE_STATUS),
        {
            .messageProcFunction = &AccountIAMMgrStub::ProcGetAvailableStatus,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(AccountIAMInterfaceCode::GET_PROPERTY),
        {
            .messageProcFunction = &AccountIAMMgrStub::ProcGetProperty,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(AccountIAMInterfaceCode::SET_PROPERTY),
        {
            .messageProcFunction = &AccountIAMMgrStub::ProcSetProperty,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(AccountIAMInterfaceCode::GET_ENROLLED_ID),
        {
            .messageProcFunction = &AccountIAMMgrStub::ProcGetEnrolledId,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(AccountIAMInterfaceCode::GET_ACCOUNT_STATE),
        {
            .messageProcFunction = &AccountIAMMgrStub::ProcGetAccountState,
        }
    }
};

AccountIAMMgrStub::AccountIAMMgrStub()
{
    messageProcMap_ = messageProcMap;
}

AccountIAMMgrStub::~AccountIAMMgrStub()
{}

std::int32_t AccountIAMMgrStub::OnRemoteRequest(
    std::uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    ACCOUNT_LOGI("Received stub message: %{public}d, callingPid: %{public}d", code, IPCSkeleton::GetCallingPid());
    MemoryGuard cacheGuard;
    Security::AccessToken::AccessTokenID tokenCaller = IPCSkeleton::GetCallingTokenID();
    int result = SetFirstCallerTokenID(tokenCaller);
    ACCOUNT_LOGD("SetFirstCallerTokenID result: %{public}d", result);
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ACCOUNT_LOGE("check descriptor failed! code %{public}u.", code);
        return ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR;
    }
    const auto &itFunc = messageProcMap_.find(code);
    if (itFunc != messageProcMap_.end()) {
        if (itFunc->second.isSyetemApi) {
            result = AccountPermissionManager::CheckSystemApp();
            if (result != ERR_OK) {
                ACCOUNT_LOGE("is not system application, result = %{public}u.", result);
                return result;
            }
        }
        return (this->*(itFunc->second.messageProcFunction))(data, reply);
    }
    ACCOUNT_LOGW("remote request unhandled: %{public}d", code);
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

ErrCode AccountIAMMgrStub::ProcOpenSession(MessageParcel &data, MessageParcel &reply)
{
    if (!CheckPermission(MANAGE_USER_IDM)) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    int32_t userId;
    if (!data.ReadInt32(userId)) {
        ACCOUNT_LOGE("failed to read userId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::vector<uint8_t> challenge;
    int32_t result = OpenSession(userId, challenge);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write result");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (result == ERR_OK) {
        if (!reply.WriteUInt8Vector(challenge)) {
            ACCOUNT_LOGE("failed to write challenge");
            return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
        }
    }
    return ERR_NONE;
}

ErrCode AccountIAMMgrStub::ProcCloseSession(MessageParcel &data, MessageParcel &reply)
{
    if (!CheckPermission(MANAGE_USER_IDM)) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    int32_t userId;
    if (!data.ReadInt32(userId)) {
        ACCOUNT_LOGE("failed to read userId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    int32_t result = CloseSession(userId);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write result");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return ERR_NONE;
}

ErrCode AccountIAMMgrStub::ReadUserIdAndAuthType(MessageParcel &data, int32_t &userId, int32_t &authType)
{
    if (!data.ReadInt32(userId)) {
        ACCOUNT_LOGE("failed to read userId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    if (!data.ReadInt32(authType)) {
        ACCOUNT_LOGE("failed to read authType");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode AccountIAMMgrStub::AddOrUpdateCredential(MessageParcel &data, MessageParcel &reply, bool isAdd)
{
    if (!CheckPermission(MANAGE_USER_IDM)) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    int32_t userId;
    int32_t authType;
    ErrCode ret = ReadUserIdAndAuthType(data, userId, authType);
    if (ret != ERR_OK) {
        return ret;
    }
    int32_t authSubType;
    if (!data.ReadInt32(authSubType)) {
        ACCOUNT_LOGE("failed to read authSubType");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    CredentialParameters credParams;
    if (!data.ReadUInt8Vector(&credParams.token)) {
        ACCOUNT_LOGE("failed to read token");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    sptr<IIDMCallback> callback = iface_cast<IIDMCallback>(data.ReadRemoteObject());
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    credParams.authType = static_cast<AuthType>(authType);
    credParams.pinType = static_cast<PinSubType>(authSubType);
    if (isAdd) {
        AddCredential(userId, credParams, callback);
    } else {
        UpdateCredential(userId, credParams, callback);
    }
    return ERR_NONE;
}

ErrCode AccountIAMMgrStub::ProcAddCredential(MessageParcel &data, MessageParcel &reply)
{
    return AddOrUpdateCredential(data, reply);
}

ErrCode AccountIAMMgrStub::ProcUpdateCredential(MessageParcel &data, MessageParcel &reply)
{
    return AddOrUpdateCredential(data, reply, false);
}

ErrCode AccountIAMMgrStub::ProcDelCred(MessageParcel &data, MessageParcel &reply)
{
    if (!CheckPermission(MANAGE_USER_IDM)) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    int32_t userId;
    if (!data.ReadInt32(userId)) {
        ACCOUNT_LOGE("failed to read userId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    uint64_t credentialId;
    if (!data.ReadUint64(credentialId)) {
        ACCOUNT_LOGE("failed to read credentialId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::vector<uint8_t> authToken;
    if (!data.ReadUInt8Vector(&authToken)) {
        ACCOUNT_LOGE("failed to read authToken for delCred");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    sptr<IIDMCallback> callback = iface_cast<IIDMCallback>(data.ReadRemoteObject());
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    DelCred(userId, credentialId, authToken, callback);
    return ERR_NONE;
}

ErrCode AccountIAMMgrStub::ProcDelUser(MessageParcel &data, MessageParcel &reply)
{
    if (!CheckPermission(MANAGE_USER_IDM)) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    int32_t userId;
    if (!data.ReadInt32(userId)) {
        ACCOUNT_LOGE("failed to read userId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::vector<uint8_t> authToken;
    if (!data.ReadUInt8Vector(&authToken)) {
        ACCOUNT_LOGE("failed to read authToken for delUser");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    sptr<IIDMCallback> callback = iface_cast<IIDMCallback>(data.ReadRemoteObject());
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    DelUser(userId, authToken, callback);
    return ERR_NONE;
}

ErrCode AccountIAMMgrStub::ProcCancel(MessageParcel &data, MessageParcel &reply)
{
    if (!CheckPermission(MANAGE_USER_IDM)) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    int32_t userId;
    if (!data.ReadInt32(userId)) {
        ACCOUNT_LOGE("failed to read userId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    int32_t result = Cancel(userId);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write result");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return ERR_NONE;
}

ErrCode AccountIAMMgrStub::ProcGetCredentialInfo(MessageParcel &data, MessageParcel &reply)
{
    if (!CheckPermission(USE_USER_IDM)) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    int32_t userId;
    int32_t authType;
    ErrCode ret = ReadUserIdAndAuthType(data, userId, authType);
    if (ret != ERR_OK) {
        return ret;
    }
    sptr<IGetCredInfoCallback> callback = iface_cast<IGetCredInfoCallback>(data.ReadRemoteObject());
    if (callback == nullptr) {
        ACCOUNT_LOGE("callback is nullptr");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    int result = GetCredentialInfo(userId, static_cast<AuthType>(authType), callback);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write result");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return ERR_NONE;
}

ErrCode AccountIAMMgrStub::ProcPrepareRemoteAuth(MessageParcel &data, MessageParcel &reply)
{
    if (!CheckPermission(ACCESS_USER_AUTH_INTERNAL)) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    std::string remoteNetworkId;
    if (!data.ReadString(remoteNetworkId)) {
        ACCOUNT_LOGE("Read remoteNetworkId failed.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }

    sptr<IPreRemoteAuthCallback> callback = iface_cast<IPreRemoteAuthCallback>(data.ReadRemoteObject());
    if (callback == nullptr) {
        ACCOUNT_LOGE("PreRemoteAuthCallback is nullptr.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    int result = PrepareRemoteAuth(remoteNetworkId, callback);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Write result failed.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    return ERR_NONE;
}

ErrCode AccountIAMMgrStub::ReadAuthParam(MessageParcel &data, AuthParam &authParam)
{
    if (!data.ReadInt32(authParam.userId)) {
        ACCOUNT_LOGE("failed to read userId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    if (!data.ReadUInt8Vector(&authParam.challenge)) {
        ACCOUNT_LOGE("failed to read challenge");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    int32_t authType;
    if (!data.ReadInt32(authType)) {
        ACCOUNT_LOGE("failed to read authType for AuthUser");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    authParam.authType = static_cast<AuthType>(authType);
    uint32_t authTrustLevel;
    if (!data.ReadUint32(authTrustLevel)) {
        ACCOUNT_LOGE("failed to read authTrustLevel for AuthUser");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    authParam.authTrustLevel = static_cast<AuthTrustLevel>(authTrustLevel);
    int32_t authIntent = 0;
    if (!data.ReadInt32(authIntent)) {
        ACCOUNT_LOGE("failed to read authIntent for AuthUser");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    authParam.authIntent = static_cast<AuthIntent>(authIntent);
    return ERR_OK;
}

ErrCode AccountIAMMgrStub::ReadRemoteAuthParam(MessageParcel &data,
    std::optional<RemoteAuthParam> &remoteAuthParam)
{
    bool res = false;
    if (!data.ReadBool(res)) {
        ACCOUNT_LOGE("Read RemoteAuthParam exist failed.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    if (!res) {
        return ERR_OK;
    }
    remoteAuthParam = RemoteAuthParam();
    if (!data.ReadBool(res)) {
        ACCOUNT_LOGE("Read verifierNetworkId exist failed.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    if (res) {
        std::string networkId;
        if (!data.ReadString(networkId)) {
            ACCOUNT_LOGE("Read verifierNetworkId failed.");
            return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
        }
        remoteAuthParam.value().verifierNetworkId = networkId;
    }
    if (!data.ReadBool(res)) {
        ACCOUNT_LOGE("Read collectorNetworkId exist failed.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    if (res) {
        std::string networkId;
        if (!data.ReadString(networkId)) {
            ACCOUNT_LOGE("Read collectorNetworkId failed.");
            return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
        }
        remoteAuthParam.value().collectorNetworkId = networkId;
    }
    if (!data.ReadBool(res)) {
        ACCOUNT_LOGE("Read collectorTokenId exist failed.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    if (res) {
        uint32_t tokenId;
        if (!data.ReadUint32(tokenId)) {
            ACCOUNT_LOGE("Read collectorTokenId failed.");
            return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
        }
        remoteAuthParam.value().collectorTokenId = tokenId;
    }
    return ERR_OK;
}

ErrCode AccountIAMMgrStub::ProcAuthUser(MessageParcel &data, MessageParcel &reply)
{
    if (!CheckPermission(ACCESS_USER_AUTH_INTERNAL)) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    AuthParam authParam;
    if (ReadAuthParam(data, authParam) != ERR_OK) {
        ACCOUNT_LOGE("failed to read authParam");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    sptr<IIDMCallback> callback = iface_cast<IIDMCallback>(data.ReadRemoteObject());
    if (callback == nullptr) {
        ACCOUNT_LOGE("UserAuthCallbackInterface is nullptr");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    if (ReadRemoteAuthParam(data, authParam.remoteAuthParam) != ERR_OK) {
        ACCOUNT_LOGE("failed to read RemoteAuthParam");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    uint64_t contextId = 0;
    ErrCode result = AuthUser(authParam, callback, contextId);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write result");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!reply.WriteUint64(contextId)) {
        ACCOUNT_LOGE("failed to write contextId");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return ERR_NONE;
}

ErrCode AccountIAMMgrStub::ProcCancelAuth(MessageParcel &data, MessageParcel &reply)
{
    if (!CheckPermission(ACCESS_USER_AUTH_INTERNAL)) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    uint64_t contextId;
    if (!data.ReadUint64(contextId)) {
        ACCOUNT_LOGE("failed to read contextId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    int32_t result = CancelAuth(contextId);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write result");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return ERR_NONE;
}

ErrCode AccountIAMMgrStub::ProcGetAvailableStatus(MessageParcel &data, MessageParcel &reply)
{
    if (!CheckPermission(ACCESS_USER_AUTH_INTERNAL)) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    int32_t authType;
    if (!data.ReadInt32(authType)) {
        ACCOUNT_LOGE("failed to read authType for GetAvailableStatus");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    uint32_t authTrustLevel;
    if (!data.ReadUint32(authTrustLevel)) {
        ACCOUNT_LOGE("failed to read authTrustLevel for GetAvailableStatus");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    int32_t status;
    int32_t result =
        GetAvailableStatus(static_cast<AuthType>(authType), static_cast<AuthTrustLevel>(authTrustLevel), status);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write result");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (result == ERR_OK) {
        if (!reply.WriteInt32(status)) {
            ACCOUNT_LOGE("failed to write status");
            return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
        }
    }
    return ERR_NONE;
}

ErrCode AccountIAMMgrStub::ProcGetProperty(MessageParcel &data, MessageParcel &reply)
{
    if (!CheckPermission(ACCESS_USER_AUTH_INTERNAL)) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    int32_t userId;
    int32_t authType;
    if (ReadUserIdAndAuthType(data, userId, authType) != ERR_OK) {
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::vector<uint32_t> keys;
    if (!data.ReadUInt32Vector(&keys)) {
        ACCOUNT_LOGE("failed to read attribute keys");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    sptr<IGetSetPropCallback> callback = iface_cast<IGetSetPropCallback>(data.ReadRemoteObject());
    if (callback == nullptr) {
        ACCOUNT_LOGE("IGetSetPropCallback is nullptr");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    GetPropertyRequest request;
    request.authType = static_cast<AuthType>(authType);
    for (auto &key : keys) {
        request.keys.push_back(static_cast<Attributes::AttributeKey>(key));
    }
    GetProperty(userId, request, callback);
    return ERR_NONE;
}

ErrCode AccountIAMMgrStub::ProcSetProperty(MessageParcel &data, MessageParcel &reply)
{
    if (!CheckPermission(ACCESS_USER_AUTH_INTERNAL)) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    int32_t userId;
    int32_t authType;
    if (ReadUserIdAndAuthType(data, userId, authType) != ERR_OK) {
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::vector<uint8_t> attr;
    if (!data.ReadUInt8Vector(&attr)) {
        ACCOUNT_LOGE("failed to read attributes");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    sptr<IGetSetPropCallback> callback = iface_cast<IGetSetPropCallback>(data.ReadRemoteObject());
    if (callback == nullptr) {
        ACCOUNT_LOGE("SetExecutorPropertyCallbackInterface is nullptr");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    SetPropertyRequest request = {
        .authType = static_cast<AuthType>(authType),
        .attrs = Attributes(attr)
    };
    SetProperty(userId, request, callback);
    return ERR_NONE;
}

ErrCode AccountIAMMgrStub::ProcGetAccountState(MessageParcel &data, MessageParcel &reply)
{
    int32_t userId;
    if (!data.ReadInt32(userId)) {
        ACCOUNT_LOGE("failed to read userId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    IAMState state = GetAccountState(userId);
    if (!reply.WriteInt32(state)) {
        ACCOUNT_LOGE("failed to write state");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return ERR_NONE;
}

ErrCode AccountIAMMgrStub::ProcGetEnrolledId(MessageParcel &data, MessageParcel &reply)
{
    if (!CheckPermission(USE_USER_IDM)) {
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    int32_t accountId;
    int32_t authType;
    ErrCode ret = ReadUserIdAndAuthType(data, accountId, authType);
    if (ret != ERR_OK) {
        return ret;
    }
    sptr<IGetEnrolledIdCallback> callback = iface_cast<IGetEnrolledIdCallback>(data.ReadRemoteObject());
    if (callback == nullptr) {
        ACCOUNT_LOGE("Callback is nullptr");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    GetEnrolledId(accountId, static_cast<AuthType>(authType), callback);
    return ERR_NONE;
}

bool AccountIAMMgrStub::CheckPermission(const std::string &permission)
{
    if (AccountPermissionManager::VerifyPermission(permission) != ERR_OK) {
        ACCOUNT_LOGE("check permission failed, permission name: %{public}s", permission.c_str());
        return false;
    }
    return true;
}
}  // AccountSA
}  // OHOS
