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

#include "app_account_authenticator_stub.h"

#include "account_error_no.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {

AppAccountAuthenticatorStub::AppAccountAuthenticatorStub()
{}

AppAccountAuthenticatorStub::~AppAccountAuthenticatorStub()
{}

int AppAccountAuthenticatorStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ACCOUNT_LOGE("failed to check descriptor! code %{public}u.", code);
        return ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR;
    }

    switch (code) {
        case static_cast<uint32_t>(AppAccountAuthenticatorInterfaceCode::ADD_ACCOUNT_IMPLICITLY):
            return ProcAddAccountImplicitly(data, reply);
        case static_cast<uint32_t>(AppAccountAuthenticatorInterfaceCode::AUTHENTICATE):
            return ProcAuthenticate(data, reply);
        case static_cast<uint32_t>(AppAccountAuthenticatorInterfaceCode::VERIFY_CREDENTIAL):
            return ProcVerifyCredential(data, reply);
        case static_cast<uint32_t>(AppAccountAuthenticatorInterfaceCode::CHECK_ACCOUNT_LABELS):
            return ProcCheckAccountLabels(data, reply);
        case static_cast<uint32_t>(AppAccountAuthenticatorInterfaceCode::SET_PROPERTIES):
            return ProcSetProperties(data, reply);
        case static_cast<uint32_t>(AppAccountAuthenticatorInterfaceCode::IS_ACCOUNT_REMOVABLE):
            return ProcIsAccountRemovable(data, reply);
        case static_cast<uint32_t>(AppAccountAuthenticatorInterfaceCode::CREATE_ACCOUNT_IMPLICITLY):
            return ProcCreateAccountImplicitly(data, reply);
        case static_cast<uint32_t>(AppAccountAuthenticatorInterfaceCode::AUTH):
            return ProcAuth(data, reply);
        default:
            break;
    }

    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

ErrCode AppAccountAuthenticatorStub::ProcAddAccountImplicitly(MessageParcel &data, MessageParcel &reply)
{
    std::string authType = data.ReadString();
    std::string callerBundleName = data.ReadString();
    std::shared_ptr<AAFwk::WantParams> options(data.ReadParcelable<AAFwk::WantParams>());
    sptr<IRemoteObject> callback = data.ReadRemoteObject();
    ErrCode result = ERR_OK;
    if ((options == nullptr) || (callback == nullptr)) {
        ACCOUNT_LOGE("invalid request parameters");
        result = ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    } else {
        result = AddAccountImplicitly(authType, callerBundleName, *options, callback);
    }
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountAuthenticatorStub::ProcAuthenticate(MessageParcel &data, MessageParcel &reply)
{
    std::string name = data.ReadString();
    std::string authType = data.ReadString();
    std::string callerBundleName = data.ReadString();
    std::shared_ptr<AAFwk::WantParams> options(data.ReadParcelable<AAFwk::WantParams>());
    sptr<IRemoteObject> callback = data.ReadRemoteObject();
    ErrCode result = ERR_OK;
    if ((options == nullptr) || (callback == nullptr)) {
        ACCOUNT_LOGE("invalid request parameters");
        result = ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    } else {
        result = Authenticate(name, authType, callerBundleName, *options, callback);
    }
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountAuthenticatorStub::ProcCreateAccountImplicitly(MessageParcel &data, MessageParcel &reply)
{
    sptr<CreateAccountImplicitlyOptions> options = data.ReadParcelable<CreateAccountImplicitlyOptions>();
    sptr<IRemoteObject> callback = data.ReadRemoteObject();
    ErrCode result = ERR_OK;
    if ((options == nullptr) || (callback == nullptr)) {
        ACCOUNT_LOGE("invalid request parameters");
        result = ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    } else {
        result = CreateAccountImplicitly(*options, callback);
    }
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountAuthenticatorStub::ProcAuth(MessageParcel &data, MessageParcel &reply)
{
    std::string name = data.ReadString();
    std::string authType = data.ReadString();
    std::shared_ptr<AAFwk::WantParams> options(data.ReadParcelable<AAFwk::WantParams>());
    sptr<IRemoteObject> callback = data.ReadRemoteObject();
    ErrCode result = ERR_OK;
    if ((options == nullptr) || (callback == nullptr)) {
        ACCOUNT_LOGE("invalid request parameters");
        result = ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    } else {
        result = Auth(name, authType, *options, callback);
    }
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountAuthenticatorStub::ProcVerifyCredential(MessageParcel &data, MessageParcel &reply)
{
    std::string name = data.ReadString();
    sptr<VerifyCredentialOptions> options = data.ReadParcelable<VerifyCredentialOptions>();
    sptr<IRemoteObject> callback = data.ReadRemoteObject();
    ErrCode result = ERR_OK;
    if ((options == nullptr) || (callback == nullptr)) {
        ACCOUNT_LOGE("invalid request parameters");
        result = ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    } else {
        result = VerifyCredential(name, *options, callback);
    }
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountAuthenticatorStub::ProcCheckAccountLabels(MessageParcel &data, MessageParcel &reply)
{
    std::string name = data.ReadString();
    std::vector<std::string> labels;
    data.ReadStringVector(&labels);
    sptr<IRemoteObject> callback = data.ReadRemoteObject();
    ErrCode result = ERR_OK;
    if (callback == nullptr) {
        ACCOUNT_LOGE("invalid request parameters");
        result = ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    } else {
        result = CheckAccountLabels(name, labels, callback);
    }
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountAuthenticatorStub::ProcSetProperties(MessageParcel &data, MessageParcel &reply)
{
    sptr<SetPropertiesOptions> options = data.ReadParcelable<SetPropertiesOptions>();
    sptr<IRemoteObject> callback = data.ReadRemoteObject();
    ErrCode result = ERR_OK;
    if ((options == nullptr) || (callback == nullptr)) {
        ACCOUNT_LOGE("invalid request parameters");
        result = ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    } else {
        result = SetProperties(*options, callback);
    }
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountAuthenticatorStub::ProcIsAccountRemovable(MessageParcel &data, MessageParcel &reply)
{
    std::string name = data.ReadString();
    sptr<IRemoteObject> callback = data.ReadRemoteObject();
    ErrCode result = ERR_OK;
    if (callback == nullptr) {
        ACCOUNT_LOGE("invalid request parameters");
        result = ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    } else {
        result = IsAccountRemovable(name, callback);
    }
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}
}  // namespace AccountSA
}  // namespace OHOS
