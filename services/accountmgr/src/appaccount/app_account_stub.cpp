/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "account_error_no.h"
#include "account_log_wrapper.h"

#include "app_account_stub.h"

namespace OHOS {
namespace AccountSA {
const std::map<uint32_t, AppAccountStub::MessageProcFunction> AppAccountStub::messageProcMap_ = {
    {
        static_cast<uint32_t>(IAppAccount::Message::ADD_ACCOUNT),
        &AppAccountStub::ProcAddAccount,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::ADD_ACCOUNT_IMPLICITLY),
        &AppAccountStub::ProcAddAccountImplicitly,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::DELETE_ACCOUNT),
        &AppAccountStub::ProcDeleteAccount,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::GET_ACCOUNT_EXTRA_INFO),
        &AppAccountStub::ProcGetAccountExtraInfo,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::SET_ACCOUNT_EXTRA_INFO),
        &AppAccountStub::ProcSetAccountExtraInfo,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::ENABLE_APP_ACCESS),
        &AppAccountStub::ProcEnableAppAccess,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::DISABLE_APP_ACCESS),
        &AppAccountStub::ProcDisableAppAccess,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::CHECK_APP_ACCOUNT_SYNC_ENABLE),
        &AppAccountStub::ProcCheckAppAccountSyncEnable,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::SET_APP_ACCOUNT_SYNC_ENABLE),
        &AppAccountStub::ProcSetAppAccountSyncEnable,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::GET_ASSOCIATED_DATA),
        &AppAccountStub::ProcGetAssociatedData,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::SET_ASSOCIATED_DATA),
        &AppAccountStub::ProcSetAssociatedData,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::GET_ACCOUNT_CREDENTIAL),
        &AppAccountStub::ProcGetAccountCredential,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::SET_ACCOUNT_CREDENTIAL),
        &AppAccountStub::ProcSetAccountCredential,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::AUTHENTICATE),
        &AppAccountStub::ProcAuthenticate,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::GET_OAUTH_TOKEN),
        &AppAccountStub::ProcGetOAuthToken,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::SET_OAUTH_TOKEN),
        &AppAccountStub::ProcSetOAuthToken,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::DELETE_OAUTH_TOKEN),
        &AppAccountStub::ProcDeleteOAuthToken,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::SET_OAUTH_TOKEN_VISIBILITY),
        &AppAccountStub::ProcSetOAuthTokenVisibility,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::CHECK_OAUTH_TOKEN_VISIBILITY),
        &AppAccountStub::ProcCheckOAuthTokenVisibility,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::GET_AUTHENTICATOR_CALLBACK),
        &AppAccountStub::ProcGetAuthenticatorCallback,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::GET_AUTHENTICATOR_INFO),
        &AppAccountStub::ProcGetAuthenticatorInfo,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::GET_ALL_OAUTH_TOKENS),
        &AppAccountStub::ProcGetAllOAuthTokens,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::GET_OAUTH_LIST),
        &AppAccountStub::ProcGetOAuthList,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::GET_ALL_ACCOUNTS),
        &AppAccountStub::ProcGetAllAccounts,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::GET_ALL_ACCESSIBLE_ACCOUNTS),
        &AppAccountStub::ProcGetAllAccessibleAccounts,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::SUBSCRIBE_ACCOUNT),
        &AppAccountStub::ProcSubscribeAccount,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::UNSUBSCRIBE_ACCOUNT),
        &AppAccountStub::ProcUnsubscribeAccount,
    },
};

AppAccountStub::AppAccountStub()
{
    ACCOUNT_LOGI("enter");
}

AppAccountStub::~AppAccountStub()
{}

int AppAccountStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    ACCOUNT_LOGI("enter");

    auto messageProc = messageProcMap_.find(code);
    if (messageProc != messageProcMap_.end()) {
        auto messageProcFunction = messageProc->second;
        if (messageProcFunction != nullptr) {
            return (this->*messageProcFunction)(data, reply);
        }
    }

    ACCOUNT_LOGI("end, code = %{public}u, flags = %{public}u", code, option.GetFlags());

    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

template<typename T>
bool AppAccountStub::WriteParcelableVector(const std::vector<T> &parcelableVector, MessageParcel &data)
{
    if (!data.WriteUint32(parcelableVector.size())) {
        ACCOUNT_LOGE("failed to WriteInt32 for parcelableVector.size()");
        return false;
    }

    for (const auto &parcelable : parcelableVector) {
        if (!data.WriteParcelable(&parcelable)) {
            ACCOUNT_LOGE("failed to WriteParcelable for parcelable");
            return false;
        }
    }

    return true;
}

template<typename T>
bool AppAccountStub::ReadParcelableVector(std::vector<T> &parcelableVector, MessageParcel &data)
{
    ACCOUNT_LOGI("enter");

    uint32_t size = 0;
    if (!data.ReadUint32(size)) {
        ACCOUNT_LOGI("read Parcelable size failed.");
        return false;
    }

    parcelableVector.clear();
    for (uint32_t index = 0; index < size; index++) {
        T *info = data.ReadParcelable<T>();
        if (info == nullptr) {
            ACCOUNT_LOGI("read Parcelable infos failed.");
            return false;
        }
        parcelableVector.emplace_back(*info);
    }

    return true;
}

ErrCode AppAccountStub::ProcAddAccount(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGI("enter");

    std::string name = data.ReadString();
    if (name.size() == 0) {
        ACCOUNT_LOGE("failed to read string for name");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_STRING_NAME)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
        return ERR_NONE;
    }

    std::string extraInfo = data.ReadString();
    if (extraInfo.size() == 0) {
        ACCOUNT_LOGI("extraInfo.size() = 0");
    }

    ErrCode result = AddAccount(name, extraInfo);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    return ERR_NONE;
}

ErrCode AppAccountStub::ProcAddAccountImplicitly(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGI("enter");

    std::string owner = data.ReadString();
    if (owner.size() == 0) {
        ACCOUNT_LOGE("failed to read string for owner");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_STRING_OWNER)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
        return ERR_NONE;
    }
    std::string authType = data.ReadString();
    AAFwk::WantParams *options = data.ReadParcelable<AAFwk::WantParams>();
    if (options == nullptr) {
        ACCOUNT_LOGE("failed to read string for options");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_PARCELABLE_OPTIONS)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
        return ERR_NONE;
    }
    sptr<IRemoteObject> callback = data.ReadParcelable<IRemoteObject>();
    std::string abilityName = data.ReadString();
    if (abilityName.size() == 0) {
        ACCOUNT_LOGE("failed to read string for abilityName");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_STRING_ABILITY_NAME)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
        return ERR_NONE;
    }
    ErrCode result = AddAccountImplicitly(owner, authType, *options, callback, abilityName);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcDeleteAccount(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGI("enter");

    std::string name = data.ReadString();
    if (name.size() == 0) {
        ACCOUNT_LOGE("failed to read string for name");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_STRING_NAME)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }

        return ERR_NONE;
    }

    ErrCode result = DeleteAccount(name);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    return ERR_NONE;
}

ErrCode AppAccountStub::ProcGetAccountExtraInfo(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGI("enter");

    std::string name = data.ReadString();
    if (name.size() == 0) {
        ACCOUNT_LOGE("failed to read string for name");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_STRING_NAME)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }

        return ERR_NONE;
    }

    std::string extraInfo;
    ErrCode result = GetAccountExtraInfo(name, extraInfo);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    if (!reply.WriteString(extraInfo)) {
        ACCOUNT_LOGE("failed to write string for extra info");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    return ERR_NONE;
}

ErrCode AppAccountStub::ProcSetAccountExtraInfo(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGI("enter");

    std::string name = data.ReadString();
    if (name.size() == 0) {
        ACCOUNT_LOGE("failed to read string for name");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_STRING_NAME)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }

        return ERR_NONE;
    }

    std::string extraInfo = data.ReadString();
    if (extraInfo.size() == 0) {
        ACCOUNT_LOGI("extraInfo.size() = 0");
    }

    ErrCode result = SetAccountExtraInfo(name, extraInfo);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    return ERR_NONE;
}

ErrCode AppAccountStub::ProcEnableAppAccess(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGI("enter");

    std::string name = data.ReadString();
    if (name.size() == 0) {
        ACCOUNT_LOGE("failed to read string for name");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_STRING_NAME)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }

        return ERR_NONE;
    }

    std::string authorizedApp = data.ReadString();
    if (authorizedApp.size() == 0) {
        ACCOUNT_LOGE("failed to read string for authorizedApp");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_STRING_AUTHORIZED_APP)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }

        return ERR_NONE;
    }

    ErrCode result = EnableAppAccess(name, authorizedApp);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    return ERR_NONE;
}

ErrCode AppAccountStub::ProcDisableAppAccess(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGI("enter");

    std::string name = data.ReadString();
    if (name.size() == 0) {
        ACCOUNT_LOGE("failed to read string for name");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_STRING_NAME)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }

        return ERR_NONE;
    }

    std::string authorizedApp = data.ReadString();
    if (authorizedApp.size() == 0) {
        ACCOUNT_LOGE("failed to read string for authorizedApp");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_STRING_AUTHORIZED_APP)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }

        return ERR_NONE;
    }

    ErrCode result = DisableAppAccess(name, authorizedApp);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    return ERR_NONE;
}

ErrCode AppAccountStub::ProcCheckAppAccountSyncEnable(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGI("enter");

    std::string name = data.ReadString();
    if (name.size() == 0) {
        ACCOUNT_LOGE("failed to read string for name");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_STRING_NAME)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }

        return ERR_NONE;
    }

    bool syncEnable = false;
    ErrCode result = CheckAppAccountSyncEnable(name, syncEnable);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    if (!reply.WriteBool(syncEnable)) {
        ACCOUNT_LOGE("failed to write bool for syncEnable");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    return ERR_NONE;
}

ErrCode AppAccountStub::ProcSetAppAccountSyncEnable(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGI("enter");

    std::string name = data.ReadString();
    if (name.size() == 0) {
        ACCOUNT_LOGE("failed to read string for name");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_STRING_NAME)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }

        return ERR_NONE;
    }

    bool syncEnable = data.ReadBool();

    ErrCode result = SetAppAccountSyncEnable(name, syncEnable);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    return ERR_NONE;
}

ErrCode AppAccountStub::ProcGetAssociatedData(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGI("enter");

    std::string name = data.ReadString();
    if (name.size() == 0) {
        ACCOUNT_LOGE("failed to read string for name");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_STRING_NAME)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }

        return ERR_NONE;
    }

    std::string key = data.ReadString();
    if (key.size() == 0) {
        ACCOUNT_LOGE("failed to read string for key");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_STRING_ASSOCIATED_DATA)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }

        return ERR_NONE;
    }

    std::string value;
    ErrCode result = GetAssociatedData(name, key, value);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    if (!reply.WriteString(value)) {
        ACCOUNT_LOGE("failed to write string for value");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    return ERR_NONE;
}

ErrCode AppAccountStub::ProcSetAssociatedData(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGI("enter");

    std::string name = data.ReadString();
    if (name.size() == 0) {
        ACCOUNT_LOGE("failed to read string for name");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_STRING_NAME)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }

        return ERR_NONE;
    }

    std::string key = data.ReadString();
    if (key.size() == 0) {
        ACCOUNT_LOGE("failed to read string for key");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_STRING_ASSOCIATED_DATA)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }

        return ERR_NONE;
    }

    std::string value = data.ReadString();
    if (value.size() == 0) {
        ACCOUNT_LOGI("value.size() = 0");
    }

    ErrCode result = SetAssociatedData(name, key, value);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    return ERR_NONE;
}

ErrCode AppAccountStub::ProcGetAccountCredential(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGI("enter");

    std::string name = data.ReadString();
    if (name.size() == 0) {
        ACCOUNT_LOGE("failed to read string for name");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_STRING_NAME)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }

        return ERR_NONE;
    }

    std::string credentialType = data.ReadString();
    if (credentialType.size() == 0) {
        ACCOUNT_LOGE("failed to read string for credentialType");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_STRING_CREDENTIAL_TYPE)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }

        return ERR_NONE;
    }

    std::string credential;
    ErrCode result = GetAccountCredential(name, credentialType, credential);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    if (!reply.WriteString(credential)) {
        ACCOUNT_LOGE("failed to write string for credential");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    return ERR_NONE;
}

ErrCode AppAccountStub::ProcSetAccountCredential(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGI("enter");

    std::string name = data.ReadString();
    if (name.size() == 0) {
        ACCOUNT_LOGE("failed to read string for name");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_STRING_NAME)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }

        return ERR_NONE;
    }

    std::string credentialType = data.ReadString();
    if (credentialType.size() == 0) {
        ACCOUNT_LOGE("failed to read string for credentialType");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_STRING_CREDENTIAL_TYPE)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }

        return ERR_NONE;
    }

    std::string credential = data.ReadString();
    if (credential.size() == 0) {
        ACCOUNT_LOGI("credential.size() = 0");
    }

    ErrCode result = SetAccountCredential(name, credentialType, credential);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    return ERR_NONE;
}

ErrCode AppAccountStub::ProcAuthenticate(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGI("enter");
    OAuthRequest request;
    request.name = data.ReadString();
    if (request.name.size() == 0) {
        ACCOUNT_LOGE("failed to read string for name");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_STRING_NAME)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
        return ERR_NONE;
    }
    request.owner = data.ReadString();
    if (request.owner.size() == 0) {
        ACCOUNT_LOGE("failed to read string for owner");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_STRING_OWNER)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
        return ERR_NONE;
    }
    request.authType = data.ReadString();
    AAFwk::WantParams *options = data.ReadParcelable<AAFwk::WantParams>();
    if (options == nullptr) {
        ACCOUNT_LOGE("failed to read string for options");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_PARCELABLE_OPTIONS)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
        return ERR_NONE;
    }
    request.options = *options;
    request.callback = iface_cast<IAppAccountAuthenticatorCallback>(data.ReadParcelable<IRemoteObject>());
    if (request.callback == nullptr) {
        ACCOUNT_LOGE("failed to read parcelable for callback");
        return IPC_STUB_INVALID_DATA_ERR;
    }
    request.callerAbilityName = data.ReadString();
    if (request.callerAbilityName.size() == 0) {
        ACCOUNT_LOGE("failed to read string for callerAbilityName");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_STRING_ABILITY_NAME)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
        return ERR_NONE;
    }
    ErrCode result = Authenticate(request);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcGetOAuthToken(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGI("enter");
    std::string name = data.ReadString();
    if (name.size() == 0) {
        ACCOUNT_LOGE("failed to read string for name");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_STRING_NAME)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
        return ERR_NONE;
    }
    std::string owner = data.ReadString();
    if (owner.size() == 0) {
        ACCOUNT_LOGE("failed to read string for owner");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_STRING_NAME)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
        return ERR_NONE;
    }
    std::string authType = data.ReadString();
    std::string token;
    ErrCode result = GetOAuthToken(name, owner, authType, token);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteString(token)) {
        ACCOUNT_LOGE("failed to write string for token");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcSetOAuthToken(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGI("enter");
    std::string name = data.ReadString();
    if (name.size() == 0) {
        ACCOUNT_LOGE("failed to read string for name");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_STRING_NAME)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
        return ERR_NONE;
    }
    std::string authType = data.ReadString();
    std::string token = data.ReadString();
    ErrCode result = SetOAuthToken(name, authType, token);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcDeleteOAuthToken(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGI("enter");
    std::string name = data.ReadString();
    if (name.size() == 0) {
        ACCOUNT_LOGE("failed to read string for name");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_STRING_NAME)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
        return ERR_NONE;
    }
    std::string owner = data.ReadString();
    if (owner.size() == 0) {
        ACCOUNT_LOGE("failed to read string for owner");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_STRING_NAME)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
    }
    std::string authType = data.ReadString();
    std::string token = data.ReadString();
    ErrCode result = DeleteOAuthToken(name, owner, authType, token);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcSetOAuthTokenVisibility(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGI("enter");
    std::string name = data.ReadString();
    if (name.size() == 0) {
        ACCOUNT_LOGE("failed to read string for name");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_STRING_NAME)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
        return ERR_NONE;
    }
    std::string authType = data.ReadString();
    std::string bundleName = data.ReadString();
    if (bundleName.size() == 0) {
        ACCOUNT_LOGE("failed to read string for bundleName");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_STRING_BUNDLE_NAME)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
    }
    bool isVisible = data.ReadBool();
    ErrCode result = SetOAuthTokenVisibility(name, authType, bundleName, isVisible);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}
 
ErrCode AppAccountStub::ProcCheckOAuthTokenVisibility(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGI("enter");
    std::string name = data.ReadString();
    if (name.size() == 0) {
        ACCOUNT_LOGE("failed to read string for name");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_STRING_NAME)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
        return ERR_NONE;
    }
    std::string authType = data.ReadString();
    std::string bundleName = data.ReadString();
    if (bundleName.size() == 0) {
        ACCOUNT_LOGE("failed to read string for bundleName");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_STRING_BUNDLE_NAME)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
    }
    bool isVisible = false;
    ErrCode result = CheckOAuthTokenVisibility(name, authType, bundleName, isVisible);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteBool(isVisible)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}
 
ErrCode AppAccountStub::ProcGetAuthenticatorInfo(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGI("enter");
    std::string owner = data.ReadString();
    if (owner.size() == 0) {
        ACCOUNT_LOGE("failed to read string for owner");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_STRING_OWNER)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
        return ERR_NONE;
    }
    AuthenticatorInfo info;
    ErrCode result = GetAuthenticatorInfo(owner, info);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteString(info.owner)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteInt32(info.iconId)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteInt32(info.labelId)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcGetAllOAuthTokens(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGI("enter");
    std::vector<OAuthTokenInfo> tokenInfos;
    std::string name = data.ReadString();
    if (name.size() == 0) {
        ACCOUNT_LOGE("failed to read string for name");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_STRING_NAME)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
        return ERR_NONE;
    }
    std::string owner = data.ReadString();
    if (owner.size() == 0) {
        ACCOUNT_LOGE("failed to read string for owner");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_STRING_OWNER)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
        return ERR_NONE;
    }
    ErrCode result = GetAllOAuthTokens(name, owner, tokenInfos);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteUint32(tokenInfos.size())) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    for (auto tokenInfo : tokenInfos) {
        ACCOUNT_LOGI("token: %{public}s, authType: %{public}s", tokenInfo.token.c_str(), tokenInfo.authType.c_str());
        if (!reply.WriteString(tokenInfo.token)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
        if (!reply.WriteString(tokenInfo.authType)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcGetOAuthList(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGI("enter");
    std::set<std::string> oauthList;
    std::string name = data.ReadString();
    if (name.size() == 0) {
        ACCOUNT_LOGE("failed to read string for name");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_STRING_NAME)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
        return ERR_NONE;
    }
    std::string authType = data.ReadString();
    ErrCode result = GetOAuthList(name, authType, oauthList);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    uint32_t size = oauthList.size();
    if (!reply.WriteUint32(size)) {
        ACCOUNT_LOGE("failed to WriteUint32 for oauthList size");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    for (auto bundleName : oauthList) {
        if (!reply.WriteString(bundleName)) {
            ACCOUNT_LOGE("failed to WriteString for bundleName");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcGetAuthenticatorCallback(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGI("enter");
    std::string sessionId = data.ReadString();
    if (sessionId.size() == 0) {
        ACCOUNT_LOGE("failed to read string for sessionId");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_STRING_NAME)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
        return ERR_NONE;
    }
    sptr<IRemoteObject> callback;
    ErrCode result = GetAuthenticatorCallback(sessionId, callback);
    if (result != ERR_OK) {
        return result;
    }
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteRemoteObject(callback)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    ACCOUNT_LOGI("end");
    return ERR_OK;
}

ErrCode AppAccountStub::ProcGetAllAccounts(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGI("enter");

    std::string owner = data.ReadString();
    if (owner.size() == 0) {
        ACCOUNT_LOGE("failed to read string for owner");
        if (!reply.WriteInt32(ERR_APPACCOUNT_KIT_READ_STRING_OWNER)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }

        return ERR_NONE;
    }

    std::vector<AppAccountInfo> appAccounts;
    ErrCode result = GetAllAccounts(owner, appAccounts);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    if (!WriteParcelableVector(appAccounts, reply)) {
        ACCOUNT_LOGE("failed to write vector<AppAccount> for appAccounts");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    return ERR_NONE;
}

ErrCode AppAccountStub::ProcGetAllAccessibleAccounts(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGI("enter");

    std::vector<AppAccountInfo> appAccounts;
    ErrCode result = GetAllAccessibleAccounts(appAccounts);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    if (!WriteParcelableVector(appAccounts, reply)) {
        ACCOUNT_LOGE("failed to write vector<AppAccount> for appAccounts");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    return ERR_NONE;
}

ErrCode AppAccountStub::ProcSubscribeAccount(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGI("enter");

    std::unique_ptr<AppAccountSubscribeInfo> subscribeInfo(data.ReadParcelable<AppAccountSubscribeInfo>());
    if (!subscribeInfo) {
        ACCOUNT_LOGE("failed to read parcelable for subscribeInfo");
        return IPC_STUB_INVALID_DATA_ERR;
    }

    sptr<IRemoteObject> eventListener = data.ReadParcelable<IRemoteObject>();
    if (eventListener == nullptr) {
        ACCOUNT_LOGE("failed to read parcelable for eventListener");
        return IPC_STUB_INVALID_DATA_ERR;
    }

    ErrCode result = SubscribeAppAccount(*subscribeInfo, eventListener);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    return ERR_NONE;
}

ErrCode AppAccountStub::ProcUnsubscribeAccount(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGI("enter");

    sptr<IRemoteObject> eventListener = data.ReadParcelable<IRemoteObject>();
    if (eventListener == nullptr) {
        ACCOUNT_LOGE("failed to read parcelable for eventListener");
        return IPC_STUB_INVALID_DATA_ERR;
    }

    ErrCode result = UnsubscribeAppAccount(eventListener);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    return ERR_NONE;
}
}  // namespace AccountSA
}  // namespace OHOS
