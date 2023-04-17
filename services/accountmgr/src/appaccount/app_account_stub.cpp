/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "app_account_stub.h"

#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "app_account_constants.h"

namespace OHOS {
namespace AccountSA {
#define RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(str)                        \
    if (CheckSpecialCharacters(str) != ERR_OK) {                           \
        ACCOUNT_LOGE("fail to check special characters");                  \
        if (!reply.WriteInt32(ERR_APPACCOUNT_SERVICE_INVALID_PARAMETER)) { \
            ACCOUNT_LOGE("failed to write reply");                         \
            return IPC_STUB_WRITE_PARCEL_ERR;                              \
        }                                                                  \
        return ERR_NONE;                                                   \
    }                                                                      \

#define RETURN_IF_STRING_IS_OVERSIZE(str, maxSize, msg)                                                         \
    if ((str).size() > (maxSize)) {                                                                             \
        ACCOUNT_LOGE("%{public}s, input size: %{public}zu, max size: %{public}zu", msg, (str).size(), maxSize); \
        if (!reply.WriteInt32(ERR_APPACCOUNT_SERVICE_INVALID_PARAMETER)) {                                      \
            ACCOUNT_LOGE("failed to write reply");                                                              \
            return IPC_STUB_WRITE_PARCEL_ERR;                                                                   \
        }                                                                                                       \
        return ERR_NONE;                                                                                        \
    }                                                                                                           \

#define RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(str, maxSize, msg)                                                \
    if ((str).empty() || ((str).size() > (maxSize))) {                                                          \
        ACCOUNT_LOGE("%{public}s, input size: %{public}zu, max size: %{public}zu", msg, (str).size(), maxSize); \
        if (!reply.WriteInt32(ERR_APPACCOUNT_SERVICE_INVALID_PARAMETER)) {                                      \
            ACCOUNT_LOGE("failed to write reply");                                                              \
            return IPC_STUB_WRITE_PARCEL_ERR;                                                                   \
        }                                                                                                       \
        return ERR_NONE;                                                                                        \
    }                                                                                                           \

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
        static_cast<uint32_t>(IAppAccount::Message::CREATE_ACCOUNT),
        &AppAccountStub::ProcCreateAccount,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::CREATE_ACCOUNT_IMPLICITLY),
        &AppAccountStub::ProcCreateAccountImplicitly,
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
        &AppAccountStub::ProcSetAppAccess,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::DISABLE_APP_ACCESS),
        &AppAccountStub::ProcSetAppAccess,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::SET_APP_ACCESS),
        &AppAccountStub::ProcSetAppAccess,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::CHECK_APP_ACCESS),
        &AppAccountStub::ProcCheckAppAccess,
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
        static_cast<uint32_t>(IAppAccount::Message::DELETE_ACCOUNT_CREDENTIAL),
        &AppAccountStub::ProcDeleteAccountCredential,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::AUTHENTICATE),
        &AppAccountStub::ProcAuthenticate,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::GET_OAUTH_TOKEN),
        &AppAccountStub::ProcGetAuthToken,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::GET_AUTH_TOKEN),
        &AppAccountStub::ProcGetAuthToken,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::SET_OAUTH_TOKEN),
        &AppAccountStub::ProcSetOAuthToken,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::DELETE_OAUTH_TOKEN),
        &AppAccountStub::ProcDeleteAuthToken,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::DELETE_AUTH_TOKEN),
        &AppAccountStub::ProcDeleteAuthToken,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::SET_OAUTH_TOKEN_VISIBILITY),
        &AppAccountStub::ProcSetAuthTokenVisibility,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::SET_AUTH_TOKEN_VISIBILITY),
        &AppAccountStub::ProcSetAuthTokenVisibility,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::CHECK_OAUTH_TOKEN_VISIBILITY),
        &AppAccountStub::ProcCheckAuthTokenVisibility,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::CHECK_AUTH_TOKEN_VISIBILITY),
        &AppAccountStub::ProcCheckAuthTokenVisibility,
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
        &AppAccountStub::ProcGetAuthList,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::GET_AUTH_LIST),
        &AppAccountStub::ProcGetAuthList,
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
        static_cast<uint32_t>(IAppAccount::Message::QUERY_ALL_ACCESSIBLE_ACCOUNTS),
        &AppAccountStub::ProcGetAllAccessibleAccounts,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::SELECT_ACCOUNTS_BY_OPTIONS),
        &AppAccountStub::ProcSelectAccountsByOptions,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::VERIFY_CREDENTIAL),
        &AppAccountStub::ProcVerifyCredential,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::CHECK_ACCOUNT_LABELS),
        &AppAccountStub::ProcCheckAccountLabels,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::SET_AUTHENTICATOR_PROPERTIES),
        &AppAccountStub::ProcSetAuthenticatorProperties,
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
{}

AppAccountStub::~AppAccountStub()
{}

int AppAccountStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ACCOUNT_LOGE("failed to check descriptor! code %{public}u.", code);
        return ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR;
    }

    auto messageProc = messageProcMap_.find(code);
    if (messageProc != messageProcMap_.end()) {
        auto messageProcFunction = messageProc->second;
        if (messageProcFunction != nullptr) {
            int ret = (this->*messageProcFunction)(code, data, reply);
            return ret;
        }
    }

    ACCOUNT_LOGD("end, code = %{public}u, flags = %{public}u", code, option.GetFlags());

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
    uint32_t size = 0;
    if (!data.ReadUint32(size)) {
        ACCOUNT_LOGE("read Parcelable size failed.");
        return false;
    }

    parcelableVector.clear();
    for (uint32_t index = 0; index < size; index++) {
        std::shared_ptr<T> info(data.ReadParcelable<T>());
        if (info == nullptr) {
            ACCOUNT_LOGE("read Parcelable infos failed.");
            return false;
        }
        parcelableVector.emplace_back(*info);
    }

    return true;
}

static ErrCode CheckSpecialCharacters(const std::string &str)
{
    for (auto specialCharacter : Constants::SPECIAL_CHARACTERS) {
        std::size_t found = str.find(specialCharacter);
        if (found != std::string::npos) {
            ACCOUNT_LOGE("found a special character, specialCharacter = %{public}c", specialCharacter);
            return ERR_APPACCOUNT_SERVICE_INVALID_PARAMETER;
        }
    }
    return ERR_OK;
}

ErrCode AppAccountStub::ProcAddAccount(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    std::string extraInfo = data.ReadString();
    RETURN_IF_STRING_IS_OVERSIZE(extraInfo, Constants::EXTRA_INFO_MAX_SIZE, "extraInfo is oversize");
    ErrCode result = AddAccount(name, extraInfo);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcAddAccountImplicitly(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    std::string owner = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize");
    std::string authType = data.ReadString();
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize");
    std::shared_ptr<AAFwk::Want> options(data.ReadParcelable<AAFwk::Want>());
    ErrCode result = ERR_OK;
    if (options == nullptr) {
        ACCOUNT_LOGE("invalid options");
        result = ERR_APPACCOUNT_SERVICE_INVALID_PARAMETER;
    } else {
        RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(options->GetStringParam(Constants::KEY_CALLER_ABILITY_NAME),
            Constants::ABILITY_NAME_MAX_SIZE, "abilityName is empty or oversize");
        sptr<IRemoteObject> callback = data.ReadRemoteObject();
        result = AddAccountImplicitly(owner, authType, *options, callback);
    }
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcCreateAccount(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    sptr<CreateAccountOptions> options = data.ReadParcelable<CreateAccountOptions>();
    ErrCode result = ERR_OK;
    if (options == nullptr) {
        ACCOUNT_LOGE("invalid options");
        result = ERR_APPACCOUNT_SERVICE_INVALID_PARAMETER;
    } else {
        RETURN_IF_STRING_IS_OVERSIZE(options->customData, Constants::MAX_CUSTOM_DATA_SIZE, "customData is oversize");
        for (const auto &it : options->customData) {
            RETURN_IF_STRING_IS_OVERSIZE(it.first, Constants::ASSOCIATED_KEY_MAX_SIZE, "customData key is oversize");
            RETURN_IF_STRING_IS_OVERSIZE(
                it.second, Constants::ASSOCIATED_VALUE_MAX_SIZE, "customData value is oversize");
        }
        result = CreateAccount(name, *options);
    }
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcCreateAccountImplicitly(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    std::string owner = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize");
    sptr<CreateAccountImplicitlyOptions> options = data.ReadParcelable<CreateAccountImplicitlyOptions>();
    ErrCode result = ERR_OK;
    if (options == nullptr) {
        ACCOUNT_LOGE("invalid options");
        result = ERR_APPACCOUNT_SERVICE_INVALID_PARAMETER;
    } else {
        RETURN_IF_STRING_IS_OVERSIZE(options->authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is empty or oversize");
        RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(options->parameters.GetStringParam(Constants::KEY_CALLER_ABILITY_NAME),
            Constants::ABILITY_NAME_MAX_SIZE, "abilityName is empty or oversize");
        RETURN_IF_STRING_IS_OVERSIZE(
            options->requiredLabels, Constants::MAX_ALLOWED_ARRAY_SIZE_INPUT, "requiredLabels array is oversize");
        sptr<IRemoteObject> callback = data.ReadRemoteObject();
        result = CreateAccountImplicitly(owner, *options, callback);
    }
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcDeleteAccount(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    ErrCode result = DeleteAccount(name);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    return ERR_NONE;
}

ErrCode AppAccountStub::ProcGetAccountExtraInfo(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
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

ErrCode AppAccountStub::ProcSetAccountExtraInfo(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    std::string extraInfo = data.ReadString();
    RETURN_IF_STRING_IS_OVERSIZE(extraInfo, Constants::EXTRA_INFO_MAX_SIZE, "extraInfo is oversize");
    ErrCode result = SetAccountExtraInfo(name, extraInfo);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcSetAppAccess(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    if (code != static_cast<uint32_t>(IAppAccount::Message::SET_APP_ACCESS)) {
        RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    }

    std::string authorizedApp = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(authorizedApp, Constants::BUNDLE_NAME_MAX_SIZE,
        "bundleName is empty or oversize");

    ErrCode result = ERR_OK;
    if (code == static_cast<uint32_t>(IAppAccount::Message::ENABLE_APP_ACCESS)) {
        result = EnableAppAccess(name, authorizedApp);
    } else if (code == static_cast<uint32_t>(IAppAccount::Message::DISABLE_APP_ACCESS)) {
        result = DisableAppAccess(name, authorizedApp);
    } else if (code == static_cast<uint32_t>(IAppAccount::Message::SET_APP_ACCESS)) {
        bool isAccessible = data.ReadBool();
        result = SetAppAccess(name, authorizedApp, isAccessible);
    } else {
        ACCOUNT_LOGE("stub code is invalid");
        return IPC_INVOKER_ERR;
    }

    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcCheckAppAccountSyncEnable(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
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

ErrCode AppAccountStub::ProcSetAppAccountSyncEnable(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    bool syncEnable = data.ReadBool();
    ErrCode result = SetAppAccountSyncEnable(name, syncEnable);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcGetAssociatedData(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    std::string name = data.ReadString();
    std::string key = data.ReadString();
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

ErrCode AppAccountStub::ProcSetAssociatedData(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    std::string key = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(key, Constants::ASSOCIATED_KEY_MAX_SIZE, "key is empty or oversize");
    std::string value = data.ReadString();
    RETURN_IF_STRING_IS_OVERSIZE(value, Constants::ASSOCIATED_VALUE_MAX_SIZE, "value is oversize");
    ErrCode result = SetAssociatedData(name, key, value);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcGetAccountCredential(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    std::string credentialType = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(credentialType, Constants::CREDENTIAL_TYPE_MAX_SIZE,
        "credentialType is empty or oversize");
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

ErrCode AppAccountStub::ProcSetAccountCredential(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    std::string credentialType = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(credentialType, Constants::CREDENTIAL_TYPE_MAX_SIZE,
        "credentialType is empty or oversize");
    std::string credential = data.ReadString();
    RETURN_IF_STRING_IS_OVERSIZE(credential, Constants::CREDENTIAL_MAX_SIZE, "credential is oversize");
    ErrCode result = SetAccountCredential(name, credentialType, credential);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcAuthenticate(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    std::string owner = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize");
    std::string authType = data.ReadString();
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize");
    std::shared_ptr<AAFwk::Want> options(data.ReadParcelable<AAFwk::Want>());
    ErrCode result = ERR_OK;
    if (options == nullptr) {
        ACCOUNT_LOGE("invalid options");
        result = ERR_APPACCOUNT_SERVICE_INVALID_PARAMETER;
    } else {
        RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(options->GetStringParam(Constants::KEY_CALLER_ABILITY_NAME),
            Constants::ABILITY_NAME_MAX_SIZE, "abilityName is empty or oversize");
        sptr<IRemoteObject> callback = data.ReadRemoteObject();
        result = Authenticate(name, owner, authType, *options, callback);
    }
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcGetAuthToken(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    std::string owner = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize");
    std::string authType = data.ReadString();
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize");
    std::string token;
    ErrCode result = ERR_OK;
    if (code == static_cast<uint32_t>(IAppAccount::Message::GET_OAUTH_TOKEN)) {
        RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
        result = GetOAuthToken(name, owner, authType, token);
    } else if (code == static_cast<uint32_t>(IAppAccount::Message::GET_AUTH_TOKEN)) {
        result = GetAuthToken(name, owner, authType, token);
    } else {
        ACCOUNT_LOGE("stub code is invalid");
        return IPC_INVOKER_ERR;
    }
    if ((!reply.WriteInt32(result)) || (!reply.WriteString(token))) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcSetOAuthToken(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    std::string authType = data.ReadString();
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize");
    std::string token = data.ReadString();
    RETURN_IF_STRING_IS_OVERSIZE(token, Constants::TOKEN_MAX_SIZE, "token is oversize");
    ErrCode result = SetOAuthToken(name, authType, token);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcDeleteAuthToken(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    std::string owner = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize");
    std::string authType = data.ReadString();
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize");
    std::string token = data.ReadString();
    RETURN_IF_STRING_IS_OVERSIZE(token, Constants::TOKEN_MAX_SIZE, "token is oversize");

    ErrCode result = ERR_OK;
    if (code == static_cast<uint32_t>(IAppAccount::Message::DELETE_OAUTH_TOKEN)) {
        RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
        result = DeleteOAuthToken(name, owner, authType, token);
    } else if (code == static_cast<uint32_t>(IAppAccount::Message::DELETE_AUTH_TOKEN)) {
        result = DeleteAuthToken(name, owner, authType, token);
    } else {
        ACCOUNT_LOGE("stub code is invalid");
        return IPC_INVOKER_ERR;
    }
     
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcSetAuthTokenVisibility(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    std::string authType = data.ReadString();
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize");
    std::string bundleName = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(bundleName, Constants::BUNDLE_NAME_MAX_SIZE,
        "bundleName is empty or oversize");
    bool isVisible = data.ReadBool();
    ErrCode result = ERR_OK;
    if (code == static_cast<uint32_t>(IAppAccount::Message::SET_OAUTH_TOKEN_VISIBILITY)) {
        RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
        result = SetOAuthTokenVisibility(name, authType, bundleName, isVisible);
    } else if (code == static_cast<uint32_t>(IAppAccount::Message::SET_AUTH_TOKEN_VISIBILITY)) {
        result = SetAuthTokenVisibility(name, authType, bundleName, isVisible);
    } else {
        ACCOUNT_LOGE("stub code is invalid");
        return IPC_INVOKER_ERR;
    }

    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcCheckAuthTokenVisibility(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    std::string authType = data.ReadString();
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize");
    std::string bundleName = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(bundleName, Constants::BUNDLE_NAME_MAX_SIZE,
        "bundleName is empty or oversize");
    bool isVisible = false;
    ErrCode result = ERR_OK;
    if (code == static_cast<uint32_t>(IAppAccount::Message::CHECK_OAUTH_TOKEN_VISIBILITY)) {
        RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
        result = CheckOAuthTokenVisibility(name, authType, bundleName, isVisible);
    } else if (code == static_cast<uint32_t>(IAppAccount::Message::CHECK_AUTH_TOKEN_VISIBILITY)) {
        result = CheckAuthTokenVisibility(name, authType, bundleName, isVisible);
    } else {
        ACCOUNT_LOGE("stub code is invalid");
        return IPC_INVOKER_ERR;
    }
     
    if ((!reply.WriteInt32(result)) || (!reply.WriteBool(isVisible))) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcGetAuthenticatorInfo(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    std::string owner = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize");
    AuthenticatorInfo info;
    ErrCode result = GetAuthenticatorInfo(owner, info);
    if ((!reply.WriteInt32(result)) || (!reply.WriteString(info.owner)) ||
        (!reply.WriteInt32(info.iconId)) || (!reply.WriteInt32(info.labelId))) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcGetAllOAuthTokens(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    std::string owner = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize");
    std::vector<OAuthTokenInfo> tokenInfos;
    ErrCode result = GetAllOAuthTokens(name, owner, tokenInfos);
    if ((!reply.WriteInt32(result)) || (!reply.WriteUint32(tokenInfos.size()))) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    for (auto tokenInfo : tokenInfos) {
        if ((!reply.WriteString(tokenInfo.token)) || (!reply.WriteString(tokenInfo.authType))) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcGetAuthList(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    std::string authType = data.ReadString();
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::OWNER_MAX_SIZE, "authType is oversize");
    std::set<std::string> oauthList;
    ErrCode result = ERR_OK;
    if (code == static_cast<uint32_t>(IAppAccount::Message::GET_OAUTH_LIST)) {
        RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
        result = GetOAuthList(name, authType, oauthList);
    } else if (code == static_cast<uint32_t>(IAppAccount::Message::GET_AUTH_LIST)) {
        result = GetAuthList(name, authType, oauthList);
    } else {
        ACCOUNT_LOGE("stub code is invalid");
        return IPC_INVOKER_ERR;
    }
    if ((!reply.WriteInt32(result)) || (!reply.WriteUint32(oauthList.size()))) {
        ACCOUNT_LOGE("failed to write reply");
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

ErrCode AppAccountStub::ProcGetAuthenticatorCallback(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    std::string sessionId = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(sessionId, Constants::SESSION_ID_MAX_SIZE,
        "sessionId is empty or oversize");
    sptr<IRemoteObject> callback;
    ErrCode result = GetAuthenticatorCallback(sessionId, callback);
    if ((!reply.WriteInt32(result)) || (!reply.WriteRemoteObject(callback))) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcGetAllAccounts(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    std::string owner = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize");
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

ErrCode AppAccountStub::ProcGetAllAccessibleAccounts(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    std::vector<AppAccountInfo> appAccounts;
    ErrCode result = ERR_OK;
    if (code == static_cast<uint32_t>(IAppAccount::Message::GET_ALL_ACCESSIBLE_ACCOUNTS)) {
        result = GetAllAccessibleAccounts(appAccounts);
    } else if (code == static_cast<uint32_t>(IAppAccount::Message::QUERY_ALL_ACCESSIBLE_ACCOUNTS)) {
        std::string owner = data.ReadString();
        RETURN_IF_STRING_IS_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is or oversize");
        result = QueryAllAccessibleAccounts(owner, appAccounts);
    } else {
        ACCOUNT_LOGE("stub code is invalid");
        return IPC_INVOKER_ERR;
    }
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

ErrCode AppAccountStub::ProcCheckAppAccess(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    std::string bundleName = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(bundleName, Constants::BUNDLE_NAME_MAX_SIZE,
        "bundleName is empty or oversize");
    bool isAccessible = false;
    ErrCode result = CheckAppAccess(name, bundleName, isAccessible);
    if ((!reply.WriteInt32(result)) || (!reply.WriteBool(isAccessible))) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcDeleteAccountCredential(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    std::string credentialType = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(credentialType, Constants::CREDENTIAL_TYPE_MAX_SIZE,
        "credentialType is empty or oversize");
    ErrCode result = DeleteAccountCredential(name, credentialType);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcSelectAccountsByOptions(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<SelectAccountsOptions> options(data.ReadParcelable<SelectAccountsOptions>());
    sptr<IRemoteObject> callback = data.ReadRemoteObject();
    ErrCode result = ERR_OK;
    if ((options == nullptr) || (callback == nullptr)) {
        ACCOUNT_LOGE("invalid parameters");
        result = ERR_APPACCOUNT_SERVICE_INVALID_PARAMETER;
    } else {
        RETURN_IF_STRING_IS_OVERSIZE(
            options->allowedAccounts, Constants::MAX_ALLOWED_ARRAY_SIZE_INPUT, "allowedAccounts array is oversize");
        RETURN_IF_STRING_IS_OVERSIZE(
            options->allowedOwners, Constants::MAX_ALLOWED_ARRAY_SIZE_INPUT, "allowedOwners array is oversize");
        RETURN_IF_STRING_IS_OVERSIZE(
            options->requiredLabels, Constants::MAX_ALLOWED_ARRAY_SIZE_INPUT, "requiredLabels array is oversize");
        result = SelectAccountsByOptions(*options, callback);
    }
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcVerifyCredential(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    std::string owner = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize");
    std::shared_ptr<VerifyCredentialOptions> options(data.ReadParcelable<VerifyCredentialOptions>());
    sptr<IRemoteObject> callback = data.ReadRemoteObject();
    ErrCode result = ERR_OK;
    if ((options == nullptr) || (callback == nullptr)) {
        ACCOUNT_LOGE("invalid parameters");
        result = ERR_APPACCOUNT_SERVICE_INVALID_PARAMETER;
    } else {
        RETURN_IF_STRING_IS_OVERSIZE(
            options->credentialType, Constants::CREDENTIAL_TYPE_MAX_SIZE, "the credential type is oversize");
        RETURN_IF_STRING_IS_OVERSIZE(
            options->credential, Constants::CREDENTIAL_MAX_SIZE, "the credential is oversize");
        result = VerifyCredential(name, owner, *options, callback);
    }
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcCheckAccountLabels(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    std::string owner = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize");
    std::vector<std::string> labels;
    data.ReadStringVector(&labels);
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(
        labels, Constants::MAX_ALLOWED_ARRAY_SIZE_INPUT, "labels array is empty or oversize");
    sptr<IRemoteObject> callback = data.ReadRemoteObject();
    ErrCode result = ERR_OK;
    if (callback == nullptr) {
        ACCOUNT_LOGE("invalid options");
        result = ERR_APPACCOUNT_SERVICE_INVALID_PARAMETER;
    } else {
        result = CheckAccountLabels(name, owner, labels, callback);
    }
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcSetAuthenticatorProperties(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    std::string owner = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE,  "owner is empty or oversize");
    std::shared_ptr<SetPropertiesOptions> options(data.ReadParcelable<SetPropertiesOptions>());
    sptr<IRemoteObject> callback = data.ReadRemoteObject();
    ErrCode result = ERR_OK;
    if ((options == nullptr) || (callback == nullptr)) {
        ACCOUNT_LOGE("invalid parameters");
        result = ERR_APPACCOUNT_SERVICE_INVALID_PARAMETER;
    } else {
        result = SetAuthenticatorProperties(owner, *options, callback);
    }
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcSubscribeAccount(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<AppAccountSubscribeInfo> subscribeInfo(data.ReadParcelable<AppAccountSubscribeInfo>());
    if (!subscribeInfo) {
        ACCOUNT_LOGE("failed to read parcelable for subscribeInfo");
        return IPC_STUB_INVALID_DATA_ERR;
    }
    sptr<IRemoteObject> eventListener = data.ReadRemoteObject();
    if (eventListener == nullptr) {
        ACCOUNT_LOGE("failed to read remote object for eventListener");
        return IPC_STUB_INVALID_DATA_ERR;
    }
    ErrCode result = SubscribeAppAccount(*subscribeInfo, eventListener);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcUnsubscribeAccount(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> eventListener = data.ReadRemoteObject();
    if (eventListener == nullptr) {
        ACCOUNT_LOGE("failed to read remote object for eventListener");
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
