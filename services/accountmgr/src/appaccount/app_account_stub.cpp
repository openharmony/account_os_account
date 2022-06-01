/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
    ACCOUNT_LOGD("enter");
}

AppAccountStub::~AppAccountStub()
{}

int AppAccountStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    ACCOUNT_LOGD("enter");

    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ACCOUNT_LOGE("failed to check descriptor! code %{public}u.", code);
        return ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR;
    }

    auto messageProc = messageProcMap_.find(code);
    if (messageProc != messageProcMap_.end()) {
        auto messageProcFunction = messageProc->second;
        if (messageProcFunction != nullptr) {
            return (this->*messageProcFunction)(data, reply);
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
    ACCOUNT_LOGD("enter");

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

ErrCode AppAccountStub::ProcAddAccount(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGD("enter");
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

ErrCode AppAccountStub::ProcAddAccountImplicitly(MessageParcel &data, MessageParcel &reply)
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
    }
    if (result == ERR_OK) {
        sptr<IRemoteObject> callback = data.ReadRemoteObject();
        result = AddAccountImplicitly(owner, authType, *options, callback);
    }
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcDeleteAccount(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGD("enter");

    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    ErrCode result = DeleteAccount(name);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    return ERR_NONE;
}

ErrCode AppAccountStub::ProcGetAccountExtraInfo(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGD("enter");
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

ErrCode AppAccountStub::ProcSetAccountExtraInfo(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGD("enter");
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

ErrCode AppAccountStub::ProcEnableAppAccess(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGD("enter");
    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    std::string bundleName = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(bundleName, Constants::BUNDLE_NAME_MAX_SIZE,
        "bundleName is empty or oversize");
    ErrCode result = EnableAppAccess(name, bundleName);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcDisableAppAccess(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGD("enter");
    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    std::string bundleName = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(bundleName, Constants::BUNDLE_NAME_MAX_SIZE,
        "bundleName is empty or oversize");
    ErrCode result = DisableAppAccess(name, bundleName);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcCheckAppAccountSyncEnable(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGD("enter");
    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
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
    ACCOUNT_LOGD("enter");
    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
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
    ACCOUNT_LOGD("enter");
    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    std::string key = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(key, Constants::ASSOCIATED_KEY_MAX_SIZE, "key is empty or oversize");
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
    ACCOUNT_LOGD("enter");
    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
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

ErrCode AppAccountStub::ProcGetAccountCredential(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGD("enter");
    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
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

ErrCode AppAccountStub::ProcSetAccountCredential(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGD("enter");
    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
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

ErrCode AppAccountStub::ProcAuthenticate(MessageParcel &data, MessageParcel &reply)
{
    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
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
    }
    if (result == ERR_OK) {
        sptr<IRemoteObject> callback = data.ReadRemoteObject();
        result = Authenticate(name, owner, authType, *options, callback);
    }
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcGetOAuthToken(MessageParcel &data, MessageParcel &reply)
{
    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    std::string owner = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize");
    std::string authType = data.ReadString();
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize");
    std::string token;
    ErrCode result = GetOAuthToken(name, owner, authType, token);
    if ((!reply.WriteInt32(result)) || (!reply.WriteString(token))) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcSetOAuthToken(MessageParcel &data, MessageParcel &reply)
{
    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
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

ErrCode AppAccountStub::ProcDeleteOAuthToken(MessageParcel &data, MessageParcel &reply)
{
    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    std::string owner = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(owner, Constants::OWNER_MAX_SIZE, "owner is empty or oversize");
    std::string authType = data.ReadString();
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize");
    std::string token = data.ReadString();
    RETURN_IF_STRING_IS_OVERSIZE(token, Constants::TOKEN_MAX_SIZE, "token is oversize");
    ErrCode result = DeleteOAuthToken(name, owner, authType, token);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcSetOAuthTokenVisibility(MessageParcel &data, MessageParcel &reply)
{
    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    std::string authType = data.ReadString();
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize");
    std::string bundleName = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(bundleName, Constants::BUNDLE_NAME_MAX_SIZE,
        "bundleName is empty or oversize");
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
    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    std::string authType = data.ReadString();
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::AUTH_TYPE_MAX_SIZE, "authType is oversize");
    std::string bundleName = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(bundleName, Constants::BUNDLE_NAME_MAX_SIZE,
        "bundleName is empty or oversize");
    bool isVisible = false;
    ErrCode result = CheckOAuthTokenVisibility(name, authType, bundleName, isVisible);
    if ((!reply.WriteInt32(result)) || (!reply.WriteBool(isVisible))) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode AppAccountStub::ProcGetAuthenticatorInfo(MessageParcel &data, MessageParcel &reply)
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

ErrCode AppAccountStub::ProcGetAllOAuthTokens(MessageParcel &data, MessageParcel &reply)
{
    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
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

ErrCode AppAccountStub::ProcGetOAuthList(MessageParcel &data, MessageParcel &reply)
{
    std::string name = data.ReadString();
    RETURN_IF_STRING_IS_EMPTY_OR_OVERSIZE(name, Constants::NAME_MAX_SIZE, "name is empty or oversize");
    RETURN_IF_STRING_CONTAINS_SPECIAL_CHAR(name);
    std::string authType = data.ReadString();
    RETURN_IF_STRING_IS_OVERSIZE(authType, Constants::OWNER_MAX_SIZE, "authType is oversize");
    std::set<std::string> oauthList;
    ErrCode result = GetOAuthList(name, authType, oauthList);
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

ErrCode AppAccountStub::ProcGetAuthenticatorCallback(MessageParcel &data, MessageParcel &reply)
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

ErrCode AppAccountStub::ProcGetAllAccounts(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGD("enter");
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

ErrCode AppAccountStub::ProcGetAllAccessibleAccounts(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGD("enter");
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
    ACCOUNT_LOGD("enter");
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

ErrCode AppAccountStub::ProcUnsubscribeAccount(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGD("enter");
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
