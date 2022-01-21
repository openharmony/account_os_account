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
        static_cast<uint32_t>(IAppAccount::Message::GET_OAUTH_TOKEN),
        &AppAccountStub::ProcGetOAuthToken,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::SET_OAUTH_TOKEN),
        &AppAccountStub::ProcSetOAuthToken,
    },
    {
        static_cast<uint32_t>(IAppAccount::Message::CLEAR_OAUTH_TOKEN),
        &AppAccountStub::ProcClearOAuthToken,
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

    std::string token;
    ErrCode result = GetOAuthToken(name, token);
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

    std::string token = data.ReadString();
    if (token.size() == 0) {
        ACCOUNT_LOGI("token.size() = 0");
    }

    ErrCode result = SetOAuthToken(name, token);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    return ERR_NONE;
}

ErrCode AppAccountStub::ProcClearOAuthToken(MessageParcel &data, MessageParcel &reply)
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

    ErrCode result = ClearOAuthToken(name);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    return ERR_NONE;
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
