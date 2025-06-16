/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "app_account_common.h"

#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "app_account_constants.h"

namespace OHOS {
namespace AccountSA {
namespace {
constexpr uint32_t MAX_VEC_SIZE = 1024;
}

bool AuthenticatorInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(owner)) {
        ACCOUNT_LOGE("Write owner failed, please check owner value or parcel status");
        return false;
    }
    if (!parcel.WriteString(abilityName)) {
        ACCOUNT_LOGE("Write abilityName failed, please check abilityName value or parcel status");
        return false;
    }
    if (!parcel.WriteUint32(iconId)) {
        ACCOUNT_LOGE("Write iconId failed, please check iconId value or parcel status");
        return false;
    }
    if (!parcel.WriteUint32(labelId)) {
        ACCOUNT_LOGE("Write labelId failed, please check labelId value or parcel status");
        return false;
    }
    return true;
}

AuthenticatorInfo *AuthenticatorInfo::Unmarshalling(Parcel &parcel)
{
    AuthenticatorInfo *info = new (std::nothrow) AuthenticatorInfo();
    if ((info != nullptr) && (!info->ReadFromParcel(parcel))) {
        ACCOUNT_LOGW("Read from parcel failed, please check parcel data");
        delete info;
        info = nullptr;
    }
    return info;
}

bool AuthenticatorInfo::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadString(owner)) {
        ACCOUNT_LOGE("Read owner failed, please check owner data in parcel");
        return false;
    }
    if (!parcel.ReadString(abilityName)) {
        ACCOUNT_LOGE("Read abilityName failed, please check abilityName data in parcel");
        return false;
    }
    if (!parcel.ReadUint32(iconId)) {
        ACCOUNT_LOGE("Read iconId failed, please check iconId data in parcel");
        return false;
    }
    if (!parcel.ReadUint32(labelId)) {
        ACCOUNT_LOGE("Read labelId failed, please check labelId data in parcel");
        return false;
    }
    return true;
}

bool SelectAccountsOptions::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteBool(hasAccounts) || !parcel.WriteBool(hasOwners) || !parcel.WriteBool(hasLabels)) {
        ACCOUNT_LOGE("WriteBool failed");
        return false;
    }
    if (!parcel.WriteUint32(allowedAccounts.size())) {
        ACCOUNT_LOGE("WriteUint32 failed");
        return false;
    }
    for (auto item : allowedAccounts) {
        if ((!parcel.WriteString(item.first)) || (!parcel.WriteString(item.second))) {
            ACCOUNT_LOGE("WriteString failed");
            return false;
        }
    }
    return parcel.WriteStringVector(allowedOwners) && parcel.WriteStringVector(requiredLabels);
}

SelectAccountsOptions *SelectAccountsOptions::Unmarshalling(Parcel &parcel)
{
    SelectAccountsOptions *info = new (std::nothrow) SelectAccountsOptions();
    if ((info != nullptr) && (!info->ReadFromParcel(parcel))) {
        ACCOUNT_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

bool SelectAccountsOptions::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadBool(hasAccounts) || !parcel.ReadBool(hasOwners) || !parcel.ReadBool(hasLabels)) {
        return false;
    }
    uint32_t size = 0;
    if (!parcel.ReadUint32(size)) {
        return false;
    }
    if (size > MAX_VEC_SIZE) {
        ACCOUNT_LOGE("option is oversize, the limit is %{public}d", MAX_VEC_SIZE);
        return false;
    }
    std::string name;
    std::string type;
    for (uint32_t i = 0; i < size; ++i) {
        if ((!parcel.ReadString(name)) || (!parcel.ReadString(type))) {
            return false;
        }
        allowedAccounts.push_back(std::make_pair(name, type));
    }
    return parcel.ReadStringVector(&allowedOwners) && parcel.ReadStringVector(&requiredLabels);
}

AuthorizationRequest::AuthorizationRequest(const int32_t &callingUid, const AAFwk::WantParams &parameters,
    const sptr<IAppAccountAuthorizationExtensionCallback> &callback)
    : callerUid(callingUid), parameters(parameters), callback(callback)
{}

AuthorizationRequest::AuthorizationRequest()
{}

bool VerifyCredentialOptions::Marshalling(Parcel &parcel) const
{
    return parcel.WriteString(credentialType) && parcel.WriteString(credential) && parcel.WriteParcelable(&parameters);
}

VerifyCredentialOptions *VerifyCredentialOptions::Unmarshalling(Parcel &parcel)
{
    VerifyCredentialOptions *info = new (std::nothrow) VerifyCredentialOptions();
    if ((info != nullptr) && (!info->ReadFromParcel(parcel))) {
        ACCOUNT_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

bool VerifyCredentialOptions::ReadFromParcel(Parcel &parcel)
{
    if ((!parcel.ReadString(credentialType)) || (!parcel.ReadString(credential))) {
        return false;
    }
    sptr<AAFwk::WantParams> wantParams = parcel.ReadParcelable<AAFwk::WantParams>();
    if (wantParams == nullptr) {
        return false;
    }
    parameters = *wantParams;
    return true;
}

bool SetPropertiesOptions::Marshalling(Parcel &parcel) const
{
    return parcel.WriteParcelable(&properties) && parcel.WriteParcelable(&parameters);
}

SetPropertiesOptions *SetPropertiesOptions::Unmarshalling(Parcel &parcel)
{
    SetPropertiesOptions *info = new (std::nothrow) SetPropertiesOptions();
    if ((info != nullptr) && (!info->ReadFromParcel(parcel))) {
        ACCOUNT_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

bool SetPropertiesOptions::ReadFromParcel(Parcel &parcel)
{
    sptr<AAFwk::WantParams> propPtr = parcel.ReadParcelable<AAFwk::WantParams>();
    if (propPtr == nullptr) {
        return false;
    }
    properties = *propPtr;
    sptr<AAFwk::WantParams> paramsPtr = parcel.ReadParcelable<AAFwk::WantParams>();
    if (paramsPtr == nullptr) {
        return false;
    }
    parameters = *paramsPtr;
    return true;
}

bool CreateAccountOptions::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteUint32(customData.size())) {
        ACCOUNT_LOGE("failed to write custom data size");
        return false;
    }
    for (const auto& it : customData) {
        if (!parcel.WriteString(it.first)) {
            ACCOUNT_LOGE("failed to write key");
            return false;
        }
        if (!parcel.WriteString(it.second)) {
            ACCOUNT_LOGE("failed to write value");
            return false;
        }
    }
    return true;
}

CreateAccountOptions *CreateAccountOptions::Unmarshalling(Parcel &parcel)
{
    CreateAccountOptions *info = new (std::nothrow) CreateAccountOptions();
    if ((info != nullptr) && (!info->ReadFromParcel(parcel))) {
        ACCOUNT_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

bool CreateAccountOptions::ReadFromParcel(Parcel &parcel)
{
    customData.clear();
    uint32_t size = 0;
    if (!parcel.ReadUint32(size)) {
        ACCOUNT_LOGE("fail to read custom data size");
        return false;
    }
    if (size > MAX_VEC_SIZE) {
        ACCOUNT_LOGE("custom data is oversize, the limit is %{public}d", MAX_VEC_SIZE);
        return false;
    }
    for (uint32_t i = 0; i < size; ++i) {
        std::string key;
        if (!parcel.ReadString(key)) {
            ACCOUNT_LOGE("fail to read custom data key");
            return false;
        }
        std::string value;
        if (!parcel.ReadString(value)) {
            ACCOUNT_LOGE("fail to read custom data value");
            return false;
        }
        customData.emplace(key, value);
    }
    return true;
}

bool CreateAccountImplicitlyOptions::Marshalling(Parcel &parcel) const
{
    return parcel.WriteBool(hasAuthType) && parcel.WriteBool(hasRequiredLabels) && parcel.WriteString(authType) &&
        parcel.WriteStringVector(requiredLabels) && parcel.WriteParcelable(&parameters);
}

CreateAccountImplicitlyOptions *CreateAccountImplicitlyOptions::Unmarshalling(Parcel &parcel)
{
    CreateAccountImplicitlyOptions *info = new (std::nothrow) CreateAccountImplicitlyOptions();
    if ((info != nullptr) && (!info->ReadFromParcel(parcel))) {
        ACCOUNT_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

bool CreateAccountImplicitlyOptions::ReadFromParcel(Parcel &parcel)
{
    bool result = parcel.ReadBool(hasAuthType) && parcel.ReadBool(hasRequiredLabels) && parcel.ReadString(authType) &&
        parcel.ReadStringVector(&requiredLabels);
    sptr<AAFwk::Want> params = parcel.ReadParcelable<AAFwk::Want>();
    if ((!result) || (params == nullptr)) {
        return false;
    }
    parameters = *params;
    return true;
}

bool AccountCapabilityRequest::Marshalling(Parcel &parcel) const
{
    return parcel.WriteBool(isEnableContext) && parcel.WriteString(bundleName) && parcel.WriteString(abilityName) &&
           parcel.WriteParcelable(&parameters);
}

AccountCapabilityRequest *AccountCapabilityRequest::Unmarshalling(Parcel &parcel)
{
    AccountCapabilityRequest *info = new (std::nothrow) AccountCapabilityRequest();
    if ((info != nullptr) && (!info->ReadFromParcel(parcel))) {
        ACCOUNT_LOGE("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

bool AuthorizationRequest::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(callerUid)) {
        ACCOUNT_LOGE("Write callerUid failed, please check callerUid value or parcel status");
        return false;
    }
    if (!parcel.WriteBool(isEnableContext)) {
        ACCOUNT_LOGE("Write isEnableContext failed, please check isEnableContext value or parcel status");
        return false;
    }
    if (!parcel.WriteParcelable(&parameters)) {
        ACCOUNT_LOGE("Write parameters failed, please check parameters value or parcel status");
        return false;
    }
    if ((callback == nullptr) || (!parcel.WriteRemoteObject(callback->AsObject()))) {
        ACCOUNT_LOGE("WriteRemoteObject failed, please check callback value or parcel status");
        return false;
    }
    return true;
}

AuthorizationRequest *AuthorizationRequest::Unmarshalling(Parcel &parcel)
{
    AuthorizationRequest *info = new (std::nothrow) AuthorizationRequest();
    if ((info != nullptr) && (!info->ReadFromParcel(parcel))) {
        ACCOUNT_LOGW("ReadFromParcel failed, please check parcel data");
        delete info;
        info = nullptr;
    }
    return info;
}

bool AuthorizationRequest::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadInt32(callerUid)) {
        ACCOUNT_LOGE("Read callerUid failed, please check callerUid in parcel");
        return false;
    }
    if (!parcel.ReadBool(isEnableContext)) {
        ACCOUNT_LOGE("Read isEnableContext failed, please check isEnableContext in parcel");
        return false;
    }
    sptr<AAFwk::WantParams> paramsPtr = parcel.ReadParcelable<AAFwk::WantParams>();
    if (paramsPtr == nullptr) {
        ACCOUNT_LOGE("Read parameters failed, please check parameters in parcel");
        return false;
    }
    parameters = *paramsPtr;
    auto readCallback = (static_cast<MessageParcel*>(&parcel))->ReadRemoteObject();
    if (readCallback == nullptr) {
        ACCOUNT_LOGE("Read callback failed, please check callback object in parcel");
        return false;
    }
    callback = iface_cast<IAppAccountAuthorizationExtensionCallback>(readCallback);
    if (callback == nullptr) {
        ACCOUNT_LOGE("Convert callback failed, please check callback object in parcel");
        return false;
    }
    return true;
}

bool AccountCapabilityRequest::ReadFromParcel(Parcel &parcel)
{
    if ((!parcel.ReadBool(isEnableContext)) || (!parcel.ReadString(bundleName)) || (!parcel.ReadString(abilityName))) {
        return false;
    }
    sptr<AAFwk::WantParams> paramsPtr = parcel.ReadParcelable<AAFwk::WantParams>();
    if (paramsPtr == nullptr) {
        return false;
    }
    parameters = *paramsPtr;
    return true;
}

int32_t ConvertOtherJSErrCodeV8(int32_t errCode)
{
    switch (errCode) {
        case ERR_OK:
            return ERR_JS_SUCCESS_V8;
        case ERR_APPACCOUNT_SERVICE_ACCOUNT_NOT_EXIST:
            return ERR_JS_ACCOUNT_NOT_EXIST;
        case ERR_APPACCOUNT_SERVICE_OAUTH_AUTHENTICATOR_NOT_EXIST:
            return ERR_JS_OAUTH_AUTHENTICATOR_NOT_EXIST;
        case ERR_APPACCOUNT_SERVICE_OAUTH_BUSY:
            return ERR_JS_OAUTH_SERVICE_BUSY;
        case ERR_APPACCOUNT_SERVICE_OAUTH_LIST_MAX_SIZE:
            return ERR_JS_OAUTH_LIST_TOO_LARGE;
        case ERR_APPACCOUNT_SERVICE_OAUTH_SESSION_NOT_EXIST:
            return ERR_JS_OAUTH_SESSION_NOT_EXIST;
        case ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_NOT_EXIST:
            return ERR_JS_OAUTH_TOKEN_NOT_EXIST;
        case ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_MAX_SIZE:
            return ERR_JS_OAUTH_TOKEN_TOO_MANY;
        case ERR_ACCOUNT_COMMON_PERMISSION_DENIED:
            return ERR_JS_PERMISSION_DENIED_V8;
        default:
            return ERR_JS_APP_ACCOUNT_SERVICE_EXCEPTION;
    }
}

int32_t ConvertToJSErrCodeV8(int32_t errCode)
{
    if ((errCode == ERR_ACCOUNT_COMMON_INVALID_PARAMETER) ||
        (errCode >= ERR_APPACCOUNT_KIT_SUBSCRIBER_IS_NULLPTR && errCode <= ERR_APPACCOUNT_KIT_SEND_REQUEST) ||
        (errCode >= ERR_APPACCOUNT_SERVICE_ADD_EXISTING_ACCOUNT &&
        errCode <= ERR_APPACCOUNT_SERVICE_DISABLE_APP_ACCESS_NOT_EXISTED)) {
        return ERR_JS_INVALID_REQUEST;
    } else if ((errCode >= ERR_APPACCOUNT_KIT_READ_PARCELABLE_APP_ACCOUNT_INFO &&
        errCode <= ERR_APPACCOUNT_KIT_READ_PARCELABLE_VECTOR_ACCOUNT_INFO) ||
        (errCode == ERR_APPACCOUNT_SERVICE_OAUTH_INVALID_RESPONSE) ||
        (errCode == ERR_APPACCOUNT_SERVICE_OAUTH_AUTHENTICATOR_CALLBACK_NOT_EXIST)) {
        return ERR_JS_INVALID_RESPONSE;
    } else {
        return ConvertOtherJSErrCodeV8(errCode);
    }
}
}  // namespace AccountSA
}  // namespace OHOS