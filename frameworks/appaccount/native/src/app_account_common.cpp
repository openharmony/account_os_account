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

#include "app_account_common.h"

#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "app_account_constants.h"

namespace OHOS {
namespace AccountSA {
namespace {
constexpr const uint32_t MAX_OPTION_SIZE = 1024;
}

bool SelectAccountsOptions::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteBool(hasAccounts) || !parcel.WriteBool(hasOwners) || !parcel.WriteBool(hasLabels)) {
        return false;
    }
    if (!parcel.WriteUint32(allowedAccounts.size())) {
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
    if (info && !info->ReadFromParcel(parcel)) {
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
    if (size > MAX_OPTION_SIZE) {
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

bool VerifyCredentialOptions::Marshalling(Parcel &parcel) const
{
    return parcel.WriteString(credentialType) && parcel.WriteString(credential) && parcel.WriteParcelable(&parameters);
}

VerifyCredentialOptions *VerifyCredentialOptions::Unmarshalling(Parcel &parcel)
{
    VerifyCredentialOptions *info = new (std::nothrow) VerifyCredentialOptions();
    if (info && !info->ReadFromParcel(parcel)) {
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
    if (info && !info->ReadFromParcel(parcel)) {
        ACCOUNT_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

bool SetPropertiesOptions::ReadFromParcel(Parcel &parcel)
{
    sptr<AAFwk::WantParams> wantParams = parcel.ReadParcelable<AAFwk::WantParams>();
    if (!wantParams) {
        return false;
    }
    properties = *wantParams;
    wantParams = parcel.ReadParcelable<AAFwk::WantParams>();
    if (!wantParams) {
        return false;
    }
    parameters = *wantParams;
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
        default:
            return ERR_JS_APP_ACCOUNT_SERVICE_EXCEPTION;
    }
}

int32_t ConvertToJSErrCodeV8(int32_t errCode)
{
    if ((errCode >= ERR_APPACCOUNT_KIT_NAME_IS_EMPTY && errCode <= ERR_APPACCOUNT_KIT_SEND_REQUEST) ||
        (errCode >= ERR_APPACCOUNT_SERVICE_NAME_IS_EMPTY && errCode <= ERR_APPACCOUNT_SERVICE_INVALID_PARAMETER) ||
        (errCode >= ERR_APPACCOUNT_SERVICE_ADD_EXISTING_ACCOUNT &&
        errCode <= ERR_APPACCOUNT_SERVICE_DISABLE_APP_ACCESS_NOT_EXISTED)) {
        return ERR_JS_INVALID_REQUEST;
    } else if ((errCode >= ERR_APPACCOUNT_KIT_READ_PARCELABLE_APP_ACCOUNT_INFO &&
        errCode <= ERR_APPACCOUNT_KIT_READ_PARCELABLE_VECTOR_ACCOUNT_INFO) ||
        (errCode == ERR_APPACCOUNT_SERVICE_OAUTH_INVALID_RESPONSE) ||
        (errCode == ERR_APPACCOUNT_SERVICE_OAUTH_AUTHENTICATOR_CALLBACK_NOT_EXIST)) {
        return ERR_JS_INVALID_RESPONSE;
    } else if (errCode == ERR_APPACCOUNT_SERVICE_PERMISSION_DENIED ||
        errCode == ERR_APPACCOUNT_SERVICE_SUBSCRIBE_PERMISSION_DENIED) {
        return ERR_JS_PERMISSION_DENIED_V8;
    } else {
        return ConvertOtherJSErrCodeV8(errCode);
    }
}
}  // namespace AccountSA
}  // namespace OHOS