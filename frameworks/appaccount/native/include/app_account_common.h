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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_COMMON_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_COMMON_H

#include <string>
#include "iapp_account_authenticator_callback.h"
#include "want.h"

namespace OHOS {
namespace AccountSA {
namespace {
const std::string UNKONW_STRING_VALUE = "unknown";
}

struct AppAccountCallingInfo {
    int32_t callingUid = -1;
    std::string bundleName;
    uint32_t appIndex;
};

struct AuthenticatorInfo {
    std::string owner;
    std::string abilityName;
    int32_t iconId;
    int32_t labelId;
};

struct SelectAccountsOptions : public Parcelable {
    bool hasAccounts = false;
    bool hasOwners = false;
    bool hasLabels = false;
    std::vector<std::pair<std::string, std::string>> allowedAccounts;
    std::vector<std::string> allowedOwners;
    std::vector<std::string> requiredLabels;
    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static SelectAccountsOptions *Unmarshalling(Parcel &parcel);
};

struct VerifyCredentialOptions : public Parcelable {
    std::string credentialType;
    std::string credential;
    AAFwk::WantParams parameters;
    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static VerifyCredentialOptions *Unmarshalling(Parcel &parcel);
};

struct SetPropertiesOptions : public Parcelable {
    AAFwk::WantParams properties;
    AAFwk::WantParams parameters;
    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static SetPropertiesOptions *Unmarshalling(Parcel &parcel);
};

struct CreateAccountOptions : public Parcelable {
    std::map<std::string, std::string> customData;
    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static CreateAccountOptions *Unmarshalling(Parcel &parcel);
};

struct CreateAccountImplicitlyOptions : public Parcelable {
    bool hasAuthType = false;
    bool hasRequiredLabels = false;
    std::string authType;
    std::vector<std::string> requiredLabels;
    AAFwk::Want parameters;
    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static CreateAccountImplicitlyOptions *Unmarshalling(Parcel &parcel);
};

struct AuthenticatorSessionRequest {
    std::string action;
    std::string sessionId;
    std::string name = UNKONW_STRING_VALUE;
    std::string owner = UNKONW_STRING_VALUE;
    std::string authType;
    std::string token;
    std::string bundleName = UNKONW_STRING_VALUE;
    std::string callerBundleName;
    std::string callerAbilityName = UNKONW_STRING_VALUE;
    uint32_t appIndex;
    bool isTokenVisible = false;
    pid_t callerPid;
    pid_t callerUid;
    AAFwk::Want options;
    std::vector<std::string> labels;
    VerifyCredentialOptions verifyCredOptions;
    SetPropertiesOptions setPropOptions;
    CreateAccountImplicitlyOptions createOptions;
    sptr<IAppAccountAuthenticatorCallback> callback = nullptr;
};

enum AuthenticatorAction {
    ADD_ACCOUNT_IMPLICITLY,
    AUTHENTICATE,
    VERIFY_CREDENTIAL,
    CHECK_ACCOUNT_LABELS,
    SET_AUTHENTICATOR_PROPERTIES,
    IS_ACCOUNT_REMOVABLE,
    CREATE_ACCOUNT_IMPLICITLY,
    AUTH,
};

enum JSResultCode {
    ERR_JS_SUCCESS_V8 = 0,
    ERR_JS_ACCOUNT_NOT_EXIST = 10001,
    ERR_JS_APP_ACCOUNT_SERVICE_EXCEPTION = 10002,
    ERR_JS_INVALID_PASSWORD = 10003,
    ERR_JS_INVALID_REQUEST = 10004,
    ERR_JS_INVALID_RESPONSE = 10005,
    ERR_JS_NETWORK_EXCEPTION = 10006,
    ERR_JS_OAUTH_AUTHENTICATOR_NOT_EXIST = 10007,
    ERR_JS_OAUTH_CANCELED = 10008,
    ERR_JS_OAUTH_LIST_TOO_LARGE = 10009,
    ERR_JS_OAUTH_SERVICE_BUSY = 10010,
    ERR_JS_OAUTH_SERVICE_EXCEPTION = 10011,
    ERR_JS_OAUTH_SESSION_NOT_EXIST = 10012,
    ERR_JS_OAUTH_TIMEOUT = 10013,
    ERR_JS_OAUTH_TOKEN_NOT_EXIST = 10014,
    ERR_JS_OAUTH_TOKEN_TOO_MANY = 10015,
    ERR_JS_OAUTH_UNSUPPORT_ACTION = 10016,
    ERR_JS_OAUTH_UNSUPPORT_AUTH_TYPE = 10017,
    ERR_JS_PERMISSION_DENIED_V8 = 10018
};

int32_t ConvertToJSErrCodeV8(int32_t errCode);
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_COMMON_H
