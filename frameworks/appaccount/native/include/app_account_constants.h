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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_CONSTANTS_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_CONSTANTS_H

#include "account_error_no.h"
#include "iaccount_info.h"
#include "parcel.h"

namespace OHOS {
namespace AccountSA {
namespace Constants {
const std::string SYSTEM_ACTION_APP_ACCOUNT_AUTH = "ohos.appAccount.action.auth";
const std::string SYSTEM_ACTION_APP_ACCOUNT_OAUTH = "ohos.account.appAccount.action.oauth";
const std::string OAUTH_ACTION_ADD_ACCOUNT_IMPLICITLY = "addAccountImplicitly";
const std::string OAUTH_ACTION_AUTHENTICATE = "authenticate";
const std::string ACTION_CREATE_ACCOUNT_IMPLICITLY = "createAccountImplicitly";
const std::string ACTION_AUTH = "auth";
const std::string ACTION_VERIFY_CREDENTIAL = "verifyCredential";
const std::string ACTION_SET_AUTHENTICATOR_PROPERTIES = "setAuthenticatorProperties";
const std::string APP_ACCOUNT_APP_ID = "app_account_manager_service";
const std::string KEY_NAME = "name";
const std::string KEY_OWNER = "owner";
const std::string KEY_TOKEN = "token";
const std::string KEY_ACTION = "action";
const std::string KEY_AUTH_TYPE = "authType";
const std::string KEY_SESSION_ID = "sessionId";
const std::string KEY_CALLER_BUNDLE_NAME = "callerBundleName";
const std::string KEY_CALLER_ABILITY_NAME = "callerAbilityName";
const std::string KEY_CALLER_PID = "callerPid";
const std::string KEY_CALLER_UID = "callerUid";
const std::string KEY_REQUIRED_LABELS = "requiredLabels";
const std::string KEY_BOOLEAN_RESULT = "booleanResult";
const std::string KEY_ACCOUNT_NAMES = "accountNames";
const std::string KEY_ACCOUNT_OWNERS = "accountOwners";
const std::string SPECIAL_CHARACTERS = " ";
const std::string HYPHEN = "#";
const std::string API_V9 = "apiV9";
constexpr std::size_t APP_ACCOUNT_SUBSCRIBER_MAX_SIZE = 200;
constexpr std::size_t NAME_MAX_SIZE = 512;
constexpr std::size_t EXTRA_INFO_MAX_SIZE = 1024;
constexpr std::size_t BUNDLE_NAME_MAX_SIZE = 512;
constexpr std::size_t ASSOCIATED_KEY_MAX_SIZE = 1024;
constexpr std::size_t ASSOCIATED_VALUE_MAX_SIZE = 1024;
constexpr std::size_t CREDENTIAL_TYPE_MAX_SIZE = 1024;
constexpr std::size_t CREDENTIAL_MAX_SIZE = 1024;
constexpr std::size_t TOKEN_MAX_SIZE = 1024;
constexpr std::size_t OWNER_MAX_SIZE = 1024;
constexpr std::size_t AUTH_TYPE_MAX_SIZE = 1024;
constexpr std::size_t ABILITY_NAME_MAX_SIZE = 512;
constexpr std::size_t SESSION_ID_MAX_SIZE = 1024;
constexpr std::size_t MAX_ALLOWED_ARRAY_SIZE_INPUT = 1024;
constexpr std::size_t MAX_CUSTOM_DATA_SIZE = 1024;
constexpr uint32_t API_VERSION7 = 7;
constexpr uint32_t API_VERSION8 = 8;
constexpr uint32_t API_VERSION9 = 9;
};  // namespace Constants
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_CONSTANTS_H
