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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_CONSTANTS_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_CONSTANTS_H

#include "account_error_no.h"
#include "iaccount_info.h"
#include "parcel.h"

namespace OHOS {
namespace AccountSA {
namespace Constants {
const std::string SYSTEM_ACTION_APP_ACCOUNT_OAUTH = "ohos.account.appAccount.action.oauth";
const std::string OAUTH_ACTION_ADD_ACCOUNT_IMPLICITLY = "addAccountImplicitly";
const std::string OAUTH_ACTION_AUTHENTICATE = "authenticate";
const std::string APP_ACCOUNT_APP_ID = "app_account_manager_service";
const std::string KEY_NAME = "name";
const std::string KEY_OWNER = "owner";
const std::string KEY_TOKEN = "token";
const std::string KEY_ACTION = "action";
const std::string KEY_AUTH_TYPE = "authType";
const std::string KEY_SESSION_ID = "sessionId";
const std::string KEY_CALLER_BUNDLE_NAME = "callerBundleName";
const std::string KEY_CALLER_PID = "callerPid";
const std::string KEY_CALLER_UID = "callerUid";
};  // namespace Constants
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_APPACCOUNT_APP_ACCOUNT_CONSTANTS_H
