/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#ifndef OS_ACCOUNT_FRAMEWORK_OS_ACCOUNT_INFO_JSON_PARSER_H
#define OS_ACCOUNT_FRAMEWORK_OS_ACCOUNT_INFO_JSON_PARSER_H

#include "json_utils.h"
#include "os_account_info.h"

namespace OHOS {
namespace AccountSA {
namespace {
const char LOCAL_ID[] = "localId";
const char LOCAL_NAME[] = "localName";
const char SHORT_NAME[] = "shortName";
const char TYPE[] = "type";
const char CONSTRAINTS[] = "constraints";
const char IS_OS_ACCOUNT_VERIFIED[] = "isVerified";
const char PHOTO[] = "photo";
const char CREATE_TIME[] = "createTime";
const char LAST_LOGGED_IN_TIME[] = "lastLoginTime";
const char SERIAL_NUMBER[] = "serialNumber";
const char IS_ACTIVATED[] = "isActived";
const char IS_ACCOUNT_COMPLETED[] = "isCreateCompleted";
const char DOMAIN_INFO[] = "domainInfo";
const char DOMAIN_NAME[] = "domain";
const char DOMAIN_ACCOUNT_NAME[] = "accountName";
const char DOMAIN_ACCOUNT_ID[] = "accountId";
const char TO_BE_REMOVED[] = "toBeRemoved";
const char CREDENTIAL_ID[] = "credentialId";
const char DISPLAY_ID[] = "displayId";
const char IS_FOREGROUND[] = "isForeground";
const char IS_LOGGED_IN[] = "isLoggedIn";
const char IS_DATA_REMOVABLE[] = "isDataRemovable";
const char CREATOR_TYPE[] = "creatorType";
const char DOMAIN_ACCOUNT_STATUS[] = "domainAccountStatus";
const char DOMAIN_ACCOUNT_CONFIG[] = "domainServerConfigId";
constexpr int32_t ALLOWED_HAP_LIST_MAX_SIZE = 1000;
} // namespace
CJsonUnique ToJson(const OsAccountInfo &accountInfo);
bool FromJson(cJSON *jsonObject, OsAccountInfo &accountInfo);
CJsonUnique ToJson(const DomainAccountInfo &domainInfo);
bool FromJson(cJSON *jsonObject, DomainAccountInfo &domainInfo);
} // namespace AccountSA
} // namespace OHOS

#endif // OS_ACCOUNT_FRAMEWORK_OS_ACCOUNT_INFO_JSON_PARSER_H