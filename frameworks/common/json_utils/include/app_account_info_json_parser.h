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

#ifndef OS_ACCOUNT_FRAMEWORK_APP_ACCOUNT_INFO_JSON_PARSER_H
#define OS_ACCOUNT_FRAMEWORK_APP_ACCOUNT_INFO_JSON_PARSER_H

#include "app_account_info.h"
#include "json_utils.h"

namespace OHOS {
namespace AccountSA {
namespace {
const char OWNER[] = "owner";
const char NAME[] = "name";
const char ALIAS[] = "alias";
const char EXTRA_INFO[] = "extraInfo";
const char SYNC_ENABLE[] = "syncEnable";
const char AUTHORIZED_APPS[] = "authorizedApps";
const char ASSOCIATED_DATA[] = "associatedData";
const char ACCOUNT_CREDENTIAL[] = "accountCredential";
const char OAUTH_TOKEN[] = "oauthToken";
const char OAUTH_TOKEN_INFOS[] = "tokenInfos";
const char OAUTH_TYPE[] = "authType";
const char OAUTH_TOKEN_STATUS[] = "status";
const char OAUTH_AUTH_LIST[] = "authList";
const std::string OAUTH_TOKEN_TO_TYPE = "tokenToType";
const char HYPHEN[] = "#";
constexpr uint32_t APP_INDEX = 0;
constexpr uint32_t MAX_TOKEN_NUMBER = 128;
constexpr uint32_t MAX_OAUTH_LIST_SIZE = 512;
constexpr uint32_t MAX_ASSOCIATED_DATA_NUMBER = 1024;
constexpr uint32_t MAX_APP_AUTH_LIST_SIZE = 1024;
#ifdef HAS_ASSET_PART
constexpr uint32_t HASH_LENGTH = 32;
constexpr uint32_t WIDTH_FOR_HEX = 2;
#endif
constexpr int32_t MAX_MAP_SZIE = 1024;
} // namespace
CJsonUnique ToJson(const AppAccountInfo &accountInfo);
bool FromJson(cJSON *jsonObject, AppAccountInfo &accountInfo);
} // namespace AccountSA
} // namespace OHOS

#endif // OS_ACCOUNT_FRAMEWORK_APP_ACCOUNT_INFO_JSON_PARSER_H