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

#include "app_account_info_json_parser.h"
#include "app_account_info.h"
#include "json_utils.h"

namespace OHOS {
namespace AccountSA {

static void ParseTokenInfosFromJson(const cJSON *jsonObject, AppAccountInfo &accountInfo)
{
    cJSON *item = nullptr;
    cJSON_ArrayForEach(item, jsonObject) {
        OAuthTokenInfo tokenInfo;
        tokenInfo.token = GetStringFromJson(item, OAUTH_TOKEN);
        tokenInfo.status = GetBoolFromJson(item, OAUTH_TOKEN_STATUS);
        tokenInfo.authType = GetStringFromJson(item, OAUTH_TYPE);
        GetSetStringFromJson(item, OAUTH_AUTH_LIST, tokenInfo.authList);
        accountInfo.oauthTokens_.emplace(tokenInfo.authType, tokenInfo);
    }
}

CJsonUnique ToJson(const AppAccountInfo &accountInfo)
{
    auto tokenArray = CreateJsonArray();
    for (const auto &pair : accountInfo.oauthTokens_) {
        const auto &authType = pair.first;
        const auto &tokenInfo = pair.second;
        if (!tokenInfo.status && tokenInfo.authList.empty()) {
            continue;
        }
        auto tokenObject = CreateJson();
        AddStringToJson(tokenObject, OAUTH_TYPE, authType);
        AddStringToJson(tokenObject, OAUTH_TOKEN, tokenInfo.token);
        AddBoolToJson(tokenObject, OAUTH_TOKEN_STATUS, tokenInfo.status);
        AddSetStringToJson(tokenObject, OAUTH_AUTH_LIST, tokenInfo.authList);
        AddObjToArray(tokenArray, tokenObject);
    }
    auto jsonObject = CreateJson();

    AddStringToJson(jsonObject, OWNER, accountInfo.owner_);
    AddStringToJson(jsonObject, NAME, accountInfo.name_);
    AddStringToJson(jsonObject, ALIAS, accountInfo.alias_);
    AddStringToJson(jsonObject, EXTRA_INFO, accountInfo.extraInfo_);
    AddSetStringToJson(jsonObject, AUTHORIZED_APPS, accountInfo.authorizedApps_);
    AddBoolToJson(jsonObject, SYNC_ENABLE, accountInfo.syncEnable_);
    AddStringToJson(jsonObject, ASSOCIATED_DATA, accountInfo.associatedData_);
    AddStringToJson(jsonObject, ACCOUNT_CREDENTIAL, accountInfo.accountCredential_);
    AddObjToJson(jsonObject, OAUTH_TOKEN_INFOS, tokenArray);

    return jsonObject;
}

bool FromJson(cJSON *jsonObject, AppAccountInfo &accountInfo)
{
    if (jsonObject == nullptr || !IsObject(jsonObject)) {
        return false;
    }

    GetDataByType<std::string>(jsonObject, OWNER, accountInfo.owner_);
    GetDataByType<std::string>(jsonObject, NAME, accountInfo.name_);
    GetDataByType<std::string>(jsonObject, ALIAS, accountInfo.alias_);
    GetDataByType<std::string>(jsonObject, EXTRA_INFO, accountInfo.extraInfo_);
    GetDataByType<bool>(jsonObject, SYNC_ENABLE, accountInfo.syncEnable_);
    GetDataByType<std::set<std::string>>(jsonObject, AUTHORIZED_APPS, accountInfo.authorizedApps_);
    GetDataByType<std::string>(jsonObject, ASSOCIATED_DATA, accountInfo.associatedData_);
    GetDataByType<std::string>(jsonObject, ACCOUNT_CREDENTIAL, accountInfo.accountCredential_);
    if (IsKeyExist(jsonObject, OAUTH_TOKEN_INFOS)) {
        cJSON *item = GetJsonArrayFromJson(jsonObject, OAUTH_TOKEN_INFOS);
        ParseTokenInfosFromJson(item, accountInfo);
    }

    return true;
}
} // namespace AccountSA
} // namespace OHOS