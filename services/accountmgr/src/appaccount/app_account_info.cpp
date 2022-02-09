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

#include "account_log_wrapper.h"
#include "nlohmann/json.hpp"

#include "app_account_info.h"

namespace OHOS {
namespace AccountSA {
namespace {
const std::string OWNER = "owner";
const std::string NAME = "name";
const std::string EXTRA_INFO = "extraInfo";
const std::string SYNC_ENABLE = "syncEnable";
const std::string AUTHORIZED_APPS = "authorizedApps";
const std::string ASSOCIATED_DATA = "associatedData";
const std::string ACCOUNT_CREDENTIAL = "accountCredential";
const std::string OAUTH_TOKEN = "oauthToken";
const std::string OAUTH_TOKEN_INFOS = "tokenInfos";
const std::string OAUTH_TYPE = "authType";
const std::string OAUTH_AUTH_LIST = "authList";
const std::string OAUTH_TOKEN_TO_TYPE = "tokenToType";

const std::string HYPHEN = "#";
}  // namespace

AppAccountInfo::AppAccountInfo()
{
    owner_ = "";
    name_ = "";
    extraInfo_ = "";
    authorizedApps_.clear();
    syncEnable_ = false;
    associatedData_ = "";
    accountCredential_ = "";
    oauthTokens_.clear();
}

AppAccountInfo::AppAccountInfo(const std::string &name, const std::string &owner)
{
    name_ = name;
    owner_ = owner;

    extraInfo_ = "";
    authorizedApps_.clear();
    syncEnable_ = false;
    associatedData_ = "";
    accountCredential_ = "";
    oauthTokens_.clear();
}

ErrCode AppAccountInfo::GetOwner(std::string &owner)
{
    ACCOUNT_LOGI("enter");

    owner = owner_;

    return ERR_OK;
}

ErrCode AppAccountInfo::SetOwner(const std::string &owner)
{
    ACCOUNT_LOGI("enter");

    owner_ = owner;

    return ERR_OK;
}

ErrCode AppAccountInfo::GetName(std::string &name) const
{
    ACCOUNT_LOGI("enter");

    name = name_;

    return ERR_OK;
}

ErrCode AppAccountInfo::SetName(const std::string &name)
{
    ACCOUNT_LOGI("enter");

    name_ = name;

    return ERR_OK;
}

ErrCode AppAccountInfo::GetExtraInfo(std::string &extraInfo) const
{
    ACCOUNT_LOGI("enter");

    extraInfo = extraInfo_;

    return ERR_OK;
}

ErrCode AppAccountInfo::SetExtraInfo(const std::string &extraInfo)
{
    ACCOUNT_LOGI("enter");

    extraInfo_ = extraInfo;

    return ERR_OK;
}

ErrCode AppAccountInfo::EnableAppAccess(const std::string &authorizedApp)
{
    ACCOUNT_LOGI("enter");

    auto it = authorizedApps_.emplace(authorizedApp);
    if (!it.second) {
        return ERR_APPACCOUNT_SERVICE_ENABLE_APP_ACCESS_ALREADY_EXISTS;
    }

    return ERR_OK;
}

ErrCode AppAccountInfo::DisableAppAccess(const std::string &authorizedApp)
{
    ACCOUNT_LOGI("enter");

    auto result = authorizedApps_.erase(authorizedApp);
    ACCOUNT_LOGI("result = %{public}zu", result);
    if (result == 0) {
        return ERR_APPACCOUNT_SERVICE_DISABLE_APP_ACCESS_NOT_EXISTED;
    }

    return ERR_OK;
}

ErrCode AppAccountInfo::GetAuthorizedApps(std::set<std::string> &apps) const
{
    ACCOUNT_LOGI("enter");

    apps = authorizedApps_;

    return ERR_OK;
}

ErrCode AppAccountInfo::SetAuthorizedApps(const std::set<std::string> &apps)
{
    ACCOUNT_LOGI("enter");

    authorizedApps_ = apps;

    return ERR_OK;
}

ErrCode AppAccountInfo::GetSyncEnable(bool &syncEnable) const
{
    ACCOUNT_LOGI("enter");

    syncEnable = syncEnable_;

    return ERR_OK;
}

ErrCode AppAccountInfo::SetSyncEnable(const bool &syncEnable)
{
    ACCOUNT_LOGI("enter");

    syncEnable_ = syncEnable;

    return ERR_OK;
}

ErrCode AppAccountInfo::GetAssociatedData(const std::string &key, std::string &value) const
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("key = %{public}s, value = %{public}s", key.c_str(), value.c_str());
    ACCOUNT_LOGI("associatedData_ = %{public}s", associatedData_.c_str());

    auto jsonObject = Json::parse(associatedData_, nullptr, false);
    if (jsonObject.is_discarded()) {
        jsonObject = Json::object();
    }

    if (jsonObject.find(key) == jsonObject.end()) {
        ACCOUNT_LOGE("failed to find value, key = %{public}s", key.c_str());
        return ERR_APPACCOUNT_SERVICE_GET_ASSOCIATED_DATA;
    }

    value = jsonObject.at(key);

    ACCOUNT_LOGI("associatedData_ = %{public}s", associatedData_.c_str());

    return ERR_OK;
}

ErrCode AppAccountInfo::SetAssociatedData(const std::string &key, const std::string &value)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("key = %{public}s, value = %{public}s", key.c_str(), value.c_str());
    ACCOUNT_LOGI("associatedData_ = %{public}s", associatedData_.c_str());

    auto jsonObject = Json::parse(associatedData_, nullptr, false);
    if (jsonObject.is_discarded()) {
        jsonObject = Json::object();
    }

    auto it = jsonObject.find(key);
    if (it == jsonObject.end()) {
        jsonObject.emplace(key, value);
    } else {
        jsonObject[key] = value;
    }

    associatedData_ = jsonObject.dump();

    ACCOUNT_LOGI("associatedData_ = %{public}s", associatedData_.c_str());

    return ERR_OK;
}

ErrCode AppAccountInfo::GetAccountCredential(const std::string &credentialType, std::string &credential) const
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("credentialType = %{public}s", credentialType.c_str());
    ACCOUNT_LOGI("credential = %{public}s", credential.c_str());
    ACCOUNT_LOGI("accountCredential_ = %{public}s", accountCredential_.c_str());

    auto jsonObject = Json::parse(accountCredential_, nullptr, false);
    if (jsonObject.is_discarded()) {
        jsonObject = Json::object();
    }

    if (jsonObject.find(credentialType) == jsonObject.end()) {
        ACCOUNT_LOGE("failed to find value, credentialType = %{public}s", credentialType.c_str());
        return ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_CREDENTIAL;
    }

    credential = jsonObject.at(credentialType);

    ACCOUNT_LOGI("accountCredential_ = %{public}s", accountCredential_.c_str());

    return ERR_OK;
}

ErrCode AppAccountInfo::SetAccountCredential(const std::string &credentialType, const std::string &credential)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("credentialType = %{public}s", credentialType.c_str());
    ACCOUNT_LOGI("credential = %{public}s", credential.c_str());
    ACCOUNT_LOGI("accountCredential_ = %{public}s", accountCredential_.c_str());

    auto jsonObject = Json::parse(accountCredential_, nullptr, false);
    if (jsonObject.is_discarded()) {
        jsonObject = Json::object();
    }

    auto it = jsonObject.find(credentialType);
    if (it == jsonObject.end()) {
        jsonObject.emplace(credentialType, credential);
    } else {
        jsonObject[credentialType] = credential;
    }

    accountCredential_ = jsonObject.dump();

    ACCOUNT_LOGI("accountCredential_ = %{public}s", accountCredential_.c_str());

    return ERR_OK;
}

ErrCode AppAccountInfo::GetOAuthToken(const std::string &authType, std::string &token) const
{
    ACCOUNT_LOGI("enter");
    token = "";
    auto it = oauthTokens_.find(authType);
    if ((it == oauthTokens_.end()) || (it->second.token.empty())) {
        ACCOUNT_LOGI("oauth token not exist");
        return ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_NOT_EXIST;
    }
    token = it->second.token;
    return ERR_OK;
}

ErrCode AppAccountInfo::SetOAuthToken(const std::string &authType, const std::string &token)
{
    ACCOUNT_LOGI("enter");
    auto it = oauthTokens_.find(authType);
    if (it != oauthTokens_.end()) {
        it->second.token = token;
        return ERR_OK;
    }
    if (oauthTokens_.size() >= MAX_TOKEN_SIZE) {
        ACCOUNT_LOGE("too many types of oauth token, capacity for each account is %{public}d", MAX_TOKEN_SIZE);
        return ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_MAX_SIZE;
    }
    OAuthTokenInfo tokenInfo;
    tokenInfo.token = token;
    oauthTokens_.emplace(authType, tokenInfo);
    return ERR_OK;
}

ErrCode AppAccountInfo::DeleteOAuthToken(const std::string &authType, const std::string &token)
{
    ACCOUNT_LOGI("enter");
    auto it = oauthTokens_.find(authType);
    if ((it != oauthTokens_.end()) && (it->second.token == token)) {
        it->second.token = "";
        return ERR_OK;
    }
    return ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_NOT_EXIST;
}

ErrCode AppAccountInfo::SetOAuthTokenVisibility(
    const std::string &authType, const std::string &bundleName, bool isVisible)
{
    ACCOUNT_LOGI("enter");
    if (bundleName == owner_) {
        return ERR_OK;
    }
    auto it = oauthTokens_.find(authType);
    if (it == oauthTokens_.end()) {
        if (!isVisible) {
            return ERR_OK;
        }
        if (oauthTokens_.size() >= MAX_TOKEN_SIZE) {
            ACCOUNT_LOGE("too many types of oauth token, capacity for each account is %{public}d", MAX_TOKEN_SIZE);
            return ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_MAX_SIZE;
        }
        OAuthTokenInfo tokenInfo;
        tokenInfo.authList.emplace(bundleName);
        oauthTokens_.emplace(authType, tokenInfo);
        return ERR_OK;
    }
    if (!isVisible) {
        it->second.authList.erase(bundleName);
        return ERR_OK;
    }
    it->second.authList.emplace(bundleName);
    if (it->second.authList.size() > MAX_OAUTH_LIST_SIZE) {
        ACCOUNT_LOGE("the authorization list is too large, whose capacity for each authType is %{public}d",
            MAX_OAUTH_LIST_SIZE);
        it->second.authList.erase(bundleName);
        return ERR_APPACCOUNT_SERVICE_OAUTH_LIST_MAX_SIZE;
    }
    return ERR_OK;
}
 
ErrCode AppAccountInfo::CheckOAuthTokenVisibility(
    const std::string &authType, const std::string &bundleName, bool &isVisible) const
{
    ACCOUNT_LOGI("enter");
    isVisible = false;
    if (bundleName == owner_) {
        isVisible = true;
        return ERR_OK;
    }
    auto tokenInfoIt = oauthTokens_.find(authType);
    if (tokenInfoIt == oauthTokens_.end()) {
        return ERR_OK;
    }
    std::set<std::string> authList = tokenInfoIt->second.authList;
    auto it = authList.find(bundleName);
    if (it != authList.end()) {
        isVisible = true;
    }
    return ERR_OK;
}

ErrCode AppAccountInfo::GetAllOAuthTokens(std::vector<OAuthTokenInfo> &tokenInfos) const
{
    ACCOUNT_LOGI("enter");
    tokenInfos.clear();
    for (auto it = oauthTokens_.begin(); it != oauthTokens_.end(); ++it) {
        tokenInfos.push_back(it->second);
    }
    return ERR_OK;
}

ErrCode AppAccountInfo::GetOAuthList(const std::string &authType, std::set<std::string> &oauthList) const
{
    ACCOUNT_LOGI("enter");
    oauthList.clear();
    auto it = oauthTokens_.find(authType);
    if (it == oauthTokens_.end()) {
        return ERR_OK;
    }
    oauthList = it->second.authList;
    return ERR_OK;
}

bool AppAccountInfo::Marshalling(Parcel &parcel) const
{
    ACCOUNT_LOGI("enter");

    if (!parcel.WriteString(owner_)) {
        ACCOUNT_LOGE("failed to write string for owner_");
        return false;
    }

    if (!parcel.WriteString(name_)) {
        ACCOUNT_LOGE("failed to write string for name_");
        return false;
    }

    if (!parcel.WriteString(extraInfo_)) {
        ACCOUNT_LOGE("failed to write string for extraInfo_");
        return false;
    }

    if (!WriteStringSet(authorizedApps_, parcel)) {
        ACCOUNT_LOGE("failed to write string set for authorizedApps_");
        return false;
    }

    if (!parcel.WriteBool(syncEnable_)) {
        ACCOUNT_LOGE("failed to write bool for syncEnable_");
        return false;
    }

    if (!parcel.WriteString(associatedData_)) {
        ACCOUNT_LOGE("failed to write string for associatedData_");
        return false;
    }

    if (!parcel.WriteString(accountCredential_)) {
        ACCOUNT_LOGE("failed to write string for accountCredential_");
        return false;
    }

    if (!WriteTokenInfos(oauthTokens_, parcel)) {
        ACCOUNT_LOGE("failed to write string map for oauthTokens_");
        return false;
    }
    return true;
}

AppAccountInfo *AppAccountInfo::Unmarshalling(Parcel &parcel)
{
    ACCOUNT_LOGI("enter");

    AppAccountInfo *appAccountInfo = new (std::nothrow) AppAccountInfo();

    if (appAccountInfo && !appAccountInfo->ReadFromParcel(parcel)) {
        ACCOUNT_LOGE("failed to read from pacel");
        delete appAccountInfo;
        appAccountInfo = nullptr;
    }

    return appAccountInfo;
}

Json AppAccountInfo::ToJson() const
{
    ACCOUNT_LOGI("enter");

    auto tokenArray = Json::array();
    for (auto it = oauthTokens_.begin(); it != oauthTokens_.end(); ++it) {
        if ((it->second.token.empty()) && (it->second.authList.size() == 0)) {
            continue;
        }
        auto tokenObject = Json {
            {OAUTH_TYPE, it->first},
            {OAUTH_TOKEN, it->second.token},
            {OAUTH_AUTH_LIST, it->second.authList}
        };
        tokenArray.push_back(tokenObject);
    }
    auto jsonObject = Json {
        {OWNER, owner_},
        {NAME, name_},
        {EXTRA_INFO, extraInfo_},
        {AUTHORIZED_APPS, authorizedApps_},
        {SYNC_ENABLE, syncEnable_},
        {ASSOCIATED_DATA, associatedData_},
        {ACCOUNT_CREDENTIAL, accountCredential_},
        {OAUTH_TOKEN_INFOS, tokenArray},
    };

    return jsonObject;
}

void AppAccountInfo::ParseTokenInfosFromJson(const Json &jsonObject)
{
    ACCOUNT_LOGI("enter");
    oauthTokens_.clear();
    for (auto it = jsonObject.begin(); it != jsonObject.end(); ++it) {
        OAuthTokenInfo tokenInfo;
        if (it->find(OAUTH_TOKEN) != it->end()) {
            it->at(OAUTH_TOKEN).get_to(tokenInfo.token);
        }
        if (it->find(OAUTH_TYPE) != it->end()) {
            it->at(OAUTH_TYPE).get_to(tokenInfo.authType);
        }
        if (it->find(OAUTH_AUTH_LIST) != it->end()) {
            it->at(OAUTH_AUTH_LIST).get_to(tokenInfo.authList);
        }
        oauthTokens_.emplace(tokenInfo.authType, tokenInfo);
    }
}

void AppAccountInfo::FromJson(const Json &jsonObject)
{
    ACCOUNT_LOGI("enter");
    const auto &jsonObjectEnd = jsonObject.end();

    OHOS::AccountSA::GetDataByType<std::string>(
        jsonObject, jsonObjectEnd, OWNER, owner_, OHOS::AccountSA::JsonType::STRING);
    OHOS::AccountSA::GetDataByType<std::string>(
        jsonObject, jsonObjectEnd, NAME, name_, OHOS::AccountSA::JsonType::STRING);
    OHOS::AccountSA::GetDataByType<std::string>(
        jsonObject, jsonObjectEnd, EXTRA_INFO, extraInfo_, OHOS::AccountSA::JsonType::STRING);
    OHOS::AccountSA::GetDataByType<bool>(
        jsonObject, jsonObjectEnd, SYNC_ENABLE, syncEnable_, OHOS::AccountSA::JsonType::BOOLEAN);
    OHOS::AccountSA::GetDataByType<std::set<std::string>>(
        jsonObject, jsonObjectEnd, AUTHORIZED_APPS, authorizedApps_, OHOS::AccountSA::JsonType::ARRAY);
    OHOS::AccountSA::GetDataByType<std::string>(
        jsonObject, jsonObjectEnd, ASSOCIATED_DATA, associatedData_, OHOS::AccountSA::JsonType::STRING);
    OHOS::AccountSA::GetDataByType<std::string>(
        jsonObject, jsonObjectEnd, ACCOUNT_CREDENTIAL, accountCredential_, OHOS::AccountSA::JsonType::STRING);
    if (jsonObject.find(OAUTH_TOKEN_INFOS) != jsonObjectEnd) {
        ParseTokenInfosFromJson(jsonObject.at(OAUTH_TOKEN_INFOS));
    }
}

std::string AppAccountInfo::ToString() const
{
    ACCOUNT_LOGI("enter");

    auto jsonObject = ToJson();

    return jsonObject.dump();
}

std::string AppAccountInfo::GetPrimeKey() const
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("name_ = %{public}s, owner_ = %{public}s", name_.c_str(), owner_.c_str());

    const std::string id = owner_ + HYPHEN + name_;
    ACCOUNT_LOGI("id = %{public}s", id.c_str());

    return id;
}

bool AppAccountInfo::ReadFromParcel(Parcel &parcel)
{
    ACCOUNT_LOGI("enter");

    if (!parcel.ReadString(owner_)) {
        ACCOUNT_LOGE("failed to read string for owner_");
        return false;
    }

    if (!parcel.ReadString(name_)) {
        ACCOUNT_LOGE("failed to read string for name_");
        return false;
    }

    if (!parcel.ReadString(extraInfo_)) {
        ACCOUNT_LOGE("failed to read string for extraInfo_");
        return false;
    }

    if (!ReadStringSet(authorizedApps_, parcel)) {
        ACCOUNT_LOGE("failed to read string set for authorizedApps_");
        return false;
    }

    if (!parcel.ReadBool(syncEnable_)) {
        ACCOUNT_LOGE("failed to read string for syncEnable_");
        return false;
    }

    if (!parcel.ReadString(associatedData_)) {
        ACCOUNT_LOGE("failed to read string for associatedData_");
        return false;
    }

    if (!parcel.ReadString(accountCredential_)) {
        ACCOUNT_LOGE("failed to read string for accountCredential_");
        return false;
    }

    if (!ReadTokenInfos(oauthTokens_, parcel)) {
        ACCOUNT_LOGE("failed to read string map for oauthTokens_");
        return false;
    }
    return true;
}

bool AppAccountInfo::WriteStringSet(const std::set<std::string> &stringSet, Parcel &data) const
{
    ACCOUNT_LOGI("enter");

    if (!data.WriteUint32(stringSet.size())) {
        ACCOUNT_LOGE("failed to WriteInt32 for stringSet.size()");
        return false;
    }

    for (auto it : stringSet) {
        if (!data.WriteString(it)) {
            ACCOUNT_LOGE("failed to WriteString for it");
            return false;
        }
    }

    return true;
}

bool AppAccountInfo::ReadStringSet(std::set<std::string> &stringSet, Parcel &data)
{
    ACCOUNT_LOGI("enter");

    uint32_t size = 0;
    if (!data.ReadUint32(size)) {
        ACCOUNT_LOGE("failed to ReadInt32 for size");
        return false;
    }

    stringSet.clear();
    for (uint32_t index = 0; index < size; index += 1) {
        std::string it = data.ReadString();
        if (it.size() == 0) {
            ACCOUNT_LOGE("failed to ReadString for it");
            return false;
        }
        stringSet.emplace(it);
    }

    return true;
}

bool AppAccountInfo::WriteStringMap(const std::map<std::string, std::string> &stringMap, Parcel &data) const
{
    ACCOUNT_LOGI("enter");

    if (!data.WriteInt32(stringMap.size())) {
        ACCOUNT_LOGE("failed to WriteInt32 for stringSet.size()");
        return false;
    }

    for (auto& it : stringMap) {
        if (!data.WriteString(it.first)) {
            ACCOUNT_LOGE("failed to WriteString for authType");
            return false;
        }
        if (!data.WriteString(it.second)) {
            ACCOUNT_LOGE("failed to WriteString for token");
            return false;
        }
    }

    return true;
}

bool AppAccountInfo::WriteTokenInfos(const std::map<std::string, OAuthTokenInfo> &tokenInfos, Parcel &data) const
{
    ACCOUNT_LOGI("enter");
    if (!data.WriteInt32(tokenInfos.size())) {
        ACCOUNT_LOGE("failed to WriteInt32 for stringSet.size()");
        return false;
    }
    for (auto& it : tokenInfos) {
        if (!data.WriteString(it.first)) {
            ACCOUNT_LOGE("failed to WriteString for authType");
            return false;
        }
        if (!data.WriteString(it.second.token)) {
            ACCOUNT_LOGE("failed to WriteString for token");
            return false;
        }
        if (!WriteStringSet(it.second.authList, data)) {
            ACCOUNT_LOGE("failed to WriteString for authList");
            return false;
        }
    }
    return true;
}

bool AppAccountInfo::ReadStringMap(std::map<std::string, std::string> &stringMap, Parcel &data)
{
    ACCOUNT_LOGI("enter");

    int32_t size = 0;
    if (!data.ReadInt32(size)) {
        ACCOUNT_LOGE("failed to ReadInt32 for size");
        return false;
    }

    stringMap.clear();
    for (int32_t index = 0; index < size; ++index) {
        std::string key;
        std::string value;
        if (!data.ReadString(key)) {
            ACCOUNT_LOGE("failed to ReadString for key");
            return false;
        }
        if (!data.ReadString(value)) {
            ACCOUNT_LOGE("failed to ReadString for value");
            return false;
        }
        stringMap.emplace(key, value);
    }

    return true;
}

bool AppAccountInfo::ReadTokenInfos(std::map<std::string, OAuthTokenInfo> &tokenInfos, Parcel &data)
{
    ACCOUNT_LOGI("enter");
    int32_t size = 0;
    if (!data.ReadInt32(size)) {
        ACCOUNT_LOGE("failed to ReadInt32 for size");
        return false;
    }
    tokenInfos.clear();
    for (int32_t index = 0; index < size; ++index) {
        OAuthTokenInfo tokenInfo;
        if (!data.ReadString(tokenInfo.authType)) {
            ACCOUNT_LOGE("failed to ReadString for authType");
            return false;
        }
        if (!data.ReadString(tokenInfo.token)) {
            ACCOUNT_LOGE("failed to ReadString for token");
            return false;
        }
        if (!ReadStringSet(tokenInfo.authList, data)) {
            ACCOUNT_LOGE("failed to ReadString for authList");
            return false;
        }
        tokenInfos.emplace(tokenInfo.authType, tokenInfo);
    }
    return true;
}
}  // namespace AccountSA
}  // namespace OHOS
