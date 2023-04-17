/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "app_account_info.h"

#include "account_log_wrapper.h"
#include "nlohmann/json.hpp"

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
constexpr uint32_t APP_INDEX = 0;
constexpr uint32_t MAX_TOKEN_NUMBER = 128;
constexpr uint32_t MAX_OAUTH_LIST_SIZE = 512;
constexpr uint32_t MAX_ASSOCIATED_DATA_NUMBER = 1024;
}  // namespace

AppAccountInfo::AppAccountInfo()
{
    owner_ = "";
    name_ = "";
    appIndex_ = APP_INDEX;
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
    appIndex_ = APP_INDEX;
    extraInfo_ = "";
    authorizedApps_.clear();
    syncEnable_ = false;
    associatedData_ = "";
    accountCredential_ = "";
    oauthTokens_.clear();
}

std::string AppAccountInfo::GetOwner()
{
    return owner_;
}

void AppAccountInfo::GetOwner(std::string &owner)
{
    owner = owner_;
}

void AppAccountInfo::SetOwner(const std::string &owner)
{
    owner_ = owner;
}

std::string AppAccountInfo::GetName()
{
    return name_;
}

void AppAccountInfo::GetName(std::string &name) const
{
    name = name_;
}

void AppAccountInfo::SetName(const std::string &name)
{
    name_ = name;
}

uint32_t AppAccountInfo::GetAppIndex()
{
    return appIndex_;
}

void AppAccountInfo::SetAppIndex(const uint32_t &appIndex)
{
    appIndex_ = appIndex;
}

void AppAccountInfo::GetExtraInfo(std::string &extraInfo) const
{
    extraInfo = extraInfo_;
}

void AppAccountInfo::SetExtraInfo(const std::string &extraInfo)
{
    extraInfo_ = extraInfo;
}

ErrCode AppAccountInfo::EnableAppAccess(const std::string &authorizedApp, const uint32_t apiVersion)
{
    auto it = authorizedApps_.emplace(authorizedApp);
    if (!it.second && apiVersion < Constants::API_VERSION9) {
        return ERR_APPACCOUNT_SERVICE_ENABLE_APP_ACCESS_ALREADY_EXISTS;
    }
    return ERR_OK;
}

ErrCode AppAccountInfo::DisableAppAccess(const std::string &authorizedApp, const uint32_t apiVersion)
{
    auto result = authorizedApps_.erase(authorizedApp);
    if (result == 0 && apiVersion < Constants::API_VERSION9) {
        return ERR_APPACCOUNT_SERVICE_DISABLE_APP_ACCESS_NOT_EXISTED;
    }
    return ERR_OK;
}

ErrCode AppAccountInfo::CheckAppAccess(const std::string &authorizedApp, bool &isAccessible)
{
    isAccessible = false;
    auto it = authorizedApps_.find(authorizedApp);
    if (it != authorizedApps_.end()) {
        isAccessible = true;
    }
    return ERR_OK;
}

void AppAccountInfo::GetAuthorizedApps(std::set<std::string> &apps) const
{
    apps = authorizedApps_;
}

void AppAccountInfo::SetAuthorizedApps(const std::set<std::string> &apps)
{
    authorizedApps_ = apps;
}

void AppAccountInfo::GetSyncEnable(bool &syncEnable) const
{
    syncEnable = syncEnable_;
}

void AppAccountInfo::SetSyncEnable(const bool &syncEnable)
{
    syncEnable_ = syncEnable;
}

ErrCode AppAccountInfo::InitCustomData(const std::map<std::string, std::string> &data)
{
    Json jsonObject = data;
    try {
        associatedData_ = jsonObject.dump();
    } catch (Json::type_error& err) {
        ACCOUNT_LOGE("failed to dump json object, reason: %{public}s", err.what());
        return ERR_ACCOUNT_COMMON_DUMP_JSON_ERROR;
    }
    return ERR_OK;
}

ErrCode AppAccountInfo::GetAllAssociatedData(std::map<std::string, std::string> &data) const
{
    auto jsonObject = Json::parse(associatedData_, nullptr, false);
    if (!jsonObject.is_object()) {
        ACCOUNT_LOGE("jsonObject is_discarded");
        return ERR_APPACCOUNT_SERVICE_GET_ASSOCIATED_DATA;
    }
    try {
        data = jsonObject.get<std::map<std::string, std::string>>();
    }  catch (Json::type_error& err) {
        ACCOUNT_LOGE("failed to convert json object to map, reason: %{public}s", err.what());
        return ERR_APPACCOUNT_SERVICE_GET_ASSOCIATED_DATA;
    }
    return ERR_OK;
}

ErrCode AppAccountInfo::GetAssociatedData(const std::string &key, std::string &value) const
{
    auto jsonObject = Json::parse(associatedData_, nullptr, false);
    if (jsonObject.is_discarded()) {
        ACCOUNT_LOGI("jsonObject is_discarded");
        jsonObject = Json::object();
    }

    if (jsonObject.find(key) == jsonObject.end()) {
        ACCOUNT_LOGE("failed to find value, key = %{public}s", key.c_str());
        return ERR_APPACCOUNT_SERVICE_ASSOCIATED_DATA_KEY_NOT_EXIST;
    }

    value = jsonObject.at(key);
    return ERR_OK;
}

ErrCode AppAccountInfo::SetAssociatedData(const std::string &key, const std::string &value)
{
    auto jsonObject = Json::parse(associatedData_, nullptr, false);
    if (jsonObject.is_discarded() || (!jsonObject.is_object())) {
        ACCOUNT_LOGI("jsonObject is discarded");
        jsonObject = Json::object();
    }
    auto it = jsonObject.find(key);
    if (it == jsonObject.end()) {
        if (jsonObject.size() >= MAX_ASSOCIATED_DATA_NUMBER) {
            ACCOUNT_LOGW("associated data is over size, the max number is: %{public}d", MAX_ASSOCIATED_DATA_NUMBER);
            return ERR_APPACCOUNT_SERVICE_ASSOCIATED_DATA_OVER_SIZE;
        }
        jsonObject.emplace(key, value);
    } else {
        jsonObject[key] = value;
    }

    try {
        associatedData_ = jsonObject.dump();
    } catch (Json::type_error& err) {
        ACCOUNT_LOGE("failed to dump json object, reason: %{public}s", err.what());
        return ERR_ACCOUNT_COMMON_DUMP_JSON_ERROR;
    }
    return ERR_OK;
}

ErrCode AppAccountInfo::GetAccountCredential(const std::string &credentialType, std::string &credential) const
{
    auto jsonObject = Json::parse(accountCredential_, nullptr, false);
    if (jsonObject.is_discarded()) {
        jsonObject = Json::object();
    }

    if (jsonObject.find(credentialType) == jsonObject.end()) {
        ACCOUNT_LOGE("failed to find value, credentialType = %{public}s", credentialType.c_str());
        return ERR_APPACCOUNT_SERVICE_ACCOUNT_CREDENTIAL_NOT_EXIST;
    }

    credential = jsonObject.at(credentialType);
    return ERR_OK;
}

ErrCode AppAccountInfo::SetAccountCredential(
    const std::string &credentialType, const std::string &credential, bool isDelete)
{
    auto jsonObject = Json::parse(accountCredential_, nullptr, false);
    if (jsonObject.is_discarded() || (!jsonObject.is_object())) {
        ACCOUNT_LOGI("jsonObject is discarded");
        jsonObject = Json::object();
    }

    if (isDelete) {
        auto ret = jsonObject.erase(credentialType);
        if (ret == 0) {
            return ERR_APPACCOUNT_SERVICE_ACCOUNT_CREDENTIAL_NOT_EXIST;
        }
    } else {
        jsonObject[credentialType] = credential;
    }

    try {
        accountCredential_ = jsonObject.dump();
    } catch (Json::type_error& err) {
        ACCOUNT_LOGE("failed to dump json object, reason: %{public}s", err.what());
        return ERR_ACCOUNT_COMMON_DUMP_JSON_ERROR;
    }
    return ERR_OK;
}

ErrCode AppAccountInfo::GetOAuthToken(const std::string &authType, std::string &token, const uint32_t apiVersion) const
{
    token = "";
    auto it = oauthTokens_.find(authType);
    if (apiVersion >= Constants::API_VERSION9) {
        if ((it == oauthTokens_.end()) || (!it->second.status)) {
            ACCOUNT_LOGE("oauth token not exist");
            return ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_NOT_EXIST;
        }
    } else {
        if ((it == oauthTokens_.end()) || (it->second.token.empty())) {
            ACCOUNT_LOGE("oauth token not exist");
            return ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_NOT_EXIST;
        }
    }
    token = it->second.token;
    return ERR_OK;
}

ErrCode AppAccountInfo::SetOAuthToken(const std::string &authType, const std::string &token)
{
    auto it = oauthTokens_.find(authType);
    if (it != oauthTokens_.end()) {
        it->second.token = token;
        return ERR_OK;
    }
    if (oauthTokens_.size() >= MAX_TOKEN_NUMBER) {
        ACCOUNT_LOGE("too many types of oauth token, capacity for each account is %{public}d", MAX_TOKEN_NUMBER);
        return ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_MAX_SIZE;
    }
    OAuthTokenInfo tokenInfo;
    tokenInfo.token = token;
    oauthTokens_.emplace(authType, tokenInfo);
    return ERR_OK;
}

ErrCode AppAccountInfo::DeleteOAuthToken(const std::string &authType, const std::string &token)
{
    auto it = oauthTokens_.find(authType);
    if ((it != oauthTokens_.end()) && (it->second.token == token)) {
        it->second.token = "";
        return ERR_OK;
    }
    return ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_NOT_EXIST;
}

ErrCode AppAccountInfo::DeleteAuthToken(const std::string &authType, const std::string &token, bool isOwnerSelf)
{
    auto it = oauthTokens_.find(authType);
    if (it == oauthTokens_.end()) {
        return ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_NOT_EXIST;
    }
    if (it->second.token == token && isOwnerSelf) {
        oauthTokens_.erase(it);
    } else {
        it->second.status = false;
    }
    return ERR_OK;
}

ErrCode AppAccountInfo::SetOAuthTokenVisibility(
    const std::string &authType, const std::string &bundleName, bool isVisible, const uint32_t apiVersion)
{
    if (bundleName == owner_) {
        return ERR_OK;
    }
    auto it = oauthTokens_.find(authType);
    if (it == oauthTokens_.end()) {
        if (apiVersion >= Constants::API_VERSION9) {
            return ERR_APPACCOUNT_SERVICE_OAUTH_TYPE_NOT_EXIST;
        }
        if (!isVisible) {
            return ERR_OK;
        }
        if (oauthTokens_.size() >= MAX_TOKEN_NUMBER) {
            ACCOUNT_LOGE("too many types of oauth token, capacity for each account is %{public}d", MAX_TOKEN_NUMBER);
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
    const std::string &authType, const std::string &bundleName, bool &isVisible, const uint32_t apiVersion) const
{
    isVisible = false;
    if (bundleName == owner_) {
        isVisible = true;
        return ERR_OK;
    }
    auto tokenInfoIt = oauthTokens_.find(authType);
    if (tokenInfoIt == oauthTokens_.end()) {
        if (apiVersion >= Constants::API_VERSION9) {
            return ERR_APPACCOUNT_SERVICE_OAUTH_TYPE_NOT_EXIST;
        } else {
            return ERR_OK;
        }
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
    tokenInfos.clear();
    for (auto it = oauthTokens_.begin(); it != oauthTokens_.end(); ++it) {
        tokenInfos.push_back(it->second);
    }
    return ERR_OK;
}

ErrCode AppAccountInfo::GetOAuthList(
    const std::string &authType, std::set<std::string> &oauthList, const uint32_t apiVersion) const
{
    oauthList.clear();
    auto it = oauthTokens_.find(authType);
    if (it == oauthTokens_.end()) {
        if (apiVersion >= Constants::API_VERSION9) {
            return ERR_APPACCOUNT_SERVICE_OAUTH_TYPE_NOT_EXIST;
        } else {
            return ERR_OK;
        }
    }
    oauthList = it->second.authList;
    return ERR_OK;
}

bool AppAccountInfo::Marshalling(Parcel &parcel) const
{
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
    AppAccountInfo *appAccountInfo = new (std::nothrow) AppAccountInfo();

    if ((appAccountInfo != nullptr) && (!appAccountInfo->ReadFromParcel(parcel))) {
        ACCOUNT_LOGE("failed to read from parcel");
        delete appAccountInfo;
        appAccountInfo = nullptr;
    }

    return appAccountInfo;
}

Json AppAccountInfo::ToJson() const
{
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
    auto jsonObject = ToJson();
    try {
        return jsonObject.dump();
    } catch (Json::type_error& err) {
        ACCOUNT_LOGE("failed to dump json object, reason: %{public}s", err.what());
        return "";
    }
}

std::string AppAccountInfo::GetPrimeKey() const
{
    return (owner_ + HYPHEN + std::to_string(appIndex_) + HYPHEN + name_ + HYPHEN);
}

bool AppAccountInfo::ReadFromParcel(Parcel &parcel)
{
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
    if (!data.WriteUint32(tokenInfos.size())) {
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
    uint32_t size = 0;
    if (!data.ReadUint32(size)) {
        ACCOUNT_LOGE("failed to ReadInt32 for size");
        return false;
    }
    if (size > MAX_TOKEN_NUMBER) {
        ACCOUNT_LOGE("invalid token number");
        return false;
    }
    tokenInfos.clear();
    for (uint32_t index = 0; index < size; ++index) {
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
