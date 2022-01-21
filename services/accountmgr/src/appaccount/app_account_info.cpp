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
    oauthToken_ = "";
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
    oauthToken_ = "";
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

ErrCode AppAccountInfo::GetOAuthToken(std::string &token) const
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("token = %{public}s", token.c_str());

    token = oauthToken_;

    return ERR_OK;
}

ErrCode AppAccountInfo::SetOAuthToken(const std::string &token)
{
    ACCOUNT_LOGI("enter");

    ACCOUNT_LOGI("token = %{public}s", token.c_str());

    oauthToken_ = token;

    return ERR_OK;
}

ErrCode AppAccountInfo::ClearOAuthToken(void)
{
    ACCOUNT_LOGI("enter");

    oauthToken_.clear();

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

    auto jsonObject = Json {
        {OWNER, owner_},
        {NAME, name_},
        {EXTRA_INFO, extraInfo_},
        {AUTHORIZED_APPS, authorizedApps_},
        {SYNC_ENABLE, syncEnable_},
        {ASSOCIATED_DATA, associatedData_},
        {ACCOUNT_CREDENTIAL, accountCredential_},
    };

    return jsonObject;
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
    OHOS::AccountSA::GetDataByType<std::string>(
        jsonObject, jsonObjectEnd, OAUTH_TOKEN, oauthToken_, OHOS::AccountSA::JsonType::STRING);
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
}  // namespace AccountSA
}  // namespace OHOS
