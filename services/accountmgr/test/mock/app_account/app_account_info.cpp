/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "app_account_info_error.h"
#include "app_account_info_json_parser.h"
#include "account_log_wrapper.h"
#include "account_hisysevent_adapter.h"
#ifdef HAS_ASSET_PART
#include <iomanip>
#include <sstream>
#include <openssl/sha.h>
#endif

namespace OHOS {
namespace AccountSA {

bool OAuthTokenInfo::Marshalling(Parcel &parcel) const
{
    return true;
}

OAuthTokenInfo *OAuthTokenInfo::Unmarshalling(Parcel &parcel)
{
    OAuthTokenInfo *info = new (std::nothrow) OAuthTokenInfo();
    if ((info != nullptr) && (!info->ReadFromParcel(parcel))) {
        ACCOUNT_LOGW("ReadFromParcel failed, please check paecel data");
        delete info;
        info = nullptr;
    }
    return info;
}

bool OAuthTokenInfo::ReadFromParcel(Parcel &parcel)
{
    return true;
}

bool AppAccountStringInfo::ReadFromParcel(Parcel &parcel)
{
    return true;
}

bool AppAccountStringInfo::Marshalling(Parcel &parcel) const
{
    return true;
}

AppAccountStringInfo* AppAccountStringInfo::Unmarshalling(Parcel &parcel)
{
    AppAccountStringInfo *info = new (std::nothrow) AppAccountStringInfo();
    if ((info != nullptr) && (!info->ReadFromParcel(parcel))) {
        ACCOUNT_LOGW("ReadFromParcel failed, please check paecel data");
        delete info;
        info = nullptr;
    }
    return info;
}

AppAccountAuthenticatorStringInfo::AppAccountAuthenticatorStringInfo(
    std::string name, std::string authType, std::string callerBundleName)
    : name(name), authType(authType), callerBundleName(callerBundleName)
{}

bool AppAccountAuthenticatorStringInfo::ReadFromParcel(Parcel &parcel)
{
    return true;
}

bool AppAccountAuthenticatorStringInfo::Marshalling(Parcel &parcel) const
{
    return true;
}

AppAccountAuthenticatorStringInfo* AppAccountAuthenticatorStringInfo::Unmarshalling(Parcel &parcel)
{
    AppAccountAuthenticatorStringInfo *info = new (std::nothrow) AppAccountAuthenticatorStringInfo();
    if ((info != nullptr) && (!info->ReadFromParcel(parcel))) {
        ACCOUNT_LOGW("ReadFromParcel failed, please check paecel data");
        delete info;
        info = nullptr;
    }
    return info;
}

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
    alias_ = "";
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
    alias_ = "";
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
    alias_ = "";
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
    alias_ = "";
}

uint32_t AppAccountInfo::GetAppIndex()
{
    return appIndex_;
}

void AppAccountInfo::SetAppIndex(const uint32_t &appIndex)
{
    appIndex_ = appIndex;
    alias_ = "";
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
    if (authorizedApps_.size() > MAX_APP_AUTH_LIST_SIZE) {
        authorizedApps_.erase(authorizedApp);
        return ERR_APPACCOUNT_SERVICE_OAUTH_LIST_MAX_SIZE;
    }
    return ERR_OK;
}

ErrCode AppAccountInfo::DisableAppAccess(const std::string &authorizedApp, const uint32_t apiVersion)
{
    return ERR_OK;
}

ErrCode AppAccountInfo::CheckAppAccess(const std::string &authorizedApp, bool &isAccessible)
{
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
    if (data.empty()) {
        return ERR_ACCOUNTDATASTORAGE_FAILED;
    }
    return ERR_OK;
}

ErrCode AppAccountInfo::GetAllAssociatedData(std::map<std::string, std::string> &data) const
{
    return ERR_OK;
}

ErrCode AppAccountInfo::GetAssociatedData(const std::string &key, std::string &value) const
{
    return ERR_OK;
}

ErrCode AppAccountInfo::SetAssociatedData(const std::string &key, const std::string &value)
{
    if (key == "") {
        return ERR_ACCOUNTDATASTORAGE_FAILED;
    }
    return ERR_OK;
}

ErrCode AppAccountInfo::GetAccountCredential(const std::string &credentialType, std::string &credential) const
{
    return ERR_OK;
}

ErrCode AppAccountInfo::SetAccountCredential(
    const std::string &credentialType, const std::string &credential)
{
    if (credentialType == "") {
        return ERR_ACCOUNTDATASTORAGE_FAILED;
    }
    return ERR_OK;
}

ErrCode AppAccountInfo::DeleteAccountCredential(const std::string &credentialType)
{
    if (credentialType == "") {
        return ERR_ACCOUNTDATASTORAGE_FAILED;
    }
    return ERR_OK;
}

ErrCode AppAccountInfo::GetOAuthToken(const std::string &authType, std::string &token, const uint32_t apiVersion) const
{
    if (apiVersion == 0) {
        return ERR_ACCOUNTDATASTORAGE_FAILED;
    }
    return ERR_OK;
}

ErrCode AppAccountInfo::SetOAuthToken(const std::string &authType, const std::string &token)
{
    if (authType == "") {
        return ERR_ACCOUNTDATASTORAGE_FAILED;
    }
    return ERR_OK;
}

ErrCode AppAccountInfo::DeleteOAuthToken(const std::string &authType, const std::string &token)
{
    if (authType == "") {
        return ERR_ACCOUNTDATASTORAGE_FAILED;
    }
    return ERR_APPACCOUNT_SERVICE_OAUTH_TOKEN_NOT_EXIST;
}

ErrCode AppAccountInfo::DeleteAuthToken(const std::string &authType, const std::string &token, bool isOwnerSelf)
{
    if (authType == "") {
        return ERR_ACCOUNTDATASTORAGE_FAILED;
    }
    return ERR_OK;
}

ErrCode AppAccountInfo::SetOAuthTokenVisibility(
    const std::string &authType, const std::string &bundleName, bool isVisible, const uint32_t apiVersion)
{
    return ERR_OK;
}

ErrCode AppAccountInfo::CheckOAuthTokenVisibility(
    const std::string &authType, const std::string &bundleName, bool &isVisible, const uint32_t apiVersion) const
{
    if (apiVersion == 0) {
        return ERR_ACCOUNTDATASTORAGE_FAILED;
    }
    if (apiVersion == 1) {
        isVisible = false;
        return ERR_ACCOUNTDATASTORAGE_FAILED;
    }
    isVisible = true;
    return ERR_OK;
}

ErrCode AppAccountInfo::GetAllOAuthTokens(std::vector<OAuthTokenInfo> &tokenInfos) const
{
    return ERR_ACCOUNTDATASTORAGE_FAILED;
}

ErrCode AppAccountInfo::GetOAuthList(
    const std::string &authType, std::set<std::string> &oauthList, const uint32_t apiVersion) const
{
    return ERR_OK;
}

bool AppAccountInfo::Marshalling(Parcel &parcel) const
{
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

std::string AppAccountInfo::ToString() const
{
    auto jsonObject = ToJson(*this);
    std::string strValue = PackJsonToString(jsonObject);
    if (strValue.empty()) {
        ACCOUNT_LOGE("failed to dump json object");
        return "";
    }
    return strValue;
}

std::string AppAccountInfo::GetPrimeKey() const
{
    return (owner_ + HYPHEN + std::to_string(appIndex_) + HYPHEN + name_ + HYPHEN);
}

std::string AppAccountInfo::GetAlias()
{
    return alias_;
}

bool AppAccountInfo::ReadFromParcel(Parcel &parcel)
{
    return true;
}

bool AppAccountInfo::WriteStringSet(const std::set<std::string> &stringSet, Parcel &data) const
{
    return true;
}

bool AppAccountInfo::ReadStringSet(std::set<std::string> &stringSet, Parcel &data)
{
    return true;
}

bool AppAccountInfo::WriteStringMap(const std::map<std::string, std::string> &stringMap, Parcel &data) const
{
    return true;
}

bool AppAccountInfo::WriteTokenInfos(const std::map<std::string, OAuthTokenInfo> &tokenInfos, Parcel &data) const
{
    return true;
}

bool AppAccountInfo::ReadStringMap(std::map<std::string, std::string> &stringMap, Parcel &data)
{
    return true;
}

bool AppAccountInfo::ReadTokenInfos(std::map<std::string, OAuthTokenInfo> &tokenInfos, Parcel &data)
{
    return true;
}
}  // namespace AccountSA
}  // namespace OHOS
