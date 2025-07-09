/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "account_data_storage.h"
#include <memory>
#include <unistd.h>
#include "account_log_wrapper.h"
#include "account_hisysevent_adapter.h"
#include "app_account_info_json_parser.h"
#include "json_utils.h"

namespace OHOS {
namespace AccountSA {

AccountDataStorage::AccountDataStorage(const std::string &appId, const std::string &storeId,
    const AccountDataStorageOptions &options)
{
    ACCOUNT_LOGI("mock enter");
}

AccountDataStorage::~AccountDataStorage()
{
    ACCOUNT_LOGI("mock enter");
}

void AccountDataStorage::TryTwice(const std::function<DistributedKv::Status()> &func) const
{
    ACCOUNT_LOGI("mock enter");
}

OHOS::DistributedKv::Status AccountDataStorage::GetKvStore()
{
    ACCOUNT_LOGI("mock enter");
    return OHOS::DistributedKv::Status::SUCCESS;
}

bool AccountDataStorage::CheckKvStore()
{
    ACCOUNT_LOGI("mock enter");
    return true;
}

ErrCode AccountDataStorage::LoadAllData(std::map<std::string, std::shared_ptr<IAccountInfo>> &infos)
{
    ACCOUNT_LOGI("mock enter");
    return ERR_OK;
}

ErrCode AccountDataStorage::AddAccountInfo(const IAccountInfo &iAccountInfo)
{
    ACCOUNT_LOGI("mock enter");
    return ERR_OK;
}

ErrCode AccountDataStorage::SaveAccountInfo(const IAccountInfo &iAccountInfo)
{
    ACCOUNT_LOGI("mock enter");
    return ERR_OK;
}

ErrCode AccountDataStorage::RemoveValueFromKvStore(const std::string &keyStr)
{
    ACCOUNT_LOGI("mock enter");
    return ERR_OK;
}

OHOS::DistributedKv::Status AccountDataStorage::GetEntries(
    std::string subId, std::vector<OHOS::DistributedKv::Entry> &allEntries) const
{
    ACCOUNT_LOGI("mock enter");
    return OHOS::DistributedKv::Status::SUCCESS;
}

ErrCode AccountDataStorage::Close()
{
    ACCOUNT_LOGI("mock enter");
    return ERR_OK;
}

ErrCode AccountDataStorage::DeleteKvStore()
{
    ACCOUNT_LOGI("mock enter");
    return ERR_OK;
}

ErrCode AccountDataStorage::StartTransaction()
{
    ACCOUNT_LOGI("mock enter");
    return ERR_OK;
}

ErrCode AccountDataStorage::Commit()
{
    ACCOUNT_LOGI("mock enter");
    return ERR_OK;
}

ErrCode AccountDataStorage::Rollback()
{
    ACCOUNT_LOGI("mock enter");
    return ERR_OK;
}

class AccountInfoMOCK : public IAccountInfo {
private:
    std::string name;
    std::string primeKey;

public:
    AccountInfoMOCK(const std::string &name, const std::string &key) : name(name), primeKey(key)
    {}

    CJsonUnique ToJson() const
    {
        ACCOUNT_LOGI("mock enter");
        auto tokenArray = CreateJsonArray();
        for (auto it = oauthTokens_.begin(); it != oauthTokens_.end(); ++it) {
            if (!it->second.status && it->second.authList.empty()) {
                continue;
            }
            auto tokenObject = CreateJson();
            AddStringToJson(tokenObject, "authType", it->first);
            AddStringToJson(tokenObject, "oauthToken", it->second.token);
            AddBoolToJson(tokenObject, "status", it->second.status);
            AddSetStringToJson(tokenObject, "authList", it->second.authList);
            AddObjToArray(tokenArray, tokenObject);
        }
        auto jsonObject = CreateJson();
        AddStringToJson(jsonObject, "owner", owner_);
        AddStringToJson(jsonObject, "name", name_);
        AddStringToJson(jsonObject, "alias", alias_);
        AddStringToJson(jsonObject, "extraInfo", extraInfo_);
        AddSetStringToJson(jsonObject, "authorizedApps", authorizedApps_);
        AddBoolToJson(jsonObject, "syncEnable", syncEnable_);
        AddStringToJson(jsonObject, "associatedData", associatedData_);
        AddStringToJson(jsonObject, "accountCredential", accountCredential_);
        AddObjToJson(jsonObject, "tokenInfos", tokenArray);
        return jsonObject;
    }

    void ParseTokenInfosFromJson(const cJSON *jsonObject, AppAccountInfo &accountInfo)
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

    std::string ToString() const override
    {
        ACCOUNT_LOGI("mock enter");
        auto jsonObject = ToJson();
        if (jsonObject == nullptr) {
            ACCOUNT_LOGE("failed to create json object");
            return "";
        }
        std::string jsonString = PackJsonToString(jsonObject);
        if (jsonString.empty()) {
            ACCOUNT_LOGE("failed to dump json object");
            return "";
        }
        return jsonString;
    }

    std::string GetPrimeKey() const override
    {
        ACCOUNT_LOGI("mock enter");
        return (owner_ + "#" + std::to_string(appIndex_) + "#" + name_ + "#");
    }
    ErrCode SetOAuthToken(const std::string &authType, const std::string &token)
    {
        ACCOUNT_LOGI("mock enter");
        OAuthTokenInfo tokenInfo;
        tokenInfo.status = !token.empty();
        tokenInfo.token = token;
        tokenInfo.authType = authType;
        tokenInfo.authList.emplace("bundlename");
        oauthTokens_.emplace(authType, tokenInfo);
        return ERR_OK;
    }
    virtual ~AccountInfoMOCK() {}

    std::string owner_;
    std::string name_;
    std::string alias_;
    uint32_t appIndex_ = 0;
    std::string extraInfo_;
    std::set<std::string> authorizedApps_;
    bool syncEnable_ = false;
    std::string associatedData_;
    std::string accountCredential_;
    std::map<std::string, OAuthTokenInfo> oauthTokens_;
};

ErrCode AccountDataStorage::GetAccountInfoById(const std::string id, AppAccountInfo &accountInfo)
{
    ACCOUNT_LOGI("mock enter,id = %{public}s", id.c_str());
    if (id != "com.example.ownermax#0#name#") {
        AccountInfoMOCK appAccountInfo("name", "key");
        appAccountInfo.SetOAuthToken("test_authType1", "test_authToken1");

        auto mkckJson = appAccountInfo.ToJson();
        appAccountInfo.FromJson(mkckJson.get(), accountInfo);
        return ERR_OK;
    } else {
        return ERR_APPACCOUNT_SERVICE_DATA_STORAGE_PTR_IS_NULLPTR;
    }
}

ErrCode AccountDataStorage::LoadDataByLocalFuzzyQuery(
    std::string subId, std::map<std::string, std::shared_ptr<IAccountInfo>> &infos)
{
    ACCOUNT_LOGI("mock enter");
    if (subId == "com.example.ownermax#0") {
        for (int i = 0; i < 1002; ++i) { // 1002 is the maximum number created
            std::string accountKey = "Account" + std::to_string(i);
            infos[accountKey] = std::make_shared<AccountInfoMOCK>(accountKey + "name", accountKey + "kkk");
        }
        return ERR_OK;
    } else {
        return ERR_OK;
    }
}

ErrCode AccountDataStorage::PutValueToKvStore(const std::string &keyStr, const std::string &valueStr)
{
    ACCOUNT_LOGI("mock enter");
    return ERR_OK;
}

ErrCode AccountDataStorage::GetValueFromKvStore(const std::string &keyStr, std::string &valueStr)
{
    ACCOUNT_LOGI("mock enter");
    valueStr = "{\"name\":[\"com.example.ownermax#0#name#\", \"bbbbb\"]}";
    return ERR_OK;
}

bool AccountDataStorage::IsKeyExists(const std::string keyStr)
{
    ACCOUNT_LOGI("mock enter");
    return true;
}

ErrCode AccountDataStorage::MoveData(const std::shared_ptr<AccountDataStorage> &ptr)
{
    ACCOUNT_LOGI("mock enter");
    return ERR_OK;
}

ErrCode StartDbTransaction(
    const std::shared_ptr<AccountDataStorage> &dataStoragePtr, DatabaseTransaction &dbtransaction)
{
    return ERR_OK;
}

ErrCode CommitDbTransaction(
    const std::shared_ptr<AccountDataStorage> &dataStoragePtr, DatabaseTransaction &dbtransaction)
{
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS
