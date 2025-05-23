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

struct OAuthTokenInfo {
    std::string authType;
    std::string token;
    std::set<std::string> authList;
    bool status = true;
};
class AccountInfoMOCK : public IAccountInfo {
private:
    std::string name;
    std::string primeKey;

public:
    AccountInfoMOCK(const std::string &name, const std::string &key) : name(name), primeKey(key)
    {}

    Json ToJson() const override
    {
        ACCOUNT_LOGI("mock enter");
        auto tokenArray = Json::array();
        for (auto it = oauthTokens_.begin(); it != oauthTokens_.end(); ++it) {
            if (!it->second.status && it->second.authList.empty()) {
                continue;
            }
            auto tokenObject = Json {
                {"authType", it->first},
                {"oauthToken", it->second.token},
                {"status", it->second.status},
                {"authList", it->second.authList}
            };
            tokenArray.push_back(tokenObject);
        }
        auto jsonObject = Json {
            {"owner", owner_},
            {"name", name_},
            {"alias", alias_},
            {"extraInfo", extraInfo_},
            {"authorizedApps", authorizedApps_},
            {"syncEnable", syncEnable_},
            {"associatedData", associatedData_},
            {"accountCredential", accountCredential_},
            {"tokenInfos", tokenArray},
        };
        return jsonObject;
    }

    bool FromJson(const Json &jsonObject) override
    {
        ACCOUNT_LOGI("mock enter");
        name = jsonObject["name"];
        primeKey = jsonObject["primeKey"];
        return true;
    }
  
    std::string ToString() const override
    {
        ACCOUNT_LOGI("mock enter");
        auto jsonObject = ToJson();
        try {
            return jsonObject.dump();
        } catch (Json::type_error& err) {
            ACCOUNT_LOGE("failed to dump json object, reason: %{public}s", err.what());
            return "";
        }
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

ErrCode AccountDataStorage::GetAccountInfoById(const std::string id, IAccountInfo &iAccountInfo)
{
    ACCOUNT_LOGI("mock enter,id = %{public}s", id.c_str());
    if (id != "com.example.ownermax#0#name#") {
        AccountInfoMOCK appAccountInfo("name", "key");
        appAccountInfo.SetOAuthToken("test_authType1", "test_authToken1");

        Json mkckJson = appAccountInfo.ToJson();
        iAccountInfo.FromJson(mkckJson);
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
