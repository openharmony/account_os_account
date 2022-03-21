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

#include "app_account_data_storage.h"

#include "app_account_constants.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
const std::string AppAccountDataStorage::DATA_STORAGE_SUFFIX = "_sync";
const std::string AppAccountDataStorage::AUTHORIZED_ACCOUNTS = "authorizedAccounts";

AppAccountDataStorage::AppAccountDataStorage(const std::string &storeId, const bool &autoSync)
    : AccountDataStorage(Constants::APP_ACCOUNT_APP_ID, storeId, autoSync)
{
    ACCOUNT_LOGI("enter");
}

Json AppAccountDataStorage::GetAccessibleAccountsFromAuthorizedAccounts(const std::string &authorizedAccounts,
    const std::string &authorizedApp, std::vector<std::string> &accessibleAccounts)
{
    ACCOUNT_LOGI("enter");

    accessibleAccounts.clear();

    auto jsonObject = Json::parse(authorizedAccounts, nullptr, false);
    if (jsonObject.is_discarded()) {
        jsonObject = Json::object();
    } else {
        auto value = jsonObject.find(authorizedApp);
        if (value == jsonObject.end()) {
            jsonObject.emplace(authorizedApp, Json::array());
        } else if (value->is_array()) {
            accessibleAccounts = jsonObject[authorizedApp].get<std::vector<std::string>>();
        }
    }

    ACCOUNT_LOGI("accessibleAccounts.size() = %{public}zu", accessibleAccounts.size());
    for (auto account : accessibleAccounts) {
        ACCOUNT_LOGI("account = %{public}s", account.c_str());
    }

    return jsonObject;
}

ErrCode AppAccountDataStorage::GetAccessibleAccountsFromDataStorage(
    const std::string &authorizedApp, std::vector<std::string> &accessibleAccounts)
{
    ACCOUNT_LOGI("enter");

    std::string authorizedAccounts;
    ErrCode result = GetValueFromKvStore(AUTHORIZED_ACCOUNTS, authorizedAccounts);
    ACCOUNT_LOGI("authorizedAccounts = %{public}s", authorizedAccounts.c_str());
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get config by id from data storage");
    }

    GetAccessibleAccountsFromAuthorizedAccounts(authorizedAccounts, authorizedApp, accessibleAccounts);

    return ERR_OK;
}

ErrCode AppAccountDataStorage::GetAccountInfoFromDataStorage(AppAccountInfo &appAccountInfo)
{
    ACCOUNT_LOGI("enter");

    ErrCode result = GetAccountInfoById(appAccountInfo.GetPrimeKey(), appAccountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get account info by id, result %{public}d.", result);
        return ERR_APPACCOUNT_SERVICE_GET_ACCOUNT_INFO_BY_ID;
    }

    ACCOUNT_LOGI("appAccountInfo.GetPrimeKey() = %{public}s", appAccountInfo.GetPrimeKey().c_str());
    ACCOUNT_LOGI("end, result = %{public}d", result);

    return ERR_OK;
}

ErrCode AppAccountDataStorage::AddAccountInfoIntoDataStorage(AppAccountInfo &appAccountInfo)
{
    ACCOUNT_LOGI("enter");

    ErrCode result = AddAccountInfo(appAccountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGI("failed to add account info, result = %{public}d", result);
        return ERR_APPACCOUNT_SERVICE_ADD_ACCOUNT_INFO;
    }

    ACCOUNT_LOGI("end, result = %{public}d", result);

    return ERR_OK;
}

ErrCode AppAccountDataStorage::SaveAccountInfoIntoDataStorage(AppAccountInfo &appAccountInfo)
{
    ACCOUNT_LOGI("enter");

    ErrCode result = SaveAccountInfo(appAccountInfo);
    if (result != ERR_OK) {
        ACCOUNT_LOGI("failed to save account info, result = %{public}d", result);
        return ERR_APPACCOUNT_SERVICE_SAVE_ACCOUNT_INFO;
    }

    ACCOUNT_LOGI("end, result = %{public}d", result);

    return ERR_OK;
}

ErrCode AppAccountDataStorage::DeleteAccountInfoFromDataStorage(AppAccountInfo &appAccountInfo)
{
    ACCOUNT_LOGI("enter.");
    ErrCode ret = RemoveValueFromKvStore(appAccountInfo.GetPrimeKey());
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("RemoveValueFromKvStore failed! ret = %{public}d.", ret);
    } else {
        ACCOUNT_LOGI("RemoveValueFromKvStore succeed.");
    }
    return ret;
}

void AppAccountDataStorage::SaveEntries(
    std::vector<OHOS::DistributedKv::Entry> allEntries, std::map<std::string, std::shared_ptr<IAccountInfo>> &infos)
{
    ACCOUNT_LOGI("enter");

    for (auto const &item : allEntries) {
        Json jsonObject = Json::parse(item.value.ToString(), nullptr, false);
        if (jsonObject.is_discarded()) {
            ACCOUNT_LOGE("error key: %{private}s", item.key.ToString().c_str());
            // it's a bad json, delete it
            {
                std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
                kvStorePtr_->Delete(item.key);
            }
            continue;
        }

        AppAccountInfo appAccountInfo;
        appAccountInfo.FromJson(jsonObject);
        infos.emplace(item.key.ToString(), std::make_shared<AppAccountInfo>(appAccountInfo));
    }
}
}  // namespace AccountSA
}  // namespace OHOS