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

#include "ohos_account_data_deal.h"
#include <fstream>
#include <iostream>
#include <vector>
#include "account_error_no.h"
#include "account_info.h"
#include "account_log_wrapper.h"
#include "directory_ex.h"
#include "file_ex.h"

namespace OHOS {
namespace AccountSA {
OhosAccountDataDeal::OhosAccountDataDeal(const std::string &configFile) : configFile_(configFile)
{
    initOk_ = false;
}

ErrCode OhosAccountDataDeal::Init()
{
    if (!FileExists(configFile_)) {
        ACCOUNT_LOGI("file %{public}s not exist, create!", configFile_.c_str());
        BuildJsonFileFromScratch();
    }

    std::ifstream fin(configFile_);
    if (!fin) {
        ACCOUNT_LOGE("Failed to open file %{public}s", configFile_.c_str());
        return ERR_ACCOUNT_DATADEAL_INPUT_FILE_ERROR;
    }

    // NOT-allow exceptions when parse json file
    nlohmann::json jsonData = json::parse(fin, nullptr, false);
    if (!jsonData.is_structured()) {
        ACCOUNT_LOGE("Invalid json file, remove");
        fin.close();
        if (RemoveFile(configFile_)) {
            ACCOUNT_LOGE("Remove invalid json file failed");
        }
        return ERR_ACCOUNT_DATADEAL_JSON_FILE_CORRUPTION;
    }

    // jsonData_ keeps well-structured json key-values
    jsonData_ = jsonData;
    initOk_ = true;
    fin.close();
    return ERR_OK;
}

ErrCode OhosAccountDataDeal::AccountInfoFromJson(AccountInfo &accountInfo)
{
    if (!initOk_) {
        return ERR_ACCOUNT_DATADEAL_NOT_READY;
    }

    const auto &jsonObjectEnd = jsonData_.end();
    if (jsonData_.find(DATADEAL_JSON_KEY_ACCOUNT_NAME) != jsonObjectEnd) {
        accountInfo.ohosAccountName_ = jsonData_.at(DATADEAL_JSON_KEY_ACCOUNT_NAME).get<std::string>();
    }

    if (jsonData_.find(DATADEAL_JSON_KEY_OPENID) != jsonObjectEnd) {
        accountInfo.ohosAccountUid_ = jsonData_.at(DATADEAL_JSON_KEY_OPENID).get<std::string>();
    }

    if (jsonData_.find(DATADEAL_JSON_KEY_UID) != jsonObjectEnd) {
        accountInfo.userId_ = jsonData_.at(DATADEAL_JSON_KEY_UID).get<std::int32_t>();
    }

    if (jsonData_.find(DATADEAL_JSON_KEY_BIND_TIME) != jsonObjectEnd) {
        accountInfo.bindTime_ = jsonData_.at(DATADEAL_JSON_KEY_BIND_TIME).get<std::time_t>();
    }
    ACCOUNT_LOGI("AccountInfo, bindTime: %{public}ld", accountInfo.bindTime_);

    if (jsonData_.find(DATADEAL_JSON_KEY_STATUS) != jsonObjectEnd) {
        accountInfo.ohosAccountStatus_ = jsonData_.at(DATADEAL_JSON_KEY_STATUS).get<std::int32_t>();
    }
    ACCOUNT_LOGI("AccountInfo, ohos account status: %{public}d", accountInfo.ohosAccountStatus_);

    return ERR_OK;
}

ErrCode OhosAccountDataDeal::AccountInfoToJson(AccountInfo &accountInfo)
{
    if (!initOk_) {
        ACCOUNT_LOGE("Not init ok");
        return ERR_ACCOUNT_DATADEAL_NOT_READY;
    }

    SaveAccountInfo(accountInfo);
    return ERR_OK;
}

void OhosAccountDataDeal::CreateDefaultAccountInfo(AccountInfo &accountInfo)
{
    accountInfo.userId_ = 0;
    accountInfo.bindTime_ = 0;
    accountInfo.ohosAccountUid_ = DEFAULT_OHOS_ACCOUNT_UID;
    accountInfo.ohosAccountName_ = DEFAULT_OHOS_ACCOUNT_NAME;
    accountInfo.ohosAccountStatus_ = ACCOUNT_STATE_UNBOUND;
    accountInfo.digest_ = "";
}

void OhosAccountDataDeal::SaveAccountInfo(AccountInfo &accountInfo)
{
    jsonData_[DATADEAL_JSON_KEY_BIND_TIME] = accountInfo.bindTime_;
    jsonData_[DATADEAL_JSON_KEY_UID] = accountInfo.userId_;
    jsonData_[DATADEAL_JSON_KEY_OPENID] = accountInfo.ohosAccountUid_;
    jsonData_[DATADEAL_JSON_KEY_ACCOUNT_NAME] = accountInfo.ohosAccountName_;
    jsonData_[DATADEAL_JSON_KEY_STATUS] = accountInfo.ohosAccountStatus_;

    /* update config file */
    std::ofstream out(configFile_);
    if (!out) {
        ACCOUNT_LOGE("Failed to open file %{public}s", configFile_.c_str());
        return;
    }
    out << jsonData_;
    out.close();
}

void OhosAccountDataDeal::BuildJsonFileFromScratch()
{
    AccountInfo accountInfo;

    CreateDefaultAccountInfo(accountInfo);

    SaveAccountInfo(accountInfo);
}
} // namespace AccountSA
} // namespace OHOS
