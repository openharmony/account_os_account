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

#ifndef BASE_ACCOUNT_INCLUDE_OHOS_ACCOUNT_DATA_DEAL_H
#define BASE_ACCOUNT_INCLUDE_OHOS_ACCOUNT_DATA_DEAL_H

#include <string>
#include <nlohmann/json.hpp>
#include "account_info.h"
#include "account_error_no.h"

namespace OHOS {
namespace AccountSA {
using json = nlohmann::json;

const std::string DATADEAL_JSON_KEY_ACCOUNT_NAME = "account_name";
const std::string DATADEAL_JSON_KEY_OPENID = "openId";
const std::string DATADEAL_JSON_KEY_UID = "uid";
const std::string DATADEAL_JSON_KEY_BIND_TIME = "bind_time";
const std::string DATADEAL_JSON_KEY_STATUS = "bind_status";

class OhosAccountDataDeal {
public:
    explicit OhosAccountDataDeal(const std::string &configFile);
    ErrCode Init();
    ErrCode AccountInfoFromJson(AccountInfo &accountInfo);
    ErrCode AccountInfoToJson(AccountInfo &accountInfo);
    ~OhosAccountDataDeal() {};

private:
    json jsonData_;
    bool initOk_;
    std::string configFile_;
    void BuildJsonFileFromScratch();
    void CreateDefaultAccountInfo(AccountInfo &accountInfo);
    void SaveAccountInfo(AccountInfo &accountInfo);
};
}
}
#endif // BASE_ACCOUNT_INCLUDE_OHOS_ACCOUNT_DATA_DEAL_H
