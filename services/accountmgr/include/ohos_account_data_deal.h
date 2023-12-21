/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OHOS_ACCOUNT_DATA_DEAL_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OHOS_ACCOUNT_DATA_DEAL_H

#include <string>
#include <mutex>
#include <nlohmann/json.hpp>
#include "account_error_no.h"
#include "account_file_operator.h"
#include "account_file_watcher_manager.h"
#include "account_info.h"

namespace OHOS {
namespace AccountSA {
using json = nlohmann::json;

class OhosAccountDataDeal {
public:
    explicit OhosAccountDataDeal(const std::string &configFileDir);
    ErrCode Init(std::int32_t userId);

    ErrCode AccountInfoFromJson(AccountInfo &accountInfo, int32_t userId);
    ErrCode AccountInfoToJson(const AccountInfo &accountInfo);
    ~OhosAccountDataDeal() {}

private:
    bool DealWithFileModifyEvent(const std::string &fileName, const int32_t id);
    void DealWithFileDeleteEvent(const std::string &fileName, const int32_t id);
    bool initOk_;
    std::string configFileDir_;
    std::mutex mutex_;
    void BuildJsonFileFromScratch(int32_t userId);
    ErrCode SaveAccountInfo(const AccountInfo &accountInfo);
    ErrCode GetAccountInfo(AccountInfo &accountInfo, const int32_t userId);
    ErrCode ParseJsonFromFile(const std::string &filePath, nlohmann::json &jsonData, int32_t userId);
    ErrCode GetAccountInfoFromJson(const nlohmann::json &jsonData, AccountInfo &accountInfo, const int32_t userId);
    ErrCode GenerateAccountInfoDigestStr(
        const std::string &userInfoPath, const std::string &accountInfoStr, std::string &digestStr);
    void AddFileWatcher(const int32_t id);

    std::mutex accountInfoFileLock_;
    AccountFileWatcherMgr &accountFileWatcherMgr_;
    std::shared_ptr<AccountFileOperator> accountFileOperator_;
    CheckNotifyEventCallbackFunc checkCallbackFunc_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OHOS_ACCOUNT_DATA_DEAL_H
