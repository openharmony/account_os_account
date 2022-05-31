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

#include "os_account_data_storage.h"

#include "account_error_no.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
OsAccountDataStorage::~OsAccountDataStorage()
{
    ACCOUNT_LOGD("enter");
}

OsAccountDataStorage::OsAccountDataStorage(const std::string &appId, const std::string &storeId, const bool &autoSync)
    : AccountDataStorage(appId, storeId, autoSync)
{
    ACCOUNT_LOGD("enter");
}

void OsAccountDataStorage::SaveEntries(
    std::vector<OHOS::DistributedKv::Entry> allEntries, std::map<std::string, std::shared_ptr<IAccountInfo>> &infos)
{
    ACCOUNT_LOGD("start, allEntries size is: %{public}zu", allEntries.size());
    for (auto const &item : allEntries) {
        OsAccountInfo osAccountInfo;
        nlohmann::json jsonObject = nlohmann::json::parse(item.value.ToString(), nullptr, false);
        if (jsonObject.is_discarded()) {
            ACCOUNT_LOGE("error key: %{private}s", item.key.ToString().c_str());
            // it's a bad json, delete it
            {
                std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
                kvStorePtr_->Delete(item.key);
            }
            continue;
        }
        osAccountInfo.FromJson(jsonObject);
        infos.emplace(item.key.ToString(), std::make_shared<OsAccountInfo>(osAccountInfo));
    }
    ACCOUNT_LOGD("end");
}
}  // namespace AccountSA
}  // namespace OHOS