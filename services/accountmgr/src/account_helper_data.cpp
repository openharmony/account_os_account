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

#include "account_helper_data.h"
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <vector>
#include "account_log_wrapper.h"
#include "file_ex.h"

namespace OHOS {
namespace AccountSA {
using json = nlohmann::json;
namespace {
const std::string ACCOUNTMGR_HELPER_JSON_FILE = "/system/etc/account/accountmgr_helper.json";
const std::string KEY_BUNDLE_NAME_LIST = "BundleNameTrustList";
}

std::vector<std::string> AccountHelperData::GetBundleNameTrustList()
{
    std::vector<std::string> result = {""};
    if (!FileExists(ACCOUNTMGR_HELPER_JSON_FILE)) {
        ACCOUNT_LOGI("file %{public}s not exist, empty default!", ACCOUNTMGR_HELPER_JSON_FILE.c_str());
        return result;
    }

    std::ifstream fin(ACCOUNTMGR_HELPER_JSON_FILE);
    if (!fin) {
        ACCOUNT_LOGE("Failed to open file %{public}s", ACCOUNTMGR_HELPER_JSON_FILE.c_str());
        return result;
    }

    nlohmann::json jsonData = json::parse(fin, nullptr, false);
    if (!jsonData.is_structured()) {
        ACCOUNT_LOGE("not valid json file!");
        fin.close();
        return result;
    }
    fin.close();

    if (jsonData.find(KEY_BUNDLE_NAME_LIST) != jsonData.end() && jsonData.at(KEY_BUNDLE_NAME_LIST).is_array()) {
        result = jsonData.at(KEY_BUNDLE_NAME_LIST).get<std::vector<std::string>>();
    }

    return result;
}
} // namespace AccountSA
} // namespace OHOS
