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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_HELPER_DATA_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_HELPER_DATA_H

#include <map>
#include <string>
#include <vector>

namespace OHOS {
namespace AccountSA {
class AccountHelperData {
public:
    static std::vector<std::string> GetBundleNameTrustList();
    static std::map<std::string, std::string> GetAccountEventMap();
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_HELPER_DATA_H
