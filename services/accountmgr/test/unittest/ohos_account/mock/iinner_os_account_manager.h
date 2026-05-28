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

#ifndef MOCK_IINNER_OS_ACCOUNT_MANAGER_H
#define MOCK_IINNER_OS_ACCOUNT_MANAGER_H

#include <vector>
#include "account_error_no.h"
#include "os_account_info.h"

namespace OHOS {
namespace AccountSA {

class IInnerOsAccountManager {
public:
    static IInnerOsAccountManager &GetInstance();
    ErrCode QueryAllCreatedOsAccounts(std::vector<OsAccountInfo> &osAccountInfos);
    ErrCode GetOsAccountInfoById(const int id, OsAccountInfo &osAccountInfo);
    ErrCode SetOsAccountForegroundSubspaceId(int32_t localId, int32_t subspaceId);
};

} // namespace AccountSA
} // namespace OHOS

#endif
