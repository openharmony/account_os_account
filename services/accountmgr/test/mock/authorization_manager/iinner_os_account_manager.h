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

#ifndef MOCK_OSACCOUNT_IINNER_OS_ACCOUNT_MANAGER_H
#define MOCK_OSACCOUNT_IINNER_OS_ACCOUNT_MANAGER_H

#include "os_account_info.h"
 #include "os_account_control_file_manager.h"
#include <thread>

namespace OHOS {
namespace AccountSA {
const int32_t UID_TRANSFORM_DIVISOR = 200000;

class IInnerOsAccountManager {
public:
    IInnerOsAccountManager()
    {
        osAccountControl_ = std::make_shared<OsAccountControlFileManager>();
    }
    static IInnerOsAccountManager &GetInstance()
    {
        static IInnerOsAccountManager instance;
        return instance;
    }

    OsAccountControlFileManager &GetFileController()
    {
        return *std::reinterpret_pointer_cast<OsAccountControlFileManager>(osAccountControl_);
    }

    ~IInnerOsAccountManager() = default;

    ErrCode GetOsAccountType(const int id, OsAccountType &type);

    ErrCode QueryAllCreatedOsAccounts(std::vector<OsAccountInfo> &osAccountInfos)
    {
        return ERR_OK;
    }

    ErrCode GetRealOsAccountInfoById(const int id, OsAccountInfo &osAccountInfo)
    {
        return ERR_OK;
    }

    ErrCode IsOsAccountDeactivating(const int id, bool &isDeactivating)
    {
        return ERR_OK;
    }
public:
   std::shared_ptr<OsAccountControlFileManager> osAccountControl_;
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // MOCK_OSACCOUNT_IINNER_OS_ACCOUNT_MANAGER_H
