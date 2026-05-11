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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OS_ACCOUNT_SUBSPACE_MANAGER_SERVICE_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OS_ACCOUNT_SUBSPACE_MANAGER_SERVICE_H

#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
#include "os_account_subspace_stub.h"
#include "account_info.h"

namespace OHOS {
namespace AccountSA {
class OsAccountSubspaceManagerService : public OsAccountSubspaceStub {
public:
    OsAccountSubspaceManagerService() = default;
    ~OsAccountSubspaceManagerService() override = default;

    int32_t CreateOsAccountSubspace(int32_t osAccountId,
        OsAccountSubspaceResult &subspaceResult) override;
    int32_t DeleteOsAccountSubspace(int32_t osAccountId,
        int32_t subspaceId) override;
    int32_t SwitchOsAccountSubspace(int32_t osAccountId,
        int32_t subspaceId) override;
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_OS_ACCOUNT_SUBSPACE_MANAGER_SERVICE_H