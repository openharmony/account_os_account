/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#ifndef OSACCOUNT_MANAGER_IMPL_H
#define OSACCOUNT_MANAGER_IMPL_H

#include <cstdint>
#include <vector>

namespace OHOS::AccountJsKit {
    class OsAccountManagerImpl {
    public:
        static bool IsOsAccountConstraintEnabled(char *constraint, int32_t *errCode);
        static int32_t GetOsAccountType(int32_t *errCode);
        static bool CheckMultiOsAccountEnabled(int32_t *errCode);
        static int32_t GetOsAccountLocalId(int32_t *errCode);
        static int32_t GetActivatedOsAccountLocalIds(std::vector<int> &osAccountIds);
        static uint32_t GetOsAccountCount(int32_t *errCode);
        static char *QueryDistributedVirtualDeviceId(int32_t *errCode);
        static int64_t GetSerialNumberForOsAccountLocalId(uint32_t localId, int32_t *errCode);
        static int32_t GetOsAccountLocalIdForSerialNumber(int64_t serialNumber, int32_t *errCode);
        static int32_t GetOsAccountLocalIdForDomain(char *domain, char *accountName, int32_t *errCode);
        static int32_t GetOsAccountLocalIdForUid(int32_t uid, int32_t *errCode);
        static char *GetOsAccountName(int32_t *errCode);
        static bool IsOsAccountUnlocked(int32_t *errCode);

        static char *MallocCString(const std::string &origin);

    private:
    };
}
#endif // OSACCOUNT_MANAGER_IMPL_H