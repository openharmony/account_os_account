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

#include "osaccount_manager_impl.h"
#include "os_account_manager.h"
#include "account_error_no.h"
#include "os_account_info.h"
#include "account_log_wrapper.h"

namespace OHOS::AccountJsKit {
    using namespace OHOS::AccountSA;

    bool OsAccountManagerImpl::IsOsAccountConstraintEnabled(char *constraint, int32_t *errCode)
    {
        int32_t id = 0;
        bool isConsEnable = false;
        std::vector<int32_t> ids;
        *errCode = OsAccountManager::QueryActiveOsAccountIds(ids);
        if (*errCode != ERR_OK) {
            ACCOUNT_LOGE("isOsAccountConstraintEnabled Get id failed");
            return false;
        }
        if (ids.empty()) {
            *errCode = ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
            ACCOUNT_LOGE("isOsAccountConstraintEnabled No Active OsAccount Ids");
            return false;
        }
        id = ids[0];
        *errCode = OsAccountManager::CheckOsAccountConstraintEnabled(id, constraint, isConsEnable);
        return isConsEnable;
    }

    int32_t OsAccountManagerImpl::GetOsAccountType(int32_t *errCode)
    {
        OsAccountType type;
        *errCode = OsAccountManager::GetOsAccountTypeFromProcess(type);
        return type;
    }

    bool OsAccountManagerImpl::CheckMultiOsAccountEnabled(int32_t *errCode)
    {
        bool isMultiOAEnable = false;
        *errCode = OsAccountManager::IsMultiOsAccountEnable(isMultiOAEnable);
        return isMultiOAEnable;
    }

    int32_t OsAccountManagerImpl::GetOsAccountLocalId(int32_t *errCode)
    {
        int32_t id = 0;
        *errCode = OsAccountManager::GetOsAccountLocalIdFromProcess(id);
        return id;
    }

    int32_t OsAccountManagerImpl::GetActivatedOsAccountLocalIds(std::vector<int32_t> &osAccountIds)
    {
        return OsAccountManager::QueryActiveOsAccountIds(osAccountIds);
    }

    uint32_t OsAccountManagerImpl::GetOsAccountCount(int32_t *errCode)
    {
        uint32_t osAccountCount = 0;
        *errCode = OsAccountManager::GetCreatedOsAccountsCount(osAccountCount);
        return osAccountCount;
    }

    char *OsAccountManagerImpl::QueryDistributedVirtualDeviceId(int32_t *errCode)
    {
        std::string deviceId;
        *errCode = OsAccountManager::GetDistributedVirtualDeviceId(deviceId);
        return MallocCString(deviceId);
    }

    int64_t OsAccountManagerImpl::GetSerialNumberForOsAccountLocalId(uint32_t localId, int32_t *errCode)
    {
        int64_t serialNum;
        *errCode = OsAccountManager::GetSerialNumberByOsAccountLocalId(localId, serialNum);
        return serialNum;
    }

    int32_t OsAccountManagerImpl::GetOsAccountLocalIdForSerialNumber(int64_t serialNumber, int32_t *errCode)
    {
        int32_t id = 0;
        *errCode = OsAccountManager::GetOsAccountLocalIdBySerialNumber(serialNumber, id);
        return id;
    }

    int32_t OsAccountManagerImpl::GetOsAccountLocalIdForDomain(char *domain, char *accountName, int32_t *errCode)
    {
        int32_t id = 0;
        DomainAccountInfo domainInfo;
        domainInfo.accountId_ = domain;
        domainInfo.accountName_ = accountName;
        *errCode = OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo, id);
        return id;
    }

    int32_t OsAccountManagerImpl::GetOsAccountLocalIdForUid(int32_t uid, int32_t *errCode)
    {
        int32_t id = 0;
        *errCode = OsAccountManager::GetOsAccountLocalIdFromUid(uid, id);
        return id;
    }

    char *OsAccountManagerImpl::GetOsAccountName(int32_t *errCode)
    {
        std::string name;
        *errCode = OsAccountManager::GetOsAccountName(name);
        return MallocCString(name);
    }

    bool OsAccountManagerImpl::IsOsAccountUnlocked(int32_t *errCode)
    {
        bool isVerified = false;
        *errCode = OsAccountManager::IsCurrentOsAccountVerified(isVerified);
        return isVerified;
    }

    char *OsAccountManagerImpl::MallocCString(const std::string &origin)
    {
        if (origin.empty()) {
            return nullptr;
        }
        auto len = origin.length() + 1;
        char *res = static_cast<char *>(malloc(sizeof(char) * len));
        if (res == nullptr) {
            return nullptr;
        }
        return std::char_traits<char>::copy(res, origin.c_str(), len);
    }
}