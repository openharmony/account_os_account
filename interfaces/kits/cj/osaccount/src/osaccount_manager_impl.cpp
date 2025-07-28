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
#include "account_info.h"
#include "account_log_wrapper.h"
#include <unistd.h>

namespace OHOS::AccountJsKit {
    using namespace OHOS::AccountSA;

    bool OsAccountManagerImpl::IsOsAccountConstraintEnabled(char *constraint, int32_t *errCode)
    {
        int32_t id = static_cast<int32_t>(getuid()) / OHOS::AccountSA::UID_TRANSFORM_DIVISOR;
        bool isConsEnable = false;
        *errCode = ConvertToJSErrCode(OsAccountManager::CheckOsAccountConstraintEnabled(id, constraint, isConsEnable));
        return isConsEnable;
    }

    int32_t OsAccountManagerImpl::GetOsAccountType(int32_t *errCode)
    {
        OsAccountType type;
        *errCode = ConvertToJSErrCode(OsAccountManager::GetOsAccountTypeFromProcess(type));
        return type;
    }

    bool OsAccountManagerImpl::CheckMultiOsAccountEnabled(int32_t *errCode)
    {
        bool isMultiOAEnable = false;
        *errCode = ConvertToJSErrCode(OsAccountManager::IsMultiOsAccountEnable(isMultiOAEnable));
        return isMultiOAEnable;
    }

    int32_t OsAccountManagerImpl::GetOsAccountLocalId(int32_t *errCode)
    {
        int32_t id = 0;
        *errCode = ConvertToJSErrCode(OsAccountManager::GetOsAccountLocalIdFromProcess(id));
        return id;
    }

    int32_t OsAccountManagerImpl::GetActivatedOsAccountLocalIds(std::vector<int32_t> &osAccountIds)
    {
        return ConvertToJSErrCode(OsAccountManager::QueryActiveOsAccountIds(osAccountIds));
    }

    uint32_t OsAccountManagerImpl::GetOsAccountCount(int32_t *errCode)
    {
        uint32_t osAccountCount = 0;
        *errCode = ConvertToJSErrCode(OsAccountManager::GetCreatedOsAccountsCount(osAccountCount));
        return osAccountCount;
    }

    char *OsAccountManagerImpl::QueryDistributedVirtualDeviceId(int32_t *errCode)
    {
        std::string deviceId;
        *errCode = ConvertToJSErrCode(OsAccountManager::GetDistributedVirtualDeviceId(deviceId));
        return MallocCString(deviceId);
    }

    int64_t OsAccountManagerImpl::GetSerialNumberForOsAccountLocalId(uint32_t localId, int32_t *errCode)
    {
        int64_t serialNum;
        *errCode = ConvertToJSErrCode(OsAccountManager::GetSerialNumberByOsAccountLocalId(localId, serialNum));
        return serialNum;
    }

    int32_t OsAccountManagerImpl::GetOsAccountLocalIdForSerialNumber(int64_t serialNumber, int32_t *errCode)
    {
        int32_t id = 0;
        *errCode = ConvertToJSErrCode(OsAccountManager::GetOsAccountLocalIdBySerialNumber(serialNumber, id));
        return id;
    }

    int32_t OsAccountManagerImpl::GetOsAccountLocalIdForDomain(char *domain, char *accountName, int32_t *errCode)
    {
        int32_t id = 0;
        DomainAccountInfo domainInfo;
        domainInfo.accountId_ = domain;
        domainInfo.accountName_ = accountName;
        *errCode = ConvertToJSErrCode(OsAccountManager::GetOsAccountLocalIdFromDomain(domainInfo, id));
        return id;
    }

    int32_t OsAccountManagerImpl::GetOsAccountLocalIdForUid(int32_t uid, int32_t *errCode)
    {
        int32_t id = 0;
        *errCode = ConvertToJSErrCode(OsAccountManager::GetOsAccountLocalIdFromUid(uid, id));
        return id;
    }

    char *OsAccountManagerImpl::GetOsAccountName(int32_t *errCode)
    {
        std::string name;
        *errCode = ConvertToJSErrCode(OsAccountManager::GetOsAccountName(name));
        return MallocCString(name);
    }

    bool OsAccountManagerImpl::IsOsAccountUnlocked(int32_t *errCode)
    {
        bool isVerified = false;
        *errCode = ConvertToJSErrCode(OsAccountManager::IsCurrentOsAccountVerified(isVerified));
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