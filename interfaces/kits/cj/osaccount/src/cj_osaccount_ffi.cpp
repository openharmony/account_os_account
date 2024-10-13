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

#include "cj_osaccount_ffi.h"
#include "account_error_no.h"
#include "account_permission_manager.h"
#include "account_log_wrapper.h"
#include "osaccount_manager_impl.h"

using namespace OHOS::AccountSA;

namespace OHOS::AccountJsKit {
    EXTERN_C_START
    bool FfiOHOSOsAccountIsOsAccountConstraintEnabled(char *constraint, int32_t *errCode)
    {
        if (constraint == nullptr) {
            *errCode = ERR_JS_PARAMETER_ERROR;
            ACCOUNT_LOGE("[osAccount] IsOsAccountConstraintEnabled constraint is null! errCode %{public}d",
                *errCode);
            return false;
        }
        if (AccountPermissionManager::CheckSystemApp(false) != ERR_OK) {
            *errCode = ERR_JS_IS_NOT_SYSTEM_APP;
            ACCOUNT_LOGE("[osAccount] IsOsAccountConstraintEnabled CheckSystemApp failed! errCode %{public}d",
                *errCode);
            return false;
        }
        ACCOUNT_LOGE("[osAccount] IsOsAccountConstraintEnabled start");
        bool ret = OsAccountManagerImpl::IsOsAccountConstraintEnabled(constraint, errCode);
        ACCOUNT_LOGE("[osAccount] IsOsAccountConstraintEnabled success. errCode %{public}d", *errCode);
        return ret;
    }

    int32_t FfiOHOSOsAccountGetOsAccountType(int32_t *errCode)
    {
        ACCOUNT_LOGE("[osAccount] GetOsAccountType start");
        int32_t ret = OsAccountManagerImpl::GetOsAccountType(errCode);
        ACCOUNT_LOGE("[osAccount] GetOsAccountType success. errCode %{public}d", *errCode);
        return ret;
    }

    bool FfiOHOSOsAccountCheckOsAccountTestable(int32_t *errCode)
    {
        *errCode = ERR_JS_SUCCESS;
        return false;
    }

    bool FfiOHOSOsAccountCheckMultiOsAccountEnabled(int32_t *errCode)
    {
        ACCOUNT_LOGE("[osAccount] CheckMultiOsAccountEnabled start");
        bool ret = OsAccountManagerImpl::CheckMultiOsAccountEnabled(errCode);
        ACCOUNT_LOGE("[osAccount] CheckMultiOsAccountEnabled success. errCode %{public}d", *errCode);
        return ret;
    }

    int32_t FfiOHOSOsAccountGetOsAccountLocalId(int32_t *errCode)
    {
        ACCOUNT_LOGE("[osAccount] GetOsAccountLocalId start");
        int32_t ret = OsAccountManagerImpl::GetOsAccountLocalId(errCode);
        ACCOUNT_LOGE("[osAccount] GetOsAccountLocalId success. errCode %{public}d", *errCode);
        return ret;
    }

    RetDataCArrI32 FfiOHOSOsAccountGetActivatedOsAccountLocalIds()
    {
        std::vector<int32_t> osAccountIds;
        ACCOUNT_LOGE("[osAccount] GetActivatedOsAccountLocalIds start");
        int32_t code = OsAccountManagerImpl::GetActivatedOsAccountLocalIds(osAccountIds);
        ACCOUNT_LOGE("[osAccount] GetActivatedOsAccountLocalIds success. errCode %{public}d", code);
        CArrI32 data = {.head = nullptr, .size = 0};
        RetDataCArrI32 ret = {.code = code, .data = data};
        if (code != ERR_JS_SUCCESS) {
            return ret;
        }
        size_t listSize = osAccountIds.size();
        ret.data.size = static_cast<int64_t>(listSize);
        if (listSize > 0) {
            int32_t *retValue = static_cast<int32_t *>(malloc(sizeof(int32_t) * listSize));
            if (retValue == nullptr) {
                ret.code = ERR_JS_SYSTEM_SERVICE_EXCEPTION;
                return ret;
            }
            for (int32_t i = 0; i < listSize; i++) {
                retValue[i] = osAccountIds[i];
            }
            ret.data.head = retValue;
        }
        return ret;
    }

    uint32_t FfiOHOSOsAccountGetOsAccountCount(int32_t *errCode)
    {
        ACCOUNT_LOGE("[osAccount] GetOsAccountCount start");
        int32_t ret = OsAccountManagerImpl::GetOsAccountCount(errCode);
        ACCOUNT_LOGE("[osAccount] GetOsAccountCount success. errCode %{public}d", *errCode);
        return ret;
    }

    char *FfiOHOSOsAccountQueryDistributedVirtualDeviceId(int32_t *errCode)
    {
        ACCOUNT_LOGE("[osAccount] QueryDistributedVirtualDeviceId start");
        char *ret = OsAccountManagerImpl::QueryDistributedVirtualDeviceId(errCode);
        ACCOUNT_LOGE("[osAccount] QueryDistributedVirtualDeviceId success. errCode %{public}d", *errCode);
        return ret;
    }

    int64_t FfiOHOSOsAccountGetSerialNumberForOsAccountLocalId(uint32_t localId, int32_t *errCode)
    {
        ACCOUNT_LOGE("[osAccount] GetSerialNumberForOsAccountLocalId start");
        int32_t ret = OsAccountManagerImpl::GetSerialNumberForOsAccountLocalId(localId, errCode);
        ACCOUNT_LOGE("[osAccount] GetSerialNumberForOsAccountLocalId success. errCode %{public}d", *errCode);
        return ret;
    }

    int32_t FfiOHOSOsAccountGetOsAccountLocalIdForSerialNumber(int64_t serialNumber, int32_t *errCode)
    {
        ACCOUNT_LOGE("[osAccount] GetOsAccountLocalIdForSerialNumber start");
        int32_t ret = OsAccountManagerImpl::GetOsAccountLocalIdForSerialNumber(serialNumber, errCode);
        ACCOUNT_LOGE("[osAccount] GetOsAccountLocalIdForSerialNumber success. errCode %{public}d", *errCode);
        return ret;
    }

    int32_t FfiOHOSOsAccountGetOsAccountLocalIdForDomain(CDomainAccountInfo cDoaminInfo, int32_t *errCode)
    {
        ACCOUNT_LOGE("[osAccount] GetOsAccountLocalIdForDomain start");
        int32_t ret = OsAccountManagerImpl::GetOsAccountLocalIdForDomain(
            cDoaminInfo.domain, cDoaminInfo.accountName, errCode);
        ACCOUNT_LOGE("[osAccount] GetOsAccountLocalIdForDomain success. errCode %{public}d", *errCode);
        return ret;
    }

    int32_t FfiOHOSOsAccountGetOsAccountLocalIdForUid(int32_t uid, int32_t *errCode)
    {
        ACCOUNT_LOGE("[osAccount] GetOsAccountLocalIdForUid start");
        int32_t ret = OsAccountManagerImpl::GetOsAccountLocalIdForUid(uid, errCode);
        ACCOUNT_LOGE("[osAccount] GetOsAccountLocalIdForUid success. errCode %{public}d", *errCode);
        return ret;
    }

    char *FfiOHOSOsAccountGetOsAccountName(int32_t *errCode)
    {
        ACCOUNT_LOGE("[osAccount] GetOsAccountName start");
        char *ret = OsAccountManagerImpl::GetOsAccountName(errCode);
        ACCOUNT_LOGE("[osAccount] GetOsAccountName success. errCode %{public}d", *errCode);
        return ret;
    }

    bool FfiOHOSOsAccountIsOsAccountUnlocked(int32_t *errCode)
    {
        if (AccountPermissionManager::CheckSystemApp(false) != ERR_OK) {
            *errCode = ERR_JS_IS_NOT_SYSTEM_APP;
            ACCOUNT_LOGE("[osAccount] IsOsAccountUnlocked CheckSystemApp failed! errCode %{public}d", *errCode);
            return false;
        }
        ACCOUNT_LOGE("[osAccount] IsOsAccountUnlocked start");
        bool ret = OsAccountManagerImpl::IsOsAccountUnlocked(errCode);
        ACCOUNT_LOGE("[osAccount] IsOsAccountUnlocked success. errCode %{public}d", *errCode);
        return ret;
    }
    EXTERN_C_END
} // namespace OHOS::AccountJsKit
