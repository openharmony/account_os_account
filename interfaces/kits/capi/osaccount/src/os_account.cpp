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
#include "os_account.h"
#include <string>
#include <securec.h>
#include "account_log_wrapper.h"
#include "os_account_common.h"
#include "os_account_manager.h"

using namespace OHOS;
using namespace OHOS::AccountSA;
OsAccount_ErrCode OH_OsAccount_GetName(char *buffer, size_t buffer_size)
{
    if ((buffer == nullptr) || (buffer_size == 0)) {
        ACCOUNT_LOGE("Buffer is nullptr or length is zero.");
        return OsAccount_ErrCode::OS_ACCOUNT_ERR_INVALID_PARAMETER;
    }
    std::string accountName;
    ErrCode err = AccountSA::OsAccountManager::GetOsAccountName(accountName);
    if (err != ERR_OK) {
        ACCOUNT_LOGE("Internal error(%{public}d).", err);
        return OsAccount_ErrCode::OS_ACCOUNT_ERR_INTERNAL_ERROR;
    }
    size_t accountSize = accountName.size();
    if (buffer_size <= accountSize) {
        ACCOUNT_LOGE(
            "Buffer size(%{public}zu) is less than length of account name(%{public}zu).", buffer_size, accountSize);
        return OsAccount_ErrCode::OS_ACCOUNT_ERR_INVALID_PARAMETER;
    }
    err = strncpy_s(buffer, buffer_size, accountName.c_str(), accountSize);
    if (err != EOK) {
        ACCOUNT_LOGE("Failed to strncpy_s, err(%{public}d).", err);
        return OsAccount_ErrCode::OS_ACCOUNT_ERR_INTERNAL_ERROR;
    }
    buffer[accountSize] = '\0';
    return OsAccount_ErrCode::OS_ACCOUNT_ERR_OK;
}