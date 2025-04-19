/*
* Copyright (c) 2025 Huawei Device Co., Ltd.
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#include "taihe_common.h"
#include "account_log_wrapper.h"
namespace OHOS {
namespace AccountSA {
TaiheOsAccountType::key_t ConvertToOsAccountTypeKey(OsAccountType type)
{
    switch (type) {
        case OsAccountType::ADMIN:
            return TaiheOsAccountType::key_t::ADMIN;
        case OsAccountType::GUEST:
            return TaiheOsAccountType::key_t::GUEST;
        case OsAccountType::PRIVATE:
            return TaiheOsAccountType::key_t::PRIVATE;
        case OsAccountType::NORMAL:
        default:
            return TaiheOsAccountType::key_t::NORMAL;
    }
}

OsAccountType ConvertFromOsAccountTypeKey(int32_t type)
{
    switch (static_cast<TaiheOsAccountType::key_t>(type)) {
        case TaiheOsAccountType::key_t::ADMIN:
            return OsAccountType::ADMIN;
        case TaiheOsAccountType::key_t::GUEST:
            return OsAccountType::GUEST;
        case TaiheOsAccountType::key_t::PRIVATE:
            return OsAccountType::PRIVATE;
        case TaiheOsAccountType::key_t::NORMAL:
        default:
            return OsAccountType::NORMAL;
    }
}

bool IsAccountIdValid(int32_t accountId)
{
    if (accountId < 0) {
        ACCOUNT_LOGI("The account id is invalid");
        return false;
    }
    return true;
}


int32_t IsSystemApp()
{
    uint64_t tokenId = OHOS::IPCSkeleton::GetSelfTokenID();
    bool isSystemApp = OHOS::Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(tokenId);
    if (!isSystemApp) {
        ACCOUNT_LOGI("Not system app.");
        return ERR_JS_IS_NOT_SYSTEM_APP;
    }
    return ERR_OK;
}
}
}