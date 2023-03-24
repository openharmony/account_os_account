/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "mock_inner_os_account_manager.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
const std::string TEST_DOMAIN_ACCOUNT_NAME = "test_domain_account_name";
const std::string TEST_DOMAIN = "test_domain";
const std::int32_t MAIN_ACCOUNT_ID = 100;
ErrCode IInnerOsAccountManager::GetOsAccountLocalIdFromDomain(const DomainAccountInfo &domainInfo, int &id)
{
    ACCOUNT_LOGI("mock IInnerOsAccountManager GetOsAccountLocalIdFromDomain enter");
    if (domainInfo.accountName_ == TEST_DOMAIN_ACCOUNT_NAME) {
        id = MAIN_ACCOUNT_ID;
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::QueryOsAccountById(const int id, OsAccountInfo &osAccountInfo)
{
    ACCOUNT_LOGI("mock IInnerOsAccountManager QueryOsAccountById enter");
    if (id == MAIN_ACCOUNT_ID) {
        DomainAccountInfo domainInfo;
        domainInfo.accountName_ = TEST_DOMAIN_ACCOUNT_NAME;
        domainInfo.domain_ = TEST_DOMAIN;
        osAccountInfo.SetDomainInfo(domainInfo);
    }
    return ERR_OK;
}

ErrCode IInnerOsAccountManager::QueryActiveOsAccountIds(std::vector<int32_t>& ids)
{
    ACCOUNT_LOGI("mock IInnerOsAccountManager QueryActiveOsAccountIds enter");
    ids.clear();
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS

