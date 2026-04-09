/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_TEST_COMMON_INCLUDE_ACCOUNT_TEST_COMMON_H
#define OS_ACCOUNT_TEST_COMMON_INCLUDE_ACCOUNT_TEST_COMMON_H

#include <string>
#include "account_error_no.h"
#include "domain_account_callback.h"
#include "domain_account_common.h"
#include "os_account_info.h"

const std::vector<std::string> ALL_ACCOUNT_PERMISSION_LIST {
    "ohos.permission.MANAGE_LOCAL_ACCOUNTS",
    "ohos.permission.GET_LOCAL_ACCOUNTS",
    "ohos.permission.MANAGE_DISTRIBUTED_ACCOUNTS",
    "ohos.permission.GET_DISTRIBUTED_ACCOUNTS",
    "ohos.permission.DISTRIBUTED_DATASYNC",
    "ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS",
    "ohos.permission.GET_LOCAL_ACCOUNT_IDENTIFIERS",
    "ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS_EXTENSION"
};

namespace OHOS {
namespace AccountSA {
    uint64_t GetTokenIdFromProcess(const std::string &process);
    uint64_t GetTokenIdFromBundleName(const std::string &bundleName);
    bool MockTokenId(const std::string &process);
    bool AllocPermission(std::vector<std::string> permissions, uint64_t &tokenID, bool isSystemApp = true);
    bool RecoveryPermission(uint64_t tokenID, uint64_t oldTokenID);
    uint64_t GetAllAccountPermission();
    ErrCode CreateOsAccountForTest(const std::string &name, const OsAccountType &type, OsAccountInfo &osAccountInfo);
    ErrCode CreateOsAccountForTest(const std::string &localName, const std::string &shortName,
        const OsAccountType &type, OsAccountInfo &osAccountInfo);
    ErrCode CreateOsAccountForTest(const std::string &localName, const std::string &shortName,
        const OsAccountType &type, const CreateOsAccountOptions &options, OsAccountInfo &osAccountInfo);
    ErrCode CreateOsAccountWithFullInfoForTest(OsAccountInfo &osAccountInfo,
        const CreateOsAccountOptions &options = {});
    ErrCode CreateOsAccountForDomainForTest(const OsAccountType &type, const DomainAccountInfo &domainInfo,
        const std::shared_ptr<DomainAccountCallback> &callback,
        const CreateOsAccountForDomainOptions &options = {});
    ErrCode SetOsAccountToBeRemovedForTest(int32_t localId, bool toBeRemoved);
    ErrCode RemoveOsAccountForTest(int id);
    ErrCode RemoveOsAccountForTest(int id, const RemoveOsAccountOptions &options);
    ErrCode CreateOsAccountByProxyForTest(const std::string &name, const OsAccountType &type,
        OsAccountInfo &osAccountInfo);
    ErrCode CreateOsAccountByProxyForTest(const std::string &localName, const std::string &shortName,
        const OsAccountType &type, OsAccountInfo &osAccountInfo, const CreateOsAccountOptions &options = {});
    ErrCode RemoveOsAccountByProxyForTest(int id);
    ErrCode RemoveOsAccountByProxyForTest(int id, const RemoveOsAccountOptions &options);
} // namespace AccountSA
} // namespace OHOS

#endif // OS_ACCOUNT_TEST_COMMON_INCLUDE_ACCOUNT_TEST_COMMON_H
