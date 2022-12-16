/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_ACCOUNT_PLUGIN_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_ACCOUNT_PLUGIN_H

#include "os_account_info.h"
#include "domain_auth_callback.h"

namespace OHOS {
namespace AccountSA {
class DomainAccountPlugin {
public:
    /**
     * Authenticates the specified domain account with the specified password,
     * the authentication result should be returned from the callback.
     *
     * @param info Indicates the domain account information, including accountName and domain.
     * @param password Indicates the password for authentication.
     * @param callback Indicates the result callback.
    */
    virtual void Auth(const DomainAccountInfo &info, const std::vector<uint8_t> &password,
        const std::shared_ptr<DomainAuthCallback> &callback) = 0;

    /**
     * Gets the authentication property of the specified domain account,
     * which can be used to prevent brute-force attack.
     *
     * @param info Indicates the domain account information, including accountName and domain.
     * @param[out] property Indicates the authentication property, including remaining times and freezing time.
     * @return 0 indicates success, others indicate failure.
    */
    virtual int32_t GetAuthProperty(const DomainAccountInfo &info, DomainAuthProperty &property) = 0;
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_ACCOUNT_PLUGIN_H