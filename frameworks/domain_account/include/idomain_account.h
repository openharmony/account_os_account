/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_INCLUDE_IDOMAIN_ACCOUNT_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_INCLUDE_IDOMAIN_ACCOUNT_H

#include <string>
#include <iremote_broker.h>
#include "accountmgr_service_ipc_interface_code.h"
#include "idomain_account_callback.h"
#include "idomain_account_plugin.h"
#include "want.h"

namespace OHOS {
namespace AccountSA {
class IDomainAccount : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.accountfwk.IDomainAccount");

    virtual ErrCode RegisterPlugin(const sptr<IDomainAccountPlugin> &plugin) = 0;
    virtual ErrCode UnregisterPlugin() = 0;
    virtual ErrCode GetAccountStatus(const DomainAccountInfo &info, DomainAccountStatus &status) = 0;
    virtual ErrCode RegisterAccountStatusListener(const sptr<IDomainAccountCallback> &listener) = 0;
    virtual ErrCode UnregisterAccountStatusListener(const sptr<IDomainAccountCallback> &listener) = 0;
    virtual ErrCode Auth(const DomainAccountInfo &info, const std::vector<uint8_t> &password,
        const sptr<IDomainAccountCallback> &callback) = 0;
    virtual ErrCode AuthUser(int32_t userId, const std::vector<uint8_t> &password,
        const sptr<IDomainAccountCallback> &callback) = 0;
    virtual ErrCode AuthWithPopup(int32_t userId, const sptr<IDomainAccountCallback> &callback) = 0;
    virtual ErrCode HasDomainAccount(const DomainAccountInfo &info, const sptr<IDomainAccountCallback> &callback) = 0;
    virtual ErrCode UpdateAccountToken(const DomainAccountInfo &info, const std::vector<uint8_t> &token) = 0;
    virtual ErrCode IsAuthenticationExpired(const DomainAccountInfo &info, bool &isExpired) = 0;
    virtual ErrCode SetAccountPolicy(const DomainAccountPolicy &policy) = 0;
    virtual ErrCode GetAccessToken(const DomainAccountInfo &info, const AAFwk::WantParams &parameters,
        const sptr<IDomainAccountCallback> &callback) = 0;
    virtual ErrCode GetDomainAccountInfo(
        const DomainAccountInfo &Info, const sptr<IDomainAccountCallback> &callback) = 0;
    virtual ErrCode AddServerConfig(const std::string &paramter, DomainServerConfig &config) = 0;
    virtual ErrCode RemoveServerConfig(const std::string &configId) = 0;
    virtual ErrCode GetAccountServerConfig(const DomainAccountInfo &info, DomainServerConfig &config) = 0;
    virtual ErrCode UpdateAccountInfo(
        const DomainAccountInfo &oldAccountInfo, const DomainAccountInfo &newAccountInfo) = 0;
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_INCLUDE_IDOMAIN_ACCOUNT_H
