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

#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_NATIVE_INCLUDE_DOMAIN_ACCOUNT_PROXY_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_NATIVE_INCLUDE_DOMAIN_ACCOUNT_PROXY_H

#include <string>
#include "account_error_no.h"
#include "idomain_account.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace AccountSA {
class DomainAccountProxy : public IRemoteProxy<IDomainAccount> {
public:
    explicit DomainAccountProxy(const sptr<IRemoteObject> &object);
    ~DomainAccountProxy() override;
    ErrCode RegisterPlugin(const sptr<IDomainAccountPlugin> &plugin) override;
    ErrCode UnregisterPlugin() override;
    ErrCode GetAccountStatus(
        const DomainAccountInfo &info, DomainAccountStatus &status) override;
    ErrCode RegisterAccountStatusListener(const sptr<IDomainAccountCallback> &listener) override;
    ErrCode UnregisterAccountStatusListener(const sptr<IDomainAccountCallback> &listener) override;
    ErrCode Auth(const DomainAccountInfo &info, const std::vector<uint8_t> &password,
        const sptr<IDomainAccountCallback> &callback) override;
    ErrCode AuthUser(int32_t userId, const std::vector<uint8_t> &password,
        const sptr<IDomainAccountCallback> &callback) override;
    ErrCode AuthWithPopup(int32_t userId, const sptr<IDomainAccountCallback> &callback) override;
    ErrCode HasDomainAccount(const DomainAccountInfo &info, const sptr<IDomainAccountCallback> &callback) override;
    ErrCode UpdateAccountToken(const DomainAccountInfo &info, const std::vector<uint8_t> &token) override;
    ErrCode IsAuthenticationExpired(const DomainAccountInfo &info, bool &isExpired) override;
    ErrCode SetAccountPolicy(const DomainAccountPolicy &policy) override;
    ErrCode GetAccessToken(const DomainAccountInfo &info, const AAFwk::WantParams &parameters,
        const sptr<IDomainAccountCallback> &callback) override;
    ErrCode GetDomainAccountInfo(const DomainAccountInfo &info, const sptr<IDomainAccountCallback> &callback) override;
    ErrCode AddServerConfig(const std::string &paramter, DomainServerConfig &config) override;
    ErrCode RemoveServerConfig(const std::string &configId) override;
    ErrCode GetAccountServerConfig(const DomainAccountInfo &info, DomainServerConfig &config) override;
    ErrCode UpdateAccountInfo(
        const DomainAccountInfo &oldAccountInfo, const DomainAccountInfo &newAccountInfo) override;

private:
    ErrCode SendRequest(DomainAccountInterfaceCode code, MessageParcel &data, MessageParcel &reply);

private:
    static inline BrokerDelegator<DomainAccountProxy> delegator_;
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_DOMAIN_ACCOUNT_NATIVE_INCLUDE_DOMAIN_ACCOUNT_PROXY_H