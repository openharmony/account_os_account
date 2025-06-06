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

#ifndef OS_ACCOUNT_SERVICES_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_ACCOUNT_PLUGIN_PROXY_H
#define OS_ACCOUNT_SERVICES_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_ACCOUNT_PLUGIN_PROXY_H

#include <string>
#include "account_error_no.h"
#include "idomain_account_plugin.h"
#include "iremote_proxy.h"
#include "want.h"

namespace OHOS {
namespace AccountSA {
class DomainAccountPluginProxy : public IRemoteProxy<IDomainAccountPlugin> {
public:
    explicit DomainAccountPluginProxy(const sptr<IRemoteObject> &object);
    ~DomainAccountPluginProxy() override;
    ErrCode Auth(const DomainAccountInfo &info, const std::vector<uint8_t> &password,
        const sptr<IDomainAccountCallback> &callback) override;
    ErrCode AuthWithPopup(const DomainAccountInfo &info, const sptr<IDomainAccountCallback> &callback) override;
    ErrCode AuthWithToken(const DomainAccountInfo &info, const std::vector<uint8_t> &token,
        const sptr<IDomainAccountCallback> &callback) override;
    ErrCode GetAuthStatusInfo(const DomainAccountInfo &info, const sptr<IDomainAccountCallback> &callback) override;
    ErrCode GetDomainAccountInfo(
        const GetDomainAccountInfoOptions &options, const sptr<IDomainAccountCallback> &callback) override;
    ErrCode OnAccountBound(const DomainAccountInfo &info, const int32_t localId,
        const sptr<IDomainAccountCallback> &callback) override;
    ErrCode OnAccountUnBound(const DomainAccountInfo &info,
        const sptr<IDomainAccountCallback> &callback) override;
    ErrCode IsAccountTokenValid(const DomainAccountInfo &info, const std::vector<uint8_t> &token,
        const sptr<IDomainAccountCallback> &callback) override;
    ErrCode GetAccessToken(const DomainAccountInfo &domainInfo, const std::vector<uint8_t> &accountToken,
        const GetAccessTokenOptions &option, const sptr<IDomainAccountCallback> &callback) override;

private:
    ErrCode SendRequest(DomainAccountPluginInterfaceCode code, MessageParcel &data, MessageParcel &reply);
    ErrCode AuthCommonInterface(const DomainAccountInfo &info, const std::vector<uint8_t> &password,
        const sptr<IDomainAccountCallback> &callback, AuthMode authMode);

private:
    static inline BrokerDelegator<DomainAccountPluginProxy> delegator_;
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_SERVICES_DOMAIN_ACCOUNT_INCLUDE_DOMAIN_ACCOUNT_PLUGIN_PROXY_H