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

#ifndef OS_ACCOUNT_INTERFACES_FRAMEWORKS_DOMAIN_ACCOUNT_INCLUDE_IDOMAIN_ACCOUNT_PLUGIN_H
#define OS_ACCOUNT_INTERFACES_FRAMEWORKS_DOMAIN_ACCOUNT_INCLUDE_IDOMAIN_ACCOUNT_PLUGIN_H

#include <string>
#include <iremote_broker.h>
#include "accountmgr_service_ipc_interface_code.h"
#include "domain_account_common.h"
#include "idomain_account_callback.h"
#include "want.h"

namespace OHOS {
namespace AccountSA {
class IDomainAccountPlugin : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.accountfwk.IDomainAccountPlugin");

    virtual ErrCode Auth(const DomainAccountInfo &info, const std::vector<uint8_t> &password,
        const sptr<IDomainAccountCallback> &callback) = 0;
    virtual ErrCode AuthWithPopup(const DomainAccountInfo &info, const sptr<IDomainAccountCallback> &callback) = 0;
    virtual ErrCode AuthWithToken(const DomainAccountInfo &info, const std::vector<uint8_t> &token,
        const sptr<IDomainAccountCallback> &callback) = 0;
    virtual ErrCode GetAuthStatusInfo(const DomainAccountInfo &info,
        const sptr<IDomainAccountCallback> &callback) = 0;
    virtual ErrCode GetDomainAccountInfo(
        const GetDomainAccountInfoOptions &options, const sptr<IDomainAccountCallback> &callback) = 0;
    virtual ErrCode OnAccountBound(const DomainAccountInfo &info, const int32_t localId,
        const sptr<IDomainAccountCallback> &callback) = 0;
    virtual ErrCode OnAccountUnBound(const DomainAccountInfo &info, const sptr<IDomainAccountCallback> &callback) = 0;
    virtual ErrCode IsAccountTokenValid(const DomainAccountInfo &info, const std::vector<uint8_t> &token,
        const sptr<IDomainAccountCallback> &callback) = 0;
    virtual ErrCode GetAccessToken(const DomainAccountInfo &domainInfo, const std::vector<uint8_t> &accountToken,
        const GetAccessTokenOptions &option, const sptr<IDomainAccountCallback> &callback) = 0;
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_FRAMEWORKS_DOMAIN_ACCOUNT_INCLUDE_IDOMAIN_ACCOUNT_PLUGIN_H
