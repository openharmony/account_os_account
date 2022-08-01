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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_IAM_PROXY_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_IAM_PROXY_H

#include "account_error_no.h"
#include "account_iam_info.h"
#include "iaccount_iam.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace AccountSA {
class AccountIAMProxy : public IRemoteProxy<IAccountIAM> {
public:
    explicit AccountIAMProxy(const sptr<IRemoteObject> &object);
    ~AccountIAMProxy() override;

    ErrCode ActivateUserKey(
        std::int32_t userId, const std::vector<uint8_t> &token, const std::vector<uint8_t> &secret) override;
    ErrCode UpdateUserKey(int32_t userId, uint64_t credentialId,
        const std::vector<uint8_t> &token, const std::vector<uint8_t> &newSecret) override;
    ErrCode RemoveUserKey(int32_t userId, const std::vector<uint8_t> &token) override;
    ErrCode RestoreUserKey(int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &token) override;

private:
    ErrCode SendRequest(IAccountIAM::Message code, MessageParcel &data, MessageParcel &reply);

private:
    static inline BrokerDelegator<AccountIAMProxy> delegator_;
};
}  // AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_IAM_PROXY_H