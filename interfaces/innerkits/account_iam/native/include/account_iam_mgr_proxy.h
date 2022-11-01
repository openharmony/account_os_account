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

#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_ACCOUNT_IAM_NATIVE_INCLUDE_ACCOUNT_IAM_MGR_PROXY_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_ACCOUNT_IAM_NATIVE_INCLUDE_ACCOUNT_IAM_MGR_PROXY_H

#include "account_error_no.h"
#include "account_iam_info.h"
#include "iaccount_iam.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace AccountSA {
class AccountIAMMgrProxy : public IRemoteProxy<IAccountIAM> {
public:
    explicit AccountIAMMgrProxy(const sptr<IRemoteObject> &object);
    ~AccountIAMMgrProxy() override;

    int32_t OpenSession(int32_t userId, std::vector<uint8_t> &challenge) override;
    int32_t CloseSession(int32_t userId) override;
    void AddCredential(
        int32_t userId, const CredentialParameters &credInfo, const sptr<IIDMCallback> &callback) override;
    void UpdateCredential(int32_t userId, const CredentialParameters &credInfo,
        const sptr<IIDMCallback> &callback) override;
    int32_t Cancel(int32_t userId) override;
    void DelCred(int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &authToken,
        const sptr<IIDMCallback> &callback) override;
    void DelUser(int32_t userId, const std::vector<uint8_t> &authToken, const sptr<IIDMCallback> &callback) override;
    int32_t GetCredentialInfo(
        int32_t userId, AuthType authType, const sptr<IGetCredInfoCallback> &callback) override;
    uint64_t AuthUser(int32_t userId, const std::vector<uint8_t> &challenge, AuthType authType,
        AuthTrustLevel authTrustLevel, const sptr<IIDMCallback> &callback) override;
    int32_t CancelAuth(uint64_t contextId) override;
    int32_t GetAvailableStatus(AuthType authType, AuthTrustLevel authTrustLevel, int32_t &status) override;
    void GetProperty(
        int32_t userId, const GetPropertyRequest &request, const sptr<IGetSetPropCallback> &callback) override;
    void SetProperty(
        int32_t userId, const SetPropertyRequest &request, const sptr<IGetSetPropCallback> &callback) override;
    IAMState GetAccountState(int32_t userId) override;

private:
    ErrCode SendRequest(IAccountIAM::Message code, MessageParcel &data, MessageParcel &reply);
    void AddOrUpdateCredential(int32_t userId, const CredentialParameters &credInfo,
        const sptr<IIDMCallback> &callback, bool isAdd);
    bool WriteCommonData(MessageParcel &data, int32_t userId);

private:
    static inline BrokerDelegator<AccountIAMMgrProxy> delegator_;
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_ACCOUNT_IAM_NATIVE_INCLUDE_ACCOUNT_IAM_MGR_PROXY_H