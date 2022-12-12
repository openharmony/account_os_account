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

#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_ACCOUNT_IAM_NATIVE_INCLUDE_ACCOUNT_IAM_CLIENT_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_ACCOUNT_IAM_NATIVE_INCLUDE_ACCOUNT_IAM_CLIENT_H

#include <map>
#include <mutex>
#include <vector>
#include <set>
#include "account_iam_client_callback.h"
#include "account_iam_info.h"
#include "account_error_no.h"
#include "iaccount_iam.h"
#include "singleton.h"

namespace OHOS {
namespace AccountSA {
class AccountIAMClient : public DelayedRefSingleton<AccountIAMClient> {
public:
    AccountIAMClient();
    int32_t OpenSession(int32_t userId, std::vector<uint8_t> &challenge);
    int32_t CloseSession(int32_t userId);
    void AddCredential(
        int32_t userId, const CredentialParameters& credInfo, const std::shared_ptr<IDMCallback> &callback);
    void UpdateCredential(
        int32_t userId, const CredentialParameters& credInfo, const std::shared_ptr<IDMCallback> &callback);
    int32_t Cancel(int32_t userId);
    void DelCred(int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &authToken,
        const std::shared_ptr<IDMCallback>& callback);
    void DelUser(int32_t userId, const std::vector<uint8_t> &authToken, const std::shared_ptr<IDMCallback> &callback);
    int32_t GetCredentialInfo(int32_t userId, AuthType authType, const std::shared_ptr<GetCredInfoCallback> &callback);
    uint64_t Auth(const std::vector<uint8_t> &challenge, AuthType authType, AuthTrustLevel authTrustLevel,
        const std::shared_ptr<IDMCallback> &callback);
    uint64_t AuthUser(int32_t userId, const std::vector<uint8_t> &challenge, AuthType authType,
        AuthTrustLevel authTrustLevel, const std::shared_ptr<IDMCallback> &callback);
    int32_t CancelAuth(uint64_t contextId);
    int32_t GetAvailableStatus(AuthType authType, AuthTrustLevel authTrustLevel, int32_t &status);
    void GetProperty(
        int32_t userId, const GetPropertyRequest &request, const std::shared_ptr<GetSetPropCallback> &callback);
    void SetProperty(
        int32_t userId, const SetPropertyRequest &request, const std::shared_ptr<GetSetPropCallback> &callback);
    ErrCode RegisterPINInputer(const std::shared_ptr<IInputer> &inputer);
    void UnregisterPINInputer();
    ErrCode RegisterInputer(int32_t authType, const std::shared_ptr<IInputer> &inputer);
    ErrCode UnregisterInputer(int32_t authType);
    IAMState GetAccountState(int32_t userId);
    void SetAuthSubType(int32_t userId, int32_t authSubType);
    int32_t GetAuthSubType(int32_t userId);
    void SetCredential(int32_t userId, const std::vector<uint8_t> &credential);
    void GetCredential(int32_t userId, CredentialItem &credItem);
    void ClearCredential(int32_t userId);

private:
    class AccountIAMDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        AccountIAMDeathRecipient() = default;
        ~AccountIAMDeathRecipient() = default;
        void OnRemoteDied(const wptr<IRemoteObject>& remote) override;

    private:
        DISALLOW_COPY_AND_MOVE(AccountIAMDeathRecipient);
    };
    ErrCode GetAccountIAMProxy();
    void ResetAccountIAMProxy(const wptr<IRemoteObject>& remote);
    bool GetCurrentUserId(int32_t &userId);
    uint64_t StartDomainAuth(int32_t userId, const std::shared_ptr<IDMCallback> &callback);
    ErrCode RegisterDomainInputer(const std::shared_ptr<IInputer> &inputer);
    ErrCode UnregisterDomainInputer();
    bool CheckSelfPermission(const std::string &permissionName);

private:
    std::mutex mutex_;
    std::mutex pinMutex_;
    std::mutex domainMutex_;
    std::map<int32_t, CredentialItem> credentialMap_;
    sptr<IAccountIAM> proxy_ = nullptr;
    sptr<AccountIAMDeathRecipient> deathRecipient_ = nullptr;
    std::shared_ptr<IInputer> pinInputer_ = nullptr;
    std::shared_ptr<IInputer> domainInputer_ = nullptr;
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_ACCOUNT_IAM_NATIVE_INCLUDE_ACCOUNT_IAM_CLIENT_H