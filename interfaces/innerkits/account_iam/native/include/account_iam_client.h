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
#include <vector>
#include "account_iam_callback.h"
#include "account_iam_info.h"
#include "account_error_no.h"
#include "iaccount_iam.h"
#include "singleton.h"

namespace OHOS {
namespace AccountSA {
class AccountIAMClient : public DelayedRefSingleton<AccountIAMClient> {
public:
    AccountIAMClient();
    ErrCode OpenSession(int32_t userId, std::vector<uint8_t> &challenge);
    ErrCode CloseSession(int32_t userId);
    ErrCode AddCredential(
        const CredentialParameters& credInfo, const std::shared_ptr<UserIdmClientCallback>& callback);
    ErrCode UpdateCredential(
        const CredentialParameters& credInfo, const std::shared_ptr<UserIdmClientCallback>& callback);
    ErrCode Cancel(uint64_t challenge, int32_t &resultCode);
    ErrCode DelCred(
        uint64_t credentialId, std::vector<uint8_t> authToken, const std::shared_ptr<UserIdmClientCallback>& callback);
    ErrCode DelUser(std::vector<uint8_t> authToken, const std::shared_ptr<UserIdmClientCallback>& callback);
    ErrCode GetAuthInfo(AuthType authType, const std::shared_ptr<GetCredentialInfoCallback>& callback);
    ErrCode Auth(
        const std::vector<uint8_t> &challenge, const AuthType authType, const AuthTrustLevel authTrustLevel,
        const std::shared_ptr<AuthenticationCallback> &callback, uint64_t &contextId);
    ErrCode AuthUser(const int32_t userId, const std::vector<uint8_t> &challenge, const AuthType authType,
        const AuthTrustLevel authTrustLevel, const std::shared_ptr<AuthenticationCallback> &callback,
        uint64_t &contextId);
    ErrCode CancelAuth(const uint64_t contextId, int32_t &resultCode);
    ErrCode GetAvailableStatus(const AuthType authType, const AuthTrustLevel authTrustLevel, int32_t &status);
    ErrCode GetProperty(const GetPropertyRequest &request, std::shared_ptr<GetPropCallback> callback);
    ErrCode SetProperty(const SetPropertyRequest &request, std::shared_ptr<SetPropCallback> callback);
    ErrCode RegisterInputer(const std::shared_ptr<IInputer> inputer, bool &isSucceed);
    ErrCode UnRegisterInputer();
    IAMState GetState(int32_t userId);
    void SetState(int32_t userId, IAMState state);
    void GetChallenge(int32_t userId, std::vector<uint8_t> &challenge);
    void SetCredential(int32_t userId, int32_t authSubType, const std::vector<uint8_t> &credential);
    void GetCredential(int32_t userId, int32_t authSubType, CredentialPair &credPair);
    void ClearCredential(int32_t userId, int32_t authSubType);
    ErrCode ActivateUserKey(int32_t userId, const std::vector<uint8_t> &token, const std::vector<uint8_t> &secret);
    ErrCode UpdateUserKey(int32_t userId, uint64_t credentialId,
        const std::vector<uint8_t> &token, const std::vector<uint8_t> &newSecret);
    ErrCode RemoveUserKey(int32_t userId, const std::vector<uint8_t> &token);
    ErrCode RestoreUserKey(int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &token);

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

private:
    std::mutex mutex_;
    sptr<IAccountIAM> proxy_ = nullptr;
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ = nullptr;
    std::map<int32_t, IAMState> userStateMap_;
    std::map<std::string, CredentialPair> credentialMap_;
    std::map<int32_t, std::vector<uint8_t>> userChallengeMap_;
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_ACCOUNT_IAM_NATIVE_INCLUDE_ACCOUNT_IAM_CLIENT_H