/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_INNER_ACCOUNT_IAM_MANAGER_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_INNER_ACCOUNT_IAM_MANAGER_H

#include <map>
#include <vector>
#include "account_iam_callback.h"
#include "account_iam_info.h"
#include "account_error_no.h"
#include "domain_account_common.h"
#include "iaccount_iam.h"
#include "singleton.h"
#ifdef HAS_STORAGE_PART
#include "istorage_manager.h"
#include "storage_manager_proxy.h"
#endif

namespace OHOS {
namespace AccountSA {
struct AccountCredentialInfo {
    uint64_t oldSecureUid = 0;
    uint64_t secureUid = 0;
    std::vector<uint8_t> oldSecret;
    std::vector<uint8_t> secret;
};

class InnerAccountIAMManager {
public:
    static InnerAccountIAMManager &GetInstance();
    void OpenSession(int32_t userId, std::vector<uint8_t> &challenge);
    void CloseSession(int32_t userId);
    void AddCredential(
        int32_t userId, const CredentialParameters &credInfo, const sptr<IIDMCallback> &callback);
    void UpdateCredential(
        int32_t userId, const CredentialParameters &credInfo, const sptr<IIDMCallback> &callback);
    void DelCred(int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &authToken,
        const sptr<IIDMCallback> &callback);
    void DelUser(int32_t userId, const std::vector<uint8_t> &authToken,
        const sptr<IIDMCallback> &callback);
    void GetCredentialInfo(
        int32_t userId, AuthType authType, const sptr<IGetCredInfoCallback> &callback);
    int32_t Cancel(int32_t userId);
    int32_t PrepareRemoteAuth(
        const std::string &remoteNetworkId, const sptr<IPreRemoteAuthCallback> &callback);
    int32_t AuthUser(AuthParam &authParam, const sptr<IIDMCallback> &callback, uint64_t &contextId);
    int32_t CancelAuth(uint64_t contextId);
    int32_t GetAvailableStatus(AuthType authType, AuthTrustLevel authTrustLevel, int32_t &status);
    void GetProperty(
        int32_t userId, const GetPropertyRequest &request, const sptr<IGetSetPropCallback> &callback);
    void SetProperty(
        int32_t userId, const SetPropertyRequest &request, const sptr<IGetSetPropCallback> &callback);
    void GetEnrolledId(int32_t accountId, AuthType authType, const sptr<IGetEnrolledIdCallback> &callback);
    IAMState GetState(int32_t userId);
    void SetState(int32_t userId, IAMState state);
    void GetChallenge(int32_t userId, std::vector<uint8_t> &challenge);
    ErrCode ActivateUserKey(int32_t userId, const std::vector<uint8_t> &token, const std::vector<uint8_t> &secret);

    ErrCode UnlockUserScreen(int32_t userId);
    ErrCode GetLockScreenStatus(uint32_t userId, bool &lockScreenStatus);
    bool CheckDomainAuthAvailable(int32_t userId);
    ErrCode UpdateStorageKey(int32_t userId, uint64_t secureUid, const std::vector<uint8_t> &token,
        const std::vector<uint8_t> &oldSecret, const std::vector<uint8_t> &newSecret);
    ErrCode UpdateStorageKeyContext(const int32_t userId);
    ErrCode UpdateStorageUserAuth(int32_t userId, uint64_t secureUid, const std::vector<uint8_t> &token,
        const std::vector<uint8_t> &oldSecret, const std::vector<uint8_t> &newSecret);

private:
    InnerAccountIAMManager();
    ~InnerAccountIAMManager() = default;
    DISALLOW_COPY_AND_MOVE(InnerAccountIAMManager);
    ErrCode GetStorageManagerProxy();
    ErrCode GetDomainAuthStatusInfo(
        int32_t userId, const GetPropertyRequest &request, const sptr<IGetSetPropCallback> &callback);
    void CopyAuthParam(const AuthParam &authParam, UserIam::UserAuth::AuthParam &iamAuthParam);

private:
    std::mutex mutex_;
    std::map<int32_t, IAMState> userStateMap_;
    std::map<int32_t, std::vector<uint8_t>> userChallengeMap_;
    std::map<int32_t, AccountCredentialInfo> credInfoMap_;
#ifdef HAS_STORAGE_PART
    sptr<StorageManager::IStorageManager> storageMgrProxy_;
#endif
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_INNER_ACCOUNT_IAM_MANAGER_H
