/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_IAM_CALLBACK_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_IAM_CALLBACK_H

#include <condition_variable>
#include <map>
#include <vector>

#include "access_token.h"
#include "account_file_operator.h"
#include "account_iam_info.h"
#include "domain_account_callback.h"
#include "get_cred_info_callback_stub.h"
#include "get_enrolled_id_callback_stub.h"
#include "get_set_prop_callback_stub.h"
#include "id_m_callback_stub.h"
#include "iremote_object.h"
#include "iremote_stub.h"
#include "pre_remote_auth_callback_stub.h"

namespace OHOS {
namespace AccountSA {
class AuthCallbackDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    AuthCallbackDeathRecipient() = default;
    ~AuthCallbackDeathRecipient() override = default;

    void SetContextId(uint16_t context);
    void OnRemoteDied(const wptr<IRemoteObject> &remote) override;

private:
    uint64_t contextId_ = 0;
};

class AuthCallback : public AuthenticationCallback {
public:
    AuthCallback(uint32_t userId, AuthType authType, AuthIntent authIntent, const sptr<IIDMCallback> &callback);
    AuthCallback(uint32_t userId, AuthType authType, AuthIntent authIntent,
        bool isRemoteAuth, const sptr<IIDMCallback> &callback);
    virtual ~AuthCallback() = default;

    void SetDeathRecipient(const sptr<AuthCallbackDeathRecipient> &deathRecipient);
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) override;
    void OnResult(int32_t result, const Attributes &extraInfo) override;

private:
    ErrCode UnlockAccount(int32_t accountId, const std::vector<uint8_t> &token,
        const std::vector<uint8_t> &secret, bool &isUpdateVerifiedStatus);
    ErrCode HandleAuthResult(const Attributes &extraInfo, int32_t accountId, bool &isUpdateVerifiedStatus);
    void HandleReEnroll(const Attributes &extraInfo, int32_t accountId, const std::vector<uint8_t> &token);
    ErrCode InnerHandleReEnroll(const std::vector<uint8_t> &token);
    ErrCode UnlockUserScreen(int32_t accountId, const std::vector<uint8_t> &token,
        const std::vector<uint8_t> &secret, bool &isUpdateVerifiedStatus);

private:
    uint32_t userId_;
    uint32_t callerTokenId_ = 0;
    AuthType authType_;
    AuthIntent authIntent_;
    bool isRemoteAuth_ = false;
    sptr<IIDMCallback> innerCallback_ = nullptr;
    sptr<AuthCallbackDeathRecipient> deathRecipient_ = nullptr;
};

class IDMCallbackDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    IDMCallbackDeathRecipient(uint32_t userId);
    void OnRemoteDied(const wptr<IRemoteObject> &remote) override;

private:
    uint32_t userId_ = 0;
};

class AddCredCallback : public UserIdmClientCallback {
public:
    AddCredCallback(uint32_t userId, const CredentialParameters &credInfo,
        const sptr<IIDMCallback> &callback);
    virtual ~AddCredCallback();

    void SetDeathRecipient(const sptr<IDMCallbackDeathRecipient> &deathRecipient);
    void OnResult(int32_t result, const Attributes &extraInfo) override;
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) override;

public:
    std::mutex mutex_;
    bool isCalled_ = false;
    std::condition_variable onResultCondition_;

private:
    std::uint32_t userId_;
    CredentialParameters credInfo_;
    sptr<IDMCallbackDeathRecipient> deathRecipient_ = nullptr;
    sptr<IIDMCallback> innerCallback_ = nullptr;
};

class UpdateCredCallback : public UserIdmClientCallback {
public:
    UpdateCredCallback(uint32_t userId, const CredentialParameters &credInfo,
        const sptr<IIDMCallback> &callback);
    virtual ~UpdateCredCallback();

    void SetDeathRecipient(const sptr<IDMCallbackDeathRecipient> &deathRecipient);
    void OnResult(int32_t result, const Attributes &extraInfo) override;
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) override;

private:
    void InnerOnResult(int32_t result, const Attributes &extraInfo);

public:
    std::mutex mutex_;
    bool isCalled_ = false;
    std::condition_variable onResultCondition_;

private:
    std::uint32_t userId_;
    CredentialParameters credInfo_;
    sptr<IDMCallbackDeathRecipient> deathRecipient_ = nullptr;
    const sptr<IIDMCallback> innerCallback_ = nullptr;
};

#ifdef HAS_PIN_AUTH_PART
class DelUserInputer : public IInputer {
public:
    DelUserInputer() = default;
    virtual ~DelUserInputer() = default;

    void OnGetData(int32_t authSubType, std::vector<uint8_t> challenge,
        std::shared_ptr<IInputerData> inputerData) override;
};
#endif // HAS_PIN_AUTH_PART

class VerifyTokenCallbackWrapper : public VerifyTokenCallback {
public:
    VerifyTokenCallbackWrapper(uint32_t userId, const std::vector<uint8_t> &token,
        Security::AccessToken::AccessTokenID callerTokenId, const sptr<IIDMCallback> &callback);
    virtual ~VerifyTokenCallbackWrapper();
    void OnResult(int32_t result, const Attributes &extraInfo) override;

private:
    void InnerOnResult(int32_t result, const Attributes &extraInfo);

public:
    std::mutex mutex_;
    bool isCalled_ = false;
    std::condition_variable onResultCondition_;

private:
    std::uint32_t userId_;
    std::vector<uint8_t> token_;
    Security::AccessToken::AccessTokenID callerTokenId_;
    const sptr<IIDMCallback> innerCallback_ = nullptr;
};

class CommitDelCredCallback : public UserIdmClientCallback {
public:
    CommitDelCredCallback(uint32_t userId, const sptr<IIDMCallback> callback);
    virtual ~CommitDelCredCallback() = default;

    void OnResult(int32_t result, const UserIam::UserAuth::Attributes &extraInfo) override;
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const UserIam::UserAuth::Attributes &extraInfo) override;

public:
    bool isCalled_ = false;
    std::mutex mutex_;
    std::condition_variable onResultCondition_;

private:
    std::uint32_t userId_;
    const sptr<IIDMCallback> innerCallback_ = nullptr;
};

struct UpdateCredInfo {
    uint64_t credentialId = 0;
    uint64_t secureUid = 0;
    std::vector<uint8_t> token;
    std::vector<uint8_t> newSecret;
    std::vector<uint8_t> oldSecret;

    UpdateCredInfo() = default;
    UpdateCredInfo(const Attributes &extraInfo);
    virtual ~UpdateCredInfo();
};

class CommitCredUpdateCallback : public UserIdmClientCallback {
public:
    CommitCredUpdateCallback(int32_t userId, const UpdateCredInfo &extraUpdateInfo, const sptr<IIDMCallback> &callback);
    virtual ~CommitCredUpdateCallback() = default;

    void OnResult(int32_t result, const Attributes &extraInfo) override;
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) override;

private:
    void InnerOnResult(int32_t result, const Attributes &extraInfo);

public:
    std::mutex mutex_;
    bool isCalled_ = false;
    std::condition_variable onResultCondition_;

private:
    int32_t userId_;
    UpdateCredInfo extraUpdateInfo_;
    sptr<IIDMCallback> innerCallback_ = nullptr;
};

class DelCredCallback : public UserIdmClientCallback {
public:
    DelCredCallback(int32_t userId, bool isPIN, std::vector<uint8_t> token, const sptr<IIDMCallback> &callback);
    virtual ~DelCredCallback();

    void OnResult(int32_t result, const Attributes &extraInfo) override;
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) override;

private:
    int32_t userId_;
    bool isPIN_;
    std::vector<uint8_t> token_;
    sptr<IIDMCallback> innerCallback_ = nullptr;
};

class GetCredInfoCallbackWrapper : public GetCredentialInfoCallback {
public:
    GetCredInfoCallbackWrapper(int32_t userId, int32_t authType, const sptr<IGetCredInfoCallback> &callback);
    virtual ~GetCredInfoCallbackWrapper() = default;

    void OnCredentialInfo(int32_t result, const std::vector<CredentialInfo> &infoList) override;

private:
    int32_t userId_;
    int32_t authType_;
    sptr<IGetCredInfoCallback> innerCallback_ = nullptr;
};

class GetCredentialInfoSyncCallback : public UserIam::UserAuth::GetCredentialInfoCallback {
public:
    GetCredentialInfoSyncCallback(int32_t userId);
    virtual ~GetCredentialInfoSyncCallback() = default;

    void OnCredentialInfo(int32_t result, const std::vector<UserIam::UserAuth::CredentialInfo> &infoList);

    int32_t userId_;
    bool hasPIN_ = false;
    bool isCalled_ = false;
    int32_t result_ = -1;
    std::mutex secureMtx_;
    std::condition_variable secureCv_;
};

class GetPropCallbackWrapper : public GetPropCallback {
public:
    GetPropCallbackWrapper(int32_t userId, const sptr<IGetSetPropCallback> &callback);
    virtual ~GetPropCallbackWrapper() = default;

    void OnResult(int32_t result, const Attributes &extraInfo) override;

private:
    int32_t userId_;
    sptr<IGetSetPropCallback> innerCallback_;
};

class SetPropCallbackWrapper : public SetPropCallback {
public:
    SetPropCallbackWrapper(int32_t userId, const sptr<IGetSetPropCallback> &callback);
    virtual ~SetPropCallbackWrapper() = default;

    void OnResult(int32_t result, const Attributes &extraInfo) override;

private:
    int32_t userId_;
    sptr<IGetSetPropCallback> innerCallback_;
};

class GetSecUserInfoCallbackWrapper : public GetSecUserInfoCallback {
public:
    GetSecUserInfoCallbackWrapper(int32_t userId, AuthType authType, const sptr<IGetEnrolledIdCallback> &callback);
    virtual ~GetSecUserInfoCallbackWrapper() = default;

    void OnSecUserInfo(int32_t result, const SecUserInfo &info) override;

private:
    int32_t userId_;
    AuthType authType_;
    sptr<IGetEnrolledIdCallback> innerCallback_;
};

class GetSecureUidCallback final : public GetSecUserInfoCallback {
public:
    GetSecureUidCallback(int32_t userId);

    void OnSecUserInfo(int32_t result, const SecUserInfo &info) override;

public:
    int32_t userId_;
    uint64_t secureUid_ = 0;
    bool isCalled_ = false;
    std::mutex secureMtx_;
    std::condition_variable secureCv_;
};

class PrepareRemoteAuthCallbackWrapper : public PrepareRemoteAuthCallback {
public:
    PrepareRemoteAuthCallbackWrapper(const sptr<IPreRemoteAuthCallback> &callback);
    virtual ~PrepareRemoteAuthCallbackWrapper() = default;

    void OnResult(int32_t result) override;

private:
    sptr<IPreRemoteAuthCallback> innerCallback_;
};

#ifdef SUPPORT_DOMAIN_ACCOUNTS
class GetDomainAuthStatusInfoCallback final : public DomainAccountCallback {
public:
    GetDomainAuthStatusInfoCallback(const GetPropertyRequest &request, const sptr<IGetSetPropCallback> &callback);

    void OnResult(int32_t result, Parcel &parcel) override;

private:
    GetPropertyRequest request_;
    sptr<IGetSetPropCallback> innerCallback_;
};
#endif // SUPPORT_DOMAIN_ACCOUNTS

class ReEnrollCallback final : public IRemoteStub<IIDMCallback> {
public:
    bool isCalled_ = false;
    ErrCode result_ = ERR_ACCOUNT_COMMON_NOT_INIT_ERROR;
    std::mutex mutex_;
    std::condition_variable onResultCondition_;

    ReEnrollCallback(const sptr<IIDMCallback> &innerCallback);
    ErrCode OnResult(int32_t resultCode, const std::vector<uint8_t>& extraInfoBuffer) override;
    ErrCode OnAcquireInfo(int32_t module, uint32_t acquireInfo, const std::vector<uint8_t>& extraInfoBuffer) override;
private:
    sptr<IIDMCallback> innerCallback_;
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_IAM_CALLBACK_H
