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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_IAM_CALLBACK_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_IAM_CALLBACK_H

#include <map>
#include <vector>
#include "account_iam_info.h"
#include "domain_account_callback.h"
#include "iaccount_iam_callback.h"

namespace OHOS {
namespace AccountSA {
class AuthCallback : public AuthenticationCallback {
public:
    AuthCallback(uint32_t userId, AuthType authType, const sptr<IIDMCallback> &callback);
    virtual ~AuthCallback() = default;

    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) override;
    void OnResult(int32_t result, const Attributes &extraInfo) override;

private:
    std::uint32_t userId_;
    AuthType authType_;
    sptr<IIDMCallback> innerCallback_ = nullptr;
};

class IDMAuthCallback : public AuthenticationCallback {
public:
    IDMAuthCallback(uint32_t userId, const Attributes &extraInfo);
    virtual ~IDMAuthCallback() = default;

    void OnResult(int32_t result, const Attributes &extraInfo) override;
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) override;

private:
    uint32_t userId_ = 0;
    uint64_t credentialId_ = 0;
    uint64_t secureUid_ = 0;
};

class AddCredCallback : public UserIdmClientCallback {
public:
    AddCredCallback(uint32_t userId, const CredentialParameters &credInfo,
        const sptr<IIDMCallback> &callback);
    virtual ~AddCredCallback() = default;

    void OnResult(int32_t result, const Attributes &extraInfo) override;
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) override;

private:
    std::uint32_t userId_;
    CredentialParameters credInfo_;
    const sptr<IIDMCallback> innerCallback_ = nullptr;
};

class UpdateCredCallback : public UserIdmClientCallback {
public:
    UpdateCredCallback(uint32_t userId, const CredentialParameters &credInfo,
        const sptr<IIDMCallback> &callback);
    virtual ~UpdateCredCallback() = default;

    void OnResult(int32_t result, const Attributes &extraInfo) override;
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) override;

private:
    std::uint32_t userId_;
    std::vector<uint8_t> oldCredential_;
    CredentialParameters credInfo_;
    const sptr<IIDMCallback> innerCallback_ = nullptr;
};

class DelCredCallback : public UserIdmClientCallback {
public:
    DelCredCallback(int32_t userId, const std::vector<uint8_t> &authToken, const sptr<IIDMCallback> &callback);
    virtual ~DelCredCallback() = default;

    void OnResult(int32_t result, const Attributes &extraInfo) override;
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) override;

private:
    int32_t userId_;
    std::vector<uint8_t> authToken_;
    const sptr<IIDMCallback> innerCallback_ = nullptr;
};

class GetCredInfoCallbackWrapper : public GetCredentialInfoCallback {
public:
    GetCredInfoCallbackWrapper(int32_t userId, int32_t authType, const sptr<IGetCredInfoCallback> &callback);
    virtual ~GetCredInfoCallbackWrapper() = default;

    void OnCredentialInfo(const std::vector<CredentialInfo> &infoList) override;

private:
    int32_t userId_;
    int32_t authType_;
    sptr<IGetCredInfoCallback> innerCallback_ = nullptr;
};

class GetPropCallbackWrapper : public GetPropCallback {
public:
    GetPropCallbackWrapper(const sptr<IGetSetPropCallback> &callback);
    virtual ~GetPropCallbackWrapper() = default;

    void OnResult(int32_t result, const Attributes &extraInfo) override;

private:
    sptr<IGetSetPropCallback> innerCallback_;
};

class SetPropCallbackWrapper : public SetPropCallback {
public:
    SetPropCallbackWrapper(const sptr<IGetSetPropCallback> &callback);
    virtual ~SetPropCallbackWrapper() = default;

    void OnResult(int32_t result, const Attributes &extraInfo) override;

private:
    sptr<IGetSetPropCallback> innerCallback_;
};

class GetDomainAuthStatusInfoCallback final : public DomainAccountCallback {
public:
    GetDomainAuthStatusInfoCallback(const GetPropertyRequest &request, const sptr<IGetSetPropCallback> &callback);

    void OnResult(int32_t result, Parcel &parcel) override;

private:
    GetPropertyRequest request_;
    sptr<IGetSetPropCallback> innerCallback_;
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_SERVICES_ACCOUNTMGR_INCLUDE_ACCOUNT_IAM_CALLBACK_H
