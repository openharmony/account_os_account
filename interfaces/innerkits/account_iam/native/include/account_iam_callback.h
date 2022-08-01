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

#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_ACCOUNT_IAM_NATIVE_INCLUDE_ACCOUNT_IAM_CALLBACK_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_ACCOUNT_IAM_NATIVE_INCLUDE_ACCOUNT_IAM_CALLBACK_H

#include <map>
#include <vector>
#include "account_iam_info.h"

namespace OHOS {
namespace AccountSA {
class AuthCallback : public AuthenticationCallback {
public:
    explicit AuthCallback(uint32_t userId, const std::shared_ptr<AuthenticationCallback> &callback);
    virtual ~AuthCallback();

    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) override;
    void OnResult(int32_t result, const Attributes &extraInfo) override;

private:
    std::uint32_t userId_;
    std::shared_ptr<AuthenticationCallback> innerCallback_ = nullptr;
};

class IDMAuthCallback : public AuthenticationCallback {
public:
    explicit IDMAuthCallback(uint32_t userId, const CredentialParameters &credInfo,
        int32_t oldResult, const Attributes &reqResult, const std::shared_ptr<UserIdmClientCallback> &idmCallback);
    virtual ~IDMAuthCallback();

    void OnResult(int32_t result, const Attributes &extraInfo) override;
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) override;

private:
    uint32_t userId_;
    CredentialParameters credInfo_;
    int32_t oldResult_;
    Attributes reqResult_;
    std::shared_ptr<UserIdmClientCallback> idmCallback_ = nullptr;
    uint64_t credentialId_ = 0;
};

class AddCredCallback : public UserIdmClientCallback {
public:
    explicit AddCredCallback(uint32_t userId, const CredentialParameters &credInfo,
        const std::shared_ptr<UserIdmClientCallback> &callback);
    virtual ~AddCredCallback();

    void OnResult(int32_t result, const Attributes &extraInfo) override;
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) override;

private:
    std::uint32_t userId_;
    CredentialParameters credInfo_;
    std::shared_ptr<UserIdmClientCallback> innerCallback_ = nullptr;
};

class UpdateCredCallback : public UserIdmClientCallback {
public:
    explicit UpdateCredCallback(uint32_t userId, const CredentialParameters &credInfo,
        const std::shared_ptr<UserIdmClientCallback> &callback);
    virtual ~UpdateCredCallback();

    void OnResult(int32_t result, const Attributes &extraInfo) override;
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) override;

private:
    std::uint32_t userId_;
    std::vector<uint8_t> oldCredential_;
    CredentialParameters credInfo_;
    std::shared_ptr<UserIdmClientCallback> innerCallback_ = nullptr;
};

class DelCredCallback : public UserIdmClientCallback {
public:
    explicit DelCredCallback(int32_t userId, uint64_t credentialId, const std::vector<uint8_t> &authToken,
        const std::shared_ptr<UserIdmClientCallback> &callback);
    virtual ~DelCredCallback();

    void OnResult(int32_t result, const Attributes &extraInfo) override;
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) override;

private:
    int32_t userId_;
    uint64_t credentialId_;
    std::vector<uint8_t> authToken_;
    std::shared_ptr<UserIdmClientCallback> innerCallback_ = nullptr;
};

class IAMInputerData : public IInputerData {
public:
    IAMInputerData(int32_t userId, const std::shared_ptr<IInputerData> &inputerData);
    virtual~IAMInputerData();
    void OnSetData(int32_t authSubType, std::vector<uint8_t> data) override;
    void ResetInnerInputerData(const std::shared_ptr<IInputerData> &inputerData);

private:
    int32_t userId_;
    std::shared_ptr<IInputerData> innerInputerData_;
    std::map<std::string, std::vector<uint8_t>> credMap_;
};

class IAMInputer : public IInputer {
public:
    IAMInputer(int32_t userId, const std::shared_ptr<IInputer> &inputer);
    virtual ~IAMInputer();

    void OnGetData(int32_t authSubType, std::shared_ptr<IInputerData> inputerData);
    void ResetInnerInputer(const std::shared_ptr<IInputer> &inputer);
private:
    int32_t userId_;
    std::vector<uint8_t> oldCredential_;
    std::shared_ptr<IInputer> innerInputer_ = nullptr;
    std::shared_ptr<IAMInputerData> inputerData_ = nullptr;
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_ACCOUNT_IAM_NATIVE_INCLUDE_ACCOUNT_IAM_CALLBACK_H
