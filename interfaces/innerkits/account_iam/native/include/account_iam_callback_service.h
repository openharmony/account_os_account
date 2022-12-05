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

#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_ACCOUNT_IAM_NATIVE_INCLUDE_ACCOUNT_IAM_CALLBACK_SERVICE_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_ACCOUNT_IAM_NATIVE_INCLUDE_ACCOUNT_IAM_CALLBACK_SERVICE_H

#include "account_iam_callback_stub.h"
#include "account_iam_client_callback.h"
#include "account_iam_info.h"
#include "domain_account_common.h"
#include "domain_auth_callback.h"

namespace OHOS {
namespace AccountSA {
class IDMCallbackService : public IDMCallbackStub {
public:
    explicit IDMCallbackService(int32_t userId, const std::shared_ptr<IDMCallback> &callback);
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) override;
    void OnResult(int32_t result, const Attributes &extraInfo) override;

private:
    int32_t userId_;
    std::shared_ptr<IDMCallback> callback_;
    DISALLOW_COPY_AND_MOVE(IDMCallbackService);
};

class GetCredInfoCallbackService : public GetCredInfoCallbackStub {
public:
    explicit GetCredInfoCallbackService(const std::shared_ptr<GetCredInfoCallback> &callback);
    void OnCredentialInfo(const std::vector<CredentialInfo> &infoList) override;

private:
    std::shared_ptr<GetCredInfoCallback> callback_;
    DISALLOW_COPY_AND_MOVE(GetCredInfoCallbackService);
};

class GetSetPropCallbackService : public GetSetPropCallbackStub {
public:
    explicit GetSetPropCallbackService(const std::shared_ptr<GetSetPropCallback> &callback);
    void OnResult(int32_t result, const Attributes &extraInfo) override;

private:
    std::shared_ptr<GetSetPropCallback> callback_;
    DISALLOW_COPY_AND_MOVE(GetSetPropCallbackService);
};

class DomainAuthCallbackAdapter final : public DomainAuthCallback {
public:
    DomainAuthCallbackAdapter(const std::shared_ptr<IDMCallback> &callback);
    void OnResult(int32_t resultCode, const DomainAuthResult &result);

private:
    std::shared_ptr<IDMCallback> callback_;
};

class DomainCredentialRecipient : public IInputerData {
public:
    DomainCredentialRecipient(int32_t userId, const std::shared_ptr<IDMCallback> &callback);
    virtual ~DomainCredentialRecipient();
    void OnSetData(int32_t authSubType, std::vector<uint8_t> data) override;

private:
    int32_t userId_;
    std::shared_ptr<IDMCallback> idmCallback_;
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

    void OnGetData(int32_t authSubType, std::shared_ptr<IInputerData> inputerData) override;
    void ResetInnerInputer(const std::shared_ptr<IInputer> &inputer);
private:
    int32_t userId_;
    std::vector<uint8_t> oldCredential_;
    std::shared_ptr<IInputer> innerInputer_ = nullptr;
    std::shared_ptr<IAMInputerData> inputerData_ = nullptr;
};
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_ACCOUNT_IAM_NATIVE_INCLUDE_ACCOUNT_IAM_CALLBACK_SERVICE_H
