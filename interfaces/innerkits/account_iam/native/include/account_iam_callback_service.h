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

#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_ACCOUNT_IAM_NATIVE_INCLUDE_ACCOUNT_IAM_CALLBACK_SERVICE_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_ACCOUNT_IAM_NATIVE_INCLUDE_ACCOUNT_IAM_CALLBACK_SERVICE_H

#include "account_iam_callback_stub.h"
#include "account_iam_client_callback.h"
#include "account_iam_info.h"
#include "domain_account_common.h"
#include "domain_account_callback.h"

namespace OHOS {
namespace AccountSA {
class IDMCallbackService : public IDMCallbackStub {
public:
    IDMCallbackService(int32_t userId, const std::shared_ptr<IDMCallback> &callback);
    ~IDMCallbackService();
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) override;
    void OnResult(int32_t result, const Attributes &extraInfo) override;

private:
    int32_t userId_;
    std::shared_ptr<IDMCallback> callback_;
    bool isCalled_ = false;
    DISALLOW_COPY_AND_MOVE(IDMCallbackService);
};

class GetCredInfoCallbackService : public GetCredInfoCallbackStub {
public:
    explicit GetCredInfoCallbackService(const std::shared_ptr<GetCredInfoCallback> &callback);
    ~GetCredInfoCallbackService();
    void OnCredentialInfo(const std::vector<CredentialInfo> &infoList) override;
    void SetResult(int32_t errCode);

private:
    std::shared_ptr<GetCredInfoCallback> callback_;
    bool isCalled_ = false;
    int32_t result_ = 0;
    DISALLOW_COPY_AND_MOVE(GetCredInfoCallbackService);
};

class GetSetPropCallbackService : public GetSetPropCallbackStub {
public:
    explicit GetSetPropCallbackService(const std::shared_ptr<GetSetPropCallback> &callback);
    ~GetSetPropCallbackService();
    void OnResult(int32_t result, const Attributes &extraInfo) override;

private:
    std::shared_ptr<GetSetPropCallback> callback_;
    bool isCalled_ = false;
    DISALLOW_COPY_AND_MOVE(GetSetPropCallbackService);
};

class GetEnrolledIdCallbackService : public GetEnrolledIdCallbackStub {
public:
    explicit GetEnrolledIdCallbackService(const std::shared_ptr<GetEnrolledIdCallback> &callback);
    ~GetEnrolledIdCallbackService();
    void OnEnrolledId(int32_t result, uint64_t enrolledId) override;

private:
    std::shared_ptr<GetEnrolledIdCallback> callback_;
    bool isCalled_ = false;
    DISALLOW_COPY_AND_MOVE(GetEnrolledIdCallbackService);
};

class PreRemoteAuthCallbackService : public PreRemoteAuthCallbackStub {
public:
    explicit PreRemoteAuthCallbackService(const std::shared_ptr<PreRemoteAuthCallback> &callback);
    ~PreRemoteAuthCallbackService();
    void OnResult(int32_t result) override;

private:
    std::shared_ptr<PreRemoteAuthCallback> callback_;
    bool isCalled_ = false;
    DISALLOW_COPY_AND_MOVE(PreRemoteAuthCallbackService);
};

class DomainAuthCallbackAdapter final : public DomainAccountCallback {
public:
    explicit DomainAuthCallbackAdapter(const std::shared_ptr<IDMCallback> &callback);
    void OnResult(const int32_t errCode, Parcel &parcel) override;

private:
    std::shared_ptr<IDMCallback> callback_;
};

#ifdef HAS_PIN_AUTH_PART
class DomainCredentialRecipient : public IInputerData {
public:
    DomainCredentialRecipient(int32_t userId, const std::shared_ptr<IDMCallback> &callback);
    ~DomainCredentialRecipient() override;
    void OnSetData(int32_t authSubType, std::vector<uint8_t> data) override;

private:
    int32_t userId_;
    std::shared_ptr<IDMCallback> idmCallback_;
};

class IAMInputer final : public IInputer {
public:
    IAMInputer(int32_t userId, const std::shared_ptr<IInputer> &inputer);

    void OnGetData(int32_t authSubType, std::vector<uint8_t> challenge,
        std::shared_ptr<IInputerData> inputerData) override;
private:
    int32_t userId_;
    std::shared_ptr<IInputer> innerInputer_ = nullptr;
};
#endif
}  // namespace AccountSA
}  // namespace OHOS
#endif  // OS_ACCOUNT_INTERFACES_INNERKITS_ACCOUNT_IAM_NATIVE_INCLUDE_ACCOUNT_IAM_CALLBACK_SERVICE_H
