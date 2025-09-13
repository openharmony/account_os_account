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

#ifndef OS_ACCOUNT_INTERFACES_INNERKITS_ACCOUNT_IAM_NATIVE_INCLUDE_ACCOUNT_IAM_CALLBACK_SERVICE_H
#define OS_ACCOUNT_INTERFACES_INNERKITS_ACCOUNT_IAM_NATIVE_INCLUDE_ACCOUNT_IAM_CALLBACK_SERVICE_H

#include "account_iam_client_callback.h"
#include "account_iam_info.h"
#include "domain_account_callback.h"
#include "domain_account_common.h"
#include "get_cred_info_callback_stub.h"
#include "get_enrolled_id_callback_stub.h"
#include "get_set_prop_callback_stub.h"
#include "id_m_callback_stub.h"
#include "pre_remote_auth_callback_stub.h"
#ifdef SUPPORT_DOMAIN_ACCOUNTS
#include "domain_account_client.h"
#endif

namespace OHOS {
namespace AccountSA {
class IDMCallbackService : public IDMCallbackStub {
public:
    IDMCallbackService(int32_t userId, const std::shared_ptr<IDMCallback> &callback);
    ~IDMCallbackService();
    ErrCode OnAcquireInfo(int32_t module, uint32_t acquireInfo, const std::vector<uint8_t>& extraInfoBuffer) override;
    ErrCode OnResult(int32_t resultCode, const std::vector<uint8_t>& extraInfoBuffer) override;

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
    ErrCode OnCredentialInfo(int32_t resultCode, const std::vector<CredentialInfoIam>& infoList) override;

private:
    std::shared_ptr<GetCredInfoCallback> callback_;
    bool isCalled_ = false;
    DISALLOW_COPY_AND_MOVE(GetCredInfoCallbackService);
};

class GetSetPropCallbackService : public GetSetPropCallbackStub {
public:
    explicit GetSetPropCallbackService(const std::shared_ptr<GetSetPropCallback> &callback);
    ~GetSetPropCallbackService();
    ErrCode OnResult(int32_t resultCode, const std::vector<uint8_t>& extraInfoBuffer) override;

private:
    std::shared_ptr<GetSetPropCallback> callback_;
    bool isCalled_ = false;
    DISALLOW_COPY_AND_MOVE(GetSetPropCallbackService);
};

class GetEnrolledIdCallbackService : public GetEnrolledIdCallbackStub {
public:
    explicit GetEnrolledIdCallbackService(const std::shared_ptr<GetEnrolledIdCallback> &callback);
    ~GetEnrolledIdCallbackService();
    ErrCode OnEnrolledId(int32_t resultCode, uint64_t enrolledId) override;

private:
    std::shared_ptr<GetEnrolledIdCallback> callback_;
    bool isCalled_ = false;
    DISALLOW_COPY_AND_MOVE(GetEnrolledIdCallbackService);
};

class PreRemoteAuthCallbackService : public PreRemoteAuthCallbackStub {
public:
    explicit PreRemoteAuthCallbackService(const std::shared_ptr<PreRemoteAuthCallback> &callback);
    ~PreRemoteAuthCallbackService();
    ErrCode OnResult(int32_t resultCode) override;

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
#ifdef SUPPORT_DOMAIN_ACCOUNTS
class DomainCredentialRecipient : public IInputerData {
public:
    DomainCredentialRecipient();
    ~DomainCredentialRecipient() override;
    void OnSetData(int32_t authSubType, std::vector<uint8_t> data) override;
    std::vector<uint8_t> WaitToGetData();
private:
    std::mutex mutex_;
    std::condition_variable cv_;
    std::vector<uint8_t> data_;
    std::atomic<bool> dataReady_ = false;
};
#endif // SUPPORT_DOMAIN_ACCOUNTS

class IAMInputer final: public IInputer {
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
