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

#include "getcredentialinfo_fuzzer.h"

#include <string>
#include <vector>
#define private public
#include "account_iam_client.h"
#include "account_iam_mgr_proxy.h"
#undef private
#include "fuzz_data.h"


using namespace std;
using namespace OHOS::AccountSA;

class MockIDMCallback : public OHOS::AccountSA::GetCredInfoCallback {
public:
    virtual ~MockIDMCallback() {}
    void OnCredentialInfo(int32_t result, const std::vector<CredentialInfo> &infoList) override
    {
        return;
    }
};

class MockPreRemoteAuthCallback : public OHOS::AccountSA::PreRemoteAuthCallback {
public:
    void OnResult(int32_t result)
    {
        return;
    }
    virtual ~MockPreRemoteAuthCallback() {}
};
class PreRemoteAuthCallbackMockTest final : public OHOS::AccountSA::PreRemoteAuthCallback {
public:
    void OnResult(int32_t result) override
    {
        result_ = result;
    }
    int32_t result_;
};

class MockIDMCallback1 : public OHOS::AccountSA::IDMCallback {
public:
    virtual ~MockIDMCallback1() {}
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const Attributes &extraInfo) override
    {
        return;
    }
    void OnResult(int32_t result, const Attributes &extraInfo) override
    {
        return;
    }
};

class MockGetEnrolledIdCallback final : public GetEnrolledIdCallback {
public:
    void OnEnrolledId(int32_t result, uint64_t enrolledId) override
    {
        result_ = result;
        return;
    }

public:
    int32_t result_ = -1;
};

class MockIInputer : public OHOS::AccountSA::IInputer {
public:
    virtual ~MockIInputer() {}
    void OnGetData(int32_t authSubType, std::vector<uint8_t> challenge,
        std::shared_ptr<IInputerData> inputerData) override
    {
        return;
    }
};

namespace OHOS {
bool GetCredentialInfoFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    FuzzData fuzzData(data, size);
    int32_t userId = fuzzData.GetData<int32_t>();
    AuthType authType = fuzzData.GenerateRandomEnmu(UserIam::UserAuth::RECOVERY_KEY);
    std::shared_ptr<GetCredInfoCallback> callback = make_shared<MockIDMCallback>();
    int32_t result = AccountIAMClient::GetInstance().GetCredentialInfo(userId, authType, callback);
    return result == ERR_OK;
}

bool StartDomainAuthFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    FuzzData fuzzData(data, size);
    int32_t userId = fuzzData.GetData<int32_t>();
    std::shared_ptr<IDMCallback> callback = make_shared<MockIDMCallback1>();
    int32_t result = AccountIAMClient::GetInstance().StartDomainAuth(userId, callback);
    return result == ERR_OK;
}

bool PrepareRemoteAuthFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    FuzzData fuzzData(data, size);
    std::string remoteNetworkId(fuzzData.GenerateRandomString());
    std::shared_ptr<PreRemoteAuthCallback> callback = make_shared<MockPreRemoteAuthCallback>();
    int32_t result = AccountIAMClient::GetInstance().PrepareRemoteAuth(remoteNetworkId, callback);
    return result == ERR_OK;
}

bool GetEnrolledIdFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    FuzzData fuzzData(data, size);
    int32_t userId = fuzzData.GetData<int32_t>();
    AuthType authType = static_cast<AuthType>(fuzzData.GenerateRandomEnmu(IAMAuthType::TYPE_END));
    auto callback = std::make_shared<MockGetEnrolledIdCallback>();
    AccountIAMClient::GetInstance().GetEnrolledId(userId, authType, callback);
    return callback->result_ == ERR_OK;
}

bool RegisterPINInputerTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    std::shared_ptr<IInputer> inputer = make_shared<MockIInputer>();
    int32_t result = AccountIAMClient::GetInstance().RegisterPINInputer(inputer);
    result = AccountIAMClient::GetInstance().RegisterDomainInputer(inputer);
    return result == ERR_OK;
}

bool OpenSessionFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    FuzzData fuzzData(data, size);
    int32_t userId = fuzzData.GetData<int32_t>();
    std::shared_ptr<AccountIAMMgrProxy> accountIAMMgrProxy = std::make_shared<AccountIAMMgrProxy>(nullptr);
    std::vector<uint8_t> challenge;
    int32_t result = accountIAMMgrProxy->OpenSession(userId, challenge);
    return result == ERR_OK;
}

bool CloseSessionFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    FuzzData fuzzData(data, size);
    int32_t userId = fuzzData.GetData<int32_t>();
    std::shared_ptr<AccountIAMMgrProxy> accountIAMMgrProxy = std::make_shared<AccountIAMMgrProxy>(nullptr);
    int32_t result = accountIAMMgrProxy->CloseSession(userId);
    return result == ERR_OK;
}

bool CancelFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    FuzzData fuzzData(data, size);
    int32_t userId = fuzzData.GetData<int32_t>();
    std::shared_ptr<AccountIAMMgrProxy> accountIAMMgrProxy = std::make_shared<AccountIAMMgrProxy>(nullptr);
    int32_t result = accountIAMMgrProxy->Cancel(userId);
    return result == ERR_OK;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GetCredentialInfoFuzzTest(data, size);
    OHOS::StartDomainAuthFuzzTest(data, size);
    OHOS::PrepareRemoteAuthFuzzTest(data, size);
    OHOS::GetEnrolledIdFuzzTest(data, size);
    OHOS::RegisterPINInputerTest(data, size);
    OHOS::OpenSessionFuzzTest(data, size);
    OHOS::CloseSessionFuzzTest(data, size);
    OHOS::CancelFuzzTest(data, size);
    return 0;
}
