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

#include "getcredentialinfo_fuzzer.h"

#include <string>
#include <vector>
#define private public
#include "account_iam_client.h"
#include "account_i_a_m_proxy.h"
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
    AuthType authType = fuzzData.GenerateEnmu(UserIam::UserAuth::RECOVERY_KEY);
    std::shared_ptr<GetCredInfoCallback> callback = nullptr;
    bool isInitCallback = fuzzData.GetData<bool>();
    if (isInitCallback) {
        callback = make_shared<MockIDMCallback>();
    }
    int32_t result = AccountIAMClient::GetInstance().GetCredentialInfo(userId, authType, callback);
    return result == ERR_OK;
}

}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GetCredentialInfoFuzzTest(data, size);
    return 0;
}