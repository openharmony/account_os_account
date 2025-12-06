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

#include "getenrolledid_fuzzer.h"

#include <string>
#include <vector>
#define private public
#include "account_iam_client.h"
#include "account_i_a_m_proxy.h"
#undef private
#include "fuzz_data.h"

using namespace std;
using namespace OHOS::AccountSA;

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

namespace OHOS {
bool GetEnrolledIdFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    FuzzData fuzzData(data, size);
    int32_t userId = fuzzData.GetData<int32_t>();
    AuthType authType = static_cast<AuthType>(fuzzData.GenerateEnmu(IAMAuthType::TYPE_END));
    auto callback = std::make_shared<MockGetEnrolledIdCallback>();
    bool isNullCallback = fuzzData.GetData<bool>();
    if (isNullCallback) {
        callback = nullptr;
    }
    AccountIAMClient::GetInstance().GetEnrolledId(userId, authType, callback);
    return false;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GetEnrolledIdFuzzTest(data, size);
    return 0;
}
