/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "authuserwithunlockoptions_fuzzer.h"

#include "account_log_wrapper.h"
#include "domain_account_client.h"
#include "fuzz_data.h"
#include <string>
#include <vector>

using namespace std;
using namespace OHOS::AccountSA;

namespace OHOS {
namespace {
class TestDomainAccountCallback : public DomainAccountCallback {
public:
    TestDomainAccountCallback() {};
    virtual ~TestDomainAccountCallback() {}
    void OnResult(const int32_t errCode, Parcel &parcel) override {}
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo,
        const DomainAccountUnlockExtraInfo &extraInfo) override {}
};
}

bool AuthUserWithUnlockOptionsFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    FuzzData fuzzData(data, size);
    int32_t userId = fuzzData.GetData<int32_t>();
    std::vector<uint8_t> password = {fuzzData.GetData<uint8_t>(), fuzzData.GetData<uint8_t>()};
    std::vector<uint8_t> challenge = {fuzzData.GetData<uint8_t>(), fuzzData.GetData<uint8_t>(),
        fuzzData.GetData<uint8_t>(), fuzzData.GetData<uint8_t>()};
    int32_t authIntent = fuzzData.GetData<int32_t>();
    DomainAccountUnlockOptions unlockOptions(challenge, authIntent);
    auto getPasswordHooks = [password]() {
        return password;
    };
    std::shared_ptr<DomainAccountCallback> callback = std::make_shared<TestDomainAccountCallback>();
    uint64_t contextId = 0;
    ErrCode result = DomainAccountClient::GetInstance().AuthUser(
        userId, getPasswordHooks, callback, unlockOptions, contextId);
    DomainAccountClient::GetInstance().CancelAuth(contextId);
    std::fill(password.begin(), password.end(), 0);
    return result == ERR_OK;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::AuthUserWithUnlockOptionsFuzzTest(data, size);
    return 0;
}
